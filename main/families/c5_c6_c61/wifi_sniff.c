/* Air-scanner modem layer for the C5/C6/C61 burst receiver: promiscuous Wi-Fi sniffing with on-chip aggregation.
 * See wifi_sniff.h for the protocol. Everything here is receive-only: promiscuous mode never transmits. */
#include "wifi_sniff.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_heap_caps.h"
#include "burst_serial.h"

#define MAX_ADDR 128
#define MAX_BSS 48

typedef struct {
    uint8_t mac[6], bssid[6];
    uint32_t frames, bytes;
    int32_t rssi_sum;
    int8_t rssi_max, color;
    uint16_t retries, fmt_mask;
    uint8_t has_bssid, max_bw;
    char role;
} addr_entry_t;

typedef struct {
    uint8_t bssid[6];
    int8_t rssi_max, color;
    int32_t rssi_sum;
    uint32_t beacons, rx_n;
    uint8_t ds_ch, ht_second, vht_width, vht_c0, vht_c1, he, ssid_len;
    uint16_t interval;
    char ssid[32];
} bss_entry_t;

/* Heap, not static: the C5's static sections must stay below the RF dump bank (sram_guard.ld). */
static addr_entry_t *addrs;
static bss_entry_t *bsses;
static volatile bool active;
static unsigned n_addr, n_bss, drop_addr, drop_bss;
static uint32_t t_frames, t_mgmt, t_ctrl, t_data, t_bad, t_bytes, fmt_count[8];
static int32_t nf_sum;

/* Per-frame event log for CAPSNIFF (time-aligning decoded frames with raw I/Q captures). */
typedef struct {
    int64_t cb_us;            /* esp_timer time when the callback ran */
    uint32_t rx_ts;           /* hardware RX timestamp (us, MAC clock) */
    int8_t rssi;
    uint8_t fmt, state, pad;
    uint16_t len, fc;
    uint8_t a1[6], a2[6];
} frame_ev_t;
#define MAX_EV 600
static frame_ev_t *evs;
static volatile unsigned n_ev, drop_ev;
static volatile bool logging;

static void reply(const char *s) { burst_serial_send(s, strlen(s)); }

static addr_entry_t *addr_slot(const uint8_t *mac) {
    for (unsigned i = 0; i < n_addr; i++)
        if (!memcmp(addrs[i].mac, mac, 6)) return &addrs[i];
    if (n_addr >= MAX_ADDR) { drop_addr++; return NULL; }
    addr_entry_t *a = &addrs[n_addr++];
    memset(a, 0, sizeof(*a));
    memcpy(a->mac, mac, 6);
    a->rssi_max = -128; a->color = -1; a->role = 'x';
    return a;
}

static bss_entry_t *bss_slot(const uint8_t *bssid) {
    for (unsigned i = 0; i < n_bss; i++)
        if (!memcmp(bsses[i].bssid, bssid, 6)) return &bsses[i];
    if (n_bss >= MAX_BSS) { drop_bss++; return NULL; }
    bss_entry_t *b = &bsses[n_bss++];
    memset(b, 0, sizeof(*b));
    memcpy(b->bssid, bssid, 6);
    b->rssi_max = -128; b->color = -1;
    return b;
}

/* BSS colour and bandwidth from the PHY header the hardware hands us (HE-SIG-A1, or HT-SIG for HT). */
static void phy_info(const wifi_pkt_rx_ctrl_t *rx, int *color, int *bw) {
    uint32_t s = rx->he_siga1;
    *color = -1; *bw = 0;
    switch (rx->cur_bb_format) {
    case RX_BB_FORMAT_HT: *bw = (s >> 7) & 1 ? 40 : 20; break;
    case RX_BB_FORMAT_VHT: if (s) *bw = 20 << (s & 3); break;
    case RX_BB_FORMAT_HE_SU:
    case RX_BB_FORMAT_HE_ERSU: *color = (s >> 8) & 0x3f; *bw = 20 << ((s >> 19) & 3); break;
    case RX_BB_FORMAT_HE_MU: { unsigned b = (s >> 15) & 7; *color = (s >> 5) & 0x3f; *bw = b < 4 ? 20 << b : (b < 6 ? 80 : 160); break; }
    case RX_BB_FORMAT_HE_TB: *color = (s >> 1) & 0x3f; *bw = 20 << ((s >> 24) & 3); break;
    default: break;
    }
}

static void parse_beacon(const uint8_t *p, unsigned len, bss_entry_t *b) {
    if (len < 36) return;
    b->interval = p[32] | (p[33] << 8);
    unsigned i = 36;
    while (i + 2 <= len) {
        unsigned id = p[i], l = p[i + 1];
        const uint8_t *e = p + i;
        if (i + 2 + l > len) break;
        if (id == 0 && l <= 32 && !b->ssid_len) { memcpy(b->ssid, e + 2, l); b->ssid_len = l ? l : 0; }
        else if (id == 3 && l >= 1) b->ds_ch = e[2];
        else if (id == 61 && l >= 2) { if (!b->ds_ch) b->ds_ch = e[2]; b->ht_second = e[3] & 3; }
        else if (id == 192 && l >= 3) { b->vht_width = e[2]; b->vht_c0 = e[3]; b->vht_c1 = e[4]; }
        else if (id == 255 && l >= 5 && e[2] == 36) { b->he = 1; if (!(e[6] & 0x80)) b->color = e[6] & 0x3f; }
        else if (id == 255 && l >= 1 && e[2] == 35) b->he = 1;
        i += 2 + l;
    }
}

static void rx_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (!active) return;
    const wifi_promiscuous_pkt_t *pkt = buf;
    const wifi_pkt_rx_ctrl_t *rx = &pkt->rx_ctrl;
    const uint8_t *p = pkt->payload;
    unsigned len = rx->sig_len > 4 ? rx->sig_len - 4 : 0;          /* without the FCS */
    t_frames++;
    nf_sum += rx->noise_floor;
    if (logging) {
        if (n_ev < MAX_EV) {
            frame_ev_t *e = &evs[n_ev];
            e->cb_us = esp_timer_get_time(); e->rx_ts = rx->timestamp; e->rssi = rx->rssi; e->fmt = rx->cur_bb_format;
            e->state = rx->rx_state; e->len = rx->sig_len;
            e->fc = rx->sig_len >= 2 ? (p[0] | (p[1] << 8)) : 0;
            if (rx->sig_len >= 10) memcpy(e->a1, p + 4, 6); else memset(e->a1, 0, 6);
            if (rx->sig_len >= 16) memcpy(e->a2, p + 10, 6); else memset(e->a2, 0, 6);
            n_ev++;
        } else drop_ev++;
    }
    if (rx->cur_bb_format < 8) fmt_count[rx->cur_bb_format]++;
    if (rx->rx_state) { t_bad++; return; }                          /* failed checksum: count only */
    if (len < 10) return;
    t_bytes += len;
    unsigned fc = p[0] | (p[1] << 8), ftype = (fc >> 2) & 3, sub = (fc >> 4) & 15;
    bool to_ds = (fc >> 8) & 1, from_ds = (fc >> 9) & 1, retry = (fc >> 11) & 1;
    int color, bw;
    phy_info(rx, &color, &bw);
    const uint8_t *a1 = p + 4, *a2 = p + 10, *a3 = p + 16, *bssid = NULL, *tx = NULL;
    char role = 'x';
    if (ftype == 0) {                                                /* management */
        t_mgmt++;
        if (len < 24) return;
        tx = a2; bssid = a3; role = memcmp(a2, a3, 6) ? 'm' : 'a';
        if (sub == 8 || sub == 5) {                                  /* beacon / probe response */
            bss_entry_t *b = bss_slot(a3);
            if (b) {
                if (sub == 8) b->beacons++;
                b->rx_n++;
                b->rssi_sum += rx->rssi;
                if (rx->rssi > b->rssi_max) b->rssi_max = rx->rssi;
                parse_beacon(p, len, b);
            }
        }
    } else if (ftype == 1) {                                         /* control: only some carry a transmitter */
        t_ctrl++;
        if (len >= 16 && (sub == 8 || sub == 9 || sub == 10 || sub == 11 || sub == 14)) tx = a2;
    } else if (ftype == 2) {                                         /* data */
        t_data++;
        if (len < 24) return;
        tx = a2;
        if (to_ds && !from_ds) { bssid = a1; role = 's'; }
        else if (from_ds && !to_ds) { bssid = a2; role = 'a'; }
        else if (!to_ds && !from_ds) { bssid = a3; role = memcmp(a2, a3, 6) ? 's' : 'a'; }
    }
    if (!tx || (tx[0] & 1)) return;                                  /* no transmitter, or a group address */
    addr_entry_t *a = addr_slot(tx);
    if (!a) return;
    a->frames++; a->bytes += len; a->rssi_sum += rx->rssi;
    if (rx->rssi > a->rssi_max) a->rssi_max = rx->rssi;
    if (retry) a->retries++;
    a->fmt_mask |= 1u << rx->cur_bb_format;
    if (color >= 0) a->color = color;
    if (bw > a->max_bw) a->max_bw = bw;
    if (bssid && !(bssid[0] & 1)) { memcpy(a->bssid, bssid, 6); a->has_bssid = 1; }
    if (role == 'a' || a->role == 'x' || (a->role == 'm' && role == 's')) a->role = role;
}

static bool valid_channel(unsigned ch) {
    if (ch >= 1 && ch <= 14) return true;
    if ((ch >= 36 && ch <= 64) || (ch >= 100 && ch <= 144)) return ch % 4 == 0;
    if (ch >= 149 && ch <= 177) return (ch - 149) % 4 == 0;
    return false;
}

#define MACF "%02x:%02x:%02x:%02x:%02x:%02x"
#define MACA(m) m[0], m[1], m[2], m[3], m[4], m[5]

static void reset_tables(void) {
    n_addr = n_bss = drop_addr = drop_bss = 0;
    t_frames = t_mgmt = t_ctrl = t_data = t_bad = t_bytes = 0; nf_sum = 0;
    memset(fmt_count, 0, sizeof(fmt_count));
    n_ev = drop_ev = 0;
}

int wifi_sniff_begin(unsigned ch, bool log_frames, unsigned *switch_us) {
    static bool configured;
    if (!valid_channel(ch)) return -1;
    if (!addrs) addrs = heap_caps_calloc(MAX_ADDR, sizeof(addr_entry_t), MALLOC_CAP_8BIT);
    if (!bsses) bsses = heap_caps_calloc(MAX_BSS, sizeof(bss_entry_t), MALLOC_CAP_8BIT);
    if (log_frames && !evs) evs = heap_caps_calloc(MAX_EV, sizeof(frame_ev_t), MALLOC_CAP_8BIT);
    if (!addrs || !bsses || (log_frames && !evs)) return -2;
    reset_tables();
    /* Hand the radio back to the Wi-Fi stack: a stop/start reloads the PHY's stock receive setup, undoing the SDR's
     * test-mode overrides (manual gain, TX path off, per-LO DC tables). No transmit calibration is repeated. */
    int64_t t0 = esp_timer_get_time();
    esp_wifi_set_promiscuous(false);
    esp_wifi_stop();
    if (!configured) {
#if CONFIG_SOC_WIFI_SUPPORT_5G
        esp_wifi_set_country_code("US", false);
        esp_wifi_set_band_mode(WIFI_BAND_MODE_AUTO);
#endif
        configured = true;
    }
    esp_err_t err = esp_wifi_start();
    if (err == ESP_OK) {
        esp_wifi_set_ps(WIFI_PS_NONE);
        wifi_promiscuous_filter_t f = {.filter_mask = WIFI_PROMIS_FILTER_MASK_ALL};
        esp_wifi_set_promiscuous_filter(&f);
        wifi_promiscuous_filter_t cf = {.filter_mask = WIFI_PROMIS_CTRL_FILTER_MASK_ALL};
        esp_wifi_set_promiscuous_ctrl_filter(&cf);
        esp_wifi_set_promiscuous_rx_cb(rx_cb);
        esp_wifi_set_promiscuous(true);
        err = esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    }
    if (switch_us) *switch_us = (unsigned)(esp_timer_get_time() - t0);
    if (err != ESP_OK) { esp_wifi_set_promiscuous_rx_cb(NULL); return (int)err; }
    logging = log_frames;
    active = true;
    return 0;
}

void wifi_sniff_stop(void) {
    active = false; logging = false;
    esp_wifi_set_promiscuous_rx_cb(NULL);
    vTaskDelay(pdMS_TO_TICKS(5));                                    /* let a callback in flight finish */
}

void wifi_sniff_release(void (*restore_sdr)(void)) {
    /* Back to the state the SDR expects (Wi-Fi running in promiscuous mode, no callback); the SDR redoes its
     * receive-only calibration and gain overrides before the next capture. */
    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
    restore_sdr();
}

unsigned wifi_sniff_frames(void) { return t_frames; }
void wifi_sniff_log(bool on) { logging = on && evs; }

void wifi_sniff_report_events(void) {
    char h[160];
    for (unsigned i = 0; i < n_ev; i++) {
        frame_ev_t *e = &evs[i];
        snprintf(h, sizeof(h), "F %lld %lu %d %u %u %u %04x " MACF " " MACF "\n", (long long)e->cb_us, (unsigned long)e->rx_ts, e->rssi,
                 e->fmt, e->state, e->len, e->fc, MACA(e->a1), MACA(e->a2));
        reply(h);
    }
    snprintf(h, sizeof(h), "FEND %u %u\n", n_ev, drop_ev);
    reply(h);
}

static void report_tables(unsigned switch_us) {
    char h[200];
    snprintf(h, sizeof(h), "T %lu %lu %lu %lu %lu %lu %ld %lu %lu %lu %lu %lu %lu %lu %lu %u\n",
             (unsigned long)t_frames, (unsigned long)t_mgmt, (unsigned long)t_ctrl, (unsigned long)t_data, (unsigned long)t_bad,
             (unsigned long)t_bytes, t_frames ? (long)(nf_sum / (int32_t)t_frames) : 0L,
             (unsigned long)fmt_count[0], (unsigned long)fmt_count[1], (unsigned long)fmt_count[2], (unsigned long)fmt_count[3],
             (unsigned long)fmt_count[4], (unsigned long)fmt_count[5], (unsigned long)fmt_count[6], (unsigned long)fmt_count[7], switch_us);
    reply(h);
    for (unsigned i = 0; i < n_bss; i++) {
        bss_entry_t *b = &bsses[i];
        unsigned seen = b->rx_n ? b->rx_n : 1;
        char ssid[65] = "-";
        if (b->ssid_len) for (unsigned k = 0; k < b->ssid_len; k++) snprintf(ssid + 2 * k, 3, "%02x", (uint8_t)b->ssid[k]);
        snprintf(h, sizeof(h), "B " MACF " %d %d %lu %u %u %u %u %u %u %d %u %s\n", MACA(b->bssid), b->rssi_max,
                 (int)(b->rssi_sum / (int32_t)seen), (unsigned long)b->beacons, b->ds_ch, b->ht_second, b->vht_width, b->vht_c0,
                 b->vht_c1, b->he, b->color, b->interval, ssid);
        reply(h);
    }
    for (unsigned i = 0; i < n_addr; i++) {
        addr_entry_t *a = &addrs[i];
        char bs[18] = "-";
        if (a->has_bssid) snprintf(bs, sizeof(bs), MACF, MACA(a->bssid));
        snprintf(h, sizeof(h), "A " MACF " %s %lu %lu %d %d %u %u %d %c %u\n", MACA(a->mac), bs, (unsigned long)a->frames,
                 (unsigned long)a->bytes, a->rssi_max, (int)(a->rssi_sum / (int32_t)a->frames), a->retries, a->fmt_mask, a->color,
                 a->role, a->max_bw);
        reply(h);
    }
}

bool wifi_sniff_command(const char *line, void (*restore_sdr)(void)) {
    if (strncmp(line, "SNIFF ", 6)) return false;
    unsigned ch, ms; char extra;
    if (sscanf(line, "SNIFF %u %u %c", &ch, &ms, &extra) != 2 || !valid_channel(ch) || ms < 50 || ms > 10000) {
        reply("ERR sniff_args\n");
        return true;
    }
    unsigned switch_us = 0;
    char h[200];
    int err = wifi_sniff_begin(ch, false, &switch_us);
    if (err) {
        snprintf(h, sizeof(h), "ERR sniff_channel %d\n", err);
        reply(h);
        wifi_sniff_release(restore_sdr);
        return true;
    }
    snprintf(h, sizeof(h), "SNIFF %u %u\n", ch, ms);
    reply(h);
    vTaskDelay(pdMS_TO_TICKS(ms));
    wifi_sniff_stop();

    report_tables(switch_us);
    snprintf(h, sizeof(h), "SNIFFEND 0 %u %u\n", drop_addr, drop_bss);
    reply(h);
    wifi_sniff_release(restore_sdr);
    return true;
}

/* SURVEY <ms_per_channel> <ch,ch,...>: one handover to the Wi-Fi stack, then listen on each channel in turn.
 * Reply: "SURVEY <n> <ms>", then per channel "SV <ch> <ms>" + the T/B/A lines of SNIFF + "SVEND <ch> <a_dropped> <b_dropped>",
 * then "SURVEYEND <n>". A channel the stack refuses reports "SVERR <ch> <err>". */
bool wifi_survey_command(const char *line, void (*restore_sdr)(void)) {
    if (strncmp(line, "SURVEY ", 7)) return false;
    unsigned ms, chs[64], n = 0;
    const char *p = line + 7;
    char *end;
    ms = (unsigned)strtoul(p, &end, 10);
    if (end == p || ms < 30 || ms > 5000) { reply("ERR survey_args\n"); return true; }
    p = end;
    while (*p == ' ') p++;
    while (*p && n < 64) {
        unsigned ch = (unsigned)strtoul(p, &end, 10);
        if (end == p) break;
        if (valid_channel(ch)) chs[n++] = ch;
        p = end;
        while (*p == ',' || *p == ' ') p++;
    }
    if (!n) { reply("ERR survey_args\n"); return true; }
    unsigned switch_us = 0;
    char h[96];
    int err = wifi_sniff_begin(chs[0], false, &switch_us);
    if (err) {
        snprintf(h, sizeof(h), "ERR survey_start %d\n", err);
        reply(h);
        wifi_sniff_release(restore_sdr);
        return true;
    }
    snprintf(h, sizeof(h), "SURVEY %u %u\n", n, ms);
    reply(h);
    for (unsigned i = 0; i < n; i++) {
        active = false;
        vTaskDelay(pdMS_TO_TICKS(2));
        reset_tables();
        int64_t t0 = esp_timer_get_time();
        esp_err_t e = i ? esp_wifi_set_channel(chs[i], WIFI_SECOND_CHAN_NONE) : ESP_OK;
        unsigned hop_us = (unsigned)(esp_timer_get_time() - t0) + (i ? 0 : switch_us);
        if (e != ESP_OK) { snprintf(h, sizeof(h), "SVERR %u %d\n", chs[i], (int)e); reply(h); continue; }
        active = true;
        vTaskDelay(pdMS_TO_TICKS(ms));
        active = false;
        vTaskDelay(pdMS_TO_TICKS(2));
        snprintf(h, sizeof(h), "SV %u %u\n", chs[i], ms);
        reply(h);
        report_tables(hop_us);
        snprintf(h, sizeof(h), "SVEND %u %u %u\n", chs[i], drop_addr, drop_bss);
        reply(h);
    }
    wifi_sniff_stop();
    snprintf(h, sizeof(h), "SURVEYEND %u\n", n);
    reply(h);
    wifi_sniff_release(restore_sdr);
    return true;
}

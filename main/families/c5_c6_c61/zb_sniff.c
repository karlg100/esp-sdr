/* 802.15.4 survey for the C5: promiscuous IEEE 802.15.4 receive, channel by channel. See zb_sniff.h.
 * Receive-only: promiscuous mode turns off address filtering and automatic ACKs, and nothing here calls transmit. */
#include "zb_sniff.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "esp_attr.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "esp_heap_caps.h"
#include "esp_ieee802154.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "burst_serial.h"

#define MAX_FR 160         /* frames kept per channel */
#define KEEP 40            /* PSDU bytes kept per frame */

typedef struct {
    int64_t ts;
    int8_t rssi;
    uint8_t lqi, len, n;
    uint8_t b[KEEP];
} zframe_t;

static zframe_t *frs;                          /* heap: static data must stay below the RF dump bank */
static volatile unsigned n_fr, drop_fr;
static volatile bool listening;
static volatile int ed_dbm, ed_done;

static void reply(const char *s) { burst_serial_send(s, strlen(s)); }

/* Driver callbacks (ISR context; override the driver's weak defaults). */
void IRAM_ATTR esp_ieee802154_receive_done(uint8_t *data, esp_ieee802154_frame_info_t *info) {
    if (listening) {
        unsigned i = n_fr;
        if (i < MAX_FR) {
            zframe_t *f = &frs[i];
            unsigned len = data[0];                      /* PHR: PSDU length including the 2-byte FCS */
            unsigned n = len > 2 ? len - 2 : 0;
            if (n > KEEP) n = KEEP;
            f->ts = (int64_t)info->timestamp; f->rssi = info->rssi; f->lqi = info->lqi; f->len = (uint8_t)len; f->n = (uint8_t)n;
            for (unsigned k = 0; k < n; k++) f->b[k] = data[1 + k];
            n_fr = i + 1;
        } else {
            drop_fr++;
        }
    }
    esp_ieee802154_receive_handle_done(data);
}

void IRAM_ATTR esp_ieee802154_energy_detect_done(int8_t power) {
    ed_dbm = power;
    ed_done = 1;
}

static int energy_detect(unsigned symbols) {
    ed_done = 0;
    if (esp_ieee802154_energy_detect(symbols) != ESP_OK) return -127;
    for (int i = 0; i < 40 && !ed_done; i++) vTaskDelay(pdMS_TO_TICKS(1));
    return ed_done ? ed_dbm : -127;
}

bool zb_survey_command(const char *line, void (*restore_sdr)(void)) {
    if (strncmp(line, "ZSURVEY ", 8)) return false;
    unsigned ms, chs[16], n = 0;
    const char *p = line + 8;
    char *end;
    ms = (unsigned)strtoul(p, &end, 10);
    if (end == p || ms < 20 || ms > 5000) { reply("ERR zsurvey_args\n"); return true; }
    p = end;
    while (*p == ' ') p++;
    while (*p && n < 16) {
        unsigned ch = (unsigned)strtoul(p, &end, 10);
        if (end == p) break;
        if (ch >= 11 && ch <= 26) chs[n++] = ch;
        p = end;
        while (*p == ',' || *p == ' ') p++;
    }
    if (!n) { reply("ERR zsurvey_args\n"); return true; }
    if (!frs) frs = heap_caps_calloc(MAX_FR, sizeof(zframe_t), MALLOC_CAP_8BIT);
    if (!frs) { reply("ERR zsurvey_nomem\n"); return true; }

    char h[200];
    /* Hand the radio over: stop the Wi-Fi stack (the SDR's PHY owner), bring up the 802.15.4 MAC. */
    int64_t t0 = esp_timer_get_time();
    esp_wifi_set_promiscuous(false);
    esp_wifi_stop();
    esp_err_t err = esp_ieee802154_enable();
    if (err == ESP_OK) {
        esp_ieee802154_set_promiscuous(true);
        esp_ieee802154_set_coordinator(false);
        esp_ieee802154_set_rx_when_idle(true);
        err = esp_ieee802154_set_channel((uint8_t)chs[0]);
    }
    unsigned switch_us = (unsigned)(esp_timer_get_time() - t0);
    if (err != ESP_OK) {
        snprintf(h, sizeof(h), "ERR zsurvey_start %d\n", (int)err);
        reply(h);
    } else {
        snprintf(h, sizeof(h), "ZSURVEY %u %u %u\n", n, ms, switch_us);
        reply(h);
        for (unsigned i = 0; i < n; i++) {
            listening = false;
            n_fr = drop_fr = 0;
            esp_err_t e = esp_ieee802154_set_channel((uint8_t)chs[i]);
            if (e != ESP_OK) { snprintf(h, sizeof(h), "ZCERR %u %d\n", chs[i], (int)e); reply(h); continue; }
            /* Energy detect for 4 ms at the start and the end of the dwell, listening in between. */
            int ed = energy_detect(250);
            listening = true;
            esp_ieee802154_receive();
            unsigned wait = ms > 10 ? ms - 10 : ms;
            vTaskDelay(pdMS_TO_TICKS(wait));
            listening = false;
            int ed2 = energy_detect(250);
            if (ed2 > ed) ed = ed2;
            snprintf(h, sizeof(h), "ZC %u %u %d %u %u\n", chs[i], ms, ed, n_fr, drop_fr);
            reply(h);
            unsigned nf = n_fr;
            for (unsigned k = 0; k < nf; k++) {
                zframe_t *f = &frs[k];
                int o = snprintf(h, sizeof(h), "Z %lld %d %u %u ", (long long)f->ts, f->rssi, f->lqi, f->len);
                for (unsigned j = 0; j < f->n && o < (int)sizeof(h) - 4; j++) o += snprintf(h + o, sizeof(h) - o, "%02x", f->b[j]);
                if (!f->n) o += snprintf(h + o, sizeof(h) - o, "-");
                snprintf(h + o, sizeof(h) - o, "\n");
                reply(h);
            }
            snprintf(h, sizeof(h), "ZCEND %u\n", chs[i]);
            reply(h);
        }
    }
    listening = false;
    /* Stop receiving before the MAC's clock is gated: a MAC left in RX keeps requesting the shared RF front end, and the
     * Wi-Fi receiver then hears nothing until the next reset. */
    esp_ieee802154_set_rx_when_idle(false);
    esp_ieee802154_sleep();
    vTaskDelay(pdMS_TO_TICKS(2));
    esp_ieee802154_disable();
    /* Back to the state the SDR expects: Wi-Fi started in promiscuous mode without a callback, on channel 1. */
    esp_wifi_start();
    esp_wifi_set_ps(WIFI_PS_NONE);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
    restore_sdr();
    snprintf(h, sizeof(h), "ZSURVEYEND %u\n", n);
    reply(h);
    return true;
}

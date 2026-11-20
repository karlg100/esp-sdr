#pragma once
#include <stdbool.h>

/* Air-scanner modem layer: listen with the chip's own Wi-Fi receiver (promiscuous mode) on one channel for a
 * while, aggregate what it hears on chip, and report it. The radio is handed back to the SDR afterwards.
 *
 *   SNIFF <channel> <milliseconds>      channel 1-14 or 36-177, 50-10000 ms
 *
 * Reply (text lines, then SNIFFEND):
 *   SNIFF <channel> <ms>
 *   T <frames> <mgmt> <ctrl> <data> <bad_fcs> <bytes> <noise_floor_avg> <fmt counts: 11b 11ag ht vht he_su he_mu he_er he_tb> <busy_us> <switch_us>
 *   B <bssid> <rssi_max> <rssi_avg> <beacons> <ds_channel> <ht_second> <vht_width> <vht_c0> <vht_c1> <he> <color> <interval_tu> <ssid_hex|->
 *   A <addr> <bssid|-> <frames> <bytes> <rssi_max> <rssi_avg> <retries> <fmt_mask> <color|-1> <role> <max_bw>
 *   SNIFFEND <status> <addresses_dropped> <bss_dropped>
 *
 * role: a = the address is the BSSID (an AP), s = a station sending to/from an AP, m = management only, x = other.
 * fmt_mask bits follow wifi_rx_bb_format_t (bit 0 = 11b, 1 = 11a/g, 2 = HT, 3 = VHT, 4 = HE SU, 5 = HE MU, ...).
 * max_bw (MHz) is the widest bandwidth announced in the frames' own PHY headers (HT/VHT/HE), 0 if unknown.
 */
bool wifi_sniff_command(const char *line, void (*restore_sdr)(void));

/* Building blocks for combined modes (CAPSNIFF in receiver.c): start listening on a channel with the PHY in its
 * stock Wi-Fi setup (optionally logging every frame with timestamps), stop listening, give the radio back. */
int wifi_sniff_begin(unsigned ch, bool log_frames, unsigned *switch_us);   /* 0 = ok, -1 bad channel, -2 no memory, else esp_err */
void wifi_sniff_stop(void);
void wifi_sniff_release(void (*restore_sdr)(void));
unsigned wifi_sniff_frames(void);
void wifi_sniff_log(bool on);          /* switch the per-frame event log on/off (after a begin with log_frames) */
void wifi_sniff_report_events(void);   /* "F <cb_us> <rx_ts> <rssi> <fmt> <rx_state> <len> <fc> <addr1> <addr2>" ... "FEND <n> <dropped>" */

/* SURVEY <ms_per_channel> <ch,ch,...> (up to 64 channels): one handover, then each channel in turn; see wifi_sniff.c. */
bool wifi_survey_command(const char *line, void (*restore_sdr)(void));

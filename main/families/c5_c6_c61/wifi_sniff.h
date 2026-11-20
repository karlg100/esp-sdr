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

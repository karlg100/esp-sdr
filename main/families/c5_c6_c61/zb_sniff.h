#pragma once
#include <stdbool.h>

/* Air-scanner 802.15.4 layer (Zigbee / Thread / Matter-over-Thread): listen with the chip's own IEEE 802.15.4
 * receiver in promiscuous mode, never transmitting (no ACKs, no beacon requests), then hand the radio back to the SDR.
 *
 *   ZSURVEY <ms_per_channel> <ch,ch,...>     channels 11-26, 20-5000 ms each
 *
 * Reply:
 *   ZSURVEY <n> <ms>
 *   per channel:
 *     ZC <ch> <ms> <ed_dbm> <frames> <dropped>       energy detect (max over the dwell's ED windows), frame count
 *     Z <ts_us> <rssi> <lqi> <len> <psdu_hex>        one per frame; psdu is the MAC frame (without FCS), first 40 bytes
 *     ZCEND <ch>
 *   ZSURVEYEND <n>
 * A channel the driver refuses reports "ZCERR <ch> <err>". Only frames with a good FCS are delivered by the hardware.
 */
bool zb_survey_command(const char *line, void (*restore_sdr)(void));

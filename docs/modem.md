# Modem layer: borrowing the chip's own receivers (C5, C6, C61)

Between captures, the SDR firmware can hand the radio back to the chip's own **Wi-Fi receiver**. On the ESP32-C5 it can
also hand it to the **IEEE 802.15.4 receiver**. The receiver listens for a while and the firmware reports what it decoded,
then the radio goes back to the SDR. Raw spectrum shows *that* something is on a channel; this shows *what* it is:
- network names (SSIDs) and BSSIDs;
- the channel width each AP announces;
- BSS colour and client addresses;
- signal strength in dBm;
- Zigbee and Thread PAN IDs and device addresses.

Everything here is **receive-only**:
- Wi-Fi runs in promiscuous mode with no interface configured, so it never associates, probes or acknowledges.
- 802.15.4 runs in promiscuous mode, which turns off automatic ACKs, and the code never calls transmit.

| Command | Chips | `CAPS` flag | What it does |
| --- | --- | --- | --- |
| `SNIFF <ch> <ms>` | C5, C6, C61 | `SNIFF` | Listen on one Wi-Fi channel and report networks, addresses and totals. |
| `SURVEY <ms> <ch,ch,...>` | C5, C6, C61 | `SURVEY` | Like `SNIFF`, but hop a list of channels with a single handover. |
| `CAPSNIFF <ch> <caps> <rate> [samples]` | C5, C6, C61 | `CAPSNIFF` | Experimental: raw I/Q captures *while* the Wi-Fi modem decodes, plus every frame with timestamps. |
| `ZSURVEY <ms> <ch,ch,...>` | C5 | `ZSURVEY` | Listen on 802.15.4 channels 11–26 in turn and report every valid frame. |

Check `CAPS` before using a command; older firmware and other chips don't have them. Hardware testing so far covers the
**ESP32-C5** (Seeed XIAO ESP32-C5) only. The Wi-Fi commands also build for the C6 and C61 but haven't been run on them.

## Using it

1. Open the port and `SYNC` as usual. Check `CAPS` for the flag.
2. Send the command. The reply is a block of text lines that ends with a fixed end line (`SNIFFEND`, `SURVEYEND`,
   `CAPSNIFFEND`, `ZSURVEYEND`). Read up to that line before sending anything else.
3. Afterwards, **re-send your receiver settings** (`GAIN MANUAL n`, `BANDWIDTH`, `FREQ`).
   - The handover reloads the PHY's stock setup.
   - The firmware redoes its receive-only calibration on the next capture, but gain and filter choices are the client's.
4. Command lines are limited to 127 characters. To survey many channels, split the list over several `SURVEY` commands.

Typical cost:
- A handover takes about 5 ms for Wi-Fi and about 2 ms for 802.15.4.
- Hopping to the next channel takes about 1 ms.
- A full survey of 2.4 GHz channels 1–11 plus 25 5-GHz channels at 250 ms each takes about 9 s.

### Example (Python, pyserial)

```python
import serial
s = serial.Serial("/dev/ttyACM0", 2000000, timeout=1)   # native USB ignores the baud rate
s.dtr = s.rts = True                                     # C5/C6 USB-Serial/JTAG: keep these asserted, or the chip resets

def block(cmd, end):
    s.write((cmd + "\n").encode())
    lines = []
    while True:
        ln = s.readline().decode().strip()
        lines.append(ln)
        if ln.startswith(end) or ln.startswith("ERR"):
            return lines

for ln in block("SURVEY 250 1,6,11,36,149", "SURVEYEND"):
    if ln.startswith("B "):
        f = ln.split()
        ssid = bytes.fromhex(f[13]).decode(errors="replace") if f[13] != "-" else "(hidden)"
        print(f"{f[1]}  ch {f[5]:>3}  {f[2]} dBm  {ssid}")

for ln in block("ZSURVEY 400 11,15,20,25,26", "ZSURVEYEND"):
    if ln.startswith(("ZC", "Z ")):
        print(ln)

s.write(b"GAIN MANUAL 65\n"); s.readline()   # back to SDR settings
```

## `SNIFF` and `SURVEY` (Wi-Fi)

`SNIFF <channel> <ms>` takes channel 1–14 or a 5 GHz 20 MHz channel (36–64, 100–144, 149–177), and 50–10000 ms. It replies:

```
SNIFF <channel> <ms>
T <frames> <mgmt> <ctrl> <data> <bad_fcs> <bytes> <noise_floor> <n_11b> <n_11ag> <n_ht> <n_vht> <n_he_su> <n_he_mu> <n_he_er> <n_he_tb> <switch_us>
B <bssid> <rssi_max> <rssi_avg> <beacons> <ds_channel> <ht_second> <vht_width> <vht_c0> <vht_c1> <he> <color> <interval_tu> <ssid_hex|->
...
A <addr> <bssid|-> <frames> <bytes> <rssi_max> <rssi_avg> <retries> <fmt_mask> <color> <role> <max_bw>
...
SNIFFEND 0 <addresses_dropped> <bss_dropped>
```

- **`T`**: totals for the dwell. `noise_floor` is the modem's own average noise-floor estimate in dBm (20 MHz). It's a
  useful absolute reference for calibrating the SDR's relative levels.
- **`B`**: one line per BSS heard beaconing (or sending probe responses).
  - `ds_channel` is the primary channel from the DS Parameter Set or HT Operation element.
  - `ht_second` is the HT secondary-channel offset: 1 = above, 3 = below, 0 = none.
  - `vht_width`, `vht_c0` and `vht_c1` come from the VHT Operation element: width 1 = 80 MHz, 2 = 160 MHz, with the centre channel segments.
  - `he` = 1 if the HE Capabilities/Operation element is present. `color` is the HE BSS colour, or -1.
  - The SSID is hex-encoded; `-` means hidden.
- **`A`**: one line per transmitter address.
  - `role` is `a` (the address is a BSSID), `s` (a station talking to that BSSID), `m` (management only) or `x` (other).
  - `fmt_mask` bits follow `wifi_rx_bb_format_t`: bit 0 = 11b, 1 = 11a/g, 2 = HT, 3 = VHT, 4 = HE SU, 5 = HE MU, and so on.
  - `max_bw` is the widest bandwidth (MHz) announced in the PHY headers of its frames, or 0 if unknown.
- Up to 128 addresses and 48 BSSs are kept per dwell. The `SNIFFEND` counters say how many didn't fit.

`SURVEY <ms> <ch,ch,...>` takes 30–5000 ms per channel and up to 64 channels in one line. It hands over once, then:

```
SURVEY <n> <ms>
SV <ch> <ms>
T ... / B ... / A ...        (as for SNIFF; switch_us is the hop time)
SVEND <ch> <addresses_dropped> <bss_dropped>
...
SURVEYEND <n>
```

A channel the Wi-Fi stack refuses reports `SVERR <ch> <esp_err>`. With the country code the firmware sets (US), channels
12–13 and 169–177 are refused (258, `ESP_ERR_INVALID_ARG`).

The modem decodes 20 and 40 MHz PPDUs only. An 80 or 160 MHz BSS is still found by its beacons, which are sent in 20 MHz,
and its width is read from the VHT Operation element.

## `CAPSNIFF` (experimental)

`CAPSNIFF <channel> <captures> <rate_code> [samples]` starts the Wi-Fi modem on a channel, with its stock PHY setup and
hardware AGC. While the modem decodes, it takes `<captures>` raw I/Q captures with the stock dump engine, without the
SDR's gain and filter overrides. Each capture is reported as `CS <i> <start_us> <elapsed_us> <frames_so_far> <ok> <frames_during>`,
followed by the usual `DATA` reply (IQ8). Then every frame the modem heard is reported as:

```
F <callback_us> <rx_timestamp_us> <rssi> <format> <rx_state> <len> <frame_control> <addr1> <addr2>
...
FEND <n> <dropped>
CAPSNIFFEND
```

`rx_timestamp_us` runs on the MAC clock. Within one `CAPSNIFF` run it differs from `esp_timer` (`start_us`) by a
constant offset, so bursts in the I/Q can be matched to decoded frames. Estimate the offset from the frames that land
inside each capture. Because the hardware AGC is active, sample levels aren't comparable between captures.

## `ZSURVEY` (802.15.4: Zigbee, Thread, Matter-over-Thread; ESP32-C5)

`ZSURVEY <ms> <ch,ch,...>` takes 20–5000 ms per channel, on 802.15.4 channels 11–26 (2405 + 5·(ch − 11) MHz). It stops
Wi-Fi, brings up the 802.15.4 MAC in promiscuous mode, and hops the list:

```
ZSURVEY <n> <ms> <switch_us>
ZC <ch> <ms> <ed_dbm> <frames> <dropped>
Z <timestamp_us> <rssi> <lqi> <psdu_length> <psdu_hex>
...
ZCEND <ch>
...
ZSURVEYEND <n>
```

- `ed_dbm` is the higher of two 4 ms energy-detect readings, one at the start and one at the end of the dwell. Wi-Fi on
  an overlapping channel shows up here.
- The hardware only delivers frames with a valid FCS.
  - `psdu_hex` holds the first 40 bytes of the MAC frame, without the FCS, so it starts with the frame control field.
    That covers the MAC header and the start of the NWK or 6LoWPAN header: enough to tell PAN ID, addresses, frame
    type, and Zigbee from Thread.
  - Payloads are normally encrypted at the network layer anyway.
- Up to 160 frames are kept per channel; `dropped` counts the rest.
- A channel the driver refuses reports `ZCERR <ch> <esp_err>`.

802.15.4 traffic is sparse: a Zigbee network may send only a few frames a second. A quick pass at 200–400 ms per channel
finds busy networks. Then dwell 1–2 s on the channels where something was heard.

Telling the stacks apart from the payload start:
- **Zigbee:** a NWK frame control with protocol version 2 (`payload[0] & 0x3c == 0x08`).
- **Thread:** a 6LoWPAN IPHC header (`payload[0] & 0xe0 == 0x60`), with MLE advertisements on UDP port 19788 (0x4d4c).

### Firmware notes (C5)

- The 802.15.4 driver adds static RAM, and the C5's static sections must still end below the RF dump bank (`sram_guard.ld`). To make room:
  - `sdkconfig.defaults.esp32c5` trims the driver (4 RX buffers, pending table 1, no timing optimisation).
  - It drops Wi-Fi features this firmware never uses (SoftAP, WPA3, Enterprise).
  - It moves a few IRAM-only placements to flash.
  - `spectrum.c` allocates its FFT buffer from the heap on the C5.
- Software coexistence is off, because the two radios are only used one after the other.
- The PHY cert-test library, which the SDR needs, carries its own `ieee802154_*` test routines. The C5 link allows
  multiple definitions so that the real driver, which comes first in link order, wins. The test-mode copies are never called.
- The MAC is put to sleep before it's disabled. A MAC whose clock is gated while it's still receiving keeps the shared RF
  front end, and the Wi-Fi receiver then hears nothing until reset.
- The C6 also has an 802.15.4 radio. It needs the same static-RAM trimming before `ZSURVEY` will link there.

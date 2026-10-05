# AWUS1900 (RTL8814AU) on macOS: Feasibility and Project Plan

Target: Apple Silicon Mac (dev machine: M1 Pro/Max, macOS 15.1.1 Sequoia; also verify on macOS 26 Tahoe). Goals: internet client AND monitor mode + injection.
Adapter: Alfa AWUS1900, Realtek RTL8814AU, USB ID 0bda:8813, 4x4 802.11ac.

## 1. Verdict

A conventional macOS driver (kext or DriverKit) for this adapter is not a realistic target on Apple Silicon.
A userspace driver over libusb is realistic, and has been shown to work for the sibling chip RTL8812AU.
That is the recommended path ("Track A"). An IO80211 kext ("Track B") is a research side-quest only.

## 2. Why not a "real" driver

- Apple's Wi-Fi driver interface (IO80211Family, plus IOSkywalkFamily) is private and undocumented.
  Third-party drivers such as itlwm/AirportItlwm and Airport_RTW88 rely on reverse-engineered headers
  (OpenIntelWireless/itlwm `include/Airport`, acidanthera/MacKernelSDK) and must be rebuilt as macOS changes.
- Those projects are PCIe-based and run on Hackintosh/OpenCore setups. Airport_RTW88 explicitly excludes USB.
  I found no third-party IO80211 driver working on Apple Silicon.
- DriverKit offers USBDriverKit and Ethernet-only NetworkingDriverKit. There is no 802.11 family.
- Kexts on Apple Silicon need Reduced Security plus user kext approval. Realtek's own macOS driver is Intel-only.

## 3. Track A: userspace driver (recommended)

Monitor mode and injection are chip functions: program registers, then move raw 802.11 frames over USB bulk
endpoints. No OS Wi-Fi integration is required. No kext, no SIP changes, no signing.
Internet access is bridged through a `utun` interface (shows as a tunnel, not "Wi-Fi", in System Settings).

Base project: janlueders/rtl8812au-macos (GPL-2.0, ~12k lines C, libusb). Verified on M2 Pro, macOS 26.6.2.
It already has: USB register I/O, power-on, firmware load, efuse, MAC/BB/RF init, calibration, TX power, RX with
radiotap, TX with descriptors, CCMP, WPA2-PSK, utun bridge, pcap capture, Wireshark extcap.
Not yet there: 5 GHz and WPA3 in client mode.

### Reference material (cloned into ./refs)

| Reference | Role | License |
|---|---|---|
| lwfinger/rtw88 (`rtw8814a.c` 2.3k lines, `rtw8814a_table.c` 24k lines, `rtw8814au.c`) | Primary reference: modern, clean 8814A bring-up, PHY tables, USB IDs. Also in mainline Linux since 6.15. | GPL-2.0 OR BSD-3-Clause |
| `rtw88/firmware/rtw8814a_fw.bin` (68 KB) | Firmware blob | Realtek firmware license, check redistribution terms |
| morrownr/8814au, aircrack-ng/rtl8814au | Older vendor-derived drivers: injection behavior, monitor RCR settings, 8814-specific quirks | GPL-2.0 |
| janlueders/rtl8812au-macos | macOS/libusb scaffolding, test tools, utun daemon | GPL-2.0 |
| libusb darwin backend notes | Device capture / exclusive-access behavior on macOS | LGPL |

Licensing default (2026-10-05, pending confirmation of whether the code will be shared): **clean port from rtw88, BSD-3-Clause.** Port only from rtw88 (dual-licensed).
Do not copy code from janlueders/rtl8812au-macos, morrownr/8814au or aircrack-ng/rtl8814au (all GPL-2.0). They
may be read for behavior and quirks, but every line we write must come from rtw88 or be our own. Firmware needs a
separate redistribution check: if it can't be redistributed, the install step should fetch it instead.
Note: `./refs` was cloned in the Linux workspace and is not present on the Mac yet.

Other docs to collect: Realtek RTL8814AU datasheet (usually under NDA, so we rely on the Linux sources as the
register reference), libusb API docs, Apple utun / SystemConfiguration docs, IEEE 802.11 radiotap spec.

## 4. Phases and milestones (each independently testable on your Mac)

0. Setup. Connect a folder on your Mac, install Xcode CLT and libusb. Confirm 0bda:8813 enumerates and no Apple
   driver claims it (`ioreg`, `system_profiler SPUSBDataType`). Scaffold the repo (clean port, no fork).
   **Done 2026-10-05**, see "Phase 0 results" below.
1. Bring-up on 8814A. USB control I/O, power-on sequence, chip ID, efuse (real MAC), firmware download.
   Done when firmware reports running. **Done 2026-10-05**, see "Phase 1 results". This is the first chip-specific port: 8814A differs from 8812A in its
   HALMAC-style init, 4 TX/RX chains, firmware, and PHY/RF tables.
2. MAC/BB/RF init and channels on 2.4 and 5 GHz, calibration. Done when channel switching works on both bands.
3. RX path and monitor mode. Bulk-IN parsing for the 8814A descriptor format, radiotap, pcap output.
   Done when tcpdump/Wireshark decode beacons and data frames.
4. TX path and injection. 8814A TX descriptor, rate/power handling. Done when a probe request elicits a response.
5. Station mode. WPA2-PSK, CCMP, DHCP, utun bridge, 5 GHz. Done when sustained ping with 0% loss.
6. WPA3/SAE, USB3 mode switching for throughput, power/thermal handling on a 4x4 chip.
7. Packaging. Launchd daemon with a privileged helper, small menu-bar app, install/uninstall, docs.
8. Optional Track B research. IO80211 integration on an Intel Mac with reduced security, to get a native Wi-Fi
   menu entry. High effort, fragile across macOS releases, not recommended before phase 7.

## 5. Risks

- Hardware-in-the-loop debugging is slow. The 8814AU is also reported to be one of the buggier Realtek drivers.
- Linux vendor driver (older HAL) has known injection and USB3 issues; rtw88's 8814AU support is newer and
  still being tested.
- macOS USB access: libusb on macOS cannot detach kernel drivers without entitlements. This works for us only
  because no Apple driver binds this vendor-specific device. Re-verify on each macOS update.
- Regulatory/TX power: 4x4 chip with external PAs; use efuse-calibrated limits and respect local rules.
- Scope: monitor/injection tooling should be used only on networks you own or are authorized to test.

## 6. How the work is split

Claude Code runs directly on the dev Mac with the adapter attached, so it writes, builds and tests against
the hardware itself. Each phase ends with a hardware test whose output is recorded here.

## 7. Phase 0 results (2026-10-05)

- Toolchain: Xcode at `/Applications/Xcode.app`, Homebrew libusb 1.0.30, pkgconf 3.0.7. arm64.
- Enumeration: 0bda:8813 "802.11ac NIC", bcdUSB 2.00, 480 Mbit/s, behind two VIA USB2 hubs. USB3 is
  untested until it's plugged directly into the Mac (needed for phase 6).
- Binding: only `AppleUSBHostCompositeDevice` is attached; no driver on interface 0. Chrome and Brave keep
  WebUSB user clients open on the device. They don't block the claim, but quit them if transfers misbehave.
- Interface 0: class ff/ff/ff, EPs 0x81 bulk IN, 0x02/0x03/0x04 bulk OUT, 0x85 interrupt IN (512/64 B).
- `usbprobe --regs`: claim OK. 0x00F0=0x044411b5 (SYS_CFG1), 0x00F4=0x1650dfc5, 0x00FC=0x80000008,
  0x0000=0x721caff1. Vendor-request register reads work without root.

## 8. Phase 1 results (2026-10-05)

`./rtlinit -v --fw refs/rtw88/firmware/rtw8814a_fw.bin` on the AWUS1900 (USB2, behind hubs):

- MAC power-on via the rtw88 8814A power sequence works (`src/mac.c`, `src/pwrseq_8814a.h` generated from rtw88).
- Chip info: SYS_CFG1 = 0x044411b5, cut 1.
- Efuse decodes: MAC `00:c0:ca:b6:9f:5b`, VID:PID 0bda:8813 (matches USB descriptors).
- Firmware v33.6 (68320 B) downloads and starts. Path: 3081 WCPU, not the 8051 "legacy" path. Each 4 KB chunk goes
  through the beacon-queue reserved page (bulk OUT EP 0x02, 40-byte TX descriptor), then DDMA copies it to
  DMEM/IMEM. Checksums pass and the FW_READY flags are set.
- Note: the earlier plan assumed HALMAC-style init with the 8051 path. rtw88 treats the 8814A as a 3081 chip.

Code layout: `src/dev.c` (USB register I/O), `src/mac.c` (power, efuse), `src/fw.c` (firmware), `src/rtlinit.c` (tool).
All of it ported from rtw88 only (BSD-3-Clause path). Firmware license still needs checking before redistribution.

## 9. Next steps

1. Phase 2: MAC init (queue/page config, rtw8814a_mac_init), PHY tables (rtw8814a_table.c: mac/bb/agc/rf, ~24k lines,
   to be converted to C arrays by script), RF init, channel switch for 2.4 and 5 GHz, IQK calibration.
2. Check the firmware redistribution terms.

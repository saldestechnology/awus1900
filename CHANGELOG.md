# Changelog

## 2026-10-05

### Added

- Extended the RTL8814AU macOS userspace driver with MAC/PHY initialization, 2.4 and 5 GHz channel
  selection, 20/40/80 MHz configuration, IQK calibration, and monitor-mode radiotap pcap capture.
- Added `rtlprobe` for one explicitly enabled Probe Request, plus receive-only `rtlscan` for beacon
  and Probe Response discovery and advertised WPA/SAE-H2E capabilities.
- Added `rtljoin` station support for WPA2-PSK/CCMP and WPA3-SAE group 19 using hunting-and-pecking
  or Hash-to-Element, including a bounded anti-clogging-token retry and protected management-frame
  checks. Added DHCPv4, gateway ARP resolution, IPv4 forwarding over macOS utun, and opt-in default
  route and DNS configuration with restoration on clean shutdown.
- Added opt-in thermal tracking and power correction, `rtlusb3` for explicit USB3 mode switching,
  and a native macOS menu-bar app with packaging, install, and uninstall scripts.

### Verified

- On an Apple Silicon Mac with an AWUS1900 on USB 2.0, enumeration, interface claim, efuse reads,
  firmware v33.6 download, MAC/BB/AGC/RF initialization, channel changes, and IQK calibration
  succeeded. RF readback confirmed 40/80 MHz center-channel selection.
- A 10-second channel 6 capture received 1,901 frames and 606 beacons with no CRC errors; tcpdump
  decoded the pcap. 5 GHz reception was observed while hopping channels 36–161.
- A direct-USB passive scan observed 15 BSSs across selected 2.4 and 5 GHz channels and transmitted
  no frames.
- Offline checks covered DHCP exchange and renewal, matching SAE peer keys/confirms, synthetic
  WPA3 M1–M4, rejection of a corrupted EAPOL MIC, H2E derivation against an independent
  implementation, and protected management-frame replay handling.
- `make package-macos` produced an arm64 app bundle; package, plist, and ad-hoc signature checks
  passed. The bundle is not notarized and uses the Homebrew libraries present at build time.

### Outstanding validation and limitations

- Physical TX and Probe Response reception, WPA2/WPA3 AP association, DHCP and utun traffic, route
  and DNS changes, thermal behavior, TX power accuracy, USB3 operation, and long-run stability have
  not been verified on the adapter. 40/80 MHz results are register readbacks; traffic at those
  widths has not been checked.
- The AP interoperability of SAE/H2E and anti-clogging retry remains unverified. Locally initiated
  SA Query and other robust management actions are not implemented. The menu-bar app does not start
  the IPv4 bridge; a launchd daemon and privileged helper remain future work.
- Firmware redistribution terms remain unchecked. The implementation uses the BSD-3-Clause side of
  rtw88-derived code; do not bundle the firmware until its terms are reviewed.
- A USB transfer failure during initialization has no recovery path. `rtlcap` does not run fresh IQK
  after changing channels, and `src/rtw/phy.c` retains one signed/unsigned compiler warning from
  upstream code.

# awus1900-macos

Userspace macOS driver for the Alfa AWUS1900 (Realtek RTL8814AU, USB 0bda:8813), built on libusb.
No kext, no DriverKit. See [CHANGELOG.md](CHANGELOG.md) for implementation history and verification status.

## Prerequisites (Apple Silicon)

    xcode-select --install
    brew install libusb pkg-config openssl@3

## Phase 0: probe

    make
    ./usbprobe --list        # all USB devices libusb can see
    ./usbprobe --regs        # descriptors, claim test, a few read-only register reads

## Phase 1: bring-up

    make
    ./rtlinit -v --fw refs/rtw88/firmware/rtw8814a_fw.bin   # power on, efuse, firmware download

`refs/` (rtw88 clone) is the reference source and is not part of the build.

## Phase 3: monitor-mode capture

    ./rtlcap --channel 6 --seconds 10 --out cap.pcap
    ./rtlcap --channel 6 --seconds 60 --out cap.pcap --thermal-track
    ./rtlcap --hop 36,40,44,48 --dwell-ms 700 --seconds 12 --out cap5.pcap

Writes a radiotap pcap that tcpdump/Wireshark decode. Use only on networks you own or are authorized to test.
`--thermal-track` opts into the 8814A thermal sampler and power correction during long captures.

## Phase 4: single Probe Request transmit

    ./rtlprobe --send --channel 6 --regd etsi [--ssid network-name] [--seconds 3]

Both `--send` and `--regd` are required. The tool sends one broadcast Probe Request at the adapter's
efuse MAC address, then listens for Probe Responses. It uses the selected regulatory power-limit table,
efuse calibration, and fixed 1 Mbps (2.4 GHz) or 6 Mbps (5 GHz) basic rate. Choose the correct region
and a channel permitted for your location and test network. Physical transmit behavior still needs
hardware verification.

## Station-mode groundwork: passive scan

    ./rtlscan --channels 1,6,11,36,40,44,48 --dwell-ms 250

`rtlscan` collects beacon and Probe Response information to list BSSID, channel, signal,
SSID, advertised security, and whether SAE-H2E is advertised. It listens only and does not transmit.

Request an explicit USB3 mode switch and check its re-enumerated speed with:

    ./rtlusb3 --switch

This disconnects the adapter once. Connect directly to a SuperSpeed port; a USB2 hub will re-enumerate
at USB2 and the command will report the fallback.

To exercise WPA2 association and the four-way handshake on an authorized AP:

    ./rtljoin --connect --ssid network-name --bssid 00:11:22:33:44:55 --channel 6 --regd etsi

The passphrase is read without terminal echo. To request an IPv4 lease and bridge packets through
a macOS utun interface, add `--network`:

    ./rtljoin --connect --ssid network-name --bssid 00:11:22:33:44:55 --channel 6 --regd etsi --network

`--network` runs DHCP, resolves the gateway MAC with ARP, and bridges IPv4 packets. macOS may require
administrator privileges to configure the utun address. It does not change the default route unless
you also pass `--default-route`; that option saves the current IPv4 default route and restores it when
the process exits normally or receives Ctrl-C. `--run-seconds N` can stop a network session after N
seconds; otherwise it runs until Ctrl-C.

For an authorized WPA3-Personal AP, add `--sae`:

    ./rtljoin --connect --sae --ssid network-name --bssid 00:11:22:33:44:55 --channel 6 --regd etsi

For an AP that advertises SAE-H2E in `rtlscan`, use `--sae-h2e` instead of `--sae`:

    ./rtljoin --connect --sae-h2e --ssid network-name --bssid 00:11:22:33:44:55 --channel 6 --regd etsi

SAE supports group 19 with either hunting-and-pecking or Hash-to-Element, plus one bounded
anti-clogging-token retry. H2E is selected explicitly; if an H&P attempt receives SAE status 126,
`rtljoin` points to `--sae-h2e`. It includes SAE-H2E capability in the Association Request and EAPOL
message 2. The station validates protected unicast CCMP and group-addressed BIP deauthentication and
disassociation after key installation and replies to protected unicast SA Query requests. It does not
start SA Query exchanges or handle other robust management actions.
Over-the-air SAE validation remains open. OpenSSL 3 is used for the P-256 operations and AES-CMAC.

To temporarily use the DHCP DNS server for a named macOS network service, add
`--dns-service "Wi-Fi"`. This requires `--default-route`, changes that service's system DNS for the
session, and restores its prior server list on shutdown if it has not been changed in the meantime.
DHCP renewals update the service's DNS while the session is active. Use
`networksetup -listallnetworkservices` to find the service name. This option may require administrator
privileges.

During `--network`, `rtljoin` runs the 8814A thermal sampler and efuse-limited power correction every
two seconds. Other tools leave it disabled unless `rtlcap --thermal-track` is supplied.

The network path is IPv4 only. It retries the initial DHCP exchange and renews at the lease rebind
time. System DNS configuration is opt-in through `--dns-service`; utun, DNS, and AP traffic have not
yet been validated over the air.
Use the region and channel permitted for your location.

## macOS menu-bar controller

Build the native controller app with:

    make package-macos

This creates `build/AWUS1900.app`, embedding `rtlscan` and `rtljoin`. The app passively scans, lets you
select an advertised WPA2/WPA3 network and an explicit regulatory region, then can attempt its WPA
handshake. The passphrase is read from a secure field and sent to the joiner over stdin. The app does
not enable the IPv4 bridge; use `rtljoin --network` from a terminal for DHCP and utun.

The app asks you to choose a local RTL8814A firmware file because firmware redistribution terms have
not been checked. It requires the Homebrew libusb and OpenSSL libraries used to build the tools. To
install or remove the bundle in `/Applications`, run `sudo ./scripts/install-macos.sh` or
`sudo ./scripts/uninstall-macos.sh`. The local ad-hoc signature is not notarized, and the phase 7
launchd daemon and privileged helper are not yet implemented.

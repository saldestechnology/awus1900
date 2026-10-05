# awus1900-macos

Userspace macOS driver for the Alfa AWUS1900 (Realtek RTL8814AU, USB 0bda:8813), built on libusb.
No kext, no DriverKit. See PLAN.md for the architecture and phases.

## Prerequisites (Apple Silicon)

    xcode-select --install
    brew install libusb pkg-config

## Phase 0: probe

    make
    ./usbprobe --list        # all USB devices libusb can see
    ./usbprobe --regs        # descriptors, claim test, a few read-only register reads

## Phase 1: bring-up

    make
    ./rtlinit -v --fw refs/rtw88/firmware/rtw8814a_fw.bin   # power on, efuse, firmware download

`refs/` (rtw88 clone) is the reference source and is not part of the build.

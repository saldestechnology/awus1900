CC      ?= clang
CFLAGS  += -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare -Wno-address-of-packed-member -O2 -Isrc -Isrc/rtw $(shell pkg-config --cflags libusb-1.0 openssl)
LDLIBS  += $(shell pkg-config --libs libusb-1.0 openssl)

RTW_SRC = src/rtw/phy.c src/rtw/rtw8814a.c src/rtw/rtw8814a_table.c src/rtw/pwrseq.c src/rtw/mac.c
CORE    = src/dev.c src/mac.c src/fw.c src/hal.c src/rx.c src/tx.c src/bss.c src/station.c src/wpa.c src/sae.c src/dhcp.c src/utun.c $(RTW_SRC)
HDRS    = $(wildcard src/*.h src/rtw/*.h)

all: usbprobe rtlinit rtlcap rtlprobe rtlscan rtljoin rtlusb3

usbprobe: src/usbprobe.c
	$(CC) $(CFLAGS) $< $(LDLIBS) -o $@

rtlinit: src/rtlinit.c $(CORE) $(HDRS)
	$(CC) $(CFLAGS) src/rtlinit.c $(CORE) $(LDLIBS) -o $@

rtlcap: src/rtlcap.c $(CORE) $(HDRS)
	$(CC) $(CFLAGS) src/rtlcap.c $(CORE) $(LDLIBS) -o $@

rtlprobe: src/rtlprobe.c $(CORE) $(HDRS)
	$(CC) $(CFLAGS) src/rtlprobe.c $(CORE) $(LDLIBS) -o $@

rtlscan: src/rtlscan.c $(CORE) $(HDRS)
	$(CC) $(CFLAGS) src/rtlscan.c $(CORE) $(LDLIBS) -o $@

rtljoin: src/rtljoin.c $(CORE) $(HDRS)
	$(CC) $(CFLAGS) src/rtljoin.c $(CORE) $(LDLIBS) -o $@

rtlusb3: src/rtlusb3.c $(CORE) $(HDRS)
	$(CC) $(CFLAGS) src/rtlusb3.c $(CORE) $(LDLIBS) -o $@

package-macos:
	./scripts/package-macos.sh

clean:
	rm -f usbprobe rtlinit rtlcap rtlprobe rtlscan rtljoin rtlusb3
	rm -rf build

.PHONY: all clean package-macos

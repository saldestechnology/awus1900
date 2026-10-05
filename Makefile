CC      ?= clang
CFLAGS  += -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare -Wno-address-of-packed-member -O2 -Isrc -Isrc/rtw $(shell pkg-config --cflags libusb-1.0)
LDLIBS  += $(shell pkg-config --libs libusb-1.0)

RTW_SRC = src/rtw/phy.c src/rtw/rtw8814a.c src/rtw/rtw8814a_table.c src/rtw/pwrseq.c src/rtw/mac.c
CORE    = src/dev.c src/mac.c src/fw.c src/hal.c $(RTW_SRC)
HDRS    = $(wildcard src/*.h src/rtw/*.h)

all: usbprobe rtlinit

usbprobe: src/usbprobe.c
	$(CC) $(CFLAGS) $< $(LDLIBS) -o $@

rtlinit: src/rtlinit.c $(CORE) $(HDRS)
	$(CC) $(CFLAGS) src/rtlinit.c $(CORE) $(LDLIBS) -o $@

clean:
	rm -f usbprobe rtlinit

.PHONY: all clean

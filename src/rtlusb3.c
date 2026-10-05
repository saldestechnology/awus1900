// SPDX-License-Identifier: BSD-3-Clause
/* Explicitly request RTL8814AU USB2-to-USB3 mode, then report re-enumerated speed. */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "rtl8814au.h"

static int wait_for_reenumeration(unsigned timeout_seconds, int *speed_out)
{
	libusb_context *ctx = NULL;
	struct timespec start, now, pause = { .tv_sec = 0, .tv_nsec = 250000000 };
	bool disconnected = false;
	int rc = libusb_init(&ctx);

	if (rc)
		return rc;
	if (clock_gettime(CLOCK_MONOTONIC, &start)) {
		libusb_exit(ctx);
		return LIBUSB_ERROR_OTHER;
	}

	for (;;) {
		libusb_device **list = NULL;
		ssize_t count = libusb_get_device_list(ctx, &list);
		bool found = false;

		if (count < 0) {
			libusb_exit(ctx);
			return (int)count;
		}
		for (ssize_t i = 0; i < count; i++) {
			struct libusb_device_descriptor desc;

			if (!libusb_get_device_descriptor(list[i], &desc) &&
			    desc.idVendor == 0x0bda && desc.idProduct == 0x8813) {
				*speed_out = libusb_get_device_speed(list[i]);
				found = true;
				break;
			}
		}
		libusb_free_device_list(list, 1);
		if (!found) {
			disconnected = true;
		} else if (disconnected) {
			libusb_exit(ctx);
			return 0;
		}
		if (clock_gettime(CLOCK_MONOTONIC, &now)) {
			libusb_exit(ctx);
			return LIBUSB_ERROR_OTHER;
		}
		if ((unsigned)(now.tv_sec - start.tv_sec) >= timeout_seconds) {
			libusb_exit(ctx);
			return LIBUSB_ERROR_TIMEOUT;
		}
		nanosleep(&pause, NULL);
	}
}

static void usage(FILE *stream, const char *program)
{
	fprintf(stream, "Usage: %s --switch [--fw PATH] [-v]\n", program);
	fprintf(stream, "Requests the efuse-enabled RTL8814AU USB3 mode and reports the re-enumerated speed.\n");
}

int main(int argc, char **argv)
{
	struct rtw_dev d;
	const char *fw = "refs/rtw88/firmware/rtw8814a_fw.bin";
	bool request = false, verbose = false;
	int rc, speed = LIBUSB_SPEED_UNKNOWN;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
			usage(stdout, argv[0]);
			return 0;
		} else if (!strcmp(argv[i], "--switch"))
			request = true;
		else if (!strcmp(argv[i], "--fw") && i + 1 < argc)
			fw = argv[++i];
		else if (!strcmp(argv[i], "-v"))
			verbose = true;
		else {
			usage(stderr, argv[0]);
			return 2;
		}
	}
	if (!request) {
		usage(stderr, argv[0]);
		return 2;
	}

	rc = rtl_open(&d, 0x0bda, 0x8813);
	if (rc) {
		fprintf(stderr, "cannot open adapter: %s\n", libusb_strerror(rc));
		return 1;
	}
	d.verbose = verbose;
	rtw_debug = verbose;
	if (rtl_hw_init(&d, fw)) {
		fprintf(stderr, "hardware initialization failed\n");
		rtl_mac_power_off(&d);
		rtl_close(&d);
		return 1;
	}

	if (d.usb_speed == LIBUSB_SPEED_SUPER) {
		printf("adapter is already connected at SuperSpeed (USB 3.x)\n");
		rtl_mac_power_off(&d);
		rtl_close(&d);
		return 0;
	}

	rc = rtl_usb3_request_switch(&d);
	if (rc <= 0) {
		fprintf(stderr, "USB3 switch request not sent: %s\n",
			rc == -EALREADY ? "a prior request already fell back to USB2; connect directly to a USB3 port" :
			rc == -EOPNOTSUPP ? "efuse disables switching or this USB speed is unsupported" :
			strerror(-rc));
		rtl_mac_power_off(&d);
		rtl_close(&d);
		return 1;
	}

	printf("USB3 switch requested; waiting up to 20 seconds for the adapter to re-enumerate\n");
	rtl_close(&d); /* The chip intentionally disconnects in the last switch write. */
	rc = wait_for_reenumeration(20, &speed);
	if (rc) {
		fprintf(stderr, "adapter did not re-enumerate: %s\n", libusb_strerror(rc));
		return 1;
	}
	if (speed == LIBUSB_SPEED_SUPER) {
		printf("adapter re-enumerated at SuperSpeed (USB 3.x)\n");
		return 0;
	}
	if (speed == LIBUSB_SPEED_HIGH) {
		fprintf(stderr, "adapter re-enumerated at USB 2.0; connect it directly to a SuperSpeed port\n");
		return 1;
	}
	fprintf(stderr, "adapter re-enumerated at unexpected USB speed class %d\n", speed);
	return 1;
}

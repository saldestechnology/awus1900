// SPDX-License-Identifier: BSD-3-Clause
/* Bring-up tool: power on, efuse, firmware, MAC/BB/RF init, optional channel switch.
 *
 *   ./rtlinit --fw refs/rtw88/firmware/rtw8814a_fw.bin [--channel N] [-v]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rtl8814au.h"

int main(int argc, char **argv)
{
	struct rtw_dev d;
	const char *fwpath = "refs/rtw88/firmware/rtw8814a_fw.bin";
	int channel = 0, verbose = 0, bw = 20, rc;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--fw") && i + 1 < argc)
			fwpath = argv[++i];
		else if (!strcmp(argv[i], "--channel") && i + 1 < argc)
			channel = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--bw") && i + 1 < argc)
			bw = atoi(argv[++i]);
		else if (!strcmp(argv[i], "-v"))
			verbose = 1;
	}

	rc = rtl_open(&d, 0x0bda, 0x8813);
	if (rc) {
		fprintf(stderr, "open failed: %s\n", libusb_strerror(rc));
		return 1;
	}
	d.verbose = verbose;
	rtw_debug = verbose;
	printf("USB speed class: %d (3=high, 4=super), %d bulk OUT endpoints\n", d.usb_speed, d.num_out_ep);

	rc = rtl_hw_init(&d, fwpath);
	printf("hw init: %s\n", rc ? "FAILED" : "ok");
	if (rc)
		goto out;

	{
		u32 rf18 = rtw_read_rf(&d, RF_PATH_A, 0x18, RFREG_MASK);

		printf("RF path A reg 0x18 = 0x%05x, BB 0x808 = 0x%08x\n", rf18, rtw_read32(&d, 0x808));
	}

	if (channel) {
		rc = rtl_set_channel(&d, channel, bw == 80 ? RTW_CHANNEL_WIDTH_80 :
					      bw == 40 ? RTW_CHANNEL_WIDTH_40 : RTW_CHANNEL_WIDTH_20);
		printf("set channel %d: %s\n", channel, rc ? "FAILED" : "ok");
		rtl_prepare_rfk(&d);
		printf("calibration (IQK) done\n");
		for (int p = 0; p < 4; p++)
			printf("  RF path %c reg 0x18 = 0x%05x\n", 'A' + p,
			       rtw_read_rf(&d, p, 0x18, RFREG_MASK));
	}
out:
	rtl_mac_power_off(&d);
	rtl_close(&d);
	return rc ? 1 : 0;
}

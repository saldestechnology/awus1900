// SPDX-License-Identifier: BSD-3-Clause
/* Monitor-mode capture to a radiotap pcap.
 *
 *   ./rtlcap --channel 6 --seconds 10 --out cap.pcap [--hop 1,6,11,36] [--dwell-ms 500] [--bad-fcs]
 */
#include <signal.h>
#include <sys/time.h>
#include <time.h>
#include "rtl8814au.h"

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }

static double now(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return tv.tv_sec + tv.tv_usec / 1e6;
}

struct ctx { unsigned beacons, probe_resp, data, mgmt, ctrl, other; };

static void on_frame(void *c, const struct rtw_rx_pkt_stat *ps, const u8 *f, int len)
{
	struct ctx *x = c;
	u8 type = (f[0] >> 2) & 3, sub = f[0] >> 4;

	if (type == 0 && sub == 8)
		x->beacons++;
	else if (type == 0 && sub == 5)
		x->probe_resp++;
	else if (type == 0)
		x->mgmt++;
	else if (type == 1)
		x->ctrl++;
	else if (type == 2)
		x->data++;
	else
		x->other++;
	(void)ps; (void)len;
}

int main(int argc, char **argv)
{
	const char *fw = "refs/rtw88/firmware/rtw8814a_fw.bin", *out = "cap.pcap", *hop = NULL;
	int channel = 6, seconds = 10, dwell_ms = 500, bw = 20;
	bool bad_fcs = false, thermal_track = false;
	struct rtw_dev d;
	struct pcap_out *po;
	struct rtl_rx_stats st = {0};
	struct ctx cx = {0};
	int chans[64], nchan = 0, ci = 0, rc;
	double t0, tch;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--channel") && i + 1 < argc) channel = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--seconds") && i + 1 < argc) seconds = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--out") && i + 1 < argc) out = argv[++i];
		else if (!strcmp(argv[i], "--hop") && i + 1 < argc) hop = argv[++i];
		else if (!strcmp(argv[i], "--dwell-ms") && i + 1 < argc) dwell_ms = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--fw") && i + 1 < argc) fw = argv[++i];
		else if (!strcmp(argv[i], "--bw") && i + 1 < argc) bw = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--bad-fcs")) bad_fcs = true;
		else if (!strcmp(argv[i], "--thermal-track")) thermal_track = true;
	}
	if (hop) {
		char *s = strdup(hop), *tok;

		for (tok = strtok(s, ","); tok && nchan < 64; tok = strtok(NULL, ","))
			chans[nchan++] = atoi(tok);
	} else {
		chans[nchan++] = channel;
	}

	if (rtl_open(&d, 0x0bda, 0x8813)) {
		fprintf(stderr, "cannot open adapter\n");
		return 1;
	}
	signal(SIGINT, on_sig);
	if (rtl_hw_init(&d, fw)) {
		fprintf(stderr, "hw init failed\n");
		rtl_close(&d);
		return 1;
	}
	rtl_set_channel(&d, chans[0], bw == 80 ? RTW_CHANNEL_WIDTH_80 : bw == 40 ? RTW_CHANNEL_WIDTH_40 : RTW_CHANNEL_WIDTH_20);
	rtl_thermal_track_enable(&d, thermal_track);
	rtl_rx_monitor_enable(&d, bad_fcs);
	rtl_pcap_open(&po, out);
	st.cb = on_frame;
	st.cb_ctx = &cx;

	printf("capturing on ch %d%s for %d s -> %s\n", chans[0], nchan > 1 ? " (hopping)" : "", seconds, out);
	t0 = tch = now();
	while (!stop && now() - t0 < seconds) {
		rc = rtl_rx_poll(&d, po, &st, 100);
		if (rc < 0) {
			fprintf(stderr, "rx error: %s\n", libusb_strerror(rc));
			break;
		}
		if (nchan > 1 && (now() - tch) * 1000 >= dwell_ms) {
			ci = (ci + 1) % nchan;
			rtl_set_channel(&d, chans[ci], RTW_CHANNEL_WIDTH_20);
			tch = now();
		}
	}
	printf("frames %u (crc errors %u, c2h %u, bad %u)\n", st.frames, st.crc_err, st.c2h, st.bad);
	printf("beacons %u  probe-resp %u  other-mgmt %u  ctrl %u  data %u  other %u\n", cx.beacons,
	       cx.probe_resp, cx.mgmt, cx.ctrl, cx.data, cx.other);
	rtl_pcap_close(po);
	rtl_thermal_track_enable(&d, false);
	rtl_mac_power_off(&d);
	rtl_close(&d);
	return 0;
}

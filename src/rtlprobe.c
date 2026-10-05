// SPDX-License-Identifier: BSD-3-Clause
/* Send one broadcast Probe Request and listen briefly for Probe Responses.
 *
 *   ./rtlprobe --send --channel 6 --regd etsi [--ssid network-name] [--seconds 3]
 */
#include <signal.h>
#include <sys/time.h>
#include "rtl8814au.h"

static volatile sig_atomic_t stop;

static void on_sigint(int sig)
{
	(void)sig;
	stop = 1;
}

static double now_seconds(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return tv.tv_sec + tv.tv_usec / 1e6;
}

struct probe_stats {
	unsigned responses;
};

static void on_frame(void *ctx, const struct rtw_rx_pkt_stat *ps, const u8 *frame, int len)
{
	struct probe_stats *stats = ctx;
	u16 frame_control;

	(void)ps;
	if (len < 2)
		return;

	frame_control = frame[0] | ((u16)frame[1] << 8);
	if ((frame_control & 0x00fc) == 0x0050) /* Management, Probe Response */
		stats->responses++;
}

static void usage(FILE *f)
{
	fprintf(f, "Usage: rtlprobe --send --channel N --regd REGION [--ssid NAME] [--seconds N] [--fw PATH]\n"
		"Sends exactly one broadcast Probe Request, then counts Probe Responses.\n"
		"--send and --regd are required. REGION: fcc, mkk, etsi, ic, kcc, acma, chile,\n"
		"ukraine, mexico, cn, qatar, uk, ww. Choose the region that applies to you.\n");
}

static int parse_regd(const char *name, enum rtw_regulatory_domains *regd)
{
	static const struct {
		const char *name;
		enum rtw_regulatory_domains value;
	} domains[] = {
		{ "fcc", RTW_REGD_FCC }, { "mkk", RTW_REGD_MKK },
		{ "etsi", RTW_REGD_ETSI }, { "ic", RTW_REGD_IC },
		{ "kcc", RTW_REGD_KCC }, { "acma", RTW_REGD_ACMA },
		{ "chile", RTW_REGD_CHILE }, { "ukraine", RTW_REGD_UKRAINE },
		{ "mexico", RTW_REGD_MEXICO }, { "cn", RTW_REGD_CN },
		{ "qatar", RTW_REGD_QATAR }, { "uk", RTW_REGD_UK },
		{ "ww", RTW_REGD_WW },
	};

	for (size_t i = 0; i < ARRAY_SIZE(domains); i++) {
		if (!strcmp(name, domains[i].name)) {
			*regd = domains[i].value;
			return 0;
		}
	}
	return -EINVAL;
}

int main(int argc, char **argv)
{
	const char *fw = "refs/rtw88/firmware/rtw8814a_fw.bin";
	const char *ssid = "";
	const char *regd_name = NULL;
	int channel = 0, seconds = 3, send = 0, regd_set = 0, rc = 1, rx_error = 0;
	enum rtw_regulatory_domains regd = RTW_REGD_MAX;
	struct rtw_dev d;
	struct rtl_rx_stats rx = {0};
	struct probe_stats stats = {0};
	double deadline;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
			usage(stdout);
			return 0;
		} else if (!strcmp(argv[i], "--send")) {
			send = 1;
		} else if (!strcmp(argv[i], "--channel") && i + 1 < argc) {
			channel = atoi(argv[++i]);
		} else if (!strcmp(argv[i], "--regd") && i + 1 < argc) {
			regd_name = argv[++i];
			if (parse_regd(regd_name, &regd)) {
				usage(stderr);
				return 2;
			}
			regd_set = 1;
		} else if (!strcmp(argv[i], "--seconds") && i + 1 < argc) {
			seconds = atoi(argv[++i]);
		} else if (!strcmp(argv[i], "--ssid") && i + 1 < argc) {
			ssid = argv[++i];
		} else if (!strcmp(argv[i], "--fw") && i + 1 < argc) {
			fw = argv[++i];
		} else {
			usage(stderr);
			return 2;
		}
	}

	if (!send || !regd_set || channel < 1 || channel > 177 ||
	    !rtl_channel_is_supported((u8)channel) || seconds < 1 || seconds > 30 ||
	    strlen(ssid) > 32) {
		usage(stderr);
		return 2;
	}

	rc = rtl_open(&d, 0x0bda, 0x8813);
	if (rc) {
		fprintf(stderr, "cannot open adapter: %s\n", libusb_strerror(rc));
		return 1;
	}

	if (rtl_hw_init(&d, fw)) {
		fprintf(stderr, "hardware initialization failed\n");
		rc = 1;
		goto out;
	}
	rc = rtl_set_tx_regulatory_domain(&d, regd);
	if (rc) {
		fprintf(stderr, "cannot select TX regulatory domain\n");
		goto out;
	}

	rc = rtl_set_channel(&d, channel, RTW_CHANNEL_WIDTH_20);
	if (rc) {
		fprintf(stderr, "cannot set channel %d\n", channel);
		goto out;
	}
	rtl_prepare_rfk(&d);
	rtl_rx_monitor_enable(&d, false);
	rx.cb = on_frame;
	rx.cb_ctx = &stats;

	rc = rtl_send_probe_request(&d, ssid);
	if (rc) {
		fprintf(stderr, "Probe Request transmission failed (%d)\n", rc);
		goto out;
	}
	printf("sent one broadcast Probe Request on channel %d (regulatory domain %s, %s SSID); "
	       "listening for %d s\n", channel, regd_name, *ssid ? "directed" : "wildcard", seconds);

	signal(SIGINT, on_sigint);
	deadline = now_seconds() + seconds;
	while (!stop && now_seconds() < deadline) {
		int n = rtl_rx_poll(&d, NULL, &rx, 100);

		if (n < 0) {
			fprintf(stderr, "receive error: %s\n", libusb_strerror(n));
			rx_error = n;
			break;
		}
	}
	printf("heard %u Probe Response(s) in %u received frame(s)\n", stats.responses, rx.frames);
	rc = rx_error ? 1 : 0;

out:
	rtl_mac_power_off(&d);
	rtl_close(&d);
	return rc ? 1 : 0;
}

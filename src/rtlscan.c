// SPDX-License-Identifier: BSD-3-Clause
/* Passive AP discovery for the station-mode path.
 *
 *   ./rtlscan [--channels 1,6,11,36,40] [--dwell-ms 250] [--fw PATH]
 */
#include <signal.h>
#include <sys/time.h>
#include <unistd.h>
#include "rtl8814au.h"

#define RTL_SCAN_MAX_CHANNELS 64
#define RTL_SCAN_MAX_BSS 256

static volatile sig_atomic_t stop;

static const int default_channels[] = {
	1, 6, 11,
	36, 40, 44, 48, 52, 56, 60, 64,
	100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
	149, 153, 157, 161, 165, 169, 173, 177,
};

struct scan_entry {
	struct rtl_bss_info bss;
};

struct scan_ctx {
	struct scan_entry entries[RTL_SCAN_MAX_BSS];
	unsigned count;
	u8 tuned_channel;
};

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

static int parse_channels(const char *arg, int *channels, int *count)
{
	char *copy = strdup(arg), *p;
	int n = 0, ret = -EINVAL;

	if (!copy)
		return -ENOMEM;
	p = copy;
	while (*p) {
		char *end;
		long ch = strtol(p, &end, 10);

		if (end == p || ch < 1 || ch > 177 ||
		    !rtl_channel_is_supported((u8)ch) || n == RTL_SCAN_MAX_CHANNELS)
			goto out;
		channels[n++] = (int)ch;
		if (!*end)
			break;
		if (*end != ',')
			goto out;
		p = end + 1;
		if (!*p)
			goto out;
	}
	if (n) {
		*count = n;
		ret = 0;
	}
out:
	free(copy);
	return ret;
}

static bool same_bss(const struct rtl_bss_info *a, const struct rtl_bss_info *b)
{
	return a->channel == b->channel && !memcmp(a->bssid, b->bssid, ETH_ALEN);
}

static void on_frame(void *ctx, const struct rtw_rx_pkt_stat *ps, const u8 *frame, int len)
{
	struct scan_ctx *scan = ctx;
	struct rtl_bss_info bss;
	int ret;

	if (ps->crc_err)
		return;
	ret = rtl_parse_bss(frame, len, scan->tuned_channel, ps->signal_power, &bss);
	if (ret <= 0)
		return;

	for (unsigned i = 0; i < scan->count; i++) {
		if (same_bss(&scan->entries[i].bss, &bss)) {
			if (bss.ssid_len) {
				scan->entries[i].bss.ssid_len = bss.ssid_len;
				memcpy(scan->entries[i].bss.ssid, bss.ssid, bss.ssid_len);
			}
			scan->entries[i].bss.signal_dbm = bss.signal_dbm;
			return;
		}
	}
	if (scan->count < RTL_SCAN_MAX_BSS)
		scan->entries[scan->count++].bss = bss;
}

static const char *security_name(const struct rtl_bss_info *bss)
{
	if (!bss->privacy)
		return "open";
	if (bss->rsn_psk && bss->rsn_sae)
		return "WPA2/3 transition";
	if (bss->rsn_sae)
		return "WPA3-SAE";
	if (bss->rsn_psk && bss->rsn_ccmp)
		return "WPA2-PSK/CCMP";
	if (bss->rsn_present)
		return "RSN/other";
	if (bss->wpa_vendor)
		return "WPA/legacy";
	return "WEP/unknown";
}

static void print_bssid(const u8 *addr)
{
	printf("%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2],
	       addr[3], addr[4], addr[5]);
}

static void print_ssid(const struct rtl_bss_info *bss)
{
	if (!bss->ssid_len) {
		printf("<hidden>");
		return;
	}
	for (u8 i = 0; i < bss->ssid_len; i++) {
		u8 c = bss->ssid[i];

		if (c >= 0x20 && c <= 0x7e && c != '\\')
			putchar(c);
		else
			printf("\\x%02x", c);
	}
}

static void print_json(const struct scan_ctx *scan)
{
	printf("[");
	for (unsigned i = 0; i < scan->count; i++) {
		const struct rtl_bss_info *bss = &scan->entries[i].bss;

		if (i)
			printf(",");
		printf("{\"bssid\":\"");
		print_bssid(bss->bssid);
		printf("\",\"channel\":%u,\"rssi\":%d,\"security\":\"%s\","
		       "\"wpa2_psk\":%s,\"sae\":%s,\"sae_h2e\":%s,\"ssid_hex\":\"",
		       bss->channel, (int)bss->signal_dbm, security_name(bss),
		       bss->rsn_psk ? "true" : "false",
		       bss->rsn_sae ? "true" : "false",
		       bss->rsnxe_sae_h2e ? "true" : "false");
		for (u8 j = 0; j < bss->ssid_len; j++)
			printf("%02x", bss->ssid[j]);
		printf("\"}");
	}
	printf("]\n");
}

static void usage(FILE *f)
{
	fprintf(f, "Usage: rtlscan [--channels 1,6,11,36,40] [--dwell-ms N] [--fw PATH] [--json]\n"
		"Passively collects beacon and Probe Response information. It does not transmit.\n");
}

int main(int argc, char **argv)
{
	const char *fw = "refs/rtw88/firmware/rtw8814a_fw.bin";
	int channels[RTL_SCAN_MAX_CHANNELS], channel_count = ARRAY_SIZE(default_channels);
	int dwell_ms = 250, rc = 1;
	struct rtw_dev d;
	struct rtl_rx_stats rx = {0};
	struct scan_ctx scan = {0};
	bool opened = false;
	bool json_output = false;
	int saved_stdout = -1;

	memcpy(channels, default_channels, sizeof(default_channels));
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
			usage(stdout);
			return 0;
		} else if (!strcmp(argv[i], "--channels") && i + 1 < argc) {
			if (parse_channels(argv[++i], channels, &channel_count)) {
				usage(stderr);
				return 2;
			}
		} else if (!strcmp(argv[i], "--dwell-ms") && i + 1 < argc) {
			dwell_ms = atoi(argv[++i]);
		} else if (!strcmp(argv[i], "--fw") && i + 1 < argc) {
			fw = argv[++i];
		} else if (!strcmp(argv[i], "--json")) {
			json_output = true;
		} else {
			usage(stderr);
			return 2;
		}
	}
	if (dwell_ms < 50 || dwell_ms > 5000) {
		usage(stderr);
		return 2;
	}
	if (json_output) {
		fflush(stdout);
		saved_stdout = dup(STDOUT_FILENO);
		if (saved_stdout < 0 || dup2(STDERR_FILENO, STDOUT_FILENO) < 0) {
			fprintf(stderr, "cannot isolate JSON output\n");
			if (saved_stdout >= 0)
				close(saved_stdout);
			return 1;
		}
	}

	rc = rtl_open(&d, 0x0bda, 0x8813);
	if (rc) {
		fprintf(stderr, "cannot open adapter: %s\n", libusb_strerror(rc));
		return 1;
	}
	opened = true;
	if (rtl_hw_init(&d, fw)) {
		fprintf(stderr, "hardware initialization failed\n");
		goto out;
	}
	rc = rtl_set_channel(&d, channels[0], RTW_CHANNEL_WIDTH_20);
	if (rc) {
		fprintf(stderr, "unsupported initial channel %d\n", channels[0]);
		goto out;
	}
	rtl_rx_monitor_enable(&d, false);
	rx.cb = on_frame;
	rx.cb_ctx = &scan;
	signal(SIGINT, on_sigint);

	if (!json_output)
		printf("passive scan: %d channel(s), %d ms dwell each\n", channel_count, dwell_ms);
	for (int i = 0; i < channel_count && !stop; i++) {
		double deadline;

		if (rtl_set_channel(&d, channels[i], RTW_CHANNEL_WIDTH_20)) {
			fprintf(stderr, "skip unsupported channel %d\n", channels[i]);
			continue;
		}
		scan.tuned_channel = (u8)channels[i];
		deadline = now_seconds() + dwell_ms / 1000.0;
		while (!stop && now_seconds() < deadline) {
			int n = rtl_rx_poll(&d, NULL, &rx, 100);

			if (n < 0) {
				fprintf(stderr, "receive error: %s\n", libusb_strerror(n));
				rc = 1;
				goto out;
			}
		}
	}

	if (json_output) {
		fflush(stdout);
		if (saved_stdout >= 0) {
			dup2(saved_stdout, STDOUT_FILENO);
			close(saved_stdout);
			saved_stdout = -1;
		}
		print_json(&scan);
	} else {
		printf("\nBSSID              CH  RSSI  SECURITY             SAE-H2E SSID\n");
		for (unsigned i = 0; i < scan.count; i++) {
			const struct rtl_bss_info *bss = &scan.entries[i].bss;

			print_bssid(bss->bssid);
			printf("  %3u %5d  %-20s %-7s ", bss->channel,
			       (int)bss->signal_dbm, security_name(bss),
			       bss->rsn_sae ? (bss->rsnxe_sae_h2e ? "yes" : "no") : "-");
			print_ssid(bss);
			putchar('\n');
		}
		printf("\n%u BSS(s) observed\n", scan.count);
	}
	rc = 0;

out:
	if (opened) {
		rtl_mac_power_off(&d);
		rtl_close(&d);
	}
	return rc ? 1 : 0;
}

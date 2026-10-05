// SPDX-License-Identifier: BSD-3-Clause
/* Associate to a WPA2-PSK or WPA3-SAE AP and complete the four-way handshake. */
#include <sys/time.h>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>
#include "rtl8814au.h"

struct join_ctx {
	struct rtl_station station;
	unsigned frames;
};

struct network_ctx {
	struct rtl_station *station;
	struct rtl_dhcp_client dhcp;
	struct rtl_utun tun;
	u8 gateway_mac[ETH_ALEN];
	bool gateway_mac_ready;
};

static volatile sig_atomic_t stop_requested;

static void on_signal(int signal_number)
{
	(void)signal_number;
	stop_requested = 1;
}

static double now_seconds(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return tv.tv_sec + tv.tv_usec / 1e6;
}

static void print_bssid(const u8 *bssid)
{
	printf("%02x:%02x:%02x:%02x:%02x:%02x", bssid[0], bssid[1], bssid[2],
	       bssid[3], bssid[4], bssid[5]);
}

static void on_frame(void *ctx, const struct rtw_rx_pkt_stat *ps, const u8 *frame, int len)
{
	struct join_ctx *join = ctx;
	int ret;

	if (ps->crc_err)
		return;
	join->frames++;
	ret = rtl_station_receive(&join->station, frame, len);
	if (ret < 0 && join->station.state != RTL_STA_FAILED) {
		join->station.state = RTL_STA_FAILED;
		join->station.error = ret;
	}
}

static bool ip_equal(const u8 *a, const u8 *b)
{
	return memcmp(a, b, 4) == 0;
}

static bool valid_unicast_mac(const u8 *mac)
{
	static const u8 zero[ETH_ALEN];

	return mac && !(mac[0] & 1) && memcmp(mac, zero, ETH_ALEN) != 0;
}

static int network_receive(void *ctx, u16 ethertype, const u8 *payload, size_t len)
{
	struct network_ctx *net = ctx;

	if (ethertype == 0x0800) {
		size_t ihl, ip_len;
		int ret;

		if (net->dhcp.state == RTL_DHCP_WAIT_OFFER ||
		    net->dhcp.state == RTL_DHCP_WAIT_ACK ||
		    net->dhcp.state == RTL_DHCP_RENEWING)
			return rtl_dhcp_receive(&net->dhcp, payload, len);
		if (!net->tun.configured || len < 20 || (payload[0] >> 4) != 4)
			return 0;
		ihl = (size_t)(payload[0] & 0x0f) * 4;
		ip_len = (size_t)payload[2] << 8 | payload[3];
		if (ihl < 20 || ihl > len || ip_len < ihl || ip_len > len)
			return 0;
		ret = rtl_utun_write_ipv4(&net->tun, payload, ip_len);
		if (ret == -EAGAIN || ret == -ENOBUFS)
			return 0;
		return ret;
	}
	if (ethertype == 0x0806 && len >= 28 && net->dhcp.state == RTL_DHCP_BOUND) {
		if (payload[0] == 0 && payload[1] == 1 && payload[2] == 0x08 &&
		    payload[3] == 0 && payload[4] == 6 && payload[5] == 4 &&
		    payload[6] == 0 && payload[7] == 2 &&
		    ip_equal(payload + 14, net->dhcp.gateway) &&
		    valid_unicast_mac(payload + 8) &&
		    ip_equal(payload + 24, net->dhcp.address)) {
			memcpy(net->gateway_mac, payload + 8, ETH_ALEN);
			net->gateway_mac_ready = true;
			return 1;
		}
	}
	return 0;
}

static int send_gateway_arp_request(struct network_ctx *net)
{
	static const u8 broadcast[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	u8 arp[28] = {0};

	arp[1] = 1;             /* Ethernet */
	arp[2] = 0x08;		/* IPv4 */
	arp[4] = ETH_ALEN;
	arp[5] = 4;
	arp[7] = 1;		/* ARP request */
	memcpy(arp + 8, net->station->dev->efuse.addr, ETH_ALEN);
	memcpy(arp + 14, net->dhcp.address, 4);
	memcpy(arp + 24, net->dhcp.gateway, 4);
	return rtl_station_send_ethernet(net->station, broadcast, 0x0806,
					 arp, sizeof(arp));
}

static int poll_join_radio(struct rtw_dev *d, struct rtl_rx_stats *rx,
			   struct join_ctx *join, unsigned timeout_ms)
{
	int n = rtl_rx_poll(d, NULL, rx, (int)timeout_ms);

	if (n < 0) {
		fprintf(stderr, "receive error: %s\n", libusb_strerror(n));
		join->station.state = RTL_STA_FAILED;
		join->station.error = n;
		return n;
	}
	return n;
}

static int run_network(struct join_ctx *join, struct rtl_rx_stats *rx,
		       bool default_route, unsigned run_seconds, const char *dns_service)
{
	struct network_ctx net = {.station = &join->station};
	u8 packet[2048];
	size_t packet_len;
	double deadline;
	int ret;

	net.tun.fd = -1;
	ret = rtl_utun_open(&net.tun);
	if (ret) {
		fprintf(stderr, "cannot open utun: %s\n", strerror(-ret));
		return ret;
	}
	rtl_thermal_track_enable(join->station.dev, true);
	join->station.payload_cb = network_receive;
	join->station.payload_cb_ctx = &net;
	ret = rtl_dhcp_start(&net.dhcp, &join->station);
	if (ret) {
		fprintf(stderr, "cannot send DHCP Discover: %s\n", strerror(-ret));
		goto out;
	}
	printf("DHCP Discover sent; waiting for a lease...\n");
	deadline = now_seconds() + 45;
	while (net.dhcp.state != RTL_DHCP_BOUND && net.dhcp.state != RTL_DHCP_FAILED &&
	       join->station.state == RTL_STA_CONNECTED && !stop_requested &&
	       now_seconds() < deadline) {
		ret = rtl_dhcp_tick(&net.dhcp);
		if (ret < 0 && net.dhcp.state == RTL_DHCP_FAILED)
			break;
		if (poll_join_radio(join->station.dev, rx, join, 50) < 0) {
			ret = join->station.error;
			goto out;
		}
	}
	if (stop_requested) {
		ret = -EINTR;
		goto out;
	}
	if (join->station.state != RTL_STA_CONNECTED) {
		ret = join->station.error ? join->station.error : -ECONNRESET;
		goto out;
	}
	if (net.dhcp.state != RTL_DHCP_BOUND) {
		ret = net.dhcp.error ? net.dhcp.error : -ETIMEDOUT;
		fprintf(stderr, "DHCP did not complete: %s\n", strerror(-ret));
		goto out;
	}
	ret = rtl_utun_configure(&net.tun, &net.dhcp, default_route, dns_service);
	if (ret) {
		fprintf(stderr, "cannot configure %s (network setup may require administrator privileges): %s\n",
			net.tun.ifname, strerror(-ret));
		goto out;
	}
	ret = send_gateway_arp_request(&net);
	if (ret) {
		fprintf(stderr, "cannot resolve DHCP gateway: %s\n", strerror(-ret));
		goto out;
	}
	deadline = now_seconds() + 5;
	while (!net.gateway_mac_ready && join->station.state == RTL_STA_CONNECTED &&
	       !stop_requested && now_seconds() < deadline) {
		if (poll_join_radio(join->station.dev, rx, join, 50) < 0) {
			ret = join->station.error;
			goto out;
		}
	}
	if (stop_requested) {
		ret = -EINTR;
		goto out;
	}
	if (join->station.state != RTL_STA_CONNECTED) {
		ret = join->station.error ? join->station.error : -ECONNRESET;
		goto out;
	}
	if (!net.gateway_mac_ready) {
		ret = -ETIMEDOUT;
		fprintf(stderr, "did not receive an ARP reply from the DHCP gateway\n");
		goto out;
	}
	{
		char address[INET_ADDRSTRLEN], gateway[INET_ADDRSTRLEN];
		struct in_addr ip;
		memcpy(&ip.s_addr, net.dhcp.address, 4);
		inet_ntop(AF_INET, &ip, address, sizeof(address));
		memcpy(&ip.s_addr, net.dhcp.gateway, 4);
		inet_ntop(AF_INET, &ip, gateway, sizeof(gateway));
		printf("IPv4 lease %s, gateway %s; tunnel %s is active%s.\n", address,
		       gateway, net.tun.ifname,
		       default_route ? " with the default route switched" : " (no default route change)");
	}
	deadline = run_seconds ? now_seconds() + run_seconds : 0;
	ret = 0;
	while (join->station.state == RTL_STA_CONNECTED && !stop_requested &&
	       (!deadline || now_seconds() < deadline)) {
		ret = rtl_dhcp_tick(&net.dhcp);
		if (ret < 0) {
			fprintf(stderr, "DHCP lease renewal failed: %s\n", strerror(-ret));
			break;
		}
		ret = rtl_utun_refresh_dns(&net.tun, &net.dhcp);
		if (ret) {
			fprintf(stderr, "could not update DHCP DNS settings: %s\n", strerror(-ret));
			break;
		}
		ret = 0;
		if (poll_join_radio(join->station.dev, rx, join, 20) < 0) {
			ret = join->station.error;
			break;
		}
		for (;;) {
			int read_ret = rtl_utun_read_ipv4(&net.tun, packet, sizeof(packet), &packet_len);

			if (read_ret == -EAGAIN)
				break;
			if (read_ret) {
				if (read_ret == -EMSGSIZE || read_ret == -EBADMSG)
					continue;
				ret = read_ret;
				break;
			}
			if (packet_len > 1500)
				continue;
			if (!net.gateway_mac_ready)
				continue;
			read_ret = rtl_station_send_ethernet(&join->station, net.gateway_mac,
						     0x0800, packet, packet_len);
			if (read_ret && read_ret != -EAGAIN && read_ret != -ENOBUFS) {
				fprintf(stderr, "Wi-Fi transmit failed: %s\n", strerror(-read_ret));
				ret = read_ret;
			}
			if (ret)
				break;
		}
		if (ret)
			break;
	}
	if (stop_requested)
		ret = 0;
	else if (join->station.state != RTL_STA_CONNECTED && !ret)
		ret = join->station.error ? join->station.error : -ECONNRESET;
out:
	join->station.payload_cb = NULL;
	join->station.payload_cb_ctx = NULL;
	rtl_thermal_track_enable(join->station.dev, false);
	rtl_utun_close(&net.tun);
	return ret == -EINTR ? 0 : ret;
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

static int parse_bssid(const char *arg, u8 bssid[ETH_ALEN])
{
	unsigned value[ETH_ALEN];
	char extra;

	if (sscanf(arg, "%2x:%2x:%2x:%2x:%2x:%2x%c", &value[0], &value[1], &value[2],
		   &value[3], &value[4], &value[5], &extra) != 6)
		return -EINVAL;
	for (size_t i = 0; i < ETH_ALEN; i++) {
		if (value[i] > 0xff)
			return -EINVAL;
		bssid[i] = (u8)value[i];
	}
	if (bssid[0] & 1)
		return -EINVAL;
	return 0;
}

static int hex_value(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static int parse_ssid_hex(const char *arg, u8 ssid[32], size_t *ssid_len)
{
	size_t chars;

	if (!arg || !ssid || !ssid_len)
		return -EINVAL;
	chars = strlen(arg);
	if (!chars || chars > 64 || (chars & 1))
		return -EINVAL;
	for (size_t i = 0; i < chars / 2; i++) {
		int high = hex_value(arg[i * 2]);
		int low = hex_value(arg[i * 2 + 1]);

		if (high < 0 || low < 0)
			return -EINVAL;
		ssid[i] = (u8)((high << 4) | low);
	}
	*ssid_len = chars / 2;
	return 0;
}

static void print_ssid(const u8 *ssid, size_t ssid_len)
{
	for (size_t i = 0; i < ssid_len; i++) {
		u8 c = ssid[i];

		if (c >= 0x20 && c <= 0x7e && c != '\\' && c != '\'')
			putchar(c);
		else
			printf("\\x%02x", c);
	}
}

static int read_passphrase_stdin(u8 passphrase[64], size_t *passphrase_len)
{
	size_t used = 0;
	int ch;

	if (!passphrase || !passphrase_len)
		return -EINVAL;
	while ((ch = fgetc(stdin)) != EOF && ch != '\n') {
		if (used == 63)
			return -E2BIG;
		passphrase[used++] = (u8)ch;
	}
	if (ch == EOF && ferror(stdin))
		return -EIO;
	if (used && passphrase[used - 1] == '\r')
		used--;
	*passphrase_len = used;
	return 0;
}

static void usage(FILE *f)
{
	fprintf(f,
		"Usage: rtljoin --connect (--ssid NAME | --ssid-hex HEX) --bssid MAC --channel N --regd REGION [--timeout SEC] [--network [--default-route] [--dns-service NAME] [--run-seconds SEC]] [--fw PATH]\n"
		"Joins a WPA2-PSK/CCMP AP, or use --sae for WPA3-Personal SAE group 19.\n"
		"Use --sae-h2e to select SAE Hash-to-Element for an AP advertising SAE-H2E.\n"
		"The passphrase is read without terminal echo; --passphrase-stdin reads one line from stdin.\n"
		"--connect and --regd are required.\n"
		"SAE defaults to hunting-and-pecking; rtlscan reports whether an AP advertises SAE-H2E.\n"
		"--network starts DHCP and an IPv4 utun bridge; administrator privileges may be needed.\n"
		"--default-route explicitly switches the IPv4 default route for the session.\n"
		"--dns-service temporarily sets that macOS network service to the DHCP DNS server; requires --network and --default-route.\n"
		"With --network, --run-seconds 0 (the default) runs until Ctrl-C.\n");
}

int main(int argc, char **argv)
{
	const char *fw = "refs/rtw88/firmware/rtw8814a_fw.bin";
	const char *ssid_arg = NULL, *ssid_hex_arg = NULL, *bssid_arg = NULL, *regd_name = NULL;
	const char *dns_service = NULL;
	u8 bssid[ETH_ALEN], ssid_hex[32] = {0}, passphrase[64] = {0};
	const u8 *ssid = NULL;
	size_t ssid_len = 0, passphrase_len;
	int channel = 0, timeout_sec = 30, connect = 0, regd_set = 0, network = 0;
	int use_sae = 0, use_sae_h2e = 0, passphrase_stdin = 0;
	int default_route = 0, run_seconds = 0, rc = 1;
	enum rtw_regulatory_domains regd = RTW_REGD_MAX;
	struct rtw_dev d;
	struct rtl_rx_stats rx = {0};
	struct join_ctx join = {0};
	bool opened = false;
	double deadline;
	char *prompt;
	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
			usage(stdout);
			return 0;
		} else if (!strcmp(argv[i], "--connect")) {
			connect = 1;
		} else if (!strcmp(argv[i], "--ssid") && i + 1 < argc) {
			ssid_arg = argv[++i];
		} else if (!strcmp(argv[i], "--ssid-hex") && i + 1 < argc) {
			ssid_hex_arg = argv[++i];
		} else if (!strcmp(argv[i], "--bssid") && i + 1 < argc) {
			bssid_arg = argv[++i];
		} else if (!strcmp(argv[i], "--channel") && i + 1 < argc) {
			channel = atoi(argv[++i]);
		} else if (!strcmp(argv[i], "--regd") && i + 1 < argc) {
			regd_name = argv[++i];
			if (parse_regd(regd_name, &regd)) {
				usage(stderr);
				return 2;
			}
			regd_set = 1;
		} else if (!strcmp(argv[i], "--timeout") && i + 1 < argc) {
			timeout_sec = atoi(argv[++i]);
		} else if (!strcmp(argv[i], "--network")) {
			network = 1;
		} else if (!strcmp(argv[i], "--sae")) {
			use_sae = 1;
		} else if (!strcmp(argv[i], "--sae-h2e")) {
			use_sae = 1;
			use_sae_h2e = 1;
		} else if (!strcmp(argv[i], "--passphrase-stdin")) {
			passphrase_stdin = 1;
		} else if (!strcmp(argv[i], "--default-route")) {
			default_route = 1;
		} else if (!strcmp(argv[i], "--dns-service") && i + 1 < argc) {
			dns_service = argv[++i];
		} else if (!strcmp(argv[i], "--run-seconds") && i + 1 < argc) {
			run_seconds = atoi(argv[++i]);
		} else if (!strcmp(argv[i], "--fw") && i + 1 < argc) {
			fw = argv[++i];
		} else {
			usage(stderr);
			return 2;
		}
	}
	if (ssid_arg && ssid_hex_arg) {
		usage(stderr);
		return 2;
	}
	if (ssid_arg) {
		ssid = (const u8 *)ssid_arg;
		ssid_len = strlen(ssid_arg);
	} else if (ssid_hex_arg && parse_ssid_hex(ssid_hex_arg, ssid_hex, &ssid_len)) {
		usage(stderr);
		return 2;
	} else if (ssid_hex_arg) {
		ssid = ssid_hex;
	}
	if (!connect || !regd_set || !ssid || !ssid_len || ssid_len > 32 || !bssid_arg ||
	    parse_bssid(bssid_arg, bssid) || channel < 1 || channel > 177 ||
	    !rtl_channel_is_supported((u8)channel) ||
	    timeout_sec < 5 || timeout_sec > 120 || run_seconds < 0 || run_seconds > 86400 ||
	    (default_route && !network) || (run_seconds && !network) ||
	    (dns_service && (!network || !default_route || !*dns_service || strlen(dns_service) >= 128))) {
		usage(stderr);
		return 2;
	}

	rc = rtl_open(&d, 0x0bda, 0x8813);
	if (rc) {
		fprintf(stderr, "cannot open adapter: %s\n", libusb_strerror(rc));
		return 1;
	}
	opened = true;
	rc = 1;
	if (rtl_hw_init(&d, fw)) {
		fprintf(stderr, "hardware initialization failed\n");
		goto out;
	}
	if (rtl_set_tx_regulatory_domain(&d, regd)) {
		fprintf(stderr, "cannot select TX regulatory domain\n");
		goto out;
	}
	if (rtl_set_channel(&d, (u8)channel, RTW_CHANNEL_WIDTH_20)) {
		fprintf(stderr, "cannot set channel %d\n", channel);
		goto out;
	}
	rtl_prepare_rfk(&d);
	rtl_rx_monitor_enable(&d, false);

	if (passphrase_stdin) {
		if (read_passphrase_stdin(passphrase, &passphrase_len)) {
			fprintf(stderr, "could not read passphrase from stdin\n");
			goto out;
		}
	} else {
		prompt = getpass(use_sae ? "WPA3 passphrase: " : "WPA2 passphrase: ");
		if (!prompt) {
			fprintf(stderr, "could not read passphrase\n");
			goto out;
		}
		passphrase_len = strnlen(prompt, sizeof(passphrase));
	}
	if (passphrase_len < 8 || passphrase_len > 63) {
		if (!passphrase_stdin)
			memset(prompt, 0, passphrase_len);
		memset(passphrase, 0, sizeof(passphrase));
		fprintf(stderr, "WPA2 passphrase must contain 8 to 63 bytes\n");
		goto out;
	}
	if (!passphrase_stdin) {
		memcpy(passphrase, prompt, passphrase_len);
		memset(prompt, 0, passphrase_len);
	}
	if ((use_sae ?
	     (use_sae_h2e ?
	      rtl_station_init_sae_h2e(&join.station, &d, bssid, ssid,
				 ssid_len, passphrase, passphrase_len) :
	      rtl_station_init_sae(&join.station, &d, bssid, ssid,
			   ssid_len, passphrase, passphrase_len)) :
	     rtl_station_init(&join.station, &d, bssid, ssid,
			      ssid_len, passphrase, passphrase_len))) {
		fprintf(stderr, "cannot initialize WPA%s authentication\n", use_sae ? "3 SAE" : "2");
		goto out;
	}
	memset(passphrase, 0, sizeof(passphrase));
	rx.cb = on_frame;
	rx.cb_ctx = &join;
	if (rtl_station_start(&join.station)) {
		fprintf(stderr, "could not send Authentication Request\n");
		goto out;
	}
	printf("joining %s SSID '",
	       use_sae ? (use_sae_h2e ? "WPA3-SAE-H2E" : "WPA3-SAE") :
	       "WPA2-PSK");
	print_ssid(ssid, ssid_len);
	printf("' on channel %d at BSSID ", channel);
	print_bssid(bssid);
	printf(" (regulatory domain %s)\n", regd_name);
	deadline = now_seconds() + timeout_sec;
	while (join.station.state != RTL_STA_CONNECTED && join.station.state != RTL_STA_FAILED &&
	       !stop_requested && now_seconds() < deadline) {
		int n = rtl_rx_poll(&d, NULL, &rx, 100);

		if (n < 0) {
			fprintf(stderr, "receive error: %s\n", libusb_strerror(n));
			join.station.state = RTL_STA_FAILED;
			join.station.error = n;
			break;
		}
	}
	if (join.station.state == RTL_STA_CONNECTED) {
		printf("%s four-way handshake completed (%u received frames).\n",
		       use_sae ? (use_sae_h2e ? "WPA3-SAE-H2E" : "WPA3-SAE") :
	       "WPA2", join.frames);
		if (network) {
			rc = run_network(&join, &rx, default_route, (unsigned)run_seconds,
					 dns_service) ? 1 : 0;
		} else {
			printf("DHCP and utun were not requested; use --network to start IPv4.\n");
			rc = 0;
		}
	} else {
		fprintf(stderr, "join failed or timed out (state %d, error %d)\n",
			join.station.state, join.station.error);
		if (use_sae && !use_sae_h2e && join.station.error == -EOPNOTSUPP)
			fprintf(stderr, "the AP requested SAE Hash-to-Element; retry with --sae-h2e\n");
	}

out:
	memset(passphrase, 0, sizeof(passphrase));
	rtl_station_clear(&join.station);
	if (opened) {
		rtl_mac_power_off(&d);
		rtl_close(&d);
	}
	return rc ? 1 : 0;
}

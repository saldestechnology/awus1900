// SPDX-License-Identifier: BSD-3-Clause
/* Small DHCPv4 client for an already associated WPA2 station. */
#include <arpa/inet.h>
#include <time.h>
#include "rtl8814au.h"

#define DHCP_FIXED_LEN 240
#define DHCP_MAX_LEN 512
#define DHCP_PORT_CLIENT 68
#define DHCP_PORT_SERVER 67

static const u8 broadcast_mac[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

static u16 get_be16(const u8 *p)
{
	return ((u16)p[0] << 8) | p[1];
}

static u32 get_be32(const u8 *p)
{
	return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | p[3];
}

static void put_be16(u8 *p, u16 v)
{
	p[0] = v >> 8;
	p[1] = v;
}

static void put_be32(u8 *p, u32 v)
{
	p[0] = v >> 24;
	p[1] = v >> 16;
	p[2] = v >> 8;
	p[3] = v;
}

static u16 ipv4_checksum(const u8 *data, size_t len)
{
	u32 sum = 0;

	for (size_t i = 0; i + 1 < len; i += 2)
		sum += get_be16(data + i);
	if (len & 1)
		sum += (u16)data[len - 1] << 8;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (u16)~sum;
}

static size_t add_option(u8 *p, size_t off, u8 code, const u8 *value, u8 len)
{
	p[off++] = code;
	p[off++] = len;
	memcpy(p + off, value, len);
	return off + len;
}

static int build_message(struct rtl_dhcp_client *c, bool request, bool renewal,
			 u8 *packet, size_t capacity, size_t *packet_len)
{
	u8 bootp[DHCP_MAX_LEN] = {0};
	u8 client_id[1 + ETH_ALEN], requested[4], server[4], params[] = {1, 3, 6, 51};
	size_t opt = DHCP_FIXED_LEN, bootp_len, udp_len, ip_len;
	u8 *ip, *udp, *body;

	if (!c || !c->station || !packet || !packet_len || capacity < 20 + 8 + DHCP_FIXED_LEN)
		return -EINVAL;
	bootp[0] = 1; /* BOOTREQUEST */
	bootp[1] = 1; /* Ethernet */
	bootp[2] = ETH_ALEN;
	put_be32(bootp + 4, c->xid);
	put_be16(bootp + 10, 0x8000); /* Ask the server to broadcast the reply. */
	if (renewal)
		memcpy(bootp + 12, c->address, sizeof(c->address));
	memcpy(bootp + 28, c->station->dev->efuse.addr, ETH_ALEN);
	bootp[236] = 99;
	bootp[237] = 130;
	bootp[238] = 83;
	bootp[239] = 99;
	bootp[opt++] = 53;
	bootp[opt++] = 1;
	bootp[opt++] = request ? 3 : 1; /* REQUEST or DISCOVER */
	client_id[0] = 1;
	memcpy(client_id + 1, c->station->dev->efuse.addr, ETH_ALEN);
	opt = add_option(bootp, opt, 61, client_id, sizeof(client_id));
	if (request && !renewal) {
		memcpy(requested, c->address, sizeof(requested));
		memcpy(server, c->server, sizeof(server));
		opt = add_option(bootp, opt, 50, requested, sizeof(requested));
		opt = add_option(bootp, opt, 54, server, sizeof(server));
	}
	opt = add_option(bootp, opt, 55, params, sizeof(params));
	bootp[opt++] = 255;
	bootp_len = opt;
	ip_len = 20 + 8 + bootp_len;
	if (ip_len > capacity || ip_len > UINT16_MAX)
		return -EMSGSIZE;
	memset(packet, 0, ip_len);
	ip = packet;
	ip[0] = 0x45;
	put_be16(ip + 2, (u16)ip_len);
	put_be16(ip + 4, (u16)c->xid);
	ip[8] = 64;
	ip[9] = 17;
	if (renewal)
		memcpy(ip + 12, c->address, 4);
	memset(ip + 16, 0xff, 4);
	put_be16(ip + 10, ipv4_checksum(ip, 20));
	udp = ip + 20;
	put_be16(udp, DHCP_PORT_CLIENT);
	put_be16(udp + 2, DHCP_PORT_SERVER);
	udp_len = 8 + bootp_len;
	put_be16(udp + 4, (u16)udp_len);
	body = udp + 8;
	memcpy(body, bootp, bootp_len);
	*packet_len = ip_len;
	return 0;
}

static int send_message(struct rtl_dhcp_client *c, bool request, bool renewal)
{
	u8 packet[DHCP_MAX_LEN];
	size_t packet_len;
	int ret;

	ret = build_message(c, request, renewal, packet, sizeof(packet), &packet_len);
	if (!ret)
		ret = rtl_station_send_ethernet(c->station, broadcast_mac, 0x0800,
						packet, packet_len);
	memset(packet, 0, sizeof(packet));
	return ret;
}

int rtl_dhcp_start(struct rtl_dhcp_client *c, struct rtl_station *station)
{
	int ret;

	if (!c || !station || station->state != RTL_STA_CONNECTED)
		return -EINVAL;
	memset(c, 0, sizeof(*c));
	c->station = station;
	c->xid = arc4random();
	if (!c->xid)
		c->xid = 1;
	ret = send_message(c, false, false);
	if (ret) {
		c->state = RTL_DHCP_FAILED;
		c->error = ret;
		return ret;
	}
	c->state = RTL_DHCP_WAIT_OFFER;
	c->retry_at = (u64)time(NULL) + 4;
	return 0;
}

struct parsed_options {
	u8 message_type;
	u8 server[4];
	u8 netmask[4];
	u8 gateway[4];
	u8 dns[4];
	u32 lease_seconds;
	bool has_type;
	bool has_server;
	bool has_netmask;
	bool has_gateway;
	bool has_dns;
};

static bool parse_options(const u8 *p, size_t len, struct parsed_options *out)
{
	size_t off = DHCP_FIXED_LEN;

	if (len < DHCP_FIXED_LEN || p[236] != 99 || p[237] != 130 ||
	    p[238] != 83 || p[239] != 99)
		return false;
	memset(out, 0, sizeof(*out));
	while (off < len) {
		u8 code = p[off++], n;
		const u8 *v;

		if (code == 0)
			continue;
		if (code == 255)
			return true;
		if (off >= len)
			return false;
		n = p[off++];
		if (n > len - off)
			return false;
		v = p + off;
		switch (code) {
		case 1:
			if (n == 4) {
				memcpy(out->netmask, v, 4);
				out->has_netmask = true;
			}
			break;
		case 3:
			if (n >= 4) {
				memcpy(out->gateway, v, 4);
				out->has_gateway = true;
			}
			break;
		case 6:
			if (n >= 4) {
				memcpy(out->dns, v, 4);
				out->has_dns = true;
			}
			break;
		case 51:
			if (n == 4)
				out->lease_seconds = get_be32(v);
			break;
		case 53:
			if (n == 1) {
				out->message_type = v[0];
				out->has_type = true;
			}
			break;
		case 54:
			if (n == 4) {
				memcpy(out->server, v, 4);
				out->has_server = true;
			}
			break;
		default:
			break;
		}
		off += n;
	}
	return false; /* DHCP options require an END marker. */
}

static bool all_zero(const u8 *p, size_t len)
{
	u8 v = 0;

	for (size_t i = 0; i < len; i++)
		v |= p[i];
	return v == 0;
}

static bool valid_mask(const u8 mask[4])
{
	u32 value = get_be32(mask);
	u32 inverted = ~value;

	return value && (inverted & (inverted + 1)) == 0;
}

int rtl_dhcp_receive(struct rtl_dhcp_client *c, const u8 *packet, size_t len)
{
	struct parsed_options options;
	const u8 *ip, *udp, *bootp;
	u16 ip_len, udp_len, frag;
	size_t ihl, bootp_len;
	u8 mac[ETH_ALEN];
	int ret;

	if (!c || !c->station || !packet || c->state == RTL_DHCP_IDLE)
		return -EINVAL;
	if (len < 20 || (packet[0] >> 4) != 4)
		return 0;
	ip = packet;
	ihl = (size_t)(ip[0] & 0x0f) * 4;
	if (ihl < 20 || ihl > len || ip[9] != 17 ||
	    ipv4_checksum(ip, ihl) != 0)
		return 0;
	ip_len = get_be16(ip + 2);
	frag = get_be16(ip + 6);
	if (ip_len < ihl + 8 || ip_len > len || (frag & 0x3fff))
		return 0;
	udp = ip + ihl;
	udp_len = get_be16(udp + 4);
	if (get_be16(udp) != DHCP_PORT_SERVER || get_be16(udp + 2) != DHCP_PORT_CLIENT ||
	    udp_len < 8 + DHCP_FIXED_LEN || udp_len > ip_len - ihl)
		return 0;
	bootp = udp + 8;
	bootp_len = udp_len - 8;
	memcpy(mac, c->station->dev->efuse.addr, sizeof(mac));
	if (bootp[0] != 2 || bootp[1] != 1 || bootp[2] != ETH_ALEN ||
	    get_be32(bootp + 4) != c->xid || memcmp(bootp + 28, mac, ETH_ALEN) ||
	    !parse_options(bootp, bootp_len, &options) || !options.has_type)
		return 0;

	if (c->state == RTL_DHCP_WAIT_OFFER && options.message_type == 2 &&
	    options.has_server && !all_zero(bootp + 16, 4)) {
		memcpy(c->address, bootp + 16, 4);
		memcpy(c->server, options.server, 4);
		if (options.has_netmask)
			memcpy(c->netmask, options.netmask, 4);
		if (options.has_gateway)
			memcpy(c->gateway, options.gateway, 4);
		if (options.has_dns)
			memcpy(c->dns, options.dns, 4);
		c->lease_seconds = options.lease_seconds;
		if (!valid_mask(c->netmask) || all_zero(c->gateway, 4))
			return 0;
		ret = send_message(c, true, false);
		if (ret) {
			c->state = RTL_DHCP_FAILED;
			c->error = ret;
			return c->error;
		}
		c->state = RTL_DHCP_WAIT_ACK;
		c->retries = 0;
		c->retry_at = (u64)time(NULL) + 4;
		return 1;
	}
	if ((c->state == RTL_DHCP_WAIT_ACK || c->state == RTL_DHCP_RENEWING) &&
	    options.has_server && (c->state == RTL_DHCP_RENEWING ||
	    !memcmp(options.server, c->server, 4))) {
		if (options.message_type == 6) {
			c->state = RTL_DHCP_FAILED;
			c->error = -ECONNREFUSED;
			return c->error;
		}
		if (options.message_type != 5)
			return 0;
		{
			u8 address[4], netmask[4], gateway[4];
			bool renewal = c->state == RTL_DHCP_RENEWING;

			memcpy(address, c->address, 4);
			memcpy(netmask, c->netmask, 4);
			memcpy(gateway, c->gateway, 4);
			if (!all_zero(bootp + 16, 4))
				memcpy(address, bootp + 16, 4);
			if (options.has_netmask)
				memcpy(netmask, options.netmask, 4);
			if (options.has_gateway)
				memcpy(gateway, options.gateway, 4);
			if (all_zero(address, 4) || !valid_mask(netmask) ||
			    all_zero(gateway, 4) || !options.lease_seconds ||
			    (renewal && (memcmp(address, c->address, 4) ||
					 memcmp(netmask, c->netmask, 4) ||
					 memcmp(gateway, c->gateway, 4)))) {
				c->state = RTL_DHCP_FAILED;
				c->error = renewal ? -ESTALE : -EBADMSG;
				return c->error;
			}
			memcpy(c->address, address, 4);
			memcpy(c->netmask, netmask, 4);
			memcpy(c->gateway, gateway, 4);
		}
		if (options.has_dns)
			memcpy(c->dns, options.dns, 4);
		if (options.has_server)
			memcpy(c->server, options.server, 4);
		c->lease_seconds = options.lease_seconds;
		c->lease_started = (u64)time(NULL);
		c->renew_at = c->lease_started + (u64)c->lease_seconds * 7 / 8;
		c->expires_at = c->lease_started + c->lease_seconds;
		c->retries = 0;
		c->state = RTL_DHCP_BOUND;
		return 1;
	}
	return 0;
}

int rtl_dhcp_tick(struct rtl_dhcp_client *c)
{
	u64 now;
	bool renewal;
	int ret;

	if (!c || !c->station)
		return -EINVAL;
	now = (u64)time(NULL);
	if (c->state == RTL_DHCP_BOUND) {
		if (now >= c->expires_at) {
			c->state = RTL_DHCP_FAILED;
			c->error = -ETIME;
			return c->error;
		}
		if (now < c->renew_at)
			return 0;
		c->xid = arc4random();
		if (!c->xid)
			c->xid = 1;
		ret = send_message(c, true, true);
		if (ret) {
			c->state = RTL_DHCP_FAILED;
			c->error = ret;
			return ret;
		}
		c->state = RTL_DHCP_RENEWING;
		c->retries = 0;
		c->retry_at = now + 4;
		return 1;
	}
	if (c->state != RTL_DHCP_WAIT_OFFER && c->state != RTL_DHCP_WAIT_ACK &&
	    c->state != RTL_DHCP_RENEWING)
		return c->state == RTL_DHCP_FAILED ? c->error : 0;
	if (c->state == RTL_DHCP_RENEWING && now >= c->expires_at) {
		c->state = RTL_DHCP_FAILED;
		c->error = -ETIME;
		return c->error;
	}
	if (now < c->retry_at)
		return 0;
	renewal = c->state == RTL_DHCP_RENEWING;
	if (!renewal && c->retries >= 5) {
		c->state = RTL_DHCP_FAILED;
		c->error = -ETIMEDOUT;
		return c->error;
	}
	ret = send_message(c, c->state != RTL_DHCP_WAIT_OFFER, renewal);
	if (ret) {
		c->state = RTL_DHCP_FAILED;
		c->error = ret;
		return ret;
	}
	c->retries++;
	c->retry_at = now + (renewal && c->retries >= 3 ? 10 : c->retries >= 2 ? 8 : 4);
	return 1;
}

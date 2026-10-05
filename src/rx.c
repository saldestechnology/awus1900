// SPDX-License-Identifier: BSD-3-Clause
/* RX path: bulk-IN parsing (rtw88 usb.c rx handler / rx.c rtw_rx_query_rx_desc), monitor-mode
 * filter setup and radiotap/pcap output.
 */
#include <sys/time.h>
#include "rtl8814au.h"
#include "rtw/rx.h"

#define RX_BUF_SIZE 32768

/* Accept everything for monitor mode (rtw_ops_configure_filter with all FIF_* set). */
void rtl_rx_monitor_enable(struct rtw_dev *d, bool accept_bad_fcs)
{
	d->hal.rcr = BIT_APP_FCS | BIT_APP_MIC | BIT_APP_ICV | BIT_PKTCTL_DLEN | BIT_HTC_LOC_CTRL |
		     BIT_APP_PHYSTS | BIT_VHT_DACK | BIT_AB | BIT_AM | BIT_APM | BIT_AAP;
	if (accept_bad_fcs)
		d->hal.rcr |= BIT_ACRC32;
	d->hal.rcr &= ~(BIT_CBSSID_BCN | BIT_CBSSID_DATA);

	rtw_write16(d, REG_RXFLTMAP0, 0xffff);	/* management */
	rtw_write16(d, REG_RXFLTMAP1, 0xffff);	/* control */
	rtw_write16(d, REG_RXFLTMAP2, 0xffff);	/* data */
	rtw_write32(d, REG_RCR, d->hal.rcr);
}

/* rtw_rx_query_rx_desc */
static void query_rx_desc(struct rtw_dev *d, const u8 *rx_desc8, u8 *rx_buf,
			  struct rtw_rx_pkt_stat *ps)
{
	const struct rtw_rx_desc *rd = (const struct rtw_rx_desc *)rx_desc8;
	u32 enc_type, swdec;
	u8 *phy_status;

	memset(ps, 0, sizeof(*ps));
	ps->pkt_len = le32_get_bits(rd->w0, RTW_RX_DESC_W0_PKT_LEN);
	ps->crc_err = le32_get_bits(rd->w0, RTW_RX_DESC_W0_CRC32);
	ps->icv_err = le32_get_bits(rd->w0, RTW_RX_DESC_W0_ICV_ERR);
	ps->drv_info_sz = le32_get_bits(rd->w0, RTW_RX_DESC_W0_DRV_INFO_SIZE);
	enc_type = le32_get_bits(rd->w0, RTW_RX_DESC_W0_ENC_TYPE);
	ps->shift = le32_get_bits(rd->w0, RTW_RX_DESC_W0_SHIFT);
	ps->phy_status = le32_get_bits(rd->w0, RTW_RX_DESC_W0_PHYST);
	swdec = le32_get_bits(rd->w0, RTW_RX_DESC_W0_SWDEC);
	ps->decrypted = !swdec && enc_type != RX_DESC_ENC_NONE;
	ps->cam_id = le32_get_bits(rd->w1, RTW_RX_DESC_W1_MACID);
	ps->is_c2h = le32_get_bits(rd->w2, RTW_RX_DESC_W2_C2H);
	ps->ppdu_cnt = le32_get_bits(rd->w2, RTW_RX_DESC_W2_PPDU_CNT);
	ps->rate = le32_get_bits(rd->w3, RTW_RX_DESC_W3_RX_RATE);
	ps->bw = le32_get_bits(rd->w4, RTW_RX_DESC_W4_BW);
	ps->tsf_low = le32_get_bits(rd->w5, RTW_RX_DESC_W5_TSFL);

	if (ps->rate >= DESC_RATE_MAX) {
		ps->rate = DESC_RATE1M;
		ps->bw = RTW_CHANNEL_WIDTH_20;
	}

	ps->drv_info_sz *= 8;	/* unit of 8 bytes */
	if (ps->is_c2h)
		return;

	phy_status = rx_buf + ps->shift;
	if (ps->phy_status)
		d->chip->ops->query_phy_status(d, phy_status, ps);
}

/* ---- radiotap + pcap ---- */
static int rate_to_radiotap(u8 r)
{
	static const u8 legacy[] = { 2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108 };

	return r < sizeof(legacy) ? legacy[r] : 0;
}

static void put16(u8 *p, u16 v) { p[0] = v; p[1] = v >> 8; }
static void put32(u8 *p, u32 v) { put16(p, v); put16(p + 2, v >> 16); }

/* Build a radiotap header; returns its length. */
static int build_radiotap(struct rtw_dev *d, const struct rtw_rx_pkt_stat *ps, u8 *out)
{
	bool ht = ps->rate >= DESC_RATEMCS0 && ps->rate < DESC_RATEVHT1SS_MCS0;
	bool vht = ps->rate >= DESC_RATEVHT1SS_MCS0;
	u32 present = BIT(0) | BIT(1) | BIT(3) | BIT(5);	/* TSFT FLAGS CHANNEL DBM_ANTSIGNAL */
	u8 *p = out + 8;
	u16 freq = 0, chflags;
	u8 flags = 0x10;	/* FCS at end */

	if (!ht && !vht)
		present |= BIT(2);	/* RATE */
	if (ht)
		present |= BIT(19);
	if (vht)
		present |= BIT(21);

	memset(out, 0, 64);
	out[0] = 0;
	put32(out + 4, present);

	/* TSFT (u64, align 8): only the low 32 bits are provided by the descriptor */
	p = out + 8;
	put32(p, ps->tsf_low);
	p += 8;
	if (ps->crc_err)
		flags |= 0x40;
	*p++ = flags;
	if (!ht && !vht)
		*p++ = rate_to_radiotap(ps->rate);
	/* CHANNEL (u16 freq, u16 flags), align 2 */
	if ((p - out) & 1)
		p++;
	if (d->hal.current_channel >= 1 && d->hal.current_channel <= 13)
		freq = 2407 + 5 * d->hal.current_channel;
	else if (d->hal.current_channel == 14)
		freq = 2484;
	else
		freq = 5000 + 5 * d->hal.current_channel;
	if (d->hal.current_channel <= 14)
		chflags = 0x0080 | (ps->rate <= DESC_RATE11M ? 0x0020 : 0x0040);
	else
		chflags = 0x0100 | 0x0040;
	put16(p, freq);
	put16(p + 2, chflags);
	p += 4;
	*p++ = (s8)ps->signal_power;
	if (ht) {
		u8 mcs = ps->rate - DESC_RATEMCS0;

		*p++ = 0x02 | 0x01;			/* known: bw, mcs */
		*p++ = ps->bw == RTW_CHANNEL_WIDTH_40 ? 1 : 0;
		*p++ = mcs;
	}
	if (vht) {
		u8 nss, mcs;

		if (ps->rate >= DESC_RATEVHT4SS_MCS0) { nss = 4; mcs = ps->rate - DESC_RATEVHT4SS_MCS0; }
		else if (ps->rate >= DESC_RATEVHT3SS_MCS0) { nss = 3; mcs = ps->rate - DESC_RATEVHT3SS_MCS0; }
		else if (ps->rate >= DESC_RATEVHT2SS_MCS0) { nss = 2; mcs = ps->rate - DESC_RATEVHT2SS_MCS0; }
		else { nss = 1; mcs = ps->rate - DESC_RATEVHT1SS_MCS0; }
		if ((p - out) & 1)
			p++;
		put16(p, 0x0040);			/* known: bandwidth */
		p[2] = 0;				/* flags */
		p[3] = ps->bw == RTW_CHANNEL_WIDTH_80 ? 4 : (ps->bw == RTW_CHANNEL_WIDTH_40 ? 1 : 0);
		p[4] = (mcs << 4) | nss;
		p += 12 - 0;
		p -= 0;
	}
	put16(out + 2, p - out);
	return p - out;
}

struct pcap_out { FILE *f; };

void rtl_pcap_open(struct pcap_out **po, const char *path)
{
	struct pcap_out *o = calloc(1, sizeof(*o));
	u8 hdr[24] = { 0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0 };

	put32(hdr + 16, 65535);
	put32(hdr + 20, 127);		/* LINKTYPE_IEEE802_11_RADIOTAP */
	o->f = fopen(path, "wb");
	if (o->f)
		fwrite(hdr, 1, sizeof(hdr), o->f);
	*po = o;
}

void rtl_pcap_close(struct pcap_out *o)
{
	if (o->f)
		fclose(o->f);
	free(o);
}

static void pcap_write(struct pcap_out *o, const u8 *rt, int rtlen, const u8 *frame, int len)
{
	struct timeval tv;
	u8 rec[16];

	if (!o || !o->f)
		return;
	gettimeofday(&tv, NULL);
	put32(rec, tv.tv_sec);
	put32(rec + 4, tv.tv_usec);
	put32(rec + 8, rtlen + len);
	put32(rec + 12, rtlen + len);
	fwrite(rec, 1, 16, o->f);
	fwrite(rt, 1, rtlen, o->f);
	fwrite(frame, 1, len, o->f);
}

/* Read one bulk-IN transfer and process all aggregated packets in it. Returns packets seen
 * or a negative libusb error. */
int rtl_rx_poll(struct rtw_dev *d, struct pcap_out *po, struct rtl_rx_stats *st, int timeout_ms)
{
	static u8 buf[RX_BUF_SIZE];
	u32 pkt_desc_sz = d->chip->rx_pkt_desc_sz;
	int len = 0, rc, count = 0;
	u8 *rx_desc;

	rtl_thermal_track_tick(d);
	rc = libusb_bulk_transfer(d->h, d->in_ep, buf, sizeof(buf), &len, timeout_ms);
	if (rc == LIBUSB_ERROR_TIMEOUT)
		return 0;
	if (rc && !len)
		return rc;

	rx_desc = buf;
	while (rx_desc + pkt_desc_sz < buf + len) {
		struct rtw_rx_pkt_stat ps;
		u8 *rx_buf = rx_desc + pkt_desc_sz;
		u32 pkt_offset, skb_len, next;

		query_rx_desc(d, rx_desc, rx_buf, &ps);
		pkt_offset = pkt_desc_sz + ps.drv_info_sz + ps.shift;
		skb_len = ps.pkt_len + pkt_offset;
		if (skb_len > RX_BUF_SIZE || rx_desc + skb_len > buf + len) {
			st->bad++;
			break;
		}
		next = (skb_len + 7) & ~7u;

		if (ps.is_c2h) {
			st->c2h++;
		} else if (ps.pkt_len > 4) {
			u8 rt[64];
			int rtlen = build_radiotap(d, &ps, rt);

			pcap_write(po, rt, rtlen, rx_desc + pkt_offset, ps.pkt_len);
			st->frames++;
			if (ps.crc_err)
				st->crc_err++;
			if (st->cb)
				st->cb(st->cb_ctx, &ps, rx_desc + pkt_offset, ps.pkt_len);
			count++;
		}
		rx_desc += next;
	}
	return count;
}

// SPDX-License-Identifier: BSD-3-Clause
/* TX descriptor construction and USB queue routing, ported from the BSD-3-Clause side of rtw88. */
#include "rtl8814au.h"

static int dma_mapping_to_ep(struct rtw_dev *d, enum rtw_dma_mapping mapping)
{
	int ep;

	switch (mapping) {
	case RTW_DMA_MAPPING_HIGH:
		ep = 0;
		break;
	case RTW_DMA_MAPPING_NORMAL:
		ep = 1;
		break;
	case RTW_DMA_MAPPING_LOW:
		ep = 2;
		break;
	case RTW_DMA_MAPPING_EXTRA:
		ep = 3;
		break;
	default:
		return -EINVAL;
	}

	return ep < d->num_out_ep ? ep : -EINVAL;
}

static int qsel_to_ep(struct rtw_dev *d, u8 qsel)
{
	const struct rtw_rqpn *rqpn = d->fifo.rqpn;
	enum rtw_dma_mapping mapping;

	if (!rqpn)
		return -EINVAL;

	switch (qsel) {
	case TX_DESC_QSEL_TID0:
	case TX_DESC_QSEL_TID3:
		mapping = rqpn->dma_map_be;
		break;
	case TX_DESC_QSEL_TID1:
	case TX_DESC_QSEL_TID2:
		mapping = rqpn->dma_map_bk;
		break;
	case TX_DESC_QSEL_TID4:
	case TX_DESC_QSEL_TID5:
		mapping = rqpn->dma_map_vi;
		break;
	case TX_DESC_QSEL_TID6:
	case TX_DESC_QSEL_TID7:
		mapping = rqpn->dma_map_vo;
		break;
	case TX_DESC_QSEL_BEACON:
	case TX_DESC_QSEL_HIGH:
	case TX_DESC_QSEL_H2C:
		mapping = rqpn->dma_map_hi;
		break;
	case TX_DESC_QSEL_MGMT:
		mapping = rqpn->dma_map_mg;
		break;
	default:
		return -EINVAL;
	}

	return dma_mapping_to_ep(d, mapping);
}

/* rtw_tx_fill_tx_desc(), preserving rtw88's 8814A descriptor bit layout. */
void rtw_tx_fill_tx_desc(struct rtw_dev *rtwdev,
			 struct rtw_tx_pkt_info *pkt_info,
			 struct rtw_tx_desc *tx_desc)
{
	bool more_data = pkt_info->qsel == TX_DESC_QSEL_HIGH;

	tx_desc->w0 = le32_encode_bits(pkt_info->tx_pkt_size, RTW_TX_DESC_W0_TXPKTSIZE) |
		      le32_encode_bits(pkt_info->offset, RTW_TX_DESC_W0_OFFSET) |
		      le32_encode_bits(pkt_info->bmc, RTW_TX_DESC_W0_BMC) |
		      le32_encode_bits(pkt_info->ls, RTW_TX_DESC_W0_LS) |
		      le32_encode_bits(pkt_info->dis_qselseq, RTW_TX_DESC_W0_DISQSELSEQ);

	tx_desc->w1 = le32_encode_bits(pkt_info->mac_id, RTW_TX_DESC_W1_MACID) |
		      le32_encode_bits(pkt_info->qsel, RTW_TX_DESC_W1_QSEL) |
		      le32_encode_bits(pkt_info->rate_id, RTW_TX_DESC_W1_RATE_ID) |
		      le32_encode_bits(pkt_info->sec_type, RTW_TX_DESC_W1_SEC_TYPE) |
		      le32_encode_bits(pkt_info->pkt_offset, RTW_TX_DESC_W1_PKT_OFFSET) |
		      le32_encode_bits(more_data, RTW_TX_DESC_W1_MORE_DATA);

	tx_desc->w2 = le32_encode_bits(pkt_info->ampdu_en, RTW_TX_DESC_W2_AGG_EN) |
		      le32_encode_bits(pkt_info->report, RTW_TX_DESC_W2_SPE_RPT) |
		      le32_encode_bits(pkt_info->ampdu_density, RTW_TX_DESC_W2_AMPDU_DEN) |
		      le32_encode_bits(pkt_info->bt_null, RTW_TX_DESC_W2_BT_NULL);

	tx_desc->w3 = le32_encode_bits(pkt_info->hw_ssn_sel, RTW_TX_DESC_W3_HW_SSN_SEL) |
		      le32_encode_bits(pkt_info->use_rate, RTW_TX_DESC_W3_USE_RATE) |
		      le32_encode_bits(pkt_info->dis_rate_fallback, RTW_TX_DESC_W3_DISDATAFB) |
		      le32_encode_bits(pkt_info->rts, RTW_TX_DESC_W3_USE_RTS) |
		      le32_encode_bits(pkt_info->nav_use_hdr, RTW_TX_DESC_W3_NAVUSEHDR) |
		      le32_encode_bits(pkt_info->ampdu_factor, RTW_TX_DESC_W3_MAX_AGG_NUM);

	tx_desc->w4 = le32_encode_bits(pkt_info->rate, RTW_TX_DESC_W4_DATARATE);
	if (rtwdev->chip->old_datarate_fb_limit)
		tx_desc->w4 |= le32_encode_bits(0x1f, RTW_TX_DESC_W4_DATARATE_FB_LIMIT);

	tx_desc->w5 = le32_encode_bits(pkt_info->short_gi, RTW_TX_DESC_W5_DATA_SHORT) |
		      le32_encode_bits(pkt_info->bw, RTW_TX_DESC_W5_DATA_BW) |
		      le32_encode_bits(pkt_info->ldpc, RTW_TX_DESC_W5_DATA_LDPC) |
		      le32_encode_bits(pkt_info->stbc, RTW_TX_DESC_W5_DATA_STBC);

	tx_desc->w6 = le32_encode_bits(pkt_info->sn, RTW_TX_DESC_W6_SW_DEFINE);
	tx_desc->w8 = le32_encode_bits(pkt_info->en_hwseq, RTW_TX_DESC_W8_EN_HWSEQ);
	tx_desc->w9 = le32_encode_bits(pkt_info->seq, RTW_TX_DESC_W9_SW_SEQ);

	if (pkt_info->rts) {
		tx_desc->w4 |= le32_encode_bits(DESC_RATE24M, RTW_TX_DESC_W4_RTSRATE);
		tx_desc->w5 |= le32_encode_bits(1, RTW_TX_DESC_W5_DATA_RTS_SHORT);
	}

	if (pkt_info->tim_offset)
		tx_desc->w9 |= le32_encode_bits(1, RTW_TX_DESC_W9_TIM_EN) |
			       le32_encode_bits(pkt_info->tim_offset, RTW_TX_DESC_W9_TIM_OFFSET);
}

static bool frame_is_bmc(const u8 *frame)
{
	u8 fc0 = frame[0], fc1 = frame[1];
	const u8 *da = (fc0 & 0x0c) == 0x08 && (fc1 & 0x01) ? frame + 16 : frame + 4;

	return (da[0] & 1) != 0;
}

static int submit_frame(struct rtw_dev *d, const u8 *frame, size_t frame_len,
			u8 rate, u8 qsel)
{
	struct rtw_tx_desc *tx_desc;
	struct rtw_tx_pkt_info pkt_info = {0};
	u8 *transfer;
	size_t transfer_len;
	int ep, ret;

	if (!d || !d->h || !d->chip || !d->chip->ops || !d->tx_regd_explicit || !frame ||
	    frame_len < 24 || frame_len > IEEE80211_MAX_DATA_LEN ||
	    !d->chip->ops->fill_txdesc_checksum)
		return -EINVAL;

	ep = qsel_to_ep(d, qsel);
	if (ep < 0)
		return ep;

	transfer_len = d->chip->tx_pkt_desc_sz + frame_len;
	transfer = calloc(1, transfer_len);
	if (!transfer)
		return -ENOMEM;

	pkt_info.tx_pkt_size = (u32)frame_len;
	pkt_info.offset = d->chip->tx_pkt_desc_sz;
	pkt_info.mac_id = 0;
	pkt_info.qsel = qsel;
	pkt_info.rate_id = d->hal.primary_channel > 14 ? RTW_RATEID_G : RTW_RATEID_B_20M;
	pkt_info.rate = rate;
	pkt_info.use_rate = true;
	pkt_info.dis_rate_fallback = true;
	pkt_info.dis_qselseq = true;
	pkt_info.en_hwseq = true;
	pkt_info.hw_ssn_sel = 0;
	pkt_info.bmc = frame_is_bmc(frame);
	pkt_info.ls = true;

	tx_desc = (struct rtw_tx_desc *)transfer;
	rtw_tx_fill_tx_desc(d, &pkt_info, tx_desc);
	d->chip->ops->fill_txdesc_checksum(d, &pkt_info, tx_desc);
	memcpy(transfer + d->chip->tx_pkt_desc_sz, frame, frame_len);

	ret = rtl_bulk_out(d, ep, transfer, (int)transfer_len, 1000);
	free(transfer);
	if (!ret)
		d->dm_info.tx_rate = rate;
	return ret;
}

int rtl_send_station_management(struct rtw_dev *d, const u8 *frame, size_t frame_len)
{
	u8 rate;

	if (!d || !frame || frame_len < 24 || (frame[0] & 0x0c) != 0 ||
	    memcmp(frame + 10, d->efuse.addr, ETH_ALEN))
		return -EINVAL;
	rate = d->hal.primary_channel > 14 ? DESC_RATE6M : DESC_RATE1M;
	return submit_frame(d, frame, frame_len, rate, TX_DESC_QSEL_MGMT);
}

int rtl_send_station_data(struct rtw_dev *d, const u8 *frame, size_t frame_len)
{
	u8 rate;

	if (!d || !frame || frame_len < 24 || (frame[0] & 0x0c) != 0x08 ||
	    (frame[1] & 0x03) != 0x01 ||
	    memcmp(frame + 10, d->efuse.addr, ETH_ALEN))
		return -EINVAL;
	rate = d->hal.primary_channel > 14 ? DESC_RATE6M : DESC_RATE1M;
	return submit_frame(d, frame, frame_len, rate, TX_DESC_QSEL_TID0);
}

static void put_le16(u8 *dst, u16 value)
{
	dst[0] = value;
	dst[1] = value >> 8;
}

static size_t append_ie(u8 *frame, size_t offset, u8 id, const u8 *data, size_t len)
{
	frame[offset++] = id;
	frame[offset++] = (u8)len;
	memcpy(frame + offset, data, len);
	return offset + len;
}

/* Send only a standards-compliant broadcast Probe Request; arbitrary frame injection is not exposed. */
int rtl_send_probe_request(struct rtw_dev *d, const char *ssid)
{
	static const u8 broadcast[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	static const u8 rates_2g[] = { 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24 };
	static const u8 ext_rates_2g[] = { 0x30, 0x48, 0x60, 0x6c };
	static const u8 rates_5g[] = { 0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c };
	u8 frame[80];
	const u8 *rates;
	size_t rates_len, ssid_len, offset = 24;

	if (!d || !d->h || !d->hal.primary_channel)
		return -EINVAL;

	ssid = ssid ? ssid : "";
	ssid_len = strlen(ssid);
	if (ssid_len > 32)
		return -EINVAL;

	/* 802.11 Probe Request: broadcast DA/BSSID, adapter efuse MAC as SA. */
	memset(frame, 0, sizeof(frame));
	put_le16(frame, 0x0040); /* Management, Probe Request */
	memcpy(frame + 4, broadcast, sizeof(broadcast));
	memcpy(frame + 10, d->efuse.addr, ETH_ALEN);
	memcpy(frame + 16, broadcast, sizeof(broadcast));
	offset = append_ie(frame, offset, 0, (const u8 *)ssid, ssid_len);

	if (d->hal.primary_channel > 14) {
		rates = rates_5g;
		rates_len = sizeof(rates_5g);
	} else {
		rates = rates_2g;
		rates_len = sizeof(rates_2g);
	}
	offset = append_ie(frame, offset, 1, rates, rates_len);
	if (d->hal.primary_channel <= 14)
		offset = append_ie(frame, offset, 50, ext_rates_2g, sizeof(ext_rates_2g));

	return rtl_send_station_management(d, frame, offset);
}

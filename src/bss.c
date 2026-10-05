// SPDX-License-Identifier: BSD-3-Clause
/* Passive beacon/Probe Response IE parser. */
#include "rtl8814au.h"

static u16 get_le16(const u8 *p)
{
	return p[0] | ((u16)p[1] << 8);
}

static int parse_rsn(const u8 *ie, size_t len, struct rtl_bss_info *out)
{
	static const u8 ccmp_suite[4] = { 0x00, 0x0f, 0xac, 0x04 };
	static const u8 psk_suite[4] = { 0x00, 0x0f, 0xac, 0x02 };
	static const u8 sae_suite[4] = { 0x00, 0x0f, 0xac, 0x08 };
	const u8 *p = ie, *end = ie + len;
	u16 count;

	if (len < 2 || get_le16(p) != 1)
		return -EINVAL;
	p += 2;
	if ((size_t)(end - p) < 4 + 2)
		return -EINVAL;
	p += 4; /* group cipher suite */
	count = get_le16(p);
	p += 2;
	if (count > (size_t)(end - p) / 4)
		return -EINVAL;
	for (u16 i = 0; i < count; i++, p += 4)
		if (!memcmp(p, ccmp_suite, sizeof(ccmp_suite)))
			out->rsn_ccmp = true;

	if ((size_t)(end - p) < 2)
		return -EINVAL;
	count = get_le16(p);
	p += 2;
	if (count > (size_t)(end - p) / 4)
		return -EINVAL;
	for (u16 i = 0; i < count; i++, p += 4) {
		if (!memcmp(p, psk_suite, sizeof(psk_suite)))
			out->rsn_psk = true;
		if (!memcmp(p, sae_suite, sizeof(sae_suite)))
			out->rsn_sae = true;
	}

	/* Validate optional RSN capabilities, PMKID list, and group-management cipher. */
	if (p < end) {
		if ((size_t)(end - p) < 2)
			return -EINVAL;
		p += 2; /* RSN capabilities */
	}
	if (p < end) {
		if ((size_t)(end - p) < 2)
			return -EINVAL;
		count = get_le16(p);
		p += 2;
		if (count > (size_t)(end - p) / 16)
			return -EINVAL;
		p += count * 16;
	}
	if (p < end) {
		if ((size_t)(end - p) != 4)
			return -EINVAL;
		p += 4; /* Group management cipher suite */
	}
	if (p != end)
		return -EINVAL;
	out->rsn_present = true;
	return 0;
}

/* Return 1 for a valid beacon/Probe Response, 0 for other frame types, or -EINVAL for malformed input. */
int rtl_parse_bss(const u8 *frame, size_t len, u8 tuned_channel, s32 signal_dbm,
		  struct rtl_bss_info *out)
{
	size_t frame_len, offset;
	u16 frame_control, capability;
	bool have_ssid = false, have_channel = false;

	if (!frame || !out || len < 24 + 12 + 4)
		return -EINVAL;

	frame_control = get_le16(frame);
	if ((frame_control & 0x00fc) != 0x0080 &&
	    (frame_control & 0x00fc) != 0x0050)
		return 0;

	frame_len = len - 4; /* RX monitor configuration appends the FCS. */
	if (frame_len < 24 + 12)
		return -EINVAL;

	memset(out, 0, sizeof(*out));
	memcpy(out->bssid, frame + 16, ETH_ALEN);
	out->channel = tuned_channel;
	out->signal_dbm = signal_dbm;
	capability = get_le16(frame + 34);
	out->privacy = (capability & BIT(4)) != 0;
	offset = 36;

	while (offset < frame_len) {
		u8 id, ie_len;
		const u8 *ie;

		if (frame_len - offset < 2)
			return -EINVAL;
		id = frame[offset];
		ie_len = frame[offset + 1];
		if ((size_t)ie_len > frame_len - offset - 2)
			return -EINVAL;
		ie = frame + offset + 2;

		switch (id) {
		case 0: /* SSID */
			if (!have_ssid) {
				if (ie_len > sizeof(out->ssid))
					return -EINVAL;
				memcpy(out->ssid, ie, ie_len);
				out->ssid_len = ie_len;
				have_ssid = true;
			}
			break;
		case 3: /* DS Parameter Set */
			if (ie_len >= 1) {
				out->channel = ie[0];
				have_channel = true;
			}
			break;
		case 48: /* RSN */
			if (parse_rsn(ie, ie_len, out))
				return -EINVAL;
			break;
		case 244: /* RSN Extension (RSNXE) */
			if (!ie_len || (ie[0] & 0x0f) + 1 != ie_len)
				return -EINVAL;
			out->rsnxe_sae_h2e = (ie[0] & BIT(5)) != 0;
			break;
		case 61: /* HT Operation: primary channel fallback for 5 GHz BSSs */
			if (ie_len >= 1 && !have_channel) {
				out->channel = ie[0];
				have_channel = true;
			}
			break;
		case 221: /* WPA vendor IE (00:50:f2:01) */
			if (ie_len >= 4 && ie[0] == 0x00 && ie[1] == 0x50 &&
			    ie[2] == 0xf2 && ie[3] == 0x01)
				out->wpa_vendor = true;
			break;
		default:
			break;
		}
		offset += 2 + ie_len;
	}

	return 1;
}

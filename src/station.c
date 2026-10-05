// SPDX-License-Identifier: BSD-3-Clause
/* WPA2/WPA3 station authentication, association, and four-way handshake. */
#include "rtl8814au.h"

#define EAPOL_SNAP_LEN 8
#define EAPOL_KEY_FIXED_LEN 99
#define EAPOL_MAX_LEN 4096
#define EAPOL_MIC_OFFSET 81

#define EAPOL_KEY_PAIRWISE BIT(3)
#define EAPOL_KEY_INSTALL BIT(6)
#define EAPOL_KEY_ACK BIT(7)
#define EAPOL_KEY_MIC BIT(8)
#define EAPOL_KEY_SECURE BIT(9)
#define EAPOL_KEY_ERROR BIT(10)
#define EAPOL_KEY_REQUEST BIT(11)
#define EAPOL_KEY_ENCRYPTED BIT(12)

static const u8 eapol_snap[EAPOL_SNAP_LEN] = {
	0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
};

static void clear_bytes(void *ptr, size_t len)
{
	volatile u8 *p = ptr;

	while (len--)
		*p++ = 0;
}

static const u8 rates_2g[] = { 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24 };
static const u8 ext_rates_2g[] = { 0x30, 0x48, 0x60, 0x6c };
static const u8 rates_5g[] = { 0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c };
static const u8 rsn_wpa2_psk_ccmp[] = {
	0x01, 0x00,                   /* RSN version */
	0x00, 0x0f, 0xac, 0x04,       /* group cipher: CCMP-128 */
	0x01, 0x00,                   /* pairwise cipher count */
	0x00, 0x0f, 0xac, 0x04,       /* pairwise cipher: CCMP-128 */
	0x01, 0x00,                   /* AKM suite count */
	0x00, 0x0f, 0xac, 0x02,       /* AKM: PSK */
	0x00, 0x00,                   /* RSN capabilities */
};

static const u8 rsn_wpa2_psk_ccmp_ie[] = {
	48, sizeof(rsn_wpa2_psk_ccmp),
	0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
	0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
	0x01, 0x00, 0x00, 0x0f, 0xac, 0x02,
	0x00, 0x00,
};
static const u8 rsn_wpa3_sae[] = {
	0x01, 0x00,                   /* RSN version */
	0x00, 0x0f, 0xac, 0x04,       /* group cipher: CCMP-128 */
	0x01, 0x00,                   /* pairwise cipher count */
	0x00, 0x0f, 0xac, 0x04,       /* pairwise cipher: CCMP-128 */
	0x01, 0x00,                   /* AKM suite count */
	0x00, 0x0f, 0xac, 0x08,       /* AKM: SAE */
	0xc0, 0x00,                   /* MFPR + MFPC */
	0x00, 0x00,                   /* PMKID count */
	0x00, 0x0f, 0xac, 0x06,       /* group management cipher: BIP-CMAC-128 */
};
static const u8 rsn_wpa3_sae_ie[] = {
	48, sizeof(rsn_wpa3_sae),
	0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
	0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
	0x01, 0x00, 0x00, 0x0f, 0xac, 0x08,
	0xc0, 0x00, 0x00, 0x00,
	0x00, 0x0f, 0xac, 0x06,
};
static const u8 rsnxe_sae_h2e_ie[] = { 244, 1, 0x20 };

static void put_le16(u8 *out, u16 value)
{
	out[0] = value;
	out[1] = value >> 8;
}

static size_t append_ie(u8 *frame, size_t offset, u8 id, const u8 *data, size_t len)
{
	frame[offset++] = id;
	frame[offset++] = (u8)len;
	memcpy(frame + offset, data, len);
	return offset + len;
}

static bool valid_bssid(const u8 *bssid)
{
	static const u8 zero[ETH_ALEN];
	static const u8 broadcast[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	return bssid && !(bssid[0] & 1) && memcmp(bssid, zero, ETH_ALEN) &&
		memcmp(bssid, broadcast, ETH_ALEN);
}

static void mgmt_header(u8 *frame, u16 fc, const u8 bssid[ETH_ALEN],
		       const u8 station[ETH_ALEN])
{
	memset(frame, 0, 24);
	put_le16(frame, fc);
	memcpy(frame + 4, bssid, ETH_ALEN);
	memcpy(frame + 10, station, ETH_ALEN);
	memcpy(frame + 16, bssid, ETH_ALEN);
}

int rtl_station_send_open_auth(struct rtw_dev *d, const u8 bssid[ETH_ALEN])
{
	u8 frame[30];

	if (!d || !valid_bssid(bssid))
		return -EINVAL;
	mgmt_header(frame, 0x00b0, bssid, d->efuse.addr); /* Authentication */
	put_le16(frame + 24, 0); /* Open System */
	put_le16(frame + 26, 1); /* Transaction sequence 1 */
	put_le16(frame + 28, 0);	/* Status: success */
	return rtl_send_station_management(d, frame, sizeof(frame));
}

static int station_send_assoc(struct rtw_dev *d, const u8 bssid[ETH_ALEN],
			      const u8 *ssid, size_t ssid_len, bool use_sae,
			      bool sae_h2e)
{
	u8 frame[128];
	const u8 *rates;
	size_t rates_len, offset = 28;

	if (!d || !valid_bssid(bssid) || !ssid || !ssid_len || ssid_len > 32)
		return -EINVAL;
	mgmt_header(frame, 0x0000, bssid, d->efuse.addr); /* Association Request */
	put_le16(frame + 24, BIT(0) | BIT(4)); /* ESS + privacy */
	put_le16(frame + 26, 10);             /* Listen interval */
	offset = append_ie(frame, offset, 0, ssid, ssid_len);
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
	if (use_sae) {
		offset = append_ie(frame, offset, 48, rsn_wpa3_sae,
				   sizeof(rsn_wpa3_sae));
		if (sae_h2e)
			offset = append_ie(frame, offset, 244, rsnxe_sae_h2e_ie + 2,
					   sizeof(rsnxe_sae_h2e_ie) - 2);
	} else {
		offset = append_ie(frame, offset, 48, rsn_wpa2_psk_ccmp,
				   sizeof(rsn_wpa2_psk_ccmp));
	}
	return rtl_send_station_management(d, frame, offset);
}

int rtl_station_send_wpa2_assoc(struct rtw_dev *d, const u8 bssid[ETH_ALEN],
			       const u8 *ssid, size_t ssid_len)
{
	return station_send_assoc(d, bssid, ssid, ssid_len, false, false);
}

int rtl_station_send_sae_assoc(struct rtw_dev *d, const u8 bssid[ETH_ALEN],
			      const u8 *ssid, size_t ssid_len)
{
	return station_send_assoc(d, bssid, ssid, ssid_len, true, false);
}

int rtl_station_send_sae_h2e_assoc(struct rtw_dev *d, const u8 bssid[ETH_ALEN],
				  const u8 *ssid, size_t ssid_len)
{
	return station_send_assoc(d, bssid, ssid, ssid_len, true, true);
}

static u16 get_le16(const u8 *p)
{
	return p[0] | ((u16)p[1] << 8);
}

static u16 get_be16(const u8 *p)
{
	return ((u16)p[0] << 8) | p[1];
}

static u64 get_be64(const u8 *p)
{
	u64 value = 0;

	for (int i = 0; i < 8; i++)
		value = (value << 8) | p[i];
	return value;
}

static void put_be16(u8 *p, u16 value)
{
	p[0] = value >> 8;
	p[1] = value;
}

static void put_be64(u8 *p, u64 value)
{
	for (int i = 7; i >= 0; i--) {
		p[i] = (u8)value;
		value >>= 8;
	}
}

static bool bytes_nonzero(const u8 *p, size_t len)
{
	u8 v = 0;

	for (size_t i = 0; i < len; i++)
		v |= p[i];
	return v != 0;
}

static bool bytes_equal_ct(const u8 *a, const u8 *b, size_t len)
{
	u8 diff = 0;

	for (size_t i = 0; i < len; i++)
		diff |= a[i] ^ b[i];
	return diff == 0;
}

static int install_key_data_kdes(struct rtl_station *s, const u8 *key_data, size_t len)
{
	size_t offset = 0;
	bool found_gtk = false, found_igtk = false;
	u8 gtk[16] = {0}, igtk[16] = {0}, gtk_id = 0;
	u16 igtk_id = 0;
	u64 igtk_ipn = 0;
	int ret = -EINVAL;

	while (offset < len) {
		size_t remaining = len - offset;
		u8 id, ie_len;

		/* AES key-wrap padding is 0xdd followed by zero bytes. */
		if (key_data[offset] == 0xdd &&
		    (remaining == 1 || !bytes_nonzero(key_data + offset + 1, remaining - 1)))
			break;
		if (!bytes_nonzero(key_data + offset, remaining))
			break;
		if (remaining < 2)
			goto out;
		id = key_data[offset];
		ie_len = key_data[offset + 1];
		if (ie_len > remaining - 2)
			goto out;
		if (id == 221 && ie_len >= 4 &&
		    key_data[offset + 2] == 0x00 && key_data[offset + 3] == 0x0f &&
		    key_data[offset + 4] == 0xac && key_data[offset + 5] == 0x01) {
			if (ie_len != 22 || key_data[offset + 7] != 0 || found_gtk)
				goto out; /* Only GTK-CCMP-128 is implemented. */
			gtk_id = key_data[offset + 6] & 0x03;
			memcpy(gtk, key_data + offset + 8, sizeof(gtk));
			found_gtk = true;
		} else if (id == 221 && ie_len >= 4 &&
			   key_data[offset + 2] == 0x00 && key_data[offset + 3] == 0x0f &&
			   key_data[offset + 4] == 0xac && key_data[offset + 5] == 0x09) {
			if (ie_len != 28 || found_igtk)
				goto out; /* IGTK-BIP-CMAC-128 KDE. */
			igtk_id = key_data[offset + 6] | ((u16)key_data[offset + 7] << 8);
			if (igtk_id < 4 || igtk_id > 5)
				goto out;
			for (unsigned i = 0; i < 6; i++)
				igtk_ipn |= (u64)key_data[offset + 8 + i] << (8 * i);
			memcpy(igtk, key_data + offset + 14, sizeof(igtk));
			found_igtk = true;
		}
		offset += 2 + ie_len;
	}
	if (found_gtk) {
		memcpy(s->gtk, gtk, sizeof(gtk));
		s->gtk_len = sizeof(gtk);
		s->gtk_key_id = gtk_id;
		s->has_gtk = true;
		memset(s->rx_group_packet_number, 0, sizeof(s->rx_group_packet_number));
		memset(s->rx_group_pn_valid, 0, sizeof(s->rx_group_pn_valid));
	}
	if (found_igtk) {
		memcpy(s->igtk, igtk, sizeof(igtk));
		s->igtk_key_id = igtk_id;
		s->rx_igtk_ipn = igtk_ipn;
		s->rx_igtk_ipn_valid = true;
		s->has_igtk = true;
	}
	ret = 0;
out:
	clear_bytes(gtk, sizeof(gtk));
	clear_bytes(igtk, sizeof(igtk));
	return ret;
}

static void station_fail(struct rtl_station *s, int error)
{
	s->state = RTL_STA_FAILED;
	s->error = error;
}

static int station_init_common(struct rtl_station *s, struct rtw_dev *d,
			       const u8 bssid[ETH_ALEN], const u8 *ssid,
			       size_t ssid_len)
{
	if (!s || !d || !valid_bssid(bssid) || !ssid || !ssid_len || ssid_len > 32)
		return -EINVAL;
	memset(s, 0, sizeof(*s));
	s->dev = d;
	memcpy(s->bssid, bssid, ETH_ALEN);
	memcpy(s->ssid, ssid, ssid_len);
	s->ssid_len = (u8)ssid_len;
	s->state = RTL_STA_IDLE;
	return 0;
}

int rtl_station_init(struct rtl_station *s, struct rtw_dev *d,
		     const u8 bssid[ETH_ALEN], const u8 *ssid, size_t ssid_len,
		     const u8 *passphrase, size_t passphrase_len)
{
	int ret;

	if (!passphrase)
		return -EINVAL;
	ret = station_init_common(s, d, bssid, ssid, ssid_len);
	if (ret)
		return ret;
	ret = rtl_wpa2_derive_pmk(passphrase, passphrase_len, ssid, ssid_len, s->pmk);
	if (ret) {
		clear_bytes(s, sizeof(*s));
		return ret;
	}
	return 0;
}

static int station_init_sae_mode(struct rtl_station *s, struct rtw_dev *d,
				 const u8 bssid[ETH_ALEN], const u8 *ssid,
				 size_t ssid_len, const u8 *passphrase,
				 size_t passphrase_len, bool h2e)
{
	int ret;

	if (!passphrase || passphrase_len < 8 || passphrase_len > 63)
		return -EINVAL;
	ret = station_init_common(s, d, bssid, ssid, ssid_len);
	if (ret)
		return ret;
	ret = h2e ? rtl_sae_init_h2e(&s->sae, d->efuse.addr, bssid,
				      ssid, ssid_len, passphrase, passphrase_len) :
		rtl_sae_init(&s->sae, d->efuse.addr, bssid, passphrase, passphrase_len);
	if (ret) {
		clear_bytes(s, sizeof(*s));
		return ret;
	}
	s->use_sae = true;
	s->sae_h2e = h2e;
	return 0;
}

int rtl_station_init_sae(struct rtl_station *s, struct rtw_dev *d,
			 const u8 bssid[ETH_ALEN], const u8 *ssid, size_t ssid_len,
			 const u8 *passphrase, size_t passphrase_len)
{
	return station_init_sae_mode(s, d, bssid, ssid, ssid_len, passphrase,
				     passphrase_len, false);
}

int rtl_station_init_sae_h2e(struct rtl_station *s, struct rtw_dev *d,
			     const u8 bssid[ETH_ALEN], const u8 *ssid, size_t ssid_len,
			     const u8 *passphrase, size_t passphrase_len)
{
	return station_init_sae_mode(s, d, bssid, ssid, ssid_len, passphrase,
				     passphrase_len, true);
}

static int send_sae_auth(struct rtl_station *s, u16 transaction,
			 const u8 *body, size_t body_len)
{
	u8 frame[24 + 6 + 98 + RTL_SAE_TOKEN_MAX_LEN];
	size_t frame_len = 24 + 6 + body_len;

	if (!s || !s->dev || !s->use_sae || (body_len && !body) ||
	    body_len > 98 + RTL_SAE_TOKEN_MAX_LEN || frame_len > sizeof(frame))
		return -EINVAL;
	mgmt_header(frame, 0x00b0, s->bssid, s->dev->efuse.addr);
	put_le16(frame + 24, 3); /* SAE authentication algorithm */
	put_le16(frame + 26, transaction);
	put_le16(frame + 28, 0);
	if (body_len)
		memcpy(frame + 30, body, body_len);
	return rtl_send_station_management(s->dev, frame, frame_len);
}

int rtl_station_start(struct rtl_station *s)
{
	u8 commit[98 + RTL_SAE_TOKEN_MAX_LEN];
	size_t commit_len;
	int ret;

	if (!s || !s->dev || s->state != RTL_STA_IDLE)
		return -EINVAL;
	if (s->use_sae) {
		ret = rtl_sae_build_commit_with_token(&s->sae, s->sae_token,
						      s->sae_token_len, commit,
						      sizeof(commit), &commit_len);
		if (!ret)
			ret = send_sae_auth(s, 1, commit, commit_len);
		clear_bytes(commit, sizeof(commit));
	} else {
		ret = rtl_station_send_open_auth(s->dev, s->bssid);
	}
	if (ret) {
		station_fail(s, ret);
		return ret;
	}
	s->state = s->use_sae ? RTL_STA_SAE_WAIT_COMMIT : RTL_STA_AUTH_WAIT;
	return 0;
}

static int send_eapol_key(struct rtl_station *s, u16 key_info, u64 replay,
			  const u8 nonce[32], const u8 *key_data, size_t key_data_len,
			  bool with_mic)
{
	u8 frame[24 + EAPOL_SNAP_LEN + EAPOL_MAX_LEN] = {0};
	u8 mic[16];
	u8 *eapol = frame + 24 + EAPOL_SNAP_LEN;
	size_t eapol_len, frame_len;
	int ret;

	if (key_data_len > EAPOL_MAX_LEN - EAPOL_KEY_FIXED_LEN ||
	    (key_data_len && !key_data))
		return -EMSGSIZE;
	eapol_len = EAPOL_KEY_FIXED_LEN + key_data_len;
	frame[0] = 0x08;
	frame[1] = 0x01; /* Data, To DS, unprotected EAPOL */
	memcpy(frame + 4, s->bssid, ETH_ALEN);
	memcpy(frame + 10, s->dev->efuse.addr, ETH_ALEN);
	memcpy(frame + 16, s->bssid, ETH_ALEN);
	memcpy(frame + 24, eapol_snap, sizeof(eapol_snap));
	eapol[0] = 2; /* 802.1X-2004 */
	eapol[1] = 3; /* EAPOL-Key */
	put_be16(eapol + 2, (u16)(eapol_len - 4));
	eapol[4] = 2; /* RSN key descriptor */
	put_be16(eapol + 5, key_info);
	put_be16(eapol + 7, 16); /* Pairwise CCMP key length */
	put_be64(eapol + 9, replay);
	if (nonce)
		memcpy(eapol + 17, nonce, 32);
	put_be16(eapol + 97, (u16)key_data_len);
	if (key_data_len)
		memcpy(eapol + EAPOL_KEY_FIXED_LEN, key_data, key_data_len);
	if (with_mic) {
		ret = s->use_sae ?
			rtl_wpa3_eapol_mic(s->ptk.kck, eapol, eapol_len,
					   EAPOL_MIC_OFFSET, mic) :
			rtl_wpa2_eapol_mic(s->ptk.kck, eapol, eapol_len,
					   EAPOL_MIC_OFFSET, mic);
		if (ret)
			return ret;
		memcpy(eapol + EAPOL_MIC_OFFSET, mic, sizeof(mic));
	}
	frame_len = 24 + EAPOL_SNAP_LEN + eapol_len;
	ret = rtl_send_station_data(s->dev, frame, frame_len);
	clear_bytes(mic, sizeof(mic));
	clear_bytes(frame, frame_len);
	return ret;
}

static int send_m2(struct rtl_station *s, u64 replay, u16 descriptor_version)
{
	u8 key_data[sizeof(rsn_wpa3_sae_ie) + sizeof(rsnxe_sae_h2e_ie)] = {0};
	size_t key_data_len;
	int ret;

	if (!s->use_sae)
		return send_eapol_key(s, 0x0108 | descriptor_version, replay,
				      s->snonce, rsn_wpa2_psk_ccmp_ie,
				      sizeof(rsn_wpa2_psk_ccmp_ie), true);
	memcpy(key_data, rsn_wpa3_sae_ie, sizeof(rsn_wpa3_sae_ie));
	key_data_len = sizeof(rsn_wpa3_sae_ie);
	if (s->sae_h2e) {
		memcpy(key_data + key_data_len, rsnxe_sae_h2e_ie,
		       sizeof(rsnxe_sae_h2e_ie));
		key_data_len += sizeof(rsnxe_sae_h2e_ie);
	}
	ret = send_eapol_key(s, 0x0108 | descriptor_version, replay, s->snonce,
			     key_data, key_data_len, true);
	clear_bytes(key_data, sizeof(key_data));
	return ret;
}

static int process_key_message(struct rtl_station *s, const u8 *eapol, size_t len)
{
	u8 mic[16], key_data[EAPOL_MAX_LEN];
	u16 key_info, key_data_len;
	u64 replay;
	size_t unwrapped_len;
	bool ack, has_mic, pairwise, install, secure;
	u16 descriptor_version;
	int ret;

	if (len < EAPOL_KEY_FIXED_LEN || eapol[0] < 1 || eapol[0] > 2 || eapol[1] != 3 ||
		get_be16(eapol + 2) != len - 4 || eapol[4] != 2)
		return 0;
	descriptor_version = s->use_sae ? 0 : 2;
	key_info = get_be16(eapol + 5);
	key_data_len = get_be16(eapol + 97);
	if ((size_t)key_data_len != len - EAPOL_KEY_FIXED_LEN ||
	    (key_info & 7) != descriptor_version ||
	    (key_info & (EAPOL_KEY_ERROR | EAPOL_KEY_REQUEST)))
		return 0;
	ack = (key_info & EAPOL_KEY_ACK) != 0;
	has_mic = (key_info & EAPOL_KEY_MIC) != 0;
	pairwise = (key_info & EAPOL_KEY_PAIRWISE) != 0;
	install = (key_info & EAPOL_KEY_INSTALL) != 0;
	secure = (key_info & EAPOL_KEY_SECURE) != 0;
	replay = get_be64(eapol + 9);

	/* Message 1: AP's ANonce; derive PTK and return M2 with our SNonce. */
	if (s->state == RTL_STA_KEY_WAIT_M1 && pairwise && ack && !has_mic &&
	    !install && !secure && bytes_nonzero(eapol + 17, 32)) {
		memcpy(s->anonce, eapol + 17, sizeof(s->anonce));
		arc4random_buf(s->snonce, sizeof(s->snonce));
		ret = s->use_sae ?
			rtl_wpa3_derive_ptk(s->pmk, s->dev->efuse.addr, s->bssid,
					    s->anonce, s->snonce, &s->ptk) :
			rtl_wpa2_derive_ptk(s->pmk, s->dev->efuse.addr, s->bssid,
					    s->anonce, s->snonce, &s->ptk);
		if (ret) {
			station_fail(s, ret);
			return ret;
		}
		s->m1_replay = replay;
		ret = send_m2(s, replay, descriptor_version);
		if (ret) {
			station_fail(s, ret);
			return ret;
		}
		s->state = RTL_STA_KEY_WAIT_M3;
		return 1;
	}

	/* Retransmitted M1: return the same M2 to preserve the nonce and replay counter. */
	if (s->state == RTL_STA_KEY_WAIT_M3 && pairwise && ack && !has_mic &&
	    !install && replay == s->m1_replay &&
	    bytes_equal_ct(eapol + 17, s->anonce, sizeof(s->anonce))) {
		ret = send_m2(s, replay, descriptor_version);
		if (ret)
			station_fail(s, ret);
		return ret ? ret : 1;
	}

	/* Message 3: verify replay, ANonce, and MIC, then send M4. */
	if (((s->state == RTL_STA_KEY_WAIT_M3) || (s->state == RTL_STA_CONNECTED)) &&
	    pairwise && ack && has_mic && install && secure &&
	    (key_data_len == 0 || (key_info & EAPOL_KEY_ENCRYPTED)) &&
	    replay > s->m1_replay && bytes_equal_ct(eapol + 17, s->anonce, 32)) {
		ret = s->use_sae ?
			rtl_wpa3_eapol_mic(s->ptk.kck, eapol, len,
					   EAPOL_MIC_OFFSET, mic) :
			rtl_wpa2_eapol_mic(s->ptk.kck, eapol, len,
					   EAPOL_MIC_OFFSET, mic);
		if (ret)
			return ret;
		if (!bytes_equal_ct(mic, eapol + EAPOL_MIC_OFFSET, sizeof(mic))) {
			clear_bytes(mic, sizeof(mic));
			return 0;
		}
		clear_bytes(mic, sizeof(mic));
		if (s->state == RTL_STA_CONNECTED && replay == s->m3_replay) {
			ret = send_eapol_key(s, 0x0308 | descriptor_version,
					     replay, NULL, NULL, 0, true);
			if (ret)
				station_fail(s, ret);
			return ret ? ret : 1;
		}
		if (key_data_len) {
			if (!(key_info & EAPOL_KEY_ENCRYPTED))
				return 0;
			ret = rtl_wpa2_unwrap_key_data(s->ptk.kek,
						       eapol + EAPOL_KEY_FIXED_LEN,
						       key_data_len, key_data, sizeof(key_data),
						       &unwrapped_len);
			if (ret)
				return 0;
			ret = install_key_data_kdes(s, key_data, unwrapped_len);
			clear_bytes(key_data, unwrapped_len);
			if (ret)
				return 0;
		}
		if (s->use_sae && (!s->has_gtk || !s->has_igtk))
			return 0; /* WPA3/PMF requires group and management integrity keys. */
		if (s->state != RTL_STA_KEY_WAIT_M3)
			return 0;
		ret = send_eapol_key(s, 0x0308 | descriptor_version,
				     replay, NULL, NULL, 0, true);
		if (ret) {
			station_fail(s, ret);
			return ret;
		}
		s->m3_replay = replay;
		s->have_ptk = true;
		s->state = RTL_STA_CONNECTED;
		return 1;
	}
	return 0;
}

static int receive_data(struct rtl_station *s, const u8 *frame, size_t wire_len)
{
	u8 decrypted[EAPOL_MAX_LEN];
	const u8 *payload, *eapol, *tk;
	size_t header_len, payload_len, eapol_len;
	u8 ds, tid = 0;
	bool qos, protected, group;
	u16 ethertype;
	int ret;

	if (wire_len < 24 + 4 || (frame[0] & 0x0c) != 0x08)
		return 0;
	ds = frame[1] & 0x03;
	group = (frame[4] & 1) != 0;
	if (ds != 2 || (!group && memcmp(frame + 4, s->dev->efuse.addr, ETH_ALEN)) ||
	    memcmp(frame + 10, s->bssid, ETH_ALEN))
		return 0;
	qos = (frame[0] & 0x80) != 0;
	if (frame[1] & 0x80)
		return 0; /* HT-control headers are not handled yet. */
	header_len = 24 + (qos ? 2 : 0);
	if (wire_len < header_len)
		return 0;
	if (qos)
		tid = frame[24] & 0x0f;
	protected = (frame[1] & 0x40) != 0;
	payload = frame + header_len;
	payload_len = wire_len - header_len;
	if (protected) {
		u64 packet_number;
		size_t decrypted_len;
		u8 key_id;

		if (payload_len > sizeof(decrypted) || payload_len < 8)
			return 0;
		if (group) {
			key_id = (payload[3] >> 6) & 0x03;
			if (!s->has_gtk || key_id != s->gtk_key_id)
				return 0;
			tk = s->gtk;
		} else {
			if (!s->have_ptk)
				return 0;
			key_id = 0;
			tk = s->ptk.tk;
		}
		ret = rtl_ccmp_decrypt(tk, frame, header_len, tid, key_id,
				       payload, payload_len, decrypted, sizeof(decrypted),
				       &decrypted_len, &packet_number);
		if (ret)
			return 0;
		if (group && s->rx_group_pn_valid[tid] &&
		    packet_number <= s->rx_group_packet_number[tid]) {
			clear_bytes(decrypted, decrypted_len);
			return 0;
		}
		if (!group && s->rx_pn_valid[tid] &&
		    packet_number <= s->rx_packet_number[tid]) {
			clear_bytes(decrypted, decrypted_len);
			return 0;
		}
		if (group) {
			s->rx_group_pn_valid[tid] = true;
			s->rx_group_packet_number[tid] = packet_number;
		} else {
			s->rx_pn_valid[tid] = true;
			s->rx_packet_number[tid] = packet_number;
		}
		payload = decrypted;
		payload_len = decrypted_len;
	}
	if (payload_len < EAPOL_SNAP_LEN ||
	    memcmp(payload, eapol_snap, EAPOL_SNAP_LEN - 2)) {
		if (protected)
			clear_bytes(decrypted, payload_len);
		return 0;
	}
	ethertype = get_be16(payload + EAPOL_SNAP_LEN - 2);
	if (ethertype == 0x888e) {
		if (payload_len < EAPOL_SNAP_LEN + 4) {
			ret = 0;
		} else {
			eapol = payload + EAPOL_SNAP_LEN;
			eapol_len = payload_len - EAPOL_SNAP_LEN;
			ret = process_key_message(s, eapol, eapol_len);
		}
	} else if (protected && s->payload_cb) {
		ret = s->payload_cb(s->payload_cb_ctx, ethertype,
				    payload + EAPOL_SNAP_LEN, payload_len - EAPOL_SNAP_LEN);
	} else {
		ret = 0;
	}
	if (protected)
		clear_bytes(decrypted, payload_len);
	return ret;
}

static u64 get_le48(const u8 *p)
{
	u64 value = 0;

	for (int i = 5; i >= 0; i--)
		value = (value << 8) | p[i];
	return value;
}

static int verify_group_mgmt_mic(struct rtl_station *s, const u8 *frame,
				 size_t wire_len)
{
	u8 input[20 + EAPOL_MAX_LEN], mic[16];
	size_t body_len, mmie_offset, input_len;
	u16 key_id;
	u64 ipn;
	int ret = 0;

	if (!s->has_igtk || wire_len < 24 + 2 + 18 || (frame[1] & 0x40) == 0)
		return 0;
	mmie_offset = wire_len - 18;
	if (frame[mmie_offset] != 76 || frame[mmie_offset + 1] != 16)
		return 0;
	key_id = frame[mmie_offset + 2] | ((u16)frame[mmie_offset + 3] << 8);
	ipn = get_le48(frame + mmie_offset + 4);
	if (key_id != s->igtk_key_id ||
	    (s->rx_igtk_ipn_valid && ipn <= s->rx_igtk_ipn))
		return 0;
	body_len = wire_len - 24;
	input_len = 20 + body_len;
	if (input_len > sizeof(input))
		return 0;
	input[0] = frame[0];
	input[1] = frame[1] & (u8)~0x38; /* mask Retry, Power Management, More Data */
	memcpy(input + 2, frame + 4, 18); /* BIP AAD has A1, A2, and A3 */
	memcpy(input + 20, frame + 24, body_len);
	memset(input + 20 + (mmie_offset - 24) + 10, 0, 8);
	ret = rtl_wpa3_aes_cmac(s->igtk, input, input_len, mic);
	if (!ret && !bytes_equal_ct(mic, frame + mmie_offset + 10, 8))
		ret = 0;
	else if (!ret) {
		s->rx_igtk_ipn = ipn;
		s->rx_igtk_ipn_valid = true;
		ret = 1;
	}
	clear_bytes(input, sizeof(input));
	clear_bytes(mic, sizeof(mic));
	return ret;
}

static int send_sa_query_response(struct rtl_station *s, const u8 transaction_id[2])
{
	u8 frame[24 + 8 + 4 + 8] = {0};
	u8 body[4] = {8, 1, 0, 0}, protected_body[20];
	size_t protected_len;
	u64 packet_number;
	int ret;

	if (!s || !s->dev || !s->have_ptk || !transaction_id ||
	    s->tx_packet_number >= ((1ULL << 48) - 1))
		return -EINVAL;
	memcpy(body + 2, transaction_id, 2);
	frame[0] = 0xd0; /* Action */
	frame[1] = 0x40; /* Protected */
	memcpy(frame + 4, s->bssid, ETH_ALEN);
	memcpy(frame + 10, s->dev->efuse.addr, ETH_ALEN);
	memcpy(frame + 16, s->bssid, ETH_ALEN);
	packet_number = s->tx_packet_number + 1;
	ret = rtl_ccmp_encrypt(s->ptk.tk, frame, 24, 0, 0, packet_number,
			       body, sizeof(body), protected_body,
			       sizeof(protected_body), &protected_len);
	if (!ret) {
		memcpy(frame + 24, protected_body, protected_len);
		ret = rtl_send_station_management(s->dev, frame, 24 + protected_len);
	}
	if (!ret)
		s->tx_packet_number = packet_number;
	clear_bytes(body, sizeof(body));
	clear_bytes(protected_body, sizeof(protected_body));
	clear_bytes(frame, sizeof(frame));
	return ret;
}

static int receive_robust_management(struct rtl_station *s, const u8 *frame,
				     size_t wire_len)
{
	u8 plaintext[EAPOL_MAX_LEN];
	u64 packet_number;
	size_t plaintext_len;
	u16 subtype = get_le16(frame) & 0x00fc;
	bool disconnect = subtype == 0x00a0 || subtype == 0x00c0;
	bool protected_frame = (frame[1] & 0x40) != 0;
	int ret;

	if (!disconnect && subtype != 0x00d0)
		return 0;
	if (!s->use_sae) {
		if (disconnect && !protected_frame && !(frame[4] & 1)) {
			station_fail(s, -ECONNRESET);
			return s->error;
		}
		return 0;
	}
	if (frame[4] & 1) {
		ret = verify_group_mgmt_mic(s, frame, wire_len);
		if (ret == 1 && disconnect) {
			station_fail(s, -ECONNRESET);
			return s->error;
		}
		return ret < 0 ? ret : 0;
	}
	if (!protected_frame || wire_len < 24 + 8 + 8)
		return 0;
	ret = rtl_ccmp_decrypt(s->ptk.tk, frame, 24, 0, 0, frame + 24,
			       wire_len - 24, plaintext, sizeof(plaintext),
			       &plaintext_len, &packet_number);
	if (ret || plaintext_len < 2 ||
	    (s->rx_mgmt_pn_valid && packet_number <= s->rx_mgmt_packet_number)) {
		clear_bytes(plaintext, sizeof(plaintext));
		return 0;
	}
	s->rx_mgmt_pn_valid = true;
	s->rx_mgmt_packet_number = packet_number;
	if (!disconnect && plaintext_len >= 4 && plaintext[0] == 8 && plaintext[1] == 0) {
		ret = send_sa_query_response(s, plaintext + 2);
		clear_bytes(plaintext, sizeof(plaintext));
		return ret;
	}
	clear_bytes(plaintext, sizeof(plaintext));
	if (disconnect) {
		station_fail(s, -ECONNRESET);
		return s->error;
	}
	return 0;
}

int rtl_station_receive(struct rtl_station *s, const u8 *frame, size_t frame_len)
{
	size_t wire_len;
	u16 fc, status;
	int ret;

	if (!s || !s->dev || !frame)
		return -EINVAL;
	if (frame_len < 24 + 4)
		return 0; /* Monitor RX also delivers short control frames. */
	wire_len = frame_len - 4; /* monitor RX appends the FCS */
	fc = get_le16(frame);
	if ((fc & 0x000c) == 0 &&
	    !memcmp(frame + 10, s->bssid, ETH_ALEN) &&
	    !memcmp(frame + 16, s->bssid, ETH_ALEN)) {
		if (s->state == RTL_STA_CONNECTED) {
			ret = receive_robust_management(s, frame, wire_len);
			if (ret)
				return ret;
		}
		if (memcmp(frame + 4, s->dev->efuse.addr, ETH_ALEN))
			return 0;
		if ((frame[0] & 0xfc) == 0xb0 && s->use_sae &&
		    (s->state == RTL_STA_SAE_WAIT_COMMIT ||
		     s->state == RTL_STA_SAE_WAIT_CONFIRM)) {
			u8 confirm[34];
			size_t confirm_len;
			u16 transaction;

			if (wire_len < 30 || get_le16(frame + 24) != 3)
				return 0;
			transaction = get_le16(frame + 26);
			status = get_le16(frame + 28);
			if (s->state == RTL_STA_SAE_WAIT_COMMIT && transaction == 1 &&
			    status == 76) { /* Anti-clogging token required. */
				const u8 *token_body = frame + 30;
				size_t token_body_len = wire_len - 30;
				u8 commit[98 + RTL_SAE_TOKEN_MAX_LEN];
				size_t commit_len;

				if (s->sae_anti_clogging_retried) {
					station_fail(s, -ELOOP);
					return s->error;
				}
				if (token_body_len < 3 ||
				    token_body_len > 2 + RTL_SAE_TOKEN_MAX_LEN) {
					station_fail(s, -EBADMSG);
					return s->error;
				}
				if (get_le16(token_body) != 19) {
					station_fail(s, -EPROTONOSUPPORT);
					return s->error;
				}
				s->sae_token_len = (u16)(token_body_len - 2);
				memcpy(s->sae_token, token_body + 2, s->sae_token_len);
				ret = rtl_sae_build_commit_with_token(&s->sae, s->sae_token,
							      s->sae_token_len,
							      commit, sizeof(commit),
							      &commit_len);
				if (!ret)
					ret = send_sae_auth(s, 1, commit, commit_len);
				clear_bytes(commit, sizeof(commit));
				if (ret) {
					station_fail(s, ret);
					return ret;
				}
				s->sae_anti_clogging_retried = true;
				return 1;
			}
			if (status) {
				station_fail(s, status == 126 ? -EOPNOTSUPP : -ECONNREFUSED);
				return s->error;
			}
			if (s->state == RTL_STA_SAE_WAIT_COMMIT && transaction == 1) {
				ret = rtl_sae_process_commit(&s->sae, frame + 30,
							    wire_len - 30, confirm,
							    sizeof(confirm), &confirm_len);
				if (ret) {
					station_fail(s, ret);
					return ret;
				}
				memcpy(s->pmk, s->sae.pmk, sizeof(s->pmk));
				ret = send_sae_auth(s, 2, confirm, confirm_len);
				clear_bytes(confirm, sizeof(confirm));
				if (ret) {
					station_fail(s, ret);
					return ret;
				}
				s->state = RTL_STA_SAE_WAIT_CONFIRM;
				return 1;
			}
			if (s->state == RTL_STA_SAE_WAIT_CONFIRM && transaction == 2) {
				ret = rtl_sae_check_confirm(&s->sae, frame + 30,
							   wire_len - 30);
				if (ret) {
					station_fail(s, ret);
					return ret;
				}
				ret = s->sae_h2e ?
					rtl_station_send_sae_h2e_assoc(s->dev, s->bssid,
							       s->ssid, s->ssid_len) :
					rtl_station_send_sae_assoc(s->dev, s->bssid,
							       s->ssid, s->ssid_len);
				if (ret) {
					station_fail(s, ret);
					return ret;
				}
				s->state = RTL_STA_ASSOC_WAIT;
				return 1;
			}
			clear_bytes(confirm, sizeof(confirm));
			return 0;
		}
		if ((frame[0] & 0xfc) == 0xb0 && s->state == RTL_STA_AUTH_WAIT &&
		    wire_len >= 30 && get_le16(frame + 24) == 0 && get_le16(frame + 26) == 2) {
			status = get_le16(frame + 28);
			if (status) {
				station_fail(s, -ECONNREFUSED);
				return s->error;
			}
			ret = rtl_station_send_wpa2_assoc(s->dev, s->bssid, s->ssid, s->ssid_len);
			if (ret) {
				station_fail(s, ret);
				return ret;
			}
			s->state = RTL_STA_ASSOC_WAIT;
			return 1;
		}
		if ((frame[0] & 0xfc) == 0x10 && s->state == RTL_STA_ASSOC_WAIT && wire_len >= 30) {
			status = get_le16(frame + 26);
			if (status) {
				station_fail(s, -ECONNREFUSED);
				return s->error;
			}
			s->state = RTL_STA_KEY_WAIT_M1;
			return 1;
		}
		return 0;
	}
	if (s->state == RTL_STA_KEY_WAIT_M1 || s->state == RTL_STA_KEY_WAIT_M3 ||
	    s->state == RTL_STA_CONNECTED)
		return receive_data(s, frame, wire_len);
	return 0;
}

void rtl_station_clear(struct rtl_station *s)
{
	if (s)
		clear_bytes(s, sizeof(*s));
}

int rtl_station_send_ethernet(struct rtl_station *s, const u8 destination[ETH_ALEN],
			     u16 ethertype, const u8 *payload, size_t len)
{
	u8 frame[IEEE80211_MAX_DATA_LEN] = {0};
	u8 plaintext[1508];
	size_t encrypted_len;
	int ret;

	if (!s || !s->dev || !destination || (!payload && len) ||
	    s->state != RTL_STA_CONNECTED || !s->have_ptk || len > 1500 ||
	    ethertype == 0x888e)
		return -EINVAL;
	if (s->tx_packet_number >= ((1ULL << 48) - 1))
		return -EOVERFLOW;
	frame[0] = 0x08; /* Data */
	frame[1] = 0x41; /* To DS + Protected */
	memcpy(frame + 4, s->bssid, ETH_ALEN);
	memcpy(frame + 10, s->dev->efuse.addr, ETH_ALEN);
	memcpy(frame + 16, destination, ETH_ALEN);
	memcpy(plaintext, eapol_snap, EAPOL_SNAP_LEN - 2);
	put_be16(plaintext + EAPOL_SNAP_LEN - 2, ethertype);
	if (len)
		memcpy(plaintext + EAPOL_SNAP_LEN, payload, len);
	ret = rtl_ccmp_encrypt(s->ptk.tk, frame, 24, 0, 0, ++s->tx_packet_number,
			       plaintext, EAPOL_SNAP_LEN + len, frame + 24,
			       sizeof(frame) - 24, &encrypted_len);
	if (!ret)
		ret = rtl_send_station_data(s->dev, frame, 24 + encrypted_len);
	clear_bytes(plaintext, EAPOL_SNAP_LEN + len);
	clear_bytes(frame, sizeof(frame));
	return ret;
}

// SPDX-License-Identifier: BSD-3-Clause
/* WPA2-PSK key derivation and CCMP, using the macOS CommonCrypto primitives. */
#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonKeyDerivation.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include "rtl8814au.h"

#define CCMP_HDR_LEN 8
#define CCMP_MIC_LEN 8
#define CCMP_MAX_PN ((1ULL << 48) - 1)
#define CCMP_MAX_AAD 40

static void secure_clear(void *ptr, size_t len)
{
	volatile u8 *p = ptr;

	while (len--)
		*p++ = 0;
}

int rtl_wpa2_derive_pmk(const u8 *passphrase, size_t passphrase_len,
		       const u8 *ssid, size_t ssid_len, u8 pmk[32])
{
	if (!passphrase || passphrase_len < 8 || passphrase_len > 63 || !ssid ||
	    ssid_len < 1 || ssid_len > 32 || !pmk)
		return -EINVAL;

	if (CCKeyDerivationPBKDF(kCCPBKDF2, (const char *)passphrase, passphrase_len,
				 ssid, ssid_len, kCCPRFHmacAlgSHA1, 4096, pmk, 32) != kCCSuccess)
		return -EIO;
	return 0;
}

int rtl_wpa2_derive_ptk(const u8 pmk[32], const u8 addr1[ETH_ALEN],
		       const u8 addr2[ETH_ALEN], const u8 nonce1[32],
		       const u8 nonce2[32], struct rtl_wpa2_ptk *ptk)
{
	static const u8 label[] = "Pairwise key expansion";
	u8 context[ETH_ALEN * 2 + 64];
	u8 input[sizeof(label) + sizeof(context) + 1];
	u8 output[80];
	const u8 *mac_lo, *mac_hi, *nonce_lo, *nonce_hi;
	size_t offset = 0, generated = 0;
	u8 counter = 0;

	if (!pmk || !addr1 || !addr2 || !nonce1 || !nonce2 || !ptk)
		return -EINVAL;
	mac_lo = memcmp(addr1, addr2, ETH_ALEN) <= 0 ? addr1 : addr2;
	mac_hi = mac_lo == addr1 ? addr2 : addr1;
	nonce_lo = memcmp(nonce1, nonce2, 32) <= 0 ? nonce1 : nonce2;
	nonce_hi = nonce_lo == nonce1 ? nonce2 : nonce1;
	memcpy(context, mac_lo, ETH_ALEN);
	memcpy(context + ETH_ALEN, mac_hi, ETH_ALEN);
	memcpy(context + ETH_ALEN * 2, nonce_lo, 32);
	memcpy(context + ETH_ALEN * 2 + 32, nonce_hi, 32);
	memcpy(input, label, sizeof(label) - 1);
	offset += sizeof(label) - 1;
	input[offset++] = 0;
	memcpy(input + offset, context, sizeof(context));
	offset += sizeof(context);

	while (generated < 64) {
		u8 digest[CC_SHA1_DIGEST_LENGTH];
		size_t take;

		input[offset] = counter++;
		CCHmac(kCCHmacAlgSHA1, pmk, 32, input, offset + 1, digest);
		take = sizeof(output) - generated;
		if (take > sizeof(digest))
			take = sizeof(digest);
		memcpy(output + generated, digest, take);
		generated += take;
		secure_clear(digest, sizeof(digest));
	}

	memcpy(ptk->kck, output, sizeof(ptk->kck));
	memcpy(ptk->kek, output + sizeof(ptk->kck), sizeof(ptk->kek));
	memcpy(ptk->tk, output + sizeof(ptk->kck) + sizeof(ptk->kek), sizeof(ptk->tk));
	secure_clear(context, sizeof(context));
	secure_clear(input, sizeof(input));
	secure_clear(output, sizeof(output));
	return 0;
}

int rtl_wpa2_eapol_mic(const u8 kck[16], const u8 *eapol, size_t eapol_len,
		       size_t mic_offset, u8 mic[16])
{
	u8 *copy, digest[CC_SHA1_DIGEST_LENGTH];

	if (!kck || !eapol || !mic || eapol_len < 4 || eapol_len > 4096 ||
	    mic_offset > eapol_len || eapol_len - mic_offset < 16)
		return -EINVAL;
	copy = malloc(eapol_len);
	if (!copy)
		return -ENOMEM;
	memcpy(copy, eapol, eapol_len);
	memset(copy + mic_offset, 0, 16);
	CCHmac(kCCHmacAlgSHA1, kck, 16, copy, eapol_len, digest);
	memcpy(mic, digest, 16);
	secure_clear(digest, sizeof(digest));
	secure_clear(copy, eapol_len);
	free(copy);
	return 0;
}

int rtl_wpa3_aes_cmac(const u8 key[16], const u8 *data, size_t data_len,
		      u8 mic[16])
{
	EVP_MAC *cmac = NULL;
	EVP_MAC_CTX *ctx = NULL;
	OSSL_PARAM params[2];
	char cipher[] = "AES-128-CBC";
	u8 digest[16];
	size_t digest_len = 0;
	int ret = -EIO;

	if (!key || (!data && data_len) || !mic || data_len > 4096)
		return -EINVAL;
	cmac = EVP_MAC_fetch(NULL, "CMAC", NULL);
	ctx = cmac ? EVP_MAC_CTX_new(cmac) : NULL;
	params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, cipher, 0);
	params[1] = OSSL_PARAM_construct_end();
	if (ctx && EVP_MAC_init(ctx, key, 16, params) == 1 &&
	    (!data_len || EVP_MAC_update(ctx, data, data_len) == 1) &&
	    EVP_MAC_final(ctx, digest, &digest_len, sizeof(digest)) == 1 &&
	    digest_len == sizeof(digest)) {
		memcpy(mic, digest, sizeof(digest));
		ret = 0;
	}
	secure_clear(digest, sizeof(digest));
	EVP_MAC_CTX_free(ctx);
	EVP_MAC_free(cmac);
	return ret;
}

int rtl_wpa3_eapol_mic(const u8 kck[16], const u8 *eapol, size_t eapol_len,
		      size_t mic_offset, u8 mic[16])
{
	u8 *copy;
	int ret;

	if (!kck || !eapol || !mic || eapol_len < 4 || eapol_len > 4096 ||
	    mic_offset > eapol_len || eapol_len - mic_offset < 16)
		return -EINVAL;
	copy = malloc(eapol_len);
	if (!copy)
		return -ENOMEM;
	memcpy(copy, eapol, eapol_len);
	memset(copy + mic_offset, 0, 16);
	ret = rtl_wpa3_aes_cmac(kck, copy, eapol_len, mic);
	secure_clear(copy, eapol_len);
	free(copy);
	return ret;
}

static int aes_begin(const u8 key[16], CCOperation operation, CCCryptorRef *aes)
{
	CCCryptorStatus status;

	status = CCCryptorCreateWithMode(operation, kCCModeECB, kCCAlgorithmAES,
					 ccNoPadding, NULL, key, 16, NULL, 0, 0, 0, aes);
	return status == kCCSuccess ? 0 : -EIO;
}

static int aes_block(CCCryptorRef aes, const u8 input[16], u8 output[16])
{
	size_t moved = 0;
	CCCryptorStatus status = CCCryptorUpdate(aes, input, 16, output, 16, &moved);

	return status == kCCSuccess && moved == 16 ? 0 : -EIO;
}

static int cbc_mac_block(CCCryptorRef aes, u8 state[16], const u8 block[16])
{
	u8 input[16];

	for (size_t i = 0; i < sizeof(input); i++)
		input[i] = state[i] ^ block[i];
	return aes_block(aes, input, state);
}

static int cbc_mac_bytes(CCCryptorRef aes, u8 state[16], const u8 *data, size_t len)
{
	u8 block[16];

	while (len >= sizeof(block)) {
		if (cbc_mac_block(aes, state, data))
			return -EIO;
		data += sizeof(block);
		len -= sizeof(block);
	}
	if (len) {
		memset(block, 0, sizeof(block));
		memcpy(block, data, len);
		if (cbc_mac_block(aes, state, block))
			return -EIO;
	}
	return 0;
}

/* Build the CCMP AAD from a non-HT-control data or management header. */
static int ccmp_aad(const u8 *hdr, size_t hdr_len, u8 tid, u8 *aad, size_t *aad_len)
{
	u8 fc0, fc1, ds;
	bool qos;
	size_t expected, pos = 0, qos_offset;

	if (!hdr || hdr_len < 24)
		return -EINVAL;
	fc0 = hdr[0];
	fc1 = hdr[1];
	if (((fc0 & 0x0c) != 0x08 && (fc0 & 0x0c) != 0) ||
	    !(fc1 & 0x40) || (fc1 & 0x80))
		return -EINVAL; /* protected data or management; no HT-control headers */
	ds = fc1 & 0x03;
	qos = (fc0 & 0x0c) == 0x08 && (fc0 & 0x80) != 0;
	expected = 24 + (ds == 3 ? 6 : 0) + (qos ? 2 : 0);
	if (hdr_len != expected || (!qos && tid) || tid > 15)
		return -EINVAL;
	qos_offset = 24 + (ds == 3 ? 6 : 0);
	if (qos && (hdr[qos_offset] & 0x0f) != tid)
		return -EINVAL;

	aad[pos++] = fc0 & 0x8f;
	aad[pos++] = fc1 & 0xc7;
	memcpy(aad + pos, hdr + 4, 18); /* addr1, addr2, addr3 */
	pos += 18;
	aad[pos++] = hdr[22] & 0x0f; /* sequence control: fragment number only */
	aad[pos++] = 0;
	if (ds == 3) {
		memcpy(aad + pos, hdr + 24, 6);
		pos += 6;
	}
	if (qos) {
		aad[pos++] = hdr[qos_offset] & 0x0f;
		aad[pos++] = 0;
	}
	*aad_len = pos;
	return pos <= CCMP_MAX_AAD ? 0 : -EINVAL;
}

static void ccmp_nonce(const u8 *hdr, u8 tid, u64 pn, u8 nonce[13])
{
	nonce[0] = tid;
	memcpy(nonce + 1, hdr + 10, ETH_ALEN);
	for (int i = 0; i < 6; i++)
		nonce[7 + i] = (u8)(pn >> (8 * (5 - i)));
}

static int ccmp_auth(CCCryptorRef aes, const u8 nonce[13], const u8 *aad,
		     size_t aad_len, const u8 *plaintext, size_t plaintext_len,
		     u8 tag[8])
{
	u8 state[16] = {0}, block[16], a[2 + CCMP_MAX_AAD];
	int ret;

	if (plaintext_len > UINT16_MAX || aad_len > CCMP_MAX_AAD)
		return -EMSGSIZE;
	block[0] = 0x59; /* AAD present, 8-byte MIC, 2-byte message length */
	memcpy(block + 1, nonce, 13);
	block[14] = (u8)(plaintext_len >> 8);
	block[15] = (u8)plaintext_len;
	ret = cbc_mac_block(aes, state, block);
	if (ret)
		return ret;
	if (aad_len) {
		a[0] = (u8)(aad_len >> 8);
		a[1] = (u8)aad_len;
		memcpy(a + 2, aad, aad_len);
		ret = cbc_mac_bytes(aes, state, a, aad_len + 2);
		if (ret)
			return ret;
	}
	ret = cbc_mac_bytes(aes, state, plaintext, plaintext_len);
	if (ret)
		return ret;
	memcpy(tag, state, 8);
	return 0;
}

static int ccmp_crypt(CCCryptorRef aes, const u8 nonce[13], const u8 *input,
		      size_t len, u8 *output)
{
	u8 counter[16] = {0}, stream[16];
	size_t offset = 0;

	counter[0] = 0x01; /* L = 2 */
	memcpy(counter + 1, nonce, 13);
	for (u16 count = 1; offset < len; count++) {
		size_t chunk = len - offset;

		counter[14] = (u8)(count >> 8);
		counter[15] = (u8)count;
		if (aes_block(aes, counter, stream))
			return -EIO;
		if (chunk > sizeof(stream))
			chunk = sizeof(stream);
		for (size_t i = 0; i < chunk; i++)
			output[offset + i] = input[offset + i] ^ stream[i];
		offset += chunk;
	}
	return 0;
}

static int ccmp_tag_mask(CCCryptorRef aes, const u8 nonce[13], const u8 tag[8], u8 out[8])
{
	u8 counter[16] = {0}, stream[16];

	counter[0] = 0x01;
	memcpy(counter + 1, nonce, 13);
	if (aes_block(aes, counter, stream))
		return -EIO;
	for (size_t i = 0; i < 8; i++)
		out[i] = tag[i] ^ stream[i];
	return 0;
}

static int ccmp_header_write(u8 *out, u8 key_id, u64 pn)
{
	if (!out || key_id > 3 || !pn || pn > CCMP_MAX_PN)
		return -EINVAL;
	out[0] = (u8)pn;
	out[1] = (u8)(pn >> 8);
	out[2] = 0;
	out[3] = 0x20 | (key_id << 6); /* ExtIV and key ID */
	for (int i = 0; i < 4; i++)
		out[4 + i] = (u8)(pn >> (16 + 8 * i));
	return 0;
}

static int ccmp_header_read(const u8 *in, u8 expected_key_id, u64 *pn)
{
	u64 value;

	if (!in || expected_key_id > 3 || in[2] != 0 || !(in[3] & 0x20) ||
	    ((in[3] >> 6) & 0x03) != expected_key_id)
		return -EINVAL;
	value = in[0] | ((u64)in[1] << 8) | ((u64)in[4] << 16) |
		((u64)in[5] << 24) | ((u64)in[6] << 32) | ((u64)in[7] << 40);
	if (!value)
		return -EINVAL;
	*pn = value;
	return 0;
}

static bool constant_time_equal(const u8 *a, const u8 *b, size_t len)
{
	u8 diff = 0;

	for (size_t i = 0; i < len; i++)
		diff |= a[i] ^ b[i];
	return diff == 0;
}

int rtl_wpa2_unwrap_key_data(const u8 kek[16], const u8 *wrapped,
			     size_t wrapped_len, u8 *plaintext,
			     size_t plaintext_capacity, size_t *plaintext_len)
{
	static const u8 initial_value[8] = { 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6 };
	CCCryptorRef aes = NULL;
	u8 a[8], block[16], decoded[16], *r;
	size_t n, result_len;
	int ret;

	if (!kek || !wrapped || !plaintext || !plaintext_len || wrapped_len < 24 ||
	    wrapped_len > 4096 || wrapped_len % 8)
		return -EINVAL;
	n = wrapped_len / 8 - 1;
	result_len = wrapped_len - 8;
	if (result_len > plaintext_capacity)
		return -ENOSPC;
	r = malloc(result_len);
	if (!r)
		return -ENOMEM;
	memcpy(a, wrapped, sizeof(a));
	memcpy(r, wrapped + sizeof(a), result_len);
	ret = aes_begin(kek, kCCDecrypt, &aes);
	if (ret)
		goto out;
	for (int j = 5; j >= 0; j--) {
		for (size_t i = n; i > 0; i--) {
			u64 t = (u64)n * j + i;

			memcpy(block, a, sizeof(a));
			for (int k = 0; k < 8; k++)
				block[7 - k] ^= (u8)(t >> (8 * k));
			memcpy(block + 8, r + (i - 1) * 8, 8);
			ret = aes_block(aes, block, decoded);
			if (ret)
				goto release;
			memcpy(a, decoded, sizeof(a));
			memcpy(r + (i - 1) * 8, decoded + 8, 8);
		}
	}
	if (!constant_time_equal(a, initial_value, sizeof(a))) {
		ret = -EBADMSG;
		goto release;
	}
	memcpy(plaintext, r, result_len);
	*plaintext_len = result_len;
	ret = 0;
release:
	CCCryptorRelease(aes);
out:
	secure_clear(a, sizeof(a));
	secure_clear(block, sizeof(block));
	secure_clear(decoded, sizeof(decoded));
	secure_clear(r, result_len);
	free(r);
	return ret;
}

int rtl_ccmp_encrypt(const u8 tk[16], const u8 *mac_header, size_t header_len,
		     u8 tid, u8 key_id, u64 packet_number, const u8 *plaintext,
		     size_t plaintext_len, u8 *out, size_t out_capacity,
		     size_t *out_len)
{
	CCCryptorRef aes = NULL;
	u8 aad[CCMP_MAX_AAD], nonce[13], tag[8], masked_tag[8];
	size_t aad_len;
	int ret;

	if (!tk || (!plaintext && plaintext_len) || !out || !out_len ||
	    plaintext_len > UINT16_MAX)
		return -EINVAL;
	if (out_capacity < CCMP_HDR_LEN + plaintext_len + CCMP_MIC_LEN)
		return -ENOSPC;
	if (packet_number > CCMP_MAX_PN || !packet_number || key_id > 3)
		return -EINVAL;
	ret = ccmp_aad(mac_header, header_len, tid, aad, &aad_len);
	if (ret)
		return ret;
	ret = aes_begin(tk, kCCEncrypt, &aes);
	if (ret)
		return ret;
	ccmp_nonce(mac_header, tid, packet_number, nonce);
	ret = ccmp_auth(aes, nonce, aad, aad_len, plaintext, plaintext_len, tag);
	if (!ret)
		ret = ccmp_header_write(out, key_id, packet_number);
	if (!ret)
		ret = ccmp_crypt(aes, nonce, plaintext, plaintext_len, out + CCMP_HDR_LEN);
	if (!ret)
		ret = ccmp_tag_mask(aes, nonce, tag, masked_tag);
	if (!ret) {
		memcpy(out + CCMP_HDR_LEN + plaintext_len, masked_tag, CCMP_MIC_LEN);
		*out_len = CCMP_HDR_LEN + plaintext_len + CCMP_MIC_LEN;
	}
	CCCryptorRelease(aes);
	secure_clear(aad, sizeof(aad));
	secure_clear(nonce, sizeof(nonce));
	secure_clear(tag, sizeof(tag));
	secure_clear(masked_tag, sizeof(masked_tag));
	return ret;
}

int rtl_ccmp_decrypt(const u8 tk[16], const u8 *mac_header, size_t header_len,
		     u8 tid, u8 expected_key_id, const u8 *ccmp_payload,
		     size_t ccmp_payload_len, u8 *plaintext, size_t plaintext_capacity,
		     size_t *plaintext_len, u64 *packet_number)
{
	CCCryptorRef aes = NULL;
	u8 aad[CCMP_MAX_AAD], nonce[13], received_tag[8], tag[8], masked_tag[8];
	size_t aad_len, data_len;
	u64 pn;
	int ret;

	if (!tk || !ccmp_payload || !plaintext || !plaintext_len || !packet_number ||
	    ccmp_payload_len < CCMP_HDR_LEN + CCMP_MIC_LEN)
		return -EINVAL;
	ret = ccmp_aad(mac_header, header_len, tid, aad, &aad_len);
	if (ret)
		return ret;
	ret = ccmp_header_read(ccmp_payload, expected_key_id, &pn);
	if (ret)
		return ret;
	data_len = ccmp_payload_len - CCMP_HDR_LEN - CCMP_MIC_LEN;
	if (data_len > UINT16_MAX || data_len > plaintext_capacity)
		return -EMSGSIZE;
	ret = aes_begin(tk, kCCEncrypt, &aes);
	if (ret)
		return ret;
	ccmp_nonce(mac_header, tid, pn, nonce);
	ret = ccmp_crypt(aes, nonce, ccmp_payload + CCMP_HDR_LEN, data_len, plaintext);
	if (!ret)
		ret = ccmp_auth(aes, nonce, aad, aad_len, plaintext, data_len, tag);
	if (!ret) {
		memcpy(received_tag, ccmp_payload + CCMP_HDR_LEN + data_len, CCMP_MIC_LEN);
		ret = ccmp_tag_mask(aes, nonce, tag, masked_tag);
		if (!ret && !constant_time_equal(received_tag, masked_tag, CCMP_MIC_LEN))
			ret = -EBADMSG;
	}
	if (!ret) {
		*plaintext_len = data_len;
		*packet_number = pn;
	} else {
		secure_clear(plaintext, data_len);
	}
	CCCryptorRelease(aes);
	secure_clear(aad, sizeof(aad));
	secure_clear(nonce, sizeof(nonce));
	secure_clear(received_tag, sizeof(received_tag));
	secure_clear(tag, sizeof(tag));
	secure_clear(masked_tag, sizeof(masked_tag));
	return ret;
}

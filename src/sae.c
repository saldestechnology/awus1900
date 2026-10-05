// SPDX-License-Identifier: BSD-3-Clause
/* WPA3-Personal SAE group 19 (P-256): H&P and Hash-to-Element PWE methods. */
#include <CommonCrypto/CommonHMAC.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include "rtl8814au.h"

#define SAE_GROUP_P256 19
#define SAE_SCALAR_LEN 32
#define SAE_ELEMENT_LEN 64
#define SAE_CONFIRM_LEN 32
#define SAE_HNP_ITERATIONS 40
#define SAE_HNP_MAX_ITERATIONS 255

static const char sae_pwe_label[] = "SAE Hunting and Pecking";
static const char sae_keys_label[] = "SAE KCK and PMK";

static void clear_bytes(void *ptr, size_t len)
{
	volatile u8 *p = ptr;

	while (len--)
		*p++ = 0;
}

/* IEEE 802.11 counter-mode KDF: LE16(counter) || label || context || LE16(bits). */
static int sae_kdf_sha256(const u8 key[32], const char *label,
		  const u8 *context, size_t context_len,
		  u8 *out, size_t out_len)
{
	u8 input[2 + 64 + 96 + 2], digest[CC_SHA256_DIGEST_LENGTH];
	size_t label_len, fixed_len, generated = 0;
	u16 counter = 1;

	if (!key || !label || (!context && context_len) || !out ||
	    context_len > 96 || out_len > 64 || out_len > UINT16_MAX / 8)
		return -EINVAL;
	label_len = strlen(label);
	if (!label_len || label_len > 64)
		return -EINVAL;
	fixed_len = 2 + label_len + context_len;
	memcpy(input + 2, label, label_len);
	if (context_len)
		memcpy(input + 2 + label_len, context, context_len);
	input[fixed_len] = (u8)(out_len * 8);
	input[fixed_len + 1] = (u8)((out_len * 8) >> 8);

	while (generated < out_len) {
		size_t take = min_t(size_t, sizeof(digest), out_len - generated);

		if (!counter)
			goto fail;
		input[0] = (u8)counter;
		input[1] = (u8)(counter >> 8);
		CCHmac(kCCHmacAlgSHA256, key, 32, input, fixed_len + 2, digest);
		memcpy(out + generated, digest, take);
		generated += take;
		counter++;
	}
	clear_bytes(input, sizeof(input));
	clear_bytes(digest, sizeof(digest));
	return 0;
fail:
	clear_bytes(input, sizeof(input));
	clear_bytes(digest, sizeof(digest));
	clear_bytes(out, out_len);
	return -EOVERFLOW;
}

static int legendre_symbol(BIGNUM *result, const BIGNUM *value,
			   const BIGNUM *exponent, const BIGNUM *prime,
			   BN_CTX *ctx)
{
	if (!BN_mod_exp_mont_consttime(result, value, exponent, prime, ctx, NULL))
		return -EIO;
	if (BN_is_one(result))
		return 1;
	if (BN_is_zero(result))
		return 0;
	return -1;
}

static int random_qr_qnr(const BIGNUM *prime, const BIGNUM *legendre_exp,
			 BN_CTX *ctx, BIGNUM *qr, BIGNUM *qnr)
{
	BIGNUM *candidate = BN_new(), *legendre = BN_new();
	bool have_qr = false, have_qnr = false;
	int ret = -EIO;

	if (!candidate || !legendre)
		goto out;
	for (unsigned i = 0; i < 1024 && (!have_qr || !have_qnr); i++) {
		int symbol;

		if (!BN_rand_range(candidate, prime) || BN_is_zero(candidate))
			continue;
		if (!BN_mod_exp(legendre, candidate, legendre_exp, prime, ctx))
			goto out;
		symbol = BN_is_one(legendre) ? 1 : -1;
		if (symbol > 0 && !have_qr) {
			if (!BN_copy(qr, candidate))
				goto out;
			have_qr = true;
		} else if (symbol < 0 && !have_qnr) {
			if (!BN_copy(qnr, candidate))
				goto out;
			have_qnr = true;
		}
	}
	if (have_qr && have_qnr)
		ret = 0;
out:
	BN_clear_free(candidate);
	BN_clear_free(legendre);
	return ret;
}

static int derive_pwe(const u8 own_addr[ETH_ALEN], const u8 peer_addr[ETH_ALEN],
		      const u8 *password, size_t password_len, u8 pwe[SAE_ELEMENT_LEN])
{
	EC_GROUP *group = NULL;
	EC_POINT *point = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *prime = NULL, *order = NULL, *legendre_exp = NULL, *sqrt_exp = NULL;
	BIGNUM *qr = NULL, *qnr = NULL, *blind = NULL, *blind_sq = NULL;
	BIGNUM *x = NULL, *x3 = NULL, *y_sq = NULL, *check = NULL;
	BIGNUM *legendre = NULL, *selected_x = NULL, *y = NULL, *minus_one = NULL;
	u8 mac_key[ETH_ALEN * 2], seed[CC_SHA256_DIGEST_LENGTH];
	u8 password_input[64], pwd_value[SAE_SCALAR_LEN], dummy_password[63];
	u8 prime_bytes[SAE_SCALAR_LEN];
	const u8 *active_password = password;
	bool selected = false;
	u8 selected_y_odd = 0;
	int ret = -EIO;

	memset(mac_key, 0, sizeof(mac_key));
	memset(seed, 0, sizeof(seed));
	memset(password_input, 0, sizeof(password_input));
	memset(pwd_value, 0, sizeof(pwd_value));
	memset(dummy_password, 0, sizeof(dummy_password));
	memset(prime_bytes, 0, sizeof(prime_bytes));
	/* SAE seeds use MAX(STA, AP) || MIN(STA, AP) as the HMAC key. */
	if (memcmp(own_addr, peer_addr, ETH_ALEN) > 0) {
		memcpy(mac_key, own_addr, ETH_ALEN);
		memcpy(mac_key + ETH_ALEN, peer_addr, ETH_ALEN);
	} else {
		memcpy(mac_key, peer_addr, ETH_ALEN);
		memcpy(mac_key + ETH_ALEN, own_addr, ETH_ALEN);
	}
	group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	ctx = BN_CTX_secure_new();
	prime = BN_new();
	order = BN_new();
	legendre_exp = BN_new();
	sqrt_exp = BN_new();
	qr = BN_new();
	qnr = BN_new();
	blind = BN_new();
	blind_sq = BN_new();
	x = BN_new();
	x3 = BN_new();
	y_sq = BN_new();
	check = BN_new();
	legendre = BN_new();
	selected_x = BN_new();
	y = BN_new();
	minus_one = BN_new();
	point = group ? EC_POINT_new(group) : NULL;
	if (!group || !ctx || !prime || !order || !legendre_exp || !sqrt_exp || !qr || !qnr ||
	    !blind || !blind_sq || !x || !x3 || !y_sq || !check || !legendre ||
	    !selected_x || !y || !minus_one || !point)
		goto out;
	if (!EC_GROUP_get_curve(group, prime, NULL, NULL, ctx) ||
	    !EC_GROUP_get_order(group, order, ctx) ||
	    !BN_copy(legendre_exp, prime) || !BN_sub_word(legendre_exp, 1) ||
	    !BN_rshift1(legendre_exp, legendre_exp) ||
	    !BN_copy(sqrt_exp, prime) || !BN_add_word(sqrt_exp, 1) ||
	    !BN_rshift(sqrt_exp, sqrt_exp, 2) ||
	    !BN_copy(minus_one, prime) || !BN_sub_word(minus_one, 1) ||
	    BN_bn2binpad(prime, prime_bytes, sizeof(prime_bytes)) != sizeof(prime_bytes))
		goto out;
	if (random_qr_qnr(prime, legendre_exp, ctx, qr, qnr))
		goto out;
	if (RAND_bytes(dummy_password, (int)password_len) != 1)
		goto out;

	for (unsigned counter = 1; counter <= SAE_HNP_MAX_ITERATIONS; counter++) {
		int in_range, symbol, is_qr, use_candidate;
		BIGNUM *multiplier;
		u8 counter_byte = (u8)counter;

		if (selected)
			active_password = dummy_password;
		memcpy(password_input, active_password, password_len);
		password_input[password_len] = counter_byte;
		CCHmac(kCCHmacAlgSHA256, mac_key, sizeof(mac_key), password_input,
		       password_len + 1, seed);
		if (sae_kdf_sha256(seed, sae_pwe_label, prime_bytes,
				  sizeof(prime_bytes), pwd_value, sizeof(pwd_value)))
			goto out;
		if (!BN_bin2bn(pwd_value, sizeof(pwd_value), x))
			goto out;
		in_range = BN_cmp(x, prime) < 0;
		if (!in_range && !BN_nnmod(x, x, prime, ctx))
			goto out;

		/* P-256 has a = -3: y^2 = x^3 - 3x + b (mod p). */
		if (!BN_mod_sqr(x3, x, prime, ctx) ||
		    !BN_mod_mul(x3, x3, x, prime, ctx) ||
		    !BN_mod_lshift1_quick(check, x, prime) ||
		    !BN_mod_add(check, check, x, prime, ctx) ||
		    !BN_mod_sub(y_sq, x3, check, prime, ctx))
			goto out;
		/* Add the P-256 curve coefficient b. */
		if (!BN_hex2bn(&check,
			"5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B") ||
		    !BN_mod_add(y_sq, y_sq, check, prime, ctx))
			goto out;
		if (!BN_rand_range(blind, prime))
			goto out;
		if (BN_is_zero(blind) && !BN_one(blind))
			goto out;
		if (!BN_mod_sqr(blind_sq, blind, prime, ctx) ||
		    !BN_mod_mul(check, y_sq, blind_sq, prime, ctx))
			goto out;
		multiplier = BN_is_odd(blind) ? qr : qnr;
		if (!BN_mod_mul(check, check, multiplier, prime, ctx))
			goto out;
		symbol = legendre_symbol(legendre, check, legendre_exp, prime, ctx);
		if (symbol == -EIO)
			goto out;
		is_qr = BN_is_odd(blind) ? symbol == 1 :
			(BN_cmp(legendre, minus_one) == 0);
		use_candidate = in_range && is_qr;
		if (!selected && use_candidate) {
			if (!BN_copy(selected_x, x))
				goto out;
			selected_y_odd = seed[sizeof(seed) - 1] & 1;
			selected = true;
		}
		clear_bytes(seed, sizeof(seed));
		if (selected && counter >= SAE_HNP_ITERATIONS)
			break;
	}
	if (!selected || !BN_mod_sqr(x3, selected_x, prime, ctx) ||
	    !BN_mod_mul(x3, x3, selected_x, prime, ctx) ||
	    !BN_mod_lshift1_quick(check, selected_x, prime) ||
	    !BN_mod_add(check, check, selected_x, prime, ctx) ||
	    !BN_mod_sub(y_sq, x3, check, prime, ctx) ||
	    !BN_hex2bn(&check,
		"5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B") ||
	    !BN_mod_add(y_sq, y_sq, check, prime, ctx) ||
	    !BN_mod_exp_mont_consttime(y, y_sq, sqrt_exp, prime, ctx, NULL) ||
	    !BN_mod_sqr(check, y, prime, ctx) || BN_cmp(check, y_sq) != 0)
		goto out;
	if ((u8)BN_is_odd(y) != selected_y_odd && !BN_sub(y, prime, y))
		goto out;
	if (!EC_POINT_set_affine_coordinates(group, point, selected_x, y, ctx) ||
	    !EC_POINT_is_on_curve(group, point, ctx) ||
	    !EC_POINT_get_affine_coordinates(group, point, x, y, ctx) ||
	    BN_bn2binpad(x, pwe, SAE_SCALAR_LEN) != SAE_SCALAR_LEN ||
	    BN_bn2binpad(y, pwe + SAE_SCALAR_LEN, SAE_SCALAR_LEN) != SAE_SCALAR_LEN)
		goto out;
	ret = 0;
out:
	clear_bytes(mac_key, sizeof(mac_key));
	clear_bytes(seed, sizeof(seed));
	clear_bytes(password_input, sizeof(password_input));
	clear_bytes(pwd_value, sizeof(pwd_value));
	clear_bytes(dummy_password, sizeof(dummy_password));
	clear_bytes(prime_bytes, sizeof(prime_bytes));
	EC_POINT_free(point);
	EC_GROUP_free(group);
	BN_CTX_free(ctx);
	BN_clear_free(prime);
	BN_clear_free(order);
	BN_clear_free(legendre_exp);
	BN_clear_free(sqrt_exp);
	BN_clear_free(qr);
	BN_clear_free(qnr);
	BN_clear_free(blind);
	BN_clear_free(blind_sq);
	BN_clear_free(x);
	BN_clear_free(x3);
	BN_clear_free(y_sq);
	BN_clear_free(check);
	BN_clear_free(legendre);
	BN_clear_free(selected_x);
	BN_clear_free(y);
	BN_clear_free(minus_one);
	return ret;
}

/* RFC 5869 HKDF-SHA256, used by the SAE Hash-to-Element PWE derivation. */
static int hkdf_sha256(const u8 *salt, size_t salt_len, const u8 *ikm,
		       size_t ikm_len, const u8 *info, size_t info_len,
		       u8 *out, size_t out_len)
{
	u8 zero_salt[CC_SHA256_DIGEST_LENGTH] = {0};
	u8 prk[CC_SHA256_DIGEST_LENGTH], block[CC_SHA256_DIGEST_LENGTH];
	u8 input[CC_SHA256_DIGEST_LENGTH + 64 + 1];
	size_t generated = 0, previous_len = 0;
	u8 counter = 1;
	int ret = -EINVAL;

	if ((!salt && salt_len) || !ikm || !ikm_len || (!info && info_len) || !out ||
	    info_len > 64 || out_len > 255 * sizeof(block))
		goto out;
	if (!salt_len) {
		salt = zero_salt;
		salt_len = sizeof(zero_salt);
	}
	CCHmac(kCCHmacAlgSHA256, salt, salt_len, ikm, ikm_len, prk);
	while (generated < out_len) {
		size_t input_len = 0;
		size_t take = min_t(size_t, sizeof(block), out_len - generated);

		if (!counter)
			goto out;
		if (previous_len) {
			memcpy(input, block, previous_len);
			input_len += previous_len;
		}
		if (info_len) {
			memcpy(input + input_len, info, info_len);
			input_len += info_len;
		}
		input[input_len++] = counter++;
		CCHmac(kCCHmacAlgSHA256, prk, sizeof(prk), input, input_len, block);
		memcpy(out + generated, block, take);
		generated += take;
		previous_len = sizeof(block);
	}
	ret = 0;
out:
	if (ret && out && out_len)
		clear_bytes(out, out_len);
	clear_bytes(zero_salt, sizeof(zero_salt));
	clear_bytes(prk, sizeof(prk));
	clear_bytes(block, sizeof(block));
	clear_bytes(input, sizeof(input));
	return ret;
}

/* RFC 9380 simplified SWU for NIST P-256 with Z = -10. */
static int p256_swu_map(const EC_GROUP *group, BN_CTX *ctx, const BIGNUM *prime,
		const BIGNUM *sqrt_exp, const BIGNUM *inverse_exp,
		const BIGNUM *u, EC_POINT *point)
{
	BIGNUM *tv1, *den, *inverse, *x1, *gx1, *x2, *gx2;
	BIGNUM *root1, *root2, *check, *a, *b, *z, *constant, *temporary;
	BIGNUM *exception_x, *negative_y;
	u8 u_bytes[SAE_SCALAR_LEN], x1_bytes[SAE_SCALAR_LEN];
	u8 x2_bytes[SAE_SCALAR_LEN], y1_bytes[SAE_SCALAR_LEN];
	u8 y2_bytes[SAE_SCALAR_LEN], gx_bytes[SAE_SCALAR_LEN];
	u8 gx2_bytes[SAE_SCALAR_LEN], check_bytes[SAE_SCALAR_LEN];
	u8 den_bytes[SAE_SCALAR_LEN], exception_bytes[SAE_SCALAR_LEN];
	u8 negative_y_bytes[SAE_SCALAR_LEN], y_bytes[SAE_SCALAR_LEN];
	u8 diff = 0;
	u8 diff2 = 0, den_nonzero = 0, choose_first, negate_y, exceptional_mask;
	int ret = -EIO;

	memset(u_bytes, 0, sizeof(u_bytes));
	memset(x1_bytes, 0, sizeof(x1_bytes));
	memset(x2_bytes, 0, sizeof(x2_bytes));
	memset(y1_bytes, 0, sizeof(y1_bytes));
	memset(y2_bytes, 0, sizeof(y2_bytes));
	memset(gx_bytes, 0, sizeof(gx_bytes));
	memset(gx2_bytes, 0, sizeof(gx2_bytes));
	memset(check_bytes, 0, sizeof(check_bytes));
	memset(den_bytes, 0, sizeof(den_bytes));
	memset(exception_bytes, 0, sizeof(exception_bytes));
	memset(negative_y_bytes, 0, sizeof(negative_y_bytes));
	memset(y_bytes, 0, sizeof(y_bytes));
	BN_CTX_start(ctx);
	tv1 = BN_CTX_get(ctx);
	den = BN_CTX_get(ctx);
	inverse = BN_CTX_get(ctx);
	x1 = BN_CTX_get(ctx);
	gx1 = BN_CTX_get(ctx);
	x2 = BN_CTX_get(ctx);
	gx2 = BN_CTX_get(ctx);
	root1 = BN_CTX_get(ctx);
	root2 = BN_CTX_get(ctx);
	check = BN_CTX_get(ctx);
	a = BN_CTX_get(ctx);
	b = BN_CTX_get(ctx);
	z = BN_CTX_get(ctx);
	constant = BN_CTX_get(ctx);
	temporary = BN_CTX_get(ctx);
	exception_x = BN_CTX_get(ctx);
	negative_y = BN_CTX_get(ctx);
	if (!negative_y ||
	    !BN_copy(a, prime) || !BN_sub_word(a, 3) || /* A = -3 */
	    !BN_hex2bn(&b,
		"5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B") ||
	    !BN_copy(z, prime) || !BN_sub_word(z, 10) || /* Z = -10 */
	    !BN_set_word(constant, 3) ||
	    !BN_mod_inverse(temporary, constant, prime, ctx) ||
	    !BN_mod_mul(constant, b, temporary, prime, ctx) || /* -B / A = B / 3 */
	    BN_bn2binpad(u, u_bytes, sizeof(u_bytes)) != sizeof(u_bytes))
		goto out;
	if (!BN_mod_sqr(tv1, u, prime, ctx) ||
	    !BN_mod_mul(tv1, tv1, z, prime, ctx) ||
	    !BN_mod_sqr(den, tv1, prime, ctx) ||
	    !BN_mod_add(den, den, tv1, prime, ctx))
		goto out;
	/* den^(p-2) is inv0(den): exponentiation also maps zero to zero. */
	if (!BN_mod_exp_mont_consttime(inverse, den, inverse_exp, prime, ctx, NULL))
		goto out;
	if (!BN_one(temporary) ||
	    !BN_mod_add(temporary, temporary, inverse, prime, ctx) ||
	    !BN_mod_mul(x1, constant, temporary, prime, ctx) ||
	    !BN_set_word(temporary, 30) ||
	    !BN_mod_inverse(exception_x, temporary, prime, ctx) ||
	    !BN_mod_mul(constant, b, exception_x, prime, ctx) ||
	    !BN_copy(exception_x, constant) ||
	    BN_bn2binpad(den, den_bytes, sizeof(den_bytes)) != sizeof(den_bytes) ||
	    BN_bn2binpad(exception_x, exception_bytes, sizeof(exception_bytes)) !=
										    sizeof(exception_bytes) ||
	    BN_bn2binpad(x1, x1_bytes, sizeof(x1_bytes)) != sizeof(x1_bytes))
		goto out;
	for (size_t i = 0; i < sizeof(den_bytes); i++)
		den_nonzero |= den_bytes[i];
	exceptional_mask = (u8)(0 - (u8)(den_nonzero == 0));
	for (size_t i = 0; i < sizeof(x1_bytes); i++)
		x1_bytes[i] = (x1_bytes[i] & (u8)~exceptional_mask) |
			(exception_bytes[i] & exceptional_mask);
	if (!BN_bin2bn(x1_bytes, sizeof(x1_bytes), x1))
		goto out;
	if (!BN_mod_sqr(gx1, x1, prime, ctx) ||
	    !BN_mod_mul(gx1, gx1, x1, prime, ctx) ||
	    !BN_mod_mul(temporary, a, x1, prime, ctx) ||
	    !BN_mod_add(gx1, gx1, temporary, prime, ctx) ||
	    !BN_mod_add(gx1, gx1, b, prime, ctx) ||
	    !BN_mod_mul(x2, tv1, x1, prime, ctx) ||
	    !BN_mod_sqr(gx2, x2, prime, ctx) ||
	    !BN_mod_mul(gx2, gx2, x2, prime, ctx) ||
	    !BN_mod_mul(temporary, a, x2, prime, ctx) ||
	    !BN_mod_add(gx2, gx2, temporary, prime, ctx) ||
	    !BN_mod_add(gx2, gx2, b, prime, ctx) ||
	    !BN_mod_exp_mont_consttime(root1, gx1, sqrt_exp, prime, ctx, NULL) ||
	    !BN_mod_exp_mont_consttime(root2, gx2, sqrt_exp, prime, ctx, NULL) ||
	    !BN_mod_sqr(check, root1, prime, ctx) ||
	    BN_bn2binpad(check, check_bytes, sizeof(check_bytes)) != sizeof(check_bytes) ||
	    BN_bn2binpad(gx1, gx_bytes, sizeof(gx_bytes)) != sizeof(gx_bytes))
		goto out;
	for (size_t i = 0; i < sizeof(gx_bytes); i++)
		diff |= check_bytes[i] ^ gx_bytes[i];
	choose_first = (u8)(0 - (u8)(diff == 0));
	if (BN_bn2binpad(x1, x1_bytes, sizeof(x1_bytes)) != sizeof(x1_bytes) ||
	    BN_bn2binpad(x2, x2_bytes, sizeof(x2_bytes)) != sizeof(x2_bytes) ||
	    BN_bn2binpad(root1, y1_bytes, sizeof(y1_bytes)) != sizeof(y1_bytes) ||
	    BN_bn2binpad(root2, y2_bytes, sizeof(y2_bytes)) != sizeof(y2_bytes) ||
	    !BN_mod_sqr(check, root2, prime, ctx) ||
	    BN_bn2binpad(check, check_bytes, sizeof(check_bytes)) != sizeof(check_bytes) ||
	    BN_bn2binpad(gx2, gx2_bytes, sizeof(gx2_bytes)) != sizeof(gx2_bytes))
		goto out;
	for (size_t i = 0; i < sizeof(gx2_bytes); i++)
		diff2 |= check_bytes[i] ^ gx2_bytes[i];
	if (!choose_first && diff2 != 0)
		goto out;
	for (size_t i = 0; i < SAE_SCALAR_LEN; i++) {
		x1_bytes[i] = (x1_bytes[i] & choose_first) | (x2_bytes[i] & (u8)~choose_first);
		y_bytes[i] = (y1_bytes[i] & choose_first) | (y2_bytes[i] & (u8)~choose_first);
	}
	negate_y = (u8)((y_bytes[SAE_SCALAR_LEN - 1] ^ u_bytes[SAE_SCALAR_LEN - 1]) & 1);
	if (!BN_bin2bn(y_bytes, sizeof(y_bytes), temporary) ||
	    !BN_mod_sub(negative_y, prime, temporary, prime, ctx) ||
	    BN_bn2binpad(negative_y, negative_y_bytes, sizeof(negative_y_bytes)) !=
										 sizeof(negative_y_bytes))
		goto out;
	{
		u8 negate_mask = (u8)(0 - negate_y);

		for (size_t i = 0; i < sizeof(y_bytes); i++)
			y_bytes[i] = (y_bytes[i] & (u8)~negate_mask) |
				(negative_y_bytes[i] & negate_mask);
	}
	if (!BN_bin2bn(x1_bytes, sizeof(x1_bytes), x1) ||
	    !BN_bin2bn(y_bytes, sizeof(y_bytes), root1) ||
	    !EC_POINT_set_affine_coordinates(group, point, x1, root1, ctx) ||
	    EC_POINT_is_on_curve(group, point, ctx) != 1)
		goto out;
	ret = 0;
out:
	clear_bytes(u_bytes, sizeof(u_bytes));
	clear_bytes(x1_bytes, sizeof(x1_bytes));
	clear_bytes(x2_bytes, sizeof(x2_bytes));
	clear_bytes(y1_bytes, sizeof(y1_bytes));
	clear_bytes(y2_bytes, sizeof(y2_bytes));
	clear_bytes(gx_bytes, sizeof(gx_bytes));
	clear_bytes(gx2_bytes, sizeof(gx2_bytes));
	clear_bytes(check_bytes, sizeof(check_bytes));
	clear_bytes(den_bytes, sizeof(den_bytes));
	clear_bytes(exception_bytes, sizeof(exception_bytes));
	clear_bytes(negative_y_bytes, sizeof(negative_y_bytes));
	clear_bytes(y_bytes, sizeof(y_bytes));
	BN_CTX_end(ctx);
	return ret;
}

static int derive_pwe_h2e(const u8 *ssid, size_t ssid_len,
			  const u8 *password, size_t password_len,
			  u8 pwe[SAE_ELEMENT_LEN])
{
	static const u8 u1_label[] = "SAE Hash to Element u1 P1";
	static const u8 u2_label[] = "SAE Hash to Element u2 P2";
	EC_GROUP *group = NULL;
	EC_POINT *p1 = NULL, *p2 = NULL, *sum = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *prime = NULL, *sqrt_exp = NULL, *inverse_exp = NULL;
	BIGNUM *u1 = NULL, *u2 = NULL, *x = NULL, *y = NULL;
	u8 uniform[48];
	int ret = -EIO;

	memset(uniform, 0, sizeof(uniform));
	if (!ssid || !ssid_len || ssid_len > 32 || !password ||
	    password_len < 8 || password_len > 63 || !pwe)
		return -EINVAL;
	group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	ctx = BN_CTX_secure_new();
	prime = BN_new();
	sqrt_exp = BN_new();
	inverse_exp = BN_new();
	u1 = BN_new();
	u2 = BN_new();
	x = BN_new();
	y = BN_new();
	p1 = group ? EC_POINT_new(group) : NULL;
	p2 = group ? EC_POINT_new(group) : NULL;
	sum = group ? EC_POINT_new(group) : NULL;
	if (!group || !ctx || !prime || !sqrt_exp || !inverse_exp || !u1 || !u2 ||
	    !x || !y || !p1 || !p2 || !sum)
		goto out;
	if (!EC_GROUP_get_curve(group, prime, NULL, NULL, ctx) ||
	    !BN_copy(sqrt_exp, prime) || !BN_add_word(sqrt_exp, 1) ||
	    !BN_rshift(sqrt_exp, sqrt_exp, 2) ||
	    !BN_copy(inverse_exp, prime) || !BN_sub_word(inverse_exp, 2))
		goto out;
	if (hkdf_sha256(ssid, ssid_len, password, password_len,
			u1_label, sizeof(u1_label) - 1, uniform, sizeof(uniform)) ||
	    !BN_bin2bn(uniform, sizeof(uniform), u1) || !BN_nnmod(u1, u1, prime, ctx) ||
	    p256_swu_map(group, ctx, prime, sqrt_exp, inverse_exp, u1, p1))
		goto out;
	clear_bytes(uniform, sizeof(uniform));
	if (hkdf_sha256(ssid, ssid_len, password, password_len,
			u2_label, sizeof(u2_label) - 1, uniform, sizeof(uniform)) ||
	    !BN_bin2bn(uniform, sizeof(uniform), u2) || !BN_nnmod(u2, u2, prime, ctx) ||
	    p256_swu_map(group, ctx, prime, sqrt_exp, inverse_exp, u2, p2) ||
	    !EC_POINT_add(group, sum, p1, p2, ctx) || EC_POINT_is_at_infinity(group, sum) ||
	    !EC_POINT_get_affine_coordinates(group, sum, x, y, ctx) ||
	    BN_bn2binpad(x, pwe, SAE_SCALAR_LEN) != SAE_SCALAR_LEN ||
	    BN_bn2binpad(y, pwe + SAE_SCALAR_LEN, SAE_SCALAR_LEN) != SAE_SCALAR_LEN)
		goto out;
	ret = 0;
out:
	clear_bytes(uniform, sizeof(uniform));
	if (ret && pwe)
		clear_bytes(pwe, SAE_ELEMENT_LEN);
	EC_POINT_free(p1);
	EC_POINT_free(p2);
	EC_POINT_free(sum);
	EC_GROUP_free(group);
	BN_CTX_free(ctx);
	BN_clear_free(prime);
	BN_clear_free(sqrt_exp);
	BN_clear_free(inverse_exp);
	BN_clear_free(u1);
	BN_clear_free(u2);
	BN_clear_free(x);
	BN_clear_free(y);
	return ret;
}

static int random_scalar(BIGNUM *value, const BIGNUM *order)
{
	for (unsigned i = 0; i < 100; i++) {
		if (!BN_rand_range(value, order))
			return -EIO;
		if (!BN_is_zero(value) && !BN_is_one(value)) {
			BN_set_flags(value, BN_FLG_CONSTTIME);
			return 0;
		}
	}
	return -EIO;
}

static int sae_init_with_pwe(struct rtl_sae_ctx *sae,
			     const u8 own_addr[ETH_ALEN],
			     const u8 peer_addr[ETH_ALEN],
			     const u8 pwe_bytes[SAE_ELEMENT_LEN])
{
	EC_GROUP *group = NULL;
	EC_POINT *pwe = NULL, *element = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *prime = NULL, *order = NULL, *rand = NULL, *mask = NULL;
	BIGNUM *scalar = NULL, *x = NULL, *y = NULL;
	int ret = -EIO;

	if (!sae || !own_addr || !peer_addr || !pwe_bytes ||
	    memcmp(own_addr, peer_addr, ETH_ALEN) == 0 ||
	    (own_addr[0] & 1) || (peer_addr[0] & 1))
		return -EINVAL;
	memset(sae, 0, sizeof(*sae));
	memcpy(sae->pwe, pwe_bytes, SAE_ELEMENT_LEN);
	group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	ctx = BN_CTX_secure_new();
	prime = BN_new();
	order = BN_new();
	rand = BN_new();
	mask = BN_new();
	scalar = BN_new();
	x = BN_new();
	y = BN_new();
	pwe = group ? EC_POINT_new(group) : NULL;
	element = group ? EC_POINT_new(group) : NULL;
	if (!group || !ctx || !prime || !order || !rand || !mask || !scalar ||
	    !x || !y || !pwe || !element)
		goto out;
	if (!EC_GROUP_get_curve(group, prime, NULL, NULL, ctx) ||
	    !EC_GROUP_get_order(group, order, ctx) ||
	    !BN_bin2bn(sae->pwe, SAE_SCALAR_LEN, x) ||
	    !BN_bin2bn(sae->pwe + SAE_SCALAR_LEN, SAE_SCALAR_LEN, y) ||
	    !EC_POINT_set_affine_coordinates(group, pwe, x, y, ctx) ||
	    EC_POINT_is_on_curve(group, pwe, ctx) != 1)
		goto out;
	for (unsigned attempt = 0; attempt < 100; attempt++) {
		if (random_scalar(rand, order) || random_scalar(mask, order))
			goto out;
		if (!BN_mod_add(scalar, rand, mask, order, ctx))
			goto out;
		if (!BN_is_zero(scalar) && !BN_is_one(scalar))
			break;
		if (attempt == 99)
			goto out;
	}
	if (!EC_POINT_mul(group, element, NULL, pwe, mask, ctx) ||
	    !EC_POINT_invert(group, element, ctx) ||
	    !EC_POINT_get_affine_coordinates(group, element, x, y, ctx) ||
	    BN_bn2binpad(rand, sae->own_rand, SAE_SCALAR_LEN) != SAE_SCALAR_LEN ||
	    BN_bn2binpad(scalar, sae->own_commit_scalar, SAE_SCALAR_LEN) != SAE_SCALAR_LEN ||
	    BN_bn2binpad(x, sae->own_commit_element, SAE_SCALAR_LEN) != SAE_SCALAR_LEN ||
	    BN_bn2binpad(y, sae->own_commit_element + SAE_SCALAR_LEN,
		  SAE_SCALAR_LEN) != SAE_SCALAR_LEN)
		goto out;
	sae->commit_ready = true;
	ret = 0;
out:
	if (ret)
		clear_bytes(sae, sizeof(*sae));
	EC_POINT_free(pwe);
	EC_POINT_free(element);
	EC_GROUP_free(group);
	BN_CTX_free(ctx);
	BN_clear_free(prime);
	BN_clear_free(order);
	BN_clear_free(rand);
	BN_clear_free(mask);
	BN_clear_free(scalar);
	BN_clear_free(x);
	BN_clear_free(y);
	return ret;
}

int rtl_sae_init(struct rtl_sae_ctx *sae, const u8 own_addr[ETH_ALEN],
		 const u8 peer_addr[ETH_ALEN], const u8 *password,
		 size_t password_len)
{
	u8 pwe[SAE_ELEMENT_LEN] = {0};
	int ret;

	if (!sae || !own_addr || !peer_addr || !password ||
	    password_len < 8 || password_len > 63)
		return -EINVAL;
	ret = derive_pwe(own_addr, peer_addr, password, password_len, pwe);
	if (!ret)
		ret = sae_init_with_pwe(sae, own_addr, peer_addr, pwe);
	clear_bytes(pwe, sizeof(pwe));
	return ret;
}

int rtl_sae_init_h2e(struct rtl_sae_ctx *sae, const u8 own_addr[ETH_ALEN],
		     const u8 peer_addr[ETH_ALEN], const u8 *ssid, size_t ssid_len,
		     const u8 *password, size_t password_len)
{
	u8 pwe[SAE_ELEMENT_LEN] = {0};
	int ret;

	if (!sae || !own_addr || !peer_addr || !ssid || !ssid_len ||
	    !password || password_len < 8 || password_len > 63)
		return -EINVAL;
	ret = derive_pwe_h2e(ssid, ssid_len, password, password_len, pwe);
	if (!ret)
		ret = sae_init_with_pwe(sae, own_addr, peer_addr, pwe);
	clear_bytes(pwe, sizeof(pwe));
	return ret;
}

int rtl_sae_build_commit(const struct rtl_sae_ctx *sae, u8 *out,
		 size_t capacity, size_t *out_len)
{
	return rtl_sae_build_commit_with_token(sae, NULL, 0, out, capacity, out_len);
}

int rtl_sae_build_commit_with_token(const struct rtl_sae_ctx *sae,
				    const u8 *token, size_t token_len,
				    u8 *out, size_t capacity, size_t *out_len)
{
	size_t offset = 2;

	if (!sae || !out || !out_len || !sae->commit_ready ||
	    (!token && token_len) || token_len > RTL_SAE_TOKEN_MAX_LEN ||
	    capacity < 2 + token_len + 32 + 64)
		return -EINVAL;
	out[0] = SAE_GROUP_P256 & 0xff;
	out[1] = SAE_GROUP_P256 >> 8;
	if (token_len) {
		memcpy(out + offset, token, token_len);
		offset += token_len;
	}
	memcpy(out + offset, sae->own_commit_scalar, 32);
	offset += 32;
	memcpy(out + offset, sae->own_commit_element, 64);
	offset += 64;
	*out_len = offset;
	return 0;
}

static int sae_confirm_value(const struct rtl_sae_ctx *sae, u16 counter,
			    bool local_first, u8 digest[SAE_CONFIRM_LEN])
{
	u8 input[2 + 32 + 64 + 32 + 64];
	const u8 *scalar1, *element1, *scalar2, *element2;

	if (!sae || !sae->keys_ready || !digest)
		return -EINVAL;
	scalar1 = local_first ? sae->own_commit_scalar : sae->peer_commit_scalar;
	element1 = local_first ? sae->own_commit_element : sae->peer_commit_element;
	scalar2 = local_first ? sae->peer_commit_scalar : sae->own_commit_scalar;
	element2 = local_first ? sae->peer_commit_element : sae->own_commit_element;
	input[0] = (u8)counter;
	input[1] = (u8)(counter >> 8);
	memcpy(input + 2, scalar1, 32);
	memcpy(input + 34, element1, 64);
	memcpy(input + 98, scalar2, 32);
	memcpy(input + 130, element2, 64);
	CCHmac(kCCHmacAlgSHA256, sae->kck, sizeof(sae->kck),
	       input, sizeof(input), digest);
	clear_bytes(input, sizeof(input));
	return 0;
}

int rtl_sae_process_commit(struct rtl_sae_ctx *sae, const u8 *body,
			   size_t body_len, u8 *confirm,
			   size_t confirm_capacity, size_t *confirm_len)
{
	EC_GROUP *group = NULL;
	EC_POINT *pwe = NULL, *peer_element = NULL, *sum = NULL, *shared = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *order = NULL, *prime = NULL, *peer_scalar = NULL, *x = NULL, *y = NULL;
	BIGNUM *rand = NULL, *shared_x = NULL, *scalar_sum = NULL;
	BIGNUM *pwe_x = NULL, *pwe_y = NULL, *own_scalar = NULL;
	u8 keyseed[32] = {0}, key_material[64], scalar_context[32], digest[32];
	int ret = -EINVAL;

	memset(key_material, 0, sizeof(key_material));
	memset(scalar_context, 0, sizeof(scalar_context));
	memset(digest, 0, sizeof(digest));
	if (!sae || !body || !confirm || !confirm_len || !sae->commit_ready ||
	    body_len != 98 || confirm_capacity < 34 ||
	    body[0] != SAE_GROUP_P256 || body[1] != 0)
		goto out;
	group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	ctx = BN_CTX_secure_new();
	order = BN_new();
	prime = BN_new();
	peer_scalar = BN_bin2bn(body + 2, 32, NULL);
	x = BN_bin2bn(body + 34, 32, NULL);
	y = BN_bin2bn(body + 66, 32, NULL);
	rand = BN_bin2bn(sae->own_rand, 32, NULL);
	shared_x = BN_new();
	scalar_sum = BN_new();
	pwe_x = BN_bin2bn(sae->pwe, 32, NULL);
	pwe_y = BN_bin2bn(sae->pwe + 32, 32, NULL);
	own_scalar = BN_bin2bn(sae->own_commit_scalar, 32, NULL);
	pwe = group ? EC_POINT_new(group) : NULL;
	peer_element = group ? EC_POINT_new(group) : NULL;
	sum = group ? EC_POINT_new(group) : NULL;
	shared = group ? EC_POINT_new(group) : NULL;
	if (!group || !ctx || !order || !prime || !peer_scalar || !x || !y || !rand ||
	    !shared_x || !scalar_sum || !pwe_x || !pwe_y || !own_scalar ||
	    !pwe || !peer_element || !sum || !shared)
		goto out;
	BN_set_flags(rand, BN_FLG_CONSTTIME);
	if (!EC_GROUP_get_order(group, order, ctx) ||
	    !EC_GROUP_get_curve(group, prime, NULL, NULL, ctx) ||
	    BN_is_zero(peer_scalar) || BN_is_one(peer_scalar) || BN_cmp(peer_scalar, order) >= 0 ||
	    !EC_POINT_set_affine_coordinates(group, pwe, pwe_x, pwe_y, ctx) ||
	    !EC_POINT_set_affine_coordinates(group, peer_element, x, y, ctx) ||
	    EC_POINT_is_at_infinity(group, peer_element) ||
	    EC_POINT_is_on_curve(group, peer_element, ctx) != 1)
		goto out;
	if (BN_cmp(peer_scalar, own_scalar) == 0) {
		EC_POINT *own_element = EC_POINT_new(group);
		BIGNUM *own_x = BN_bin2bn(sae->own_commit_element, 32, NULL);
		BIGNUM *own_y = BN_bin2bn(sae->own_commit_element + 32, 32, NULL);
		int same = own_element && own_x && own_y &&
			EC_POINT_set_affine_coordinates(group, own_element, own_x, own_y, ctx) &&
			EC_POINT_cmp(group, own_element, peer_element, ctx) == 0;
		EC_POINT_free(own_element);
		BN_clear_free(own_x);
		BN_clear_free(own_y);
		if (same) {
			ret = -EACCES;
			goto out;
		}
	}
	if (!EC_POINT_mul(group, sum, NULL, pwe, peer_scalar, ctx) ||
	    !EC_POINT_add(group, sum, sum, peer_element, ctx) ||
	    !EC_POINT_mul(group, shared, NULL, sum, rand, ctx) ||
	    EC_POINT_is_at_infinity(group, shared) ||
	    !EC_POINT_get_affine_coordinates(group, shared, shared_x, y, ctx) ||
	    BN_bn2binpad(shared_x, digest, sizeof(digest)) != sizeof(digest) ||
	    !BN_mod_add(scalar_sum, own_scalar, peer_scalar, order, ctx) ||
	    BN_bn2binpad(scalar_sum, scalar_context, sizeof(scalar_context)) != sizeof(scalar_context))
		goto out;
	CCHmac(kCCHmacAlgSHA256, keyseed, sizeof(keyseed), digest, sizeof(digest), keyseed);
	if (sae_kdf_sha256(keyseed, sae_keys_label, scalar_context, sizeof(scalar_context),
			   key_material, sizeof(key_material)))
		goto out;
	memcpy(sae->peer_commit_scalar, body + 2, 32);
	memcpy(sae->peer_commit_element, body + 34, 64);
	memcpy(sae->kck, key_material, sizeof(sae->kck));
	memcpy(sae->pmk, key_material + sizeof(sae->kck), sizeof(sae->pmk));
	sae->keys_ready = true;
	sae->send_confirm = 1;
	confirm[0] = (u8)sae->send_confirm;
	confirm[1] = (u8)(sae->send_confirm >> 8);
	if (sae_confirm_value(sae, sae->send_confirm, true, digest))
		goto out;
	memcpy(confirm + 2, digest, sizeof(digest));
	*confirm_len = 34;
	if (sae->send_confirm < UINT16_MAX)
		sae->send_confirm++;
	ret = 0;
out:
	clear_bytes(keyseed, sizeof(keyseed));
	clear_bytes(key_material, sizeof(key_material));
	clear_bytes(scalar_context, sizeof(scalar_context));
	clear_bytes(digest, sizeof(digest));
	EC_POINT_free(pwe);
	EC_POINT_free(peer_element);
	EC_POINT_free(sum);
	EC_POINT_free(shared);
	EC_GROUP_free(group);
	BN_CTX_free(ctx);
	BN_clear_free(order);
	BN_clear_free(prime);
	BN_clear_free(peer_scalar);
	BN_clear_free(x);
	BN_clear_free(y);
	BN_clear_free(rand);
	BN_clear_free(shared_x);
	BN_clear_free(scalar_sum);
	BN_clear_free(pwe_x);
	BN_clear_free(pwe_y);
	BN_clear_free(own_scalar);
	return ret;
}

int rtl_sae_check_confirm(struct rtl_sae_ctx *sae, const u8 *confirm,
			  size_t confirm_len)
{
	u8 expected[SAE_CONFIRM_LEN];
	u16 counter;
	int ret;

	if (!sae || !confirm || confirm_len != 2 + SAE_CONFIRM_LEN || !sae->keys_ready)
		return -EINVAL;
	counter = (u16)confirm[0] | ((u16)confirm[1] << 8);
	if (!counter || counter <= sae->peer_confirm)
		return -EINVAL;
	ret = sae_confirm_value(sae, counter, false, expected);
	if (!ret && CRYPTO_memcmp(expected, confirm + 2, sizeof(expected)))
		ret = -EACCES;
	clear_bytes(expected, sizeof(expected));
	if (!ret)
		sae->peer_confirm = counter;
	return ret;
}

int rtl_wpa3_derive_ptk(const u8 pmk[32], const u8 addr1[ETH_ALEN],
		       const u8 addr2[ETH_ALEN], const u8 nonce1[32],
		       const u8 nonce2[32], struct rtl_wpa2_ptk *ptk)
{
	static const char label[] = "Pairwise key expansion";
	u8 context[ETH_ALEN * 2 + 64], output[48], digest[CC_SHA256_DIGEST_LENGTH];
	u8 input[2 + sizeof(label) - 1 + sizeof(context) + 2];
	const u8 *mac_lo, *mac_hi, *nonce_lo, *nonce_hi;
	size_t label_len = sizeof(label) - 1, fixed_len, generated = 0;
	u16 counter = 1;

	if (!pmk || !addr1 || !addr2 || !nonce1 || !nonce2 || !ptk)
		return -EINVAL;
	memset(output, 0, sizeof(output));
	memset(digest, 0, sizeof(digest));
	mac_lo = memcmp(addr1, addr2, ETH_ALEN) <= 0 ? addr1 : addr2;
	mac_hi = mac_lo == addr1 ? addr2 : addr1;
	nonce_lo = memcmp(nonce1, nonce2, 32) <= 0 ? nonce1 : nonce2;
	nonce_hi = nonce_lo == nonce1 ? nonce2 : nonce1;
	memcpy(context, mac_lo, ETH_ALEN);
	memcpy(context + ETH_ALEN, mac_hi, ETH_ALEN);
	memcpy(context + ETH_ALEN * 2, nonce_lo, 32);
	memcpy(context + ETH_ALEN * 2 + 32, nonce_hi, 32);
	fixed_len = 2 + label_len + sizeof(context);
	memcpy(input + 2, label, label_len);
	memcpy(input + 2 + label_len, context, sizeof(context));
	input[fixed_len] = 0x80; /* 384 bits, little-endian */
	input[fixed_len + 1] = 0x01;
	while (generated < sizeof(output)) {
		size_t take = min_t(size_t, CC_SHA256_DIGEST_LENGTH,
				    sizeof(output) - generated);

		input[0] = (u8)counter;
	input[1] = (u8)(counter >> 8);
		CCHmac(kCCHmacAlgSHA256, pmk, 32, input, fixed_len + 2, digest);
		memcpy(output + generated, digest, take);
		generated += take;
		counter++;
	}
	memcpy(ptk->kck, output, sizeof(ptk->kck));
	memcpy(ptk->kek, output + sizeof(ptk->kck), sizeof(ptk->kek));
	memcpy(ptk->tk, output + sizeof(ptk->kck) + sizeof(ptk->kek), sizeof(ptk->tk));
	clear_bytes(context, sizeof(context));
	clear_bytes(input, sizeof(input));
	clear_bytes(output, sizeof(output));
	clear_bytes(digest, sizeof(digest));
	return 0;
}

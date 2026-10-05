/* SPDX-License-Identifier: BSD-3-Clause */
/* Minimal Linux-kernel-style compatibility layer so rtw88 chip code (GPL-2.0 OR BSD-3-Clause)
 * can be built in userspace over libusb.
 */
#ifndef RTW_COMPAT_H
#define RTW_COMPAT_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <libusb.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;
typedef uint16_t __le16;
typedef uint32_t __le32;
typedef uint16_t __be16;

#define __LITTLE_ENDIAN 1234
#define LINUX_VERSION_CODE 0
#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + (c))

#define __packed __attribute__((packed))
#define __aligned(x) __attribute__((aligned(x)))
#define __always_unused __attribute__((unused))
#define __maybe_unused __attribute__((unused))
#define fallthrough __attribute__((fallthrough))
#define EXPORT_SYMBOL(x)
#define EXPORT_SYMBOL_GPL(x)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define likely(x) __builtin_expect(!!(x), 1)
#define BUILD_BUG_ON(x) _Static_assert(!(x), #x)

#define BIT(n)			(1U << (n))
#define BIT_ULL(n)		(1ULL << (n))
#define GENMASK(h, l)		(((~0U) << (l)) & (~0U >> (31 - (h))))
#define ARRAY_SIZE(a)		(sizeof(a) / sizeof((a)[0]))
#define DIV_ROUND_UP(n, d)	(((n) + (d) - 1) / (d))
#define ETH_ALEN		6
#define min(a, b)		((a) < (b) ? (a) : (b))
#define max(a, b)		((a) > (b) ? (a) : (b))
#define min_t(t, a, b)		((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define max_t(t, a, b)		((t)(a) > (t)(b) ? (t)(a) : (t)(b))
#define clamp_t(t, v, lo, hi)	((t)(v) < (t)(lo) ? (t)(lo) : ((t)(v) > (t)(hi) ? (t)(hi) : (t)(v)))
#define clamp(v, lo, hi)	((v) < (lo) ? (lo) : ((v) > (hi) ? (hi) : (v)))
#define abs_diff(a, b)		((a) > (b) ? (a) - (b) : (b) - (a))
#define swap(a, b)		do { __typeof__(a) _t = (a); (a) = (b); (b) = _t; } while (0)
#define DECLARE_BITMAP(name, bits) unsigned long name[((bits) + 63) / 64]
#define set_bit(n, a)		((a)[(n) / 64] |= 1UL << ((n) % 64))
#define clear_bit(n, a)		((a)[(n) / 64] &= ~(1UL << ((n) % 64)))
#define test_bit(n, a)		(!!((a)[(n) / 64] & (1UL << ((n) % 64))))

static inline unsigned long __ffs(unsigned long x) { return __builtin_ctzl(x); }

#define cpu_to_le16(x)		((__le16)(x))
#define cpu_to_le32(x)		((__le32)(x))
#define le16_to_cpu(x)		((u16)(x))
#define le32_to_cpu(x)		((u32)(x))
#define __le16_to_cpu(x)	((u16)(x))
#define __le32_to_cpu(x)	((u32)(x))

/* bitfield helpers (mask must be a compile-time-nonzero contiguous mask) */
#define __mask_shift(m)		(__builtin_ctzll(m))
#define u32_get_bits(v, m)	((u32)(((v) & (m)) >> __mask_shift(m)))
#define u16_get_bits(v, m)	((u16)(((v) & (m)) >> __mask_shift(m)))
#define u8_get_bits(v, m)	((u8)(((v) & (m)) >> __mask_shift(m)))
#define le32_get_bits(v, m)	u32_get_bits(v, m)
#define u32_encode_bits(v, m)	((u32)(((u32)(v) << __mask_shift(m)) & (m)))
#define u16_encode_bits(v, m)	((u16)(((u32)(v) << __mask_shift(m)) & (m)))
#define u8_encode_bits(v, m)	((u8)(((u32)(v) << __mask_shift(m)) & (m)))
#define le32_encode_bits(v, m)	u32_encode_bits(v, m)
#define le32p_replace_bits(p, v, m) (*(p) = (*(p) & ~(u32)(m)) | u32_encode_bits(v, m))
#define u32p_replace_bits(p, v, m)  le32p_replace_bits(p, v, m)
#define u8p_replace_bits(p, v, m)   (*(p) = (u8)((*(p) & ~(u8)(m)) | u8_encode_bits(v, m)))

/* delays */
static inline void udelay(unsigned long us) { usleep(us); }
static inline void mdelay(unsigned long ms) { usleep(ms * 1000); }
static inline void msleep(unsigned long ms) { usleep(ms * 1000); }
static inline void usleep_range(unsigned long a, unsigned long b) { (void)b; usleep(a); }
static inline void fsleep(unsigned long us) { usleep(us); }

/* logging */
extern int rtw_debug;
#define rtw_err(rtwdev, fmt, ...)	fprintf(stderr, "rtw: " fmt, ##__VA_ARGS__)
#define rtw_warn(rtwdev, fmt, ...)	fprintf(stderr, "rtw: warn: " fmt, ##__VA_ARGS__)
#define rtw_info(rtwdev, fmt, ...)	fprintf(stdout, "rtw: " fmt, ##__VA_ARGS__)
#define rtw_dbg(rtwdev, mask, fmt, ...)	do { if (rtw_debug) fprintf(stderr, "rtw[dbg]: " fmt, ##__VA_ARGS__); } while (0)
#define WARN(cond, fmt, ...)	({ int _w = !!(cond); if (_w) fprintf(stderr, "WARN: " fmt, ##__VA_ARGS__); _w; })
#define WARN_ON(cond)		({ int _w = !!(cond); if (_w) fprintf(stderr, "WARN_ON(" #cond ")\n"); _w; })
#define RTW_DBG_PHY 0
#define RTW_DBG_FW 0
#define RTW_DBG_EFUSE 0
#define RTW_DBG_UNEXP 0
#define RTW_DBG_TX 0
#define RTW_DBG_RX 0
#define RTW_DBG_DEPRECATED 0
#define RTW_DBG_REGD 0
#define rtw_dbg_is_enabled(rtwdev, mask) (rtw_debug)

#define NL80211_BAND_2GHZ	0
#define NL80211_BAND_5GHZ	1
#define NL80211_BAND_60GHZ	2
#define NUM_NL80211_BANDS	3

struct mutex { int dummy; };
#define mutex_lock(m)
#define mutex_unlock(m)
#define mutex_init(m)


#define DECLARE_EWMA(name, p, f) \
struct ewma_##name { unsigned long internal; }; \
static inline void ewma_##name##_init(struct ewma_##name *e) { e->internal = 0; } \
static inline void ewma_##name##_add(struct ewma_##name *e, unsigned long val) \
{ \
	unsigned long w = __builtin_ctz(f); \
	e->internal = e->internal ? (((e->internal << w) - e->internal) + (val << (p))) >> w : (val << (p)); \
} \
static inline unsigned long ewma_##name##_read(struct ewma_##name *e) { return e->internal >> (p); }

#define static_assert(c, ...) _Static_assert(c, #c)
#define IEEE80211_VHT_MAX_AMPDU_256K 5
#define IEEE80211_HT_MPDU_DENSITY_2 4
#define read_poll_timeout(op, val, cond, sleep_us, timeout_us, sleep_before_read, args...) \
({ \
	unsigned long _slept = 0; \
	int _ret; \
	for (;;) { \
		(val) = op(args); \
		if (cond) { _ret = 0; break; } \
		if ((timeout_us) && _slept >= (unsigned long)(timeout_us)) { _ret = -ETIMEDOUT; break; } \
		if (sleep_us) { usleep(sleep_us); _slept += (sleep_us); } \
	} \
	_ret; \
})
#define read_poll_timeout_atomic read_poll_timeout
enum rtw_lps_deep_mode_stub { LPS_DEEP_MODE_NONE, LPS_DEEP_MODE_LCLK, LPS_DEEP_MODE_PG };
#define IEEE80211_MAX_DATA_LEN 2304
#define memcpy_eth(d, s) memcpy(d, s, ETH_ALEN)
static inline unsigned bcd2bin(unsigned char v) { return (v & 0x0f) + (v >> 4) * 10; }
#define abs(x) ((x) < 0 ? -(x) : (x))

#endif

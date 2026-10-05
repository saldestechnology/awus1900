/* SPDX-License-Identifier: BSD-3-Clause */
/* Register I/O wrappers with rtw88-style names, backed by libusb (dev.c). */
#ifndef RTW_IO_H
#define RTW_IO_H

u8  rtw_read8(struct rtw_dev *rtwdev, u32 addr);
u16 rtw_read16(struct rtw_dev *rtwdev, u32 addr);
u32 rtw_read32(struct rtw_dev *rtwdev, u32 addr);
void rtw_write8(struct rtw_dev *rtwdev, u32 addr, u8 val);
void rtw_write16(struct rtw_dev *rtwdev, u32 addr, u16 val);
void rtw_write32(struct rtw_dev *rtwdev, u32 addr, u32 val);

static inline void rtw_write8_set(struct rtw_dev *d, u32 a, u8 b)   { rtw_write8(d, a, rtw_read8(d, a) | b); }
static inline void rtw_write16_set(struct rtw_dev *d, u32 a, u16 b) { rtw_write16(d, a, rtw_read16(d, a) | b); }
static inline void rtw_write32_set(struct rtw_dev *d, u32 a, u32 b) { rtw_write32(d, a, rtw_read32(d, a) | b); }
static inline void rtw_write8_clr(struct rtw_dev *d, u32 a, u8 b)   { rtw_write8(d, a, rtw_read8(d, a) & ~b); }
static inline void rtw_write16_clr(struct rtw_dev *d, u32 a, u16 b) { rtw_write16(d, a, rtw_read16(d, a) & ~b); }
static inline void rtw_write32_clr(struct rtw_dev *d, u32 a, u32 b) { rtw_write32(d, a, rtw_read32(d, a) & ~b); }

static inline void rtw_write8_mask(struct rtw_dev *d, u32 a, u32 mask, u8 data)
{
	u32 shift = __builtin_ctz(mask);
	u8 orig = rtw_read8(d, a);

	rtw_write8(d, a, (orig & ~mask) | ((data << shift) & mask));
}

static inline void rtw_write16_mask(struct rtw_dev *d, u32 a, u32 mask, u16 data)
{
	u32 shift = __builtin_ctz(mask);
	u16 orig = rtw_read16(d, a);

	rtw_write16(d, a, (orig & ~mask) | ((data << shift) & mask));
}

static inline void rtw_write32_mask(struct rtw_dev *d, u32 a, u32 mask, u32 data)
{
	u32 shift = __builtin_ctz(mask);
	u32 orig = rtw_read32(d, a);

	rtw_write32(d, a, (orig & ~mask) | ((data << shift) & mask));
}

static inline u8  rtw_read8_mask(struct rtw_dev *d, u32 a, u32 mask)  { return (rtw_read8(d, a) & mask) >> __builtin_ctz(mask); }
static inline u16 rtw_read16_mask(struct rtw_dev *d, u32 a, u32 mask) { return (rtw_read16(d, a) & mask) >> __builtin_ctz(mask); }
static inline u32 rtw_read32_mask(struct rtw_dev *d, u32 a, u32 mask) { return (rtw_read32(d, a) & mask) >> __builtin_ctz(mask); }

static inline u32 rtw_read_rf(struct rtw_dev *d, enum rtw_rf_path path, u32 addr, u32 mask)
{
	return d->chip->ops->read_rf(d, path, addr, mask);
}

static inline void rtw_write_rf(struct rtw_dev *d, enum rtw_rf_path path, u32 addr, u32 mask, u32 data)
{
	d->chip->ops->write_rf(d, path, addr, mask, data);
}

#endif

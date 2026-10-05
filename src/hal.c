// SPDX-License-Identifier: BSD-3-Clause
/* Hardware bring-up orchestration for the RTL8814AU: follows rtw88 rtw_power_on()
 * (main.c, GPL-2.0 OR BSD-3-Clause, Copyright(c) Realtek Corporation).
 */
#include "rtl8814au.h"
#include "rtw/mac.h"
#include <time.h>

/* rtw_usb_init_burst_pkt_len */
void rtw_hci_interface_cfg(struct rtw_dev *rtwdev)
{
	u8 rxdma, burst_size;

	rxdma = BIT_DMA_BURST_CNT | BIT_DMA_MODE;
	if (rtwdev->usb_speed >= LIBUSB_SPEED_SUPER)
		burst_size = BIT_DMA_BURST_SIZE_1024;
	else if (rtwdev->usb_speed == LIBUSB_SPEED_HIGH)
		burst_size = BIT_DMA_BURST_SIZE_512;
	else
		burst_size = BIT_DMA_BURST_SIZE_64;

	u8p_replace_bits(&rxdma, burst_size, BIT_DMA_BURST_SIZE);
	rtw_write8(rtwdev, REG_RXDMA_MODE, rxdma);
	rtw_write16_set(rtwdev, REG_TXDMA_OFFSET_CHK, BIT_DROP_DATA_EN);
}

bool check_hw_ready(struct rtw_dev *rtwdev, u32 addr, u32 mask, u32 target)
{
	for (u32 cnt = 0; cnt < 1000; cnt++) {
		if (rtw_read32_mask(rtwdev, addr, mask) == target)
			return true;
		udelay(10);
	}
	return false;
}

/* chip ops hooks that only matter to the Linux driver core */
int rtw_power_on(struct rtw_dev *rtwdev) { return 0; }
void rtw_power_off(struct rtw_dev *rtwdev) { }

/* minimal rtw_phy_init (dynamic mechanisms are not used yet) */
void rtw_phy_init(struct rtw_dev *rtwdev)
{
	const struct rtw_chip_info *chip = rtwdev->chip;
	struct rtw_dm_info *dm_info = &rtwdev->dm_info;

	memset(dm_info->fa_history, 0, sizeof(dm_info->fa_history));
	memset(dm_info->igi_history, 0, sizeof(dm_info->igi_history));
	dm_info->igi_bitmap = 0;
	dm_info->igi_history[0] = rtw_read32_mask(rtwdev, chip->dig[0].addr, chip->dig[0].mask);
	for (int i = 0; i <= RTW_CHANNEL_WIDTH_40; i++)
		for (int j = 0; j < RTW_RF_PATH_MAX; j++)
			dm_info->cck_pd_lv[i][j] = CCK_PD_LV0;
	dm_info->cck_fa_avg = CCK_FA_AVG_RESET;
	dm_info->iqk.done = false;
}

/* rtw_chip_board_info_setup */
static int board_info_setup(struct rtw_dev *rtwdev)
{
	struct rtw_hal *hal = &rtwdev->hal;
	const struct rtw_rfe_def *rfe_def = rtw_get_rfe_def(rtwdev);

	if (!rfe_def) {
		fprintf(stderr, "unsupported rfe option %u\n", rtwdev->efuse.rfe_option);
		return -ENODEV;
	}

	rtw_phy_setup_phy_cond(rtwdev, hal->pkg_type);
	rtw_phy_init_tx_power(rtwdev);
	rtw_load_table(rtwdev, rfe_def->phy_pg_tbl);
	rtw_load_table(rtwdev, rfe_def->txpwr_lmt_tbl);
	rtw_phy_tx_power_by_rate_config(hal);
	rtw_phy_tx_power_limit_config(hal);
	return 0;
}

int rtl_hw_init(struct rtw_dev *d, const char *fw_path)
{
	int ret;

	rtl_read_chip_info(d);
	ret = rtl_mac_power_on(d);
	if (ret)
		return ret;
	ret = rtl_read_efuse(d);
	if (ret) {
		fprintf(stderr, "efuse read failed: %d\n", ret);
		return ret;
	}
	printf("efuse: MAC %02x:%02x:%02x:%02x:%02x:%02x rfe=%u xtal=0x%02x rf_type=%u\n",
	       d->efuse.addr[0], d->efuse.addr[1], d->efuse.addr[2], d->efuse.addr[3],
	       d->efuse.addr[4], d->efuse.addr[5], d->efuse.rfe_option, d->efuse.crystal_cap,
	       d->hal.rf_type);

	ret = board_info_setup(d);
	if (ret)
		return ret;

	/* rtw_power_on */
	ret = rtl_mac_power_on(d);
	if (ret)
		return ret;
	ret = rtl_download_firmware(d, fw_path);
	if (ret)
		return ret;
	ret = rtw_mac_init(d);
	if (ret) {
		fprintf(stderr, "mac init failed: %d\n", ret);
		return ret;
	}
	d->chip->ops->phy_set_param(d);
	return 0;
}

int rtl_set_tx_regulatory_domain(struct rtw_dev *d, enum rtw_regulatory_domains regd)
{
	if (!d || !d->chip || regd < 0 || regd >= RTW_REGD_MAX)
		return -EINVAL;

	d->hal.txpwr_regd = (u8)regd;
	d->tx_regd_explicit = true;
	return 0;
}

bool rtl_channel_is_supported(u8 channel)
{
	static const u8 channels_5g[] = {
		36, 40, 44, 48, 52, 56, 60, 64,
		100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
		149, 153, 157, 161, 165, 169, 173, 177,
	};

	if (channel >= 1 && channel <= 14)
		return true;
	for (size_t i = 0; i < ARRAY_SIZE(channels_5g); i++)
		if (channels_5g[i] == channel)
			return true;
	return false;
}

static u64 monotonic_ms(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return 0;
	return (u64)ts.tv_sec * 1000 + (u64)ts.tv_nsec / 1000000;
}

void rtl_thermal_track_enable(struct rtw_dev *d, bool enable)
{
	if (!d)
		return;
	d->thermal_track_enabled = enable;
	d->thermal_track_next_ms = 0;
}

/* The 8814A pwr_track hook alternates between starting a thermal conversion and
 * consuming its result. Polling it once per second gives a two-second sample
 * cadence, matching the driver's periodic dynamic-mechanism cadence without
 * porting unrelated firmware-dependent mechanisms.
 */
void rtl_thermal_track_tick(struct rtw_dev *d)
{
	u64 now;

	if (!d || !d->thermal_track_enabled || !d->chip || !d->chip->ops ||
	    !d->chip->ops->pwr_track || !d->h ||
	    d->efuse.thermal_meter[RF_PATH_A] == 0xff)
		return;

	now = monotonic_ms();
	if (!now || (d->thermal_track_next_ms && now < d->thermal_track_next_ms))
		return;
	d->thermal_track_next_ms = now + 1000;
	d->chip->ops->pwr_track(d);
}

/* Explicit, one-shot USB2-to-USB3 request for the RTL8814A. This is the
 * rtw88 old-chip sequence. The caller must expect the adapter to disconnect.
 */
int rtl_usb3_request_switch(struct rtw_dev *d)
{
	static const u32 regs[] = {
		REG_HCI_OPT_CTRL, REG_SYS_SDIO_CTRL, REG_ACLK_MON, 0x3d,
	};
	static const u8 values[] = { 0x08, 0x02, 0x01, 0x03 };
	u8 saved[ARRAY_SIZE(regs)], value, sdio, aclk;
	int ret;

	if (!d || !d->h || !d->chip)
		return -EINVAL;
	if (d->chip->id != RTW_CHIP_TYPE_8814A)
		return -EOPNOTSUPP;
	if (!d->efuse.usb_mode_switch)
		return -EOPNOTSUPP;

	if (d->usb_speed == LIBUSB_SPEED_SUPER) {
		ret = rtl_read8_checked(d, REG_SYS_SDIO_CTRL, &sdio);
		if (ret)
			return ret;
		ret = rtl_read8_checked(d, REG_ACLK_MON, &aclk);
		if (ret)
			return ret;
		ret = rtl_write8_checked(d, REG_SYS_SDIO_CTRL, sdio & ~BIT(1));
		if (ret)
			return ret;
		ret = rtl_write8_checked(d, REG_ACLK_MON, aclk & ~BIT(0));
		if (ret) {
			if (rtl_write8_checked(d, REG_SYS_SDIO_CTRL, sdio))
				fprintf(stderr, "warning: failed to restore USB3 SDIO mode register\n");
			return ret;
		}
		return 0;
	}
	if (d->usb_speed != LIBUSB_SPEED_HIGH)
		return -EOPNOTSUPP;

	ret = rtl_read8_checked(d, REG_HCI_OPT_CTRL, &value);
	if (ret)
		return ret;
	if ((value & (BIT(2) | BIT(3))) == BIT(3))
		return -EALREADY; /* Don't repeat a request on a USB2-only port. */

	for (size_t i = 0; i < ARRAY_SIZE(regs); i++) {
		ret = rtl_read8_checked(d, regs[i], &saved[i]);
		if (ret)
			return ret;
	}
	for (size_t i = 0; i < ARRAY_SIZE(regs); i++) {
		ret = rtl_write8_checked(d, regs[i], values[i]);
		if (ret)
			goto restore;
		ret = rtl_read8_checked(d, regs[i], &value);
		if (ret || value != values[i]) {
			ret = ret ? ret : -EIO;
			goto restore;
		}
	}

	/* Last write forces USB re-enumeration. */
	ret = rtl_write8_checked(d, REG_SYS_PW_CTRL + 1, 0x80);
	return ret ? ret : 1;

restore:
	for (size_t i = 0; i < ARRAY_SIZE(regs); i++)
		if (rtl_write8_checked(d, regs[i], saved[i]))
			fprintf(stderr, "warning: failed to restore USB mode register 0x%02x\n",
				(unsigned)regs[i]);
	return ret;
}

/* Center channel and secondary-channel index for a primary channel and width,
 * following rtw_update_channel()/rtw_get_channel_params() in rtw88 main.c.
 */
static int channel_plan(u8 primary, u8 bw, u8 *center, u8 *sc_idx, bool upper40)
{
	if (!rtl_channel_is_supported(primary))
		return -EINVAL;
	*center = primary;
	*sc_idx = RTW_SC_DONT_CARE;
	if (bw == RTW_CHANNEL_WIDTH_20)
		return 0;

	if (primary <= 14) {			/* 2.4 GHz: 40 MHz only */
		if (bw != RTW_CHANNEL_WIDTH_40)
			return -EINVAL;
		*center = upper40 ? primary + 2 : primary - 2;
		*sc_idx = upper40 ? RTW_SC_20_LOWER : RTW_SC_20_UPPER;
		return (*center < 1 || *center > 14) ? -EINVAL : 0;
	}

	if (bw == RTW_CHANNEL_WIDTH_40) {
		int base = primary >= 149 ? 149 : (primary >= 100 ? 100 : 36);
		int lower = base + ((primary - base) / 8) * 8;

		*center = lower + 2;
		*sc_idx = primary == lower ? RTW_SC_20_LOWER : RTW_SC_20_UPPER;
		return 0;
	}
	if (bw == RTW_CHANNEL_WIDTH_80) {
		static const u8 bases[] = { 36, 52, 100, 116, 132, 149 };
		int base = 0;

		for (unsigned i = 0; i < sizeof(bases); i++)
			if (primary >= bases[i] && primary <= bases[i] + 12)
				base = bases[i];
		if (!base)
			return -EINVAL;
		*center = base + 6;
		if (primary > *center)
			*sc_idx = primary - *center == 2 ? RTW_SC_20_UPPER : RTW_SC_20_UPMOST;
		else
			*sc_idx = *center - primary == 2 ? RTW_SC_20_LOWER : RTW_SC_20_LOWEST;
		return 0;
	}
	return -EINVAL;
}

/* rtw_update_channel + rtw_set_channel */
int rtl_set_channel_bw(struct rtw_dev *d, u8 primary, u8 bw, bool upper40)
{
	struct rtw_hal *hal = &d->hal;
	u8 center, sc_idx;
	int ret = channel_plan(primary, bw, &center, &sc_idx, upper40);

	if (ret) {
		fprintf(stderr, "unsupported channel/width combination: %u / %u\n", primary, bw);
		return ret;
	}

	hal->cch_by_bw[RTW_CHANNEL_WIDTH_20] = primary;
	hal->cch_by_bw[bw] = center;
	if (bw == RTW_CHANNEL_WIDTH_80)
		hal->cch_by_bw[RTW_CHANNEL_WIDTH_40] =
			primary > center ? center + 4 : center - 4;
	hal->current_primary_channel_index = sc_idx;
	hal->current_band_width = bw;
	hal->primary_channel = primary;
	hal->current_channel = center;
	hal->current_band_type = center > 14 ? RTW_BAND_5G : RTW_BAND_2G;
	d->dm_info.tx_rate = primary > 14 ? DESC_RATE6M : DESC_RATE1M;

	d->chip->ops->set_channel(d, center, bw, sc_idx);
	rtw_phy_set_tx_power_level(d, center);
	d->need_rfk = true;
	return 0;
}

int rtl_set_channel(struct rtw_dev *d, u8 channel, u8 bw)
{
	return rtl_set_channel_bw(d, channel, bw, true);
}

/* rtw_chip_prepare_tx: run RF calibration once after a channel change */
void rtl_prepare_rfk(struct rtw_dev *d)
{
	if (d->need_rfk) {
		d->need_rfk = false;
		d->chip->ops->phy_calibration(d);
	}
}

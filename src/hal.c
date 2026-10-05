// SPDX-License-Identifier: BSD-3-Clause
/* Hardware bring-up orchestration for the RTL8814AU: follows rtw88 rtw_power_on()
 * (main.c, GPL-2.0 OR BSD-3-Clause, Copyright(c) Realtek Corporation).
 */
#include "rtl8814au.h"
#include "rtw/mac.h"

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

/* rtw_update_channel (20 MHz only for now) + rtw_set_channel */
int rtl_set_channel(struct rtw_dev *d, u8 channel, u8 bw)
{
	struct rtw_hal *hal = &d->hal;
	u8 band = channel > 14 ? RTW_BAND_5G : RTW_BAND_2G;

	if (bw != RTW_CHANNEL_WIDTH_20) {
		fprintf(stderr, "only 20 MHz is supported for now\n");
		return -EINVAL;
	}

	hal->cch_by_bw[RTW_CHANNEL_WIDTH_20] = channel;
	hal->current_primary_channel_index = RTW_SC_DONT_CARE;
	hal->current_band_width = bw;
	hal->primary_channel = channel;
	hal->current_channel = channel;
	hal->current_band_type = band;

	d->chip->ops->set_channel(d, channel, bw, hal->current_primary_channel_index);
	rtw_phy_set_tx_power_level(d, channel);
	d->need_rfk = true;
	return 0;
}

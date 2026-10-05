// SPDX-License-Identifier: BSD-3-Clause
/* RTL8814A MAC power control and efuse. Ported from rtw88 mac.c / efuse.c
 * (GPL-2.0 OR BSD-3-Clause), Copyright(c) 2018-2019 Realtek Corporation.
 */
#include "rtl8814au.h"

static bool poll8(struct rtw_dev *d, u32 addr, u8 mask, u8 target)
{
	target &= mask;
	for (int i = 0; i < RTW_PWR_POLLING_CNT; i++) {
		if ((rtw_read8(d, addr) & mask) == target)
			return true;
		usleep(50);
	}
	return false;
}

static int run_sub_seq(struct rtw_dev *d, u8 cut_mask, const struct rtw_pwr_seq_cmd *cmd)
{
	for (const struct rtw_pwr_seq_cmd *c = cmd; c->cmd != RTW_PWR_CMD_END; c++) {
		u8 v;

		if (!(c->intf_mask & RTW_PWR_INTF_USB_MSK) || !(c->cut_mask & cut_mask))
			continue;

		switch (c->cmd) {
		case RTW_PWR_CMD_WRITE:
			v = rtw_read8(d, c->offset);
			v &= ~c->mask;
			v |= c->value & c->mask;
			rtw_write8(d, c->offset, v);
			break;
		case RTW_PWR_CMD_POLLING:
			if (!poll8(d, c->offset, c->mask, c->value)) {
				fprintf(stderr, "power seq poll failed: reg 0x%x mask 0x%x val 0x%x\n",
					c->offset, c->mask, c->value);
				return -EBUSY;
			}
			break;
		case RTW_PWR_CMD_DELAY:
			usleep(c->value == RTW_PWR_DELAY_US ? c->offset : c->offset * 1000);
			break;
		case RTW_PWR_CMD_READ:
			break;
		default:
			return -EINVAL;
		}
	}
	return 0;
}

static int run_seq(struct rtw_dev *d, const struct rtw_pwr_seq_cmd * const *seq)
{
	u8 cut_mask = BIT(d->hal.cut_version + 1);	/* cut A -> RTW_PWR_CUT_A_MSK */

	for (; *seq; seq++) {
		int ret = run_sub_seq(d, cut_mask, *seq);

		if (ret)
			return ret;
	}
	return 0;
}

/* rtw_chip_parameter_setup (USB) */
int rtl_read_chip_info(struct rtw_dev *d)
{
	struct rtw_hal *hal = &d->hal;
	struct rtw_efuse *efuse = &d->efuse;
	const struct rtw_chip_info *chip = &rtw8814a_hw_spec;

	d->chip = chip;
	d->hci.type = RTW_HCI_TYPE_USB;
	d->hci.bulkout_num = d->num_out_ep;
	d->hci.rpwm_addr = 0xfe58;
	d->hci.cpwm_addr = 0xfe57;
	/* Use the conservative worldwide power table until the caller selects a region. */
	hal->txpwr_regd = RTW_REGD_WW;

	hal->chip_version = rtw_read32(d, REG_SYS_CFG1);
	hal->cut_version = BIT_GET_CHIP_VER(hal->chip_version);
	hal->mp_chip = (hal->chip_version & BIT_RTL_ID) ? 0 : 1;
	if (hal->chip_version & BIT_RF_TYPE_ID) {
		hal->rf_type = RF_2T2R;
		hal->rf_path_num = 2;
		hal->antenna_tx = BB_PATH_AB;
		hal->antenna_rx = BB_PATH_AB;
	} else {
		hal->rf_type = RF_1T1R;
		hal->rf_path_num = 1;
		hal->antenna_tx = BB_PATH_A;
		hal->antenna_rx = BB_PATH_A;
	}
	hal->rf_phy_num = chip->fix_rf_phy_num ? chip->fix_rf_phy_num : hal->rf_path_num;

	efuse->physical_size = chip->phy_efuse_size;
	efuse->logical_size = chip->log_efuse_size;
	efuse->protect_size = chip->ptct_efuse_size;
	hal->rcr |= BIT_VHT_DACK;
	hal->bfee_sts_cap = 3;
	return 0;
}

/* Pre-power-on pin mux and BB/RF disable (rtw_mac_pre_system_cfg, USB path). */
static void pre_system_cfg(struct rtw_dev *d)
{
	u32 v32;
	u8 v8;

	rtw_write8(d, REG_RSV_CTRL, 0);

	v32 = rtw_read32(d, REG_PAD_CTRL1);
	rtw_write32(d, REG_PAD_CTRL1, v32 | BIT_PAPE_WLBT_SEL | BIT_LNAON_WLBT_SEL);

	v32 = rtw_read32(d, REG_LED_CFG);
	rtw_write32(d, REG_LED_CFG, v32 & ~(BIT_PAPE_SEL_EN | BIT_LNAON_SEL_EN));

	v32 = rtw_read32(d, REG_GPIO_MUXCFG);
	rtw_write32(d, REG_GPIO_MUXCFG, v32 | BIT_WLRFE_4_5_EN);

	v8 = rtw_read8(d, REG_SYS_FUNC_EN);
	rtw_write8(d, REG_SYS_FUNC_EN, v8 & ~(BIT_FEN_BB_RSTB | BIT_FEN_BB_GLB_RST));

	v8 = rtw_read8(d, REG_RF_CTRL);
	rtw_write8(d, REG_RF_CTRL, v8 & ~(BIT_RF_SDM_RSTB | BIT_RF_RSTB | BIT_RF_EN));

	v32 = rtw_read32(d, REG_WLRF1);
	rtw_write32(d, REG_WLRF1, v32 & ~BIT_WLRF1_BBRF_EN);
}

/* rtw_mac_power_switch + __rtw_mac_init_system_cfg (3081 WCPU variant). */
int rtl_mac_power_on(struct rtw_dev *d)
{
	int ret;

	pre_system_cfg(d);

	/* If the MAC is already powered (CR != 0xea), cycle it off first. */
	if (rtw_read8(d, REG_CR) != 0xea) {
		run_seq(d, d->chip->pwr_off_seq);
		pre_system_cfg(d);
	}

	ret = run_seq(d, d->chip->pwr_on_seq);
	if (ret) {
		fprintf(stderr, "mac power on failed\n");
		return ret;
	}

	/* __rtw_mac_init_system_cfg */
	rtw_write32_set(d, REG_CPU_DMEM_CON, BIT_WL_PLATFORM_RST | BIT_DDMA_EN);
	rtw_write8_set(d, REG_SYS_FUNC_EN + 1, d->chip->sys_func_en);
	rtw_write8(d, REG_CR_EXT + 3, (rtw_read8(d, REG_CR_EXT + 3) & 0xF0) | 0x0C);

	/* disable boot-from-flash for driver's firmware download */
	{
		u32 t = rtw_read32(d, REG_MCUFW_CTRL);

		if (t & BIT_BOOT_FSPI_EN) {
			rtw_write32(d, REG_MCUFW_CTRL, t & ~BIT_BOOT_FSPI_EN);
			rtw_write32_clr(d, REG_GPIO_MUXCFG, BIT_FSPI_EN);
		}
	}
	return 0;
}

void rtl_mac_power_off(struct rtw_dev *d)
{
	run_seq(d, d->chip->pwr_off_seq);
}

/* ---- efuse ---- */
#define RTW_MAX_PHY_EFUSE 1024
#define RTW_MAX_LOG_EFUSE 512
#define invalid_efuse_header(h1, h2) \
	((h1) == 0xff || (((h1) & 0x1f) == 0xf && (h2) == 0xff))

static int dump_physical_efuse(struct rtw_dev *d, u8 *map, u32 size)
{
	u32 ctl, addr;

	d->chip->ops->efuse_grant(d, true);

	/* bank 0 (wifi) */
	rtw_write32_clr(d, REG_LDO_EFUSE_CTRL, BIT_MASK_EFUSE_BANK_SEL);

	ctl = rtw_read32(d, REG_EFUSE_CTRL);
	for (addr = 0; addr < size; addr++) {
		int cnt = 1000000;

		ctl &= ~(BIT_MASK_EF_DATA | (BIT_MASK_EF_ADDR << BIT_SHIFT_EF_ADDR));
		ctl |= (addr & BIT_MASK_EF_ADDR) << BIT_SHIFT_EF_ADDR;
		rtw_write32(d, REG_EFUSE_CTRL, ctl & ~BIT_EF_FLAG);

		do {
			usleep(1);
			ctl = rtw_read32(d, REG_EFUSE_CTRL);
			if (--cnt == 0)
				return -EBUSY;
		} while (!(ctl & BIT_EF_FLAG));

		map[addr] = ctl & BIT_MASK_EF_DATA;
	}

	d->chip->ops->efuse_grant(d, false);
	return 0;
}

static int decode_logical_efuse(const u8 *phy, u32 phy_size, u8 *log, u32 log_size)
{
	u32 pi = 0;

	while (pi < phy_size) {
		u8 h1 = phy[pi], h2 = phy[pi + 1], word_en;
		u32 blk;

		if (invalid_efuse_header(h1, h2))
			break;

		if ((h1 & 0x1f) == 0xf) {
			blk = ((h2 & 0xf0) >> 1) | ((h1 >> 5) & 0x07);
			word_en = h2 & 0xf;
			pi += 2;
		} else {
			blk = (h1 & 0xf0) >> 4;
			word_en = h1 & 0xf;
			pi += 1;
		}

		for (int i = 0; i < 4; i++) {
			u32 li;

			if (word_en & BIT(i))
				continue;
			li = (blk << 3) + (i << 1);
			if (pi + 1 >= phy_size || li + 1 >= log_size)
				return -EINVAL;
			log[li] = phy[pi];
			log[li + 1] = phy[pi + 1];
			pi += 2;
		}
	}
	return 0;
}

/* rtw_parse_efuse_map + rtw_chip_efuse_info_setup fixups */
int rtl_read_efuse(struct rtw_dev *d)
{
	struct rtw_efuse *efuse = &d->efuse;
	u8 phy[RTW_MAX_PHY_EFUSE];
	u8 log[RTW_MAX_LOG_EFUSE];
	int ret;

	ret = dump_physical_efuse(d, phy, efuse->physical_size);
	if (ret)
		return ret;

	memset(log, 0xff, sizeof(log));
	ret = decode_logical_efuse(phy, efuse->physical_size, log, efuse->logical_size);
	if (ret)
		return ret;

	ret = d->chip->ops->read_efuse(d, log);
	if (ret)
		return ret;

	if (efuse->rfe_option == 0xff)
		efuse->rfe_option = 0;
	if (efuse->crystal_cap == 0xff)
		efuse->crystal_cap = 0;
	if (efuse->pa_type_2g == 0xff)
		efuse->pa_type_2g = 0;
	if (efuse->pa_type_5g == 0xff)
		efuse->pa_type_5g = 0;
	if (efuse->lna_type_2g == 0xff)
		efuse->lna_type_2g = 0;
	if (efuse->lna_type_5g == 0xff)
		efuse->lna_type_5g = 0;
	if (efuse->channel_plan == 0xff)
		efuse->channel_plan = 0x7f;
	if (efuse->rf_board_option == 0xff)
		efuse->rf_board_option = 0;
	if (efuse->regd == 0xff)
		efuse->regd = 0;
	if (efuse->tx_bb_swing_setting_2g == 0xff)
		efuse->tx_bb_swing_setting_2g = 0;
	if (efuse->tx_bb_swing_setting_5g == 0xff)
		efuse->tx_bb_swing_setting_5g = 0;

	efuse->btcoex = (efuse->rf_board_option & 0xe0) == 0x20;
	efuse->ext_pa_2g = efuse->pa_type_2g & BIT(4) ? 1 : 0;
	efuse->ext_lna_2g = efuse->lna_type_2g & BIT(3) ? 1 : 0;
	efuse->ext_pa_5g = efuse->pa_type_5g & BIT(0) ? 1 : 0;
	efuse->ext_lna_5g = efuse->lna_type_5g & BIT(3) ? 1 : 0;
	return 0;
}

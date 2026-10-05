// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright(c) 2018-2019  Realtek Corporation
 *
 * MAC initialisation, trimmed from rtw88 mac.c.
 */
#include "main.h"
#include "mac.h"
#include "reg.h"
#include "phy.h"

void rtw_set_channel_mac(struct rtw_dev *rtwdev, u8 channel, u8 bw,
			 u8 primary_ch_idx)
{
	u8 txsc40 = 0, txsc20 = 0;
	u32 value32;
	u8 value8;

	txsc20 = primary_ch_idx;
	if (bw == RTW_CHANNEL_WIDTH_80) {
		if (txsc20 == RTW_SC_20_UPPER || txsc20 == RTW_SC_20_UPMOST)
			txsc40 = RTW_SC_40_UPPER;
		else
			txsc40 = RTW_SC_40_LOWER;
	}
	rtw_write8(rtwdev, REG_DATA_SC,
		   BIT_TXSC_20M(txsc20) | BIT_TXSC_40M(txsc40));

	value32 = rtw_read32(rtwdev, REG_WMAC_TRXPTCL_CTL);
	value32 &= ~BIT_RFMOD;
	switch (bw) {
	case RTW_CHANNEL_WIDTH_80:
		value32 |= BIT_RFMOD_80M;
		break;
	case RTW_CHANNEL_WIDTH_40:
		value32 |= BIT_RFMOD_40M;
		break;
	case RTW_CHANNEL_WIDTH_20:
	default:
		break;
	}
	rtw_write32(rtwdev, REG_WMAC_TRXPTCL_CTL, value32);

	if (rtw_chip_wcpu_8051(rtwdev))
		return;

	value32 = rtw_read32(rtwdev, REG_AFE_CTRL1) & ~(BIT_MAC_CLK_SEL);
	value32 |= (MAC_CLK_HW_DEF_80M << BIT_SHIFT_MAC_CLK_SEL);
	rtw_write32(rtwdev, REG_AFE_CTRL1, value32);

	rtw_write8(rtwdev, REG_USTIME_TSF, MAC_CLK_SPEED);
	rtw_write8(rtwdev, REG_USTIME_EDCA, MAC_CLK_SPEED);

	value8 = rtw_read8(rtwdev, REG_CCK_CHECK);
	value8 = value8 & ~BIT_CHECK_CCK_EN;
	if (IS_CH_5G_BAND(channel))
		value8 |= BIT_CHECK_CCK_EN;
	rtw_write8(rtwdev, REG_CCK_CHECK, value8);
}
EXPORT_SYMBOL(rtw_set_channel_mac);

static int txdma_queue_mapping(struct rtw_dev *rtwdev)
{
	const struct rtw_chip_info *chip = rtwdev->chip;
	const struct rtw_rqpn *rqpn = NULL;
	u16 txdma_pq_map = 0;

	switch (rtw_hci_type(rtwdev)) {
	case RTW_HCI_TYPE_PCIE:
		rqpn = &chip->rqpn_table[1];
		break;
	case RTW_HCI_TYPE_USB:
		if (rtwdev->hci.bulkout_num == 2)
			rqpn = &chip->rqpn_table[2];
		else if (rtwdev->hci.bulkout_num == 3)
			rqpn = &chip->rqpn_table[3];
		else if (rtwdev->hci.bulkout_num == 4)
			rqpn = &chip->rqpn_table[4];
		else
			return -EINVAL;
		break;
	case RTW_HCI_TYPE_SDIO:
		rqpn = &chip->rqpn_table[0];
		break;
	default:
		return -EINVAL;
	}

	rtwdev->fifo.rqpn = rqpn;
	txdma_pq_map |= BIT_TXDMA_HIQ_MAP(rqpn->dma_map_hi);
	txdma_pq_map |= BIT_TXDMA_MGQ_MAP(rqpn->dma_map_mg);
	txdma_pq_map |= BIT_TXDMA_BKQ_MAP(rqpn->dma_map_bk);
	txdma_pq_map |= BIT_TXDMA_BEQ_MAP(rqpn->dma_map_be);
	txdma_pq_map |= BIT_TXDMA_VIQ_MAP(rqpn->dma_map_vi);
	txdma_pq_map |= BIT_TXDMA_VOQ_MAP(rqpn->dma_map_vo);
	rtw_write16(rtwdev, REG_TXDMA_PQ_MAP, txdma_pq_map);

	rtw_write8(rtwdev, REG_CR, 0);
	rtw_write8(rtwdev, REG_CR, MAC_TRX_ENABLE);
	if (rtw_chip_wcpu_3081(rtwdev))
		rtw_write32(rtwdev, REG_H2CQ_CSR, BIT_H2CQ_FULL);

	if (rtw_hci_type(rtwdev) == RTW_HCI_TYPE_USB) {
		rtw_write8_set(rtwdev, REG_TXDMA_PQ_MAP, BIT_RXDMA_ARBBW_EN);
	}

	return 0;
}

int rtw_set_trx_fifo_info(struct rtw_dev *rtwdev)
{
	const struct rtw_chip_info *chip = rtwdev->chip;
	struct rtw_fifo_conf *fifo = &rtwdev->fifo;
	u16 cur_pg_addr;
	u8 csi_buf_pg_num = chip->csi_buf_pg_num;

	/* config rsvd page num */
	fifo->rsvd_drv_pg_num = chip->rsvd_drv_pg_num;
	fifo->txff_pg_num = chip->txff_size / chip->page_size;
	if (rtw_chip_wcpu_8051(rtwdev))
		fifo->rsvd_pg_num = fifo->rsvd_drv_pg_num;
	else
		fifo->rsvd_pg_num = fifo->rsvd_drv_pg_num +
				   RSVD_PG_H2C_EXTRAINFO_NUM +
				   RSVD_PG_H2C_STATICINFO_NUM +
				   RSVD_PG_H2CQ_NUM +
				   RSVD_PG_CPU_INSTRUCTION_NUM +
				   RSVD_PG_FW_TXBUF_NUM +
				   csi_buf_pg_num;

	if (fifo->rsvd_pg_num > fifo->txff_pg_num)
		return -ENOMEM;

	fifo->acq_pg_num = fifo->txff_pg_num - fifo->rsvd_pg_num;
	fifo->rsvd_boundary = fifo->txff_pg_num - fifo->rsvd_pg_num;

	cur_pg_addr = fifo->txff_pg_num;
	if (rtw_chip_wcpu_3081(rtwdev)) {
		cur_pg_addr -= csi_buf_pg_num;
		fifo->rsvd_csibuf_addr = cur_pg_addr;
		cur_pg_addr -= RSVD_PG_FW_TXBUF_NUM;
		fifo->rsvd_fw_txbuf_addr = cur_pg_addr;
		cur_pg_addr -= RSVD_PG_CPU_INSTRUCTION_NUM;
		fifo->rsvd_cpu_instr_addr = cur_pg_addr;
		cur_pg_addr -= RSVD_PG_H2CQ_NUM;
		fifo->rsvd_h2cq_addr = cur_pg_addr;
		cur_pg_addr -= RSVD_PG_H2C_STATICINFO_NUM;
		fifo->rsvd_h2c_sta_info_addr = cur_pg_addr;
		cur_pg_addr -= RSVD_PG_H2C_EXTRAINFO_NUM;
		fifo->rsvd_h2c_info_addr = cur_pg_addr;
	}
	cur_pg_addr -= fifo->rsvd_drv_pg_num;
	fifo->rsvd_drv_addr = cur_pg_addr;

	if (fifo->rsvd_boundary != fifo->rsvd_drv_addr) {
		rtw_err(rtwdev, "wrong rsvd driver address\n");
		return -EINVAL;
	}

	return 0;
}
EXPORT_SYMBOL(rtw_set_trx_fifo_info);

static int __priority_queue_cfg(struct rtw_dev *rtwdev,
				const struct rtw_page_table *pg_tbl,
				u16 pubq_num)
{
	const struct rtw_chip_info *chip = rtwdev->chip;
	struct rtw_fifo_conf *fifo = &rtwdev->fifo;

	rtw_write16(rtwdev, REG_FIFOPAGE_INFO_1, pg_tbl->hq_num);
	rtw_write16(rtwdev, REG_FIFOPAGE_INFO_2, pg_tbl->lq_num);
	rtw_write16(rtwdev, REG_FIFOPAGE_INFO_3, pg_tbl->nq_num);
	rtw_write16(rtwdev, REG_FIFOPAGE_INFO_4, pg_tbl->exq_num);
	rtw_write16(rtwdev, REG_FIFOPAGE_INFO_5, pubq_num);
	rtw_write32_set(rtwdev, REG_RQPN_CTRL_2, BIT_LD_RQPN);

	rtw_write16(rtwdev, REG_FIFOPAGE_CTRL_2, fifo->rsvd_boundary);
	rtw_write8_set(rtwdev, REG_FWHW_TXQ_CTRL + 2, BIT_EN_WR_FREE_TAIL >> 16);

	rtw_write16(rtwdev, REG_BCNQ_BDNY_V1, fifo->rsvd_boundary);
	rtw_write16(rtwdev, REG_FIFOPAGE_CTRL_2 + 2, fifo->rsvd_boundary);
	rtw_write16(rtwdev, REG_BCNQ1_BDNY_V1, fifo->rsvd_boundary);
	rtw_write32(rtwdev, REG_RXFF_BNDY, chip->rxff_size - C2H_PKT_BUF - 1);

	if (rtwdev->hci.type == RTW_HCI_TYPE_USB) {
		rtw_write8_mask(rtwdev, REG_AUTO_LLT_V1, BIT_MASK_BLK_DESC_NUM,
				chip->usb_tx_agg_desc_num);

		rtw_write8(rtwdev, REG_AUTO_LLT_V1 + 3, chip->usb_tx_agg_desc_num);
		rtw_write8_set(rtwdev, REG_TXDMA_OFFSET_CHK + 1, BIT(1));
	}

	rtw_write8_set(rtwdev, REG_AUTO_LLT_V1, BIT_AUTO_INIT_LLT_V1);

	if (!check_hw_ready(rtwdev, REG_AUTO_LLT_V1, BIT_AUTO_INIT_LLT_V1, 0))
		return -EBUSY;

	rtw_write8(rtwdev, REG_CR + 3, 0);

	return 0;
}

static int __priority_queue_cfg_legacy(struct rtw_dev *rtwdev,
				       const struct rtw_page_table *pg_tbl,
				       u16 pubq_num)
{
	const struct rtw_chip_info *chip = rtwdev->chip;
	struct rtw_fifo_conf *fifo = &rtwdev->fifo;
	u32 val32;

	val32 = BIT_RQPN_NE(pg_tbl->nq_num, pg_tbl->exq_num);
	rtw_write32(rtwdev, REG_RQPN_NPQ, val32);
	val32 = BIT_RQPN_HLP(pg_tbl->hq_num, pg_tbl->lq_num, pubq_num);
	rtw_write32(rtwdev, REG_RQPN, val32);

	rtw_write8(rtwdev, REG_TRXFF_BNDY, fifo->rsvd_boundary);
	rtw_write16(rtwdev, REG_TRXFF_BNDY + 2, chip->rxff_size - REPORT_BUF - 1);
	rtw_write8(rtwdev, REG_DWBCN0_CTRL + 1, fifo->rsvd_boundary);
	rtw_write8(rtwdev, REG_BCNQ_BDNY, fifo->rsvd_boundary);
	rtw_write8(rtwdev, REG_MGQ_BDNY, fifo->rsvd_boundary);
	rtw_write8(rtwdev, REG_WMAC_LBK_BF_HD, fifo->rsvd_boundary);

	rtw_write32_set(rtwdev, REG_AUTO_LLT, BIT_AUTO_INIT_LLT);

	if (!check_hw_ready(rtwdev, REG_AUTO_LLT, BIT_AUTO_INIT_LLT, 0))
		return -EBUSY;

	return 0;
}

static int priority_queue_cfg(struct rtw_dev *rtwdev)
{
	const struct rtw_chip_info *chip = rtwdev->chip;
	struct rtw_fifo_conf *fifo = &rtwdev->fifo;
	const struct rtw_page_table *pg_tbl = NULL;
	u16 pubq_num;
	int ret;

	ret = rtw_set_trx_fifo_info(rtwdev);
	if (ret)
		return ret;

	switch (rtw_hci_type(rtwdev)) {
	case RTW_HCI_TYPE_PCIE:
		pg_tbl = &chip->page_table[1];
		break;
	case RTW_HCI_TYPE_USB:
		if (rtwdev->hci.bulkout_num == 2)
			pg_tbl = &chip->page_table[2];
		else if (rtwdev->hci.bulkout_num == 3)
			pg_tbl = &chip->page_table[3];
		else if (rtwdev->hci.bulkout_num == 4)
			pg_tbl = &chip->page_table[4];
		else
			return -EINVAL;
		break;
	case RTW_HCI_TYPE_SDIO:
		pg_tbl = &chip->page_table[0];
		break;
	default:
		return -EINVAL;
	}

	pubq_num = fifo->acq_pg_num - pg_tbl->hq_num - pg_tbl->lq_num -
		   pg_tbl->nq_num - pg_tbl->exq_num - pg_tbl->gapq_num;
	if (rtw_chip_wcpu_8051(rtwdev))
		return __priority_queue_cfg_legacy(rtwdev, pg_tbl, pubq_num);
	else
		return __priority_queue_cfg(rtwdev, pg_tbl, pubq_num);
}

static int init_h2c(struct rtw_dev *rtwdev)
{
	struct rtw_fifo_conf *fifo = &rtwdev->fifo;
	u8 value8;
	u32 value32;
	u32 h2cq_addr;
	u32 h2cq_size;
	u32 h2cq_free;
	u32 wp, rp;

	if (rtw_chip_wcpu_8051(rtwdev))
		return 0;

	h2cq_addr = fifo->rsvd_h2cq_addr << TX_PAGE_SIZE_SHIFT;
	h2cq_size = RSVD_PG_H2CQ_NUM << TX_PAGE_SIZE_SHIFT;

	value32 = rtw_read32(rtwdev, REG_H2C_HEAD);
	value32 = (value32 & 0xFFFC0000) | h2cq_addr;
	rtw_write32(rtwdev, REG_H2C_HEAD, value32);

	value32 = rtw_read32(rtwdev, REG_H2C_READ_ADDR);
	value32 = (value32 & 0xFFFC0000) | h2cq_addr;
	rtw_write32(rtwdev, REG_H2C_READ_ADDR, value32);

	value32 = rtw_read32(rtwdev, REG_H2C_TAIL);
	value32 &= 0xFFFC0000;
	value32 |= (h2cq_addr + h2cq_size);
	rtw_write32(rtwdev, REG_H2C_TAIL, value32);

	value8 = rtw_read8(rtwdev, REG_H2C_INFO);
	value8 = (u8)((value8 & 0xFC) | 0x01);
	rtw_write8(rtwdev, REG_H2C_INFO, value8);

	value8 = rtw_read8(rtwdev, REG_H2C_INFO);
	value8 = (u8)((value8 & 0xFB) | 0x04);
	rtw_write8(rtwdev, REG_H2C_INFO, value8);

	value8 = rtw_read8(rtwdev, REG_TXDMA_OFFSET_CHK + 1);
	value8 = (u8)((value8 & 0x7f) | 0x80);
	rtw_write8(rtwdev, REG_TXDMA_OFFSET_CHK + 1, value8);

	wp = rtw_read32(rtwdev, REG_H2C_PKT_WRITEADDR) & 0x3FFFF;
	rp = rtw_read32(rtwdev, REG_H2C_PKT_READADDR) & 0x3FFFF;
	h2cq_free = wp >= rp ? h2cq_size - (wp - rp) : rp - wp;

	if (h2cq_size != h2cq_free) {
		rtw_err(rtwdev, "H2C queue mismatch\n");
		return -EINVAL;
	}

	return 0;
}

static int rtw_init_trx_cfg(struct rtw_dev *rtwdev)
{
	int ret;

	ret = txdma_queue_mapping(rtwdev);
	if (ret)
		return ret;

	ret = priority_queue_cfg(rtwdev);
	if (ret)
		return ret;

	ret = init_h2c(rtwdev);
	if (ret)
		return ret;

	return 0;
}

static int rtw_drv_info_cfg(struct rtw_dev *rtwdev)
{
	u8 value8;

	rtw_write8(rtwdev, REG_RX_DRVINFO_SZ, PHY_STATUS_SIZE);
	if (rtw_chip_wcpu_3081(rtwdev)) {
		value8 = rtw_read8(rtwdev, REG_TRXFF_BNDY + 1);
		value8 &= 0xF0;
		/* For rxdesc len = 0 issue */
		value8 |= 0xF;
		rtw_write8(rtwdev, REG_TRXFF_BNDY + 1, value8);
	}
	rtw_write32_set(rtwdev, REG_RCR, BIT_APP_PHYSTS);
	rtw_write32_clr(rtwdev, REG_WMAC_OPTION_FUNCTION + 4, BIT(8) | BIT(9));

	return 0;
}

int rtw_mac_init(struct rtw_dev *rtwdev)
{
	const struct rtw_chip_info *chip = rtwdev->chip;
	int ret;

	ret = rtw_init_trx_cfg(rtwdev);
	if (ret)
		return ret;

	ret = chip->ops->mac_init(rtwdev);
	if (ret)
		return ret;

	ret = rtw_drv_info_cfg(rtwdev);
	if (ret)
		return ret;

	rtw_hci_interface_cfg(rtwdev);

	return 0;
}


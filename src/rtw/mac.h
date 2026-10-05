/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Copyright(c) 2018-2019  Realtek Corporation. Constants from rtw88 mac.h. */
#ifndef __RTW_MAC_H__
#define __RTW_MAC_H__

#define cut_version_to_mask(cut) (0x1 << ((cut) + 1))
#define DDMA_POLLING_COUNT	1000
#define C2H_PKT_BUF		256
#define REPORT_BUF		128
#define PHY_STATUS_SIZE		4
#define ILLEGAL_KEY_GROUP	0xFAAAAA00
#define OCPBASE_RXBUF_FW_88XX		0x18680000
#define OCPBASE_TXBUF_88XX		0x18780000
#define OCPBASE_ROM_88XX		0x00000000
#define OCPBASE_IMEM_88XX		0x00030000
#define OCPBASE_DMEM_88XX		0x00200000
#define OCPBASE_EMEM_88XX		0x00100000
#define RSVD_PG_DRV_NUM			16
#define RSVD_PG_H2C_EXTRAINFO_NUM	24
#define RSVD_PG_H2C_STATICINFO_NUM	8
#define RSVD_PG_H2CQ_NUM		8
#define RSVD_PG_CPU_INSTRUCTION_NUM	0
#define RSVD_PG_FW_TXBUF_NUM		4

int rtw_mac_init(struct rtw_dev *rtwdev);
int rtw_set_trx_fifo_info(struct rtw_dev *rtwdev);
void rtw_set_channel_mac(struct rtw_dev *rtwdev, u8 channel, u8 bw, u8 primary_ch_idx);
void rtw_hci_interface_cfg(struct rtw_dev *rtwdev);

#endif

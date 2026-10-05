/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Copyright(c) 2018-2019  Realtek Corporation. RX descriptor layout from rtw88 rx.h. */
#ifndef __RTW_RX_H_
#define __RTW_RX_H_

enum rtw_rx_desc_enc {
	RX_DESC_ENC_NONE	= 0,
	RX_DESC_ENC_WEP40	= 1,
	RX_DESC_ENC_TKIP_WO_MIC	= 2,
	RX_DESC_ENC_TKIP_MIC	= 3,
	RX_DESC_ENC_AES		= 4,
	RX_DESC_ENC_WEP104	= 5,
};

struct rtw_rx_desc {
	__le32 w0;
	__le32 w1;
	__le32 w2;
	__le32 w3;
	__le32 w4;
	__le32 w5;
} __packed;

#define RTW_RX_DESC_W0_PKT_LEN		GENMASK(13, 0)
#define RTW_RX_DESC_W0_CRC32		BIT(14)
#define RTW_RX_DESC_W0_ICV_ERR		BIT(15)
#define RTW_RX_DESC_W0_DRV_INFO_SIZE	GENMASK(19, 16)
#define RTW_RX_DESC_W0_ENC_TYPE		GENMASK(22, 20)
#define RTW_RX_DESC_W0_SHIFT		GENMASK(25, 24)
#define RTW_RX_DESC_W0_PHYST		BIT(26)
#define RTW_RX_DESC_W0_SWDEC		BIT(27)
#define RTW_RX_DESC_W0_EOR		BIT(30)
#define RTW_RX_DESC_W0_OWN		BIT(31)
#define RTW_RX_DESC_W1_MACID		GENMASK(6, 0)
#define RTW_RX_DESC_W2_C2H		BIT(28)
#define RTW_RX_DESC_W2_PPDU_CNT		GENMASK(30, 29)
#define RTW_RX_DESC_W3_RX_RATE		GENMASK(6, 0)
#define RTW_RX_DESC_W4_BW		GENMASK(5, 4)
#define RTW_RX_DESC_W5_TSFL		GENMASK(31, 0)

#endif

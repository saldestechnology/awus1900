/* SPDX-License-Identifier: BSD-3-Clause */
/* RTL8814AU userspace driver: public interface. Register names and structures come from the
 * rtw88-derived shim in rtw/ (GPL-2.0 OR BSD-3-Clause, Copyright(c) Realtek Corporation).
 */
#ifndef RTL8814AU_H
#define RTL8814AU_H

#include "rtw/main.h"
#include "rtw/reg.h"
#include "rtw/tx.h"
#include "rtw/phy.h"
#include "rtw/rtw8814a.h"
#include "rtw/rtw8814a_table.h"

#define FW_HDR_SIZE		64
#define FW_HDR_CHKSUM_SIZE	8
#define OCPBASE_TXBUF_88XX	0x18780000
#define OCPBASE_DMEM_88XX	0x00200000
#define TX_DESC_SIZE_8814A	40
#define SYS_FUNC_EN_8814A	0xDC
#define ILLEGAL_KEY_GROUP	0xFAAAAA00

/* dev.c */
int  rtl_open(struct rtw_dev *d, u16 vid, u16 pid);
void rtl_close(struct rtw_dev *d);
int  rtl_write_block(struct rtw_dev *d, u32 addr, const void *buf, u16 len);
int  rtl_bulk_out(struct rtw_dev *d, int qsel_ep, const void *buf, int len, int timeout_ms);

/* mac.c */
int  rtl_mac_power_on(struct rtw_dev *d);
void rtl_mac_power_off(struct rtw_dev *d);
int  rtl_read_chip_info(struct rtw_dev *d);
int  rtl_read_efuse(struct rtw_dev *d);

/* fw.c */
int rtl_download_firmware(struct rtw_dev *d, const char *path);

/* hal.c */
int  rtl_hw_init(struct rtw_dev *d, const char *fw_path);
int  rtl_set_channel(struct rtw_dev *d, u8 channel, u8 bw);

#endif

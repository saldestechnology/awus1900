// SPDX-License-Identifier: BSD-3-Clause
/* RTL8814A firmware download (3081 WCPU, DDMA path). Ported from rtw88 mac.c / fw.c / tx.c / usb.c
 * (GPL-2.0 OR BSD-3-Clause), Copyright(c) 2018-2019 Realtek Corporation.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "rtl8814au.h"

static u32 le32(const u8 *p) { return p[0] | p[1] << 8 | p[2] << 16 | (u32)p[3] << 24; }

static bool hw_ready(struct rtw_dev *d, u32 addr, u32 mask, u32 target)
{
	for (int i = 0; i < 1000; i++) {
		if ((rtw_read32(d, addr) & mask) == target)
			return true;
		usleep(10);
	}
	return false;
}

static void cpu_enable(struct rtw_dev *d, bool en)
{
	if (en) {
		rtw_write8_set(d, REG_RSV_CTRL + 1, BIT_WLMCU_IOIF);
		rtw_write8_set(d, REG_SYS_FUNC_EN + 1, BIT_FEN_CPUEN);
	} else {
		rtw_write8_clr(d, REG_SYS_FUNC_EN + 1, BIT_FEN_CPUEN);
		rtw_write8_clr(d, REG_RSV_CTRL + 1, BIT_WLMCU_IOIF);
	}
}

struct bckp { u32 reg; u32 val; u8 len; };

static void restore_regs(struct rtw_dev *d, const struct bckp *b, int n)
{
	for (int i = 0; i < n; i++) {
		if (b[i].len == 1)
			rtw_write8(d, b[i].reg, b[i].val);
		else if (b[i].len == 2)
			rtw_write16(d, b[i].reg, b[i].val);
		else
			rtw_write32(d, b[i].reg, b[i].val);
	}
}

#define NBCKP 6

static void dl_backup_and_setup(struct rtw_dev *d, struct bckp *b)
{
	u8 tmp;
	int n = 0;

	/* HIQ to high priority */
	b[n++] = (struct bckp){ REG_TXDMA_PQ_MAP + 1, rtw_read8(d, REG_TXDMA_PQ_MAP + 1), 1 };
	rtw_write8(d, REG_TXDMA_PQ_MAP + 1, RTW_DMA_MAPPING_HIGH << 6);

	/* DLFW only uses HIQ */
	b[n++] = (struct bckp){ REG_CR, rtw_read8(d, REG_CR), 1 };
	b[n++] = (struct bckp){ REG_H2CQ_CSR, BIT_H2CQ_FULL, 4 };
	rtw_write8(d, REG_CR, BIT_HCI_TXDMA_EN | BIT_TXDMA_EN);
	rtw_write32(d, REG_H2CQ_CSR, BIT_H2CQ_FULL);

	/* HIQ and public queue page numbers */
	b[n++] = (struct bckp){ REG_FIFOPAGE_INFO_1, rtw_read16(d, REG_FIFOPAGE_INFO_1), 2 };
	b[n++] = (struct bckp){ REG_RQPN_CTRL_2, rtw_read32(d, REG_RQPN_CTRL_2) | BIT_LD_RQPN, 4 };
	rtw_write16(d, REG_FIFOPAGE_INFO_1, 0x200);
	rtw_write32(d, REG_RQPN_CTRL_2, b[n - 1].val);

	/* disable beacon functions */
	tmp = rtw_read8(d, REG_BCN_CTRL);
	b[n++] = (struct bckp){ REG_BCN_CTRL, tmp, 1 };
	rtw_write8(d, REG_BCN_CTRL, (tmp & ~BIT_EN_BCN_FUNCTION) | BIT_DIS_TSF_UDT);
}

static void dl_reset_platform(struct rtw_dev *d)
{
	rtw_write8_clr(d, REG_CPU_DMEM_CON + 2, BIT_WL_PLATFORM_RST >> 16);
	rtw_write8_clr(d, REG_SYS_CLK_CTRL + 1, BIT_CPU_CLK_EN >> 8);
	rtw_write8_set(d, REG_CPU_DMEM_CON + 2, BIT_WL_PLATFORM_RST >> 16);
	rtw_write8_set(d, REG_SYS_CLK_CTRL + 1, BIT_CPU_CLK_EN >> 8);
}

/* Build tx descriptor (40 bytes) for a beacon-queue reserved page and send it on the HIQ bulk pipe. */
static int send_rsvd_page(struct rtw_dev *d, const u8 *data, u32 size)
{
	u8 pkt[TX_DESC_SIZE_8814A + 0x1000 + 1];
	u16 sum = 0;
	u32 w0, w1;
	u32 orig;
	int transferred = 0, rc;

	if (size > 0x1000 || d->num_out_ep < 1)
		return -EINVAL;

	orig = size;
	if (!(((size + 48) & 511)))		/* rtw88: avoid 512-aligned URB without ZLP */
		size += 1;
	if (!(((size + TX_DESC_SIZE_8814A) & 511)))
		size += 1;

	memset(pkt, 0, sizeof(pkt));
	w0 = size | (TX_DESC_SIZE_8814A << 16) | BIT(26);	/* TXPKTSIZE | OFFSET | LS */
	w1 = (u32)TX_DESC_QSEL_BEACON << 8;		/* QSEL */
	for (int i = 0; i < 4; i++) {
		pkt[i] = w0 >> (8 * i);
		pkt[4 + i] = w1 >> (8 * i);
	}
	for (int i = 0; i < 16; i++)			/* checksum over first 32 bytes (w7 field zero) */
		sum ^= pkt[2 * i] | pkt[2 * i + 1] << 8;
	pkt[28] = sum;
	pkt[29] = sum >> 8;

	memcpy(pkt + TX_DESC_SIZE_8814A, data, orig);

	/* HIQ -> first bulk OUT endpoint (dma_mapping_to_ep(HIGH) == 0) */
	rc = libusb_bulk_transfer(d->h, d->out_ep[0], pkt, TX_DESC_SIZE_8814A + size,
				  &transferred, 1000);
	if (rc || transferred != (int)(TX_DESC_SIZE_8814A + size)) {
		fprintf(stderr, "bulk out failed: %s (%d/%u)\n", rc ? libusb_strerror(rc) : "short",
			transferred, TX_DESC_SIZE_8814A + size);
		return -EIO;
	}
	return 0;
}

static int write_rsvd_page(struct rtw_dev *d, u16 pg_addr, const u8 *buf, u32 size)
{
	u8 cr1, bcn;
	int ret = 0;

	bcn = rtw_read8(d, REG_BCN_CTRL);

	pg_addr &= BIT_MASK_BCN_HEAD_1_V1;
	pg_addr |= BIT_BCN_VALID_V1;
	rtw_write16(d, REG_FIFOPAGE_CTRL_2, pg_addr);

	cr1 = rtw_read8(d, REG_CR + 1);
	rtw_write8(d, REG_CR + 1, cr1 | (BIT_ENSWBCN >> 8));
	rtw_write8(d, REG_BCN_CTRL, (bcn & ~BIT_EN_BCN_FUNCTION) | BIT_DIS_TSF_UDT);

	ret = send_rsvd_page(d, buf, size);
	if (!ret && !hw_ready(d, REG_FIFOPAGE_CTRL_2, BIT_BCN_VALID_V1, BIT_BCN_VALID_V1)) {
		fprintf(stderr, "error: beacon valid bit not set\n");
		ret = -EBUSY;
	}

	/* rsvd_boundary is 0 before MAC init */
	rtw_write16(d, REG_FIFOPAGE_CTRL_2, 0 | BIT_BCN_VALID_V1);
	rtw_write8(d, REG_BCN_CTRL, bcn);
	rtw_write8(d, REG_CR + 1, cr1);
	return ret;
}

static int ddma_wait_idle(struct rtw_dev *d)
{
	return hw_ready(d, REG_DDMA_CH0CTRL, BIT_DDMACH0_OWN, 0) ? 0 : -EBUSY;
}

static int ddma_download(struct rtw_dev *d, u32 src, u32 dst, u32 len, bool first)
{
	u32 ctrl = BIT_DDMACH0_CHKSUM_EN | BIT_DDMACH0_OWN;

	if (ddma_wait_idle(d))
		return -EBUSY;
	ctrl |= len & BIT_MASK_DDMACH0_DLEN;
	if (!first)
		ctrl |= BIT_DDMACH0_CHKSUM_CONT;

	rtw_write32(d, REG_DDMA_CH0SA, src);
	rtw_write32(d, REG_DDMA_CH0DA, dst);
	rtw_write32(d, REG_DDMA_CH0CTRL, ctrl);
	return ddma_wait_idle(d);
}

static bool check_fw_checksum(struct rtw_dev *d, u32 addr)
{
	u8 fw_ctrl = rtw_read8(d, REG_MCUFW_CTRL);
	bool imem = addr < OCPBASE_DMEM_88XX;

	if (rtw_read32(d, REG_DDMA_CH0CTRL) & BIT_DDMACH0_CHKSUM_STS) {
		fw_ctrl |= imem ? BIT_IMEM_DW_OK : BIT_DMEM_DW_OK;
		fw_ctrl &= ~(imem ? BIT_IMEM_CHKSUM_OK : BIT_DMEM_CHKSUM_OK);
		rtw_write8(d, REG_MCUFW_CTRL, fw_ctrl);
		fprintf(stderr, "invalid fw checksum (%s)\n", imem ? "imem" : "dmem");
		return false;
	}
	fw_ctrl |= imem ? (BIT_IMEM_DW_OK | BIT_IMEM_CHKSUM_OK) : (BIT_DMEM_DW_OK | BIT_DMEM_CHKSUM_OK);
	rtw_write8(d, REG_MCUFW_CTRL, fw_ctrl);
	return true;
}

static int download_to_mem(struct rtw_dev *d, const u8 *data, u32 dst, u32 size)
{
	const u32 max_size = 0x1000;
	u32 off = 0, residue = size;
	bool first = true;

	rtw_write32_set(d, REG_DDMA_CH0CTRL, BIT_DDMACH0_RESET_CHKSUM_STS);

	while (residue) {
		u32 pkt = residue >= max_size ? max_size : residue;
		int ret = write_rsvd_page(d, 0, data + off, pkt);

		if (ret)
			return ret;
		ret = ddma_download(d, OCPBASE_TXBUF_88XX + 0 + TX_DESC_SIZE_8814A, dst + off, pkt, first);
		if (ret) {
			fprintf(stderr, "ddma failed at offset 0x%x\n", off);
			return ret;
		}
		first = false;
		off += pkt;
		residue -= pkt;
	}
	return check_fw_checksum(d, dst) ? 0 : -EINVAL;
}

static int start_download(struct rtw_dev *d, const u8 *fw, u32 fwsize)
{
	u32 dmem_size = le32(fw + 0x24), imem_size = le32(fw + 0x30);
	u32 emem_size = (fw[0x18] & BIT(4)) ? le32(fw + 0x34) : 0;
	u32 addr;
	u16 val;
	int ret;

	(void)fwsize;
	dmem_size += FW_HDR_CHKSUM_SIZE;
	imem_size += FW_HDR_CHKSUM_SIZE;
	if (emem_size)
		emem_size += FW_HDR_CHKSUM_SIZE;

	val = rtw_read16(d, REG_MCUFW_CTRL) & 0x3800;
	val |= BIT_MCUFWDL_EN;
	rtw_write16(d, REG_MCUFW_CTRL, val);

	addr = le32(fw + 0x20) & ~BIT(31);
	if (d->verbose)
		printf("fw: dmem addr 0x%x size 0x%x\n", addr, dmem_size);
	ret = download_to_mem(d, fw + FW_HDR_SIZE, addr, dmem_size);
	if (ret)
		return ret;

	addr = le32(fw + 0x3c) & ~BIT(31);
	if (d->verbose)
		printf("fw: imem addr 0x%x size 0x%x\n", addr, imem_size);
	ret = download_to_mem(d, fw + FW_HDR_SIZE + dmem_size, addr, imem_size);
	if (ret)
		return ret;

	if (emem_size) {
		addr = le32(fw + 0x38) & ~BIT(31);
		if (d->verbose)
			printf("fw: emem addr 0x%x size 0x%x\n", addr, emem_size);
		ret = download_to_mem(d, fw + FW_HDR_SIZE + dmem_size + imem_size, addr, emem_size);
	}
	return ret;
}

static void end_flow(struct rtw_dev *d)
{
	u16 fw_ctrl;

	rtw_write32(d, REG_TXDMA_STATUS, BTI_PAGE_OVF);
	fw_ctrl = rtw_read16(d, REG_MCUFW_CTRL);
	if ((fw_ctrl & BIT_CHECK_SUM_OK) != BIT_CHECK_SUM_OK)
		return;
	fw_ctrl = (fw_ctrl | BIT_FW_DW_RDY) & ~BIT_MCUFWDL_EN;
	rtw_write16(d, REG_MCUFW_CTRL, fw_ctrl);
}

static u8 *read_file(const char *path, u32 *size)
{
	FILE *f = fopen(path, "rb");
	u8 *buf;
	long n;

	if (!f)
		return NULL;
	fseek(f, 0, SEEK_END);
	n = ftell(f);
	fseek(f, 0, SEEK_SET);
	buf = malloc(n);
	if (buf && fread(buf, 1, n, f) != (size_t)n) {
		free(buf);
		buf = NULL;
	}
	fclose(f);
	*size = n;
	return buf;
}

int rtl_download_firmware(struct rtw_dev *d, const char *path)
{
	struct bckp bckp[NBCKP];
	u32 size, real;
	u8 *fw = read_file(path, &size);
	int ret;

	if (!fw) {
		fprintf(stderr, "cannot read firmware %s\n", path);
		return -ENOENT;
	}

	real = FW_HDR_SIZE + le32(fw + 0x24) + FW_HDR_CHKSUM_SIZE + le32(fw + 0x30) + FW_HDR_CHKSUM_SIZE;
	if (fw[0x18] & BIT(4))
		real += le32(fw + 0x34) + FW_HDR_CHKSUM_SIZE;
	printf("firmware: v%u.%u  %02u-%02u %02u:%02u  size %u (expected %u)\n",
	       fw[4] | fw[5] << 8, fw[6], fw[0x11], fw[0x10], fw[0x12], fw[0x13], size, real);
	if (real != size) {
		fprintf(stderr, "firmware size mismatch\n");
		free(fw);
		return -EINVAL;
	}

	cpu_enable(d, false);
	dl_backup_and_setup(d, bckp);
	dl_reset_platform(d);

	ret = start_download(d, fw, size);
	free(fw);
	if (ret)
		goto fail;

	restore_regs(d, bckp, NBCKP);
	end_flow(d);
	cpu_enable(d, true);

	if (!hw_ready(d, REG_MCUFW_CTRL, FW_READY_MASK, FW_READY)) {
		u32 key = rtw_read32(d, REG_FW_DBG7) & FW_KEY_MASK;

		fprintf(stderr, "firmware did not start: MCUFW_CTRL=0x%08x%s\n",
			rtw_read32(d, REG_MCUFW_CTRL), key == ILLEGAL_KEY_GROUP ? " (invalid fw key)" : "");
		return -EINVAL;
	}
	return 0;

fail:
	restore_regs(d, bckp, NBCKP);
	rtw_write8_clr(d, REG_MCUFW_CTRL, BIT_MCUFWDL_EN);
	rtw_write8_set(d, REG_SYS_FUNC_EN + 1, BIT_FEN_CPUEN);
	return ret;
}

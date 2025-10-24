/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020-2025 NXP
 */

#include <unistd.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include <rte_log.h>
#include <rte_bus.h>
#include <rte_malloc.h>
#include <rte_devargs.h>
#include <rte_memcpy.h>
#include <rte_io.h>
#include <rte_spinlock.h>
#include <linux/pci_regs.h>
#include <bus_fslmc_driver.h>

#include "lsx_pciep_ctrl.h"

#define LSX_PCIE_DW_OB_WINS_NUM        (256)
#define LSX_PCIE_DW_IB_WINS_NUM        (24)

#ifndef __packed
#define __packed	__rte_packed
#endif

#define LSX_PCIE_DW_MSIX_DOOR_BELL_BAR 1

#define LSX_PCIEP_DW_WIN_MASK 0xfff

#define LSX_PCIE_DW_MAX_BAR_SIZE (16 * 1024 * 1024)

#define LSX_PCIE_DW_SHADOW_OFFSET 0x1000

#define LSX_PCIE_DW_IATU_REGION_OFFSET 0x900

#define LSX_PCIE_DW_LUT_REGION_OFFSET 0x80000

#define LSX_PCIE_DW_LUT_VF_CTL_OFFSET 0x407f8

#define LSX_PCIE_DW_LUT_VF_STRIDE 0x8000

enum dw_dbi_access_type {
	DW_DBI_SIMPLE_ACCESS = (0 << 0),
	DW_DBI_SHADOW_ACCESS = (1 << 0),
	DW_DBI_VIEWPORT_ACCESS = (1 << 1)
};

struct pcie_dw_dbi_access {
	enum dw_dbi_access_type access_type;
	int param;
};

union pcie_dw_lut_vf_ctl {
	uint32_t vf_ctl;
	struct {
		uint32_t rsv0:21;
		uint32_t vf_act:1;
		uint32_t vf_num:6;
		uint32_t rsv1:4;
	};
};

enum {
	ADDR_LOW,
	ADDR_UP,
	ADDR_NUM
};

#define PCIE_DW_ATU_VP_REGION_INBOUND		(0x1 << 31)
#define PCIE_DW_ATU_VP_REGION_OUTBOUND	(0x0 << 31)

#define PCIE_DW_ATU_CTL1_FUNC_SHIFT		(20)
#define PCIE_DW_ATU_CTL1_TYPE_MEM			(0x0 << 0)

#define PCIE_DW_ATU_CTL2_EN				(0x1 << 31)
#define PCIE_DW_ATU_CTL2_BAR_MODE_EN	(0x1 << 30)
#define PCIE_DW_ATU_CTL2_FUNC_NUM_MATCH_EN		(0x00080000)
#define PCIE_DW_ATU_CTL2_VFBAR_MATCH_MODE_EN	(0x04000000)
#define PCIE_DW_ATU_CTL2_VF_MATCH_MODE_EN	(0x00100000)
#define PCIE_DW_ATU_CTL2_BAR_NUM(bar)		((bar) << 8)

#define PCIE_DW_ATU_CTL3_VF_ACTIVE_EN		(0x1 << 31)

union pcie_dw_msix_db {
	uint32_t db;
	struct {
		uint32_t vector:11;
		uint32_t rsv0:1;
		uint32_t tc:3;
		uint32_t vf_active:1;
		uint32_t vf:8;
		uint32_t pf:5;
		uint32_t rsv1:3;
	};
};

struct pcie_dw_iatu_region {
	uint32_t view_port;
	union {
		uint32_t ctl1_ib;
		uint32_t ctl1_ob;
	};
	union {
		uint32_t ctl2_ib;
		uint32_t ctl2_ob;
	};
	uint32_t base_addr[ADDR_NUM];
	uint32_t base_limit;
	uint32_t bus_addr[ADDR_NUM];
	union {
		uint32_t ctl3_ib;
		uint32_t ctl3_ob;
	};

	uint32_t rsv[7];
	uint32_t msix_addr_l;
	uint32_t msix_addr_h;
	union pcie_dw_msix_db msix_doorbell;
	uint32_t msix_ram_ctl;
} __packed;

#define PCIE_DW_DBI_WR_DIS 0
#define PCIE_DW_DBI_WR_ENA 1
#define PCIE_DW_MISC_CONTROL_1_OFF_OFFSET 0x8bc

enum dw_win_type {
	DW_OUTBOUND_WIN,
	DW_INBOUND_WIN
};

const uint8_t s_dw_32b_bar_support_id[] = {0, 1, 2, 4};

const uint8_t s_dw_32b_bar_id[] = {0, 1};

#define DW_ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define PCIEP_DW_GLOBE_INFO_F "/tmp/pciep_dw_globe_info"
static rte_spinlock_t s_f_lock = RTE_SPINLOCK_INITIALIZER;
static int s_f_create;

struct pciep_dw_shared_ob_win {
	uint64_t bus_start;
	uint64_t bus_end;
	uint64_t offset;
	int ref_count;
};

struct pciep_dw_priv_ob_win {
	uint64_t phy_start;
	uint64_t phy_size;
	int using;
};

struct pciep_dw_info {
	uint64_t dbi_phy[LSX_MAX_PCIE_NB];
	int ob_win_used[LSX_MAX_PCIE_NB][LSX_PCIE_DW_OB_WINS_NUM];
	int ib_win_used[LSX_MAX_PCIE_NB][LSX_PCIE_DW_IB_WINS_NUM];
	uint64_t ob_base[LSX_MAX_PCIE_NB];
	uint64_t ob_offset[LSX_MAX_PCIE_NB];
	struct pciep_dw_priv_ob_win
		priv_ob_win[LSX_MAX_PCIE_NB][LSX_PCIE_DW_OB_WINS_NUM];
	struct pciep_dw_shared_ob_win
		shared_ob_win[LSX_MAX_PCIE_NB][LSX_PCIE_DW_OB_WINS_NUM];
	uint64_t ob_max_size;
	uint64_t ob_win_max_size;
	uint64_t win_mask;
	uint64_t win_max;
	int shared_ob;
};

struct pciep_dw_proc_info {
	uint64_t ob_start[LSX_PCIE_DW_OB_WINS_NUM];
	int ob_idx[LSX_PCIE_DW_OB_WINS_NUM];
	int ob_nb;

	int ob_shared_idx[LSX_PCIE_DW_OB_WINS_NUM];
	int ob_shared_nb;

	int ib_idx[LSX_PCIE_DW_IB_WINS_NUM];
	int ib_nb;

	uint64_t pf_moff[PF_MAX_NB];
	uint64_t vf_moff[PF_MAX_NB][PCIE_MAX_VF_NUM];
};

#define PCI_EXT_CAP_ID_NULL_OFF 0
#define PCI_EXT_CAP_ID_ERR_OFF 0x100
#define PCI_EXT_CAP_ID_ARI_OFF 0x148
#define PCI_EXT_CAP_ID_SECPCI_OFF 0x158
#define PCI_EXT_CAP_ID_SRIOV_OFF 0x178
#define PCI_EXT_CAP_ID_ATS_OFF 0x1b8

static const struct pcie_ctrl_ext_cap s_pf_reset_ext_cap[] = {
	[PCI_EXT_CAP_ID_ERR_OFF / sizeof(struct pcie_ctrl_ext_cap)] = {
		PCI_EXT_CAP_ID_ERR, 0, PCI_EXT_CAP_ID_ARI_OFF
	},
	[PCI_EXT_CAP_ID_ARI_OFF / sizeof(struct pcie_ctrl_ext_cap)] = {
		PCI_EXT_CAP_ID_ARI, 0, PCI_EXT_CAP_ID_SECPCI_OFF
	},
	[PCI_EXT_CAP_ID_SECPCI_OFF / sizeof(struct pcie_ctrl_ext_cap)] = {
		PCI_EXT_CAP_ID_SECPCI, 0, PCI_EXT_CAP_ID_SRIOV_OFF
	},
	[PCI_EXT_CAP_ID_SRIOV_OFF / sizeof(struct pcie_ctrl_ext_cap)] = {
		PCI_EXT_CAP_ID_SRIOV, 0, PCI_EXT_CAP_ID_ATS_OFF
	},
	[PCI_EXT_CAP_ID_ATS_OFF / sizeof(struct pcie_ctrl_ext_cap)] = {
		PCI_EXT_CAP_ID_ATS, 0, PCI_EXT_CAP_ID_NULL_OFF
	}
};

#define PCI_VF_EXT_CAP_ID_ARI_OFF 0x100

static const struct pcie_ctrl_ext_cap s_vf_reset_ext_cap[] = {
	[PCI_VF_EXT_CAP_ID_ARI_OFF / sizeof(struct pcie_ctrl_ext_cap)] = {
		PCI_EXT_CAP_ID_ARI, 0, PCI_EXT_CAP_ID_NULL_OFF
	}
};

static struct pciep_dw_proc_info g_dw_proc_info[LSX_MAX_PCIE_NB];

#define DWC_OB_PF_INFO_DUMP_FORMAT(pci, pf, \
		phy, bus, size, win) \
		"DWC OB PEX%d PF%d:" \
		"  MEM:0x%" PRIx64 \
		"  PCI:0x%" PRIx64 \
		"  SIZE:0x%" PRIx64 \
		"  WIN:%d", \
		pci, pf, \
		(unsigned long)phy, \
		(unsigned long)bus, \
		(unsigned long)size, \
		win

#define DWC_OB_VF_INFO_DUMP_FORMAT(pci, pf, vf, \
		phy, bus, size, win) \
		"DWC OB PEX%d PF%d-VF%d:" \
		"  MEM:0x%" PRIx64 \
		"  PCI:0x%" PRIx64 \
		"  SIZE:0x%" PRIx64 \
		"  WIN:%d", \
		pci, pf, vf, \
		(unsigned long)phy, \
		(unsigned long)bus, \
		(unsigned long)size, \
		win

#define DWC_IB_PF_INFO_DUMP_FORMAT(pci, pf, \
		phy, bar, size, win) \
		"DWC IB PEX%d PF%d:" \
		"  MEM:0x%" PRIx64 \
		"  bar:%d" \
		"  SIZE:0x%" PRIx64 \
		"  WIN:%d", \
		pci, pf, \
		(unsigned long)phy, \
		bar, \
		(unsigned long)size, \
		win

#define DWC_IB_VF_INFO_DUMP_FORMAT(pci, pf, vf, \
		phy, bar, size, win) \
		"DWC IB PEX%d PF%d-VF%d:" \
		"  MEM:0x%" PRIx64 \
		"  bar:%d" \
		"  SIZE:0x%" PRIx64 \
		"  WIN:%d", \
		pci, pf, vf, \
		(unsigned long)phy, \
		bar, \
		(unsigned long)size, \
		win

#define pcie_dw_malloc malloc
#define pcie_dw_free free

static inline int
pcie_dw_32b_bar_support(uint8_t bar)
{
	size_t i;

	for (i = 0; i < DW_ARRAY_SIZE(s_dw_32b_bar_support_id); i++) {
		if (bar == s_dw_32b_bar_support_id[i])
			return 1;
	}

	return 0;
}

static inline int
pcie_dw_using_32b_bar(uint8_t bar)
{
	size_t i;

	for (i = 0; i < DW_ARRAY_SIZE(s_dw_32b_bar_id); i++) {
		if (bar == s_dw_32b_bar_id[i])
			return 1;
	}

	return 0;
}

static inline void
lsx_pciep_dbi_ro_wr_en(struct lsx_pciep_hw_low *hw)
{
	uint32_t val;
	void *reg = hw->dbi_vir + PCIE_DW_MISC_CONTROL_1_OFF_OFFSET;

	val = rte_read32(reg);
	val |= PCIE_DW_DBI_WR_ENA;
	rte_write32(val, reg);
}

static inline void
lsx_pciep_dbi_ro_wr_dis(struct lsx_pciep_hw_low *hw)
{
	uint32_t val;
	void *reg = hw->dbi_vir + PCIE_DW_MISC_CONTROL_1_OFF_OFFSET;

	val = rte_read32(reg);
	val &= ~PCIE_DW_DBI_WR_ENA;
	rte_write32(val, reg);
}

static void
pcie_dw_vf_control(struct lsx_pciep_hw_low *hw,
	int pf, int vf, int en)
{
	union pcie_dw_lut_vf_ctl vf_ctl;

	vf_ctl.vf_ctl = 0;

	if (en)
		vf_ctl.vf_act = 1;
	else
		vf_ctl.vf_act = 0;

	vf_ctl.vf_num = vf + 1;
	lsx_pciep_write_config(hw->dbi_vir, &vf_ctl.vf_ctl,
		sizeof(uint32_t),
		LSX_PCIE_DW_LUT_REGION_OFFSET +
		LSX_PCIE_DW_LUT_VF_CTL_OFFSET +
		LSX_PCIE_DW_LUT_VF_STRIDE * pf);
}

static int
pcie_dw_read_config_reg(struct lsx_pciep_hw_low *hw,
	int pf, struct pcie_dw_dbi_access access,
	const void *reg, void *buf, size_t len)
{
	int ret, vf = access.param;
	off_t offset = 0;

	if (access.access_type & DW_DBI_VIEWPORT_ACCESS)
		pcie_dw_vf_control(hw, pf, vf, 1);
	if (access.access_type & DW_DBI_SHADOW_ACCESS)
		offset = LSX_PCIE_DW_SHADOW_OFFSET;

	ret = lsx_pciep_read_config(reg, buf, len, offset);

	if (access.access_type & DW_DBI_VIEWPORT_ACCESS)
		pcie_dw_vf_control(hw, pf, vf, 0);

	return ret;
}

static int
pcie_dw_write_config_reg(struct lsx_pciep_hw_low *hw,
	int pf, struct pcie_dw_dbi_access access,
	void *reg, const void *buf, size_t len, int force_w)
{
	int ret, vf = access.param;
	off_t offset = 0;

	if (access.access_type & DW_DBI_VIEWPORT_ACCESS)
		pcie_dw_vf_control(hw, pf, vf, 1);

	if (access.access_type & DW_DBI_SHADOW_ACCESS)
		offset = LSX_PCIE_DW_SHADOW_OFFSET;

	if (force_w)
		lsx_pciep_dbi_ro_wr_en(hw);
	else
		lsx_pciep_dbi_ro_wr_dis(hw);

	ret = lsx_pciep_write_config(reg, buf, len, offset);

	lsx_pciep_dbi_ro_wr_dis(hw);

	if (access.access_type & DW_DBI_VIEWPORT_ACCESS)
		pcie_dw_vf_control(hw, pf, vf, 0);

	return ret;
}

static inline uint16_t
pcie_dw_route_fun_id(int pf, int is_vf, int vf,
	uint16_t pos, uint16_t stride)
{
	if (is_vf)
		return pf + pos + vf * stride;
	else
		return pf;

	return 0;
}

static int
pcie_dw_alloc_win_idx(int pcie_id, enum dw_win_type win_type)
{
	int i, max_nb;
	int *pwin;
	FILE *f_dw_cfg;
	size_t f_ret;
	struct pciep_dw_info *info;

	if (pcie_id >= LSX_MAX_PCIE_NB)
		return -EINVAL;

	rte_spinlock_lock(&s_f_lock);
	f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "rb");
	if (!f_dw_cfg) {
		LSX_PCIEP_BUS_ERR("%s: %s read open failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		rte_spinlock_unlock(&s_f_lock);
		return -ENODEV;
	}

	info = pcie_dw_malloc(sizeof(struct pciep_dw_info));
	if (!info) {
		LSX_PCIEP_BUS_ERR("%s prepare buf for read %s failed",
			__func__,
			PCIEP_DW_GLOBE_INFO_F);
		fclose(f_dw_cfg);
		rte_spinlock_unlock(&s_f_lock);
		return -ENOMEM;
	}

	memset(info, 0, sizeof(struct pciep_dw_info));

	f_ret = fread(info, sizeof(struct pciep_dw_info),
			1, f_dw_cfg);
	fclose(f_dw_cfg);
	if (f_ret != 1) {
		LSX_PCIEP_BUS_ERR("%s: %s read (%ldB) failed (%ld)",
			__func__, PCIEP_DW_GLOBE_INFO_F,
			sizeof(struct pciep_dw_info), f_ret);
		pcie_dw_free(info);
		rte_spinlock_unlock(&s_f_lock);
		return -EIO;
	}

	f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "wb");
	if (!f_dw_cfg) {
		LSX_PCIEP_BUS_ERR("%s: %s write open failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		pcie_dw_free(info);
		rte_spinlock_unlock(&s_f_lock);
		return -ENODEV;
	}

	if (win_type == DW_OUTBOUND_WIN) {
		max_nb = LSX_PCIE_DW_OB_WINS_NUM;
		pwin = &info->ob_win_used[pcie_id][0];
	} else {
		max_nb = LSX_PCIE_DW_IB_WINS_NUM;
		pwin = &info->ib_win_used[pcie_id][0];
	}

	for (i = 0; i < max_nb; i++) {
		if (!pwin[i]) {
			pwin[i] = 1;
			break;
		}
	}

	if (i == max_nb) {
		LSX_PCIEP_BUS_ERR("alloc win index failed");
		fclose(f_dw_cfg);
		pcie_dw_free(info);
		rte_spinlock_unlock(&s_f_lock);
		return -ENODEV;
	}
	f_ret = fwrite(info, sizeof(struct pciep_dw_info),
		1, f_dw_cfg);
	if (f_ret != 1) {
		LSX_PCIEP_BUS_ERR("%s write failed",
			PCIEP_DW_GLOBE_INFO_F);
		fclose(f_dw_cfg);
		pcie_dw_free(info);
		rte_spinlock_unlock(&s_f_lock);
		return -ENODEV;
	}
	fclose(f_dw_cfg);
	pcie_dw_free(info);
	rte_spinlock_unlock(&s_f_lock);

	return i;
}

static uint64_t
pcie_dw_alloc_from_priv_ob(struct pciep_dw_info *info,
	int pcie_id, uint64_t size, int idx)
{
	struct pciep_dw_priv_ob_win *ob_win;
	uint64_t *ob_offset = &info->ob_offset[pcie_id];
	const uint64_t ob_base = info->ob_base[pcie_id];
	const uint64_t ob_max_size = info->ob_max_size;

	ob_win = &info->priv_ob_win[pcie_id][idx];
	if (ob_win->using)
		return 0;

	if (ob_win->phy_size && size <= ob_win->phy_size) {
		ob_win->using = 1;
	} else if (!ob_win->phy_size) {
		if (*ob_offset + size > ob_max_size)
			return 0;

		if (idx > 0) {
			ob_win->phy_size = size;
		} else {
			ob_win->phy_start = ob_base;
			ob_win->phy_size = size;
		}
		*ob_offset += size;
		if (idx < LSX_PCIE_DW_OB_WINS_NUM &&
			(*ob_offset < ob_max_size)) {
			ob_win[1].phy_start =
			ob_win[0].phy_start + size;
		}
		ob_win->using = 1;
	}
	return ob_win->phy_start;
}

static uint64_t
pcie_dw_alloc_ob_space(int pcie_id,
	uint64_t size)
{
	FILE *f_dw_cfg;
	struct pciep_dw_info *info;
	size_t f_ret;
	uint64_t cpu_addr = 0;
	int i;
	char err_str[128];

	rte_spinlock_lock(&s_f_lock);
	f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "rb");
	if (!f_dw_cfg) {
		LSX_PCIEP_BUS_ERR("%s: %s read open failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		rte_spinlock_unlock(&s_f_lock);
		return 0;
	}

	info = pcie_dw_malloc(sizeof(struct pciep_dw_info));
	if (!info) {
		LSX_PCIEP_BUS_ERR("%s prepare buf for read %s failed",
			__func__,
			PCIEP_DW_GLOBE_INFO_F);
		fclose(f_dw_cfg);
		rte_spinlock_unlock(&s_f_lock);
		return 0;
	}

	memset(info, 0, sizeof(struct pciep_dw_info));

	f_ret = fread(info, sizeof(struct pciep_dw_info),
			1, f_dw_cfg);
	fclose(f_dw_cfg);
	if (f_ret != 1) {
		LSX_PCIEP_BUS_ERR("%s: %s read failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		pcie_dw_free(info);
		rte_spinlock_unlock(&s_f_lock);
		return 0;
	}

	f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "wb");
	if (!f_dw_cfg) {
		LSX_PCIEP_BUS_ERR("%s: %s write open failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		pcie_dw_free(info);
		rte_spinlock_unlock(&s_f_lock);
		return 0;
	}

	if (info->ob_offset[pcie_id] + size > info->ob_max_size)
		goto no_space_available;

	for (i = 0; i < LSX_PCIE_DW_OB_WINS_NUM; i++) {
		cpu_addr = pcie_dw_alloc_from_priv_ob(info,
					pcie_id, size, i);
		if (cpu_addr)
			break;
	}
	if (!cpu_addr)
		goto no_space_available;

	f_ret = fwrite(info, sizeof(struct pciep_dw_info),
		1, f_dw_cfg);
	if (f_ret != 1) {
		LSX_PCIEP_BUS_ERR("%s write failed",
			PCIEP_DW_GLOBE_INFO_F);
		cpu_addr = 0;
	}
	fclose(f_dw_cfg);
	pcie_dw_free(info);
	rte_spinlock_unlock(&s_f_lock);

	return cpu_addr;

no_space_available:
	sprintf(err_str, "offset(0x%lx) + size(0x%lx) > max(0x%lx)",
		info->ob_offset[pcie_id], size,
		info->ob_max_size);
	LSX_PCIEP_BUS_ERR("map failed: %s", err_str);
	fclose(f_dw_cfg);
	pcie_dw_free(info);
	rte_spinlock_unlock(&s_f_lock);

	return 0;
}

static uint64_t
pcie_dw_find_shared_ob_space(int pcie_id,
	uint64_t pci_addr, uint64_t size)
{
	FILE *f_dw_cfg;
	size_t f_ret;
	int i;
	int *shared_nb = &g_dw_proc_info[pcie_id].ob_shared_nb;
	struct pciep_dw_info *info;
	struct pciep_dw_shared_ob_win *ob_shared_win;
	uint64_t ob_base, ob_addr = 0;

	rte_spinlock_lock(&s_f_lock);
	f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "rb");
	if (!f_dw_cfg) {
		LSX_PCIEP_BUS_ERR("%s: %s read open failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		rte_spinlock_unlock(&s_f_lock);
		return 0;
	}

	info = pcie_dw_malloc(sizeof(struct pciep_dw_info));
	if (!info) {
		LSX_PCIEP_BUS_ERR("%s prepare buf for read %s failed",
			__func__,
			PCIEP_DW_GLOBE_INFO_F);
		fclose(f_dw_cfg);
		rte_spinlock_unlock(&s_f_lock);
		return 0;
	}

	memset(info, 0, sizeof(struct pciep_dw_info));

	f_ret = fread(info, sizeof(struct pciep_dw_info),
			1, f_dw_cfg);
	fclose(f_dw_cfg);
	if (f_ret != 1) {
		LSX_PCIEP_BUS_ERR("%s: %s read failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		pcie_dw_free(info);
		rte_spinlock_unlock(&s_f_lock);
		return 0;
	}

	ob_shared_win = &info->shared_ob_win[pcie_id][0];
	ob_base = info->ob_base[pcie_id];

	for (i = 0; i < LSX_PCIE_DW_OB_WINS_NUM; i++) {
		if (pci_addr >= ob_shared_win->bus_start &&
			(pci_addr + size) <= ob_shared_win->bus_end) {
			ob_shared_win->ref_count++;
			ob_addr = ob_base + ob_shared_win->offset;
			break;
		}
		ob_shared_win++;
	}

	if (ob_addr) {
		f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "wb");
		if (!f_dw_cfg) {
			LSX_PCIEP_BUS_ERR("%s: %s write open failed",
				__func__, PCIEP_DW_GLOBE_INFO_F);
			pcie_dw_free(info);
			rte_spinlock_unlock(&s_f_lock);
			return 0;
		}
		f_ret = fwrite(info, sizeof(struct pciep_dw_info),
			1, f_dw_cfg);
		if (f_ret != 1) {
			LSX_PCIEP_BUS_ERR("%s write failed",
				PCIEP_DW_GLOBE_INFO_F);
			pcie_dw_free(info);
			fclose(f_dw_cfg);
			rte_spinlock_unlock(&s_f_lock);
			return 0;
		}
		fclose(f_dw_cfg);
		g_dw_proc_info[pcie_id].ob_shared_idx[*shared_nb] = i;
		(*shared_nb)++;
	}

	pcie_dw_free(info);
	rte_spinlock_unlock(&s_f_lock);

	return ob_addr;
}

static int
pcie_dw_add_shared_ob_space(int pcie_id,
	uint64_t pci_addr, uint64_t size, uint64_t cpu_addr,
	int win_id)
{
	FILE *f_dw_cfg;
	size_t f_ret;
	struct pciep_dw_info *info;
	struct pciep_dw_shared_ob_win *ob_shared_win;
	uint64_t ob_base;
	int *shared_nb = &g_dw_proc_info[pcie_id].ob_shared_nb;

	rte_spinlock_lock(&s_f_lock);
	f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "rb");
	if (!f_dw_cfg) {
		LSX_PCIEP_BUS_ERR("%s: %s read open failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		rte_spinlock_unlock(&s_f_lock);
		return -ENODEV;
	}

	info = pcie_dw_malloc(sizeof(struct pciep_dw_info));
	if (!info) {
		LSX_PCIEP_BUS_ERR("%s prepare buf for read %s failed",
			__func__,
			PCIEP_DW_GLOBE_INFO_F);
		fclose(f_dw_cfg);
		rte_spinlock_unlock(&s_f_lock);
		return -ENOMEM;
	}

	memset(info, 0, sizeof(struct pciep_dw_info));

	f_ret = fread(info, sizeof(struct pciep_dw_info),
			1, f_dw_cfg);
	fclose(f_dw_cfg);
	if (f_ret != 1) {
		LSX_PCIEP_BUS_ERR("%s: %s read failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		pcie_dw_free(info);
		rte_spinlock_unlock(&s_f_lock);
		return -EIO;
	}

	ob_shared_win = &info->shared_ob_win[pcie_id][win_id];
	ob_base = info->ob_base[pcie_id];

	ob_shared_win->bus_start = pci_addr;
	ob_shared_win->bus_end = pci_addr + size;
	ob_shared_win->offset = cpu_addr - ob_base;
	ob_shared_win->ref_count++;

	f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "wb");
	if (!f_dw_cfg) {
		LSX_PCIEP_BUS_ERR("%s: %s write open failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		rte_spinlock_unlock(&s_f_lock);
		return -ENODEV;
	}

	f_ret = fwrite(info, sizeof(struct pciep_dw_info),
		1, f_dw_cfg);
	if (f_ret != 1) {
		LSX_PCIEP_BUS_ERR("%s write failed",
			PCIEP_DW_GLOBE_INFO_F);
		pcie_dw_free(info);
		fclose(f_dw_cfg);
		rte_spinlock_unlock(&s_f_lock);
		return -EIO;
	}
	fclose(f_dw_cfg);

	g_dw_proc_info[pcie_id].ob_shared_idx[*shared_nb] = win_id;
	(*shared_nb)++;
	pcie_dw_free(info);
	rte_spinlock_unlock(&s_f_lock);

	return 0;
}

static int
pcie_dw_disable_ob_win(struct lsx_pciep_hw_low *hw,
	int idx)
{
	struct pcie_dw_iatu_region *iatu;
	int loop;

	iatu = (void *)(hw->dbi_vir + LSX_PCIE_DW_IATU_REGION_OFFSET);

	if (idx != PCIE_EP_DISABLE_ALL_WIN) {
		return -ENOTSUP;
	} else {
		for (loop = 0; loop < LSX_PCIE_DW_OB_WINS_NUM; loop++) {
			rte_write32(PCIE_DW_ATU_VP_REGION_OUTBOUND | loop,
				&iatu->view_port);
			rte_write32(0, &iatu->base_addr[ADDR_LOW]);
			rte_write32(0, &iatu->base_addr[ADDR_UP]);
			rte_write32(0, &iatu->base_limit);
			rte_write32(0, &iatu->bus_addr[ADDR_LOW]);
			rte_write32(0, &iatu->bus_addr[ADDR_UP]);
			rte_write32(PCIE_DW_ATU_CTL1_TYPE_MEM, &iatu->ctl1_ob);
			rte_write32(0, &iatu->ctl3_ob);
			rte_write32(0, &iatu->ctl2_ob);
		}
	}

	return 0;
}

static uint64_t
pcie_dw_map_ob_win(struct lsx_pciep_hw_low *hw,
	int pf, int is_vf, int vf,
	uint64_t pci_addr,
	uint64_t size, int shared)
{
	struct pcie_dw_iatu_region *iatu;
	int win_id, ob_nb;
	uint64_t cpu_addr;
	uint64_t pcie_id = hw->index;
	uint32_t ctrl1, ctrl2, ctrl3 = 0;
	struct pciep_dw_proc_info *proc_info;

	if (!hw->is_sriov && (pf > PF0_IDX || is_vf)) {
		LSX_PCIEP_BUS_ERR("%s: PCIe%d is NONE-SRIOV",
			__func__, hw->index);
		return 0;
	}

	if (shared) {
		cpu_addr = pcie_dw_find_shared_ob_space(pcie_id,
			pci_addr, size);
		if (cpu_addr)
			return cpu_addr;
	}

	win_id = pcie_dw_alloc_win_idx(pcie_id, DW_OUTBOUND_WIN);
	if (win_id < 0)
		return 0;

	cpu_addr = pcie_dw_alloc_ob_space(pcie_id, size);

	ctrl1 = PCIE_DW_ATU_CTL1_TYPE_MEM | (pf << PCIE_DW_ATU_CTL1_FUNC_SHIFT);
	ctrl2 = PCIE_DW_ATU_CTL2_EN;
	if (is_vf)
		ctrl3 = PCIE_DW_ATU_CTL3_VF_ACTIVE_EN | vf;

	if (shared) {
		if (pcie_dw_add_shared_ob_space(pcie_id,
			pci_addr, size, cpu_addr, win_id)) {
			return 0;
		}
	}

	iatu = (void *)(hw->dbi_vir + LSX_PCIE_DW_IATU_REGION_OFFSET);

	rte_write32(PCIE_DW_ATU_VP_REGION_OUTBOUND | win_id,
		&iatu->view_port);

	rte_write32(lower_32_bits(cpu_addr), &iatu->base_addr[ADDR_LOW]);
	rte_write32(upper_32_bits(cpu_addr), &iatu->base_addr[ADDR_UP]);

	rte_write32(lower_32_bits(cpu_addr + size - 1),
		&iatu->base_limit);

	rte_write32(lower_32_bits(pci_addr), &iatu->bus_addr[ADDR_LOW]);
	rte_write32(upper_32_bits(pci_addr), &iatu->bus_addr[ADDR_UP]);

	rte_write32(ctrl1, &iatu->ctl1_ob);
	if (ctrl3) {
		/* Don't program ctl3 for PF, otherwise,
		 * qdma-PCIe perf drops???
		 */
		rte_write32(ctrl3, &iatu->ctl3_ob);
	}
	rte_write32(ctrl2, &iatu->ctl2_ob);

	if (!is_vf) {
		LSX_PCIEP_BUS_INFO(DWC_OB_PF_INFO_DUMP_FORMAT(hw->index,
			pf, cpu_addr, pci_addr, size, win_id));
	} else {
		LSX_PCIEP_BUS_INFO(DWC_OB_VF_INFO_DUMP_FORMAT(hw->index,
			pf, vf, cpu_addr, pci_addr, size, win_id));
	}

	proc_info = &g_dw_proc_info[hw->index];

	ob_nb = proc_info->ob_nb;

	proc_info->ob_start[ob_nb] = cpu_addr;
	proc_info->ob_idx[ob_nb] = win_id;
	proc_info->ob_nb++;

	return cpu_addr;
}

static int
pcie_dw_set_ob_win(struct lsx_pciep_hw_low *hw,
	int idx, int pf, int is_vf, int vf,
	uint64_t cpu_addr, uint64_t pci_addr,
	uint64_t size)
{
	uint32_t ctrl1, ctrl2, ctrl3 = 0;
	struct pcie_dw_iatu_region *iatu;

	if (!hw->is_sriov && (pf > PF0_IDX || is_vf)) {
		LSX_PCIEP_BUS_ERR("%s: PCIe%d is NONE-SRIOV",
			__func__, hw->index);
		return -EIO;
	}

	ctrl1 = PCIE_DW_ATU_CTL1_TYPE_MEM | (pf << PCIE_DW_ATU_CTL1_FUNC_SHIFT);
	ctrl2 = PCIE_DW_ATU_CTL2_EN;
	if (is_vf)
		ctrl3 = PCIE_DW_ATU_CTL3_VF_ACTIVE_EN | vf;

	iatu = (void *)(hw->dbi_vir + LSX_PCIE_DW_IATU_REGION_OFFSET);

	rte_write32(PCIE_DW_ATU_VP_REGION_OUTBOUND | idx, &iatu->view_port);

	rte_write32(lower_32_bits(cpu_addr), &iatu->base_addr[ADDR_LOW]);
	rte_write32(upper_32_bits(cpu_addr), &iatu->base_addr[ADDR_UP]);

	rte_write32(lower_32_bits(cpu_addr + size - 1),
		&iatu->base_limit);

	rte_write32(lower_32_bits(pci_addr), &iatu->bus_addr[ADDR_LOW]);
	rte_write32(upper_32_bits(pci_addr), &iatu->bus_addr[ADDR_UP]);

	rte_write32(ctrl1, &iatu->ctl1_ob);
	rte_write32(ctrl3, &iatu->ctl3_ob);
	rte_write32(ctrl2, &iatu->ctl2_ob);

	if (!is_vf) {
		LSX_PCIEP_BUS_INFO(DWC_OB_PF_INFO_DUMP_FORMAT(hw->index,
			pf, cpu_addr, pci_addr, size, idx));
	} else {
		LSX_PCIEP_BUS_INFO(DWC_OB_VF_INFO_DUMP_FORMAT(hw->index,
			pf, vf, cpu_addr, pci_addr, size, idx));
	}

	return 0;
}

static int
pcie_dw_set_bar_attribute(struct lsx_pciep_hw_low *hw,
	int pf, int bar,
	int is_vf, int is_64b, int pref, int is_io)
{
	struct pcie_ctrl_cfg *cfg;
	int ret = 0;
	uint32_t *bar_cfg, attr;
	uint8_t *pf_base = hw->dbi_vir + pf * hw->dbi_pf_size;
	struct pcie_dw_dbi_access access;
	char log_info[64];

	access.access_type = DW_DBI_SHADOW_ACCESS;
	access.param = -1;

	cfg = (void *)pf_base;
	if (is_vf) {
		bar_cfg = cfg->vfbar;
		sprintf(log_info, "PCIe%d:PF%d:VF", hw->index, pf);
	} else {
		bar_cfg = cfg->pfbar;
		sprintf(log_info, "PCIe%d:PF%d", hw->index, pf);
	}

	if (is_io) {
		if (is_64b) {
			LSX_PCIEP_BUS_ERR("%s IO bar must be a 32b bar",
				log_info);
			return -EINVAL;
		}
		if (pref) {
			LSX_PCIEP_BUS_ERR("%s IO bar cannot be prefetchable",
				log_info);
			return -EINVAL;
		}
	}

	if (is_64b && !lsx_pciep_valid_64b_bar_id(bar)) {
		LSX_PCIEP_BUS_ERR("%s Invalid bar pair ID(%d)",
			log_info, bar);
		return -EINVAL;
	}
	if (!is_64b && !pcie_dw_32b_bar_support(bar)) {
		LSX_PCIEP_BUS_ERR("%s Invalid bar ID(%d)",
			log_info, bar);
		return -EINVAL;
	}

	if (is_64b) {
		bar = lsx_pciep_64bar_to_32bar(bar);
		if (bar < 0)
			return bar;
	}

	access.access_type = DW_DBI_SIMPLE_ACCESS;

	ret = pcie_dw_read_config_reg(hw, pf, access,
		&bar_cfg[bar], &attr, sizeof(uint32_t));
	if (ret)
		return ret;

	if (is_64b) {
		PCIE_BAR_SET_64B_WIDTH(attr);
		if (pref)
			PCIE_BAR_ENABLE_PREFETCH(attr);
		else
			PCIE_BAR_DISABLE_PREFETCH(attr);
	} else {
		PCIE_BAR_SET_32B_WIDTH(attr);
		if (is_io) {
			PCIE_BAR_SET_IO_SPACE_IND(attr);
			PCIE_BAR_DISABLE_PREFETCH(attr);
		} else {
			PCIE_BAR_SET_MEM_SPACE_IND(attr);
			if (pref)
				PCIE_BAR_ENABLE_PREFETCH(attr);
			else
				PCIE_BAR_DISABLE_PREFETCH(attr);
		}
	}

	ret = pcie_dw_write_config_reg(hw, pf, access,
		&bar_cfg[bar],
		&attr, sizeof(uint32_t), 1);
	if (ret)
		return ret;

	return ret;
}

static int
pcie_dw_get_bar_size(struct lsx_pciep_hw_low *hw,
	int pf, int is_vf,
	int bar, int is_64b, uint64_t *size)
{
	uint32_t size_lo = 0, size_hi = 0, attr;
	int ret = 0;
	struct pcie_ctrl_cfg *cfg;
	uint32_t *bar_size;
	struct pcie_dw_dbi_access access;

	access.access_type = DW_DBI_SIMPLE_ACCESS;
	access.param = -1;

	if (is_64b && !lsx_pciep_valid_64b_bar_id(bar)) {
		LSX_PCIEP_BUS_ERR("Invalid bar pair ID(%d)", bar);
		return -EINVAL;
	}
	if (!is_64b && !pcie_dw_32b_bar_support(bar)) {
		LSX_PCIEP_BUS_ERR("Invalid bar ID(%d)", bar);
		return -EINVAL;
	}

	cfg = (void *)(hw->dbi_vir + pf * hw->dbi_pf_size);

	if (is_vf) {
		/**All the VFs of this PF have same size.*/
		bar_size = cfg->vfbar;
	} else {
		bar_size = cfg->pfbar;
	}

	if (is_64b) {
		bar = lsx_pciep_64bar_to_32bar(bar);
		if (bar < 0)
			return bar;
	}

	ret = pcie_dw_read_config_reg(hw, pf, access, &bar_size[bar],
		&attr, sizeof(uint32_t));
	if (ret)
		return ret;

	size_lo = attr | (~0x7ffU);
	ret = pcie_dw_write_config_reg(hw, pf, access, &bar_size[bar],
		&size_lo, sizeof(uint32_t), 0);
	if (ret)
		return ret;
	ret = pcie_dw_read_config_reg(hw, pf, access, &bar_size[bar],
		&size_lo, sizeof(uint32_t));
	if (ret)
		return ret;
	ret = pcie_dw_write_config_reg(hw, pf, access, &bar_size[bar],
		&attr, sizeof(uint32_t), 0);
	if (ret)
		return ret;

	if (!is_64b) {
		PCIE_BAR_SIZE(size_lo, size_lo);
		*size = size_lo;

		return ret;
	}

	ret = pcie_dw_read_config_reg(hw, pf, access, &bar_size[bar + 1],
		&attr, sizeof(uint32_t));
	if (ret)
		return ret;

	size_hi = 0xffffffff;
	ret = pcie_dw_write_config_reg(hw, pf, access, &bar_size[bar + 1],
		&size_hi, sizeof(uint32_t), 0);
	if (ret)
		return ret;
	ret = pcie_dw_read_config_reg(hw, pf, access,
		&bar_size[bar + 1],
		&size_hi, sizeof(uint32_t));
	if (ret)
		return ret;
	ret = pcie_dw_write_config_reg(hw, pf, access, &bar_size[bar + 1],
		&attr, sizeof(uint32_t), 0);
	if (ret)
		return ret;

	*size = size_hi;
	*size = (*size) << 32;
	*size |= size_lo;

	PCIE_BAR64_SIZE((*size), (*size));

	return ret;
}

static int
pcie_dw_set_bar_size(struct lsx_pciep_hw_low *hw,
	int pf, int is_vf, int bar, uint64_t size, int is_64b)
{
	uint64_t mask, size_get = 0;
	uint32_t mask_lo, mask_hi;
	struct pcie_ctrl_cfg *cfg;
	int ret = 0, orig_bar = bar;
	uint32_t *bar_cfg;
	uint8_t *pf_base = hw->dbi_vir + pf * hw->dbi_pf_size;
	struct pcie_dw_dbi_access access;
	char log_info[64];

	access.access_type = DW_DBI_SHADOW_ACCESS;
	access.param = -1;

	cfg = (void *)pf_base;
	if (is_vf) {
		bar_cfg = cfg->vfbar;
		sprintf(log_info, "PCIe%d:PF%d:VF", hw->index, pf);
	} else {
		bar_cfg = cfg->pfbar;
		sprintf(log_info, "PCIe%d:PF%d", hw->index, pf);
	}

	if (!size) {
		/** Disable bar[bar]*/
		mask_lo = 0;
		ret = pcie_dw_write_config_reg(hw, pf, access,
			&bar_cfg[bar],
			&mask_lo, sizeof(uint32_t), 0);
		return ret;
	}

	if (is_64b && !lsx_pciep_valid_64b_bar_id(bar)) {
		LSX_PCIEP_BUS_ERR("%s Invalid bar pair ID(%d)",
			log_info, bar);
		return -EINVAL;
	}
	if (!is_64b && !pcie_dw_32b_bar_support(bar)) {
		LSX_PCIEP_BUS_ERR("%s Invalid bar ID(%d)",
			log_info, bar);
		return -EINVAL;
	}
	/* The least inbound window is 4KiB */
	if (size < (LSX_PCIEP_DW_WIN_MASK + 1)) {
		LSX_PCIEP_BUS_ERR("%s Too small bar size(0x%lx)",
			log_info, size);
		return -EINVAL;
	}

	if (!rte_is_power_of_2(size)) {
		LSX_PCIEP_BUS_ERR("%s Size(0x%lx) not power of 2",
			log_info, size);
		return -EINVAL;
	}

	mask = size - 1;
	mask_lo = (uint32_t)mask;
	mask_hi = (uint32_t)(mask >> 32);

	if (!is_64b) {
		ret = pcie_dw_write_config_reg(hw, pf, access,
			&bar_cfg[bar],
			&mask_lo, sizeof(uint32_t), 0);
		if (ret)
			return ret;
	} else {
		bar = lsx_pciep_64bar_to_32bar(bar);
		if (bar < 0)
			return bar;

		ret = pcie_dw_write_config_reg(hw, pf, access,
			&bar_cfg[bar],
			&mask_lo, sizeof(uint32_t), 0);
		if (ret)
			return ret;
		ret = pcie_dw_write_config_reg(hw, pf, access,
			&bar_cfg[bar + 1],
			&mask_hi, sizeof(uint32_t), 0);
		if (ret)
			return ret;
	}

	ret = pcie_dw_get_bar_size(hw, pf, is_vf, orig_bar,
		is_64b, &size_get);
	if (ret) {
		LSX_PCIEP_BUS_ERR("%s Get bar(%d) size failed(%d)",
			log_info, orig_bar, ret);
		return ret;
	}

	if (size != size_get) {
		LSX_PCIEP_BUS_ERR("%s bar(%d) size set(%lx) != get(%lx)",
			log_info, orig_bar, size, size_get);
		return -EINVAL;
	}

	return ret;
}

static int
pcie_dw_set_ib_win(struct lsx_pciep_hw_low *hw,
	int pf, int is_vf, int vf, int bar,
	uint64_t phys, uint64_t size)
{
	uint32_t ctrl1, ctrl2, ctrl3 = 0, need_rescan = 0;
	uint64_t size_orig = 0, size_get = 0;
	int idx = -1, ib_nb, ret = 0, bar_apply, pref, is_64b;
	struct pciep_dw_proc_info *proc_info;
	struct pcie_dw_iatu_region *iatu;

	if (!hw->is_sriov && (pf > PF0_IDX || is_vf)) {
		LSX_PCIEP_BUS_ERR("%s: PCIe%d is NONE-SRIOV",
			__func__, hw->index);
		return -EIO;
	}

	if (bar >= PCI_MAX_RESOURCE) {
		LSX_PCIEP_BUS_ERR("Invalid bar(%d)", bar);

		return -EIO;
	}

	if (size > hw->win_max && !is_vf) {
		LSX_PCIEP_BUS_ERR("PCIe%d PF%d bar%d size(%lx) > max(%lx)",
			hw->index, pf, bar, size, hw->win_max);

		return -EIO;
	} else if (size > hw->win_max && is_vf) {
		LSX_PCIEP_BUS_ERR("PCIe%d PF%d VF%d bar%d size(%lx) > max(%lx)",
			hw->index, pf, vf, bar, size, hw->win_max);

		return -EIO;
	}

	proc_info = &g_dw_proc_info[hw->index];
	ib_nb = proc_info->ib_nb;
	if (ib_nb >= LSX_PCIE_DW_IB_WINS_NUM) {
		LSX_PCIEP_BUS_ERR("No inbound window available!");

		return -EIO;
	}

	if (pcie_dw_using_32b_bar(bar)) {
		bar_apply = bar;
		pref = 0;
		is_64b = 0;
	} else {
		bar_apply = lsx_pciep_32bar_to_64bar(bar);
		pref = 1;
		is_64b = 1;
	}

	ret = pcie_dw_get_bar_size(hw, pf, is_vf,
			bar_apply, is_64b, &size_orig);
	if (ret)
		goto err_ret;

	ret = pcie_dw_set_bar_size(hw, pf, is_vf, bar_apply, size,
			is_64b);
	if (ret)
		goto err_ret;
	ret = pcie_dw_get_bar_size(hw, pf, is_vf, bar_apply,
			is_64b, &size_get);
	if (ret || size_get != size)
		goto err_ret;
	if (size_orig != size_get)
		need_rescan = 1;

	if (!is_vf) {
		ret = pcie_dw_set_bar_attribute(hw, pf, bar_apply, is_vf,
			is_64b, pref, 0);
		if (ret)
			goto err_ret;
	}

	if (need_rescan) {
		if (is_vf) {
			LSX_PCIEP_BUS_INFO("%s:%s%d:%s%d:%s%d %lx->%lx",
				"RC need rescan",
				"PF", pf, "VF", vf, "BAR", bar,
				size_orig, size_get);
		} else {
			LSX_PCIEP_BUS_INFO("%s:%s%d:%s%d %lx->%lx",
				"RC need rescan",
				"PF", pf, "BAR", bar,
				size_orig, size_get);
		}
	}

	idx = pcie_dw_alloc_win_idx(hw->index,
		DW_INBOUND_WIN);
	if (idx < 0) {
		LSX_PCIEP_BUS_ERR("Inbound window alloc failed");

		ret = -ENOMEM;
		goto err_ret;
	}

	ctrl1 = PCIE_DW_ATU_CTL1_TYPE_MEM | (pf << PCIE_DW_ATU_CTL1_FUNC_SHIFT);

	ctrl2 = PCIE_DW_ATU_CTL2_EN |
		PCIE_DW_ATU_CTL2_BAR_MODE_EN |
		PCIE_DW_ATU_CTL2_BAR_NUM(bar) |
		PCIE_DW_ATU_CTL2_FUNC_NUM_MATCH_EN;
	if (is_vf) {
		ctrl2 |= PCIE_DW_ATU_CTL2_VF_MATCH_MODE_EN;
		ctrl3 = PCIE_DW_ATU_CTL3_VF_ACTIVE_EN | vf;
	}

	iatu = (void *)(hw->dbi_vir + LSX_PCIE_DW_IATU_REGION_OFFSET);

	rte_write32(PCIE_DW_ATU_VP_REGION_INBOUND | idx,
		&iatu->view_port);

	rte_write32(lower_32_bits(phys), &iatu->bus_addr[ADDR_LOW]);
	rte_write32(upper_32_bits(phys), &iatu->bus_addr[ADDR_UP]);

	rte_write32(ctrl1, &iatu->ctl1_ib);
	rte_write32(ctrl3, &iatu->ctl3_ib);
	rte_write32(ctrl2, &iatu->ctl2_ib);

	if (!is_vf) {
		LSX_PCIEP_BUS_INFO(DWC_IB_PF_INFO_DUMP_FORMAT(hw->index,
			pf, phys, bar, size, idx));
	} else {
		LSX_PCIEP_BUS_INFO(DWC_IB_VF_INFO_DUMP_FORMAT(hw->index,
			pf, vf, phys, bar, size, idx));
	}

err_ret:
	if (size_get != size) {
		LSX_PCIEP_BUS_ERR("Bar[%d] size(%lx) get != size(%lx) set!",
			bar, size_get, size);
	}

	if (ret)
		return ret;

	proc_info->ib_idx[ib_nb] = idx;
	proc_info->ib_nb++;

	return 0;
}

static int
pcie_dw_disable_bar_env(struct lsx_pciep_hw_low *hw)
{
	int loop, i, ret = 0;
	char env[64];
	char *penv;

	for (loop = 0; loop < PCI_MAX_RESOURCE; loop++) {
		for (i = 0; i < PF_MAX_NB; i++) {
			sprintf(env,
				"LSX_DW_PCIE%d_PF%d_BAR%d_DISABLE",
				hw->index, i, loop);
			penv = getenv(env);
			if (penv && atoi(penv)) {
				ret = pcie_dw_set_bar_size(hw, i, 0, loop,
						0, 0);
				if (ret)
					return ret;
			}
			sprintf(env,
				"LSX_DW_PCIE%d_PF%d_VF_BAR%d_DISABLE",
				hw->index, i, loop);
			penv = getenv(env);
			if (penv && atoi(penv)) {
				ret = pcie_dw_set_bar_size(hw, i, 1, loop,
						0, 0);
				if (ret)
					return ret;
			}
		}
	}

	return 0;
}

static int
pcie_dw_disable_ib_win(struct lsx_pciep_hw_low *hw, int idx)
{
	struct pcie_dw_iatu_region *iatu;
	int loop, ret = 0;

	iatu = (void *)(hw->dbi_vir + LSX_PCIE_DW_IATU_REGION_OFFSET);

	if (idx != PCIE_EP_DISABLE_ALL_WIN) {
		/* Not support yet.*/
		ret = -ENOTSUP;
	} else {
		for (loop = 0; loop < LSX_PCIE_DW_IB_WINS_NUM; loop++) {
			rte_write32(PCIE_DW_ATU_VP_REGION_INBOUND | loop,
				&iatu->view_port);
			rte_write32(0, &iatu->bus_addr[ADDR_LOW]);
			rte_write32(0, &iatu->bus_addr[ADDR_UP]);
			rte_write32(PCIE_DW_ATU_CTL1_TYPE_MEM, &iatu->ctl1_ib);
			rte_write32(0, &iatu->ctl3_ib);
			rte_write32(0, &iatu->ctl2_ib);
		}

		ret = pcie_dw_disable_bar_env(hw);
	}

	return ret;
}

static int
pcie_dw_get_cap_offset(struct lsx_pciep_hw_low *hw,
	int pf, int is_vf, int vf, uint8_t cap_id)
{
	int offset = 0, ret;
	uint8_t next = 0;
	const void *cap_addr;
	const struct pcie_ctrl_cfg *cfg;
	struct pcie_dw_dbi_access access;
	struct pcie_ctrl_cap_head cap;

	access.access_type = DW_DBI_SIMPLE_ACCESS;
	access.param = -1;
	if (is_vf) {
		access.access_type |= DW_DBI_VIEWPORT_ACCESS;
		access.param = vf;
	}

	cfg = (void *)(hw->dbi_vir + pf * hw->dbi_pf_size);

	ret = pcie_dw_read_config_reg(hw, pf, access, &cfg->cap_list,
		&offset, sizeof(uint8_t));
	if (ret)
		return ret;

	while (offset > 0) {
		cap_addr = (const char *)cfg + offset;
		ret = pcie_dw_read_config_reg(hw, pf, access,
			cap_addr, &cap, sizeof(cap));
		if (!ret && cap.cap_id == cap_id)
			return offset;
		next = cap.next_offset;
		next = next & ~3;
		offset = next;
	}

	return -EIO;
}

static int
pcie_dw_sriov_ext_cap_rw(struct lsx_pciep_hw_low *hw,
	int pf, struct pcie_ctrl_ext_sriov_cap *ext_sriov_cap,
	uint32_t cap_offset, int read)
{
	size_t left = sizeof(struct pcie_ctrl_ext_sriov_cap);
	uint16_t len, offset = 0;
	int ret = 0;
	struct pcie_dw_dbi_access access;
	void *cap_base = hw->dbi_vir + pf * hw->dbi_pf_size + cap_offset;

	access.access_type = DW_DBI_SIMPLE_ACCESS;
	access.param = -1;

	if (!read)
		goto write_ext_cap;

	while (left) {
		if (left > sizeof(uint32_t))
			len = sizeof(uint32_t);
		else
			len = left;
		ret = pcie_dw_read_config_reg(hw, pf, access,
			(uint8_t *)cap_base + offset,
			(uint8_t *)ext_sriov_cap + offset, len);
		if (ret) {
			LSX_PCIEP_BUS_ERR("%s off(%d) len(%d) err(%d)",
				"Read Ext SRIOV", offset, len, ret);
			return ret;
		}
		offset += len;
		left -= len;
	}

	return 0;

write_ext_cap:

	/**Simple write for non ARI capable.*/
	while (left) {
		if (left > sizeof(uint32_t))
			len = sizeof(uint32_t);
		else
			len = left;
		ret = pcie_dw_write_config_reg(hw, pf, access,
			(uint8_t *)cap_base + offset,
			(uint8_t *)ext_sriov_cap + offset, len, 1);
		if (ret) {
			LSX_PCIEP_BUS_ERR("%s off(%d) len(%d) err(%d)",
				"Write simple Ext SRIOV", offset, len, ret);
			return ret;
		}
		offset += len;
		left -= len;
	}

	/**Shadow write for ARI capable.*/

	left = sizeof(struct pcie_ctrl_ext_sriov_cap);
	offset = 0;

	access.access_type = DW_DBI_SHADOW_ACCESS;
	access.param = -1;

	while (left) {
		if (left > sizeof(uint32_t))
			len = sizeof(uint32_t);
		else
			len = left;
		ret = pcie_dw_write_config_reg(hw, pf, access,
			(uint8_t *)cap_base + offset,
			(uint8_t *)ext_sriov_cap + offset, len, 1);
		if (ret) {
			LSX_PCIEP_BUS_ERR("%s off(%d) len(%d) err(%d)",
				"Write shadow Ext SRIOV", offset, len, ret);
			return ret;
		}
		offset += len;
		left -= len;
	}

	return ret;
}

static int
pcie_dw_msix_cap_rw(struct lsx_pciep_hw_low *hw,
	int pf, int is_vf, int vf,
	struct pcie_ctrl_sriov_cap *sriov_cap,
	int read)
{
	size_t left = sizeof(struct pcie_ctrl_sriov_cap);
	uint16_t len, offset = 0;
	int ret = 0, cap_offset;
	struct pcie_dw_dbi_access access;
	void *base;

	access.access_type = DW_DBI_SIMPLE_ACCESS;
	access.param = -1;
	if (is_vf) {
		access.access_type |= DW_DBI_VIEWPORT_ACCESS;
		access.param = vf;
	}

	cap_offset = pcie_dw_get_cap_offset(hw, pf, is_vf, vf,
		PCI_CAP_ID_MSIX);
	if (cap_offset < 0) {
		LSX_PCIEP_BUS_ERR("%s MSIx cap not found",
			__func__);
		return cap_offset;
	}
	base = (void *)(hw->dbi_vir + pf * hw->dbi_pf_size + cap_offset);

	while (left) {
		if (left > sizeof(uint32_t))
			len = sizeof(uint32_t);
		else
			len = left;
		if (read) {
			ret = pcie_dw_read_config_reg(hw, pf, access,
				(uint8_t *)base + offset,
				(uint8_t *)sriov_cap + offset, len);
		} else {
			ret = pcie_dw_write_config_reg(hw, pf, access,
				(uint8_t *)base + offset,
				(uint8_t *)sriov_cap + offset, len, 1);
		}
		if (ret) {
			LSX_PCIEP_BUS_ERR("SRIOV %s (off=%d, len=%d) err(%d)",
				read ? "Read" : "Write",
				offset, len, ret);
			return ret;
		}
		offset += len;
		left -= len;
	}

	return 0;
}

static int
pcie_dw_msix_bar_resize(struct lsx_pciep_hw_low *hw,
	int pf, int is_vf, uint32_t end,
	uint8_t bar)
{
	int ret, bar_64b;
	uint64_t bar_size;

	if (pcie_dw_using_32b_bar(bar)) {
		ret = pcie_dw_get_bar_size(hw, pf, is_vf,
				bar, 0, &bar_size);
	} else {
		bar_64b = lsx_pciep_32bar_to_64bar(bar);
		if (bar_64b < 0) {
			ret = bar_64b;
		} else {
			ret = pcie_dw_get_bar_size(hw, pf, is_vf,
					bar_64b, 1, &bar_size);
		}
	}
	if (ret) {
		LSX_PCIEP_BUS_ERR("Get MSIX bar(%d) size failed(%d)",
			bar, ret);
		return ret;
	}

	LSX_PCIEP_BUS_INFO("MSIX bar(%d)'s original size is 0x%lx",
		bar, bar_size);

	if (!bar_size)
		bar_size = end;

	while (bar_size < end)
		bar_size = bar_size * 2;

	if (bar_size < (LSX_PCIEP_DW_WIN_MASK + 1))
		bar_size = (LSX_PCIEP_DW_WIN_MASK + 1);

	ret = pcie_dw_set_bar_size(hw, pf, is_vf, bar, bar_size,
			!pcie_dw_using_32b_bar(bar));
	if (ret) {
		LSX_PCIEP_BUS_ERR("Update MSIX bar(%d) size(%lx) failed(%d)",
			bar, bar_size, ret);
	} else {
		LSX_PCIEP_BUS_INFO("%s(%d) size update to(%lx)",
			"RC need rescan, MSIx bar", bar, bar_size);
	}

	return ret;
}

static int
pcie_dw_msix_cap_init(struct lsx_pciep_hw_low *hw,
	int pf, int is_vf, int vf)
{
	uint16_t tb_entry;
	uint32_t tb_offset, pba_offset, tb_size, pba_size = 0;
	uint32_t tb_end, pba_end;
	uint8_t tb_bar, pba_bar;
	int ret = 0, cap_update = 0;
	char cap_info[256];
	struct pcie_ctrl_sriov_cap sriov_cap;

	if (is_vf)
		sprintf(cap_info, "PCIe%d:PF%d:VF%d:", hw->index, pf, vf);
	else
		sprintf(cap_info, "PCIe%d:PF%d:", hw->index, pf);

	memset(&sriov_cap, 0, sizeof(sriov_cap));
	ret = pcie_dw_msix_cap_rw(hw, pf, is_vf, vf, &sriov_cap, 1);
	if (ret)
		return ret;

	tb_entry = (sriov_cap.msix_table_size & PCI_MSIX_FLAGS_QSIZE) + 1;
	tb_bar = sriov_cap.msix_table_offset_bir & PCI_MSIX_TABLE_BIR;
	tb_offset = sriov_cap.msix_table_offset_bir & PCI_MSIX_TABLE_OFFSET;
	pba_bar = sriov_cap.msix_pba_offset_bir & PCI_MSIX_PBA_BIR;
	pba_offset = sriov_cap.msix_pba_offset_bir & PCI_MSIX_PBA_OFFSET;

	tb_size = tb_entry * sizeof(struct pcie_ctrl_msix_entry);
	pba_size = tb_entry / BITS_PER_PBA_ENTRY;
	pba_size += (tb_entry % BITS_PER_PBA_ENTRY) ?
		sizeof(struct pcie_ctrl_msix_pba_entry) : 0;

	if (tb_bar == pba_bar) {
		if (pba_offset > tb_offset &&
			(tb_offset + tb_size) > pba_offset) {
			cap_update = 1;
			tb_offset = 0;
			while ((tb_offset + tb_size) > pba_offset) {
				pba_offset +=
					sizeof(struct pcie_ctrl_msix_pba_entry);
			}
		} else if (tb_offset > pba_offset &&
			(pba_offset + pba_size) > tb_offset) {
			cap_update = 1;
			pba_offset = 0;
			while ((pba_offset + pba_size) > tb_offset) {
				tb_offset +=
					sizeof(struct pcie_ctrl_msix_entry);
			}
		}
	}

	sriov_cap.msix_table_offset_bir = tb_offset | tb_bar;
	sriov_cap.msix_pba_offset_bir = pba_offset | pba_bar;

	tb_end = tb_offset + tb_size;
	pba_end = pba_offset + pba_size;

	ret = pcie_dw_msix_bar_resize(hw, pf, is_vf, tb_end, tb_bar);
	if (ret) {
		LSX_PCIEP_BUS_ERR("Resize MSIX TB bar(%d) failed(%d)",
			tb_bar, ret);
		return ret;
	}

	ret = pcie_dw_msix_bar_resize(hw, pf, is_vf, pba_end, pba_bar);
	if (ret) {
		LSX_PCIEP_BUS_ERR("Resize MSIX PBA bar(%d) failed(%d)",
			tb_bar, ret);
		return ret;
	}

	if (cap_update) {
		ret = pcie_dw_msix_cap_rw(hw, pf, is_vf, vf, &sriov_cap, 0);
		if (ret)
			return ret;
	}

	LSX_PCIEP_BUS_INFO("%s MSIX TABLE: BAR%d, 0x%08x~0x%08x",
		cap_info, tb_bar, tb_offset, tb_offset + tb_size);
	LSX_PCIEP_BUS_INFO("%s MSIX PBA: BAR%d, 0x%08x~0x%08x",
		cap_info, pba_bar, pba_offset, pba_offset + pba_size);

	return 0;
}

static int
pcie_dw_msix_cfg(struct lsx_pciep_hw_low *hw,
	uint8_t *out_vir,
	int pf, int is_vf, int vf,
	uint64_t msg_phy_addr[], void *msg_vir_addr[],
	uint32_t msg_data[], uint64_t *size,
	int vector_total)
{
	struct pcie_ctrl_cfg *cfg;
	uint64_t maddr, phy_addr, doorbell_addr, iova, iatu_phy, moff = 0;
	void *vaddr;
	uint32_t maddr_32, msi_data, tb_bar;
	union pcie_dw_msix_db msix_data;
	int vector, ret, cap_offset;
	char pci_info[128];
	struct pcie_dw_iatu_region *iatu;
	uint16_t tb_entry;
	struct pcie_ctrl_sriov_cap sriov_cap;
	struct pcie_dw_dbi_access access;

	access.access_type = DW_DBI_SIMPLE_ACCESS;
	access.param = -1;
	if (is_vf) {
		access.access_type |= DW_DBI_VIEWPORT_ACCESS;
		access.param = vf;
	}

	iatu = (void *)(hw->dbi_vir + LSX_PCIE_DW_IATU_REGION_OFFSET);
	iatu_phy = hw->dbi_phy + LSX_PCIE_DW_IATU_REGION_OFFSET;

	if (hw->msi_flag == LSX_PCIEP_DONT_INT)
		return 0;

	if (!hw->is_sriov && (pf > PF0_IDX || is_vf)) {
		LSX_PCIEP_BUS_ERR("%s: PCIe%d is NONE-SRIOV",
			__func__, hw->index);
		return -EINVAL;
	}

	if (is_vf) {
		sprintf(pci_info, "PCI%d:PF%d:VF%d",
			hw->index, pf, vf);
	} else {
		sprintf(pci_info, "PCI%d:PF%d",
			hw->index, pf);
	}

	if (!hw->is_sriov && hw->msi_flag == LSX_PCIEP_MSIX_INT) {
		LSX_PCIEP_BUS_ERR("PCIe%d (NONE-SRIOV) %s",
			hw->index, "does not support MSI-X");
		return -ENOTSUP;
	}

	cfg = (void *)(hw->dbi_vir + pf * hw->dbi_pf_size);

	if (hw->msi_flag == LSX_PCIEP_MSIX_INT) {
		doorbell_addr = iatu_phy +
			offsetof(struct pcie_dw_iatu_region, msix_doorbell);
		vaddr = &iatu->msix_doorbell;

		memset(&sriov_cap, 0, sizeof(sriov_cap));
		ret = pcie_dw_msix_cap_rw(hw, pf, is_vf, vf, &sriov_cap, 1);
		if (ret)
			return ret;

		cap_offset = pcie_dw_get_cap_offset(hw, pf, is_vf, vf,
			PCI_CAP_ID_MSIX);
		if (cap_offset < 0) {
			LSX_PCIEP_BUS_ERR("%s MSIx cap not found",
				__func__);
			return cap_offset;
		}

		tb_entry = sriov_cap.msix_table_size & PCI_MSIX_FLAGS_QSIZE;
		tb_entry++;
		tb_bar = sriov_cap.msix_table_offset_bir & PCI_MSIX_TABLE_BIR;
		if (tb_bar != LSX_PCIE_DW_MSIX_DOOR_BELL_BAR) {
			LSX_PCIEP_BUS_ERR("%s: MSIx/bar%d %s",
				pci_info, tb_bar, "Not supported yet!");
			return -ENOTSUP;
		}

		if (vector_total > tb_entry) {
			LSX_PCIEP_BUS_WARN("%s: %s(%d) %s(%d)",
				pci_info, "reduce vector required",
				vector_total, "to supported number",
				tb_entry);
			vector_total = tb_entry;
		}
		msix_data.db = 0;
		msix_data.pf = pf;
		if (is_vf) {
			msix_data.vf = vf;
			msix_data.vf_active = 1;
		}
		for (vector = 0; vector < vector_total; vector++) {
			msg_phy_addr[vector] = doorbell_addr;
			msg_vir_addr[vector] = vaddr;
			msix_data.vector = vector;
			msg_data[vector] = msix_data.db;
		}
		if (size)
			*size = sizeof(uint32_t);
	} else if (hw->msi_flag == LSX_PCIEP_MMSI_INT) {
		ret = pcie_dw_read_config_reg(hw, pf, access,
			&cfg->msi_addr_high,
			&maddr_32, sizeof(uint32_t));
		if (ret)
			return ret;
		maddr = maddr_32;
		maddr = maddr << 32;
		ret = pcie_dw_read_config_reg(hw, pf, access,
			&cfg->msi_addr_low,
			&maddr_32, sizeof(uint32_t));
		if (ret)
			return ret;
		maddr |= maddr_32;
		ret = pcie_dw_read_config_reg(hw, pf, access,
			&cfg->msi_data,
			&msi_data, sizeof(uint16_t));
		if (ret)
			return ret;

		/* The start address must be aligned to 4 KB. */
		moff = maddr & LSX_PCIEP_DW_WIN_MASK;
		if (is_vf)
			g_dw_proc_info[hw->index].vf_moff[pf][vf] = moff;
		else
			g_dw_proc_info[hw->index].pf_moff[pf] = moff;

		maddr -= moff;
		if (!out_vir) {
			phy_addr = pcie_dw_map_ob_win(hw, pf, is_vf, vf,
				maddr, CFG_MSIX_OB_SIZE, 0);
			if (!phy_addr) {
				LSX_PCIEP_BUS_ERR("%s bus(%lx) failed",
					pci_info, maddr);
				return -EIO;
			}
			vaddr = lsx_pciep_map_region(phy_addr,
				CFG_MSIX_OB_SIZE);
			if (!vaddr) {
				LSX_PCIEP_BUS_ERR("%s phy(%lx) failed",
					pci_info, phy_addr);
				return -ENOMEM;
			}
			if (rte_eal_iova_mode() == RTE_IOVA_VA)
				iova = (uint64_t)vaddr;
			else
				iova = phy_addr;
			ret = rte_fslmc_vfio_mem_dmamap((uint64_t)vaddr,
					iova, CFG_MSIX_OB_SIZE);
			if (ret) {
				LSX_PCIEP_BUS_WARN("%s: %p:%lx:%lx",
					"MSI VFIO MAP failed: VA:PA:IOVA:",
					vaddr, phy_addr, iova);
			}
		} else {
			/* maddr is offset to outbound start.*/
			phy_addr = hw->out_base + maddr;
			vaddr = out_vir + maddr;
		}
		phy_addr += moff;
		vaddr = (uint8_t *)vaddr + moff;
		for (vector = 0; vector < vector_total; vector++) {
			msg_phy_addr[vector] = phy_addr;
			msg_vir_addr[vector] = vaddr;
			msg_data[vector] = msi_data + vector;
		}
		if (size)
			*size = CFG_MSIX_OB_SIZE;
	} else {
		LSX_PCIEP_BUS_ERR("%s: Invalid MSI flag(%d)",
			pci_info, hw->msi_flag);
		return -EINVAL;
	}

	return vector_total;
}

static int
pcie_dw_msix_decfg(struct lsx_pciep_hw_low *hw,
	uint8_t *out_vir, int pf, int is_vf, int vf,
	uint64_t msg_phy_addr[], void *msg_vir_addr[],
	uint64_t size[], int vector_total)
{
	uint64_t phy_addr, iova, moff;
	void *vaddr;
	int vector, ret;
	char pci_info[1024];
	int print_offset = 0, print_len = 0, pci_print_offset;
	uint64_t msi_phy_addr[vector_total];
	void *msi_vir_addr[vector_total];
	uint64_t msi_size[vector_total];
	int msi_nb = 0, i, found;

	if (hw->msi_flag == LSX_PCIEP_DONT_INT)
		return 0;

	if (!hw->is_sriov && (pf > PF0_IDX || is_vf)) {
		LSX_PCIEP_BUS_ERR("%s: PCIe%d is NONE-SRIOV",
			__func__, hw->index);
		return -EINVAL;
	}

	if (is_vf)
		print_len = sprintf(pci_info, "PCI%d:PF%d:VF%d",
			hw->index, pf, vf);
	else
		print_len = sprintf(pci_info, "PCI%d:PF%d",
			hw->index, pf);
	print_offset += print_len;
	pci_print_offset = print_offset;

	if (hw->msi_flag != LSX_PCIEP_MMSI_INT || out_vir) {
		/** Do nothing*/
		return 0;
	}

	if (!is_vf)
		moff = g_dw_proc_info[hw->index].pf_moff[pf];
	else
		moff = g_dw_proc_info[hw->index].vf_moff[pf][vf];

	for (vector = 0; vector < vector_total; vector++) {
		found = 0;
		for (i = 0; i < msi_nb; i++) {
			if (msg_phy_addr[vector] == msi_phy_addr[i]) {
				found = 1;
				break;
			}
		}
		if (found)
			continue;
		msi_phy_addr[msi_nb] = msg_phy_addr[vector];
		msi_vir_addr[msi_nb] = msg_vir_addr[vector];
		msi_size[msi_nb] = size[vector];
		msi_nb++;
	}

	for (vector = 0; vector < msi_nb; vector++) {
		phy_addr = msi_phy_addr[vector] - moff;
		vaddr = (uint8_t *)msi_vir_addr[vector] - moff;
		/** Size is constant (CFG_MSIX_OB_SIZE).*/
		if (rte_eal_iova_mode() == RTE_IOVA_VA)
			iova = (uint64_t)vaddr;
		else
			iova = phy_addr;
		ret = rte_fslmc_vfio_mem_dmaunmap(iova, msi_size[vector]);
		if (ret) {
			print_offset = pci_print_offset;
			print_len = sprintf(&pci_info[print_offset],
				"%s vector%d:", "MSI VFIO UNMAP failed",
				vector);
			print_offset += print_len;
			print_len = sprintf(&pci_info[print_offset],
				"size(%lx):va(%p):pa(%lx):iova(%lx)",
				msi_size[vector], vaddr, phy_addr, iova);
			LSX_PCIEP_BUS_WARN("%s", pci_info);
		}
		ret = lsx_pciep_unmap_region(vaddr, msi_size[vector]);
		if (ret) {
			print_offset = pci_print_offset;
			print_len = sprintf(&pci_info[print_offset],
				"%s vector%d:", "MSI address UNMAP failed",
				vector);
			print_offset += print_len;
			print_len = sprintf(&pci_info[print_offset],
				"size(%lx):va(%p)",
				msi_size[vector], vaddr);
			LSX_PCIEP_BUS_WARN("%s", pci_info);
		}
	}

	return 0;
}

static int
pcie_dw_ext_cap_find_pos(struct lsx_pciep_hw_low *hw,
	int pf, int is_vf, int vf, uint16_t ext_cap_id,
	uint32_t *prev_pos, uint32_t *pos, uint32_t *next_pos)
{
	uint32_t cap, next, curr, prev = 0, found = 0;
	struct pcie_ctrl_ext_cap *ext_cap;
	struct pcie_ctrl_ext_cap read;
	struct pcie_ctrl_cfg *cfg;
	char ext_cap_info[256];
	int ret;
	struct pcie_dw_dbi_access access;

	access.access_type = DW_DBI_SIMPLE_ACCESS;
	access.param = -1;
	if (is_vf) {
		access.access_type |= DW_DBI_VIEWPORT_ACCESS;
		access.param = vf;
	}

	if (is_vf) {
		sprintf(ext_cap_info, "PCIe%d:PF%d:VF%d:",
			hw->index, pf, vf);
	} else {
		sprintf(ext_cap_info, "PCIe%d:PF%d:",
			hw->index, pf);
	}

	cfg = (void *)(hw->dbi_vir + pf * hw->dbi_pf_size);
	next = offsetof(struct pcie_ctrl_cfg, aer_ext_hdr);

	do {
		curr = next;
		ext_cap = (void *)((uint8_t *)cfg + curr);
		ret = pcie_dw_read_config_reg(hw, pf, access,
			ext_cap, &read,
			sizeof(struct pcie_ctrl_ext_cap));
		if (ret)
			return ret;
		cap = read.ext_cap_id;
		next = read.next_cap_off;
		LSX_PCIEP_BUS_DBG("%s Ext cap(%04x) at %04x, next:%04x",
			ext_cap_info, cap, curr, next);
		if (cap == ext_cap_id) {
			LSX_PCIEP_BUS_INFO("%s Find Ext cap(%04x) at %04x",
				ext_cap_info, cap, curr);
			found = 1;
			if (prev_pos)
				*prev_pos = prev;
			if (pos)
				*pos = curr;
			if (next_pos)
				*next_pos = next;
			break;
		}
		prev = curr;
	} while (next);

	if (found)
		return 0;

	return -ENODEV;
}

static int
pcie_dw_get_ext_sriov(struct lsx_pciep_hw_low *hw,
	int pf, struct pcie_ctrl_ext_sriov_cap *ext_sriov_cap)
{
	uint16_t vf, rfi;
	uint32_t sriov_start;
	int ret, offset = 0;
	char *sriov_info, *penv;
	char env[1024];

	ret = pcie_dw_ext_cap_find_pos(hw, pf, 0, 0,
		PCI_EXT_CAP_ID_SRIOV,
		NULL, &sriov_start, NULL);
	if (ret)
		return ret;

	ret = pcie_dw_sriov_ext_cap_rw(hw, pf, ext_sriov_cap, sriov_start, 1);
	if (ret)
		return ret;

	sprintf(env,
		"LSX_DW_PCIE%d_PF%d_SRIOV_CAP_DUMP",
		hw->index, pf);
	penv = getenv(env);
	if (!penv || !atoi(penv))
		return 0;

	sriov_info = pcie_dw_malloc(4096);
	if (!sriov_info)
		return -ENOMEM;

	sprintf(sriov_info,
		"PCIe%d:PF:%d SRIOV offset: 0x%x, orig offset: 0x%lx",
		hw->index, pf, sriov_start,
		offsetof(struct pcie_ctrl_cfg, sriov_ext_cap));

	LSX_PCIEP_BUS_INFO("%s", sriov_info);

	offset = sprintf(sriov_info, "PCIe%d:PF:%d SRIOV: ",
		hw->index, pf);
	offset += sprintf(&sriov_info[offset], "Initial VFs: %d, ",
		ext_sriov_cap->init_vf);
	offset += sprintf(&sriov_info[offset], "Total VFs: %d, ",
		ext_sriov_cap->total_vf);
	offset += sprintf(&sriov_info[offset], "Number of VFs: %d,\r\n",
		ext_sriov_cap->number_vf);
	offset += sprintf(&sriov_info[offset], "VF offset: %d, ",
		ext_sriov_cap->first_vf_pos);
	offset += sprintf(&sriov_info[offset], "stride: %d, ",
		ext_sriov_cap->vf_stride);
	offset += sprintf(&sriov_info[offset], "Device ID: %x, ",
		ext_sriov_cap->vf_dev_id);

	LSX_PCIEP_BUS_INFO("%s", sriov_info);

	offset = 0;
	rfi = pcie_dw_route_fun_id(pf, 0, 0, 0, 0);
	offset += sprintf(sriov_info, "PF%d Route: %d\r\n",
			pf, rfi);

	for (vf = 0; vf < ext_sriov_cap->total_vf; vf++) {
		rfi = pcie_dw_route_fun_id(pf, 1, vf,
			ext_sriov_cap->first_vf_pos,
			ext_sriov_cap->vf_stride);
		if ((vf + 1) == ext_sriov_cap->total_vf) {
			offset += sprintf(&sriov_info[offset], "VF%d Route: %d",
				vf, rfi);
			break;
		}
		offset += sprintf(&sriov_info[offset], "VF%d Route: %d, ",
				vf, rfi);
		if (!((vf + 1) % 6))
			offset += sprintf(&sriov_info[offset], "\r\n");
	}
	LSX_PCIEP_BUS_INFO("%s\r\n", sriov_info);

	pcie_dw_free(sriov_info);

	return 0;
}

static int
pcie_dw_set_ext_sriov(struct lsx_pciep_hw_low *hw,
	int pf, struct pcie_ctrl_ext_sriov_cap *sriov_cap)
{
	uint32_t sriov_start;
	int ret;

	ret = pcie_dw_ext_cap_find_pos(hw, pf, 0, 0,
			PCI_EXT_CAP_ID_SRIOV,
			NULL, &sriov_start, NULL);
	if (ret)
		return ret;

	ret = pcie_dw_sriov_ext_cap_rw(hw, pf, sriov_cap,
			sriov_start, 0);
	if (ret)
		return ret;

	return 0;
}

static int
pcie_dw_fun_init(struct lsx_pciep_hw_low *hw,
	int pf, int is_vf, int vf, uint16_t vendor_id,
	uint16_t device_id, uint16_t class_id)
{
	struct pcie_ctrl_cfg *cfg;
	int ret;
	struct pcie_dw_dbi_access access;
	struct pcie_ctrl_ext_sriov_cap ext_sriov_cap;

	access.access_type = DW_DBI_SIMPLE_ACCESS;
	access.param = -1;
	if (is_vf) {
		access.access_type |= DW_DBI_VIEWPORT_ACCESS;
		access.param = vf;
	}

	if (!hw->is_sriov && (pf > PF0_IDX || is_vf)) {
		LSX_PCIEP_BUS_ERR("%s: PCIe%d is NONE-SRIOV",
			__func__, hw->index);
		return -EIO;
	}

	cfg = (void *)(hw->dbi_vir + pf * hw->dbi_pf_size);

	ret = pcie_dw_write_config_reg(hw, pf, access,
		&cfg->vendor_id,
		&vendor_id, sizeof(uint16_t), 1);
	if (ret)
		return ret;
	ret = pcie_dw_write_config_reg(hw, pf, access,
		&cfg->device_id,
		&device_id, sizeof(uint16_t), 1);
	if (ret)
		return ret;
	ret = pcie_dw_write_config_reg(hw, pf, access,
		&cfg->class_id,
		&class_id, sizeof(uint16_t), 1);

	if (is_vf) {
		ret = pcie_dw_get_ext_sriov(hw, pf, &ext_sriov_cap);
		if (ret)
			return ret;
		ext_sriov_cap.vf_dev_id = device_id;
		ret = pcie_dw_set_ext_sriov(hw, pf, &ext_sriov_cap);
		if (ret)
			return ret;
	}

	return ret;
}

static int
pcie_dw_set_ext_sriov_env(struct lsx_pciep_hw_low *hw,
	int pf)
{
	uint32_t vf_bar;
	int ret, set = 0, bar;
	struct pcie_ctrl_ext_sriov_cap sriov_cap_data;
	char *penv;
	char env[1024];
	uint64_t size;

	ret = pcie_dw_get_ext_sriov(hw, pf, &sriov_cap_data);
	if (ret)
		return ret;

	sprintf(env, "LSX_DW_PCIE%d_PF%d_INIT_VF", hw->index, pf);
	penv = getenv(env);
	if (penv) {
		sriov_cap_data.init_vf = atoi(penv);
		set = 1;
	}

	sprintf(env, "LSX_DW_PCIE%d_PF%d_TOTAL_VF", hw->index, pf);
	penv = getenv(env);
	if (penv) {
		sriov_cap_data.total_vf = atoi(penv);
		set = 1;
	}

	sprintf(env, "LSX_DW_PCIE%d_PF%d_VF_OFFSET", hw->index, pf);
	penv = getenv(env);
	if (penv) {
		sriov_cap_data.first_vf_pos = atoi(penv);
		set = 1;
	}

	sprintf(env, "LSX_DW_PCIE%d_PF%d_VF_STRIDE", hw->index, pf);
	penv = getenv(env);
	if (penv) {
		sriov_cap_data.vf_stride = atoi(penv);
		set = 1;
	}

	sprintf(env, "LSX_DW_PCIE%d_PF%d_VF_DEV_ID", hw->index, pf);
	penv = getenv(env);
	if (penv) {
		sriov_cap_data.vf_dev_id = strtol(penv, 0, 16);
		set = 1;
	}

	if (set) {
		ret = pcie_dw_set_ext_sriov(hw, pf, &sriov_cap_data);
		if (ret)
			return ret;
	}

	for (vf_bar = 0; vf_bar < PCI_MAX_RESOURCE; vf_bar++) {
		size = 0;
		if (pcie_dw_using_32b_bar(vf_bar))
			bar = vf_bar;
		else
			bar = lsx_pciep_32bar_to_64bar(vf_bar);

		if (bar >= 0) {
			ret = pcie_dw_get_bar_size(hw, pf, 1,
				bar, !pcie_dw_using_32b_bar(vf_bar), &size);
			if (!ret && (size < (LSX_PCIEP_DW_WIN_MASK + 1) ||
				size > LSX_PCIE_DW_MAX_BAR_SIZE)) {
				ret = pcie_dw_set_bar_size(hw, pf, 1,
					bar, LSX_PCIEP_DW_WIN_MASK + 1,
					!pcie_dw_using_32b_bar(vf_bar));
				if (ret)
					return ret;
			}
		}
	}

	return 0;
}

static void
pcie_dw_ext_cap_list_dump(struct lsx_pciep_hw_low *hw,
	int pf, int is_vf, int vf)
{
	uint32_t cap, next, curr, ret;
	struct pcie_ctrl_cfg *cfg;
	struct pcie_ctrl_ext_cap *ext_cap;
	struct pcie_ctrl_ext_cap ext_cap_data;
	char ext_cap_info[256];
	struct pcie_dw_dbi_access access;

	access.access_type = DW_DBI_SIMPLE_ACCESS;
	access.param = -1;
	if (is_vf) {
		access.access_type |= DW_DBI_VIEWPORT_ACCESS;
		access.param = vf;
	}

	cfg = (void *)(hw->dbi_vir + pf * hw->dbi_pf_size);
	curr = offsetof(struct pcie_ctrl_cfg, aer_ext_hdr);

	if (is_vf) {
		sprintf(ext_cap_info, "PCIe%d:PF%d:VF%d:",
			hw->index, pf, vf);
	} else {
		sprintf(ext_cap_info, "PCIe%d:PF%d:",
			hw->index, pf);
	}

	do {
		ext_cap = (void *)((uint8_t *)cfg + curr);
		ret = pcie_dw_read_config_reg(hw, pf, access,
			ext_cap, &ext_cap_data,
			sizeof(struct pcie_ctrl_ext_cap));
		if (ret)
			return;
		cap = ext_cap_data.ext_cap_id;
		next = ext_cap_data.next_cap_off;
		LSX_PCIEP_BUS_INFO("%s Ext cap(%04x) at %04x, next:%04x",
			ext_cap_info, cap, curr, next);
		curr = next;
	} while (curr);
}

static int
pcie_dw_ext_cap_add(struct lsx_pciep_hw_low *hw,
	int pf, int is_vf, int vf, uint16_t cap_add)
{
	int ret, idx_prev, idx, found = 0;
	struct pcie_ctrl_cfg *cfg;
	char ext_cap_info[256];
	uint32_t i;
	struct pcie_ctrl_ext_cap ext_cap;
	struct pcie_dw_dbi_access access;
	const struct pcie_ctrl_ext_cap *reset_ext_cap;
	uint64_t ext_cap_size;

	access.access_type = DW_DBI_SIMPLE_ACCESS;
	access.param = -1;
	if (is_vf) {
		access.access_type |= DW_DBI_VIEWPORT_ACCESS;
		access.param = vf;
	}

	if (is_vf) {
		reset_ext_cap = s_vf_reset_ext_cap;
		ext_cap_size = DW_ARRAY_SIZE(s_vf_reset_ext_cap);
		sprintf(ext_cap_info, "PCIe%d:PF%d:VF%d:",
			hw->index, pf, vf);
	} else {
		reset_ext_cap = s_pf_reset_ext_cap;
		ext_cap_size = DW_ARRAY_SIZE(s_pf_reset_ext_cap);
		sprintf(ext_cap_info, "PCIe%d:PF%d:",
			hw->index, pf);
	}

	cfg = (void *)(hw->dbi_vir + pf * hw->dbi_pf_size);

	for (i = 0; i < ext_cap_size; i++) {
		if (reset_ext_cap[i].next_cap_off) {
			idx = reset_ext_cap[i].next_cap_off;
			RTE_ASSERT(!(idx % sizeof(struct pcie_ctrl_ext_cap)));
			idx = idx / sizeof(struct pcie_ctrl_ext_cap);
			if (reset_ext_cap[idx].ext_cap_id == cap_add) {
				idx_prev = i * sizeof(struct pcie_ctrl_ext_cap);
				idx = idx * sizeof(struct pcie_ctrl_ext_cap);
				found = 1;
				break;
			}
		}
	}

	if (!found)
		return -ENODEV;

	ret = pcie_dw_read_config_reg(hw, pf, access,
		(uint8_t *)cfg + idx_prev, &ext_cap,
		sizeof(struct pcie_ctrl_ext_cap));

	ret = pcie_dw_write_config_reg(hw, pf, access,
		(uint8_t *)cfg + idx,
		&reset_ext_cap[idx / sizeof(struct pcie_ctrl_ext_cap)],
		sizeof(struct pcie_ctrl_ext_cap), 1);
	if (ret)
		return ret;

	ret = pcie_dw_write_config_reg(hw, pf, access,
		(uint8_t *)cfg + idx_prev, &ext_cap,
		sizeof(struct pcie_ctrl_ext_cap), 1);

	return ret;
}

static int
pcie_dw_ext_cap_remove(struct lsx_pciep_hw_low *hw,
	int pf, int is_vf, int vf, uint16_t cap_remove)
{
	int ret;
	struct pcie_ctrl_ext_cap *ext_cap, *prev_ext_cap = NULL;
	struct pcie_ctrl_ext_cap ext_cap_data;
	struct pcie_ctrl_cfg *cfg;
	char ext_cap_info[256];
	uint32_t remove_pos, prev_pos, next_pos;
	struct pcie_dw_dbi_access access;

	access.access_type = DW_DBI_SIMPLE_ACCESS;
	access.param = -1;
	if (is_vf) {
		access.access_type |= DW_DBI_VIEWPORT_ACCESS;
		access.param = vf;
	}

	if (is_vf) {
		sprintf(ext_cap_info, "PCIe%d:PF%d:VF%d:",
			hw->index, pf, vf);
	} else {
		sprintf(ext_cap_info, "PCIe%d:PF%d:",
			hw->index, pf);
	}

	ret = pcie_dw_ext_cap_find_pos(hw, pf, is_vf, vf,
		cap_remove, &prev_pos, &remove_pos, &next_pos);
	if (ret) {
		LSX_PCIEP_BUS_WARN("%s Ext cap(%04x) NOT found",
			ext_cap_info, cap_remove);
		return ret;
	}

	cfg = (void *)(hw->dbi_vir + pf * hw->dbi_pf_size);
	ext_cap = (void *)((uint8_t *)cfg + remove_pos);

	if (prev_pos) {
		prev_ext_cap = (void *)((uint8_t *)cfg + prev_pos);
		ret = pcie_dw_read_config_reg(hw, pf, access,
			prev_ext_cap, &ext_cap_data,
			sizeof(struct pcie_ctrl_ext_cap));
		if (ret)
			return ret;
		ext_cap_data.next_cap_off = next_pos;
		ret = pcie_dw_write_config_reg(hw, pf, access,
			prev_ext_cap, &ext_cap_data,
			sizeof(struct pcie_ctrl_ext_cap), 1);
		if (ret)
			return ret;
	}

	ret = pcie_dw_read_config_reg(hw, pf, access,
		ext_cap, &ext_cap_data,
		sizeof(struct pcie_ctrl_ext_cap));
	if (ret)
		return ret;

	ext_cap_data.next_cap_off = 0;
	ext_cap_data.ext_cap_id = PCI_EXT_CAP_ID_NULL;
	ret = pcie_dw_write_config_reg(hw, pf, access,
		ext_cap,
		&ext_cap_data, sizeof(struct pcie_ctrl_ext_cap), 1);
	if (ret)
		return ret;

	LSX_PCIEP_BUS_INFO("%s Ext cap(%04x) removed, RC need rescan!",
		ext_cap_info, cap_remove);

	return 0;
}

static int
pcie_dw_fun_init_ext(struct lsx_pciep_hw_low *hw,
	int pf, int is_vf, int vf,
	uint16_t sub_vendor_id, uint16_t sub_device_id,
	int sriov_disable, int ari_disable, int ats_disable)
{
	struct pcie_ctrl_cfg *cfg;
	size_t f_ret;
	struct pciep_dw_info *info;
	FILE *f_dw_cfg;
	int ret = 0;
	struct pcie_dw_dbi_access access;

	access.access_type = DW_DBI_SIMPLE_ACCESS;
	access.param = -1;
	if (is_vf) {
		access.access_type |= DW_DBI_VIEWPORT_ACCESS;
		access.param = vf;
	}

	if (!hw->is_sriov && pf > PF0_IDX) {
		LSX_PCIEP_BUS_ERR("%s: PCIe%d is NONE-SRIOV",
			__func__, hw->index);
		return -EIO;
	}

	if (sriov_disable && is_vf) {
		LSX_PCIEP_BUS_ERR("%s: PCIe%d sriov disable in PF",
			__func__, hw->index);
		return -EIO;
	}

	if (pf != PF0_IDX && pf != PF1_IDX) {
		LSX_PCIEP_BUS_ERR("%s: Invalid PF ID(%d)",
			__func__, pf);
		return -EIO;
	}

	rte_spinlock_lock(&s_f_lock);
	f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "rb");
	if (!f_dw_cfg) {
		LSX_PCIEP_BUS_ERR("%s: %s read open failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		rte_spinlock_unlock(&s_f_lock);
		return -ENODEV;
	}

	info = pcie_dw_malloc(sizeof(struct pciep_dw_info));
	if (!info) {
		LSX_PCIEP_BUS_ERR("%s prepare buf for read %s failed",
			__func__,
			PCIEP_DW_GLOBE_INFO_F);
		fclose(f_dw_cfg);
		rte_spinlock_unlock(&s_f_lock);
		return -ENOMEM;
	}

	memset(info, 0, sizeof(struct pciep_dw_info));

	f_ret = fread(info, sizeof(struct pciep_dw_info),
			1, f_dw_cfg);
	fclose(f_dw_cfg);
	if (f_ret != 1) {
		LSX_PCIEP_BUS_ERR("%s: %s read (%ldB) failed (%ld)",
			__func__, PCIEP_DW_GLOBE_INFO_F,
			sizeof(struct pciep_dw_info), f_ret);
		pcie_dw_free(info);
		rte_spinlock_unlock(&s_f_lock);
		return -EIO;
	}

	cfg = (void *)(hw->dbi_vir + pf * hw->dbi_pf_size);

	if (sriov_disable && hw->is_sriov && !is_vf) {
		ret = pcie_dw_ext_cap_remove(hw, pf, is_vf, vf,
			PCI_EXT_CAP_ID_SRIOV);
		if (ret)
			LSX_PCIEP_BUS_WARN("SRIOV ext cap already disabled?");
	} else if (!sriov_disable && hw->is_sriov && !is_vf) {
		ret = pcie_dw_ext_cap_add(hw, pf, is_vf, vf,
			PCI_EXT_CAP_ID_SRIOV);
		if (ret)
			LSX_PCIEP_BUS_WARN("SRIOV ext cap not support?");
	}

	if (ari_disable) {
		ret = pcie_dw_ext_cap_remove(hw, pf, is_vf, vf,
			PCI_EXT_CAP_ID_ARI);
		if (ret)
			LSX_PCIEP_BUS_WARN("ARI ext cap already disabled?");
	} else {
		ret = pcie_dw_ext_cap_add(hw, pf, is_vf, vf,
			PCI_EXT_CAP_ID_ARI);
		if (ret)
			LSX_PCIEP_BUS_WARN("ARI ext cap not support?");
	}

	if (ats_disable) {
		ret = pcie_dw_ext_cap_remove(hw, pf, is_vf, vf,
			PCI_EXT_CAP_ID_ATS);
		if (ret)
			LSX_PCIEP_BUS_WARN("ATS ext cap already disabled?");
	} else {
		ret = pcie_dw_ext_cap_add(hw, pf, is_vf, vf,
			PCI_EXT_CAP_ID_ATS);
		if (ret)
			LSX_PCIEP_BUS_WARN("ATS ext cap not support?");
	}

	pcie_dw_ext_cap_list_dump(hw, pf, is_vf, vf);

	if (hw->is_sriov && !sriov_disable && !is_vf) {
		ret = pcie_dw_set_ext_sriov_env(hw, pf);
		if (ret) {
			LSX_PCIEP_BUS_ERR("%s Set Ext SRIOV failed(%d)",
				__func__, ret);
			goto err_ret2;
		}
	}

	if (hw->is_sriov) {
		ret = pcie_dw_msix_cap_init(hw, pf, is_vf, vf);
		if (ret) {
			LSX_PCIEP_BUS_ERR("%s MSIx cap init failed(%d)",
				__func__, ret);
			goto err_ret2;
		}
	}

	f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "wb");
	if (!f_dw_cfg) {
		LSX_PCIEP_BUS_ERR("%s: %s write open failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		ret = -ENODEV;
		goto err_ret2;
	}
	f_ret = fwrite(info, sizeof(struct pciep_dw_info),
			1, f_dw_cfg);
	if (f_ret != 1) {
		LSX_PCIEP_BUS_ERR("%s: %s write failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		ret = -EIO;
		goto err_ret1;
	}

	if (sub_vendor_id && sub_vendor_id != RTE_PCI_ANY_ID) {
		ret = pcie_dw_write_config_reg(hw, pf, access,
			&cfg->sub_vendor_id,
			&sub_vendor_id, sizeof(uint16_t), 1);
		if (ret)
			return ret;
	}
	if (sub_device_id && sub_device_id != RTE_PCI_ANY_ID) {
		ret = pcie_dw_write_config_reg(hw, pf, access,
			&cfg->sub_device_id,
			&sub_device_id, sizeof(uint16_t), 1);
		if (ret)
			return ret;
	}

err_ret1:
	fclose(f_dw_cfg);

err_ret2:
	pcie_dw_free(info);
	rte_spinlock_unlock(&s_f_lock);

	return ret;
}



static uint64_t
pcie_dw_ob_unmapped(struct lsx_pciep_hw_low *hw)
{
	FILE *f_dw_cfg;
	size_t f_ret;
	uint64_t offset, cpu_addr;
	struct pciep_dw_info *info;

	rte_spinlock_lock(&s_f_lock);
	f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "rb");
	if (!f_dw_cfg) {
		LSX_PCIEP_BUS_ERR("%s: %s read open failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		rte_spinlock_unlock(&s_f_lock);
		return 0;
	}

	info = pcie_dw_malloc(sizeof(struct pciep_dw_info));
	if (!info) {
		LSX_PCIEP_BUS_ERR("%s prepare buf for read %s failed",
			__func__,
			PCIEP_DW_GLOBE_INFO_F);
		fclose(f_dw_cfg);
		rte_spinlock_unlock(&s_f_lock);
		return 0;
	}

	memset(info, 0, sizeof(struct pciep_dw_info));

	f_ret = fread(info, sizeof(struct pciep_dw_info),
			1, f_dw_cfg);
	fclose(f_dw_cfg);
	if (f_ret != 1) {
		LSX_PCIEP_BUS_ERR("%s: %s read failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		pcie_dw_free(info);
		rte_spinlock_unlock(&s_f_lock);
		return 0;
	}

	cpu_addr = info->ob_base[hw->index];
	offset = info->ob_offset[hw->index];

	pcie_dw_free(info);
	rte_spinlock_unlock(&s_f_lock);

	return cpu_addr + offset;
}

static void
pcie_dw_config(struct lsx_pciep_hw_low *hw)
{
	FILE *f_dw_cfg;
	size_t f_ret, bar_max;
	uint8_t pcie_id = hw->index;
	struct pciep_dw_info *info;
	char *penv;
	char env[1024];

	rte_spinlock_lock(&s_f_lock);

	info = pcie_dw_malloc(sizeof(struct pciep_dw_info));
	if (!info) {
		LSX_PCIEP_BUS_ERR("%s prepare buf for read %s failed",
			__func__,
			PCIEP_DW_GLOBE_INFO_F);
		return;
	}

	memset(info, 0, sizeof(struct pciep_dw_info));

	f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "rb");
	if (f_dw_cfg) {
		f_ret = fread(info, sizeof(struct pciep_dw_info),
			1, f_dw_cfg);
		if (f_ret != 1) {
			LSX_PCIEP_BUS_ERR("%s: %s read failed",
				__func__, PCIEP_DW_GLOBE_INFO_F);
			fclose(f_dw_cfg);
			pcie_dw_free(info);
			rte_spinlock_unlock(&s_f_lock);
			return;
		}
		fclose(f_dw_cfg);
	} else {
		sprintf(env, "LSX_DW_PCIE%d_BAR_MAX_SIZE", hw->index);
		penv = getenv(env);
		if (penv)
			bar_max = atoi(penv);
		else
			bar_max = LSX_PCIE_DW_MAX_BAR_SIZE;
		info->dbi_phy[pcie_id] = hw->dbi_phy;
		info->ob_base[pcie_id] = hw->out_base;
		info->ob_max_size = CFG_32G_SIZE;
		info->ob_win_max_size = CFG_4G_SIZE;
		info->win_mask = LSX_PCIEP_DW_WIN_MASK;
		info->win_max = bar_max;
		s_f_create = 1;
	}

	hw->dbi_phy = info->dbi_phy[pcie_id];
	hw->out_base = info->ob_base[pcie_id];
	hw->out_size = info->ob_max_size;
	hw->out_win_max_size = info->ob_win_max_size;
	hw->win_mask = info->win_mask;
	hw->win_max = info->win_max;

	f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "wb");
	f_ret = fwrite(info, sizeof(struct pciep_dw_info),
		1, f_dw_cfg);
	if (f_ret != 1) {
		LSX_PCIEP_BUS_ERR("%s: %s write failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
	}
	fclose(f_dw_cfg);
	pcie_dw_free(info);
	rte_spinlock_unlock(&s_f_lock);
}

static int
pcie_dw_info_empty(struct pciep_dw_info *info)
{
	int i, j;
	int empty = 1;

	for (i = 0; i < LSX_MAX_PCIE_NB; i++) {
		for (j = 0; j < LSX_PCIE_DW_OB_WINS_NUM; j++) {
			if (info->ob_win_used[i][j]) {
				empty = 0;
				goto finish_check;
			}
			if (info->priv_ob_win[i][j].using) {
				empty = 0;
				goto finish_check;
			}
			if (info->shared_ob_win[i][j].ref_count) {
				empty = 0;
				goto finish_check;
			}
		}
		for (j = 0; j < LSX_PCIE_DW_IB_WINS_NUM; j++) {
			if (info->ib_win_used[i][j]) {
				empty = 0;
				goto finish_check;
			}
		}
	}

finish_check:
	return empty;
}

static int
pcie_dw_proc_info_empty(struct lsx_pciep_hw_low *hw)
{
	struct pciep_dw_proc_info *proc_info;

	proc_info = &g_dw_proc_info[hw->index];
	if (!proc_info->ob_nb && !proc_info->ob_shared_nb &&
		!proc_info->ib_nb)
		return 1;

	return 0;
}

static void
pcie_dw_deconfig(struct lsx_pciep_hw_low *hw)
{
	int i, idx, j, ret;
	size_t f_ret;
	FILE *f_dw_cfg;
	struct pciep_dw_proc_info *proc_info;
	struct pciep_dw_info *info;
	uint64_t phy_start;

	rte_spinlock_lock(&s_f_lock);
	if (pcie_dw_proc_info_empty(hw)) {
		if (!s_f_create) {
			rte_spinlock_unlock(&s_f_lock);
			return;
		}
	}

	f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "rb");
	if (!f_dw_cfg) {
		if (pcie_dw_proc_info_empty(hw))
			return;
		LSX_PCIEP_BUS_ERR("%s: %s read open failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		rte_spinlock_unlock(&s_f_lock);
		return;
	}

	info = pcie_dw_malloc(sizeof(struct pciep_dw_info));
	if (!info) {
		LSX_PCIEP_BUS_ERR("%s prepare buf for read %s failed",
			__func__,
			PCIEP_DW_GLOBE_INFO_F);
		fclose(f_dw_cfg);
		rte_spinlock_unlock(&s_f_lock);
		return;
	}

	memset(info, 0, sizeof(struct pciep_dw_info));

	f_ret = fread(info, sizeof(struct pciep_dw_info),
			1, f_dw_cfg);
	fclose(f_dw_cfg);
	if (f_ret != 1) {
		LSX_PCIEP_BUS_ERR("%s: %s read (%ldB) failed (%ld)",
			__func__, PCIEP_DW_GLOBE_INFO_F,
			sizeof(struct pciep_dw_info), f_ret);
		pcie_dw_free(info);
		rte_spinlock_unlock(&s_f_lock);
		return;
	}

	proc_info = &g_dw_proc_info[hw->index];
	for (i = 0; i < proc_info->ob_nb; i++) {
		idx = proc_info->ob_idx[i];
		phy_start = proc_info->ob_start[i];
		info->ob_win_used[hw->index][idx] = 0;
		for (j = 0; j < LSX_PCIE_DW_OB_WINS_NUM; j++) {
			if (info->priv_ob_win[hw->index][j].using &&
				info->priv_ob_win[hw->index][j].phy_start ==
				phy_start) {
				info->priv_ob_win[hw->index][j].using = 0;
			}
		}
	}
	for (i = 0; i < proc_info->ib_nb; i++) {
		idx = proc_info->ib_idx[i];
		info->ib_win_used[hw->index][idx] = 0;
	}

	for (i = 0; i < proc_info->ob_shared_nb; i++) {
		idx = proc_info->ob_shared_idx[i];
		info->shared_ob_win[hw->index][idx].ref_count--;
	}

	memset(proc_info, 0, sizeof(struct pciep_dw_proc_info));
	if (pcie_dw_info_empty(info)) {
		if (access(PCIEP_DW_GLOBE_INFO_F, F_OK) != -1) {
			ret = remove(PCIEP_DW_GLOBE_INFO_F);
			if (ret) {
				LSX_PCIEP_BUS_ERR("%s removed failed",
					PCIEP_DW_GLOBE_INFO_F);
			}
		}
		pcie_dw_free(info);
		rte_spinlock_unlock(&s_f_lock);
		return;
	}

	f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "wb");
	if (!f_dw_cfg) {
		LSX_PCIEP_BUS_ERR("%s: %s write open failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		pcie_dw_free(info);
		rte_spinlock_unlock(&s_f_lock);
		return;
	}

	f_ret = fwrite(info, sizeof(struct pciep_dw_info),
		1, f_dw_cfg);
	if (f_ret != 1) {
		LSX_PCIEP_BUS_ERR("%s write failed",
			PCIEP_DW_GLOBE_INFO_F);
	}
	fclose(f_dw_cfg);
	pcie_dw_free(info);
	rte_spinlock_unlock(&s_f_lock);
}

static int
pcie_dw_is_sriov(struct lsx_pciep_hw_low *hw)
{
	struct pcie_ctrl_cfg *cfg;
	uint32_t dev_cap_reg = 0;
	int ret;
	struct pcie_dw_dbi_access access;

	access.access_type = DW_DBI_SIMPLE_ACCESS;
	access.param = -1;

	cfg = (void *)hw->dbi_vir;
	ret = pcie_dw_read_config_reg(hw, 0, access,
		&cfg->dev_cap,
		&dev_cap_reg, sizeof(uint32_t));
	if (ret)
		return ret;
	if (dev_cap_reg & PCI_FUN_RESET_SRIOV_CAP)
		hw->is_sriov = 1;
	else
		hw->is_sriov = 0;
	LSX_PCIEP_BUS_INFO("PCIe%d is %s controller",
		hw->index,
		hw->is_sriov ? "SRIOV" : "NONE SRIOV");

	return hw->is_sriov;
}

static struct lsx_pciep_ops pcie_dw_ops = {
	.pcie_config = pcie_dw_config,
	.pcie_deconfig = pcie_dw_deconfig,
	.pcie_fun_init = pcie_dw_fun_init,
	.pcie_fun_init_ext = pcie_dw_fun_init_ext,
	.pcie_disable_ob_win = pcie_dw_disable_ob_win,
	.pcie_disable_ib_win = pcie_dw_disable_ib_win,
	.pcie_map_ob_win = pcie_dw_map_ob_win,
	.pcie_cfg_ob_win = pcie_dw_set_ob_win,
	.pcie_cfg_ib_win = pcie_dw_set_ib_win,
	.pcie_msix_cfg = pcie_dw_msix_cfg,
	.pcie_msix_decfg = pcie_dw_msix_decfg,
	.pcie_get_ob_unmapped = pcie_dw_ob_unmapped,
	.pcie_is_sriov = pcie_dw_is_sriov,
};

struct lsx_pciep_ops *lsx_pciep_get_dw_ops(void)
{
	return &pcie_dw_ops;
}

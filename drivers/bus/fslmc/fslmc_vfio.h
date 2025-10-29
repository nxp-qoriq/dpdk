/* SPDX-License-Identifier: BSD-3-Clause
 *
 *   Copyright (c) 2015-2016 Freescale Semiconductor, Inc. All rights reserved.
 *   Copyright 2016,2019-2023,2025 NXP
 *
 */

#ifndef _FSLMC_VFIO_H_
#define _FSLMC_VFIO_H_

#include <rte_compat.h>
#include <rte_vfio.h>
#include <rte_interrupts.h>

#ifndef __hot
#define __hot __attribute__((hot))
#endif

/* Pathname of FSL-MC devices directory. */
#define SYSFS_FSL_MC_DEVICES	"/sys/bus/fsl-mc/devices"
#define DPAA2_MC_DPNI_DEVID	7
#define DPAA2_MC_DPSECI_DEVID	3
#define DPAA2_MC_DPCON_DEVID	5
#define DPAA2_MC_DPIO_DEVID	9
#define DPAA2_MC_DPBP_DEVID	10
#define DPAA2_MC_DPCI_DEVID	11

struct fslmc_vfio_device {
	LIST_ENTRY(fslmc_vfio_device) next;
	int fd; /* fslmc root container device ?? */
	int index; /*index of child object */
	char dev_name[64];
	struct fslmc_vfio_device *child; /* Child object */
};

struct fslmc_vfio_group {
	LIST_ENTRY(fslmc_vfio_group) next;
	int fd; /* /dev/vfio/"groupid" */
	int groupid;
	int connected;
	char group_name[64]; /* dprc.x*/
	int iommu_type;
	LIST_HEAD(, fslmc_vfio_device) vfio_devices;
};

struct fslmc_vfio_container {
	int fd; /* /dev/vfio/vfio */
	LIST_HEAD(, fslmc_vfio_group) groups;
};

extern char *fslmc_container;

extern uint32_t dpaa2_svr_family;
extern uint32_t dpaa2_dqrr_size;
extern uint32_t dpaa2_eqcr_size;
extern uint32_t dpaa2_cluster_base;
extern uint32_t dpaa2_cluster_size;

#define DPAA2_SVR_MASK 0xffff0000

#define SVR_LS1080A	0x87030000
#define SVR_LS2080A	0x87010000
#define SVR_LS2088A	0x87090000
#define SVR_LX2160A	0x87360000

#define RTE_FSL_MC_REV(major, minor, revision) \
	((((uint64_t)(major)) << 32) + (((uint64_t)(major)) << 16) + (revision))

__rte_internal
int rte_dpaa2_intr_enable(struct rte_intr_handle *intr_handle, int index);

__rte_internal
int rte_dpaa2_intr_disable(struct rte_intr_handle *intr_handle, int index);

int rte_dpaa2_vfio_setup_intr(struct rte_intr_handle *intr_handle,
			      int vfio_dev_fd,
			      int num_irqs);

int fslmc_vfio_setup_group(void);
int fslmc_vfio_process_group(void);
int fslmc_vfio_close_group(void);
int fslmc_get_container_group(const char *group_name, int *gropuid);
int fslmc_vfio_dmamap(void);
int fslmc_vfio_core_cluster_sdest(uint32_t cpu_id);

#endif /* _FSLMC_VFIO_H_ */

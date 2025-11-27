/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#include "compat.h"

#define NXP_USMEM_DEVICE "nxp_usmem"
#define NXP_RESERVE_MEMORY "resv_mem"

/* sizes */
#define DPAAX_SIZE_256KB 0x40000
#define DPAAX_SIZE_2MB 0x200000

/* IOCTLS */
enum nxp_mem_cp {
	NXP_CP_DEFAULT = 0,
	NXP_CP_WC,
	NXP_CP_WB,
	NXP_CP_WT
};

#define IOCTL_ALLOC_CHUNKS _IOWR('N', 1, struct nxp_usmem_reserve)
#define IOCTL_GET_MEM_INFO _IOR('N', 2, struct nxp_usmem_info)
#define IOCTL_RELEASE_CHUNKS _IOWR('N', 3, struct nxp_usmem_reserve)

struct nxp_usmem_reserve {
	int chunks;
	unsigned long offset;
	enum nxp_mem_cp mem_cp;
};

struct nxp_usmem_info {
	unsigned long phys_base;
	unsigned long chunk_size;
	unsigned long total_size;
	unsigned long free_chunks;
};
/* IOCTLS end */

struct dpaax_usmem_ctx {
	int fd;
};

struct dpaax_usmem_alloc {
	uint64_t request_mem; /* input */
	uint64_t virt_addr;
	uint64_t phy_addr;
	uint64_t size;
	struct nxp_usmem_reserve res;
};

/* APIs are not thread safe */

/* Allocate a reserved memory context for managing reserved memory allocations.
 * This context must be released after use by calling dpaax_release_reserve_memctx().
 * The caller is responsible for freeing the context once all operations are complete.
 */
__rte_internal
int
dpaax_alloc_reserve_memctx(const char *device_name, struct dpaax_usmem_ctx *ctx);

/* Get current reserve memory information */
__rte_internal
int
dpaax_get_reserve_meminfo(struct dpaax_usmem_ctx *ctx, struct nxp_usmem_info *info);

/* Allocate reserve memory. Memory will be allocated in chunks*/
__rte_internal
int
dpaax_alloc_reserve_memory(struct dpaax_usmem_ctx *ctx, struct dpaax_usmem_alloc *alloc);

/* Release reserved memory */
__rte_internal
void
dpaax_release_reserve_memory(struct dpaax_usmem_ctx *ctx, struct dpaax_usmem_alloc *alloc);

/* Release reserved memory context */
__rte_internal
void
dpaax_release_reserve_memctx(struct dpaax_usmem_ctx *ctx);

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#include "dpaax_usermem.h"
#include "dpaax_logs.h"

#include <sys/ioctl.h>

#define DPAAX_DEVICE_FILE_BASE "/dev/"
#define DPAAX_DEVICE_PHYADDR_BASE "/sys/class/"

int
dpaax_alloc_reserve_memctx(const char *device_name, struct dpaax_usmem_ctx *ctx)
{
	int fd;
	char device_path[64];

	if (ctx == NULL || device_name == NULL)
		return -1;

	snprintf(device_path, sizeof(device_path),
		"%s%s", DPAAX_DEVICE_FILE_BASE, device_name);

	fd = open(device_path, O_RDWR | O_SYNC);
	if (fd < 0) {
		DPAAX_LOG(ERR, "Failed to open device file %s, error = %s",
				device_name, strerror(errno));
		return -1;
	}
	ctx->fd = fd;

	return 0;
}

void
dpaax_release_reserve_memctx(struct dpaax_usmem_ctx *ctx)
{
	if (ctx && ctx->fd >= 0) {
		close(ctx->fd);
		ctx->fd = -1;
	}
}

int
dpaax_get_reserve_meminfo(struct dpaax_usmem_ctx *ctx, struct nxp_usmem_info *info)
{
	int ret;

	if (info == NULL)
		return -1;

	if (ctx == NULL || ctx->fd < 0)
		return -1;

	ret = ioctl(ctx->fd, IOCTL_GET_MEM_INFO, info);
	if (ret) {
		DPAAX_LOG(ERR, "Failed to get reserve memory info for device FD %d, err = %s",
				ctx->fd, strerror(errno));
		return -1;
	}

	return 0;
}

int
dpaax_alloc_reserve_memory(struct dpaax_usmem_ctx *ctx, struct dpaax_usmem_alloc *alloc)
{
	int ret;
	uint64_t aligned;
	struct nxp_usmem_info info = {0};
	void *mem_addr;

	if (alloc == NULL)
		return -1;

	if (ctx == NULL || ctx->fd < 0)
		return -1;

	ret = ioctl(ctx->fd, IOCTL_GET_MEM_INFO, &info);
	if (ret) {
		DPAAX_LOG(ERR, "Failed to get reserve memory info for device fd = %d, err = %s",
				ctx->fd, strerror(errno));
		return -1;
	}

	if (alloc->request_mem == 0 || alloc->request_mem > info.total_size) {
		DPAAX_LOG(ERR, "Invalid requested memory size = 0x%" PRIx64
			       " total reserve memory size 0x%lx",
			       alloc->request_mem, info.total_size);
		return -1;
	}
	aligned = RTE_ALIGN_CEIL(alloc->request_mem, info.chunk_size);
	alloc->res.chunks = aligned / info.chunk_size;

	if (alloc->res.chunks > (int)info.free_chunks) {
		DPAAX_LOG(ERR, "Not enough memory, available chunks = %lu, chunk size = 0x%lx",
				info.free_chunks, info.chunk_size);
		return -1;
	}

	ret = ioctl(ctx->fd, IOCTL_ALLOC_CHUNKS, &alloc->res);
	if (ret) {
		DPAAX_LOG(ERR, "Failed to reserve memory chunks %d for device fd = %d, err = %s",
				alloc->res.chunks, ctx->fd, strerror(errno));
		return -1;
	}

	DPAAX_LOG(INFO, "Reserve memory chunks %d for device fd %d at offset = 0%0lx",
			alloc->res.chunks, ctx->fd, alloc->res.offset);

	alloc->size = (uint64_t)alloc->res.chunks * info.chunk_size;
	mem_addr = mmap(NULL, alloc->size, PROT_READ | PROT_WRITE,
			MAP_SHARED, ctx->fd, alloc->res.offset);
	if (mem_addr == MAP_FAILED) {
		DPAAX_LOG(ERR, "Failed to mmap memory of size 0x%" PRIx64 " for device fd = %d, err = %s",
				alloc->size, ctx->fd, strerror(errno));
		ret = ioctl(ctx->fd, IOCTL_RELEASE_CHUNKS, &alloc->res);
		if (ret) {
			DPAAX_LOG(ERR, "Failed to free reserve memory chunks %d for device fd %d, err = %s",
					alloc->res.chunks, ctx->fd, strerror(errno));
		}
		return -1;
	}
	alloc->virt_addr = (uint64_t)(uintptr_t)mem_addr;
	alloc->phy_addr = (uint64_t)info.phys_base + alloc->res.offset;

	return 0;
}

void
dpaax_release_reserve_memory(struct dpaax_usmem_ctx *ctx, struct dpaax_usmem_alloc *alloc)
{
	int ret;

	if (alloc == NULL)
		return;

	if (ctx == NULL || ctx->fd < 0)
		return;

	munmap((void *)(uintptr_t)alloc->virt_addr, alloc->size);

	ret = ioctl(ctx->fd, IOCTL_RELEASE_CHUNKS, &alloc->res);
	if (ret) {
		DPAAX_LOG(ERR, "Failed to free reserve memory chunks %d for device fd %d, err = %s",
				alloc->res.chunks, ctx->fd, strerror(errno));
	}
}

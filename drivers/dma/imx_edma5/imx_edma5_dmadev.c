/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2026 NXP
 */

/*
 * NXP i.MX95 eDMA5 dmadev driver.
 *
 * Exposes an eDMA5 controller instance as a DPDK dmadev. Each configured
 * virtual channel maps 1:1 onto a hardware eDMA5 channel. Memory-to-memory
 * copy and scatter-gather copy are supported using software-initiated
 * single-block transfers programmed through the per-channel 64-bit TCD.
 *
 * The device is bound to userspace through the platform bus (vfio-platform);
 * the device tree node must be released from the kernel fsl-edma driver before
 * it can be used here.
 */

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bus_platform_driver.h>
#include <rte_bitops.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_dmadev_pmd.h>
#include <rte_malloc.h>

#include "imx_edma5_dmadev.h"

#include "imx_edma5_logs.h"

RTE_LOG_REGISTER_DEFAULT(imx_edma5_logtype, INFO);

/* Compatible string for i.MX95 eDMA5 device tree nodes. */
#define IMX_EDMA5_COMPAT		"fsl,imx95-edma5"

/* sysfs base path for platform devices' device-tree nodes. */
#define IMX_EDMA5_SYSFS_DEVICES		"/sys/bus/platform/devices"

/*
 * Read the device-tree "dma-channel-mask" property and return the combined
 * 64-bit mask of reserved hardware channels. The property is a raw binary file
 * of big-endian 32-bit cells: cell[0] covers channels 0-31, cell[1] channels
 * 32-63. A set bit marks a channel owned by another bus master (e.g. SCMI
 * firmware) that must not be accessed. Returns 0 if the property is absent.
 */
static uint64_t
imx_edma5_read_channel_mask(const char *dev_name)
{
	char path[PATH_MAX];
	uint32_t cells[2] = { 0, 0 };
	uint64_t mask = 0;
	size_t n;
	FILE *f;

	snprintf(path, sizeof(path),
		 IMX_EDMA5_SYSFS_DEVICES "/%s/of_node/dma-channel-mask",
		 dev_name);

	f = fopen(path, "rb");
	if (f == NULL)
		return 0;

	n = fread(cells, 1, sizeof(cells), f);
	fclose(f);

	/* Device-tree cells are big-endian regardless of CPU endianness. */
	if (n >= sizeof(uint32_t))
		mask |= rte_be_to_cpu_32(cells[0]);
	if (n >= 2 * sizeof(uint32_t))
		mask |= (uint64_t)rte_be_to_cpu_32(cells[1]) << 32;

	return mask;
}

/* Return the register base of hardware channel n. */
static inline uint8_t *
imx_edma5_chan_base(struct imx_edma5_dev *ed, uint32_t chan)
{
	return ed->reg_base + IMX_EDMA5_CHAN_BASE_OFF +
	       (size_t)chan * IMX_EDMA5_CHAN_STRIDE;
}

static int
imx_edma5_info_get(const struct rte_dma_dev *dev, struct rte_dma_info *dev_info,
		   uint32_t info_sz)
{
	const struct imx_edma5_dev *ed = dev->data->dev_private;

	RTE_SET_USED(info_sz);

	dev_info->dev_capa = RTE_DMA_CAPA_MEM_TO_MEM |
			     RTE_DMA_CAPA_OPS_COPY |
			     RTE_DMA_CAPA_OPS_COPY_SG;
	dev_info->max_vchans = ed->max_vchans;
	dev_info->max_desc = IMX_EDMA5_MAX_DESC;
	dev_info->min_desc = IMX_EDMA5_MIN_DESC;
	dev_info->max_sges = IMX_EDMA5_MAX_SGES;

	return 0;
}

static void imx_edma5_reset_hw_chan(struct imx_edma5_vchan *vc);

static int
imx_edma5_configure(struct rte_dma_dev *dev, const struct rte_dma_conf *conf,
		    uint32_t conf_sz)
{
	struct imx_edma5_dev *ed = dev->data->dev_private;

	RTE_SET_USED(conf_sz);

	if (conf->nb_vchans == 0 || conf->nb_vchans > ed->max_vchans) {
		IMX_EDMA5_LOG(ERR, "Invalid nb_vchans %u (max %u)",
			      conf->nb_vchans, ed->max_vchans);
		return -EINVAL;
	}

	if (ed->vchans == NULL) {
		ed->vchans = rte_zmalloc_socket("imx_edma5_vchans",
				ed->max_vchans * sizeof(struct imx_edma5_vchan),
				RTE_CACHE_LINE_SIZE, dev->data->numa_node);
		if (ed->vchans == NULL) {
			IMX_EDMA5_LOG(ERR, "Failed to alloc vchan array");
			return -ENOMEM;
		}
	} else {
		/* Reconfigure: reset and free every previously configured channel. */
		uint16_t i;

		for (i = 0; i < ed->nb_vchans; i++) {
			struct imx_edma5_vchan *vc = &ed->vchans[i];

			if (!vc->configured)
				continue;
			imx_edma5_reset_hw_chan(vc);
			rte_free(vc->jobs);
			rte_free(vc->sg_tcd_pool);
			memset(vc, 0, sizeof(*vc));
		}
	}

	ed->nb_vchans = conf->nb_vchans;

	return 0;
}

/* Reset a hardware channel to a known idle state. */
static void
imx_edma5_reset_hw_chan(struct imx_edma5_vchan *vc)
{
	uint8_t *ch = vc->ch_regs;
	uint8_t *tcd = vc->tcd_regs;
	uint32_t sbr;

	/*
	 * Disable hardware request and clear latched completion state.
	 * CH_CSR.DONE is write-1-to-clear, so write the DONE bit to clear any
	 * stale completion (e.g. left by the bootloader/kernel driver) while
	 * leaving all other control bits disabled.
	 */
	imx_edma5_write32(ch, IMX_EDMA5_CH_CSR, IMX_EDMA5_CH_CSR_DONE);
	imx_edma5_write32(ch, IMX_EDMA5_CH_ES, IMX_EDMA5_CH_ES_ERR);
	imx_edma5_write32(ch, IMX_EDMA5_CH_INT, IMX_EDMA5_CH_INT_INT);

	/*
	 * Enable the read/write attribute bits in the System Bus Register with a
	 * read-modify-write. The security/privilege attribute bits carried here
	 * come up with a valid reset default that the bus fabric (XRDC) checks
	 * and that must be preserved; a blind write of just RD|WR would clear
	 * them and make the fabric reject the eDMA master transaction.
	 */
	sbr = imx_edma5_read32(ch, IMX_EDMA5_CH_SBR);
	sbr |= IMX_EDMA5_CH_SBR_RD | IMX_EDMA5_CH_SBR_WR;
	imx_edma5_write32(ch, IMX_EDMA5_CH_SBR, sbr);

	/*
	 * Program cache-coherent memory attributes so the eDMA snoops the CPU
	 * caches, matching the Linux fsl-edma driver on a dma-coherent
	 * controller.
	 */
	imx_edma5_write32(ch, IMX_EDMA5_CH_MATTR, IMX_EDMA5_CH_MATTR_COHERENT);

	/* Clear the TCD control/status so the channel is idle. */
	imx_edma5_write16(tcd, IMX_EDMA5_TCD_CSR, 0);
	imx_edma5_write16(tcd, IMX_EDMA5_TCD_CITER, 0);
	imx_edma5_write16(tcd, IMX_EDMA5_TCD_BITER, 0);
}

static int
imx_edma5_vchan_setup(struct rte_dma_dev *dev, uint16_t vchan,
		      const struct rte_dma_vchan_conf *conf,
		      uint32_t conf_sz)
{
	struct imx_edma5_dev *ed = dev->data->dev_private;
	struct imx_edma5_vchan *vc;

	RTE_SET_USED(conf_sz);

	if (vchan >= ed->nb_vchans) {
		IMX_EDMA5_LOG(ERR, "vchan %u out of range", vchan);
		return -EINVAL;
	}

	if (conf->direction != RTE_DMA_DIR_MEM_TO_MEM) {
		IMX_EDMA5_LOG(ERR, "Only mem-to-mem direction supported");
		return -EINVAL;
	}

	if (!rte_is_power_of_2(conf->nb_desc) ||
	    conf->nb_desc < IMX_EDMA5_MIN_DESC ||
	    conf->nb_desc > IMX_EDMA5_MAX_DESC) {
		IMX_EDMA5_LOG(ERR, "nb_desc must be power of 2 in [%u..%u]",
			      IMX_EDMA5_MIN_DESC, IMX_EDMA5_MAX_DESC);
		return -EINVAL;
	}

	vc = &ed->vchans[vchan];

	/* Free previous rings if this vchan is being reconfigured. */
	rte_free(vc->jobs);
	rte_free(vc->sg_tcd_pool);
	memset(vc, 0, sizeof(*vc));

	/*
	 * Map this vchan onto a usable hardware channel. chan_map[] skips
	 * channels reserved by "dma-channel-mask" (channels 0 and 1 on i.MX95).
	 */
	vc->hw_chan = ed->chan_map[vchan];
	vc->ch_regs = imx_edma5_chan_base(ed, vc->hw_chan);
	vc->tcd_regs = vc->ch_regs + IMX_EDMA5_CH_TCD_OFF;
	vc->nb_desc = conf->nb_desc;
	vc->desc_mask = conf->nb_desc - 1;

	vc->jobs = rte_zmalloc_socket("imx_edma5_jobs",
			vc->nb_desc * sizeof(struct imx_edma5_job),
			RTE_CACHE_LINE_SIZE, dev->data->numa_node);
	if (vc->jobs == NULL) {
		IMX_EDMA5_LOG(ERR, "Failed to alloc job ring for vchan %u",
			      vchan);
		return -ENOMEM;
	}

	/* One IMX_EDMA5_SG_TCD_PER_JOB descriptor slice per job ring slot. */
	vc->sg_tcd_pool = rte_zmalloc_socket("imx_edma5_sgtcd",
			(size_t)vc->nb_desc * IMX_EDMA5_SG_TCD_PER_JOB *
				sizeof(struct imx_edma5_hw_tcd64),
			RTE_CACHE_LINE_SIZE, dev->data->numa_node);
	if (vc->sg_tcd_pool == NULL) {
		IMX_EDMA5_LOG(ERR, "Failed to alloc SG TCD pool for vchan %u",
			      vchan);
		rte_free(vc->jobs);
		vc->jobs = NULL;
		return -ENOMEM;
	}
	vc->sg_tcd_iova = rte_malloc_virt2iova(vc->sg_tcd_pool);

	imx_edma5_reset_hw_chan(vc);
	vc->configured = true;

	return 0;
}

static int
imx_edma5_start(struct rte_dma_dev *dev)
{
	struct imx_edma5_dev *ed = dev->data->dev_private;
	uint32_t mp_csr;
	uint16_t i;

	/*
	 * Enable round-robin arbitration with a read-modify-write so GCLC (set
	 * in probe) is preserved; clearing GCLC would re-gate the per-channel
	 * clocks and external-abort any subsequent channel access.
	 */
	mp_csr = imx_edma5_read32(ed->reg_base, IMX_EDMA5_MP_CSR);
	mp_csr |= IMX_EDMA5_MP_CSR_GCLC | IMX_EDMA5_MP_CSR_ERCA;
	imx_edma5_write32(ed->reg_base, IMX_EDMA5_MP_CSR, mp_csr);

	for (i = 0; i < ed->nb_vchans; i++) {
		struct imx_edma5_vchan *vc = &ed->vchans[i];

		if (!vc->configured)
			continue;
		imx_edma5_reset_hw_chan(vc);
		vc->head = 0;
		vc->tail = 0;
		vc->nb_enqueued = 0;
		vc->ridx = 0;
		/* Seed last_idx one step before the first cookie (0). */
		vc->last_idx = UINT16_MAX;
		vc->submitted_count = 0;
		vc->completed_count = 0;
		vc->errors_count = 0;
	}

	return 0;
}

static int
imx_edma5_stop(struct rte_dma_dev *dev)
{
	struct imx_edma5_dev *ed = dev->data->dev_private;
	uint16_t i;

	for (i = 0; i < ed->nb_vchans; i++) {
		struct imx_edma5_vchan *vc = &ed->vchans[i];

		if (vc->configured)
			imx_edma5_reset_hw_chan(vc);
	}

	return 0;
}

static int
imx_edma5_close(struct rte_dma_dev *dev)
{
	struct imx_edma5_dev *ed = dev->data->dev_private;
	uint16_t i;

	if (ed->vchans != NULL) {
		for (i = 0; i < ed->max_vchans; i++) {
			rte_free(ed->vchans[i].jobs);
			rte_free(ed->vchans[i].sg_tcd_pool);
		}
		rte_free(ed->vchans);
		ed->vchans = NULL;
	}

	ed->nb_vchans = 0;

	return 0;
}

/*
 * Encode the largest natural transfer size (SSIZE/DSIZE) usable for a given
 * source, destination and length. The address must be aligned to the transfer
 * size and the byte count must be a multiple of it.
 */
static uint16_t
imx_edma5_calc_attr(uint64_t src, uint64_t dst, uint32_t len)
{
	uint32_t sz = IMX_EDMA5_TCD_SIZE_1B;

	if (((src | dst | len) & 0x1F) == 0)
		sz = IMX_EDMA5_TCD_SIZE_32B;
	else if (((src | dst | len) & 0xF) == 0)
		sz = IMX_EDMA5_TCD_SIZE_16B;
	else if (((src | dst | len) & 0x7) == 0)
		sz = IMX_EDMA5_TCD_SIZE_8B;
	else if (((src | dst | len) & 0x3) == 0)
		sz = IMX_EDMA5_TCD_SIZE_4B;
	else if (((src | dst | len) & 0x1) == 0)
		sz = IMX_EDMA5_TCD_SIZE_2B;

	return IMX_EDMA5_TCD_ATTR_SSIZE(sz) | IMX_EDMA5_TCD_ATTR_DSIZE(sz);
}

/*
 * Program the channel TCD for a single-block copy: one minor loop of "len"
 * bytes with a major count of 1. Completion is polled via CH_CSR.DONE.
 */
static inline void
imx_edma5_program_copy(struct imx_edma5_vchan *vc, uint64_t src, uint64_t dst,
		       uint32_t len)
{
	uint8_t *tcd = vc->tcd_regs;
	uint16_t attr = imx_edma5_calc_attr(src, dst, len);

	imx_edma5_write64(tcd, IMX_EDMA5_TCD_SADDR, src);
	imx_edma5_write64(tcd, IMX_EDMA5_TCD_DADDR, dst);
	imx_edma5_write16(tcd, IMX_EDMA5_TCD_ATTR, attr);
	imx_edma5_write16(tcd, IMX_EDMA5_TCD_SOFF,
			  (uint16_t)(1u << IMX_EDMA5_TCD_ATTR_GET_SSIZE(attr)));
	imx_edma5_write16(tcd, IMX_EDMA5_TCD_DOFF,
			  (uint16_t)(1u << IMX_EDMA5_TCD_ATTR_GET_DSIZE(attr)));
	imx_edma5_write32(tcd, IMX_EDMA5_TCD_NBYTES, len);
	imx_edma5_write64(tcd, IMX_EDMA5_TCD_SLAST, 0);
	imx_edma5_write64(tcd, IMX_EDMA5_TCD_DLAST_SGA, 0);
	imx_edma5_write16(tcd, IMX_EDMA5_TCD_CITER, 1);
	imx_edma5_write16(tcd, IMX_EDMA5_TCD_BITER, 1);
	/* Clear CSR so no scatter-gather link is followed. */
	imx_edma5_write16(tcd, IMX_EDMA5_TCD_CSR, 0);
}

/* Fill an in-memory hardware TCD64 descriptor for one copy segment. */
static inline void
imx_edma5_fill_tcd(struct imx_edma5_hw_tcd64 *t, uint64_t src, uint64_t dst,
		   uint32_t len)
{
	uint16_t attr = imx_edma5_calc_attr(src, dst, len);
	uint16_t soff = (uint16_t)(1u << IMX_EDMA5_TCD_ATTR_GET_SSIZE(attr));
	uint16_t doff = (uint16_t)(1u << IMX_EDMA5_TCD_ATTR_GET_DSIZE(attr));

	t->saddr = rte_cpu_to_le_64(src);
	t->soff = rte_cpu_to_le_16(soff);
	t->attr = rte_cpu_to_le_16(attr);
	t->nbytes = rte_cpu_to_le_32(len);
	t->slast = 0;
	t->daddr = rte_cpu_to_le_64(dst);
	t->dlast_sga = 0;
	t->doff = rte_cpu_to_le_16(doff);
	t->citer = rte_cpu_to_le_16(1);
	t->csr = 0;
	t->biter = rte_cpu_to_le_16(1);
}

static inline void
imx_edma5_hw_start(struct imx_edma5_vchan *vc)
{
	uint16_t csr = imx_edma5_read16(vc->tcd_regs, IMX_EDMA5_TCD_CSR);

	csr |= IMX_EDMA5_TCD_CSR_START;
	imx_edma5_write16(vc->tcd_regs, IMX_EDMA5_TCD_CSR, csr);
}

/*
 * Invalidate the CPU cache lines covering a completed job's destination(s) so
 * the application reads the DMA result rather than stale cache. The lines were
 * cleaned at enqueue time, so this clean+invalidate behaves as a pure
 * invalidate.
 */
static inline void
imx_edma5_job_invalidate_dst(struct imx_edma5_job *job)
{
	if (job->nb_sg > 0) {
		uint16_t s;

		for (s = 0; s < job->nb_sg; s++) {
			rte_iova_t da = rte_le_to_cpu_64(job->sg_tcd[s].daddr);
			uint32_t len = rte_le_to_cpu_32(job->sg_tcd[s].nbytes);
			void *va = rte_mem_iova2virt(da);

			if (va != NULL)
				imx_edma5_cache_inval(va, len);
		}
	} else if (job->dst_va != NULL) {
		imx_edma5_cache_inval(job->dst_va, job->len);
	}
}

/*
 * Upper bound on how long to poll for a single-block transfer to complete.
 * A wall-clock deadline is used rather than a raw spin count so the bound is
 * independent of CPU speed and transfer size: even the largest single-block
 * copy this driver issues completes in well under a millisecond at eDMA5 bus
 * rates, so 1 ms is comfortably above the worst case while still bounding a
 * wedged channel instead of hanging the CPU.
 */
#define IMX_EDMA5_WAIT_TIMEOUT_MS	1

/*
 * Wait for the single register TCD transfer to finish and clear its latched
 * status. Returns true on success, false on a logged channel error (CH_ES.ERR)
 * or timeout. The per-transfer completion flag CH_CSR.DONE and the CH_ES error
 * bit are both write-1-to-clear.
 */
static inline bool
imx_edma5_wait_done(struct imx_edma5_vchan *vc)
{
	uint64_t deadline = rte_get_timer_cycles() +
		(rte_get_timer_hz() * IMX_EDMA5_WAIT_TIMEOUT_MS) / 1000;

	do {
		uint32_t ch_es = imx_edma5_read32(vc->ch_regs, IMX_EDMA5_CH_ES);
		uint32_t ch_csr;

		if (ch_es & IMX_EDMA5_CH_ES_ERR) {
			imx_edma5_write32(vc->ch_regs, IMX_EDMA5_CH_ES,
					  IMX_EDMA5_CH_ES_ERR);
			/* Reset the errored channel before the next job reuses it. */
			imx_edma5_reset_hw_chan(vc);
			return false;
		}

		ch_csr = imx_edma5_read32(vc->ch_regs, IMX_EDMA5_CH_CSR);
		if (ch_csr & IMX_EDMA5_CH_CSR_DONE) {
			imx_edma5_write32(vc->ch_regs, IMX_EDMA5_CH_CSR,
					  IMX_EDMA5_CH_CSR_DONE);
			return true;
		}
	} while (rte_get_timer_cycles() < deadline);

	IMX_EDMA5_LOG(ERR,
		      "channel %u timed out waiting for DONE (CH_CSR=0x%08x "
		      "CH_ES=0x%08x)",
		      vc->hw_chan,
		      imx_edma5_read32(vc->ch_regs, IMX_EDMA5_CH_CSR),
		      imx_edma5_read32(vc->ch_regs, IMX_EDMA5_CH_ES));

	/* Reset the possibly-still-active channel before the next job reuses it. */
	imx_edma5_reset_hw_chan(vc);
	return false;
}

/*
 * Execute one job to completion on the channel's single register TCD.
 *
 * The eDMA5 exposes a single TCD and a single completion flag per channel, so
 * jobs are serialised in software: a job is run synchronously here (program the
 * TCD, software-start, busy-wait for DONE) and its completion recorded in
 * job->done for the completion API to reap. Scatter-gather segments are played
 * out one at a time as single-block transfers, since the eDMA5 does not
 * auto-advance a hardware TCD chain for software-started mem-to-mem transfers.
 * On success the destination cache lines are invalidated (non-coherent master).
 */
static inline void
imx_edma5_run_job(struct imx_edma5_vchan *vc, struct imx_edma5_job *job)
{
	bool ok = true;

	if (job->nb_sg > 0) {
		uint16_t s;

		for (s = 0; s < job->nb_sg; s++) {
			uint64_t src = rte_le_to_cpu_64(job->sg_tcd[s].saddr);
			uint64_t dst = rte_le_to_cpu_64(job->sg_tcd[s].daddr);
			uint32_t len = rte_le_to_cpu_32(job->sg_tcd[s].nbytes);

			imx_edma5_program_copy(vc, src, dst, len);
			imx_edma5_hw_start(vc);
			if (!imx_edma5_wait_done(vc)) {
				ok = false;
				break;
			}
		}
	} else {
		imx_edma5_program_copy(vc, job->src_iova, job->dst_iova,
				       job->len);
		imx_edma5_hw_start(vc);
		ok = imx_edma5_wait_done(vc);
	}

	if (ok)
		imx_edma5_job_invalidate_dst(job);

	job->error = ok ? 0 : 1;
	job->done = 1;
	vc->submitted_count++;
}

static int
imx_edma5_copy(void *dev_private, uint16_t vchan, rte_iova_t src,
	       rte_iova_t dst, uint32_t length, uint64_t flags)
{
	struct imx_edma5_dev *ed = dev_private;
	struct imx_edma5_vchan *vc = &ed->vchans[vchan];
	struct imx_edma5_job *job;
	uint16_t slot;

	/* NBYTES = 0 is undefined on the eDMA5 and can wedge the channel. */
	if (length == 0)
		return -EINVAL;

	/* Ring full? one slot is kept free to distinguish full from empty. */
	if (vc->nb_enqueued >= (uint16_t)(vc->nb_desc - 1))
		return -ENOSPC;

	slot = vc->head;
	job = &vc->jobs[slot];
	job->ridx = vc->ridx;
	job->submitted = 0;
	job->done = 0;
	job->error = 0;
	job->nb_sg = 0;
	job->len = length;
	job->src_iova = src;
	job->dst_iova = dst;
	job->dst_va = rte_mem_iova2virt(dst);

	/*
	 * Non-cache-coherent master: clean the source so the device reads the
	 * CPU's latest writes, and clean the destination so a prior dirty line
	 * cannot be written back over the DMA result (the destination is
	 * invalidated after completion).
	 */
	{
		void *src_va = rte_mem_iova2virt(src);

		if (src_va != NULL)
			imx_edma5_cache_clean(src_va, length);
		if (job->dst_va != NULL)
			imx_edma5_cache_clean(job->dst_va, length);
	}

	/* Run now if SUBMIT is set, else later by imx_edma5_submit(). */
	if (flags & RTE_DMA_OP_FLAG_SUBMIT) {
		imx_edma5_run_job(vc, job);
		job->submitted = 1;
	}

	vc->head = (vc->head + 1) & vc->desc_mask;
	vc->nb_enqueued++;

	return vc->ridx++;
}

static int
imx_edma5_copy_sg(void *dev_private, uint16_t vchan,
		  const struct rte_dma_sge *src, const struct rte_dma_sge *dst,
		  uint16_t nb_src, uint16_t nb_dst, uint64_t flags)
{
	struct imx_edma5_dev *ed = dev_private;
	struct imx_edma5_vchan *vc = &ed->vchans[vchan];
	struct imx_edma5_hw_tcd64 *tcd;
	struct imx_edma5_job *job;
	uint16_t slot;
	uint16_t s;
	uint16_t si = 0, di = 0;	/* current source/destination seg index */
	uint32_t s_off = 0, d_off = 0;	/* byte offset within current segment */
	uint16_t nsg = 0;		/* sub-transfers produced so far */
	uint64_t src_total = 0, dst_total = 0;

	/*
	 * The scatter-gather contract is a byte stream: the source and
	 * destination lists may be segmented independently but their
	 * concatenations are equal. The lists are walked as two cursors,
	 * emitting one single-block sub-transfer per run that fits in both the
	 * current source and destination segments. This yields at most
	 * nb_src + nb_dst - 1 sub-transfers, which fit in IMX_EDMA5_SG_TCD_PER_JOB.
	 */
	if (nb_src == 0 || nb_dst == 0 ||
	    nb_src > IMX_EDMA5_MAX_SGES || nb_dst > IMX_EDMA5_MAX_SGES) {
		IMX_EDMA5_LOG(ERR, "Unsupported SG shape src=%u dst=%u",
			      nb_src, nb_dst);
		return -EINVAL;
	}

	/* Ring full? one slot is kept free to distinguish full from empty. */
	if (vc->nb_enqueued >= (uint16_t)(vc->nb_desc - 1))
		return -ENOSPC;

	slot = vc->head;
	job = &vc->jobs[slot];
	job->ridx = vc->ridx;
	job->submitted = 0;
	job->done = 0;
	job->error = 0;

	/* This job's dedicated slice of the in-memory TCD pool. */
	job->sg_tcd = &vc->sg_tcd_pool[(size_t)slot * IMX_EDMA5_SG_TCD_PER_JOB];
	tcd = job->sg_tcd;

	/*
	 * Clean every source and destination segment up front (non-coherent
	 * master): the device must read current source data, and dirty
	 * destination lines must be flushed before the transfer.
	 */
	for (s = 0; s < nb_src; s++) {
		void *va = rte_mem_iova2virt(src[s].addr);

		src_total += src[s].length;
		if (va != NULL)
			imx_edma5_cache_clean(va, src[s].length);
	}
	for (s = 0; s < nb_dst; s++) {
		void *va = rte_mem_iova2virt(dst[s].addr);

		dst_total += dst[s].length;
		if (va != NULL)
			imx_edma5_cache_clean(va, dst[s].length);
	}

	/* copy_sg requires equal total bytes on both lists; reject misuse. */
	if (src_total != dst_total) {
		IMX_EDMA5_LOG(ERR,
			      "SG byte count mismatch src=%" PRIu64
			      " dst=%" PRIu64, src_total, dst_total);
		return -EINVAL;
	}

	while (si < nb_src && di < nb_dst) {
		uint32_t s_rem = src[si].length - s_off;
		uint32_t d_rem = dst[di].length - d_off;
		uint32_t len = RTE_MIN(s_rem, d_rem);

		/* Skip zero-length segments without emitting a descriptor. */
		if (len == 0) {
			if (s_rem == 0) {
				si++;
				s_off = 0;
			}
			if (d_rem == 0) {
				di++;
				d_off = 0;
			}
			continue;
		}

		if (nsg >= IMX_EDMA5_SG_TCD_PER_JOB) {
			IMX_EDMA5_LOG(ERR,
				      "SG produced too many sub-transfers "
				      "(src=%u dst=%u)", nb_src, nb_dst);
			/* Defensive: clear nb_sg so the abandoned slot is not reused. */
			job->nb_sg = 0;
			return -EINVAL;
		}

		imx_edma5_fill_tcd(&tcd[nsg], src[si].addr + s_off,
				   dst[di].addr + d_off, len);
		nsg++;

		s_off += len;
		d_off += len;
		if (s_off == src[si].length) {
			si++;
			s_off = 0;
		}
		if (d_off == dst[di].length) {
			di++;
			d_off = 0;
		}
	}

	/* No sub-transfer (all segments zero-length): NBYTES = 0 wedges eDMA5. */
	if (nsg == 0) {
		IMX_EDMA5_LOG(ERR, "SG produced zero sub-transfers");
		return -EINVAL;
	}

	job->nb_sg = nsg;

	/* Run now if SUBMIT is set, else later by imx_edma5_submit(). */
	if (flags & RTE_DMA_OP_FLAG_SUBMIT) {
		imx_edma5_run_job(vc, job);
		job->submitted = 1;
	}

	vc->head = (vc->head + 1) & vc->desc_mask;
	vc->nb_enqueued++;

	return vc->ridx++;
}

static int
imx_edma5_submit(void *dev_private, uint16_t vchan)
{
	struct imx_edma5_dev *ed = dev_private;
	struct imx_edma5_vchan *vc = &ed->vchans[vchan];
	uint16_t idx = vc->tail;

	/* Run every enqueued-but-not-yet-submitted job to completion (FIFO). */
	while (idx != vc->head) {
		struct imx_edma5_job *job = &vc->jobs[idx];

		if (!job->submitted) {
			imx_edma5_run_job(vc, job);
			job->submitted = 1;
		}
		idx = (idx + 1) & vc->desc_mask;
	}

	return 0;
}

/*
 * Reap completed jobs from the software ring in FIFO order. Jobs run
 * synchronously, so a submitted job's result is already in job->done/error.
 * An unsubmitted job stops the walk.
 */
static uint16_t
imx_edma5_completed(void *dev_private, uint16_t vchan, const uint16_t nb_cpls,
		    uint16_t *last_idx, bool *has_error)
{
	struct imx_edma5_dev *ed = dev_private;
	struct imx_edma5_vchan *vc = &ed->vchans[vchan];
	uint16_t count = 0;

	*has_error = false;

	while (count < nb_cpls && vc->tail != vc->head) {
		struct imx_edma5_job *job = &vc->jobs[vc->tail];

		if (!job->submitted || !job->done)
			break;

		/*
		 * Stop before an errored job: it is left in the ring for
		 * rte_dma_completed_status(), and last_idx stays at the last
		 * successful transfer.
		 */
		if (job->error) {
			*has_error = true;
			break;
		}

		vc->last_idx = job->ridx;
		vc->completed_count++;

		vc->tail = (vc->tail + 1) & vc->desc_mask;
		vc->nb_enqueued--;
		count++;
	}

	*last_idx = vc->last_idx;

	return count;
}

static uint16_t
imx_edma5_completed_status(void *dev_private, uint16_t vchan,
			   const uint16_t nb_cpls, uint16_t *last_idx,
			   enum rte_dma_status_code *status)
{
	struct imx_edma5_dev *ed = dev_private;
	struct imx_edma5_vchan *vc = &ed->vchans[vchan];
	uint16_t count = 0;

	while (count < nb_cpls && vc->tail != vc->head) {
		struct imx_edma5_job *job = &vc->jobs[vc->tail];

		if (!job->submitted || !job->done)
			break;

		if (job->error) {
			status[count] = RTE_DMA_STATUS_BUS_ERROR;
			vc->errors_count++;
		} else {
			status[count] = RTE_DMA_STATUS_SUCCESSFUL;
		}

		vc->last_idx = job->ridx;
		vc->completed_count++;

		vc->tail = (vc->tail + 1) & vc->desc_mask;
		vc->nb_enqueued--;
		count++;
	}

	*last_idx = vc->last_idx;

	return count;
}

static uint16_t
imx_edma5_burst_capacity(const void *dev_private, uint16_t vchan)
{
	const struct imx_edma5_dev *ed = dev_private;
	const struct imx_edma5_vchan *vc = &ed->vchans[vchan];

	/* One slot is reserved to distinguish full from empty. */
	return vc->nb_desc - 1 - vc->nb_enqueued;
}

static int
imx_edma5_vchan_status(const struct rte_dma_dev *dev, uint16_t vchan,
		       enum rte_dma_vchan_status *status)
{
	const struct imx_edma5_dev *ed = dev->data->dev_private;
	const struct imx_edma5_vchan *vc = &ed->vchans[vchan];
	uint16_t idx;

	/*
	 * HALTED_ERROR if an errored job is still unreaped, ACTIVE while any job
	 * is outstanding (not done, or enqueued but not submitted), else IDLE.
	 */
	*status = RTE_DMA_VCHAN_IDLE;

	for (idx = vc->tail; idx != vc->head; idx = (idx + 1) & vc->desc_mask) {
		const struct imx_edma5_job *job = &vc->jobs[idx];

		if (job->submitted && job->done && job->error) {
			*status = RTE_DMA_VCHAN_HALTED_ERROR;
			break;
		}

		if (!job->submitted || !job->done) {
			*status = RTE_DMA_VCHAN_ACTIVE;
			break;
		}
	}

	return 0;
}

static int
imx_edma5_stats_get(const struct rte_dma_dev *dev, uint16_t vchan,
		    struct rte_dma_stats *stats, uint32_t stats_sz)
{
	const struct imx_edma5_dev *ed = dev->data->dev_private;

	RTE_SET_USED(stats_sz);

	stats->submitted = 0;
	stats->completed = 0;
	stats->errors = 0;

	/* RTE_DMA_ALL_VCHAN requests the aggregate across every vchan. */
	if (vchan == RTE_DMA_ALL_VCHAN) {
		uint16_t i;

		for (i = 0; i < ed->nb_vchans; i++) {
			const struct imx_edma5_vchan *vc = &ed->vchans[i];

			stats->submitted += vc->submitted_count;
			stats->completed += vc->completed_count;
			stats->errors += vc->errors_count;
		}
	} else if (vchan < ed->nb_vchans) {
		const struct imx_edma5_vchan *vc = &ed->vchans[vchan];

		stats->submitted = vc->submitted_count;
		stats->completed = vc->completed_count;
		stats->errors = vc->errors_count;
	}

	return 0;
}

static int
imx_edma5_stats_reset(struct rte_dma_dev *dev, uint16_t vchan)
{
	struct imx_edma5_dev *ed = dev->data->dev_private;

	/* RTE_DMA_ALL_VCHAN requests a reset of every vchan. */
	if (vchan == RTE_DMA_ALL_VCHAN) {
		uint16_t i;

		for (i = 0; i < ed->nb_vchans; i++) {
			struct imx_edma5_vchan *vc = &ed->vchans[i];

			vc->submitted_count = 0;
			vc->completed_count = 0;
			vc->errors_count = 0;
		}
	} else if (vchan < ed->nb_vchans) {
		struct imx_edma5_vchan *vc = &ed->vchans[vchan];

		vc->submitted_count = 0;
		vc->completed_count = 0;
		vc->errors_count = 0;
	}

	return 0;
}

static int
imx_edma5_dump(const struct rte_dma_dev *dev, FILE *f)
{
	const struct imx_edma5_dev *ed = dev->data->dev_private;
	uint16_t i;

	(void)fprintf(f, "  imx_edma5 nb_channels=%u nb_vchans=%u\n",
		      ed->nb_channels, ed->nb_vchans);
	for (i = 0; i < ed->nb_vchans; i++) {
		const struct imx_edma5_vchan *vc = &ed->vchans[i];

		(void)fprintf(f,
			"    vchan %u: hw_chan=%u nb_desc=%u enqueued=%u "
			"submitted=%" PRIu64 " completed=%" PRIu64
			" errors=%" PRIu64 "\n",
			i, vc->hw_chan, vc->nb_desc, vc->nb_enqueued,
			vc->submitted_count, vc->completed_count,
			vc->errors_count);
	}

	return 0;
}

static const struct rte_dma_dev_ops imx_edma5_ops = {
	.dev_info_get	= imx_edma5_info_get,
	.dev_configure	= imx_edma5_configure,
	.dev_start	= imx_edma5_start,
	.dev_stop	= imx_edma5_stop,
	.dev_close	= imx_edma5_close,

	.vchan_setup	= imx_edma5_vchan_setup,
	.vchan_status	= imx_edma5_vchan_status,

	.stats_get	= imx_edma5_stats_get,
	.stats_reset	= imx_edma5_stats_reset,

	.dev_dump	= imx_edma5_dump,
};

static int
imx_edma5_probe(struct rte_platform_device *pdev)
{
	struct rte_platform_resource *res;
	struct imx_edma5_dev *ed;
	struct rte_dma_dev *dev;
	const char *name;

	name = pdev->name;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		IMX_EDMA5_LOG(ERR, "Secondary process not supported for %s",
			      name);
		return -ENOTSUP;
	}

	if (pdev->num_resource < 1 || pdev->resource == NULL) {
		IMX_EDMA5_LOG(ERR, "No MMIO resource for %s", name);
		return -EINVAL;
	}
	res = &pdev->resource[0];
	if (res->mem.addr == NULL) {
		IMX_EDMA5_LOG(ERR, "MMIO resource not mapped for %s", name);
		return -EINVAL;
	}

	dev = rte_dma_pmd_allocate(name, rte_socket_id(),
				   sizeof(struct imx_edma5_dev));
	if (dev == NULL) {
		IMX_EDMA5_LOG(ERR, "Failed to allocate dmadev for %s", name);
		return -ENOMEM;
	}

	dev->device = &pdev->device;
	dev->dev_ops = &imx_edma5_ops;
	dev->fp_obj->dev_private = dev->data->dev_private;
	dev->fp_obj->copy = imx_edma5_copy;
	dev->fp_obj->copy_sg = imx_edma5_copy_sg;
	dev->fp_obj->submit = imx_edma5_submit;
	dev->fp_obj->completed = imx_edma5_completed;
	dev->fp_obj->completed_status = imx_edma5_completed_status;
	dev->fp_obj->burst_capacity = imx_edma5_burst_capacity;

	ed = dev->data->dev_private;
	ed->reg_base = res->mem.addr;
	ed->reg_size = res->mem.len;
	ed->dev_id = dev->data->dev_id;

	/*
	 * Build a map from usable vchan index to hardware channel index,
	 * skipping channels reserved for other bus masters by the device-tree
	 * "dma-channel-mask" (accessing them external-aborts).
	 */
	ed->masked_channels = imx_edma5_read_channel_mask(name);
	ed->nb_channels = 0;
	{
		uint16_t hw;

		for (hw = 0; hw < IMX_EDMA5_MAX_CHANNELS; hw++) {
			if (ed->masked_channels & (RTE_BIT64(hw)))
				continue;
			ed->chan_map[ed->nb_channels++] = hw;
		}
	}
	ed->max_vchans = ed->nb_channels;

	if (ed->nb_channels == 0) {
		IMX_EDMA5_LOG(ERR,
			      "No usable eDMA5 channels for %s (mask 0x%" PRIx64 ")",
			      name, ed->masked_channels);
		rte_dma_pmd_release(name);
		return -ENODEV;
	}

	dev->state = RTE_DMA_DEV_READY;

	/*
	 * Set MP_CSR.GCLC (Global Clock Control) before any per-channel register
	 * is touched: the per-channel windows are individually clock-gated and
	 * external-abort when accessed with GCLC clear. Also enable round-robin
	 * arbitration (ERCA). Use read-modify-write to preserve reset defaults.
	 */
	{
		uint32_t mp_csr = imx_edma5_read32(ed->reg_base, IMX_EDMA5_MP_CSR);

		mp_csr |= IMX_EDMA5_MP_CSR_GCLC | IMX_EDMA5_MP_CSR_ERCA;
		imx_edma5_write32(ed->reg_base, IMX_EDMA5_MP_CSR, mp_csr);
	}

	IMX_EDMA5_LOG(INFO, "Probed i.MX95 eDMA5 dmadev %s (%u channels)",
		      name, ed->nb_channels);

	return 0;
}

static int
imx_edma5_remove(struct rte_platform_device *pdev)
{
	const char *name = pdev->name;

	return rte_dma_pmd_release(name);
}

static struct rte_platform_driver imx_edma5_pmd_drv = {
	.probe = imx_edma5_probe,
	.remove = imx_edma5_remove,
	/*
	 * The eDMA5 is programmed with the IOVA of the buffers, so it works in
	 * both IOVA=VA and IOVA=PA modes; no IOVA-as-VA requirement is forced.
	 */
	.drv_flags = 0,
};

RTE_PMD_REGISTER_PLATFORM(dma_imx_edma5, imx_edma5_pmd_drv);
RTE_PMD_REGISTER_ALIAS(dma_imx_edma5, IMX_EDMA5_COMPAT);

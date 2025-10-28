/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2025 NXP
 */

#include <stdio.h>
#include <sys/queue.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_prefetch.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_sctp.h>

#include "lsxinic_common.h"
#include "lsxinic_common_helper.h"
#include "lsxinic_rc_rxtx.h"
#include "lsxinic_rc_hw.h"

#include "lsxinic_self_test_data.h"

/* Default RS bit threshold values */
#ifndef DEFAULT_TX_RS_THRESH
#define DEFAULT_TX_RS_THRESH   32
#endif

/* TX queues list */
TAILQ_HEAD(lxsnic_tx_queue_list, lxsnic_ring);

/* per thread TX queue list */
RTE_DEFINE_PER_LCORE(uint8_t, lxsnic_txq_list_initialized);
RTE_DEFINE_PER_LCORE(uint8_t, lxsnic_txq_num_in_list);
RTE_DEFINE_PER_LCORE(struct lxsnic_tx_queue_list, lxsnic_txq_list);

static RTE_DEFINE_PER_LCORE(pthread_t, pthrd_id);
static RTE_DEFINE_PER_LCORE(int, txq_added[LSINIC_RING_MAX_COUNT]);

static int lxsnic_add_txq_to_list(struct lxsnic_ring *txq)
{
	struct lxsnic_ring *queue = NULL;

	if (txq->core_id != RTE_MAX_LCORE)
		return 0;

	if (!RTE_PER_LCORE(lxsnic_txq_list_initialized)) {
		TAILQ_INIT(&RTE_PER_LCORE(lxsnic_txq_list));
		RTE_PER_LCORE(lxsnic_txq_list_initialized) = 1;
		RTE_PER_LCORE(lxsnic_txq_num_in_list) = 0;
	}

	/* Check if txq already added to list */
	TAILQ_FOREACH(queue, &RTE_PER_LCORE(lxsnic_txq_list), next) {
		if (queue == txq)
			return 0;
	}

	TAILQ_INSERT_TAIL(&RTE_PER_LCORE(lxsnic_txq_list), txq, next);
	txq->core_id = rte_lcore_id();
	txq->pid = pthread_self();
	RTE_PER_LCORE(lxsnic_txq_num_in_list)++;

	LSXINIC_PMD_DBG("Add port%d txq%d to list NUM%d\n",
		txq->port, txq->queue_index,
		RTE_PER_LCORE(lxsnic_txq_num_in_list));

	return 0;
}

static void lxsnic_tx_complete_ring_clean(struct lxsnic_ring *tx_ring)
{
	uint16_t bd_idx;
	uint32_t mbuf_idx;
	struct rte_mbuf *last_mbuf;
	uint8_t *tx_complete = &tx_ring->tx_complete->bd_complete;

	bd_idx = tx_ring->last_used_idx & (tx_ring->count - 1);

	rte_rmb();

	do {
		if (tx_complete[bd_idx] != RING_BD_HW_COMPLETE)
			break;

		mbuf_idx = bd_idx;
		if (mbuf_idx == LSINIC_BD_CTX_IDX_INVALID)
			break;
		last_mbuf = (struct rte_mbuf *)tx_ring->q_mbuf[mbuf_idx];
		RTE_ASSERT(last_mbuf);
		rte_pktmbuf_free(last_mbuf);

		tx_complete[bd_idx] = RING_BD_READY;

		tx_ring->last_used_idx++;

		bd_idx = tx_ring->last_used_idx & (tx_ring->count - 1);

		rte_rmb();
	} while (1);
}

static void lxsnic_tx_ring_clean(struct lxsnic_ring *tx_ring)
{
	uint16_t bd_idx;
	uint32_t status;
	uint32_t mbuf_idx;
	struct lsinic_bd_desc *rc_tx_desc;
	struct rte_mbuf *last_mbuf;

	bd_idx = tx_ring->last_used_idx & (tx_ring->count - 1);
	rc_tx_desc = &tx_ring->rc_bd_desc[bd_idx];

	status = rc_tx_desc->bd_status & RING_BD_STATUS_MASK;

	rte_rmb();

	do {
		if (status != RING_BD_HW_COMPLETE)
			break;

		mbuf_idx = lsinic_bd_ctx_idx(rc_tx_desc->bd_status);
		last_mbuf = (struct rte_mbuf *)tx_ring->q_mbuf[mbuf_idx];
		RTE_ASSERT(last_mbuf);
		rte_pktmbuf_free(last_mbuf);

		rc_tx_desc->bd_status &= (~((uint32_t)RING_BD_STATUS_MASK));
		rc_tx_desc->bd_status |= RING_BD_READY;

		tx_ring->last_used_idx++;

		bd_idx = tx_ring->last_used_idx & (tx_ring->count - 1);
		rc_tx_desc = &tx_ring->rc_bd_desc[bd_idx];
		status = rc_tx_desc->bd_status & RING_BD_STATUS_MASK;

		rte_rmb();
	} while (1);
}

static void lxsnic_tx_ring_idx_clean(struct lxsnic_ring *tx_ring)
{
	uint32_t start_free_idx = tx_ring->tx_free_start_idx;
	const uint32_t last_free_idx = tx_ring->rc_reg->cir;
	uint32_t mbuf_idx;
	struct rte_mbuf *last_mbuf;

	if (!tx_ring->tx_free_len)
		return;

	while (start_free_idx != last_free_idx) {
		mbuf_idx = start_free_idx;
		last_mbuf = (struct rte_mbuf *)tx_ring->q_mbuf[mbuf_idx];
		rte_pktmbuf_free(last_mbuf);

		tx_ring->last_used_idx++;
		start_free_idx = (start_free_idx + 1) & (tx_ring->count - 1);
		tx_ring->tx_free_len--;
		RTE_ASSERT(tx_ring->tx_free_len >= 0);
	}

	tx_ring->tx_free_start_idx = start_free_idx;
}

static int
lxsnic_xmit_one_pkt_idx(struct lxsnic_ring *tx_ring,
	struct rte_mbuf *tx_pkt, uint16_t mg_num,
	struct lsinic_ep_rx_src_addrx *notify)
{
	dma_addr_t dma;
	uint16_t bd_idx = 0;
	uint32_t pkt_len = 0;
	struct lsinic_ep_rx_src_addrx *ep_tx_desc = 0;
	struct lsinic_ep_rx_src_addrx local_desc;
	struct lxsnic_adapter *adapter = tx_ring->adapter;
	uint32_t mbuf_idx = 0, pending_cnt = 0;
	char *pdata = NULL;
	uint8_t *tx_complete;
	const uint32_t pkt_addr_interval = adapter->pkt_addr_interval;
	const uint64_t pkt_addr_base = adapter->pkt_addr_base;

#ifndef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	UNUSED(mg_num);
#endif

	if (unlikely(tx_pkt->data_off != RTE_PKTMBUF_HEADROOM)) {
		LSXINIC_PMD_ERR("IDX xmit invalid offset(%d != %d)",
			tx_pkt->data_off, RTE_PKTMBUF_HEADROOM);

		return -EINVAL;
	}

	if (tx_pkt->nb_segs > 1)
		return -EINVAL;

	bd_idx = tx_ring->last_avail_idx & (tx_ring->count - 1);
	ep_tx_desc = &tx_ring->ep_tx_addrx[bd_idx];
	if (tx_ring->rc_mem_bd_type == RC_MEM_IDX_CNF) {
		while (unlikely(((bd_idx + 1 + XMIT_IDX_EXTRA_SPACE) &
			(tx_ring->count - 1)) ==
			tx_ring->tx_free_start_idx)) {
			/** Make special room, otherwise no way to
			 * identify ring is empty or full.
			 */
			if (pending_cnt > 1000) {
				tx_ring->ring_full++;
				tx_ring->errors++;
				return -EAGAIN;
			}
			pending_cnt++;
			lxsnic_tx_ring_idx_clean(tx_ring);
			rte_wmb();
			rte_rmb();
		}
		mbuf_idx = bd_idx;
	} else if (tx_ring->rc_mem_bd_type == RC_MEM_BD_CNF) {
		tx_complete = &tx_ring->tx_complete[bd_idx].bd_complete;
		if (*tx_complete != RING_BD_READY) {
#ifdef LXSNIC_DEBUG_RX_TX
			adapter->stats.tx_desc_err++;
#endif
			tx_ring->ring_full++;
			tx_ring->errors++;
			return -EAGAIN;
		}
		mbuf_idx = bd_idx;
		*tx_complete = RING_BD_AVAILABLE;
	} else {
		rte_panic("Invalid confirm(%d) for xmit pkt idx",
			tx_ring->rc_mem_bd_type);
	}

	pkt_len = tx_pkt->pkt_len;  /* total packet length */
	dma = rte_mbuf_data_iova(tx_pkt);
	if (tx_ring->adapter->cap & LSINIC_CAP_XFER_COMPLETE) {
		pdata = (char *)rte_pktmbuf_mtod(tx_pkt, char *);
		*((uint8_t *)pdata + pkt_len) =
			LSINIC_XFER_COMPLETE_DONE_FLAG;
	}

	tx_ring->q_mbuf[mbuf_idx] = tx_pkt;

	local_desc.pkt_idx = (dma - pkt_addr_base) / pkt_addr_interval;
	if (unlikely((local_desc.pkt_idx * pkt_addr_interval +
		pkt_addr_base) != dma)) {
		rte_panic("RC xmit buf idx fatal!");
	}
	RTE_ASSERT((local_desc.pkt_idx * pkt_addr_interval +
		pkt_addr_base) == dma);
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	RTE_ASSERT(pkt_len < (MAX_U16 / 2));
	local_desc.len_cmd = pkt_len;
	if (mg_num)
		local_desc.len_cmd |= LSINIC_EP_RX_SRC_ADDRX_MERGE;
#else
	RTE_ASSERT(pkt_len < MAX_U16);
	local_desc.len = pkt_len;
#endif

	if (!notify)
		ep_tx_desc->idx_cmd_len = local_desc.idx_cmd_len;
	else
		notify->idx_cmd_len = local_desc.idx_cmd_len;

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	if (!mg_num)
#endif
	{
		tx_ring->packets++;
		tx_ring->bytes += tx_pkt->pkt_len;
		tx_ring->bytes_fcs += tx_pkt->pkt_len + LSINIC_ETH_FCS_SIZE;
		tx_ring->bytes_overhead += tx_pkt->pkt_len +
			LSINIC_ETH_OVERHEAD_SIZE;
	}

	tx_ring->tx_free_len++;
	tx_ring->last_avail_idx++;

	return 0;
}

static int
lxsnic_xmit_one_pkt_addrl(struct lxsnic_ring *tx_ring,
	struct rte_mbuf *tx_pkt, uint16_t mg_num,
	struct lsinic_ep_rx_src_addrl *notify)
{
	dma_addr_t dma;
	uint32_t cmd_type;
	uint16_t bd_idx = 0;
	uint32_t pkt_len = 0;
	struct lsinic_ep_rx_src_addrl *ep_tx_desc = 0;
	struct lsinic_ep_rx_src_addrl local_desc;
	uint32_t mbuf_idx = 0;
	char *pdata = NULL;
	uint8_t *tx_complete;

#ifndef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	UNUSED(mg_num);
#endif

	if (tx_pkt->nb_segs > 1)
		return -EINVAL;

	bd_idx = tx_ring->last_avail_idx & (tx_ring->count - 1);
	ep_tx_desc = &tx_ring->ep_tx_addrl[bd_idx];
	if (tx_ring->rc_mem_bd_type == RC_MEM_IDX_CNF) {
		if (unlikely(((bd_idx + 1) &
			(tx_ring->count - 1)) ==
			tx_ring->tx_free_start_idx)) {
			/** Make special room, otherwise no way to
			 * identify ring is empty or full.
			 */
			tx_ring->ring_full++;
			tx_ring->errors++;
			return -EAGAIN;
		}
		mbuf_idx = bd_idx;
	} else if (tx_ring->rc_mem_bd_type == RC_MEM_BD_CNF) {
		tx_complete = &tx_ring->tx_complete[bd_idx].bd_complete;
		if (*tx_complete != RING_BD_READY) {
#ifdef LXSNIC_DEBUG_RX_TX
			tx_ring->adapter->stats.tx_desc_err++;
#endif
			tx_ring->ring_full++;
			tx_ring->errors++;
			return -EAGAIN;
		}
		*tx_complete = RING_BD_AVAILABLE;
		mbuf_idx = bd_idx;
	} else {
		rte_panic("Invalid confirm(%d) for xmit pkt addl",
			tx_ring->rc_mem_bd_type);
	}

	pkt_len = tx_pkt->pkt_len;  /* total packet length */
	cmd_type = LSINIC_BD_CMD_EOP;
	dma = rte_mbuf_data_iova(tx_pkt);
	if (tx_ring->adapter->cap & LSINIC_CAP_XFER_COMPLETE) {
		pdata = (char *)rte_pktmbuf_mtod(tx_pkt, char *);
		*((uint8_t *)pdata + pkt_len) =
			LSINIC_XFER_COMPLETE_DONE_FLAG;
	}
	tx_ring->q_mbuf[mbuf_idx] = tx_pkt;

	/* write last descriptor with RS and EOP bits */
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	if (mg_num) {
		cmd_type |= LSINIC_BD_CMD_MG | pkt_len;
		cmd_type |=
			((uint32_t)mg_num) << LSINIC_BD_MG_NUM_SHIFT;
	} else
#endif
	{
		cmd_type |= pkt_len;
	}

	local_desc.pkt_addr_low = dma - tx_ring->adapter->pkt_addr_base;
	local_desc.len_cmd = cmd_type;

	if (!notify)
		ep_tx_desc->addr_cmd_len = local_desc.addr_cmd_len;
	else
		notify->addr_cmd_len = local_desc.addr_cmd_len;

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	if (!mg_num)
#endif
	{
		tx_ring->packets++;
		tx_ring->bytes += tx_pkt->pkt_len;
		tx_ring->bytes_fcs += tx_pkt->pkt_len + LSINIC_ETH_FCS_SIZE;
		tx_ring->bytes_overhead += tx_pkt->pkt_len +
			LSINIC_ETH_OVERHEAD_SIZE;
	}
	tx_ring->tx_free_len++;
	tx_ring->last_avail_idx++;

	return 0;
}

static int
lxsnic_xmit_one_pkt(struct lxsnic_ring *tx_ring, struct rte_mbuf *tx_pkt,
	uint16_t mg_num, struct lsinic_bd_desc *local_desc)
{
	dma_addr_t dma;
	uint32_t cmd_type;
	uint16_t bd_idx = 0;
	uint32_t pkt_len = 0, bd_status;
	struct lsinic_bd_desc *ep_tx_desc = 0;
	struct lsinic_bd_desc local_tx_desc;
	struct lsinic_bd_desc *tx_complete_desc;
	uint32_t mbuf_idx = 0;
	char *pdata = NULL;
	uint8_t *tx_complete;
	uint32_t cap = tx_ring->adapter->cap;

#ifndef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	UNUSED(mg_num);
#endif

	if (tx_pkt->nb_segs > 1)
		return -EINVAL;

	bd_idx = tx_ring->last_avail_idx & (tx_ring->count - 1);

	ep_tx_desc = &tx_ring->ep_bd_desc[bd_idx];

	if (tx_ring->rc_mem_bd_type == RC_MEM_IDX_CNF) {
		if (unlikely(((bd_idx + 1) &
			(tx_ring->count - 1)) ==
			tx_ring->tx_free_start_idx)) {
			/** Make special room, otherwise no way to
			 * identify ring is empty or full.
			 */
			tx_ring->ring_full++;
			tx_ring->errors++;
			return -EAGAIN;
		}
		mbuf_idx = bd_idx;
		tx_ring->q_mbuf[mbuf_idx] = tx_pkt;
	} else if (tx_ring->rc_mem_bd_type == RC_MEM_BD_CNF) {
		tx_complete = &tx_ring->tx_complete[bd_idx].bd_complete;
		if (*tx_complete != RING_BD_READY) {
			uint8_t current_ep_status;

			ep_tx_desc = &tx_ring->ep_bd_desc[bd_idx];
			current_ep_status =
				ep_tx_desc->bd_status & RING_BD_STATUS_MASK;
			if (current_ep_status == RING_BD_HW_COMPLETE) {
				/** Workaround to sync with EP BD status.*/
				*tx_complete = RING_BD_HW_COMPLETE;
				tx_ring->sync_err++;
			}
#ifdef LXSNIC_DEBUG_RX_TX
			tx_ring->adapter->stats.tx_desc_err++;
#endif
			tx_ring->ring_full++;
			tx_ring->errors++;
			return -EAGAIN;
		}
		*tx_complete = RING_BD_AVAILABLE;
		mbuf_idx = bd_idx;
		tx_ring->q_mbuf[mbuf_idx] = tx_pkt;
	} else if (tx_ring->rc_mem_bd_type == RC_MEM_LONG_BD) {
		tx_complete_desc = &tx_ring->rc_bd_desc[bd_idx];
		bd_status = tx_complete_desc->bd_status;
		if ((bd_status & RING_BD_STATUS_MASK) != RING_BD_READY) {
#ifdef LXSNIC_DEBUG_RX_TX
			tx_ring->adapter->stats.tx_desc_err++;
#endif
			tx_ring->ring_full++;
			tx_ring->errors++;
			return -EAGAIN;
		}
		mbuf_idx = lsinic_bd_ctx_idx(bd_status);
		if (unlikely(mbuf_idx == LSINIC_BD_CTX_IDX_INVALID))
			mbuf_idx = bd_idx;

		tx_ring->q_mbuf[mbuf_idx] = tx_pkt;
		tx_complete_desc->bd_status &=
			(~((uint32_t)RING_BD_STATUS_MASK));
		tx_complete_desc->bd_status |= RING_BD_HW_PROCESSING;
	}

	pkt_len = tx_pkt->pkt_len;  /* total packet length */
	cmd_type = LSINIC_BD_CMD_EOP;
	dma = rte_mbuf_data_iova(tx_pkt);
	if (cap & LSINIC_CAP_XFER_COMPLETE) {
		pdata = (char *)rte_pktmbuf_mtod(tx_pkt, char *);
		*((uint8_t *)pdata + pkt_len) =
			LSINIC_XFER_COMPLETE_DONE_FLAG;
	}

	/* write last descriptor with RS and EOP bits */
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	if (mg_num) {
		cmd_type |= LSINIC_BD_CMD_MG | pkt_len;
		cmd_type |=
			(((uint32_t)mg_num) << LSINIC_BD_MG_NUM_SHIFT);
	} else
#endif
	{
		cmd_type |= pkt_len;
	}

	local_tx_desc.pkt_addr = dma;
	local_tx_desc.len_cmd = cmd_type;
	local_tx_desc.bd_status = (mbuf_idx << LSINIC_BD_CTX_IDX_SHIFT);
	local_tx_desc.bd_status |= RING_BD_AVAILABLE;
	if (local_desc) {
		memcpy(local_desc, &local_tx_desc,
			sizeof(struct lsinic_bd_desc));
	} else {
		memcpy(ep_tx_desc, &local_tx_desc,
			sizeof(struct lsinic_bd_desc));
	}

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	if (!mg_num)
#endif
	{
		tx_ring->packets++;
		tx_ring->bytes += tx_pkt->pkt_len;
		tx_ring->bytes_fcs += tx_pkt->pkt_len + LSINIC_ETH_FCS_SIZE;
		tx_ring->bytes_overhead += tx_pkt->pkt_len +
			LSINIC_ETH_OVERHEAD_SIZE;
	}
	tx_ring->tx_free_len++;
	tx_ring->last_avail_idx++;

	return 0;
}

static int
lxsnic_xmit_one_seg_pkt(struct lxsnic_ring *tx_ring,
	struct rte_mbuf *tx_pkt, struct lsinic_seg_desc *local_desc)
{
	dma_addr_t dma;
	struct rte_mbuf *pkt_curr = NULL;
	uint16_t bd_idx = 0, idx, copy_len;
	struct lsinic_seg_desc *ep_sg_desc = 0;
	struct lsinic_seg_desc local_sg_desc;
	uint32_t mbuf_idx = 0;
	char *pdata = NULL;

	bd_idx = tx_ring->last_avail_idx & (tx_ring->count - 1);

	ep_sg_desc = &tx_ring->ep_tx_sg[bd_idx];

	if (tx_ring->rc_mem_bd_type == RC_MEM_IDX_CNF) {
		if (unlikely(((bd_idx + 1) &
			(tx_ring->count - 1)) ==
			tx_ring->tx_free_start_idx)) {
			/** Make special room, otherwise no way to
			 * identify ring is empty or full.
			 */
			tx_ring->ring_full++;
			tx_ring->errors++;
			return -EAGAIN;
		}
		mbuf_idx = bd_idx;
		tx_ring->q_mbuf[mbuf_idx] = tx_pkt;
	} else {
		return -EINVAL;
	}

	local_sg_desc.base_addr = tx_pkt->buf_iova + tx_pkt->data_off;
	local_sg_desc.entry[0].positive = 0;
	local_sg_desc.entry[0].offset = 0;
	if (tx_pkt->data_len == tx_pkt->pkt_len ||
		tx_pkt->nb_segs <= 1) {
		local_sg_desc.entry[0].len = tx_pkt->pkt_len;
		local_sg_desc.nb = 1;
	} else {
		pkt_curr = tx_pkt;
		local_sg_desc.entry[0].len = pkt_curr->data_len;
		for (idx = 1; idx < tx_pkt->nb_segs; idx++) {
			pkt_curr = pkt_curr->next;
			dma = pkt_curr->buf_iova + pkt_curr->data_off;
			if (dma > local_sg_desc.base_addr) {
				local_sg_desc.entry[idx].positive = 1;
				local_sg_desc.entry[idx].offset =
					dma - local_sg_desc.base_addr;
			} else {
				local_sg_desc.entry[idx].positive = 0;
				local_sg_desc.entry[idx].offset =
					local_sg_desc.base_addr - dma;
			}
			local_sg_desc.entry[idx].len = pkt_curr->data_len;
		}
		local_sg_desc.nb = tx_pkt->nb_segs;
	}

	if (tx_ring->adapter->cap & LSINIC_CAP_XFER_COMPLETE) {
		if (pkt_curr) {
			pdata = (char *)rte_pktmbuf_mtod(pkt_curr, char *);
			*((uint8_t *)pdata + pkt_curr->data_len) =
				LSINIC_XFER_COMPLETE_DONE_FLAG;
		} else {
			pdata = (char *)rte_pktmbuf_mtod(tx_pkt, char *);
			*((uint8_t *)pdata + tx_pkt->pkt_len) =
				LSINIC_XFER_COMPLETE_DONE_FLAG;
		}
	}

	if (local_desc) {
		memcpy(local_desc, &local_sg_desc,
			sizeof(struct lsinic_seg_desc));
	} else {
		copy_len = sizeof(uint64_t) +
			sizeof(struct lsinic_seg_desc_entry) *
			local_sg_desc.nb;

		lsinic_pcie_memcp_align(ep_sg_desc,
			&local_sg_desc, copy_len);
		rte_wmb();
		ep_sg_desc->nb = local_sg_desc.nb;
	}

	tx_ring->packets += local_sg_desc.nb;
	tx_ring->bytes += tx_pkt->pkt_len;
	tx_ring->bytes_fcs += tx_pkt->pkt_len + LSINIC_ETH_FCS_SIZE;
	tx_ring->bytes_overhead += tx_pkt->pkt_len +
			LSINIC_ETH_OVERHEAD_SIZE;

	tx_ring->tx_free_len++;
	tx_ring->last_avail_idx++;

	return 0;
}

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
static int
lxsnic_try_to_merge(struct lxsnic_ring *txq,
	struct rte_mbuf **tx_pkts, uint16_t nb_pkts,
	struct rte_mbuf **free_pkts, uint16_t *nb_free,
	void *local_notify)
{
	uint16_t i, free_idx = 0;
	int ret = 0;
	uint16_t mg_num;
	uint16_t mg_len = 0, align_len, align_off;
	uint32_t bytes, overhead, fcs;
	struct rte_mbuf *tx_pkt;
	char *dst_buf, *data = NULL;
	struct lsinic_mg_header *mg_header;
	uint32_t max_data_room;
	const uint32_t cap = txq->adapter->cap;

	if (!(cap & LSINIC_CAP_XFER_PKT_MERGE))
		return 0;

	bytes = 0;
	overhead = 0;
	fcs = 0;

	max_data_room = txq->adapter->max_data_room;
	max_data_room -= LSINIC_RC_TX_DATA_ROOM_OVERHEAD;
	if (cap & LSINIC_CAP_XFER_COMPLETE)
		max_data_room--;

	for (mg_num = 0; mg_num < nb_pkts; mg_num++) {
		if (mg_num == LSINIC_MERGE_MAX_NUM)
			break;

		tx_pkt = tx_pkts[mg_num];
		if (tx_pkt->nb_segs > 1)
			return 0;

		if (tx_pkt->pkt_len > txq->adapter->merge_threshold)
			break;

		if ((mg_len + ALIGN(tx_pkt->pkt_len, LSINIC_MG_ALIGN_SIZE)) >=
			max_data_room)
			break;

		mg_len += ALIGN(tx_pkt->pkt_len, LSINIC_MG_ALIGN_SIZE);
		/* todo calculate sg mbuf */
	}

	/* No need to merge */
	if (mg_num <= 1)
		return 0;

	/* The first packet */
	tx_pkt = tx_pkts[0];

	data = (char *)rte_pktmbuf_mtod(tx_pkt, char *);
	mg_header = (struct lsinic_mg_header *)
		(data - sizeof(struct lsinic_mg_header));
	align_len = ALIGN(tx_pkt->pkt_len, LSINIC_MG_ALIGN_SIZE);
	align_off = align_len - tx_pkt->pkt_len;
	mg_header->len_cmd[0] =
		lsinic_mg_entry_set(tx_pkt->pkt_len, align_off);

	dst_buf = data + align_len;
	bytes += tx_pkt->pkt_len;
	fcs += tx_pkt->pkt_len + LSINIC_ETH_FCS_SIZE;
	overhead += tx_pkt->pkt_len + LSINIC_ETH_OVERHEAD_SIZE;

	for (i = 1; i < mg_num; i++) {
		tx_pkt = tx_pkts[i];
		align_len = ALIGN(tx_pkt->pkt_len, LSINIC_MG_ALIGN_SIZE);
		align_off = align_len - tx_pkt->pkt_len;
		mg_header->len_cmd[i] =
			lsinic_mg_entry_set(tx_pkt->pkt_len, align_off);
		rte_memcpy(dst_buf, rte_pktmbuf_mtod(tx_pkt, char *),
			tx_pkt->pkt_len);
		dst_buf += align_len;

		bytes += tx_pkt->pkt_len;
		fcs += tx_pkt->pkt_len + LSINIC_ETH_FCS_SIZE;
		overhead += tx_pkt->pkt_len + LSINIC_ETH_OVERHEAD_SIZE;

		free_pkts[free_idx] = tx_pkt;
		free_idx++;
	}
	if (mg_num < LSINIC_MERGE_MAX_NUM)
		mg_header->len_cmd[mg_num] = 0;

	tx_pkt = tx_pkts[0];
	tx_pkt->pkt_len = mg_len;
	tx_pkt->data_len = mg_len;
	RTE_ASSERT(tx_pkt->data_off > sizeof(struct lsinic_mg_header));
	tx_pkt->nb_segs = 1;
	tx_pkt->next = NULL;
	if (txq->ep_mem_bd_type == EP_MEM_SRC_ADDRX_BD) {
		ret = lxsnic_xmit_one_pkt_idx(txq,
			tx_pkt, mg_num, local_notify);
	} else if (txq->ep_mem_bd_type == EP_MEM_SRC_ADDRL_BD) {
		ret = lxsnic_xmit_one_pkt_addrl(txq,
			tx_pkt, mg_num, local_notify);
	} else {
		ret = lxsnic_xmit_one_pkt(txq, tx_pkt, mg_num, local_notify);
	}
	if (unlikely(ret))
		return -1;

	txq->bytes += bytes;
	txq->bytes_fcs += fcs;
	txq->bytes_overhead += overhead;
	txq->packets += mg_num;
	(*nb_free) += free_idx;

	return mg_num;
}
#endif

static inline void
lxsnic_eth_xmit_notify(struct lxsnic_ring *txq,
	uint16_t first_idx, uint16_t notify_len,
	union lsinic_ep2rc_notify *notify)
{
	struct lsinic_ep_rx_src_addrl *tx_addrl;
	struct lsinic_ep_rx_src_addrx *tx_addrx;
	struct lsinic_bd_desc *desc;
	void *src, *dst;
	int i;
	uint16_t ext_notify_len;

	if (txq->rdma) {
		tx_addrl = txq->rc_tx_addrl;
		tx_addrx = txq->rc_tx_addrx;
		desc = txq->rc_bd_desc;
	} else {
		tx_addrl = txq->ep_tx_addrl;
		tx_addrx = txq->ep_tx_addrx;
		desc = txq->ep_bd_desc;
	}

	if (txq->ep_mem_bd_type == EP_MEM_SRC_ADDRL_BD) {
		if ((first_idx + notify_len) <= txq->count) {
			src = &notify->ep_tx_addrl[0];
			dst = &tx_addrl[first_idx];
			memcpy(dst, src, notify_len *
				sizeof(struct lsinic_ep_rx_src_addrl));
		} else {
			src = &notify->ep_tx_addrl[0];
			dst = &tx_addrl[first_idx];
			memcpy(dst, src, (txq->count - first_idx) *
				sizeof(struct lsinic_ep_rx_src_addrl));

			src = &notify->ep_tx_addrl[txq->count - first_idx];
			dst = &tx_addrl[0];
			memcpy(dst, src,
				(notify_len + first_idx - txq->count) *
				sizeof(struct lsinic_ep_rx_src_addrl));
		}
	} else if (txq->ep_mem_bd_type == EP_MEM_SRC_ADDRX_BD) {
		struct lsinic_ep_rx_src_addrx *addrx;

		if ((first_idx + notify_len) <= txq->count) {
			addrx = &notify->ep_tx_addrx[notify_len];
			for (i = 0; i < XMIT_IDX_EXTRA_SPACE; i++)
				addrx[i].idx_cmd_len = 0;

			ext_notify_len = notify_len + XMIT_IDX_EXTRA_SPACE;
			src = &notify->ep_tx_addrx[0];
			dst = &tx_addrx[first_idx];
			memcpy(dst, src, ext_notify_len *
				sizeof(struct lsinic_ep_rx_src_addrx));
		} else {
			ext_notify_len = txq->count - first_idx +
				XMIT_IDX_EXTRA_SPACE;
			src = &notify->ep_tx_addrx[0];
			dst = &tx_addrx[first_idx];
			memcpy(dst, src, ext_notify_len *
				sizeof(struct lsinic_ep_rx_src_addrx));

			addrx = &notify->ep_tx_addrx[notify_len];
			for (i = 0; i < XMIT_IDX_EXTRA_SPACE; i++)
				addrx[i].idx_cmd_len = 0;
			ext_notify_len = first_idx + notify_len - txq->count +
				XMIT_IDX_EXTRA_SPACE;
			src = &notify->ep_tx_addrx[txq->count - first_idx];
			dst = &tx_addrx[0];
			memcpy(dst, src, ext_notify_len *
				sizeof(struct lsinic_ep_rx_src_addrx));
		}
	} else if (txq->ep_mem_bd_type == EP_MEM_LONG_BD) {
		int dst_idx;
		struct lsinic_bd_desc *src_desc;

		src_desc = notify->ep_tx_addr;
		for (i = 0; i < notify_len; i++) {
			src = (void *)&src_desc[i];
			dst_idx = (first_idx + i) & (txq->count - 1);
			dst = (void *)&desc[dst_idx];
			mem_cp128b_atomic(dst, src);
		}
	} else {
		LSXINIC_PMD_ERR("%s: type(%d) of bd in ep mem un-support",
			__func__, txq->ep_mem_bd_type);

		return;
	}

	if (txq->rdma) {
		rte_wmb();
		txq->ep_reg->pir = (first_idx + notify_len) & (txq->count - 1);
	}
}

static uint16_t
_lxsnic_eth_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
		uint16_t nb_pkts)
{
	int ret = 0;
	uint8_t ret_val = 0;
	uint16_t tx_num = 0;
	uint16_t total_nb_pkts = nb_pkts;
	struct lxsnic_ring *tx_ring = tx_queue;
	struct rte_mbuf *free_pkts[LSINIC_MAX_BURST_NUM];
	uint16_t free_nb = 0, notify_len = 0;
	uint16_t first_idx =
		tx_ring->last_avail_idx & (tx_ring->count - 1);
	union lsinic_ep2rc_notify notify;

	tx_ring->loop_total++;

	if (tx_ring->rc_reg)
		ret_val = LSINIC_READ_REG(&tx_ring->rc_reg->sr);
	else
		ret_val = LSINIC_READ_REG(&tx_ring->ep_reg->sr);

	tx_ring->status = ret_val;

	if (unlikely(!RTE_PER_LCORE(txq_added[tx_ring->queue_index]))) {
		rte_spinlock_lock(&tx_ring->multi_core_lock);
		lxsnic_add_txq_to_list(tx_ring);
		rte_spinlock_unlock(&tx_ring->multi_core_lock);
		RTE_PER_LCORE(txq_added[tx_ring->queue_index]) = 1;
	} else {
		lxsnic_add_txq_to_list(tx_ring);
	}

	if (unlikely(!RTE_PER_LCORE(pthrd_id)))
		RTE_PER_LCORE(pthrd_id) = pthread_self();

	if (tx_ring->pair && unlikely(tx_ring->core_id !=
		rte_lcore_id() || !pthread_equal(tx_ring->pid,
		RTE_PER_LCORE(pthrd_id)))) {
		if (!tx_ring->multi_core_ring) {
			char ring_name[RTE_MEMZONE_NAMESIZE];

			sprintf(ring_name, "tx_ring_mpsc_ring_%d_%d",
				tx_ring->port, tx_ring->queue_index);
			rte_spinlock_lock(&tx_ring->multi_core_lock);
			if (tx_ring->multi_core_ring) {
				rte_spinlock_unlock(&tx_ring->multi_core_lock);
				goto eq_start;
			}
			tx_ring->multi_core_ring = rte_ring_create(ring_name,
				tx_ring->count, rte_socket_id(),
				RING_F_SC_DEQ);
			rte_spinlock_unlock(&tx_ring->multi_core_lock);
			if (tx_ring->multi_core_ring) {
				LSXINIC_PMD_INFO("%s created on core%d",
					ring_name, rte_lcore_id());
			} else {
				LSXINIC_PMD_ERR("%s created on core%d failed",
					ring_name, rte_lcore_id());
				return 0;
			}
		}

eq_start:
		ret = rte_ring_mp_enqueue_burst(tx_ring->multi_core_ring,
			(void * const *)tx_pkts, nb_pkts, NULL);
		return ret;
	}

	if (ret_val == LSINIC_QUEUE_STOP) {
		if (ret_val != tx_ring->ep_sr)
			LSXINIC_PMD_DBG("ep-rx queue down");

		tx_ring->ep_sr = ret_val;
		tx_ring->errors++;
		tx_num = 0;
		goto end_of_tx;
	}

	if (tx_ring->rc_mem_bd_type == RC_MEM_BD_CNF)
		lxsnic_tx_complete_ring_clean(tx_ring);
	else if (tx_ring->rc_mem_bd_type == RC_MEM_IDX_CNF)
		lxsnic_tx_ring_idx_clean(tx_ring);
	else
		lxsnic_tx_ring_clean(tx_ring);

	nb_pkts = (uint16_t)RTE_MIN(tx_ring->count, total_nb_pkts);
	if (unlikely(!nb_pkts)) {
		tx_num = 0;
		goto end_of_tx;
	}

	if (tx_ring->ep_mem_bd_type == EP_MEM_SRC_SEG_BD) {
		while (nb_pkts) {
			ret = lxsnic_xmit_one_seg_pkt(tx_ring,
				tx_pkts[tx_num], NULL);
			if (likely(!ret)) {
				tx_num++;
				nb_pkts--;
			} else {
				break;
			}
		}
		return tx_num;
	}

	if (tx_ring->ep_mem_bd_type == EP_MEM_SRC_ADDRL_BD) {
		while (nb_pkts) {
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
			ret = lxsnic_try_to_merge(tx_ring, &tx_pkts[tx_num],
				nb_pkts, &free_pkts[free_nb], &free_nb,
				&notify.ep_tx_addrl[notify_len]);
			if (ret < 0)
				goto end_of_tx;
			if (ret) {
				notify_len++;
				tx_num += ret;
				nb_pkts -= ret;
			} else
#endif
			{
				ret = lxsnic_xmit_one_pkt_addrl(tx_ring,
					tx_pkts[tx_num], 0,
					&notify.ep_tx_addrl[notify_len]);
				if (ret)
					goto end_of_tx;
				notify_len++;
				tx_num++;
				nb_pkts--;
			}
		}
		goto end_of_tx;
	} else if (tx_ring->ep_mem_bd_type == EP_MEM_SRC_ADDRX_BD) {
		while (nb_pkts) {
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
			ret = lxsnic_try_to_merge(tx_ring, &tx_pkts[tx_num],
				nb_pkts, &free_pkts[free_nb], &free_nb,
				&notify.ep_tx_addrx[notify_len]);
			if (ret < 0)
				goto end_of_tx;
			if (ret) {
				notify_len++;
				tx_num += ret;
				nb_pkts -= ret;
			} else
#endif
			{
				ret = lxsnic_xmit_one_pkt_idx(tx_ring,
					tx_pkts[tx_num], 0,
					&notify.ep_tx_addrx[notify_len]);
				if (ret)
					goto end_of_tx;
				notify_len++;
				tx_num++;
				nb_pkts--;
			}
		}
		goto end_of_tx;
	}

	while (nb_pkts) {
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
		ret = lxsnic_try_to_merge(tx_ring, &tx_pkts[tx_num],
			nb_pkts, &free_pkts[free_nb], &free_nb,
			&notify.ep_tx_addr[notify_len]);
		if (ret < 0)
			goto end_of_tx;

		if (ret) {
			notify_len++;
			tx_num += ret;
			nb_pkts -= ret;
		} else
#endif
		{
			ret = lxsnic_xmit_one_pkt(tx_ring,
				tx_pkts[tx_num], 0,
				&notify.ep_tx_addr[notify_len]);
			if (ret)
				goto end_of_tx;

			notify_len++;
			tx_num++;
			nb_pkts--;
		}
	}

end_of_tx:
	lxsnic_eth_xmit_notify(tx_ring, first_idx, notify_len, &notify);

	if (free_nb > 0)
		rte_pktmbuf_free_bulk(free_pkts, free_nb);

	tx_ring->loop_avail++;

	tx_ring->drop_packet_num += (total_nb_pkts - tx_num);

	return tx_num;
}

uint16_t
lxsnic_eth_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts)
{
	struct lxsnic_ring *tx_ring = (struct lxsnic_ring *)tx_queue;

	if (unlikely(tx_ring->adapter->self_test !=
		LXSNIC_RC_SELF_NONE_TEST))
		return 0;

	return _lxsnic_eth_xmit_pkts(tx_queue, tx_pkts, nb_pkts);
}

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
static int
lxsnic_fetch_merge_rx_buffer(struct lxsnic_ring *rx_queue,
	void *rx_desc, uint16_t mg_num)
{
	char *data = NULL;
	char *data_base;
	uint16_t pkt_len = 0, align_off;
	int idx = 0, offset = 0;
	struct rte_mbuf *mbuf;
	struct lsinic_mg_header *mg_header;
	uint32_t total_size;
	struct lsinic_bd_desc *bd_desc = NULL;
	uint32_t mbuf_idx;
	struct lsinic_rc_rx_len_cmd *rx_len_cmd;
	const uint32_t cap = rx_queue->adapter->cap;

	if (rx_queue->rc_mem_bd_type == RC_MEM_LEN_CMD) {
		rx_len_cmd = rx_desc;
		if (cap & LSINIC_CAP_XFER_ORDER_PRSV) {
			mbuf_idx = rx_queue->last_used_idx &
				(rx_queue->count - 1);
		} else {
			mbuf_idx = EP2RC_TX_CTX_IDX(rx_len_cmd->cnt_idx);
		}
		mbuf = (struct rte_mbuf *)rx_queue->q_mbuf[mbuf_idx];
		total_size = rx_len_cmd->total_len;
	} else {
		bd_desc = rx_desc;
		if (cap & LSINIC_CAP_XFER_ORDER_PRSV) {
			mbuf_idx = rx_queue->last_used_idx &
				(rx_queue->count - 1);
		} else {
			mbuf_idx = lsinic_bd_ctx_idx(bd_desc->bd_status);
		}
		mbuf = (struct rte_mbuf *)rx_queue->q_mbuf[mbuf_idx];
		total_size = LSINIC_READ_REG(&bd_desc->len_cmd) &
			LSINIC_BD_LEN_MASK;
	}

	RTE_ASSERT(mbuf);

#ifdef RTE_ENABLE_ASSERT
	if (bd_desc && bd_desc->bd_status & RING_BD_ADDR_CHECK) {
		rte_iova_t iova = rte_mbuf_data_iova_default(mbuf);

		if (unlikely(iova != bd_desc->pkt_addr)) {
			LSXINIC_PMD_ERR("pkt_addr(0x%lx) != mbuf iova(0x%lx)",
				bd_desc->pkt_addr, iova);
		}
		RTE_ASSERT(rte_cpu_to_le_64(iova) == bd_desc->pkt_addr);
	}
#endif
	rte_lxsnic_prefetch(mbuf);

	if (total_size  > rx_queue->adapter->max_data_room) {
		LSXINIC_PMD_ERR("packet(%d) is too bigger!\n",
			total_size);
		return 0;
	}

	mbuf->data_off = RTE_PKTMBUF_HEADROOM;
	data_base = rte_pktmbuf_mtod(mbuf, char *);
	rte_lxsnic_packet_prefetch(data_base);
	mg_header = (struct lsinic_mg_header *)
		(data_base - sizeof(struct lsinic_mg_header));

	pkt_len = lsinic_mg_entry_len(mg_header->len_cmd[0]);

	mbuf->nb_segs = 1;
	mbuf->next = NULL;
	mbuf->pkt_len = pkt_len;
	mbuf->data_len = pkt_len;
	mbuf->port = rx_queue->port;
	mbuf->packet_type = RTE_PTYPE_L3_IPV4;
	rx_queue->mcache[rx_queue->mtail] = mbuf;
	rx_queue->mtail = (rx_queue->mtail + 1) & MCACHE_MASK;
	rx_queue->mcnt++;

	align_off = lsinic_mg_entry_align_offset(mg_header->len_cmd[0]);
	offset = pkt_len + align_off;

	LSXINIC_PMD_DBG("RC MGD0: len=%d next mgd offset=%d\n",
		pkt_len, offset);

	for (idx = 1; idx < mg_num; idx++) {
		pkt_len = lsinic_mg_entry_len(mg_header->len_cmd[idx]);
		align_off =
			lsinic_mg_entry_align_offset(mg_header->len_cmd[idx]);

		mbuf = rte_mbuf_raw_alloc(rx_queue->mb_pool);
		if (!mbuf) {
			LSXINIC_PMD_DBG("MG RX mbuf alloc failed p:%u q:%u",
				rx_queue->port, rx_queue->queue_index);
			break;
		}

		mbuf->data_off = RTE_PKTMBUF_HEADROOM;
		data = rte_pktmbuf_mtod(mbuf, char *);
		rte_memcpy(data, (void *)(data_base + offset), pkt_len);
		mbuf->nb_segs = 1;
		mbuf->next = NULL;
		mbuf->pkt_len = pkt_len;
		mbuf->data_len = pkt_len;
		mbuf->port = rx_queue->port;
		mbuf->packet_type = RTE_PTYPE_L3_IPV4;

		rx_queue->mcache[rx_queue->mtail] = mbuf;
		rx_queue->mtail = (rx_queue->mtail + 1) & MCACHE_MASK;
		rx_queue->mcnt++;

		offset += pkt_len + align_off;
		LSXINIC_PMD_DBG("RC CBD%d: len=%d next mg offset=%d",
			idx, pkt_len, offset);
	}

	return idx;
}
#endif

static struct rte_mbuf *
lxsnic_fetch_rx_buffer(struct lxsnic_ring *rx_queue,
	void *rx_desc)
{
	struct rte_mbuf *mbuf;
	uint16_t rx_packet_len;
	struct lsinic_bd_desc *bd_desc;
	uint32_t mbuf_idx;
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	struct lsinic_rc_rx_len_cmd *rx_len_cmd;
#else
	struct lsinic_rc_rx_len_idx *rx_len_idx;
#endif
	const uint32_t cap = rx_queue->adapter->cap;

	if (rx_queue->rc_mem_bd_type == RC_MEM_LEN_CMD) {
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
		rx_len_cmd = rx_desc;
		if (cap & LSINIC_CAP_XFER_ORDER_PRSV) {
			mbuf_idx = rx_queue->last_used_idx &
				(rx_queue->count - 1);
		} else {
			mbuf_idx = EP2RC_TX_CTX_IDX(rx_len_cmd->cnt_idx);
		}
		mbuf = (struct rte_mbuf *)rx_queue->q_mbuf[mbuf_idx];
		rx_packet_len = rx_len_cmd->total_len;
#else
		rx_len_idx = rx_desc;
		if (cap & LSINIC_CAP_XFER_ORDER_PRSV) {
			mbuf_idx = rx_queue->last_used_idx &
				(rx_queue->count - 1);
		} else {
			mbuf_idx = rx_len_idx->idx;
		}
		mbuf = (struct rte_mbuf *)rx_queue->q_mbuf[mbuf_idx];
		rx_packet_len = rx_len_idx->total_len;
#endif
	} else {
		bd_desc = rx_desc;
		if (cap & LSINIC_CAP_XFER_ORDER_PRSV) {
			mbuf_idx = rx_queue->last_used_idx &
				(rx_queue->count - 1);
		} else {
			mbuf_idx = lsinic_bd_ctx_idx(bd_desc->bd_status);
		}
		mbuf = (struct rte_mbuf *)rx_queue->q_mbuf[mbuf_idx];
		rx_packet_len = LSINIC_READ_REG(&bd_desc->len_cmd) &
			LSINIC_BD_LEN_MASK;
	}

	RTE_ASSERT(mbuf);

	rte_lxsnic_prefetch(mbuf);

	if (rx_packet_len  > rx_queue->adapter->max_data_room) {
		LSXINIC_PMD_ERR("recv pkt len %d, too big!",
			rx_packet_len);

		return NULL;
	}

	mbuf->data_off = RTE_PKTMBUF_HEADROOM;
	rte_lxsnic_packet_prefetch((char *)mbuf->buf_addr);
	mbuf->nb_segs = 1;
	mbuf->next = NULL;
	mbuf->pkt_len = rx_packet_len;
	mbuf->data_len = rx_packet_len;
	mbuf->port = rx_queue->port;
	mbuf->packet_type = RTE_PTYPE_L3_IPV4;
	/* TODO populate checksum, timestamp, VLAN, and protocol */

	return mbuf;
}

static inline void
lxsnic_rx_lbd_fill(struct lxsnic_ring *rx_queue, uint16_t start_idx,
	struct rte_mbuf *mbufs[], int count)
{
	int cnt = 0;
	uint64_t dma_addr = 0;
	uint16_t idx = start_idx;
	uint32_t mbuf_idx;
	struct lsinic_bd_desc *ep_rx_desc = NULL, *rc_rx_desc = NULL;
	struct lsinic_bd_desc local_rx_desc;
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	struct lsinic_rc_rx_len_cmd *rx_len_cmd;
#else
	struct lsinic_rc_rx_len_idx *rx_len_idx;
#endif

	ep_rx_desc = rx_queue->ep_bd_desc;
	while (cnt < count) {
		mbufs[cnt]->data_off = RTE_PKTMBUF_HEADROOM;
		mbufs[cnt]->port = rx_queue->port;
		dma_addr = rte_mbuf_data_iova_default(mbufs[cnt]);

		if (rx_queue->rc_mem_bd_type == RC_MEM_LONG_BD) {
			rc_rx_desc = &rx_queue->rc_bd_desc[idx];
			mbuf_idx = lsinic_bd_ctx_idx(rc_rx_desc->bd_status);
		} else {
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
			rx_len_cmd = &rx_queue->rx_len_cmd[idx];
			mbuf_idx = EP2RC_TX_CTX_IDX(rx_len_cmd->cnt_idx);
			rx_len_cmd->len_cnt_idx = 0;
#else
			rx_len_idx = &rx_queue->rx_len_idx[idx];
			mbuf_idx = rx_len_idx->idx;
			rx_len_idx->len_idx = 0;
#endif
			rc_rx_desc = &local_rx_desc;
			memset(rc_rx_desc, 0, sizeof(struct lsinic_bd_desc));
		}
		rc_rx_desc->pkt_addr = dma_addr;
		rc_rx_desc->bd_status = RING_BD_READY |
			(mbuf_idx << LSINIC_BD_CTX_IDX_SHIFT);
		if (!rx_queue->rdma) {
			memcpy(&ep_rx_desc[idx], rc_rx_desc,
				sizeof(struct lsinic_bd_desc));
		}
		rx_queue->q_mbuf[mbuf_idx] = mbufs[cnt];
		cnt++;
		idx = (idx + 1) & (rx_queue->count - 1);
	}

	if (rx_queue->rdma) {
		rte_wmb();
		rx_queue->ep_reg->pir =
			(start_idx + count) & (rx_queue->count - 1);
	}
}

static inline void
lxsnic_rx_sbd_fill(struct lxsnic_ring *rx_queue, uint16_t start_idx,
	struct rte_mbuf *mbufs[], int count)
{
	int cnt = 0;
	uint64_t dma_addr = 0;
	uint16_t idx = start_idx;
	uint32_t mbuf_idx;
	struct lsinic_ep_tx_dst_addr *local_recv_addr;
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	struct lsinic_rc_rx_len_cmd *rx_len_cmd;
#else
	struct lsinic_rc_rx_len_idx *rx_len_idx;
#endif

	local_recv_addr = rx_queue->rc_rx_addr;

	while (cnt < count) {
		mbufs[cnt]->data_off = RTE_PKTMBUF_HEADROOM;
		mbufs[cnt]->port = rx_queue->port;
		dma_addr = rte_mbuf_data_iova_default(mbufs[cnt]);

		mbuf_idx = idx;
		local_recv_addr[idx].pkt_addr = dma_addr;
		if (rx_queue->rc_mem_bd_type == RC_MEM_LEN_CMD) {
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
			rx_len_cmd = &rx_queue->rx_len_cmd[idx];
			rx_len_cmd->len_cnt_idx = 0;
#else
			rx_len_idx = &rx_queue->rx_len_idx[idx];
			rx_len_idx->len_idx = 0;
#endif
		}
		rx_queue->q_mbuf[mbuf_idx] = mbufs[cnt];
		cnt++;
		idx = (idx + 1) & (rx_queue->count - 1);
	}

	if (rx_queue->rdma) {
		rte_wmb();
		rx_queue->ep_reg->pir =
			(start_idx + count) & (rx_queue->count - 1);

		return;
	}
	if ((start_idx + cnt) <= rx_queue->count) {
		memcpy(&rx_queue->ep_rx_addr[start_idx],
			&local_recv_addr[start_idx],
			sizeof(uint64_t) * cnt);
	} else {
		memcpy(&rx_queue->ep_rx_addr[start_idx],
			&local_recv_addr[start_idx],
			sizeof(uint64_t) *
			(rx_queue->count - start_idx));
		memcpy(&rx_queue->ep_rx_addr[0],
			&local_recv_addr[0],
			sizeof(uint64_t) *
			(start_idx + cnt - rx_queue->count));
	}
}

static void
lxsnic_rx_bd_fill(struct lxsnic_ring *rx_queue, uint16_t start_idx,
	struct rte_mbuf *mbufs[], int count)
{
	if (unlikely(!count))
		return;

	if (rx_queue->ep_mem_bd_type == EP_MEM_DST_ADDR_BD)
		lxsnic_rx_sbd_fill(rx_queue, start_idx, mbufs, count);
	else
		lxsnic_rx_lbd_fill(rx_queue, start_idx, mbufs, count);
}

static inline void
lxsnic_rx_seg_bd_fill(struct lxsnic_ring *rx_queue, uint16_t start_idx,
	struct rte_mbuf *mbufs[], uint8_t count)
{
	int cnt = 0;
	uint64_t dma_addr = 0;
	struct lsinic_ep_tx_seg_dst_addr *local_seg =
		rx_queue->local_rx_addr_seg;
	struct lsinic_ep_tx_seg_dst_addr *ep_rx_addr_seg;

	local_seg->addr_base = rte_mbuf_data_iova_default(mbufs[0]);
	ep_rx_addr_seg = &rx_queue->ep_rx_addr_seg[start_idx];
	while (cnt < count) {
		mbufs[cnt]->data_off = RTE_PKTMBUF_HEADROOM;
		mbufs[cnt]->port = rx_queue->port;
		dma_addr = rte_mbuf_data_iova_default(mbufs[cnt]);

		if (dma_addr > local_seg->addr_base) {
			local_seg->entry[cnt].positive = 1;
			local_seg->entry[cnt].offset =
				dma_addr - local_seg->addr_base;
		} else {
			local_seg->entry[cnt].positive = 0;
			local_seg->entry[cnt].offset =
				local_seg->addr_base - dma_addr;
		}

		rx_queue->seg_mbufs[start_idx].mbufs[cnt] = mbufs[cnt];
		cnt++;
	}

	lsinic_pcie_memcp_align(ep_rx_addr_seg,
		local_seg,
		sizeof(uint64_t) +
		sizeof(struct lsinic_ep_tx_seg_entry) * count);
	rte_wmb();
	ep_rx_addr_seg->ready = count;
}

static uint16_t
lxsnic_eth_recv_seg_pkts_to_cache(struct lxsnic_ring *rxq)
{
	int ret, total_nb, i;
	uint32_t ret_val = 0, total_len = 0;
	uint16_t nb_rx = 0;
	struct lsinic_rc_rx_seg *rx_seg;
	struct rte_mbuf *mbuf, *next_mbuf = NULL;
	uint16_t idx = 0, seg_nb = 0, next_idx;

	rxq->loop_total++;

	if (rxq->rc_reg)
		ret_val = LSINIC_READ_REG(&rxq->rc_reg->sr);
	else
		ret_val = LSINIC_READ_REG(&rxq->ep_reg->sr);

	rxq->status = ret_val;
	rxq->core_id = rte_lcore_id();

	if (ret_val == LSINIC_QUEUE_STOP) {
		if (ret_val != rxq->ep_sr)
			LSXINIC_PMD_DBG("ep-tx queue down");
		rxq->ep_sr = ret_val;
		return 0;
	}
	rxq->ep_sr = ret_val;

	rx_seg = rxq->rx_seg;

	while (nb_rx < rxq->count) {
		if (rxq->mcnt > LSINIC_MAX_BURST_NUM)
			break;
		idx = rxq->last_used_idx & (rxq->count - 1);

		next_idx = (idx + 1) & (rxq->count - 1);
		rte_prefetch0(&rx_seg[next_idx]);

		if (!rx_seg[idx].nb)
			break;

		rxq->rx_fill_len++;
		total_nb = rx_seg[idx].nb;
		total_len = 0;
		seg_nb = 0;
		next_mbuf = NULL;
		for (i = total_nb - 1; i >= 0; i--) {
			mbuf = rxq->seg_mbufs[idx].mbufs[i];
			mbuf->data_len = rx_seg[idx].len[i];
			total_len += mbuf->data_len;
			mbuf->pkt_len = total_len;
			seg_nb++;
			mbuf->nb_segs = seg_nb;
			mbuf->next = next_mbuf;
			next_mbuf = mbuf;
		}
		rx_seg[idx].nb = 0;
		rxq->mcache[rxq->mtail] = rxq->seg_mbufs[idx].mbufs[0];
		rxq->mtail = (rxq->mtail + 1) & MCACHE_MASK;
		rxq->mcnt++;

		nb_rx++;

		rxq->last_used_idx++;  /* step to next */
		ret = rte_pktmbuf_alloc_bulk(rxq->mb_pool,
			rxq->seg_mbufs[idx].mbufs,
			total_nb);
		if (ret)
			break;

		lxsnic_rx_seg_bd_fill(rxq, rxq->rx_fill_start_idx,
			rxq->seg_mbufs[idx].mbufs, LSINIC_EP_TX_SEG_MAX_ENTRY);
		rxq->rx_fill_start_idx++;
		rxq->rx_fill_start_idx =
			rxq->rx_fill_start_idx & (rxq->count - 1);
		rxq->rx_fill_len--;
	}

	rxq->loop_avail++;

	return nb_rx;
}

static uint16_t
lxsnic_eth_recv_pkts_to_cache(struct lxsnic_ring *rx_queue)
{
	int count = 0;
	uint32_t ret_val = 0;
	uint16_t nb_rx = 0;
	struct lsinic_bd_desc *rx_desc;
	struct lsinic_bd_desc local_desc;
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	struct lsinic_rc_rx_len_cmd *rx_len_cmd = NULL;
#else
	struct lsinic_rc_rx_len_idx *rx_len_idx = NULL;
#endif
	struct rte_mbuf *mbuf = NULL;
	uint16_t idx = 0;

	if (rx_queue->rc_mem_bd_type == RC_MEM_SEG_LEN)
		return lxsnic_eth_recv_seg_pkts_to_cache(rx_queue);

	rx_queue->loop_total++;

	if (rx_queue->rc_reg)
		ret_val = LSINIC_READ_REG(&rx_queue->rc_reg->sr);
	else
		ret_val = LSINIC_READ_REG(&rx_queue->ep_reg->sr);

	rx_queue->status = ret_val;
	rx_queue->core_id = rte_lcore_id();

	if (ret_val == LSINIC_QUEUE_STOP) {
		if (ret_val != rx_queue->ep_sr)
			LSXINIC_PMD_DBG("ep-tx queue down");
		rx_queue->ep_sr = ret_val;
		return 0;
	}
	rx_queue->ep_sr = ret_val;

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	if (rx_queue->rc_mem_bd_type == RC_MEM_LEN_CMD)
		rx_len_cmd = rx_queue->rx_len_cmd;

	while (nb_rx < rx_queue->count) {
		idx = rx_queue->last_used_idx & (rx_queue->count - 1);

		if (rx_len_cmd) {
			if (!rx_len_cmd[idx].len_cnt_idx)
				break;
			goto mg_skip_parse_bd;
		}
		rx_desc = &rx_queue->rc_bd_desc[idx];
		mem_cp128b_atomic((uint8_t *)&local_desc, (uint8_t *)rx_desc);
		if ((local_desc.bd_status & RING_BD_STATUS_MASK) !=
			RING_BD_HW_COMPLETE)
			break;
		rx_desc = &local_desc;

mg_skip_parse_bd:
		rx_queue->rx_fill_len++;

		/* This memory barrier is needed to keep us from reading
		 * any other fields out of the rx_desc until we know the
		 * descriptor has been written back
		 */
		count = 0;
		if (rx_len_cmd) {
			count = EP2RC_TX_CTX_CNT(rx_len_cmd[idx].cnt_idx);
			if (count) {
				count = lxsnic_fetch_merge_rx_buffer(rx_queue,
					&rx_len_cmd[idx], count);
			} else {
				mbuf = lxsnic_fetch_rx_buffer(rx_queue,
					&rx_len_cmd[idx]);
				if (mbuf) {
					rx_queue->mcache[rx_queue->mtail] =
						mbuf;
					rx_queue->mtail = (rx_queue->mtail + 1)
						& MCACHE_MASK;
					rx_queue->mcnt++;
					count = 1;
				}
			}
		} else if (lxsnic_test_staterr(rx_desc, LSINIC_BD_CMD_MG)) {
			count = ((rx_desc->len_cmd & LSINIC_BD_MG_NUM_MASK) >>
					LSINIC_BD_MG_NUM_SHIFT);
			count = lxsnic_fetch_merge_rx_buffer(rx_queue,
					rx_desc, count);
		} else {
			mbuf = lxsnic_fetch_rx_buffer(rx_queue, rx_desc);
			if (mbuf) {
				rx_queue->mcache[rx_queue->mtail] = mbuf;
				rx_queue->mtail = (rx_queue->mtail + 1)
					& MCACHE_MASK;
				rx_queue->mcnt++;
				count = 1;
			}
		}

		nb_rx++;

		rx_queue->last_used_idx++;  /* step to next */
		if (!count) {
			rx_queue->drop_packet_num++;
			break;
		}
		if (rx_queue->mcnt > LSINIC_MERGE_MAX_NUM)
			break;
	}
#else
	if (rx_queue->rc_mem_bd_type == RC_MEM_LEN_CMD)
		rx_len_idx = rx_queue->rx_len_idx;

	while (nb_rx < rx_queue->count) {
		idx = rx_queue->last_used_idx & (rx_queue->count - 1);

		if (rx_len_idx) {
			if (!rx_len_idx[idx].len_idx)
				break;
			goto skip_parse_bd;
		}
		rx_desc = &rx_queue->rc_bd_desc[idx];
		mem_cp128b_atomic((uint8_t *)&local_desc, (uint8_t *)rx_desc);
		if ((local_desc.bd_status & RING_BD_STATUS_MASK) !=
			RING_BD_HW_COMPLETE)
			break;
		rx_desc = &local_desc;

skip_parse_bd:
		rx_queue->rx_fill_len++;

		/* This memory barrier is needed to keep us from reading
		 * any other fields out of the rx_desc until we know the
		 * descriptor has been written back
		 */
		count = 0;
		if (rx_len_idx) {
			mbuf = lxsnic_fetch_rx_buffer(rx_queue,
					&rx_len_idx[idx]);
			if (mbuf) {
				rx_queue->mcache[rx_queue->mtail] =
					mbuf;
				rx_queue->mtail = (rx_queue->mtail + 1)
					& MCACHE_MASK;
				rx_queue->mcnt++;
				count = 1;
			}
		} else {
			mbuf = lxsnic_fetch_rx_buffer(rx_queue, rx_desc);
			if (mbuf) {
				rx_queue->mcache[rx_queue->mtail] = mbuf;
				rx_queue->mtail = (rx_queue->mtail + 1)
					& MCACHE_MASK;
				rx_queue->mcnt++;
				count = 1;
			}
		}

		nb_rx++;

		rx_queue->last_used_idx++;  /* step to next */
		if (!count) {
			rx_queue->drop_packet_num++;
			break;
		}
		if (rx_queue->mcnt > LSINIC_MAX_BURST_NUM)
			break;
	}

#endif

	if (rx_queue->rx_fill_len > 1) {
		int ret = -ENOMEM, nb;
		struct rte_mbuf *mbufs[2 * LSINIC_MAX_BURST_NUM];

		if (unlikely(rx_queue->rx_fill_len >
			(2 * LSINIC_MAX_BURST_NUM)))
			nb = (2 * LSINIC_MAX_BURST_NUM);
		else
			nb = rx_queue->rx_fill_len / 2 * 2;
		while (ret) {
			ret = rte_pktmbuf_alloc_bulk(rx_queue->mb_pool,
				mbufs, nb);
			if (ret)
				nb = nb / 2;
			if (!nb)
				break;
		}
		lxsnic_rx_bd_fill(rx_queue, rx_queue->rx_fill_start_idx,
			mbufs, nb);
		rx_queue->rx_fill_start_idx =
			(rx_queue->rx_fill_start_idx + nb) &
			(rx_queue->count - 1);
		rx_queue->rx_fill_len -= nb;
	}

	rx_queue->loop_avail++;

	return nb_rx;
}

static void lxsnic_eth_self_xmit_gen_pkt(uint8_t *payload,
	uint16_t len)
{
	struct rte_ether_hdr *eth_header;
	struct rte_ipv4_hdr *ipv4_header;
	uint64_t rand = rte_rand();

	len -= sizeof(struct rte_ether_hdr);
	memcpy(payload, s_self_test_xmit_data_base,
		sizeof(s_self_test_xmit_data_base));
	eth_header = (struct rte_ether_hdr *)payload;
	ipv4_header = (struct rte_ipv4_hdr *)(eth_header + 1);
	ipv4_header->total_length = rte_cpu_to_be_16(len);
	ipv4_header->src_addr = (rte_be32_t)(rand & 0xffffffff);
	ipv4_header->dst_addr = (rte_be32_t)((rand >> 32) & 0xffffffff);
	ipv4_header->hdr_checksum = 0;
	ipv4_header->hdr_checksum = rte_ipv4_cksum(ipv4_header);
}

uint8_t s_perf_mode_set[RTE_MAX_LCORE];

static uint16_t
lxsnic_eth_xmit_by_rc_cpu(struct lxsnic_ring *tx_queue,
	struct rte_mbuf **tx_pkts, uint16_t nb_pkts,
	uint8_t *vir_base)
{
	int i, max_size = RTE_MBUF_DEFAULT_DATAROOM;
	uint16_t bd_idx;
	uint8_t *src;

	vir_base += 2 * max_size * tx_queue->count * tx_queue->reg_idx;
	for (i = 0; i < nb_pkts; i++) {
		bd_idx = tx_queue->last_avail_idx & (tx_queue->count - 1);
		src = (uint8_t *)tx_pkts[i]->buf_addr + tx_pkts[i]->data_off;
		memcpy(vir_base + max_size * bd_idx, src,
			tx_pkts[i]->pkt_len);
		tx_queue->packets++;
		tx_queue->bytes += tx_pkts[i]->pkt_len;
		tx_queue->bytes_fcs += tx_pkts[i]->pkt_len +
			LSINIC_ETH_FCS_SIZE;
		tx_queue->bytes_overhead += tx_pkts[i]->pkt_len +
			LSINIC_ETH_OVERHEAD_SIZE;
		tx_queue->last_avail_idx++;
	}

	return nb_pkts;
}

static uint16_t
lxsnic_eth_recv_by_rc_cpu(struct lxsnic_ring *rx_queue,
	struct rte_mbuf **rx_pkts, uint16_t nb_pkts,
	uint8_t *vir_base, uint16_t test_len)
{
	int i, max_size = RTE_MBUF_DEFAULT_DATAROOM;
	uint16_t bd_idx;
	uint8_t *dst;

	vir_base += 2 * max_size * rx_queue->count * rx_queue->reg_idx;
	vir_base += max_size * rx_queue->count;
	for (i = 0; i < nb_pkts; i++) {
		bd_idx = rx_queue->last_avail_idx & (rx_queue->count - 1);
		dst = (uint8_t *)rx_pkts[i]->buf_addr + rx_pkts[i]->data_off;
		memcpy(dst, vir_base + max_size * bd_idx, test_len);
		rx_queue->packets++;
		rx_queue->bytes += test_len;
		rx_queue->bytes_fcs += test_len +
			LSINIC_ETH_FCS_SIZE;
		rx_queue->bytes_overhead += test_len +
			LSINIC_ETH_OVERHEAD_SIZE;
		rx_queue->last_avail_idx++;
		rx_pkts[i]->pkt_len = test_len;
		rx_pkts[i]->data_len = test_len;
	}

	return nb_pkts;
}

static void lxsnic_txq_loop(void)
{
	struct lxsnic_ring *q, *tq;
	struct rte_mbuf *tx_pkts[DEFAULT_TX_RS_THRESH];
	uint16_t ret, i, xmit_ret, sent, wait = 0;

	if (RTE_PER_LCORE(lxsnic_txq_num_in_list) == 0)
		return;

	/* Check if txq already added to list */
	RTE_TAILQ_FOREACH_SAFE(q, &RTE_PER_LCORE(lxsnic_txq_list), next, tq) {
		if (unlikely(q->multi_core_ring &&
			q->core_id == rte_lcore_id())) {
			ret = rte_ring_sc_dequeue_burst(q->multi_core_ring,
				(void **)tx_pkts, DEFAULT_TX_RS_THRESH, NULL);
			if (ret) {
				xmit_ret = 0;
xmit_again:
				sent = lxsnic_eth_xmit_pkts(q,
					&tx_pkts[xmit_ret], ret - xmit_ret);
				xmit_ret += sent;
				wait++;
				if (xmit_ret < ret && wait < 10000)
					goto xmit_again;
				for (i = xmit_ret; i < ret; i++)
					rte_pktmbuf_free(tx_pkts[i]);
			}
		}

		if (unlikely(q->core_id != rte_lcore_id())) {
			TAILQ_REMOVE(&RTE_PER_LCORE(lxsnic_txq_list),
				q, next);
			continue;
		}

		q->loop_total++;
	}
}

static uint16_t
_lxsnic_eth_recv_pkts(struct lxsnic_ring *rxq,
	struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	uint16_t nb_rx = 0;
	uint16_t count = 0;
	struct rte_mbuf *mbuf = NULL;

	lxsnic_eth_recv_pkts_to_cache(rxq);

	lxsnic_txq_loop();

	count = RTE_MIN(nb_pkts, rxq->mcnt);
	for (nb_rx = 0; nb_rx < count; nb_rx++) {
		mbuf = rxq->mcache[rxq->mhead];
		rxq->mhead = (rxq->mhead + 1) & MCACHE_MASK;
		rxq->mcnt--;

		rx_pkts[nb_rx] = mbuf;
		rxq->packets++;
		rxq->bytes += mbuf->pkt_len;
		rxq->bytes_fcs += mbuf->pkt_len +
			LSINIC_ETH_FCS_SIZE;
		rxq->bytes_overhead += mbuf->pkt_len +
			LSINIC_ETH_OVERHEAD_SIZE;

#ifdef DEBUG_MBUF
		print_mbuf(mbuf);
#endif
	}

	return nb_rx;
}

static uint16_t
lxsnic_eth_self_test(struct lxsnic_ring *rxq,
	struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	int tx_nb, ret;
	struct rte_mbuf *pkt;
	struct rte_mbuf *tx_pkts[LSINIC_MAX_BURST_NUM];
	struct lxsnic_adapter *adapter = rxq->adapter;
	struct rte_eth_dev *eth_dev = adapter->eth_dev;
	struct lxsnic_ring *txq =
		eth_dev->data->tx_queues[rxq->queue_index];
	uint8_t *pay_load;

	if (!txq)
		return 0;

	ret = rte_pktmbuf_alloc_bulk(rxq->mb_pool, tx_pkts,
		LSINIC_MAX_BURST_NUM);
	if (ret)
		return 0;

	for (tx_nb = 0; tx_nb < LSINIC_MAX_BURST_NUM; tx_nb++) {
		pkt = tx_pkts[tx_nb];
		pkt->data_off = RTE_PKTMBUF_HEADROOM;
		pay_load = (uint8_t *)pkt->buf_addr + pkt->data_off;
		if (0) {
			/**In case pkts go to EP MAC.*/
			lxsnic_eth_self_xmit_gen_pkt(pay_load,
				adapter->self_test_len);
		}
		pkt->pkt_len = adapter->self_test_len;
		pkt->data_len = adapter->self_test_len;
	}

	if (adapter->self_test == LXSNIC_RC_SELF_REMOTE_MEM_TEST) {
		if (!adapter->ep_memzone_vir) {
			LSXINIC_PMD_ERR("NO EP memory mapped");
			LSXINIC_PMD_ERR("please export %s = 1 in EP",
				LSINIC_EP_MAP_MEM_ENV);
			LSXINIC_PMD_ERR("please quit");
			rte_delay_ms(2000);

			return 0;
		}
		tx_nb = lxsnic_eth_xmit_by_rc_cpu(txq, tx_pkts,
			LSINIC_MAX_BURST_NUM, adapter->ep_memzone_vir);
		rte_pktmbuf_free_bulk(tx_pkts, LSINIC_MAX_BURST_NUM);
	} else if (adapter->self_test == LXSNIC_RC_SELF_LOCAL_MEM_TEST) {
		if (!adapter->rc_memzone_vir) {
			LSXINIC_PMD_ERR("NO RC memory reserved");
			LSXINIC_PMD_ERR("please quit");
			rte_delay_ms(2000);

			return 0;
		}
		tx_nb = lxsnic_eth_xmit_by_rc_cpu(txq, tx_pkts,
			LSINIC_MAX_BURST_NUM, adapter->rc_memzone_vir);
		rte_pktmbuf_free_bulk(tx_pkts, LSINIC_MAX_BURST_NUM);
	} else {
		tx_nb = _lxsnic_eth_xmit_pkts(txq, tx_pkts,
			LSINIC_MAX_BURST_NUM);
		if (tx_nb < LSINIC_MAX_BURST_NUM) {
			rte_pktmbuf_free_bulk(&tx_pkts[tx_nb],
				LSINIC_MAX_BURST_NUM - tx_nb);
		}
	}

	if (adapter->self_test == LXSNIC_RC_SELF_PMD_TEST)
		return _lxsnic_eth_recv_pkts(rxq, rx_pkts, nb_pkts);

	ret = rte_pktmbuf_alloc_bulk(rxq->mb_pool, rx_pkts, nb_pkts);
	if (ret)
		return 0;

	if (adapter->self_test == LXSNIC_RC_SELF_LOCAL_MEM_TEST) {
		return lxsnic_eth_recv_by_rc_cpu(rxq, rx_pkts, nb_pkts,
				adapter->rc_memzone_vir,
				adapter->self_test_len);
	} else {
		return lxsnic_eth_recv_by_rc_cpu(rxq, rx_pkts, nb_pkts,
				adapter->ep_memzone_vir,
				adapter->self_test_len);
	}
}

uint16_t
lxsnic_eth_recv_pkts(void *queue, struct rte_mbuf **rx_pkts,
	uint16_t nb_pkts)
{
	struct lxsnic_ring *rx_queue = (struct lxsnic_ring *)queue;
	struct lxsnic_adapter *adapter = rx_queue->adapter;
	struct lxsnic_ring *pair_txq = rx_queue->pair;

	if (pair_txq) {
		uint8_t idx = pair_txq->queue_index;

		if (unlikely(!RTE_PER_LCORE(txq_added[idx]))) {
			rte_spinlock_lock(&pair_txq->multi_core_lock);
			lxsnic_add_txq_to_list(pair_txq);
			rte_spinlock_unlock(&pair_txq->multi_core_lock);
			RTE_PER_LCORE(txq_added[idx]) = 1;
		} else {
			lxsnic_add_txq_to_list(pair_txq);
		}
	}

	if (unlikely(!s_perf_mode_set[rte_lcore_id()])) {
		if (getenv("NXP_CHRT_PERF_MODE")) {
			pid_t tid = rte_gettid();
			char command[256];
			int ret;

			snprintf(command, 256, "chrt -p 90 %d", tid);
			ret = system(command);
			if (ret < 0)
				LSXINIC_PMD_ERR("%s excuted failed", command);
			else
				LSXINIC_PMD_INFO("%s excuted success", command);
		}
		s_perf_mode_set[rte_lcore_id()] = 1;
	}

	if (unlikely(adapter->self_test != LXSNIC_RC_SELF_NONE_TEST))
		return lxsnic_eth_self_test(rx_queue, rx_pkts, nb_pkts);

	return _lxsnic_eth_recv_pkts(rx_queue, rx_pkts, nb_pkts);
}

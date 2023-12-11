/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2023 NXP
 */

#include <rte_memzone.h>
#include <sys/mman.h>
#include <rte_io.h>
#include <fcntl.h>
#include <unistd.h>
#include <rte_mbuf.h>
#include <rte_io.h>

#include "enetqos_hw.h"
#include "enetqos_ethdev.h"
#include "enetqos_pmd_logs.h"

static int enetqos_get_rx_status(struct dma_desc *p)
{
	unsigned int rdes3 = p->des3;
	int ret = ok_frame;

	if (unlikely(rdes3 & ENETQ_RDES3_OWN))
		return dma_owner;

	if (unlikely(rdes3 & ENETQ_RDES3_CTX_DESC))
		return discard_frame;

	if (likely(!(rdes3 & ENETQ_RDES3_LAST_DESC)))
		return rx_not_ldesc;

	if (unlikely(rdes3 & ENETQ_RDES3_ERR_SUMMARY)) {
		if (unlikely(rdes3 & ENETQ_RDES3_GIANT_PKT))
			ENETQOS_DP_LOG(DEBUG, "rx_fifo_error");
		if (unlikely(rdes3 & ENETQ_RDES3_OVERFLOW_ERR))
			ENETQOS_DP_LOG(DEBUG, "overflow_error");
		if (unlikely(rdes3 & ENETQ_RDES3_RECEIVE_ERR))
			ENETQOS_DP_LOG(DEBUG, "receive_error");
		if (unlikely(rdes3 & ENETQ_RDES3_CRC_ERR))
			ENETQOS_DP_LOG(DEBUG, "crc_error");
		if (unlikely(rdes3 & ENETQ_RDES3_DRIBBLE_ERR))
			ENETQOS_DP_LOG(DEBUG, "dribble_error");

		ret = discard_frame;
	}

	return ret;
}

static void enetqos_set_rx_owner(struct dma_desc *p)
{
	p->des3 |= ENETQ_RDES3_OWN | ENETQ_RDES3_BUFFER1_VALID_ADDR;
}

static int enetqos_wrback_get_rx_frame_len(struct dma_desc *p)
{
	return (p->des3 & ENETQ_RDES3_PKT_SZ_MASK);
}

uint16_t
enetqos_recv_pkts(void *rxq1, struct rte_mbuf **rx_pkts,
	uint16_t nb_pkts)
{
	struct enetqos_rx_queue *rxq = (struct enetqos_rx_queue *)rxq1;
	struct enetqos_priv *priv;
	struct dma_desc *desc, *first;
	struct rte_mempool *pool;
	struct rte_mbuf *mbuf, *new_mbuf = NULL;
	unsigned short status;
	unsigned short pkt_len;
	int pkt_received = 0;
	int entry;
	struct rte_eth_stats *stats = &rxq->priv_data->stats;
	rte_iova_t addr;
	unsigned int next_entry = rxq->cur_rx;

	pool = rxq->pool;
	priv = rxq->priv_data;
	entry = next_entry;

	desc = rxq->dma_rx + entry;
	first = desc;

	/* Process the incoming packet */
	status = enetqos_get_rx_status(first);
	while (!(status & dma_owner)) {

		if (pkt_received >= nb_pkts)
			break;

		/* Check for errors. */
		if (status == discard_frame) {
			stats->ierrors++;
			mbuf = rxq->rx_mbuf[entry];
			rte_pktmbuf_free(mbuf);
			goto rx_processing_done;
		}

		/* Process the incoming frame */
		stats->ipackets++;
		pkt_len = enetqos_wrback_get_rx_frame_len(first);
		stats->ibytes += pkt_len;
		mbuf = rxq->rx_mbuf[entry];
		mbuf->data_len = pkt_len;
		mbuf->pkt_len = pkt_len;

		rx_pkts[pkt_received] = mbuf;
		pkt_received++;

rx_processing_done:
		new_mbuf = rte_pktmbuf_alloc(pool);
		if (unlikely(new_mbuf == NULL)) {
			stats->rx_nombuf++;
			break;
		}

		rxq->rx_mbuf[entry] = new_mbuf;
		addr = rte_pktmbuf_iova(new_mbuf);
		enetqos_set_addr(first, addr);

		next_entry = STMMAC_GET_ENTRY(entry, priv->dma_rx_size);
		desc = rxq->dma_rx + next_entry;
		rte_prefetch0(desc);

		/* Make sure the updates to rest of the descriptor are
		 * performed before transferring ownership.
		 */
		enetqos_set_rx_owner(first);

		/* Increment the desc to next descriptor
		 * The DMA automatically wraps around the base
		 * address when the end of ring is reached
		 */
		rxq->cur_rx = next_entry;
		entry = next_entry;
		rxq->dirty_rx = next_entry;
		first = desc;

		status = enetqos_get_rx_status(first);
	}

	rxq->rx_tail_addr = rxq->dma_rx_phy +
				(rxq->dirty_rx * sizeof(struct dma_desc));
	enetqos_set_rx_tail_ptr(priv->ioaddr, rxq->rx_tail_addr, rxq->queue_index);

	return pkt_received;
}

static void
enetqos_prepare_tx_desc(struct dma_desc *p, int len, unsigned int tot_pkt_len)
{
	p->des2 = len & ENETQ_TDES2_BUF1_SZ_MASK;

	p->des3	= tot_pkt_len & ENETQ_TDES3_PKT_SZ_MASK;
	p->des3 |= ENETQ_TDES3_FIRST_DESC | ENETQ_TDES3_LAST_DESC;
}

static int enetqos_get_tx_status(struct dma_desc *p)
{
	unsigned int tdes3;
	int ret = tx_comp;

	tdes3 = p->des3;

	/* Get tx owner first */
	if (tdes3 & ENETQ_TDES3_OWN)
		return tx_dma_owner;

	/* Verify tx error by looking at the last segment. */
	if (!(tdes3 & ENETQ_TDES3_LAST_DESC))
		return tx_not_ldesc;

	if (tdes3 & ENETQ_TDES3_ERR_SUMMARY) {
		ret = tx_error;

		if (tdes3 & ENETQ_TDES3_JABBER_TIMEOUT)
			ENETQOS_DP_LOG(DEBUG, "Jabber Timeout");
		if (tdes3 & ENETQ_TDES3_PKT_FLUSHED)
			ENETQOS_DP_LOG(DEBUG, "Packet Flush");
		if (tdes3 & ENETQ_TDES3_LOSS_CARRIER)
			ENETQOS_DP_LOG(DEBUG, "Loss of Carrier");
		if (tdes3 & ENETQ_TDES3_NO_CARRIER)
			ENETQOS_DP_LOG(DEBUG, "No Carrier");
		if ((tdes3 & ENETQ_TDES3_LATE_COLLISION) ||
				(tdes3 & ENETQ_TDES3_EXCESSIVE_COLLISION))
			ENETQOS_DP_LOG(DEBUG, "late or excessive collision");
		if (tdes3 & ENETQ_TDES3_EXCESSIVE_DEFERRAL)
			ENETQOS_DP_LOG(DEBUG, "Excessive Deferral");
		if (tdes3 & ENETQ_TDES3_UNDERFLOW_ERR) {
			ENETQOS_DP_LOG(DEBUG, "Underflow Error");
			ret |= tx_error_bump_tc;
		}

		if (tdes3 & ENETQ_TDES3_IP_HDR_ERR)
			ENETQOS_DP_LOG(DEBUG, "IP Header Error");

		if (tdes3 & ENETQ_TDES3_PL_ERR)
			ENETQOS_DP_LOG(DEBUG, "Payload Checksum Error");
	}

	if (tdes3 & ENETQ_TDES3_DEF)
		ENETQOS_DP_LOG(DEBUG, "Deferred");

	return ret;
}

static void enetqos_flush_tx_descriptors(struct enetqos_priv *priv, int queue)
{
	struct enetqos_tx_queue *tx_q = priv->tx_queue[queue];
	int desc_size;

	desc_size = sizeof(struct dma_desc);

	tx_q->tx_tail_addr = tx_q->dma_tx_phy + (tx_q->cur_tx * desc_size);
	enetqos_set_tx_tail_ptr(priv->ioaddr, tx_q->tx_tail_addr, queue);
}

uint16_t
enetqos_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	struct enetqos_tx_queue *tx_q = (struct enetqos_tx_queue *)tx_queue;
	struct enetqos_priv *priv;
	struct dma_desc *desc, *first;
	unsigned int tx_packets = 0;
	int entry;
	struct rte_mbuf *mbuf;
	unsigned short status;
	unsigned short buflen;
	struct rte_eth_stats *stats = &tx_q->priv_data->stats;
	rte_iova_t addr;
	uint8_t *data;
	int ind = 0;

	priv = tx_q->priv_data;
	entry = tx_q->cur_tx;
	desc = tx_q->dma_tx + entry;
	first = desc;

	while (tx_packets < nb_pkts) {
		mbuf = *(tx_pkts);

		ind++;

		status = enetqos_get_tx_status(first);

		if (status & tx_dma_owner) {
			stats->oerrors++;
			break;
		}

		if (tx_q->tx_mbuf[entry])
			rte_pktmbuf_free(tx_q->tx_mbuf[entry]);

		addr = rte_pktmbuf_iova(mbuf);
		buflen = rte_pktmbuf_pkt_len(mbuf);
		stats->obytes += buflen;
		enetqos_set_addr(first, addr);

		data = rte_pktmbuf_mtod(mbuf, void *);
		for (int i = 0; i <= buflen; i += RTE_CACHE_LINE_SIZE)
			dcbf(data + i);

		enetqos_prepare_tx_desc(first, buflen, buflen);
		tx_q->tx_mbuf[entry] = mbuf;
		stats->opackets++;
		tx_packets++;
		tx_q->tx_count_frames += tx_packets;

		/* Increment the desc to next descriptor
		 * The DMA automatically wraps around the base
		 * address when the end of ring is reached
		 */

		entry = STMMAC_GET_ENTRY(entry, priv->dma_tx_size);
		tx_q->cur_tx = entry;
		desc = tx_q->dma_tx + entry;
		rte_wmb();
		/* Finally set the OWN bit. Later the DMA will start! */
		first->des3 |= ENETQ_TDES3_OWN;
		enetqos_flush_tx_descriptors(priv, tx_q->queue_index);
		first = desc;
		tx_pkts++;
	}

	return tx_packets;
}

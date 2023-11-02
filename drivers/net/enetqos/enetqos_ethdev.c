/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2023 NXP
 */

#include <rte_memzone.h>
#include <sys/mman.h>
#include <rte_io.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <ethdev_vdev.h>
#include <ethdev_driver.h>

#include "enetqos_hw.h"
#include "enetqos_ethdev.h"
#include "enetqos_pmd_logs.h"
#include <kpage_ncache_api.h>

#define EXTRACT_CCSR_ADDR(s)	(s + strlen(s) - 8)

#define EXTRACT_CCSR_ADDR(s)	(s + strlen(s) - 8)

static void
enetqos_free_buffers(struct rte_eth_dev *dev)
{
	struct enetqos_priv *priv = dev->data->dev_private;
	unsigned int i, q;
	struct rte_mbuf *mbuf;
	struct enetqos_rx_queue *rxq;
	struct enetqos_tx_queue *txq;

	for (q = 0; q < dev->data->nb_rx_queues; q++) {
		rxq = priv->rx_queue[q];
		for (i = 0; i < priv->dma_rx_size; i++) {
			mbuf = rxq->rx_mbuf[i];
			rxq->rx_mbuf[i] = NULL;
			rte_pktmbuf_free(mbuf);
		}
	}

	for (q = 0; q < dev->data->nb_tx_queues; q++) {
		txq = priv->tx_queue[q];
		for (i = 0; i < priv->dma_tx_size; i++) {
			mbuf = txq->tx_mbuf[i];
			txq->tx_mbuf[i] = NULL;
			rte_pktmbuf_free(mbuf);
		}
	}
}

static int
reset_poll_timeout(void *ioaddr, uint32_t value, int delay_us, int timeout_us)
{
	uint16_t wait_time = 0;
	int ret = 0;

	do {
		value = rte_read32((void *)((size_t)ioaddr + ENETQ_DMA_MODE));
		rte_delay_us(delay_us);
		wait_time += delay_us;

		if (!(value & ENETQ_DMA_BUS_MODE_SFT_RESET))
			return ret;
	} while (wait_time < timeout_us);

	ret = -ETIMEDOUT;
	return ret;
}

static int enetqos_dma_reset(void *ioaddr)
{
	uint32_t value = rte_read32((void *)((size_t)ioaddr + ENETQ_DMA_MODE));

	/* DMA SW reset */
	value |= ENETQ_DMA_BUS_MODE_SFT_RESET;
	rte_write32(value, (void *)((size_t) ioaddr + ENETQ_DMA_MODE));

	return reset_poll_timeout((void *)((size_t)ioaddr + ENETQ_DMA_MODE),
			value, 10000, 1000000);
}

static void enetqos_dma_init_channel(void *ioaddr,
	struct enetqos_dma_cfg *dma_cfg, uint32_t chan)
{
	uint32_t value;

	/* common channel control register config */
	value = rte_read32((void *)&(ENETQ_DMA_CHX_REGS(ioaddr, chan))->ctrl);

	if (dma_cfg->pblx8)
		value = value | ENETQ_DMA_BUS_MODE_PBL;

	rte_write32(value, (void *)&(ENETQ_DMA_CHX_REGS(ioaddr, chan))->ctrl);
}

static void enetqos_dma_init(void *ioaddr,
	struct enetqos_dma_cfg *dma_cfg)
{
	uint32_t value =
		rte_read32((void *)((size_t) ioaddr + ENETQ_DMA_SYS_BUS_MODE));

	/* Set the Fixed burst mode*/
	if (dma_cfg->fixed_burst)
		value |= ENETQ_DMA_SYS_BUS_FB;

	/* Mixed Burst has no effect when fb mode is set*/
	if (dma_cfg->mixed_burst)
		value |= ENETQ_DMA_SYS_BUS_MB;

	if (dma_cfg->aal)
		value |= ENETQ_DMA_SYS_BUS_AAL;

	if (dma_cfg->eame)
		value |= ENETQ_DMA_SYS_BUS_EAME;

	rte_write32(value, (void *)((size_t) ioaddr + ENETQ_DMA_SYS_BUS_MODE));

	value = rte_read32((void *)((size_t)ioaddr + ENETQ_DMA_MODE));

	if (dma_cfg->dche)
		value |= ENETQ_DMA_BUS_MODE_DCHE;

	rte_write32(value, (void *)((size_t)ioaddr + ENETQ_DMA_MODE));
}

static void enetqos_dma_init_tx_chan(void *ioaddr,
	struct enetqos_dma_cfg *dma_cfg,
	dma_addr_t dma_tx_phy, uint32_t chan)
{
	uint32_t value;
	uint32_t txpbl = dma_cfg->txpbl ? : dma_cfg->pbl;

	value = rte_read32((void *)&(ENETQ_DMA_CHX_REGS(ioaddr, chan))->tx_ctrl);
	value = value | (txpbl << ENETQ_DMA_BUS_MODE_PBL_SHIFT);

	/* Enable OSP to get best performance */
	value |= ENETQ_DMA_CONTROL_OSP;
	/* Disable the enhanced descriptor */
	value &= ~ENETQ_DMA_CONTROL_EDSE;

	rte_write32(value,(void *)&(ENETQ_DMA_CHX_REGS(ioaddr, chan))->tx_ctrl);

 	rte_write32(upper_32_bits(dma_tx_phy), 
		(void *)&(ENETQ_DMA_CHX_REGS(ioaddr, chan))->tx_addr_hi);
	rte_write32(lower_32_bits(dma_tx_phy),
		(void *)&(ENETQ_DMA_CHX_REGS(ioaddr, chan))->tx_addr);
}

static void enetqos_set_tx_ring_len(void *ioaddr, uint32_t len, uint32_t chan)
{
	rte_write32(len, (void *)&(ENETQ_DMA_CHX_REGS(ioaddr, chan))->tx_ring_len);
}

static void enetqos_set_rx_ring_len(void *ioaddr, uint32_t len, uint32_t chan)
{
	rte_write32(len, (void *)&(ENETQ_DMA_CHX_REGS(ioaddr, chan))->rx_ring_len);
}

static void enetqos_set_rings_length(struct enetqos_priv *priv)
{
	uint32_t tx_channels_count = priv->tx_queues_to_use;
	uint32_t rx_channels_count = priv->rx_queues_to_use;
	uint32_t chan;

	/* set TX ring length */
	for (chan = 0; chan < tx_channels_count; chan++)
		enetqos_set_tx_ring_len(priv->ioaddr,
			(priv->dma_tx_size - 1), chan);
	/* set RX ring length */
	for (chan = 0; chan < rx_channels_count; chan++)
		enetqos_set_rx_ring_len(priv->ioaddr,
			(priv->dma_rx_size - 1), chan);
}

static void enetqos_core_init(void *ioaddr)
{
	uint32_t value = rte_read32((void *)((size_t) ioaddr + ENETQ_MAC_CONFIG));

	value |= ENETQ_MAC_CORE_INIT;
	value |= ENETQ_MAC_CONFIG_TE;
	value |= ENETQ_MAC_CONFIG_RE;

	rte_write32(value, (void *)((size_t) ioaddr + ENETQ_MAC_CONFIG));
}

static void enetqos_dma_tx_mode(void *ioaddr, int mode,
	uint32_t channel, int fifosz, uint8_t qmode)
{
	uint32_t mtl_tx_op_mode = rte_read32((void *)((size_t)ioaddr + ENETQ_MTL_CH_TX_OP_MODE(channel)));
	unsigned int tqs = fifosz / MTL_QUEUE_BLK - 1;

	if (mode == SF_DMA_MODE) {
		/* enable TX store and forward mode */
		mtl_tx_op_mode |= ENETQ_MTL_OP_MODE_TSF;
	}

	mtl_tx_op_mode &= ~ENETQ_MTL_OP_MODE_TXQEN_MASK;
	if (qmode != MTL_QUEUE_AVB_MODE)
		mtl_tx_op_mode |= ENETQ_MTL_OP_MODE_TXQEN;
	else
		mtl_tx_op_mode |= ENETQ_MTL_OP_MODE_TXQEN_AV;
	mtl_tx_op_mode &= ~ENETQ_MTL_OP_MODE_TQS_MASK;
	mtl_tx_op_mode |= tqs << ENETQ_MTL_OP_MODE_TQS_SHIFT;

	rte_write32(mtl_tx_op_mode,
		(void *)((size_t) ioaddr + ENETQ_MTL_CH_TX_OP_MODE(channel)));
}

static void enetqos_dma_rx_mode(void *ioaddr, int mode,
	uint32_t channel, int fifosz, uint8_t qmode)
{
	unsigned int rqs = fifosz / MTL_QUEUE_BLK - 1;
	uint32_t mtl_rx_op_mode;

	mtl_rx_op_mode = rte_read32((void *)((size_t)ioaddr + ENETQ_MTL_CH_RX_OP_MODE(channel)));

	if (mode == SF_DMA_MODE) {
		/* enable RX store and forward mode */
		mtl_rx_op_mode |= ENETQ_MTL_OP_MODE_RSF;
	}

	mtl_rx_op_mode &= ~ENETQ_MTL_OP_MODE_RQS_MASK;
	mtl_rx_op_mode |= rqs << ENETQ_MTL_OP_MODE_RQS_SHIFT;

	/* Enable flow control only if each channel gets 4 KiB or more FIFO and
	 * only if channel is not an AVB channel.
	 */
	if ((fifosz >= FIFO_SIZE_4KiB) && (qmode != MTL_QUEUE_AVB_MODE)) {
		unsigned int rfd, rfa;

		mtl_rx_op_mode |= ENETQ_MTL_OP_MODE_EHFC;

		/* Set Threshold for Activating Flow Control to min 2 frames,
		 * i.e. 1500 * 2 = 3000 bytes.
		 *
		 * Set Threshold for Deactivating Flow Control to min 1 frame,
		 * i.e. 1500 bytes.
		 */
		switch (fifosz) {
		case FIFO_SIZE_4KiB:
			/* This violates the above formula because of FIFO size
			 * limit therefore overflow may occur in spite of this.
			 */
			rfd = 0x03; /* Full-2.5K */
			rfa = 0x01; /* Full-1.5K */
			break;

		default:
			rfd = 0x07; /* Full-4.5K */
			rfa = 0x04; /* Full-3K */
			break;
		}

		mtl_rx_op_mode &= ~ENETQ_MTL_OP_MODE_RFD_MASK;
		mtl_rx_op_mode |= rfd << ENETQ_MTL_OP_MODE_RFD_SHIFT;

		mtl_rx_op_mode &= ~ENETQ_MTL_OP_MODE_RFA_MASK;
		mtl_rx_op_mode |= rfa << ENETQ_MTL_OP_MODE_RFA_SHIFT;
	}

	rte_write32(mtl_rx_op_mode, (void *)((size_t)ioaddr + ENETQ_MTL_CH_RX_OP_MODE(channel)));
}

static void enetqos_dma_operation_mode(struct enetqos_priv *priv)
{
	uint32_t rx_channels_count = priv->rx_queues_to_use;
	uint32_t tx_channels_count = priv->tx_queues_to_use;
	int rxfifosz = MTL_FIFO_SIZE;
	int txfifosz = MTL_FIFO_SIZE;
	uint32_t txmode = 0;
	uint32_t rxmode = 0;
	uint32_t chan = 0;
	uint8_t qmode;

	/* Adjust for real per queue fifo size */
	rxfifosz /= rx_channels_count;
	txfifosz /= tx_channels_count;

	qmode = MTL_QUEUE_DCB_MODE;
	txmode = SF_DMA_MODE;
	rxmode = SF_DMA_MODE;

	/* configure all channels */
	for (chan = 0; chan < tx_channels_count; chan++) {
		enetqos_dma_tx_mode(priv->ioaddr, txmode, chan,
			txfifosz, qmode);
	}

	for (chan = 0; chan < rx_channels_count; chan++) {
		enetqos_dma_rx_mode(priv->ioaddr, rxmode, chan,
			rxfifosz, qmode);
	}
}

static void enetqos_map_mtl_dma(void *ioaddr, uint32_t queue, uint32_t chan)
{
	uint32_t value;

	if (queue < (MTL_MAX_RX_QUEUES / 2))
		value = rte_read32((void *)((size_t)ioaddr + ENETQ_MTL_RXQ_DMA_MAP0));
	else
		value = rte_read32((void *)((size_t)ioaddr + ENETQ_MTL_RXQ_DMA_MAP1));

	if (queue == 0 || queue == (MTL_MAX_RX_QUEUES / 2)) {
		value &= ~ENETQ_MTL_RXQ_DMA_Q0MDMACH_MASK;
		value |= ENETQ_MTL_RXQ_DMA_Q0MDMACH(chan);
	} else {
		value &= ~ENETQ_MTL_RXQ_DMA_QXMDMACH_MASK(queue);
		value |= ENETQ_MTL_RXQ_DMA_QXMDMACH(chan, queue);
	}

	if (queue < (MTL_MAX_RX_QUEUES / 2))
		rte_write32(value, (void *)((size_t)ioaddr + ENETQ_MTL_RXQ_DMA_MAP0));
	else
		rte_write32(value, (void *)((size_t)ioaddr + ENETQ_MTL_RXQ_DMA_MAP1));
}

/**
 *  enetqos_rx_queue_dma_chan_map - Map RX queue to RX dma channel
 *  @priv: driver private structure
 *  Description: It is used for mapping RX queues to RX dma channels
 */
static void enetqos_rx_queue_dma_chan_map(struct enetqos_priv *priv)
{
	uint32_t rx_queues_count = priv->rx_queues_to_use;
	uint32_t queue;
	uint32_t chan;

	for (queue = 0; queue < rx_queues_count; queue++) {
		chan = queue;
		enetqos_map_mtl_dma(priv->ioaddr, queue, chan);
	}
}

static void enetqos_rx_queue_enable(void *ioaddr, uint8_t mode, uint32_t queue)
{
	uint32_t value = rte_read32((void *)((size_t)ioaddr + ENETQ_MAC_RXQ_CTRL(0)));

	value &= ENETQ_MAC_RX_QUEUE_CLEAR(queue);

	if (mode == MTL_QUEUE_AVB_MODE)
		value |= ENETQ_MAC_RX_AV_QUEUE_ENABLE(queue);
	else if (mode == MTL_QUEUE_DCB_MODE)
		value |= ENETQ_MAC_RX_DCB_QUEUE_ENABLE(queue);

	rte_write32(value, (void *)((size_t)ioaddr + ENETQ_MAC_RXQ_CTRL(0)));
}

/**
 *  enetqos_mac_enable_rx_queues - Enable MAC rx queues
 *  @priv: driver private structure
 *  Description: It is used for enabling the rx queues in the MAC
 */
static void enetqos_mac_enable_rx_queues(struct enetqos_priv *priv)
{
	uint32_t rx_queues_count = priv->rx_queues_to_use;
	uint32_t queue;
	uint8_t mode;

	for (queue = 0; queue < rx_queues_count; queue++) {
		mode = MTL_QUEUE_DCB_MODE;
		enetqos_rx_queue_enable(priv->ioaddr, mode, queue);
	}
}

static void enetqos_dma_start_tx(void *ioaddr, uint32_t chan)
{
	uint32_t value =
		rte_read32((void *)&(ENETQ_DMA_CHX_REGS(ioaddr, chan))->tx_ctrl);

	/* Start Transmission */
	value |= ENETQ_DMA_CONTROL_ST;
	rte_write32(value, (void *)&(ENETQ_DMA_CHX_REGS(ioaddr, chan))->tx_ctrl);

	value = rte_read32((void *)((size_t) ioaddr + ENETQ_MAC_CONFIG));

	/* Transmitter Enable */
	value |= ENETQ_MAC_CONFIG_TE;
	rte_write32(value, (void *)((size_t) ioaddr + ENETQ_MAC_CONFIG));
}

static void enetqos_dma_start_rx(void *ioaddr, uint32_t chan)
{
	uint32_t value =
		rte_read32((void *)&(ENETQ_DMA_CHX_REGS(ioaddr, chan))->rx_ctrl);

	/* Start Receive */
	value |= ENETQ_DMA_CONTROL_SR;
	rte_write32(value, (void *)&(ENETQ_DMA_CHX_REGS(ioaddr, chan))->rx_ctrl);

	value = rte_read32((void *)((size_t) ioaddr + ENETQ_MAC_CONFIG));

	/* Receiver Enable */
	value |= ENETQ_MAC_CONFIG_RE;
	rte_write32(value, (void *)((size_t) ioaddr + ENETQ_MAC_CONFIG));
}

static void enetqos_start_all_dma(struct enetqos_priv *priv)
{
	uint32_t tx_channels_count = priv->tx_queues_to_use;
	uint32_t rx_channels_count = priv->rx_queues_to_use;
	uint32_t chan = 0;

	for (chan = 0; chan < rx_channels_count; chan++)
		enetqos_dma_start_rx(priv->ioaddr, chan);
	for (chan = 0; chan < tx_channels_count; chan++)
		enetqos_dma_start_tx(priv->ioaddr, chan);
}

static void enetqos_dma_stop_tx(void *ioaddr, uint32_t chan)
{
	uint32_t value =
		rte_read32((void *)&(ENETQ_DMA_CHX_REGS(ioaddr, chan))->tx_ctrl);

	/* Stop Transmission */
	value &= ~ENETQ_DMA_CONTROL_ST;
	rte_write32(value,
		(void *)&(ENETQ_DMA_CHX_REGS(ioaddr, chan))->tx_ctrl);
}

static void enetqos_dma_stop_rx(void *ioaddr, uint32_t chan)
{
	uint32_t value =
		rte_read32((void *)&(ENETQ_DMA_CHX_REGS(ioaddr, chan))->rx_ctrl);

	/* Stop Receive */
	value &= ~ENETQ_DMA_CONTROL_SR;
	rte_write32(value,
		(void *)&(ENETQ_DMA_CHX_REGS(ioaddr, chan))->rx_ctrl);
}

static void enetqos_stop_all_dma(struct enetqos_priv *priv)
{
	uint32_t tx_channels_count = priv->tx_queues_to_use;
	uint32_t rx_channels_count = priv->rx_queues_to_use;
	uint32_t chan = 0;

	for (chan = 0; chan < rx_channels_count; chan++)
		enetqos_dma_stop_rx(priv->ioaddr, chan);
	for (chan = 0; chan < tx_channels_count; chan++)
		enetqos_dma_stop_tx(priv->ioaddr, chan);
}

static void desc_clear(struct dma_desc *p)
{
	p->des0 = 0;
	p->des1 = 0;
	p->des2 = 0;
	p->des3 = 0;
}

static int
enetqos_tx_queue_setup(struct rte_eth_dev *dev,
	uint16_t queue_idx,
	uint16_t nb_desc,
	unsigned int socket_id __rte_unused,
	const struct rte_eth_txconf *tx_conf __rte_unused)
{
	struct enetqos_priv *priv = dev->data->dev_private;
	struct enetqos_tx_queue *txq;
	struct dma_desc *p;
	int i;

	/* Allocate transmit queue */
	txq = rte_zmalloc(NULL, sizeof(*txq), RTE_CACHE_LINE_SIZE);
	if (txq == NULL) {
		ENETQOS_PMD_ERR("transmit queue allocation failed\n");
		return -ENOMEM;
	}

	if (nb_desc > DMA_DEFAULT_TX_SIZE)
		nb_desc = DMA_DEFAULT_TX_SIZE;

	priv->tx_queue[queue_idx] = txq;
	txq->queue_index = queue_idx;
	txq->priv_data = priv;
	txq->dma_tx = (struct dma_desc *) priv->dma_baseaddr_t[queue_idx];
	txq->dma_tx_phy = priv->bd_addr_p_t[queue_idx];
	txq->dirty_tx = 0;
	txq->cur_tx = 0;
	txq->tx_count_frames = 0;

	for (i = 0; i < nb_desc; i++) {
		/* Initialize the BD descriptors */
		p = txq->dma_tx + i;
		/* Clearing the descriptor */
		desc_clear(p);
		if (txq->tx_mbuf[i] != NULL) {
			rte_pktmbuf_free(txq->tx_mbuf[i]);
			txq->tx_mbuf[i] = NULL;
		}
	}

	enetqos_dma_init_tx_chan(priv->ioaddr, priv->dma_cfg, txq->dma_tx_phy, queue_idx);
	txq->tx_tail_addr = txq->dma_tx_phy;
	enetqos_set_tx_tail_ptr(priv->ioaddr, txq->tx_tail_addr, queue_idx);

	dev->data->tx_queues[queue_idx] = priv->tx_queue[queue_idx];
	return 0;
}

static void enetqos_dma_init_rx_chan(void *ioaddr,
			struct enetqos_dma_cfg *dma_cfg,
			dma_addr_t dma_rx_phy, uint32_t chan)
{
	uint32_t value;
	uint32_t rxpbl = dma_cfg->rxpbl ? : dma_cfg->pbl;

	value = rte_read32((void *)&(ENETQ_DMA_CHX_REGS(ioaddr, chan))->rx_ctrl);
	value = value | (rxpbl << ENETQ_DMA_BUS_MODE_RPBL_SHIFT);
	rte_write32(value, (void *)&(ENETQ_DMA_CHX_REGS(ioaddr, chan))->rx_ctrl);

	rte_write32(upper_32_bits(dma_rx_phy),
		(void *)&(ENETQ_DMA_CHX_REGS(ioaddr, chan))->rx_addr_hi);
	rte_write32(lower_32_bits(dma_rx_phy),
		(void *)&(ENETQ_DMA_CHX_REGS(ioaddr, chan))->rx_addr);
}

static int enetqos_set_bfsize(int mtu)
{
	int ret;

	if (mtu >= BUF_SIZE_8KiB)
		ret = BUF_SIZE_16KiB;
	else if (mtu >= BUF_SIZE_4KiB)
		ret = BUF_SIZE_8KiB;
	else if (mtu >= BUF_SIZE_2KiB)
		ret = BUF_SIZE_4KiB;
	else if (mtu > DEFAULT_BUFSIZE)
		ret = BUF_SIZE_2KiB;
	else
		ret = DEFAULT_BUFSIZE;

	return ret;
}

static void enetqos_set_dma_bfsize(void *ioaddr, int bfsize, uint32_t chan)
{
	uint32_t value =
		rte_read32((void *)&(ENETQ_DMA_CHX_REGS(ioaddr, chan))->rx_ctrl);

	value &= ~ENETQ_DMA_RBSZ_MASK;
	value |= (bfsize << ENETQ_DMA_RBSZ_SHIFT) & ENETQ_DMA_RBSZ_MASK;

	rte_write32(value, (void *)&(ENETQ_DMA_CHX_REGS(ioaddr, chan))->rx_ctrl);
}

static int
enetqos_rx_queue_setup(struct rte_eth_dev *dev,
	uint16_t queue_idx,
	uint16_t nb_rx_desc,
	unsigned int socket_id __rte_unused,
	const struct rte_eth_rxconf *rx_conf __rte_unused,
	struct rte_mempool *mb_pool)
{
	struct enetqos_priv *priv = dev->data->dev_private;
	struct enetqos_rx_queue *rxq;
	struct dma_desc *p;
	rte_iova_t addr;
	int i, bfsize;

	/* allocate receive queue */
	rxq = rte_zmalloc(NULL, sizeof(*rxq), RTE_CACHE_LINE_SIZE);
	if (rxq == NULL) {
		ENETQOS_PMD_ERR("receive queue allocation failed \n");
		return -ENOMEM;
	}

	if (nb_rx_desc > DMA_DEFAULT_RX_SIZE) {
		nb_rx_desc = DMA_DEFAULT_RX_SIZE;
		ENETQOS_PMD_INFO("modified the nb_desc to MAX_RX_BD_RING_SIZE: %d", DMA_DEFAULT_RX_SIZE);
	}

	priv->rx_queue[queue_idx] = rxq;
	rxq->queue_index = queue_idx;
	rxq->priv_data = priv;

	rxq->pool = mb_pool;
	rxq->dma_rx = (struct dma_desc *)priv->dma_baseaddr_r[queue_idx];
	rxq->dma_rx_phy = priv->bd_addr_p_r[queue_idx];
	rxq->dirty_rx = 0;
	rxq->cur_rx = 0;
	rxq->rx_count_frames = 0;

	for (i = 0; i < nb_rx_desc; i++) {
		/* Initialize Rx buffers from pktmbuf pool */
		struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mb_pool);
		if (mbuf == NULL) {
			ENETQOS_PMD_ERR("mbuf failed\n");
			goto err_alloc;
		}

		addr = rte_pktmbuf_iova(mbuf);
		p = rxq->dma_rx + i;
		enetqos_set_addr(p, addr);

		rxq->rx_mbuf[i] = mbuf;
		rxq->buf_alloc_num++;

		/* Set the owner bit and valid buffer address bit for the
		   descriptors in the BD ring.
		 */
		p->des3 |= rte_cpu_to_le_32(ENETQ_RDES3_OWN | ENETQ_RDES3_BUFFER1_VALID_ADDR);
	}

	enetqos_dma_init_rx_chan(priv->ioaddr, priv->dma_cfg, rxq->dma_rx_phy, rxq->queue_index);

	rxq->rx_tail_addr = rxq->dma_rx_phy + (rxq->buf_alloc_num *
		sizeof(struct dma_desc));
	enetqos_set_rx_tail_ptr(priv->ioaddr, rxq->rx_tail_addr, queue_idx);

	bfsize = enetqos_set_bfsize(dev->data->mtu);
	enetqos_set_dma_bfsize(priv->ioaddr, bfsize, queue_idx);

	dev->data->rx_queues[queue_idx] = priv->rx_queue[queue_idx];

	return 0;
err_alloc:
	for (i = 0; i < nb_rx_desc; i++) {
		if (rxq->rx_mbuf[i] != NULL) {
			rte_pktmbuf_free(rxq->rx_mbuf[i]);
			rxq->rx_mbuf[i] = NULL;
		}
	}
	rte_free(rxq);
	return errno;
}

static int enetqos_hw_setup(struct enetqos_priv *priv)
{
	struct enetqos_dma_cfg *dma_cfg;
	uint32_t chan;
	int ret;

	uint32_t rx_channels_count = priv->rx_queues_to_use;
	uint32_t tx_channels_count = priv->tx_queues_to_use;
	uint32_t dma_csr_ch = RTE_MAX(rx_channels_count, tx_channels_count);

	/* Software reset */
	ret = enetqos_dma_reset(priv->ioaddr);
	if (ret)
		return ret;

	dma_cfg = malloc(sizeof(struct enetqos_dma_cfg));
	if (!dma_cfg)
		return -ENOMEM;

	dma_cfg->pbl = PBL_VAL;
	dma_cfg->pblx8 = true;
	dma_cfg->eame = true;
	dma_cfg->aal = false;
	dma_cfg->dche = false;
	dma_cfg->fixed_burst = 0;
	dma_cfg->mixed_burst = 0;

	priv->dma_cfg = dma_cfg;

	enetqos_dma_init(priv->ioaddr, priv->dma_cfg);

	for (chan = 0; chan < dma_csr_ch; chan++)
		enetqos_dma_init_channel(priv->ioaddr, priv->dma_cfg, chan);

	/* Initialize the MAC Core */
	enetqos_core_init(priv->ioaddr);

	/* Map RX MTL to DMA channels */
	enetqos_rx_queue_dma_chan_map(priv);

	/* Enable MAC RX Queues */
	enetqos_mac_enable_rx_queues(priv);

	/* Set the HW DMA mode*/
	enetqos_dma_operation_mode(priv);

	return 0;
}

static int
enetqos_eth_configure(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}

static int
enetqos_eth_start(struct rte_eth_dev *dev)
{
	struct enetqos_priv *priv = dev->data->dev_private;

	enetqos_start_all_dma(priv);

	enetqos_set_rings_length(priv);

	dev->rx_pkt_burst = &enetqos_recv_pkts;
	dev->tx_pkt_burst = &enetqos_xmit_pkts;

	return 0;
}

static int
enetqos_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats)
{
	struct enetqos_priv *priv = dev->data->dev_private;
	struct rte_eth_stats *eth_stats = &priv->stats;

	stats->ipackets = eth_stats->ipackets;
	stats->ibytes = eth_stats->ibytes;
	stats->ierrors = eth_stats->ierrors;
	stats->rx_nombuf = eth_stats->rx_nombuf;
	stats->opackets = eth_stats->opackets;
	stats->obytes = eth_stats->obytes;
	stats->oerrors = eth_stats->oerrors;

	return 0;
}

static int
enetqos_eth_info(struct rte_eth_dev *dev __rte_unused,
	struct rte_eth_dev_info *dev_info)
{
	dev_info->max_rx_pktlen = ENETQOS_MAX_RX_PKT_LEN;
	dev_info->nb_tx_queues = ENETQOS_MAX_Q;
	dev_info->nb_rx_queues = ENETQOS_MAX_Q;
	dev_info->max_rx_queues = ENETQOS_MAX_Q;
	dev_info->max_tx_queues = ENETQOS_MAX_Q;

	return 0;
}

/* Set a MAC change in hardware. */
static int
enetqos_set_mac_address(struct rte_eth_dev *dev,
	struct rte_ether_addr *addr)
{
	struct enetqos_priv *priv = dev->data->dev_private;
	unsigned long data;
	unsigned int high, low;

	high = ENETQ_MAC_ADDR_HIGH(0);
	low = ENETQ_MAC_ADDR_LOW(0);
	data = (addr->addr_bytes[5] << 8) | addr->addr_bytes[4];

	data |= (ENETQOS_CH0 << ENETQ_MAC_HI_DCS_SHIFT);
	rte_write32(data | ENETQ_MAC_HI_REG_AE,
		(void *)((size_t)priv->ioaddr + high));
	data = (addr->addr_bytes[3] << 24) | (addr->addr_bytes[2] << 16) | (addr->addr_bytes[1] << 8) | addr->addr_bytes[0];
	rte_write32(data, (void *)((size_t) priv->ioaddr + low));

	rte_ether_addr_copy(addr, &dev->data->mac_addrs[0]);

	return 0;
}

static int
enetqos_eth_link_update(struct rte_eth_dev *dev,
	int wait_to_complete __rte_unused)
{
	struct rte_eth_link link;
	unsigned int lstatus = 1;

	memset(&link, 0, sizeof(struct rte_eth_link));

	link.link_status = lstatus;
	link.link_speed = RTE_ETH_SPEED_NUM_1G;

	ENETQOS_PMD_INFO("Port (%d) link is %s\n", dev->data->port_id, "Up");

	return rte_eth_linkstatus_set(dev, &link);
}

static int
enetqos_promiscuous_enable(struct rte_eth_dev *dev)
{
	struct enetqos_priv *priv = dev->data->dev_private;
	unsigned int value;

	value = rte_read32((void *)((size_t) priv->ioaddr + ENETQ_MAC_PKT_FILTER));
	value |= ENETQ_MAC_PKT_FILTER_PR;

	rte_write32(value,
		(void *)((size_t) priv->ioaddr + ENETQ_MAC_PKT_FILTER));

	return 0;
}

static void
enetqos_disable(struct enetqos_priv *priv)
{
	uint32_t value = rte_read32((void *)((size_t) priv->ioaddr + ENETQ_MAC_CONFIG));
	value &= ~(ENETQ_MAC_CORE_INIT | ENETQ_MAC_CONFIG_TE | ENETQ_MAC_CONFIG_RE);
	rte_write32(value, (void *)((size_t) priv->ioaddr + ENETQ_MAC_CONFIG));
}

static int
enetqos_eth_stop(struct rte_eth_dev *dev)
{
	struct enetqos_priv *priv = dev->data->dev_private;

	dev->data->dev_started = 0;
	enetqos_disable(priv);

	return 0;
}

static int
enetqos_eth_close(struct rte_eth_dev *dev)
{
	enetqos_free_buffers(dev);

	return 0;
}

static const struct eth_dev_ops enetqos_ops = {
	.dev_configure		= enetqos_eth_configure,
	.dev_start		= enetqos_eth_start,
	.dev_stop		= enetqos_eth_stop,
	.dev_close		= enetqos_eth_close,
	.dev_infos_get		= enetqos_eth_info,
	.stats_get		= enetqos_stats_get,
	.mac_addr_set		= enetqos_set_mac_address,
	.link_update		= enetqos_eth_link_update,
	.promiscuous_enable	= enetqos_promiscuous_enable,
	.rx_queue_setup		= enetqos_rx_queue_setup,
	.tx_queue_setup		= enetqos_tx_queue_setup
};

static int
enetqos_eth_init(struct rte_eth_dev *dev)
{
	struct enetqos_priv *priv = dev->data->dev_private;

	dev->dev_ops = &enetqos_ops;
	enetqos_hw_setup(priv);

	rte_eth_dev_probing_finish(dev);

	return 0;
}

static void
enetqos_free_queue(struct rte_eth_dev *dev)
{
	struct enetqos_priv *priv = dev->data->dev_private;
	unsigned int i;

	for (i = 0; i < dev->data->nb_rx_queues; i++)
		rte_free(priv->rx_queue[i]);
	for (i = 0; i < dev->data->nb_tx_queues; i++)
		rte_free(priv->tx_queue[i]);
}

static int
mark_memory_ncache(struct enetqos_priv *priv, const char *mz_name, int size) {
	const struct rte_memzone *tz;
	struct rte_memseg* memseg;
	uint64_t non_alloc_diff;
	uint64_t huge_page;

	tz = rte_memzone_reserve(mz_name, size, SOCKET_ID_ANY, 0);

	if (tz) {
		priv->bd_addr_v = tz->addr;
		priv->bd_addr_p = tz->iova;

		memseg = rte_mem_virt2memseg((void*) ((uintptr_t)tz->addr + size - 1), NULL);
		non_alloc_diff = (uintptr_t)memseg->addr - (uintptr_t)tz->addr;

		if (non_alloc_diff != 0) {
			rte_memzone_free(tz);
			tz = rte_memzone_reserve(mz_name, size + non_alloc_diff, SOCKET_ID_ANY, 0);

			if (tz) {
				if (priv->bd_addr_v == tz->addr) {
					priv->bd_addr_v = (void*) ((uintptr_t)tz->addr + non_alloc_diff);
					priv->bd_addr_p = tz->iova + non_alloc_diff;
				} else {
					/* If the memzone allocation after freeing it is different
					 * from the previous allocated, system will reserve
					 * a 2MB aligned hugepage for BD memory.
					 */
					rte_memzone_free(tz);
					tz = rte_memzone_reserve_aligned(mz_name, SIZE_2MB, SOCKET_ID_ANY, 0, SIZE_2MB);
					if (tz) {
						priv->bd_addr_v = tz->addr;
						priv->bd_addr_p = tz->iova;
					} else {
						ENETQOS_PMD_ERR("Failed to allocate memzone");
						return -ENOMEM;
					}
				}
			} else {
				ENETQOS_PMD_ERR("Failed to allocate memzone");
				return -ENOMEM;
			}
		}
	} else {
		ENETQOS_PMD_ERR("Failed to allocate memzone");
		return -ENOMEM;
	}

/* Mark memory NON-CACHEABLE */
	huge_page =
		(uint64_t)RTE_PTR_ALIGN_FLOOR(priv->bd_addr_v, SIZE_2MB);

	mark_kpage_ncache(huge_page);

	return 0;
}

static int pmd_enetqos_probe(struct rte_vdev_device *vdev)
{
	struct rte_ether_addr macaddr = {
		.addr_bytes = { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 }
	};
	char *dtb_entry;
	const char *mz_name = "bd_addr_v";
	struct rte_eth_dev *dev = NULL;
	size_t ccsr_addr, ccsr_size;
	struct enetqos_priv *priv;
	unsigned int bdsize, i;
	const char *name;
	int bd_total = 0;
	int fd = -1;
	FILE *file;
	int size;
	int ret, rt;
	int cnt;

	name = rte_vdev_device_name(vdev);
	ENETQOS_PMD_LOG(INFO, "Initializing pmd_fec for %s", name);

	dev = rte_eth_vdev_allocate(vdev, sizeof(*priv));
	if (dev == NULL)
		return -ENOMEM;

	priv = dev->data->dev_private;

	if (!priv->dma_tx_size)
		priv->dma_tx_size = DMA_DEFAULT_TX_SIZE;
	if (!priv->dma_rx_size)
		priv->dma_rx_size = DMA_DEFAULT_RX_SIZE;

	size = sizeof(struct dma_desc);
	/* BD memory is 160kb so reserving a max of 2MB memory */
	bd_total = SIZE_2MB;

	priv->rx_queues_to_use = 1;
	priv->tx_queues_to_use = 1;
	bdsize = size * DMA_DEFAULT_SIZE;

	if (mark_memory_ncache(priv, mz_name, bd_total)) {
		ENETQOS_PMD_ERR("Failed to mark BD memory non-cacheable!");
		rt = -1;
		goto err;
	}

	for (i = 0; i < priv->tx_queues_to_use; i++) {
		priv->dma_baseaddr_t[i] = priv->bd_addr_v;
		priv->bd_addr_p_t[i] = priv->bd_addr_p;
		priv->bd_addr_v = (uint8_t *)priv->bd_addr_v + bdsize;
		priv->bd_addr_p = priv->bd_addr_p + bdsize;
	}
	for (i = 0; i < priv->rx_queues_to_use; i++) {
		priv->dma_baseaddr_r[i] = priv->bd_addr_v;
		priv->bd_addr_p_r[i] = priv->bd_addr_p;
		priv->bd_addr_v = (uint8_t *)priv->bd_addr_v + bdsize;
		priv->bd_addr_p = priv->bd_addr_p + bdsize;
	}


	file = fopen("/proc/device-tree/aliases/ethernet1", "r");
	if (file) {
		dtb_entry = malloc(MAX_LINE_SIZE);
		if (!dtb_entry) {
			ENETQOS_PMD_ERR("malloc failed!!");
			rt = -1;
			goto err;
		}
		cnt = fread(dtb_entry, sizeof(char), MAX_LINE_SIZE, file);
		/* fread success */
		if (cnt) {
			ret = sscanf(EXTRACT_CCSR_ADDR(dtb_entry), "%lx",
				     &ccsr_addr);
			if (ret != 1) {
				ENETQOS_PMD_ERR("sscanf failed!!");
				rt = -1;
				free(dtb_entry);
				fclose(file);
				goto err;
			}
			ccsr_size = ENETQ_CCSR_SIZE;
		}
		free(dtb_entry);
		fclose(file);
	} else {
		ENETQOS_PMD_ERR("File open failed!!");
		rt = -1;
		goto err;
	}

	fd = open("/dev/mem", O_RDWR);
	if (fd) {
		priv->hw_baseaddr_v = mmap(NULL, ccsr_size, PROT_READ | PROT_WRITE,
				      MAP_SHARED, fd, ccsr_addr);
		if (priv->hw_baseaddr_v == MAP_FAILED) {
			ENETQOS_PMD_ERR("Can not map CCSR base");
			rt = -EINVAL;
			close(fd);
			goto err;
		}
		close(fd);
	} else {
		ENETQOS_PMD_ERR("Failed to open /dev/mem");
		rt = -1;
		goto err;
	}

	priv->ioaddr = priv->hw_baseaddr_v;

	/* Copy the station address into the dev structure, */
	dev->data->mac_addrs = rte_zmalloc("mac_addr", RTE_ETHER_ADDR_LEN, 0);
	if (dev->data->mac_addrs == NULL) {
		ENETQOS_PMD_ERR("Failed to allocate mem %d to store MAC addresses",
			RTE_ETHER_ADDR_LEN);
		rt = -ENOMEM;
		goto err;
	}

	enetqos_set_mac_address(dev, &macaddr);

	rt = enetqos_eth_init(dev);
	if (rt)
		ENETQOS_PMD_ERR("ENET-QOS init failed");

	return 0;
err:
	rte_eth_dev_release_port(dev);
	return rt;
}

static int
pmd_enetqos_remove(struct rte_vdev_device *vdev)
{
	struct rte_eth_dev *eth_dev = NULL;
	struct enetqos_priv *priv;
	int ret;

	/* find the ethdev entry */
	eth_dev = rte_eth_dev_allocated(rte_vdev_device_name(vdev));
	if (eth_dev == NULL)
		return -ENODEV;

	priv = eth_dev->data->dev_private;

	enetqos_stop_all_dma(priv);
	enetqos_free_queue(eth_dev);
	enetqos_eth_stop(eth_dev);

	ret = rte_eth_dev_release_port(eth_dev);
	if (ret != 0)
		return -EINVAL;

	ENETQOS_PMD_INFO("Release enetqos sw device");

	return 0;
}

static struct rte_vdev_driver pmd_enetqos_drv = {
	.probe = pmd_enetqos_probe,
	.remove = pmd_enetqos_remove,
};

RTE_PMD_REGISTER_VDEV(ENETQOS_NAME_PMD, pmd_enetqos_drv);
RTE_LOG_REGISTER_DEFAULT(enetqos_logtype_pmd, NOTICE);

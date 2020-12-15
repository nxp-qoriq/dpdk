/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 NXP
 */
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <errno.h>
#include <rte_kvargs.h>
#include <rte_ethdev_vdev.h>
#include <rte_bus_vdev.h>
#include <rte_dev.h>
#include <rte_ether.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <dpaa_of.h>
#include <rte_io.h>
#include "enet_regs.h"
#include "enet_ethdev.h"
#include "enet_pmd_logs.h"

#define ENETFEC_NAME_PMD	net_enetfec
#define ENET_VDEV_GEM_ID_ARG	"intf"
#define ENET_CDEV_INVALID_FD	-1
#define DEVICE_FILE    "/dev/fec_dev"
#define BD_SIZE 32

#define BIT(nr)			(1 << (nr))
/* FEC receive acceleration */
#define ENET_RACC_IPDIS		(1 << 1)
#define ENET_RACC_PRODIS	(1 << 2)
#define ENET_RACC_SHIFT16	BIT(7)
#define ENET_RACC_OPTIONS	(ENET_RACC_IPDIS | ENET_RACC_PRODIS)

/* Transmitter timeout */
#define TX_TIMEOUT (2 * HZ)

#define ENET_PAUSE_FLAG_AUTONEG		0x1
#define ENET_PAUSE_FLAG_ENABLE		0x2
#define ENET_WOL_HAS_MAGIC_PACKET	(0x1 << 0)
#define ENET_WOL_FLAG_ENABLE		(0x1 << 1)
#define ENET_WOL_FLAG_SLEEP_ON		(0x1 << 2)

/* Pause frame feild and FIFO threshold */
#define ENET_ENET_FCE		(1 << 5)
#define ENET_ENET_RSEM_V	0x84
#define ENET_ENET_RSFL_V	16
#define ENET_ENET_RAEM_V	0x8
#define ENET_ENET_RAFL_V	0x8
#define ENET_ENET_OPD_V		0xFFF0
#define ENET_MDIO_PM_TIMEOUT	100 /* ms */

int enetfec_logtype_pmd;

/* Supported Rx offloads */
static uint64_t dev_rx_offloads_sup =
		DEV_RX_OFFLOAD_IPV4_CKSUM |
		DEV_RX_OFFLOAD_UDP_CKSUM |
		DEV_RX_OFFLOAD_TCP_CKSUM |
		DEV_RX_OFFLOAD_VLAN_STRIP |
		DEV_RX_OFFLOAD_CHECKSUM;

static uint64_t dev_tx_offloads_sup =
		DEV_TX_OFFLOAD_IPV4_CKSUM |
		DEV_TX_OFFLOAD_UDP_CKSUM |
		DEV_TX_OFFLOAD_TCP_CKSUM;

static void enet_free_buffers(struct rte_eth_dev *dev)
{
	struct enetfec_private *fep = dev->data->dev_private;
	unsigned int i;
	struct rte_mbuf *mbuf;
	struct bufdesc  *bdp;
	struct enetfec_priv_rx_q *rxq;
	struct enetfec_priv_tx_q *txq;
	unsigned int q;

	for (q = 0; q < fep->max_rx_queues; q++) {
		rxq = fep->rx_queues[q];
		bdp = rxq->bd.base;
		for (i = 0; i < rxq->bd.ring_size; i++) {
			mbuf = rxq->rx_mbuf[i];
			rxq->rx_mbuf[i] = NULL;
			if (mbuf)
				rte_pktmbuf_free(mbuf);
			bdp = enet_get_nextdesc(bdp, &rxq->bd);
		}
	}

	for (q = 0; q < fep->max_tx_queues; q++) {
		txq = fep->tx_queues[q];
		bdp = txq->bd.base;
		for (i = 0; i < txq->bd.ring_size; i++) {
			rte_free(txq->tx_bounce[i]);
			txq->tx_bounce[i] = NULL;
			mbuf = txq->tx_mbuf[i];
			txq->tx_mbuf[i] = NULL;
			if (mbuf)
				rte_pktmbuf_free(mbuf);
		}
	}
}

static int
enetfec_tx_queue_setup(struct rte_eth_dev *dev,
			uint16_t queue_idx,
			uint16_t nb_desc,
			__rte_unused unsigned int socket_id,
			__rte_unused const struct rte_eth_txconf *tx_conf)
{
	struct enetfec_private *fep = dev->data->dev_private;
	unsigned int i;
	struct bufdesc  *bdp;
	struct enetfec_priv_tx_q *txq;

	txq = fep->tx_queues[queue_idx];
	txq->fep = fep;
	bdp = txq->bd.base;

	if (nb_desc > TX_BD_RING_SIZE)
		nb_desc = TX_BD_RING_SIZE;

	for (i = 0; i < nb_desc; i++) {
		txq->tx_bounce[i] = rte_malloc(NULL, ENET_TX_FR_SIZE,
					RTE_CACHE_LINE_SIZE);
		if (!txq->tx_bounce[i])
			goto err_alloc;

		rte_write16(rte_cpu_to_le_16(0), &bdp->bd_sc);
		rte_write32(rte_cpu_to_le_32(0), &bdp->bd_bufaddr);
		bdp = enet_get_nextdesc(bdp, &txq->bd);
	}

	/* Set the last buffer to wrap. */
	bdp = enet_get_prevdesc(bdp, &txq->bd);
	rte_write16((rte_cpu_to_le_16(TX_BD_WRAP) | rte_read16(&bdp->bd_sc)),
			&bdp->bd_sc);
	dev->data->tx_queues[queue_idx] = fep->tx_queues[queue_idx];
	return 0;

err_alloc:
	enet_free_buffers(dev);
	return -ENOMEM;
}

static void *
create_mmap(uint64_t dbaseaddr_p, size_t len)
{
	int fd;
	void *v_addr;

	/* open the char device */
	printf("Opening File:%s\n", DEVICE_FILE);
	fd = open(DEVICE_FILE, O_RDWR);
	if (fd < 0) {
		perror("Open Failed");
		exit(1);
	}

	v_addr = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED,
			fd, dbaseaddr_p);
	if (v_addr == MAP_FAILED)
		ENET_PMD_ERR("Failed %s\n", __func__);

	printf("Closing File\n");
	close(fd);

	return v_addr;
}

static int
enetfec_rx_queue_setup(struct rte_eth_dev *dev,
			uint16_t queue_idx,
			uint16_t nb_rx_desc,
			 __rte_unused unsigned int socket_id,
			 __rte_unused const struct rte_eth_rxconf *rx_conf,
			struct rte_mempool *mb_pool)
{
	struct enetfec_private *fep = dev->data->dev_private;
	unsigned int i;
	struct bufdesc  *bdp;
	struct enetfec_priv_rx_q *rxq;

	rxq = fep->rx_queues[queue_idx];
	rxq->pool = mb_pool;
	rxq->fep = fep;
	bdp = rxq->bd.base;

	if (nb_rx_desc > RX_BD_RING_SIZE)
		nb_rx_desc = RX_BD_RING_SIZE;

	for (i = 0; i < nb_rx_desc; i++) {
		/* Initialize Rx buffers from the shared memory */
		struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mb_pool);
		if (mbuf == NULL) {
			ENET_PMD_ERR("mbuf failed\n");
			goto err_alloc;
		}

		/* Get the virtual address & physical address */
		enet_new_rxbdp(fep, bdp, mbuf);

		rxq->rx_mbuf[i] = mbuf;
		rte_write16(rte_cpu_to_le_16(RX_BD_EMPTY), &bdp->bd_sc);

		bdp = enet_get_nextdesc(bdp, &rxq->bd);
	}

	/* Set the last buffer to wrap. */
	bdp = enet_get_prevdesc(bdp, &rxq->bd);
	rte_write16((rte_cpu_to_le_16(RX_BD_WRAP) | rte_read16(&bdp->bd_sc)),
			&bdp->bd_sc);
	dev->data->rx_queues[queue_idx] = fep->rx_queues[queue_idx];
	return 0;

err_alloc:
	enet_free_buffers(dev);
	return -ENOMEM;
}

static int
enetfec_promiscuous_disable(__rte_unused struct rte_eth_dev *dev)
{
	ENET_PMD_INFO("%s: returning zero ", __func__);
	return 0;
}

static int
enetfec_promiscuous_enable(__rte_unused struct rte_eth_dev *dev)
{
	struct enetfec_private *fep = dev->data->dev_private;
	uint32_t tmp;

	tmp = rte_read32(fep->hw_baseaddr + ENET_RCR);
	tmp |= 0x8;
	tmp &= ~0x2;
	rte_write32(tmp, fep->hw_baseaddr + ENET_RCR);

	return 0;
}

static int
enetfec_eth_link_update(__rte_unused struct rte_eth_dev *dev,
			__rte_unused int wait_to_complete)
{
	return 0;
}

static int
enetfec_eth_configure(__rte_unused struct rte_eth_dev *dev)
{
	ENET_PMD_INFO("%s: returning zero ", __func__);
	return 0;
}

static int
enetfec_eth_info(__rte_unused struct rte_eth_dev *dev,
	     struct rte_eth_dev_info *dev_info)
{
	dev_info->max_rx_queues = 3;
	dev_info->max_tx_queues = 3;
	dev_info->min_mtu = RTE_ETHER_MIN_MTU;
	dev_info->rx_offload_capa = dev_rx_offloads_sup;
	dev_info->tx_offload_capa = dev_tx_offloads_sup;
	return 0;
}

static void
enetfec_stop(__rte_unused struct rte_eth_dev *dev)
{
/*TODO*/
}

static void
enetfec_eth_close(__rte_unused struct rte_eth_dev *dev)
{
	/* phy_stop(ndev->phydev); */
	enetfec_stop(dev);
	/* phy_disconnect(ndev->phydev); */

	enet_free_buffers(dev);
}

static uint16_t
enetfec_dummy_xmit_pkts(__rte_unused void *tx_queue,
		__rte_unused struct rte_mbuf **tx_pkts,
		__rte_unused uint16_t nb_pkts)
{
	return 0;
}

static uint16_t
enetfec_dummy_recv_pkts(__rte_unused void *rxq,
		__rte_unused struct rte_mbuf **rx_pkts,
		__rte_unused uint16_t nb_pkts)
{
	return 0;
}

static void
enetfec_eth_stop(__rte_unused struct rte_eth_dev *dev)
{
	dev->rx_pkt_burst = &enetfec_dummy_recv_pkts;
	dev->tx_pkt_burst = &enetfec_dummy_xmit_pkts;

	return;
}

static int
enetfec_multicast_enable(struct rte_eth_dev *dev)
{
	struct enetfec_private *fep = dev->data->dev_private;

	rte_write32(0xffffffff, fep->hw_baseaddr + ENET_GAUR);
	rte_write32(0xffffffff, fep->hw_baseaddr + ENET_GALR);
	dev->data->all_multicast = 1;

	rte_write32(0x04400002, fep->hw_baseaddr + ENET_GAUR);
	rte_write32(0x10800049, fep->hw_baseaddr + ENET_GALR);

	return 0;
}

/* Init RX & TX buffer descriptors */
static void enet_bd_init(struct rte_eth_dev *dev)
{
	struct enetfec_private *fep = dev->data->dev_private;
	struct enetfec_priv_tx_q *txq;
	struct enetfec_priv_rx_q *rxq;
	struct bufdesc *bdp;
	unsigned int i, q;

	for (q = 0; q < fep->max_rx_queues; q++) {
		/* Initialize the receive buffer descriptors. */
		rxq = fep->rx_queues[q];
		bdp = rxq->bd.base;

		for (i = 0; i < rxq->bd.ring_size; i++) {
			/* Initialize the BD for every fragment in the page. */
			if (rte_read32(&bdp->bd_bufaddr))
				rte_write16(rte_cpu_to_le_16(RX_BD_EMPTY),
					&bdp->bd_sc);
			else
				rte_write16(rte_cpu_to_le_16(0), &bdp->bd_sc);
			bdp = enet_get_nextdesc(bdp, &rxq->bd);
		}

		/* Set the last buffer to wrap */
		bdp = enet_get_prevdesc(bdp, &rxq->bd);
		rte_write16((rte_cpu_to_le_16(RX_BD_WRAP) |
			     rte_read16(&bdp->bd_sc)),	&bdp->bd_sc);
		rxq->bd.cur = rxq->bd.base;
	}

	for (q = 0; q < fep->max_tx_queues; q++) {
		/* ...and the same for transmit */
		txq = fep->tx_queues[q];
		bdp = txq->bd.base;
		txq->bd.cur = bdp;

		for (i = 0; i < txq->bd.ring_size; i++) {
			/* Initialize the BD for every fragment in the page. */
			rte_write16(rte_cpu_to_le_16(0), &bdp->bd_sc);
			if (txq->tx_mbuf[i]) {
				rte_pktmbuf_free(txq->tx_mbuf[i]);
				txq->tx_mbuf[i] = NULL;
			}
			rte_write32(rte_cpu_to_le_32(0), &bdp->bd_bufaddr);
			bdp = enet_get_nextdesc(bdp, &txq->bd);
		}

		/* Set the last buffer to wrap */
		bdp = enet_get_prevdesc(bdp, &txq->bd);
		rte_write16((rte_cpu_to_le_16(TX_BD_WRAP) |
			     rte_read16(&bdp->bd_sc)), &bdp->bd_sc);
		txq->dirty_tx = bdp;
	}
}

static void enet_active_rxring(struct rte_eth_dev *dev)
{
	struct enetfec_private *fep = dev->data->dev_private;
	unsigned int i;

	for (i = 0; i < fep->max_rx_queues; i++)
		rte_write32(0x0, fep->rx_queues[i]->bd.active_reg_desc);
}

static void enet_enable_ring(struct rte_eth_dev *dev)
{
	struct enetfec_private *fep = dev->data->dev_private;
//	struct enetfec_priv_tx_q *txq;
//	struct enetfec_priv_rx_q *rxq;
	unsigned int i;

	for (i = 0; i < fep->max_rx_queues; i++) {
//		rxq = fep->rx_queues[i];
//		rte_write32(rxq->bd.descr_baseaddr_p,
//				fep->hw_baseaddr + ENET_RD_START(i));
//		rte_write32(PKT_MAX_BUF_SIZE,
//				fep->hw_baseaddr + ENET_MRB_SIZE(i));

		/* enable DMA1/2 */
		if (i)
			rte_write32(RCM_MATCHEN | RCM_CMP(i),
				fep->hw_baseaddr + ENET_RCM(i));
	}

	for (i = 0; i < fep->max_tx_queues; i++) {
//		txq = fep->tx_queues[i];
//		rte_write32(txq->bd.descr_baseaddr_p,
//				fep->hw_baseaddr + ENET_TD_START(i));

		/* enable DMA1/2 */
		if (i)
			rte_write32(ENABLE_DMA_CLASS | SLOPE_IDLE(i),
				fep->hw_baseaddr + ENET_DMACFG(i));
	}
}

/*
 * This function is called to start or restart the FEC during a link
 * change, transmit timeout, or to reconfigure the FEC.  The network
 * packet processing for this device must be stopped before this call.
 */
static void
enetfec_restart(struct rte_eth_dev *dev)
{
	struct enetfec_private *fep = dev->data->dev_private;
	uint32_t temp_mac[2];
	uint32_t rcntl = OPT_FRAME_SIZE | 0x04;
	uint32_t ecntl = ENET_ETHEREN; /* ETHEREN */
	/* TODO get eth addr from eth dev */
	struct rte_ether_addr addr = {
		.addr_bytes = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6} };
	uint32_t val;

	/* For i.MX6SX SOC, enet use AXI bus, we use disable MAC
	 * instead of reset MAC itself.
	 */
	/*
	 * if (fep->quirks & ENET_QUIRK_HAS_AVB) {
	 *	rte_write32(0, fep->hw_baseaddr + ENET_ECR);
	 * } else {
	 *	rte_write32(1, fep->hw_baseaddr + ENET_ECR);
	 *	rte_delay_us(10);
	 * }
	 */

	/*
	 * enet-mac reset will reset mac address registers too,
	 * so need to reconfigure it.
	 */
	memcpy(&temp_mac, addr.addr_bytes, ETH_ALEN);
	rte_write32(rte_cpu_to_be_32(temp_mac[0]),
		fep->hw_baseaddr + ENET_PALR);
	rte_write32(rte_cpu_to_be_32(temp_mac[1]),
		fep->hw_baseaddr + ENET_PAUR);

	/* Clear any outstanding interrupt. */
	writel(0xffffffff, fep->hw_baseaddr + ENET_EIR);

	enet_bd_init(dev);
	enet_enable_ring(dev);

	/* Enable MII mode */
	if (fep->full_duplex == FULL_DUPLEX) {
		/* FD enable */
		rte_write32(0x04, fep->hw_baseaddr + ENET_TCR);
	} else {
		/* No Rcv on Xmit */
		rcntl |= 0x02;
		rte_write32(0x0, fep->hw_baseaddr + ENET_TCR);
	}

	if (fep->quirks & QUIRK_RACC) {
		val = rte_read32(fep->hw_baseaddr + ENET_RACC);
		/* align IP header */
		val |= ENET_RACC_SHIFT16;
		if (fep->flag_csum & RX_FLAG_CSUM_EN)
			/* set RX checksum */
			val |= ENET_RACC_OPTIONS;
		else
			val &= ~ENET_RACC_OPTIONS;
		rte_write32(val, fep->hw_baseaddr + ENET_RACC);
		rte_write32(PKT_MAX_BUF_SIZE,
			fep->hw_baseaddr + ENET_FRAME_TRL);
	}

	/*
	 * The phy interface and speed need to get configured
	 * differently on enet-mac.
	 */
	if (fep->quirks & QUIRK_HAS_ENET_MAC) {
		/* Enable flow control and length check */
		rcntl |= 0x40000000 | 0x00000020;

		/* RGMII, RMII or MII */
		rcntl |= (1 << 6);
		ecntl |= (1 << 5);
	}

	/* enable pause frame*/
	if ((fep->flag_pause & ENET_PAUSE_FLAG_ENABLE) ||
		((fep->flag_pause & ENET_PAUSE_FLAG_AUTONEG)
		/*&& ndev->phydev && ndev->phydev->pause*/)) {
		rcntl |= ENET_ENET_FCE;

		/* set FIFO threshold parameter to reduce overrun */
		rte_write32(ENET_ENET_RSEM_V,
				fep->hw_baseaddr + ENET_R_FIFO_SEM);
		rte_write32(ENET_ENET_RSFL_V,
				fep->hw_baseaddr + ENET_R_FIFO_SFL);
		rte_write32(ENET_ENET_RAEM_V,
				fep->hw_baseaddr + ENET_R_FIFO_AEM);
		rte_write32(ENET_ENET_RAFL_V,
				fep->hw_baseaddr + ENET_R_FIFO_AFL);

		/* OPD */
		rte_write32(ENET_ENET_OPD_V, fep->hw_baseaddr + ENET_OPD);
	} else {
		rcntl &= ~ENET_ENET_FCE;
	}

	rte_write32(rcntl, fep->hw_baseaddr + ENET_RCR);

	rte_write32(0, fep->hw_baseaddr + ENET_IAUR);
	rte_write32(0, fep->hw_baseaddr + ENET_IALR);

	if (fep->quirks & QUIRK_HAS_ENET_MAC) {
		/* enable ENET endian swap */
		ecntl |= (1 << 8);
		/* enable ENET store and forward mode */
		rte_write32(1 << 8, fep->hw_baseaddr + ENET_TFWR);
	}

	if (fep->bufdesc_ex)
		ecntl |= (1 << 4);

	if (fep->quirks & QUIRK_SUPPORT_DELAYED_CLKS &&
		fep->rgmii_txc_delay)
		ecntl |= ENET_TXC_DLY;
	if (fep->quirks & QUIRK_SUPPORT_DELAYED_CLKS &&
		fep->rgmii_rxc_delay)
		ecntl |= ENET_RXC_DLY;

	/* Enable the MIB statistic event counters */
	rte_write32(0 << 31, fep->hw_baseaddr + ENET_MIBC);

	ecntl |= 0x70000000;
	/* And last, enable the transmit and receive processing */
	rte_write32(ecntl, fep->hw_baseaddr + ENET_ECR);
	rte_delay_us(10);
	enet_active_rxring(dev);
}

static int
enetfec_eth_open(struct rte_eth_dev *dev)
{
	enetfec_restart(dev);

	dev->rx_pkt_burst = &enetfec_recv_pkts;
	dev->tx_pkt_burst = &enetfec_xmit_pkts;

	return 0;
}

static int
enetfec_stats_get(struct rte_eth_dev *dev,
	      struct rte_eth_stats *stats)
{
	struct enetfec_private *fep = dev->data->dev_private;
	struct rte_eth_stats *eth_stats = &fep->stats;

	if (stats == NULL)
		return -1;

	memset(stats, 0, sizeof(struct rte_eth_stats));

	stats->ipackets = eth_stats->ipackets;
	stats->ibytes = eth_stats->ibytes;
	stats->ierrors = eth_stats->ierrors;
	stats->opackets = eth_stats->opackets;
	stats->obytes = eth_stats->obytes;
	stats->oerrors = eth_stats->oerrors;

	return 0;
}

/* Set a MAC change in hardware. */
static int
enetfec_set_mac_address(struct rte_eth_dev *dev,
		    struct rte_ether_addr *addr)
{
	struct enetfec_private *fep = dev->data->dev_private;

	writel(addr->addr_bytes[3] | (addr->addr_bytes[2] << 8) |
		(addr->addr_bytes[1] << 16) | (addr->addr_bytes[0] << 24),
		fep->hw_baseaddr + ENET_PALR);
	writel((addr->addr_bytes[5] << 16) | (addr->addr_bytes[4] << 24),
		fep->hw_baseaddr + ENET_PAUR);

	rte_ether_addr_copy(addr, &dev->data->mac_addrs[0]);

	return 0;
}


static const struct eth_dev_ops ops = {
	.dev_start = enetfec_eth_open,
	.dev_stop = enetfec_eth_stop,
	.dev_close = enetfec_eth_close,
	.dev_configure = enetfec_eth_configure,
	.dev_infos_get = enetfec_eth_info,
	.rx_queue_setup = enetfec_rx_queue_setup,
	.tx_queue_setup = enetfec_tx_queue_setup,
	.link_update  = enetfec_eth_link_update,
	.mac_addr_set	      = enetfec_set_mac_address,
	.stats_get  = enetfec_stats_get,
	.promiscuous_enable   = enetfec_promiscuous_enable,
	.promiscuous_disable  = enetfec_promiscuous_disable,
	.allmulticast_enable = enetfec_multicast_enable
};

static const unsigned short offset_des_active_rxq[] = {
	ENET_RDAR_0, ENET_RDAR_1, ENET_RDAR_2
};

static const unsigned short offset_des_active_txq[] = {
	ENET_TDAR_0, ENET_TDAR_1, ENET_TDAR_2
};

static void enet_free_queue(struct rte_eth_dev *dev)
{
	struct enetfec_private *fep = dev->data->dev_private;
	unsigned int i;

	for (i = 0; i < fep->max_rx_queues; i++)
		rte_free(fep->rx_queues[i]);
	for (i = 0; i < fep->max_tx_queues; i++)
		rte_free(fep->rx_queues[i]);
}

/*
 * TODO:'enet_alloc_queue' and 'enet_bd_init' should be part of
 * queue configure (Rx and Tx separately). Tt should be based on the queue
 * that is being configured
 */
static int enet_alloc_queue(struct rte_eth_dev *dev)
{
	struct enetfec_private *fep = dev->data->dev_private;
	unsigned int i;
	int ret = 0;
	struct enetfec_priv_tx_q *txq;
	struct enetfec_priv_rx_q *rxq;

	for (i = 0; i < fep->max_tx_queues; i++) {
		txq = rte_zmalloc(NULL, sizeof(*txq), RTE_CACHE_LINE_SIZE);
		if (!txq) {
			ret = -ENOMEM;
			goto alloc_failed;
		}

		txq->bd.ring_size = TX_BD_RING_SIZE;
		fep->total_tx_ring_size += txq->bd.ring_size;
		fep->tx_queues[i] = txq;
	}

	for (i = 0; i < fep->max_rx_queues; i++) {
		rxq = rte_zmalloc(NULL, sizeof(*rxq),
					RTE_CACHE_LINE_SIZE);
		if (!rxq) {
			ret = -ENOMEM;
			goto alloc_failed;
		}
		rxq->bd.ring_size = RX_BD_RING_SIZE;
		fep->total_rx_ring_size += rxq->bd.ring_size;
		fep->rx_queues[i] = rxq;
	}
	return ret;

alloc_failed:
	enet_free_queue(dev);
	return ret;
}

static int
enetfec_eth_init(struct rte_eth_dev *dev)
{
	struct enetfec_private *fep = dev->data->dev_private;
	struct bufdesc *bd_base;
//	int bd_size;
	unsigned int i, ret;
	unsigned int dsize = fep->bufdesc_ex ? sizeof(struct bufdesc_ex) :
			sizeof(struct bufdesc);
	unsigned int dsize_log2 = fls64(dsize);
	uint64_t dbaseaddr_p;
	struct rte_eth_conf *eth_conf = &fep->dev->data->dev_conf;
	uint64_t rx_offloads = eth_conf->rxmode.offloads;

	fep->full_duplex = FULL_DUPLEX;
	/* fep->phy_interface = PHY_INTERFACE_MODE_RGMII; */

	ret = enet_alloc_queue(dev);
	if (ret)
		return ret;
/*
 *	bd_size = (fep->total_tx_ring_size + fep->total_rx_ring_size) * dsize;
 *
 *	// Allocate memory for buffer descriptors.
 *	bd_base = rte_zmalloc(NULL, bd_size, RTE_CACHE_LINE_SIZE);
 *	if (!bd_base) {
 *		ret = -ENOMEM;
 *		goto free_queue_mem;
 *	}
 *
 *	dbaseaddr_p = enetfec_mem_vtop((uintptr_t)bd_base);
 */
	dbaseaddr_p = rte_read32(fep->hw_baseaddr + ENET_RD_START(0));

	fep->dma_baseaddr_r[0] = create_mmap(dbaseaddr_p, (size_t)98304);
	if (fep->dma_baseaddr_r[0] == MAP_FAILED)
		ENET_PMD_ERR("mmap failed\n");
	bd_base = (struct bufdesc *)fep->dma_baseaddr_r[0];

	/* Set receive and transmit descriptor base. */
	for (i = 0; i < 3; i++) {
		struct enetfec_priv_rx_q *rxq = fep->rx_queues[i];
		unsigned int size = dsize * rxq->bd.ring_size;
		rxq->bd.que_id = i;
		rxq->bd.base = bd_base;
		rxq->bd.cur = bd_base;
		rxq->bd.d_size = dsize;
		rxq->bd.descr_baseaddr_p = dbaseaddr_p;
		rxq->bd.d_size_log2 = dsize_log2;
		dbaseaddr_p += size;
		rxq->bd.active_reg_desc =
				fep->hw_baseaddr + offset_des_active_rxq[i];
		bd_base = (struct bufdesc *)(((void *)bd_base) + size);
		rxq->bd.last = (struct bufdesc *)(((void *)bd_base) - dsize);
	}

	for (i = 0; i < 3; i++) {
		struct enetfec_priv_tx_q *txq = fep->tx_queues[i];
		unsigned int size = dsize * txq->bd.ring_size;
		txq->bd.que_id = i;
		txq->bd.base = bd_base;
		txq->bd.cur = bd_base;
		txq->bd.d_size = dsize;
		txq->bd.descr_baseaddr_p = dbaseaddr_p;
		txq->bd.d_size_log2 = dsize_log2;
		dbaseaddr_p += size;
		txq->bd.active_reg_desc =
				fep->hw_baseaddr + offset_des_active_txq[i];
		bd_base = (struct bufdesc *)(((void *)bd_base) + size);
		txq->bd.last = (struct bufdesc *)(((void *)bd_base) - dsize);
	}

	dev->dev_ops = &ops;
	if (fep->quirks & QUIRK_VLAN)
		/* enable hw VLAN support */
		rx_offloads |= DEV_RX_OFFLOAD_VLAN;

	if (fep->quirks & QUIRK_CSUM) {
		/* enable hw accelerator */
		rx_offloads |= DEV_RX_OFFLOAD_CHECKSUM;
		fep->flag_csum |= RX_FLAG_CSUM_EN;
	}

	rte_eth_dev_probing_finish(dev);
	return 0;

//free_queue_mem:
	enet_free_queue(dev);
	return ret;
}

static int
pmd_enetfec_probe(struct rte_vdev_device *vdev)
{
	struct rte_eth_dev *dev = NULL;
	struct enetfec_private *fep;
	const char *name;
	uint32_t swapped, *addr;
	const uint32_t *addr1;
	int rc = -1, fd = -1;
	const struct device_node *np;
	struct rte_ether_addr macaddr;

	name = rte_vdev_device_name(vdev);
	ENET_PMD_LOG(INFO, "Initializing pmd_fec for %s", name);

	dev = rte_eth_vdev_allocate(vdev, sizeof(*fep));
	if (dev == NULL)
		return -ENOMEM;

	/* setup board info structure */
	fep = dev->data->dev_private;
	fep->dev = dev;

	/* TODO: use DTB to read*/
	fep->max_rx_queues = ENET_MAX_Q;
	fep->max_tx_queues = ENET_MAX_Q;
	fep->quirks = QUIRK_HAS_ENET_MAC | QUIRK_GBIT |	QUIRK_BUFDESC_EX
		| QUIRK_CSUM | QUIRK_VLAN | QUIRK_ERR007885
		| QUIRK_RACC | QUIRK_COALESCE | QUIRK_EEE;

	/* Load the device-tree driver */
	rc = of_init();
	if (rc) {
		ENET_PMD_ERR("of_init failed with ret: %d\n", rc);
		goto err;
	}

	/* Return value: the node found */
	np = of_find_compatible_node(NULL, NULL, "fsl,imx8mm-fec");
	if (!np) {
		ENET_PMD_ERR("Invalid device node\n");
		rc = -EINVAL;
		goto err;
	}

	/* Return value: The first address of the read address data */
	addr1 = of_get_address(np, 0, &fep->cbus_size, NULL);
	if (!addr1) {
		ENET_PMD_ERR("of_get_address cannot return qman address\n");
		goto err;
	}

	swapped = rte_be_to_cpu_32(*addr1);
	addr = &swapped;

	/* mmap the hw base addr */
	fd = open("/dev/mem", O_RDWR);
	fep->hw_baseaddr = mmap(NULL, fep->cbus_size, PROT_READ | PROT_WRITE,
				MAP_SHARED, fd, *addr);
	close(fd);
	if (fep->hw_baseaddr == MAP_FAILED) {
		ENET_PMD_ERR("mmap failed\n");
		rc = -EINVAL;
		goto err;
	}

	/* Copy the station address into the dev structure, */
	dev->data->mac_addrs = rte_zmalloc("mac_addr", ETHER_ADDR_LEN, 0);
	if (dev->data->mac_addrs == NULL) {
		ENET_PMD_ERR("Failed to allocate mem %d to store MAC addresses",
			ETHER_ADDR_LEN);
		rc = -ENOMEM;
		goto err;
	}
	/* TODO get mac address from device tree or get random addr.
	 * Currently setting default as 1,1,1,1,1,1
	 */

	macaddr.addr_bytes[0] = 1;
	macaddr.addr_bytes[1] = 1;
	macaddr.addr_bytes[2] = 1;
	macaddr.addr_bytes[3] = 1;
	macaddr.addr_bytes[4] = 1;
	macaddr.addr_bytes[5] = 1;

	enetfec_set_mac_address(dev, &macaddr);

	fep->bufdesc_ex = 1;
	rc = enetfec_eth_init(dev);
	if (rc)
		goto failed_init;

	return 0;
failed_init:
	ENET_PMD_ERR("Failed to init");
err:
	rte_eth_dev_release_port(dev);
	return rc;
}

static int
pmd_enetfec_remove(struct rte_vdev_device *vdev)
{
	struct rte_eth_dev *eth_dev = NULL;
	struct enetfec_private *fep;
	struct enetfec_priv_rx_q *rxq;

	/* find the ethdev entry */
	eth_dev = rte_eth_dev_allocated(rte_vdev_device_name(vdev));
	if (!eth_dev)
		return -ENODEV;
	fep = eth_dev->data->dev_private;
	/* Free descriptor base of first RX queue as it was configured
	 * first in enetfec_eth_init().
	 */
	rxq = fep->rx_queues[0];
	rte_free(rxq->bd.base);
	enet_free_queue(eth_dev);

	enetfec_eth_stop(eth_dev);
	rte_eth_dev_release_port(eth_dev);

	ENET_PMD_INFO("Closing sw device\n");
	munmap(fep->hw_baseaddr, fep->cbus_size);

	return 0;
}

static
struct rte_vdev_driver pmd_enetfec_drv = {
	.probe = pmd_enetfec_probe,
	.remove = pmd_enetfec_remove,
};

RTE_PMD_REGISTER_VDEV(ENETFEC_NAME_PMD, pmd_enetfec_drv);
RTE_PMD_REGISTER_PARAM_STRING(ENETFEC_NAME_PMD, ENET_VDEV_GEM_ID_ARG "=<int>");

RTE_INIT(enetfec_pmd_init_log)
{
	enetfec_logtype_pmd = rte_log_register("pmd.net.enetfec");
	if (enetfec_logtype_pmd >= 0)
		rte_log_set_level(enetfec_logtype_pmd, RTE_LOG_NOTICE);
}

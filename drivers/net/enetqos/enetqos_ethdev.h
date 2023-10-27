/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2023 NXP
 */
#ifndef __ENETQOS_ETHDEV_
#define  __ENETQOS_ETHDEV_

#include <rte_ethdev.h>

#define ENETQOS_NAME_PMD	net_enetqos
#define MTL_MAX_RX_QUEUES	8
#define MTL_MAX_TX_QUEUES	8
#define ENETQOS_MAX_Q		1 //Support for single queue for now

/* RX/TX Queue Mode */
#define MTL_QUEUE_AVB_MODE		0x0
#define MTL_QUEUE_DCB_MODE		0x1
#define ENETQOS_MAX_RX_PKT_LEN		3000

#define SF_DMA_MODE 1 /* DMA STORE-AND-FORWARD Operation Mode */
/* TX and RX Descriptor Length, these need to be power of two.
 * TX descriptor length less than 64 may cause transmit queue timed out error.
 * RX descriptor length less than 64 may cause inconsistent Rx chain error.
 */
#define DMA_MIN_TX_SIZE	64
#define DMA_MAX_TX_SIZE	1024
#define DMA_DEFAULT_TX_SIZE	512
#define DMA_MIN_RX_SIZE	64
#define DMA_MAX_RX_SIZE	1024
#define DMA_DEFAULT_RX_SIZE	512
#define NUM_OF_BD_QUEUES	10
#define DMA_DEFAULT_SIZE	512

#define ENETQOS_CH0		0

#define STMMAC_GET_ENTRY(x, size)	((x + 1) & (size - 1))
#define MAP_PAGE_SIZE			4096

#define lower_32_bits(x)	((uint32_t)((uint64_t)x))
#define upper_32_bits(x)	((uint32_t)(((uint64_t)(x) >> 16) >> 16))

typedef	unsigned long long	dma_addr_t;

#if defined(RTE_ARCH_ARM) && defined(RTE_ARCH_64)
#define dcbf(p) { asm volatile("dc cvac, %0" : : "r"(p) : "memory"); }
#define dcbf_64(p) dcbf(p)
#define dccivac(p) { asm volatile("dc civac, %0" : : "r"(p) : "memory"); }
#else
#define dcbf(p) RTE_SET_USED(p)
#define dcbf_64(p) RTE_SET_USED(p)
#define dccivac(p) RTE_SET_USED(p)
#endif

/* RX Buffer size must be multiple of 4/8/16 bytes */
#define BUF_SIZE_16KiB 16368
#define BUF_SIZE_8KiB 8188
#define BUF_SIZE_4KiB 4096
#define BUF_SIZE_2KiB 2048
#define DEFAULT_BUFSIZE 1536

#define SIZE_2MB 0x200000
#define MTL_QUEUE_BLK 256
#define MTL_FIFO_SIZE 8192
#define FIFO_SIZE_4KiB 4096

#define PBL_VAL 8

/* Basic descriptor structure for normal and alternate descriptors */
struct dma_desc {
	uint32_t des0;
	uint32_t des1;
	uint32_t des2;
	uint32_t des3;
};

struct enetqos_tx_queue {
	struct enetqos_priv	*priv_data;
	uint32_t		queue_index;
	unsigned int	cur_tx;
	unsigned int	dirty_tx;
	struct dma_desc *dma_tx;
	uint32_t		tx_count_frames;
	dma_addr_t	tx_tail_addr;
	dma_addr_t	dma_tx_phy;
	struct rte_mbuf	*tx_mbuf[DMA_DEFAULT_TX_SIZE];
};

struct enetqos_rx_queue {
	struct enetqos_priv *priv_data;
	uint32_t		queue_index;
	unsigned int	cur_rx;
	unsigned int	dirty_rx;
	struct dma_desc	*dma_rx;
	uint32_t		rx_count_frames;
	dma_addr_t	dma_rx_phy;
	dma_addr_t	rx_tail_addr;
	struct rte_mempool *pool;
	struct rte_mbuf	*rx_mbuf[DMA_DEFAULT_RX_SIZE];
	unsigned int	buf_alloc_num;
};

struct enetqos_priv {
	struct rte_eth_dev	*dev;
	struct rte_eth_stats	stats;
	uint16_t		max_rx_queues;
	uint16_t		max_tx_queues;
	unsigned int	total_tx_ring_size;
	unsigned int	total_rx_ring_size;
	unsigned int	reg_size;
	unsigned int	bd_size;
	void		*hw_baseaddr_v;
	void		*bd_addr_v;
	uint32_t		hw_baseaddr_p;
	dma_addr_t	bd_addr_p;
	uint32_t		bd_addr_p_r[ENETQOS_MAX_Q];
	uint32_t		bd_addr_p_t[ENETQOS_MAX_Q];
	void		*dma_baseaddr_r[ENETQOS_MAX_Q];
	void		*dma_baseaddr_t[ENETQOS_MAX_Q];
	/* RX Queue */
	struct enetqos_rx_queue *rx_queue[MTL_MAX_RX_QUEUES];
	unsigned int dma_rx_size;

	/* TX Queue */
	struct enetqos_tx_queue	*tx_queue[MTL_MAX_TX_QUEUES];
	unsigned int dma_tx_size;

	struct enetqos_dma_cfg  *dma_cfg;
	uint32_t		rx_queues_to_use;
	uint32_t		tx_queues_to_use;
	void		*ioaddr;
};

struct enetqos_dma_cfg {
	int pbl;
	int txpbl;
	int rxpbl;
	int fixed_burst;
	int mixed_burst;
	bool pblx8;
	bool aal;
	bool eame;
	bool multi_msi_en;
	bool dche;
};

static
void enetqos_set_rx_tail_ptr(void *ioaddr, uint32_t tail_ptr, uint32_t chan)
{
	rte_write32(tail_ptr,
		(void *)&(ENETQ_DMA_CHX_REGS(ioaddr, chan))->rx_tail_addr);
}

static
void enetqos_set_tx_tail_ptr(void *ioaddr, dma_addr_t tail_ptr, uint32_t chan)
{
	rte_write64(tail_ptr,
		(void *)&(ENETQ_DMA_CHX_REGS(ioaddr, chan))->tx_tail_addr);
}

static
void enetqos_set_addr(struct dma_desc *p, dma_addr_t addr)
{
	rte_write32(rte_cpu_to_le_32(lower_32_bits(addr)), &p->des0);
	rte_write32(rte_cpu_to_le_32(upper_32_bits(addr)), &p->des1);
}

uint16_t enetqos_recv_pkts(void *rxq1, struct rte_mbuf **rx_pkts,
		uint16_t nb_pkts);
uint16_t enetqos_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
		uint16_t nb_pkts);
#endif /*__ENETQOS_ETHDEV_ */

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020-2021 NXP
 */

#ifndef __ENET_ETHDEV_H__
#define __ENET_ETHDEV_H__

#include <compat.h>
#include <rte_ethdev_vdev.h>
#include <rte_ethdev.h>

/* ENET with AVB IP can support maximum 3 rx and tx queues.
 */
#define ENET_MAX_Q	3

#define BD_LEN			49152
#define ENET_TX_FR_SIZE		2048
#define MAX_TX_BD_RING_SIZE		512	/* It should be power of 2 */
#define MAX_RX_BD_RING_SIZE		512

/* full duplex or half duplex */
#define HALF_DUPLEX             0x00
#define FULL_DUPLEX             0x01
#define UNKNOWN_DUPLEX          0xff

#define PKT_MAX_BUF_SIZE        1984
#define OPT_FRAME_SIZE		(PKT_MAX_BUF_SIZE << 16)
#define ETH_ALEN		RTE_ETHER_ADDR_LEN
#define ETH_HLEN		RTE_ETHER_HDR_LEN
#define VLAN_HLEN		4


struct bufdesc {
	uint16_t	bd_datlen;  /* buffer data length */
	uint16_t	bd_sc;	    /* buffer control & status */
	uint32_t	bd_bufaddr; /* buffer address */
};

struct bufdesc_ex {
	struct		bufdesc desc;
	uint32_t	bd_esc;
	uint32_t	bd_prot;
	uint32_t	bd_bdu;
	uint32_t	ts;
	uint16_t	res0[4];
};

struct bufdesc_prop {
	int que_id;
	/* Addresses of Tx and Rx buffers */
	struct bufdesc	*base;
	struct bufdesc	*last;
	struct bufdesc	*cur;
	void __iomem	*active_reg_desc;
	uint64_t	descr_baseaddr_p;
	unsigned short	ring_size;
	unsigned char	d_size;
	unsigned char	d_size_log2;
};

struct enetfec_priv_tx_q {
	struct bufdesc_prop	bd;
	struct rte_mbuf		*tx_mbuf[MAX_TX_BD_RING_SIZE];
	struct bufdesc		*dirty_tx;
	struct rte_mempool	*pool;
	struct enetfec_private	*fep;
};

struct enetfec_priv_rx_q {
	struct bufdesc_prop	bd;
	struct rte_mbuf		*rx_mbuf[MAX_RX_BD_RING_SIZE];
	struct rte_mempool	*pool;
	struct enetfec_private	*fep;
};

/* Buffer descriptors of FEC are used to track the ring buffers. Buffer
 * descriptor base is x_bd_base. Currently available buffer are x_cur
 * and x_cur. where x is rx or tx. Current buffer is tracked by dirty_tx
 * that is sent by the controller.
 * The tx_cur and dirty_tx are same in completely full and empty
 * conditions. Actual condition is determine by empty & ready bits.
 */
struct enetfec_private {
	struct rte_eth_dev	*dev;
	struct rte_eth_stats	stats;
	struct rte_mempool	*pool;

	struct enetfec_priv_rx_q *rx_queues[ENET_MAX_Q];
	struct enetfec_priv_tx_q *tx_queues[ENET_MAX_Q];
	uint16_t	max_rx_queues;
	uint16_t	max_tx_queues;

	unsigned int	total_tx_ring_size;
	unsigned int	total_rx_ring_size;

	bool		bufdesc_ex;
	unsigned int	tx_align;
	unsigned int	rx_align;
	int		full_duplex;
	unsigned int	phy_speed;
	u_int32_t	quirks;
	int		flag_csum;
	int		flag_pause;
	int		flag_wol;
	bool		rgmii_txc_delay;
	bool		rgmii_rxc_delay;
	int		link;
	void		*hw_baseaddr_v;
	uint64_t	hw_baseaddr_p;
	void		*bd_addr_v;
	uint64_t	bd_addr_p;
	uint64_t	bd_addr_p_r[ENET_MAX_Q];
	uint64_t	bd_addr_p_t[ENET_MAX_Q];
	void		*dma_baseaddr_r[ENET_MAX_Q];
	void		*dma_baseaddr_t[ENET_MAX_Q];
	uint64_t	cbus_size;
	unsigned int	reg_size;
	unsigned int	bd_size;
	int		hw_ts_rx_en;
	int		hw_ts_tx_en;
};

#define writel(v, p) ({*(volatile unsigned int *)(p) = (v); })
#define readl(p) rte_read32(p)

static __always_inline
void __read_once_size(volatile void *p, void *res, int size)
{
	switch (size) {
	case 1:
		*(__u8 *)res = *(volatile __u8 *)p;
		break;
	case 2:
		*(__u16 *)res = *(volatile __u16 *)p;
		break;
	case 4:
		*(__u32 *)res = *(volatile __u32 *)p;
		break;
	case 8:
		*(__u64 *)res = *(volatile __u64 *)p;
		break;
	default:
		break;
	}
}

#define __READ_ONCE(x)\
({\
	union { typeof(x) __val; char __c[1]; } __u;\
	 __read_once_size(&(x), __u.__c, sizeof(x));\
	 __u.__val;\
})
#ifndef READ_ONCE
#define READ_ONCE(x) __READ_ONCE(x)
#endif

static inline struct
bufdesc *enet_get_nextdesc(struct bufdesc *bdp,

						struct bufdesc_prop *bd)
{
	return (bdp >= bd->last) ? bd->base
			: (struct bufdesc *)(((void *)bdp) + bd->d_size);
}

static inline struct
bufdesc *enet_get_prevdesc(struct bufdesc *bdp,
						struct bufdesc_prop *bd)
{
	return (bdp <= bd->base) ? bd->last
			: (struct bufdesc *)(((void *)bdp) - bd->d_size);
}

static inline int
enet_get_bd_index(struct bufdesc *bdp,
					struct bufdesc_prop *bd)
{
	return ((const char *)bdp - (const char *)bd->base) >> bd->d_size_log2;
}

static inline phys_addr_t enetfec_mem_vtop(uint64_t vaddr)
{
	const struct rte_memseg *memseg;
	memseg = rte_mem_virt2memseg((void *)(uintptr_t)vaddr, NULL);
	if (memseg)
		return memseg->iova + RTE_PTR_DIFF(vaddr, memseg->addr);
	return (size_t)NULL;
}

static inline int fls64(unsigned long word)
{
	return (64 - __builtin_clzl(word)) - 1;
}

uint16_t enetfec_recv_pkts(void *rxq1, __rte_unused struct rte_mbuf **rx_pkts,
		uint16_t nb_pkts);
uint16_t
enetfec_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts);
struct bufdesc *enet_get_nextdesc(struct bufdesc *bdp,
		struct bufdesc_prop *bd);
int enet_new_rxbdp(struct enetfec_private *fep, struct bufdesc *bdp,
		struct rte_mbuf *mbuf);

#endif /*__FEC_ETHDEV_H__*/

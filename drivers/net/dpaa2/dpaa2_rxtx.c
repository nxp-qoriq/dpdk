/* SPDX-License-Identifier: BSD-3-Clause
 *
 *   Copyright (c) 2016 Freescale Semiconductor, Inc. All rights reserved.
 *   Copyright 2016-2025 NXP
 *
 */

#include <time.h>
#include <net/if.h>

#include <rte_mbuf.h>
#include <ethdev_driver.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_string_fns.h>
#include <dev_driver.h>
#include <rte_hexdump.h>

#include <bus_fslmc_driver.h>
#include <fslmc_vfio.h>
#include <dpaa2_hw_pvt.h>
#include <dpaa2_hw_dpio.h>
#include <dpaa2_hw_mempool.h>
#include <dpaax_ptp.h>

#include "dpaa2_pmd_logs.h"
#include "dpaa2_ethdev.h"
#include "base/dpaa2_hw_dpni_annot.h"
#include "dpaa2_parser_decode.h"

static inline void
dpaa2_dev_rx_annot_prefetch(const struct qbman_fd *fd)
{
	size_t fd_addr;
	void *hw_annot_addr;

	fd_addr = (size_t)DPAA2_IOVA_TO_VADDR(DPAA2_GET_FD_ADDR(fd));
	hw_annot_addr = (void *)(fd_addr + DPAA2_FD_PTA_SIZE);
	rte_prefetch0(hw_annot_addr);
}

static inline void
dpaa2_dev_rx_parse_offset(struct dpaa2_dev_priv *priv,
	struct rte_mbuf *mbuf, const struct qbman_fd *fd)
{
	size_t fd_addr;
	const struct dpaa2_annot_hdr *annotation;
	uint64_t word6;
	struct dpaa2_psr_result_word6 *decoded;
	struct dpaa2_dyn_rx_protocol_pos *pos;

	fd_addr = (size_t)DPAA2_IOVA_TO_VADDR(DPAA2_GET_FD_ADDR(fd));
	annotation = (void *)(fd_addr + DPAA2_FD_PTA_SIZE);

	RTE_ASSERT(priv->psr_dynfield_offset >=
		offsetof(struct rte_mbuf, dynfield1[0]) &&
		priv->psr_dynfield_offset < (sizeof(struct rte_mbuf) -
		sizeof(struct dpaa2_dyn_rx_protocol_pos)));
	pos = (void *)((uint8_t *)mbuf + priv->psr_dynfield_offset);

	word6 = rte_cpu_to_be_64(annotation->word6);
	decoded = (void *)&word6;
	pos->l3_offset = decoded->l3_off;
	pos->l4_offset = decoded->l4_off;
	pos->l5_offset = decoded->l5_off;
}

#define DPAA2_MBUF_TO_CONTIG_FD(_mbuf, _fd, _bpid)  do { \
	DPAA2_SET_FD_ADDR(_fd, DPAA2_MBUF_VADDR_TO_IOVA(_mbuf)); \
	DPAA2_SET_FD_LEN(_fd, _mbuf->data_len); \
	DPAA2_SET_ONLY_FD_BPID(_fd, _bpid); \
	DPAA2_SET_FD_OFFSET(_fd, _mbuf->data_off); \
	DPAA2_SET_FD_FRC(_fd, 0);		\
	DPAA2_RESET_FD_CTRL(_fd);		\
	DPAA2_RESET_FD_FLC(_fd);		\
} while (0)

#define DPAA2_MBUF_TO_CONF_CONTIG_FD(_mbuf, _fd)  do { \
	DPAA2_SET_FD_ADDR(_fd, DPAA2_MBUF_VADDR_TO_IOVA(_mbuf)); \
	DPAA2_SET_FD_LEN(_fd, (_mbuf)->data_len); \
	DPAA2_SET_ONLY_FD_BPID(_fd, MAX_BPID); \
	DPAA2_SET_FD_IVP(_fd); \
	DPAA2_SET_FD_OFFSET(_fd, (_mbuf)->data_off); \
	DPAA2_SET_FD_FRC(_fd, 0); \
	DPAA2_RESET_FD_CTRL(_fd); \
	DPAA2_SET_FD_FLC(_fd, _mbuf); \
} while (0)

static inline void
dpaa2_dev_rx_print_parser_result(struct dpaa2_dev_priv *priv,
	const struct qbman_fd *fd)
{
	size_t fd_addr;
	void *hw_annot_addr;

	if (likely(!(priv->flags & DPAA2_RX_PRINT_PSR_RESULT_FLAG)))
		return;

	if (dpaa2_svr_family == SVR_LX2160A)
		dpaa2_print_fd_frc(fd);

	fd_addr = (size_t)DPAA2_IOVA_TO_VADDR(DPAA2_GET_FD_ADDR(fd));
	hw_annot_addr = (void *)(fd_addr + DPAA2_FD_PTA_SIZE);
	dpaa2_print_parse_result(hw_annot_addr);
}

static inline void
dpaa2_dev_rx_mbuf_sched_set(struct rte_mbuf *m,
	const struct qbman_fd *fd)
{
	uint32_t flc_lo, tc, flow;

	flc_lo = fd->simple.flc_lo;
	if (flc_lo & (1 << DPAA2_FS_FLC_FS_MARK_OFFSET)) {
		m->ol_flags |= RTE_MBUF_F_RX_FDIR;
		tc = (flc_lo >> DPAA2_FS_FLC_TC_OFFSET) &
			DPAA2_FS_FLC_TC_MASK;
		flow = flc_lo >> DPAA2_FS_FLC_FLOW_OFFSET;
		rte_mbuf_sched_set(m, flow, tc, DPAA2_GET_FD_DROPP(fd));
		DPAA2_PMD_DP_DEBUG("FS frame received from TC[%d]->flow%d",
			tc, flow);
	} else {
		m->hash.rss = fd->simple.flc_hi;
		m->ol_flags |= RTE_MBUF_F_RX_RSS_HASH;
		DPAA2_PMD_DP_DEBUG("Hash frame received with RSS(%08x)",
			m->hash.rss);
	}
}

static inline void
dpaa2_dev_rx_read_timestamp(struct dpaa2_dev_priv *priv,
	struct rte_mbuf *m)
{
	struct dpaa2_annot_hdr *annotation;
	rte_mbuf_timestamp_t *ts;

	if (!(priv->flags & DPAA2_IEEE1588_RX_TS_FLAG))
		return;

	annotation = (void *)((uint8_t *)m->buf_addr + DPAA2_FD_PTA_SIZE);
	if (BIT_ISSET_AT_POS(annotation->word1, DPAA2_ETH_FAS_PTP)) {
		m->ol_flags |= RTE_MBUF_F_RX_IEEE1588_PTP;
		m->ol_flags |= RTE_MBUF_F_RX_IEEE1588_TMST;
	}
	ts = RTE_MBUF_DYNFIELD(m, priv->rx_ts_offset, void *);
	*ts = annotation->word2;
	m->ol_flags |= priv->rx_ts_flag;
	__atomic_store_n(&priv->rx_timestamp, *ts, __ATOMIC_RELAXED);
	dpaa2_timestamp_debug(priv, __func__, priv->rx_timestamp);
}

static void __rte_hot
dpaa2_dev_rx_parse_new(struct dpaa2_dev_priv *priv,
	struct rte_mbuf *m, const struct qbman_fd *fd,
	void *hw_annot_addr, int is_vlan)
{
	uint16_t frc = DPAA2_GET_FD_FRC_PARSE_SUM(fd);
	struct dpaa2_annot_hdr *annotation = hw_annot_addr;
	int default_parsed = false, vlan2 = false;

	RTE_SET_USED(priv);

	m->packet_type = RTE_PTYPE_UNKNOWN;
	if (unlikely(is_vlan)) {
		if (frc & DPAA2_PKT_TYPE_VLAN_2)
			vlan2 = true;
		frc &= (~DPAA2_PKT_TYPE_VLAN);
	}
	switch (frc) {
	case DPAA2_PKT_TYPE_IPV4_UDP:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_UDP;
		break;
	case DPAA2_PKT_TYPE_IPV4_TCP:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_TCP;
		break;
	case DPAA2_PKT_TYPE_IPV4:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV4;
		break;
	case DPAA2_PKT_TYPE_IPV6_UDP:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_UDP;
		break;
	case DPAA2_PKT_TYPE_IPV6_TCP:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_TCP;
		break;
	case DPAA2_PKT_TYPE_IPV6:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV6;
		break;
	case DPAA2_PKT_TYPE_IPV4_FRAG:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_FRAG;
		break;
	case DPAA2_PKT_TYPE_IPV6_FRAG:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_FRAG;
		break;
	case DPAA2_PKT_TYPE_IPV4_ESP:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV4 | RTE_PTYPE_TUNNEL_ESP;
		break;
	case DPAA2_PKT_TYPE_IPV6_ESP:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV6 | RTE_PTYPE_TUNNEL_ESP;
		break;
	case DPAA2_PKT_TYPE_IPV4_GTPU:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV4 | RTE_PTYPE_TUNNEL_GTPU;
		break;
	case DPAA2_PKT_TYPE_IPV6_GTPU:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV6 | RTE_PTYPE_TUNNEL_GTPU;
		break;
	case DPAA2_PKT_TYPE_IPV4_GTPC:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV4 | RTE_PTYPE_TUNNEL_GTPC;
		break;
	case DPAA2_PKT_TYPE_IPV6_GTPC:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV6 | RTE_PTYPE_TUNNEL_GTPC;
		break;
	case DPAA2_PKT_TYPE_ETHER:
		m->packet_type = RTE_PTYPE_L2_ETHER;
		break;
	default:
		m->packet_type = dpaa2_dev_rx_parse_frc(fd, m, annotation);
		default_parsed = true;
	}

	if (unlikely(is_vlan && !default_parsed)) {
		struct dpaa2_psr_result_word5 word5;
		rte_be16_t *vlan_tci = NULL;

		m->packet_type |= RTE_PTYPE_L2_ETHER_VLAN;
		m->ol_flags |= RTE_MBUF_F_RX_VLAN;
		*(rte_be64_t *)&word5 = rte_cpu_to_be_64(annotation->word5);
		if (vlan2) {
			vlan_tci = rte_pktmbuf_mtod_offset(m, void *,
				word5.vlan_tci_n_off);
		} else {
			vlan_tci = rte_pktmbuf_mtod_offset(m, void *,
				word5.vlan_tci_1_off);
		}
		m->vlan_tci = rte_be_to_cpu_16(*vlan_tci);
	}

	DPAA2_PMD_DP_DEBUG("HW frc = 0x%x\t packet type =0x%x "
		"ol_flags =0x%" PRIx64 "",
		frc, m->packet_type, m->ol_flags);
}

static inline uint32_t __rte_hot
dpaa2_dev_rx_parse_slow(struct rte_mbuf *mbuf,
	struct dpaa2_annot_hdr *annotation)
{
	uint32_t pkt_type = RTE_PTYPE_UNKNOWN;
	uint16_t *vlan_tci;

	DPAA2_PMD_DP_DEBUG("(slow parse)annotation(3)=0x%" PRIx64 "\t"
			"(4)=0x%" PRIx64 "\t",
			annotation->word3, annotation->word4);

	if (BIT_ISSET_AT_POS(annotation->word3, L2_VLAN_1_PRESENT)) {
		vlan_tci = rte_pktmbuf_mtod_offset(mbuf, uint16_t *,
			(VLAN_TCI_OFFSET_1(annotation->word5) >> 16));
		mbuf->vlan_tci = rte_be_to_cpu_16(*vlan_tci);
		mbuf->ol_flags |= RTE_MBUF_F_RX_VLAN;
		pkt_type |= RTE_PTYPE_L2_ETHER_VLAN;
	} else if (BIT_ISSET_AT_POS(annotation->word3, L2_VLAN_N_PRESENT)) {
		vlan_tci = rte_pktmbuf_mtod_offset(mbuf, uint16_t *,
			(VLAN_TCI_OFFSET_1(annotation->word5) >> 16));
		mbuf->vlan_tci = rte_be_to_cpu_16(*vlan_tci);
		mbuf->ol_flags |= RTE_MBUF_F_RX_VLAN | RTE_MBUF_F_RX_QINQ;
		pkt_type |= RTE_PTYPE_L2_ETHER_QINQ;
	}

	if (BIT_ISSET_AT_POS(annotation->word3, L2_ARP_PRESENT)) {
		pkt_type |= RTE_PTYPE_L2_ETHER_ARP;
		goto parse_done;
	} else if (BIT_ISSET_AT_POS(annotation->word3, L2_ETH_MAC_PRESENT)) {
		pkt_type |= RTE_PTYPE_L2_ETHER;
	} else {
		goto parse_done;
	}

	if (BIT_ISSET_AT_POS(annotation->word3, L2_MPLS_1_PRESENT |
				L2_MPLS_N_PRESENT))
		pkt_type |= RTE_PTYPE_L2_ETHER_MPLS;

	if (BIT_ISSET_AT_POS(annotation->word4, L3_IPV4_1_PRESENT |
			     L3_IPV4_N_PRESENT)) {
		pkt_type |= RTE_PTYPE_L3_IPV4;
		if (BIT_ISSET_AT_POS(annotation->word4, L3_IP_1_OPT_PRESENT |
			L3_IP_N_OPT_PRESENT))
			pkt_type |= RTE_PTYPE_L3_IPV4_EXT;
		if (BIT_ISSET_AT_POS(annotation->word4, L3_PROTO_IPSEC_ESP_PRESENT |
					L3_PROTO_ESP_PRESENT))
			pkt_type |= RTE_PTYPE_TUNNEL_ESP;

	} else if (BIT_ISSET_AT_POS(annotation->word4, L3_IPV6_1_PRESENT |
		  L3_IPV6_N_PRESENT)) {
		pkt_type |= RTE_PTYPE_L3_IPV6;
		if (BIT_ISSET_AT_POS(annotation->word4, L3_IP_1_OPT_PRESENT |
		    L3_IP_N_OPT_PRESENT))
			pkt_type |= RTE_PTYPE_L3_IPV6_EXT;
		if (BIT_ISSET_AT_POS(annotation->word4, L3_PROTO_IPSEC_ESP_PRESENT |
					L3_PROTO_ESP_PRESENT))
			pkt_type |= RTE_PTYPE_TUNNEL_ESP;
	} else {
		goto parse_done;
	}

	if (BIT_ISSET_AT_POS(annotation->word1, DPAA2_ETH_FAS_L3CE))
		mbuf->ol_flags |= RTE_MBUF_F_RX_IP_CKSUM_BAD;
	else if (BIT_ISSET_AT_POS(annotation->word1, DPAA2_ETH_FAS_L4CE))
		mbuf->ol_flags |= RTE_MBUF_F_RX_L4_CKSUM_BAD;

	if (BIT_ISSET_AT_POS(annotation->word4, L3_IP_1_FIRST_FRAGMENT |
	    L3_IP_1_MORE_FRAGMENT |
	    L3_IP_N_FIRST_FRAGMENT |
	    L3_IP_N_MORE_FRAGMENT)) {
		pkt_type |= RTE_PTYPE_L4_FRAG;
		goto parse_done;
	} else {
		pkt_type |= RTE_PTYPE_L4_NONFRAG;
	}

	if (BIT_ISSET_AT_POS(annotation->word4, L3_PROTO_UDP_PRESENT))
		pkt_type |= RTE_PTYPE_L4_UDP;

	else if (BIT_ISSET_AT_POS(annotation->word4, L3_PROTO_TCP_PRESENT))
		pkt_type |= RTE_PTYPE_L4_TCP;

	else if (BIT_ISSET_AT_POS(annotation->word4, L3_PROTO_SCTP_PRESENT))
		pkt_type |= RTE_PTYPE_L4_SCTP;

	else if (BIT_ISSET_AT_POS(annotation->word4, L3_PROTO_ICMP_PRESENT))
		pkt_type |= RTE_PTYPE_L4_ICMP;

	else if (BIT_ISSET_AT_POS(annotation->word4, L3_IP_UNKNOWN_PROTOCOL))
		pkt_type |= RTE_PTYPE_UNKNOWN;

parse_done:
	return pkt_type;
}

static inline uint32_t __rte_hot
dpaa2_dev_rx_parse(struct dpaa2_dev_priv *priv,
	struct rte_mbuf *mbuf, void *hw_annot_addr)
{
	struct dpaa2_annot_hdr *annotation = hw_annot_addr;

	DPAA2_PMD_DP_DEBUG("(fast parse) Annotation = 0x%" PRIx64 "\t",
		annotation->word4);

	RTE_SET_USED(priv);

	/* Check detailed parsing requirement */
	if (unlikely(annotation->word3 & 0x7FFFFC3FFFF))
		return dpaa2_dev_rx_parse_slow(mbuf, annotation);

	/* Return some common types from parse processing */
	switch (annotation->word4) {
	case DPAA2_L3_IPv4:
		return RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4;
	case DPAA2_L3_IPv6:
		return  RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6;
	case DPAA2_L3_IPv4_TCP:
		return  RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4 |
				RTE_PTYPE_L4_TCP;
	case DPAA2_L3_IPv4_UDP:
		return  RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4 |
				RTE_PTYPE_L4_UDP;
	case DPAA2_L3_IPv6_TCP:
		return  RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6 |
				RTE_PTYPE_L4_TCP;
	case DPAA2_L3_IPv6_UDP:
		return  RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6 |
				RTE_PTYPE_L4_UDP;
	default:
		break;
	}

	return dpaa2_dev_rx_parse_slow(mbuf, annotation);
}

int
rte_pmd_dpaa2_rx_get_offset(uint16_t port_id, struct rte_mbuf *m,
	uint8_t *l3_off, uint8_t *l4_off, uint8_t *l5_off)
{
	struct rte_eth_dev *dev;
	struct dpaa2_dyn_rx_protocol_pos *pos;
	struct dpaa2_dev_priv *priv;

	if (port_id >= RTE_MAX_ETHPORTS)
		port_id = m->port;

	if (unlikely(!rte_pmd_dpaa2_dev_is_dpaa2(port_id)))
		return -EINVAL;

	dev = &rte_eth_devices[port_id];
	if (!dev->data)
		return -EINVAL;

	if (!dev->data->dev_private)
		return -EINVAL;

	priv = dev->data->dev_private;
	if (unlikely(priv->psr_dynfield_offset < 0)) {
		DPAA2_PMD_ERR("%s: Not register for RX protocol pos.\n",
			__func__);

		return -EINVAL;
	}
	pos = (void *)((uint8_t *)m + priv->psr_dynfield_offset);

	if (l3_off)
		*l3_off = pos->l3_offset;
	if (l4_off)
		*l4_off = pos->l4_offset;
	if (l5_off)
		*l5_off = pos->l5_offset;

	return 0;
}

struct rte_mbuf *__rte_hot
eth_sg_fd_to_mbuf(struct dpaa2_dev_priv *priv, const struct qbman_fd *fd)
{
	struct qbman_sge *sgt, *sge;
	size_t fd_addr;
	int i = 0;
	void *hw_annot_addr, *sg_addr;
	struct rte_mbuf *first_seg, *next_seg, *cur_seg, *temp;

	fd_addr = (size_t)DPAA2_IOVA_TO_VADDR(DPAA2_GET_FD_ADDR(fd));
	hw_annot_addr = (void *)(fd_addr + DPAA2_FD_PTA_SIZE);

	/* Get Scatter gather table address */
	sgt = (struct qbman_sge *)(fd_addr + DPAA2_GET_FD_OFFSET(fd));

	sge = &sgt[i++];
	sg_addr = DPAA2_IOVA_TO_VADDR(DPAA2_GET_FLE_ADDR(sge));

	/* First Scatter gather entry */
	first_seg = DPAA2_INLINE_MBUF_FROM_BUF(sg_addr,
		rte_dpaa2_bpid_info[DPAA2_GET_FD_BPID(fd)].meta_data_size);
	/* Prepare all the metadata for first segment */
	first_seg->buf_addr = sg_addr;
	first_seg->ol_flags = 0;
	first_seg->data_off = DPAA2_GET_FLE_OFFSET(sge);
	first_seg->data_len = sge->length  & 0x1FFFF;
	first_seg->pkt_len = DPAA2_GET_FD_LEN(fd);
	first_seg->nb_segs = 1;
	first_seg->next = NULL;
	first_seg->port = priv->eth_dev->data->port_id;
	if (dpaa2_svr_family == SVR_LX2160A) {
		dpaa2_dev_rx_parse_new(priv, first_seg, fd, hw_annot_addr, false);
	} else {
		first_seg->packet_type = dpaa2_dev_rx_parse(priv, first_seg,
			hw_annot_addr);
	}
	dpaa2_dev_rx_mbuf_sched_set(first_seg, fd);

	rte_mbuf_refcnt_set(first_seg, 1);
#ifdef RTE_LIBRTE_MEMPOOL_DEBUG
	rte_mempool_check_cookies(rte_mempool_from_obj((void *)first_seg),
		(void **)&first_seg, 1, 1);
#endif
	cur_seg = first_seg;
	while (!DPAA2_SG_IS_FINAL(sge)) {
		sge = &sgt[i++];
		sg_addr = DPAA2_IOVA_TO_VADDR(DPAA2_GET_FLE_ADDR(sge));
		next_seg = DPAA2_INLINE_MBUF_FROM_BUF(sg_addr,
			rte_dpaa2_bpid_info[DPAA2_GET_FLE_BPID(sge)].meta_data_size);
		next_seg->buf_addr = sg_addr;
		next_seg->data_off = DPAA2_GET_FLE_OFFSET(sge);
		next_seg->data_len = sge->length & 0x1FFFF;
		first_seg->nb_segs += 1;
		rte_mbuf_refcnt_set(next_seg, 1);
#ifdef RTE_LIBRTE_MEMPOOL_DEBUG
		rte_mempool_check_cookies(rte_mempool_from_obj((void *)next_seg),
			(void **)&next_seg, 1, 1);
#endif
		cur_seg->next = next_seg;
		next_seg->next = NULL;
		cur_seg = next_seg;
	}
	temp = DPAA2_INLINE_MBUF_FROM_BUF(fd_addr,
		rte_dpaa2_bpid_info[DPAA2_GET_FD_BPID(fd)].meta_data_size);
	rte_mbuf_refcnt_set(temp, 1);
#ifdef RTE_LIBRTE_MEMPOOL_DEBUG
	rte_mempool_check_cookies(rte_mempool_from_obj((void *)temp),
		(void **)&temp, 1, 1);
#endif
	rte_pktmbuf_free_seg(temp);

	return (void *)first_seg;
}

struct rte_mbuf *__rte_hot
eth_fd_to_mbuf(struct dpaa2_dev_priv *priv, const struct qbman_fd *fd)
{
	uint8_t *v_addr = DPAA2_IOVA_TO_VADDR(DPAA2_GET_FD_ADDR(fd));
	void *hw_annot_addr = v_addr + DPAA2_FD_PTA_SIZE;
	struct rte_mbuf *mbuf = DPAA2_INLINE_MBUF_FROM_BUF(v_addr,
		rte_dpaa2_bpid_info[DPAA2_GET_FD_BPID(fd)].meta_data_size);
	int is_vlan = false;

	if (unlikely(dpaa2_svr_family == SVR_LX2160A &&
		(DPAA2_GET_FD_FRC_PARSE_SUM(fd) &
		DPAA2_PKT_TYPE_VLAN))) {
		mbuf->data_off = DPAA2_GET_FD_OFFSET(fd);
		rte_prefetch0(rte_pktmbuf_mtod(mbuf, void *));
		rte_prefetch0(hw_annot_addr);
		is_vlan = true;
	}

	/* need to repopulated some of the fields,
	 * as they may have changed in last transmission
	 */
	mbuf->nb_segs = 1;
	mbuf->ol_flags = 0;
	mbuf->data_off = DPAA2_GET_FD_OFFSET(fd);
	mbuf->data_len = DPAA2_GET_FD_LEN(fd);
	mbuf->pkt_len = mbuf->data_len;
	mbuf->port = priv->eth_dev->data->port_id;
	mbuf->next = NULL;
	rte_mbuf_refcnt_set(mbuf, 1);
#ifdef RTE_LIBRTE_MEMPOOL_DEBUG
	rte_mempool_check_cookies(rte_mempool_from_obj((void *)mbuf),
		(void **)&mbuf, 1, 1);
#endif

	/* Parse the packet */
	/* parse results for LX2 are there in FRC field of FD.
	 * For other DPAA2 platforms , parse results are after
	 * the private - sw annotation area
	 */

	if (dpaa2_svr_family == SVR_LX2160A)
		dpaa2_dev_rx_parse_new(priv, mbuf, fd, hw_annot_addr, is_vlan);
	else
		mbuf->packet_type = dpaa2_dev_rx_parse(priv, mbuf, hw_annot_addr);
	dpaa2_dev_rx_mbuf_sched_set(mbuf, fd);

	DPAA2_PMD_DP_DEBUG("to mbuf - mbuf =%p, mbuf->buf_addr =%p, off = %d,"
		"fd_off=%d fd =%" PRIx64 ", meta = %d  bpid =%d, len=%d",
		mbuf, mbuf->buf_addr, mbuf->data_off,
		DPAA2_GET_FD_OFFSET(fd), DPAA2_GET_FD_ADDR(fd),
		rte_dpaa2_bpid_info[DPAA2_GET_FD_BPID(fd)].meta_data_size,
		DPAA2_GET_FD_BPID(fd), DPAA2_GET_FD_LEN(fd));

	return mbuf;
}

static void dpaa2_dev_tx_enable_tstamp(struct qbman_fd *fd)
{
	struct dpaa2_faead *fd_faead;
	void *fd_va = DPAA2_IOVA_TO_VADDR(DPAA2_GET_FD_ADDR(fd));

	/* Set frame annotation status field as valid */
	(fd)->simple.frc |= DPAA2_FD_FRC_FASV;

	/* Set frame annotation egress action descriptor as valid */
	(fd)->simple.frc |= DPAA2_FD_FRC_FAEADV;

	/* Set Annotation Length as 128B */
	(fd)->simple.ctrl |= DPAA2_FD_CTRL_ASAL;

	/* enable update of confirmation frame annotation */
	fd_faead = (void *)((size_t)fd_va +
		DPAA2_FD_PTA_SIZE + DPAA2_FD_HW_ANNOT_FAEAD_OFFSET);
	fd_faead->ctrl |= (DPAA2_ANNOT_FAEAD_A2V |
		DPAA2_ANNOT_FAEAD_UPDV | DPAA2_ANNOT_FAEAD_UPD);
}

static inline struct rte_mbuf *
dpaa2_dev_mbuf_copy_one_seg(const struct rte_mbuf *sgm, struct rte_mempool *mp)
{
	struct rte_mbuf *mc = rte_pktmbuf_alloc(mp);

	if (!mc)
		return NULL;
	if ((mc->data_off + sgm->data_len) > mc->buf_len) {
		rte_pktmbuf_free(mc);
		return NULL;
	}
	rte_memcpy(rte_pktmbuf_mtod(mc, void *),
		rte_pktmbuf_mtod(sgm, void *), sgm->data_len);
	mc->pkt_len = sgm->data_len;
	mc->data_len = sgm->data_len;
	mc->next = NULL;

	return mc;
}

static inline void
dpaa2_dev_tx_config_dynamic_confirm(struct qbman_fd *fd,
	struct dpaa2_queue *txq, int enable, int tstamp)
{
	struct dpaa2_faead *fd_faead;
	void *fd_va = DPAA2_IOVA_TO_VADDR(DPAA2_GET_FD_ADDR(fd));

	if (tstamp) {
		DPAA2_SET_FD_FRC(fd,
			DPAA2_GET_FD_FRC(fd) |
			DPAA2_FD_FRC_FAEADV | DPAA2_FD_FRC_FASV);
		fd->simple.ctrl |= DPAA2_FD_CTRL_ASAL;
	} else {
		DPAA2_SET_FD_FRC(fd, DPAA2_GET_FD_FRC(fd) |
			DPAA2_FD_FRC_FAEADV);
	}
	/* enable update of confirmation frame annotation */
	fd_faead = (void *)((size_t)fd_va +
			DPAA2_FD_PTA_SIZE + DPAA2_FD_HW_ANNOT_FAEAD_OFFSET);
	if (enable) {
		fd_faead->fqid = txq->tx_conf_queue->fqid;
		fd_faead->ctrl = DPAA2_TX_CONFIRM_ENABLE;
		if (tstamp) {
			fd_faead->ctrl |= (DPAA2_ANNOT_FAEAD_A2V |
				DPAA2_ANNOT_FAEAD_UPDV |
				DPAA2_ANNOT_FAEAD_UPD);
		}
	} else {
		fd_faead->fqid = 0;
		fd_faead->ctrl &= (~DPAA2_TX_CONFIRM_ENABLE);
	}
}

static int
dpaa2_dev_tx_no_conf_mbuf_to_sge(struct qbman_sge *sgt,
	struct rte_mbuf *mbuf, uint16_t nb_segs, struct rte_mbuf *sg_mbuf,
	struct rte_mempool *hw_mp)
{
	int i;
	struct qbman_sge *sge = NULL;
	struct rte_mbuf *cur_seg, *mi, *prev, *copy_mbuf;

	cur_seg = mbuf;
	prev = NULL;
	for (i = 0; i < nb_segs; i++) {
		sge = &sgt[i];
		/*Resetting the buffer pool id and offset field*/
		sge->fin_bpid_offset = 0;
		if (unlikely(RTE_MBUF_CLONED(cur_seg))) {
			copy_mbuf = dpaa2_dev_mbuf_copy_one_seg(cur_seg, hw_mp);
			if (!copy_mbuf)
				return -ENOMEM;
			mi = rte_mbuf_from_indirect(cur_seg);
			if (rte_mbuf_refcnt_read(mi) > 1)
				rte_mbuf_refcnt_update(mi, -1);
			else
				rte_pktmbuf_free_seg(mi);
			copy_mbuf->next = cur_seg->next;
			if (prev)
				prev->next = copy_mbuf;
			rte_pktmbuf_init(cur_seg->pool, NULL, cur_seg, 0);
			rte_pktmbuf_free_seg(cur_seg);
			cur_seg = copy_mbuf;
		}
		if (unlikely(RTE_MBUF_HAS_EXTBUF(cur_seg) ||
			cur_seg->pool->ops_index != hw_mp->ops_index)) {
			copy_mbuf = dpaa2_dev_mbuf_copy_one_seg(cur_seg, hw_mp);
			if (!copy_mbuf)
				return -ENOMEM;

			copy_mbuf->next = cur_seg->next;

			if (prev)
				prev->next = copy_mbuf;
			if (rte_mbuf_refcnt_read(cur_seg) > 1)
				rte_mbuf_refcnt_update(cur_seg, -1);
			else
				rte_pktmbuf_free_seg(cur_seg);
			cur_seg = copy_mbuf;
		}
		DPAA2_SET_FLE_ADDR(sge, DPAA2_MBUF_VADDR_TO_IOVA(cur_seg));
		DPAA2_SET_FLE_OFFSET(sge, cur_seg->data_off);
		DPAA2_SET_FLE_LEN(sge, cur_seg->data_len);
		if (unlikely(rte_mbuf_refcnt_read(cur_seg) > 1)) {
			DPAA2_SET_FLE_BPID(sge, MAX_BPID);
			DPAA2_SET_FLE_IVP(sge);
			rte_mbuf_refcnt_update(cur_seg, -1);
		} else {
			DPAA2_SET_FLE_BPID(sge, mempool_to_bpid(cur_seg->pool));
		}
		if (sg_mbuf == cur_seg)
			DPAA2_SG_SET_FORMAT(sge, qbman_fd_list);
		prev = cur_seg;
		cur_seg = cur_seg->next;
	}

	if (likely(sge))
		DPAA2_SG_SET_FINAL(sge, true);

	return 0;
}

static void
dpaa2_dev_tx_conf_mbuf_to_sge(struct qbman_sge *sgt,
	struct rte_mbuf *mbuf, uint16_t nb_segs, struct rte_mbuf *sg_mbuf)
{
	int i;
	struct qbman_sge *sge = NULL;
	struct rte_mbuf *cur_seg = mbuf, *mi, *prev;

	prev = NULL;
	for (i = 0; i < nb_segs; i++) {
		sge = &sgt[i];
		/*Resetting the buffer pool id and offset field*/
		sge->fin_bpid_offset = 0;
		if (unlikely(RTE_MBUF_CLONED(cur_seg))) {
			mi = rte_mbuf_from_indirect(cur_seg);
			mi->next = cur_seg->next;
			if (prev)
				prev->next = mi;
			rte_pktmbuf_init(cur_seg->pool, NULL, cur_seg, 0);
			rte_pktmbuf_free_seg(cur_seg);
			cur_seg = mi;
		}
		DPAA2_SET_FLE_ADDR(sge, DPAA2_MBUF_VADDR_TO_IOVA(cur_seg));
		DPAA2_SET_FLE_OFFSET(sge, cur_seg->data_off);
		DPAA2_SET_FLE_LEN(sge, cur_seg->data_len);
		DPAA2_SET_FLE_BPID(sge, MAX_BPID);
		DPAA2_SET_FLE_IVP(sge);
		if (sg_mbuf == cur_seg)
			DPAA2_SG_SET_FORMAT(sge, qbman_fd_list);
		prev = cur_seg;
		cur_seg = cur_seg->next;
	}

	if (likely(sge))
		DPAA2_SG_SET_FINAL(sge, true);
}

static int __rte_noinline __rte_hot
dpaa2_dev_tx_mbuf_to_sg_fd(struct rte_mempool *hw_mp,
	struct rte_mbuf *mbuf, struct qbman_fd *fd,
	struct dpaa2_queue *txq, enum dpaa2_tx_conf_type conf,
	uint8_t *dy_conf, int tstamp)
{
	struct rte_mbuf *cur_seg = mbuf, *sg_mbuf;
	struct qbman_sge *sgt;
	int offset = 0, ret, need_dyconf = false, need_conf = false;
	uint16_t nb_segs = mbuf->nb_segs;
	uint32_t sg_size = nb_segs * sizeof(struct qbman_sge);
	struct rte_mempool *mp;
	struct dpaa2_dev_priv *priv = txq->eth_data->dev_private;

	if (conf == DPAA2_TX_DYNAMIC_CONF) {
		while (cur_seg) {
			if (!RTE_MBUF_DIRECT(cur_seg) ||
				cur_seg->pool->ops_index != hw_mp->ops_index ||
				rte_mbuf_refcnt_read(cur_seg) > 1 || tstamp) {
				need_dyconf = true;
				break;
			}
			cur_seg = cur_seg->next;
		}
		cur_seg = mbuf;
	}
	if (need_dyconf || conf == DPAA2_TX_ABSOLUTE_CONF)
		need_conf = true;

	if (need_dyconf || tstamp)
		offset = DPAA2_FD_PTA_SIZE + DPAA2_DYN_TX_MIN_FD_OFFSET;

	if (mbuf->pool->ops_index == hw_mp->ops_index &&
		RTE_MBUF_DIRECT(mbuf) &&
		(mbuf->data_off > RTE_ALIGN(sg_size + offset, 8))) {
		sg_mbuf = mbuf;
		mp = mbuf->pool;
		if (need_conf) {
			DPAA2_SET_ONLY_FD_BPID(fd, MAX_BPID);
			DPAA2_SET_FD_IVP(fd);
		} else {
			if (unlikely(rte_mbuf_refcnt_read(sg_mbuf) > 1)) {
				DPAA2_SET_ONLY_FD_BPID(fd, MAX_BPID);
				DPAA2_SET_FD_IVP(fd);
				rte_mbuf_refcnt_update(sg_mbuf, -1);
			} else {
				DPAA2_SET_ONLY_FD_BPID(fd, mempool_to_bpid(mp));
			}
		}
#ifdef RTE_LIBRTE_MEMPOOL_DEBUG
		rte_mempool_check_cookies(rte_mempool_from_obj(sg_mbuf),
			(void **)&sg_mbuf, 1, 0);
#endif
		DPAA2_SET_FD_OFFSET(fd, offset);
	} else {
		sg_mbuf = NULL;
		if (priv->tx_sg_pool)
			sg_mbuf = rte_pktmbuf_alloc(priv->tx_sg_pool);
		if (!sg_mbuf) {
			DPAA2_PMD_DP_DEBUG("No memory to allocate S/G table");
			return -ENOMEM;
		}
		if (need_conf) {
			if (need_dyconf)
				sg_mbuf->data_off = RTE_ALIGN(offset, 8);
			else
				sg_mbuf->data_off = RTE_PKTMBUF_HEADROOM;
			DPAA2_SET_ONLY_FD_BPID(fd, MAX_BPID);
			DPAA2_SET_FD_IVP(fd);
		} else {
			DPAA2_SET_ONLY_FD_BPID(fd, mempool_to_bpid(priv->tx_sg_pool));
		}
		DPAA2_SET_FD_OFFSET(fd, sg_mbuf->data_off);
		offset = sg_mbuf->data_off;
#ifdef RTE_LIBRTE_MEMPOOL_DEBUG
		rte_mempool_check_cookies(rte_mempool_from_obj(sg_mbuf),
			(void **)&sg_mbuf, 1, 0);
#endif
	}

	/*Set Scatter gather table and Scatter gather entries*/
	sgt = (void *)((size_t)sg_mbuf->buf_addr + offset);
	DPAA2_SET_FD_ADDR(fd, DPAA2_MBUF_VADDR_TO_IOVA(sg_mbuf));
	DPAA2_SET_FD_LEN(fd, mbuf->pkt_len);
	DPAA2_FD_SET_FORMAT(fd, qbman_fd_sg);
	DPAA2_RESET_FD_FRC(fd);
	DPAA2_RESET_FD_CTRL(fd);
	if (need_conf)
		DPAA2_SET_FD_FLC(fd, sg_mbuf);
	else
		DPAA2_RESET_FD_FLC(fd);
	if (need_dyconf)
		dpaa2_dev_tx_config_dynamic_confirm(fd, txq, true, tstamp);
	else if (tstamp)
		dpaa2_dev_tx_enable_tstamp(fd);

	if (cur_seg != sg_mbuf && need_conf)
		sg_mbuf->next = cur_seg;

	if (need_conf) {
		dpaa2_dev_tx_conf_mbuf_to_sge(sgt, cur_seg, nb_segs, sg_mbuf);
	} else {
		ret = dpaa2_dev_tx_no_conf_mbuf_to_sge(sgt, cur_seg, nb_segs,
			sg_mbuf, hw_mp);
		if (ret)
			return ret;
	}
	if (dy_conf && need_dyconf)
		*dy_conf = true;

	return 0;
}

static inline void
dpaa2_dev_prefetch_next_psr(const struct qbman_result *dq)
{
	const struct qbman_fd *fd;
	const struct dpaa2_annot_hdr *annotation;
	uint64_t annot_iova;

	dq++;

	fd = qbman_result_DQ_fd(dq);
	annot_iova = DPAA2_GET_FD_ADDR(fd) + DPAA2_FD_PTA_SIZE;
	annotation = DPAA2_IOVA_TO_VADDR(annot_iova);

	/** Prefetch from word3 to parse next header.*/
	rte_prefetch0(&annotation->word3);
}

static int __rte_noinline __rte_hot
dpaa2_dev_tx_mbuf_to_simple_fd(struct rte_mempool *hw_mp,
	struct rte_mbuf *mbuf, struct qbman_fd *fd,
	struct dpaa2_queue *txq, enum dpaa2_tx_conf_type conf,
	uint8_t *dy_conf, int tstamp)
{
	int need_dyconf = false, need_conf = false;
	struct rte_mbuf *mi;
	struct rte_mbuf *copy_mbuf;
	int ret = 0;

	if (unlikely(RTE_MBUF_CLONED(mbuf))) {
		mi = rte_mbuf_from_indirect(mbuf);
		if (rte_mbuf_refcnt_read(mbuf) > 1) {
			rte_mbuf_refcnt_update(mbuf, -1);
		} else {
			rte_pktmbuf_init(mbuf->pool, NULL, mbuf, 0);
			rte_pktmbuf_free(mbuf);
		}
		mbuf = mi;
	}
	if (conf == DPAA2_TX_DYNAMIC_CONF &&
		(mbuf->pool->ops_index != hw_mp->ops_index ||
		RTE_MBUF_HAS_EXTBUF(mbuf) ||
		rte_mbuf_refcnt_read(mbuf) > 1 || tstamp))
		need_dyconf = true;
	if (conf == DPAA2_TX_ABSOLUTE_CONF || need_dyconf)
		need_conf = true;

	if (need_conf) {
		DPAA2_MBUF_TO_CONF_CONTIG_FD(mbuf, fd);
	} else if (mbuf->pool->ops_index == hw_mp->ops_index) {
		DPAA2_MBUF_TO_CONTIG_FD(mbuf, fd, mempool_to_bpid(mbuf->pool));
	} else {
		copy_mbuf = dpaa2_dev_mbuf_copy_one_seg(mbuf, hw_mp);
		if (!copy_mbuf) {
			ret = -ENOMEM;
			goto quit;
		}
		DPAA2_MBUF_TO_CONTIG_FD(copy_mbuf, fd, mempool_to_bpid(hw_mp));
quit:
		rte_pktmbuf_free(mbuf);
	}

	if (need_dyconf) {
		dpaa2_dev_tx_config_dynamic_confirm(fd, txq, true, tstamp);
		if (dy_conf)
			*dy_conf = true;
	} else if (tstamp) {
		dpaa2_dev_tx_enable_tstamp(fd);
	}

	return ret;
}

static void
dump_err_pkts(struct dpaa2_queue *dpaa2_q)
{
	/* Function receive frames for a given device and VQ */
	struct qbman_result *dq_storage;
	uint32_t fqid = dpaa2_q->fqid;
	int ret, num_rx = 0;
	uint8_t pending, status;
	struct qbman_swp *swp;
	const struct qbman_fd *fd;
	struct qbman_pull_desc pulldesc;
	struct rte_eth_dev_data *eth_data = dpaa2_q->eth_data;
	uint32_t lcore_id = rte_lcore_id(), i = 0;
	void *v_addr, *hw_annot_addr;
	struct dpaa2_fas *fas;
	struct rte_mbuf *mbuf;
	char title[32];
	struct dpaa2_dev_priv *priv = eth_data->dev_private;

	if (unlikely(!DPAA2_PER_LCORE_DPIO)) {
		ret = dpaa2_affine_qbman_swp();
		if (ret) {
			DPAA2_PMD_ERR("Failed to allocate IO portal, tid: %d",
				rte_gettid());
			return;
		}
	}
	swp = DPAA2_PER_LCORE_PORTAL;

	dq_storage = dpaa2_q->q_storage[lcore_id]->dq_storage[0];
	qbman_pull_desc_clear(&pulldesc);
	qbman_pull_desc_set_fq(&pulldesc, fqid);
	qbman_pull_desc_set_storage(&pulldesc, dq_storage,
			(size_t)(DPAA2_VADDR_TO_IOVA(dq_storage)), 1);
	qbman_pull_desc_set_numframes(&pulldesc, dpaa2_dqrr_size);

	while (1) {
		if (qbman_swp_pull(swp, &pulldesc)) {
			DPAA2_PMD_DP_DEBUG("VDQ command is not issued.QBMAN is busy");
			/* Portal was busy, try again */
			continue;
		}
		break;
	}

	/* Check if the previous issued command is completed. */
	while (!qbman_check_command_complete(dq_storage))
		;

	pending = 1;
	do {
		/* Loop until the dq_storage is updated with
		 * new token by QBMAN
		 */
		while (!qbman_check_new_result(dq_storage))
			;

		/* Check whether Last Pull command is Expired and
		 * setting Condition for Loop termination
		 */
		if (qbman_result_DQ_is_pull_complete(dq_storage)) {
			pending = 0;
			/* Check for valid frame. */
			status = qbman_result_DQ_flags(dq_storage);
			if (unlikely((status &
				QBMAN_DQ_STAT_VALIDFRAME) == 0))
				continue;
		}
		fd = qbman_result_DQ_fd(dq_storage);
		v_addr = DPAA2_IOVA_TO_VADDR(DPAA2_GET_FD_ADDR(fd));
		hw_annot_addr = (void *)((size_t)v_addr + DPAA2_FD_PTA_SIZE);
		fas = hw_annot_addr;

		dpaa2_dev_rx_print_parser_result(priv, fd);

		if (priv->psr_dynfield_offset >= 0)
			dpaa2_dev_rx_annot_prefetch(fd);
		if (DPAA2_FD_GET_FORMAT(fd) == qbman_fd_sg)
			mbuf = eth_sg_fd_to_mbuf(priv, fd);
		else
			mbuf = eth_fd_to_mbuf(priv, fd);
		if (priv->psr_dynfield_offset >= 0)
			dpaa2_dev_rx_parse_offset(priv, mbuf, fd);

		dpaa2_dev_rx_read_timestamp(priv, mbuf);

		DPAA2_PMD_ERR("Err pkt on port[%d]:", eth_data->port_id);
		DPAA2_PMD_ERR("FD offset: %d, FD err: %x, FAS status: %x",
			DPAA2_GET_FD_OFFSET(fd), DPAA2_GET_FD_ERR(fd),
			fas->status);

		if (mbuf)
			__rte_mbuf_sanity_check(mbuf, 1);
		if (mbuf->nb_segs > 1) {
			while (mbuf) {
				sprintf(title, "Payload seg[%d]", i);
				rte_hexdump(stderr, title,
					(char *)mbuf->buf_addr + mbuf->data_off,
					mbuf->data_len);
				mbuf = mbuf->next;
				i++;
			}
		} else {
			rte_hexdump(stderr, "Payload",
				(char *)mbuf->buf_addr + mbuf->data_off,
				mbuf->data_len);
		}

		rte_pktmbuf_free(mbuf);
		dq_storage++;
		num_rx++;
	} while (pending);

	dpaa2_q->err_pkts += num_rx;
}

/* This function assumes that caller will be keep the same value for nb_pkts
 * across calls per queue, if that is not the case, better use non-prefetch
 * version of rx call.
 * It will return the packets as requested in previous call without honoring
 * the current nb_pkts or bufs space.
 */
uint16_t
dpaa2_dev_prefetch_rx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	/* Function receive frames for a given device and VQ*/
	struct dpaa2_queue *dpaa2_q = queue;
	struct qbman_result *dq_storage, *dq_storage1 = NULL;
	uint32_t fqid = dpaa2_q->fqid;
	int ret, num_rx = 0, pull_size;
	uint8_t pending, status;
	struct qbman_swp *swp;
	const struct qbman_fd *fd;
	struct qbman_pull_desc pulldesc;
	struct queue_storage_info_t *q_storage;
	struct rte_eth_dev_data *eth_data = dpaa2_q->eth_data;
	struct dpaa2_dev_priv *priv = eth_data->dev_private;

	q_storage = dpaa2_q->q_storage[rte_lcore_id()];

	if (unlikely(priv->flags & DPAA2_RX_ERROR_QUEUE_FLAG))
		dump_err_pkts(priv->rx_err_vq);

	if (unlikely(!DPAA2_PER_LCORE_ETHRX_DPIO)) {
		ret = dpaa2_affine_qbman_ethrx_swp();
		if (ret) {
			DPAA2_PMD_ERR("Failure in affining portal");
			return 0;
		}
	}

	if (unlikely(!rte_dpaa2_bpid_info &&
		     rte_eal_process_type() == RTE_PROC_SECONDARY))
		rte_dpaa2_bpid_info = dpaa2_q->bp_array;

	swp = DPAA2_PER_LCORE_ETHRX_PORTAL;
	pull_size = (nb_pkts > dpaa2_dqrr_size) ? dpaa2_dqrr_size : nb_pkts;
	if (unlikely(!q_storage->active_dqs)) {
		q_storage->toggle = 0;
		dq_storage = q_storage->dq_storage[q_storage->toggle];
		q_storage->last_num_pkts = pull_size;
		qbman_pull_desc_clear(&pulldesc);
		qbman_pull_desc_set_numframes(&pulldesc,
					      q_storage->last_num_pkts);
		qbman_pull_desc_set_fq(&pulldesc, fqid);
		qbman_pull_desc_set_storage(&pulldesc, dq_storage,
			(uint64_t)(DPAA2_VADDR_TO_IOVA(dq_storage)), 1);
		if (check_swp_active_dqs(DPAA2_PER_LCORE_ETHRX_DPIO->index)) {
			while (!qbman_check_command_complete(
			       get_swp_active_dqs(
			       DPAA2_PER_LCORE_ETHRX_DPIO->index)))
				;
			clear_swp_active_dqs(DPAA2_PER_LCORE_ETHRX_DPIO->index);
		}
		while (1) {
			if (qbman_swp_pull(swp, &pulldesc)) {
				DPAA2_PMD_DP_DEBUG("VDQ command is not issued."
						  " QBMAN is busy (1)");
				/* Portal was busy, try again */
				continue;
			}
			break;
		}
		q_storage->active_dqs = dq_storage;
		q_storage->active_dpio_id = DPAA2_PER_LCORE_ETHRX_DPIO->index;
		set_swp_active_dqs(DPAA2_PER_LCORE_ETHRX_DPIO->index,
				   dq_storage);
	}

	dq_storage = q_storage->active_dqs;
	rte_prefetch0((void *)(size_t)(dq_storage));
	rte_prefetch0((void *)(size_t)(dq_storage + 1));

	/* Prepare next pull descriptor. This will give space for the
	 * prefetching done on DQRR entries
	 */
	q_storage->toggle ^= 1;
	dq_storage1 = q_storage->dq_storage[q_storage->toggle];
	qbman_pull_desc_clear(&pulldesc);
	qbman_pull_desc_set_numframes(&pulldesc, pull_size);
	qbman_pull_desc_set_fq(&pulldesc, fqid);
	qbman_pull_desc_set_storage(&pulldesc, dq_storage1,
		(uint64_t)(DPAA2_VADDR_TO_IOVA(dq_storage1)), 1);

	/* Check if the previous issued command is completed.
	 * Also seems like the SWP is shared between the Ethernet Driver
	 * and the SEC driver.
	 */
	while (!qbman_check_command_complete(dq_storage))
		;
	if (dq_storage == get_swp_active_dqs(q_storage->active_dpio_id))
		clear_swp_active_dqs(q_storage->active_dpio_id);

	pending = 1;

	do {
		/* Loop until the dq_storage is updated with
		 * new token by QBMAN
		 */
		while (!qbman_check_new_result(dq_storage))
			;
		rte_prefetch0((void *)((size_t)(dq_storage + 2)));
		/* Check whether Last Pull command is Expired and
		 * setting Condition for Loop termination
		 */
		if (qbman_result_DQ_is_pull_complete(dq_storage)) {
			pending = 0;
			/* Check for valid frame. */
			status = qbman_result_DQ_flags(dq_storage);
			if (unlikely((status & QBMAN_DQ_STAT_VALIDFRAME) == 0))
				continue;
		}
		if (dpaa2_svr_family != SVR_LX2160A)
			/** Packet type is parsed from FRC for LX2160A.*/
			dpaa2_dev_prefetch_next_psr(dq_storage);

		fd = qbman_result_DQ_fd(dq_storage);
		dpaa2_dev_rx_print_parser_result(priv, fd);

		if (priv->psr_dynfield_offset >= 0)
			dpaa2_dev_rx_annot_prefetch(fd);
		if (unlikely(DPAA2_FD_GET_FORMAT(fd) == qbman_fd_sg))
			bufs[num_rx] = eth_sg_fd_to_mbuf(priv, fd);
		else
			bufs[num_rx] = eth_fd_to_mbuf(priv, fd);
		if (priv->psr_dynfield_offset >= 0)
			dpaa2_dev_rx_parse_offset(priv, bufs[num_rx], fd);

		dpaa2_dev_rx_read_timestamp(priv, bufs[num_rx]);

		if (priv->en_ordered) {
			*dpaa2_seqn(bufs[num_rx]) = DPAA2_ENQUEUE_FLAG_ORP;
			*dpaa2_seqn(bufs[num_rx]) |= qbman_result_DQ_odpid(dq_storage) << DPAA2_EQCR_OPRID_SHIFT;
			*dpaa2_seqn(bufs[num_rx]) |= qbman_result_DQ_seqnum(dq_storage) << DPAA2_EQCR_SEQNUM_SHIFT;
		}

		if (eth_data->dev_conf.rxmode.offloads &
				RTE_ETH_RX_OFFLOAD_VLAN_STRIP)
			rte_vlan_strip(bufs[num_rx]);

		dq_storage++;
		num_rx++;
	} while (pending);

	if (check_swp_active_dqs(DPAA2_PER_LCORE_ETHRX_DPIO->index)) {
		while (!qbman_check_command_complete(
		       get_swp_active_dqs(DPAA2_PER_LCORE_ETHRX_DPIO->index)))
			;
		clear_swp_active_dqs(DPAA2_PER_LCORE_ETHRX_DPIO->index);
	}
	/* issue a volatile dequeue command for next pull */
	while (1) {
		if (qbman_swp_pull(swp, &pulldesc)) {
			DPAA2_PMD_DP_DEBUG("VDQ command is not issued."
					  "QBMAN is busy (2)");
			continue;
		}
		break;
	}
	q_storage->active_dqs = dq_storage1;
	q_storage->active_dpio_id = DPAA2_PER_LCORE_ETHRX_DPIO->index;
	set_swp_active_dqs(DPAA2_PER_LCORE_ETHRX_DPIO->index, dq_storage1);

	dpaa2_q->rx_pkts += num_rx;

	return num_rx;
}

void __rte_hot
dpaa2_dev_process_parallel_event(struct qbman_swp *swp,
	const struct qbman_fd *fd,
	const struct qbman_result *dq,
	struct dpaa2_queue *rxq,
	struct rte_event *ev)
{
	if (dpaa2_svr_family != SVR_LX2160A)
		dpaa2_dev_rx_annot_prefetch(fd);

	ev->event = rxq->ev.event;
	ev->mbuf = eth_fd_to_mbuf(rxq->eth_data->dev_private, fd);

	qbman_swp_dqrr_consume(swp, dq);
}

void __rte_hot
dpaa2_dev_process_atomic_event(struct qbman_swp *swp __rte_unused,
	const struct qbman_fd *fd,
	const struct qbman_result *dq,
	struct dpaa2_queue *rxq,
	struct rte_event *ev)
{
	uint8_t dqrr_index;

	if (dpaa2_svr_family != SVR_LX2160A)
		dpaa2_dev_rx_annot_prefetch(fd);

	ev->event = rxq->ev.event;
	ev->mbuf = eth_fd_to_mbuf(rxq->eth_data->dev_private, fd);

	dqrr_index = qbman_get_dqrr_idx(dq);
	*dpaa2_seqn(ev->mbuf) = dqrr_index + 1;
	DPAA2_PER_LCORE_DQRR_SIZE++;
	DPAA2_PER_LCORE_DQRR_HELD |= 1 << dqrr_index;
	DPAA2_PER_LCORE_DQRR_MBUF(dqrr_index) = ev->mbuf;
}

void __rte_hot
dpaa2_dev_process_ordered_event(struct qbman_swp *swp,
	const struct qbman_fd *fd,
	const struct qbman_result *dq,
	struct dpaa2_queue *rxq,
	struct rte_event *ev)
{
	if (dpaa2_svr_family != SVR_LX2160A)
		dpaa2_dev_rx_annot_prefetch(fd);

	ev->event = rxq->ev.event;
	ev->mbuf = eth_fd_to_mbuf(rxq->eth_data->dev_private, fd);

	*dpaa2_seqn(ev->mbuf) = DPAA2_ENQUEUE_FLAG_ORP;
	*dpaa2_seqn(ev->mbuf) |= qbman_result_DQ_odpid(dq) << DPAA2_EQCR_OPRID_SHIFT;
	*dpaa2_seqn(ev->mbuf) |= qbman_result_DQ_seqnum(dq) << DPAA2_EQCR_SEQNUM_SHIFT;

	qbman_swp_dqrr_consume(swp, dq);
}

uint16_t
dpaa2_dev_rx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	/* Function receive frames for a given device and VQ */
	struct dpaa2_queue *dpaa2_q = queue;
	struct qbman_result *dq_storage;
	uint32_t fqid = dpaa2_q->fqid, next_pull = nb_pkts;
	int ret;
	uint8_t pending, status, num_rx = 0, num_pulled;
	struct qbman_swp *swp;
	const struct qbman_fd *fd;
	struct qbman_pull_desc pulldesc;
	struct rte_eth_dev_data *eth_data = dpaa2_q->eth_data;
	struct dpaa2_dev_priv *priv = eth_data->dev_private;

	if (unlikely(priv->flags & DPAA2_RX_ERROR_QUEUE_FLAG))
		dump_err_pkts(priv->rx_err_vq);

	if (unlikely(!DPAA2_PER_LCORE_DPIO)) {
		ret = dpaa2_affine_qbman_swp();
		if (ret) {
			DPAA2_PMD_ERR(
				"Failed to allocate IO portal, tid: %d",
				rte_gettid());
			return 0;
		}
	}
	swp = DPAA2_PER_LCORE_PORTAL;

	do {
		dq_storage = dpaa2_q->q_storage[0]->dq_storage[0];
		qbman_pull_desc_clear(&pulldesc);
		qbman_pull_desc_set_fq(&pulldesc, fqid);
		qbman_pull_desc_set_storage(&pulldesc, dq_storage,
				(size_t)(DPAA2_VADDR_TO_IOVA(dq_storage)), 1);

		if (next_pull > dpaa2_dqrr_size) {
			qbman_pull_desc_set_numframes(&pulldesc,
				dpaa2_dqrr_size);
			next_pull -= dpaa2_dqrr_size;
		} else {
			qbman_pull_desc_set_numframes(&pulldesc, next_pull);
			next_pull = 0;
		}

		while (1) {
			if (qbman_swp_pull(swp, &pulldesc)) {
				DPAA2_PMD_DP_DEBUG(
					"VDQ command is not issued.QBMAN is busy");
				/* Portal was busy, try again */
				continue;
			}
			break;
		}

		rte_prefetch0((void *)((size_t)(dq_storage + 1)));
		/* Check if the previous issued command is completed. */
		while (!qbman_check_command_complete(dq_storage))
			;

		num_pulled = 0;
		pending = 1;
		do {
			/* Loop until the dq_storage is updated with
			 * new token by QBMAN
			 */
			while (!qbman_check_new_result(dq_storage))
				;
			rte_prefetch0((void *)((size_t)(dq_storage + 2)));
			/* Check whether Last Pull command is Expired and
			 * setting Condition for Loop termination
			 */
			if (qbman_result_DQ_is_pull_complete(dq_storage)) {
				pending = 0;
				/* Check for valid frame. */
				status = qbman_result_DQ_flags(dq_storage);
				if (unlikely((status &
					QBMAN_DQ_STAT_VALIDFRAME) == 0))
					continue;
			}
			if (dpaa2_svr_family != SVR_LX2160A)
				/** Packet type is parsed from FRC for LX2160A.*/
				dpaa2_dev_prefetch_next_psr(dq_storage);

			fd = qbman_result_DQ_fd(dq_storage);
			dpaa2_dev_rx_print_parser_result(priv, fd);

			if (priv->psr_dynfield_offset >= 0)
				dpaa2_dev_rx_annot_prefetch(fd);
			if (unlikely(DPAA2_FD_GET_FORMAT(fd) == qbman_fd_sg))
				bufs[num_rx] = eth_sg_fd_to_mbuf(priv, fd);
			else
				bufs[num_rx] = eth_fd_to_mbuf(priv, fd);
			if (priv->psr_dynfield_offset >= 0)
				dpaa2_dev_rx_parse_offset(priv, bufs[num_rx], fd);

			dpaa2_dev_rx_read_timestamp(priv, bufs[num_rx]);
			if (eth_data->dev_conf.rxmode.offloads &
				RTE_ETH_RX_OFFLOAD_VLAN_STRIP)
				rte_vlan_strip(bufs[num_rx]);

			dq_storage++;
			num_rx++;
			num_pulled++;
		} while (pending);
	/* Last VDQ provided all packets and more packets are requested */
	} while (next_pull && num_pulled == dpaa2_dqrr_size);

	dpaa2_q->rx_pkts += num_rx;

	return num_rx;
}

static inline int
dpaa2_dev_is_mbuf_from_spec_pool(struct rte_mempool *mp,
	struct rte_mbuf *mbuf)
{
	while (mbuf) {
		if (mbuf->pool != mp)
			return false;
		mbuf = mbuf->next;
	}

	return true;
}

uint16_t dpaa2_dev_tx_conf(void *txq, int drain)
{
	/* Function receive frames for a given device and VQ*/
	struct dpaa2_queue *dpaa2_txq = txq;
	struct dpaa2_queue *dpaa2_q = dpaa2_txq->tx_conf_queue;
	struct qbman_result *dq_storage, *dq_storage1 = NULL;
	uint32_t fqid = dpaa2_q->fqid;
	int ret, num_tx_conf, pull_size, total = 0, bulk_free;
	uint8_t pending, status, idx, buf_idx;
	struct qbman_swp *swp;
	const struct qbman_fd *fd;
	struct qbman_pull_desc pulldesc;
	struct queue_storage_info_t *q_storage;
	struct qbman_result *rst;

	struct rte_mbuf *mbufs[dpaa2_dqrr_size];
	struct rte_mempool *mp = NULL;
	struct rte_eth_dev_data *eth_data = dpaa2_q->eth_data;
	struct dpaa2_dev_priv *priv = eth_data->dev_private;
	struct dpaa2_annot_hdr *annotation;
	void *v_addr;
	#define swp_idx (DPAA2_PER_LCORE_ETHRX_DPIO->index)

conf_again:
	bulk_free = true;
	num_tx_conf = 0;
	idx = 0;
	q_storage = dpaa2_q->q_storage[rte_lcore_id()];
	if (unlikely(!DPAA2_PER_LCORE_ETHRX_DPIO)) {
		ret = dpaa2_affine_qbman_ethrx_swp();
		if (ret) {
			DPAA2_PMD_ERR("Failure in affining portal");
			return 0;
		}
	}

	swp = DPAA2_PER_LCORE_ETHRX_PORTAL;
	pull_size = dpaa2_dqrr_size;
	if (unlikely(!q_storage->active_dqs)) {
		q_storage->toggle = 0;
		dq_storage = q_storage->dq_storage[q_storage->toggle];
		q_storage->last_num_pkts = pull_size;
		qbman_pull_desc_clear(&pulldesc);
		qbman_pull_desc_set_numframes(&pulldesc,
			q_storage->last_num_pkts);
		qbman_pull_desc_set_fq(&pulldesc, fqid);
		qbman_pull_desc_set_storage(&pulldesc, dq_storage,
			DPAA2_VADDR_TO_IOVA(dq_storage), 1);
		if (check_swp_active_dqs(swp_idx)) {
			rst = get_swp_active_dqs(swp_idx);
			while (!qbman_check_command_complete(rst))
				;
			clear_swp_active_dqs(swp_idx);
		}
		while (1) {
			if (qbman_swp_pull(swp, &pulldesc)) {
				DPAA2_PMD_DP_DEBUG("QBMAN is busy (1)\n");
				/* Portal was busy, try again */
				continue;
			}
			break;
		}
		q_storage->active_dqs = dq_storage;
		q_storage->active_dpio_id = swp_idx;
		set_swp_active_dqs(swp_idx, dq_storage);
	}

	dq_storage = q_storage->active_dqs;
	rte_prefetch0((void *)(dq_storage));
	rte_prefetch0((void *)(dq_storage + 1));

	/* Prepare next pull descriptor. This will give space for the
	 * prefetching done on DQRR entries
	 */
	q_storage->toggle ^= 1;
	dq_storage1 = q_storage->dq_storage[q_storage->toggle];
	qbman_pull_desc_clear(&pulldesc);
	qbman_pull_desc_set_numframes(&pulldesc, pull_size);
	qbman_pull_desc_set_fq(&pulldesc, fqid);
	qbman_pull_desc_set_storage(&pulldesc, dq_storage1,
		DPAA2_VADDR_TO_IOVA(dq_storage1), 1);

	/* Check if the previous issued command is completed.
	 * Also seems like the SWP is shared between the Ethernet Driver
	 * and the SEC driver.
	 */
	while (!qbman_check_command_complete(dq_storage))
		;
	if (dq_storage == get_swp_active_dqs(q_storage->active_dpio_id))
		clear_swp_active_dqs(q_storage->active_dpio_id);

	pending = 1;

	do {
		/* Loop until the dq_storage is updated with
		 * new token by QBMAN
		 */
		while (!qbman_check_new_result(dq_storage))
			;
		rte_prefetch0((void *)(dq_storage + 2));
		/* Check whether Last Pull command is Expired and
		 * setting Condition for Loop termination
		 */
		if (qbman_result_DQ_is_pull_complete(dq_storage)) {
			pending = 0;
			/* Check for valid frame. */
			status = qbman_result_DQ_flags(dq_storage);
			if (unlikely((status & QBMAN_DQ_STAT_VALIDFRAME) == 0))
				continue;
		}

		fd = qbman_result_DQ_fd(dq_storage);
		mbufs[idx] = (void *)DPAA2_GET_FD_FLC(fd);
		if (unlikely(!mp))
			mp = mbufs[idx]->pool;
		if (unlikely(rte_mbuf_refcnt_read(mbufs[idx]) > 1))
			bulk_free = false;
		if (bulk_free == true &&
			!dpaa2_dev_is_mbuf_from_spec_pool(mp, mbufs[idx]))
			bulk_free = false;
		if (unlikely(mbufs[idx]->ol_flags & RTE_MBUF_F_TX_IEEE1588_TMST)) {
			v_addr = mbufs[idx]->buf_addr;
			annotation = (void *)((size_t)v_addr + DPAA2_FD_PTA_SIZE);
			__atomic_store_n(&priv->tx_timestamp,
				annotation->word2, __ATOMIC_RELAXED);
			__atomic_store_n(&priv->next_txq_to_cnf,
				dpaa2_txq, __ATOMIC_RELAXED);
			dpaa2_q->ts_to_cnfd--;
			dpaa2_timestamp_debug(priv, __func__, priv->tx_timestamp);
		}
		idx++;
		dq_storage++;
		num_tx_conf++;
		dpaa2_q->to_cnfd--;
	} while (pending);

	if (check_swp_active_dqs(swp_idx)) {
		rst = get_swp_active_dqs(swp_idx);
		while (!qbman_check_command_complete(rst))
			;
		clear_swp_active_dqs(swp_idx);
	}
	/* issue a volatile dequeue command for next pull */
	while (1) {
		if (qbman_swp_pull(swp, &pulldesc)) {
			DPAA2_PMD_DP_DEBUG("QBMAN is busy (2)\n");
			continue;
		}
		break;
	}
	q_storage->active_dqs = dq_storage1;
	q_storage->active_dpio_id = swp_idx;
	set_swp_active_dqs(swp_idx, dq_storage1);

	if (unlikely(dpaa2_q->to_cnfd < 0)) {
		rte_panic("%s: to be confirmed count(%d) < 0",
			__func__, dpaa2_q->to_cnfd);
	}

	if (bulk_free) {
		rte_pktmbuf_free_bulk(mbufs, idx);
	} else {
		for (buf_idx = 0; buf_idx < idx; buf_idx++) {
			if (rte_mbuf_refcnt_read(mbufs[buf_idx]) > 1)
				rte_mbuf_refcnt_update(mbufs[buf_idx], -1);
			else
				rte_pktmbuf_free(mbufs[buf_idx]);
		}
	}

	dpaa2_q->rx_pkts += num_tx_conf;
	total += num_tx_conf;
	if (drain && dpaa2_q->to_cnfd > 0)
		goto conf_again;

	return total;
}

static inline int
dpaa2_dev_tx_fast_mbuf_to_fd(struct rte_eth_dev_data *dev,
	struct rte_mbuf *buf, struct qbman_fd *fd,
	enum dpaa2_tx_conf_type conf)
{
	struct rte_mempool *mp = buf->pool;
	struct dpaa2_dev_priv *priv = dev->dev_private;

	if (likely(RTE_MBUF_DIRECT(buf) &&
		mp && mp->ops_index ==
		priv->bp_list->dpaa2_ops_index &&
		buf->nb_segs == 1 &&
		rte_mbuf_refcnt_read(buf) == 1)) {
		if (unlikely(buf->next)) {
			DPAA2_PMD_WARN("Single mbuf has next segment(%p)\n",
				buf->next);
		}
		if (unlikely(conf == DPAA2_TX_ABSOLUTE_CONF))
			DPAA2_MBUF_TO_CONF_CONTIG_FD(buf, fd);
		else
			DPAA2_MBUF_TO_CONTIG_FD(buf, fd, mempool_to_bpid(mp));
#ifdef RTE_LIBRTE_MEMPOOL_DEBUG
		rte_mempool_check_cookies(rte_mempool_from_obj(buf),
			(void **)&buf, 1, 0);
#endif
		return 0;
	}

	return -EAGAIN;
}

uint16_t
dpaa2_dev_tx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	/* Function to transmit the frames to given device and VQ*/
	uint32_t loop, retry_count, i;
	int32_t ret, tstamp[MAX_TX_RING_SLOTS], ptp_set_count, ptp_set;
	struct qbman_fd fd_arr[MAX_TX_RING_SLOTS];
	uint32_t frames_to_send;
	struct qbman_eq_desc eqdesc;
	struct dpaa2_queue *dpaa2_q = queue;
	struct qbman_swp *swp;
	uint16_t num_tx = 0;
	struct rte_eth_dev_data *eth_data = dpaa2_q->eth_data;
	struct dpaa2_dev_priv *priv = eth_data->dev_private;
	struct rte_mempool *hw_mp;
	uint32_t flags[MAX_TX_RING_SLOTS] = {0};
	uint8_t dy_conf[MAX_TX_RING_SLOTS];

	if (unlikely(!DPAA2_PER_LCORE_DPIO)) {
		ret = dpaa2_affine_qbman_swp();
		if (ret) {
			DPAA2_PMD_ERR("Failed to allocate IO portal, tid: %d",
				rte_gettid());
			return 0;
		}
	}
	swp = DPAA2_PER_LCORE_PORTAL;

	DPAA2_PMD_DP_DEBUG("===> eth_data =%p, fqid =%d",
		eth_data, dpaa2_q->fqid);

	if (unlikely(!priv->bp_list)) {
		DPAA2_PMD_ERR("%s's buffer pool not initialized!",
			eth_data->name);
		return 0;
	}
	hw_mp = priv->bp_list->mp;

	if (dpaa2_q->tx_conf_queue &&
		dpaa2_q->tx_conf_queue->to_cnfd > 0)
		dpaa2_dev_tx_conf(dpaa2_q, false);

	/*Prepare enqueue descriptor*/
	qbman_eq_desc_clear(&eqdesc);
	qbman_eq_desc_set_no_orp(&eqdesc, DPAA2_EQ_RESP_ERR_FQ);
	qbman_eq_desc_set_fq(&eqdesc, dpaa2_q->fqid);

	/*Clear the unused FD fields before sending*/

tx_again:
	/*Check if the queue is congested*/
	retry_count = 0;
	ptp_set_count = 0;
	while (qbman_result_SCN_state(dpaa2_q->cscn)) {
		retry_count++;
		/* Retry for some time before giving up */
		if (retry_count > CONG_RETRY_COUNT)
			goto skip_tx;
	}

	frames_to_send = (nb_pkts > dpaa2_eqcr_size) ?
		dpaa2_eqcr_size : nb_pkts;

	for (loop = 0; loop < frames_to_send; loop++) {
		dy_conf[loop] = false;
		if (*dpaa2_seqn(*bufs)) {
			uint8_t dqrr_index = *dpaa2_seqn(*bufs) - 1;

			flags[loop] = QBMAN_ENQUEUE_FLAG_DCA | dqrr_index;
			DPAA2_PER_LCORE_DQRR_SIZE--;
			DPAA2_PER_LCORE_DQRR_HELD &= ~(1 << dqrr_index);
			*dpaa2_seqn(*bufs) = DPAA2_INVALID_MBUF_SEQN;
		}

		if (unlikely(((*bufs)->ol_flags & RTE_MBUF_F_TX_VLAN) ||
			(eth_data->dev_conf.txmode.offloads
			& RTE_ETH_TX_OFFLOAD_VLAN_INSERT))) {
			ret = rte_vlan_insert(bufs);
			if (ret)
				goto send_n_return;
		}

		tstamp[loop] = false;
		if (unlikely(((*bufs)->ol_flags & RTE_MBUF_F_TX_IEEE1588_TMST) &&
			(priv->flags & DPAA2_IEEE1588_TX_TS_FLAG))) {
			ptp_set = false;
			dpaa2_dev_tx_ptp_one_step_runtime(priv->eth_dev, *bufs,
				&tstamp[loop], &ptp_set);
			if (ptp_set)
				ptp_set_count++;
			if (ptp_set_count > 1)
				DPAA2_PMD_WARN("Multiple ptp formats in burst transmission!\n");
			goto skip_fast_mbuf2fd;
		}

		ret = dpaa2_dev_tx_fast_mbuf_to_fd(eth_data,
			*bufs, &fd_arr[loop], priv->tx_conf_type);
		if (likely(!ret)) {
			bufs++;
			continue;
		}

skip_fast_mbuf2fd:
		if (unlikely((*bufs)->nb_segs > 1)) {
			ret = dpaa2_dev_tx_mbuf_to_sg_fd(hw_mp, *bufs, &fd_arr[loop],
				dpaa2_q, priv->tx_conf_type, &dy_conf[loop], tstamp[loop]);
		} else {
			ret = dpaa2_dev_tx_mbuf_to_simple_fd(hw_mp, *bufs, &fd_arr[loop],
				dpaa2_q, priv->tx_conf_type, &dy_conf[loop], tstamp[loop]);
		}
		if (ret)
			goto send_n_return;
		bufs++;
	}

	loop = 0;
	retry_count = 0;
	while (loop < frames_to_send) {
		ret = qbman_swp_enqueue_multiple(swp, &eqdesc,
				&fd_arr[loop], &flags[loop],
				frames_to_send - loop);
		if (unlikely(ret < 0)) {
			retry_count++;
			if (retry_count > DPAA2_MAX_TX_RETRY_COUNT) {
				num_tx += loop;
				nb_pkts -= loop;
				goto send_n_return;
			}
		} else {
			loop += ret;
			retry_count = 0;
		}
	}

	num_tx += loop;
	nb_pkts -= loop;
	if (priv->tx_conf_type != DPAA2_TX_NO_CONF) {
		for (i = 0; i < loop; i++) {
			if (dy_conf[i])
				dpaa2_q->tx_conf_queue->to_cnfd++;
			if (tstamp[i])
				dpaa2_q->tx_conf_queue->ts_to_cnfd++;
		}
	}
	if (nb_pkts > 0)
		goto tx_again;

	dpaa2_q->tx_pkts += num_tx;
	if (priv->tx_conf_type == DPAA2_TX_ABSOLUTE_CONF)
		dpaa2_q->tx_conf_queue->to_cnfd += num_tx;

	return num_tx;

send_n_return:
	/* send any already prepared fd */
	retry_count = 0;
	i = 0;
	while (i < loop) {
		ret = qbman_swp_enqueue_multiple(swp, &eqdesc, &fd_arr[i],
			&flags[i], loop - i);
		if (unlikely(ret < 0)) {
			retry_count++;
			if (retry_count > DPAA2_MAX_TX_RETRY_COUNT)
				break;
		} else {
			i += ret;
			retry_count = 0;
		}
	}
	num_tx += i;
	if (priv->tx_conf_type != DPAA2_TX_NO_CONF) {
		loop = i;
		for (i = 0; i < loop; i++) {
			if (dy_conf[i])
				dpaa2_q->tx_conf_queue->to_cnfd++;
			if (tstamp[i])
				dpaa2_q->tx_conf_queue->ts_to_cnfd++;
		}
	}

skip_tx:
	dpaa2_q->tx_pkts += num_tx;
	if (priv->tx_conf_type == DPAA2_TX_ABSOLUTE_CONF)
		dpaa2_q->tx_conf_queue->to_cnfd += num_tx;

	return num_tx;
}

void
dpaa2_dev_free_eqresp_buf(uint16_t eqresp_ci, struct dpaa2_queue *dpaa2_q)
{
	struct dpaa2_dpio_dev *dpio_dev = DPAA2_PER_LCORE_DPIO;
	struct qbman_fd *fd;
	struct rte_mbuf *m;

	fd = qbman_result_eqresp_fd(&dpio_dev->eqresp[eqresp_ci]);

	/* Setting port id does not matter as we are to free the mbuf */
	m = eth_fd_to_mbuf(dpaa2_q->eth_data->dev_private, fd);
	rte_pktmbuf_free(m);
}

static void
dpaa2_set_enqueue_descriptor(struct dpaa2_queue *dpaa2_q,
			     struct rte_mbuf *m,
			     struct qbman_eq_desc *eqdesc)
{
	struct rte_eth_dev_data *eth_data = dpaa2_q->eth_data;
	struct dpaa2_dev_priv *priv = eth_data->dev_private;
	struct dpaa2_dpio_dev *dpio_dev = DPAA2_PER_LCORE_DPIO;
	struct eqresp_metadata *eqresp_meta;
	uint16_t orpid, seqnum;
	uint8_t dq_idx;

	qbman_eq_desc_set_fq(eqdesc, dpaa2_q->fqid);

	if (*dpaa2_seqn(m) & DPAA2_ENQUEUE_FLAG_ORP) {
		orpid = (*dpaa2_seqn(m) & DPAA2_EQCR_OPRID_MASK) >>
			DPAA2_EQCR_OPRID_SHIFT;
		seqnum = (*dpaa2_seqn(m) & DPAA2_EQCR_SEQNUM_MASK) >>
			DPAA2_EQCR_SEQNUM_SHIFT;

		if (!priv->en_loose_ordered) {
			qbman_eq_desc_set_orp(eqdesc, 1, orpid, seqnum, 0);
			qbman_eq_desc_set_response(eqdesc, (uint64_t)
				DPAA2_VADDR_TO_IOVA(&dpio_dev->eqresp[
				dpio_dev->eqresp_pi]), 1);
			qbman_eq_desc_set_token(eqdesc, 1);

			eqresp_meta = &dpio_dev->eqresp_meta[
				dpio_dev->eqresp_pi];
			eqresp_meta->dpaa2_q = dpaa2_q;
			eqresp_meta->mp = m->pool;

			dpio_dev->eqresp_pi + 1 < MAX_EQ_RESP_ENTRIES ?
				dpio_dev->eqresp_pi++ :
				(dpio_dev->eqresp_pi = 0);
		} else {
			qbman_eq_desc_set_orp(eqdesc, 0, orpid, seqnum, 0);
		}
	} else {
		dq_idx = *dpaa2_seqn(m) - 1;
		qbman_eq_desc_set_dca(eqdesc, 1, dq_idx, 0);
		DPAA2_PER_LCORE_DQRR_SIZE--;
		DPAA2_PER_LCORE_DQRR_HELD &= ~(1 << dq_idx);
	}
	*dpaa2_seqn(m) = DPAA2_INVALID_MBUF_SEQN;
}

uint16_t
dpaa2_dev_tx_multi_txq_ordered(void **queue,
	struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	/* Function to transmit the frames to multiple queues respectively.*/
	uint32_t loop, retry_count, sent = 0, i;
	int32_t ret = 0, tstamp[MAX_TX_RING_SLOTS], ptp_set_count, ptp_set;
	struct qbman_fd fd_arr[MAX_TX_RING_SLOTS];
	uint32_t frames_to_send, num_free_eq_desc = 0;
	struct rte_mempool *hw_mp;
	struct qbman_eq_desc eqdesc[MAX_TX_RING_SLOTS];
	struct dpaa2_queue *dpaa2_q[MAX_TX_RING_SLOTS];
	struct qbman_swp *swp;
	struct rte_eth_dev_data *eth_data;
	struct dpaa2_dev_priv *priv;
	struct dpaa2_queue *order_sendq;
	uint8_t dy_conf[MAX_TX_RING_SLOTS];

	if (unlikely(!DPAA2_PER_LCORE_DPIO)) {
		ret = dpaa2_affine_qbman_swp();
		if (ret) {
			DPAA2_PMD_ERR("Failed to allocate IO portal, tid: %d",
				rte_gettid());
			return 0;
		}
	}
	swp = DPAA2_PER_LCORE_PORTAL;

tx_again:
	ptp_set_count = 0;
	frames_to_send = (nb_pkts > dpaa2_eqcr_size) ?
		dpaa2_eqcr_size : nb_pkts;

	for (loop = 0; loop < frames_to_send; loop++) {
		dpaa2_q[loop] = queue[loop];
		if (dpaa2_q[loop]->tx_conf_queue &&
			dpaa2_q[loop]->tx_conf_queue->to_cnfd > 0)
			dpaa2_dev_tx_conf(dpaa2_q[loop], false);
		eth_data = dpaa2_q[loop]->eth_data;
		priv = eth_data->dev_private;
		dy_conf[loop] = false;
		if (unlikely(!priv->bp_list)) {
			DPAA2_PMD_ERR("%s's buffer pool not initialized!",
				eth_data->name);
			ret = -ENOMEM;
			goto send_frames;
		}
		hw_mp = priv->bp_list->mp;
		if (!priv->en_loose_ordered &&
			(*dpaa2_seqn(*bufs) & DPAA2_ENQUEUE_FLAG_ORP)) {
			if (!num_free_eq_desc) {
				num_free_eq_desc = dpaa2_free_eq_descriptors();
				if (!num_free_eq_desc) {
					ret = -EIO;
					goto send_frames;
				}
			}
			num_free_eq_desc--;
		}

		DPAA2_PMD_DP_DEBUG("===> eth_data =%p, fqid =%d",
			eth_data, dpaa2_q[loop]->fqid);

		/* Check if the queue is congested */
		retry_count = 0;
		while (qbman_result_SCN_state(dpaa2_q[loop]->cscn)) {
			retry_count++;
			/* Retry for some time before giving up */
			if (retry_count > CONG_RETRY_COUNT) {
				ret = -ETIME;
				goto send_frames;
			}
		}

		/* Prepare enqueue descriptor */
		qbman_eq_desc_clear(&eqdesc[loop]);

		if (*dpaa2_seqn(*bufs) && priv->en_ordered) {
			order_sendq = priv->tx_vq[0];
			dpaa2_set_enqueue_descriptor(order_sendq, *bufs,
				&eqdesc[loop]);
		} else {
			qbman_eq_desc_set_no_orp(&eqdesc[loop], DPAA2_EQ_RESP_ERR_FQ);
			qbman_eq_desc_set_fq(&eqdesc[loop], dpaa2_q[loop]->fqid);
		}

		tstamp[loop] = false;
		if (unlikely(((*bufs)->ol_flags & RTE_MBUF_F_TX_IEEE1588_TMST) &&
			(priv->flags & DPAA2_IEEE1588_TX_TS_FLAG))) {
			ptp_set = false;
			dpaa2_dev_tx_ptp_one_step_runtime(priv->eth_dev, *bufs,
				&tstamp[loop], &ptp_set);
			if (ptp_set)
				ptp_set_count++;
			if (ptp_set_count > 1)
				DPAA2_PMD_WARN("Multiple ptp formats in burst transmission!\n");
			goto skip_fast_mbuf2fd;
		}

		ret = dpaa2_dev_tx_fast_mbuf_to_fd(eth_data,
				*bufs, &fd_arr[loop], priv->tx_conf_type);
		if (likely(!ret)) {
			if (priv->tx_conf_type == DPAA2_TX_ABSOLUTE_CONF)
				dy_conf[loop] = true;
			bufs++;
			continue;
		}

skip_fast_mbuf2fd:
		if (unlikely((*bufs)->nb_segs > 1)) {
			ret = dpaa2_dev_tx_mbuf_to_sg_fd(hw_mp, *bufs, &fd_arr[loop],
				dpaa2_q[loop], priv->tx_conf_type, &dy_conf[loop], tstamp[loop]);
		} else {
			ret = dpaa2_dev_tx_mbuf_to_simple_fd(hw_mp, *bufs, &fd_arr[loop],
				dpaa2_q[loop], priv->tx_conf_type, &dy_conf[loop], tstamp[loop]);
		}
		if (ret)
			goto send_frames;
		if (priv->tx_conf_type == DPAA2_TX_ABSOLUTE_CONF)
			dy_conf[loop] = true;
		bufs++;
	}

send_frames:
	frames_to_send = loop;
	loop = 0;
	retry_count = 0;
	while (loop < frames_to_send) {
		ret = qbman_swp_enqueue_multiple_desc(swp, &eqdesc[loop],
				&fd_arr[loop],
				frames_to_send - loop);
		if (likely(ret > 0)) {
			loop += ret;
			retry_count = 0;
		} else {
			retry_count++;
			if (retry_count > DPAA2_MAX_TX_RETRY_COUNT)
				break;
		}
	}
	nb_pkts -= loop;
	sent += loop;
	for (i = 0; i < loop; i++) {
		if (dy_conf[i])
			dpaa2_q[i]->tx_conf_queue->to_cnfd++;
		if (tstamp[i] && dpaa2_q[i]->tx_conf_queue)
			dpaa2_q[i]->tx_conf_queue->ts_to_cnfd++;
	}
	if (nb_pkts > 0 && !ret)
		goto tx_again;

	return sent;
}

uint16_t
rte_dpaa2_dev_tx_multi_ports(uint16_t port_id[],
	uint16_t txq_id[], struct rte_mbuf **bufs,
	uint16_t nb_pkts)
{
	uint16_t i;
	void *txq[nb_pkts];
	struct rte_eth_dev_data *data;

	if (txq_id) {
		for (i = 0; i < nb_pkts; i++) {
			data = rte_eth_devices[port_id[i]].data;
			txq[i] = data->tx_queues[txq_id[i]];
		}
	} else {
		for (i = 0; i < nb_pkts; i++) {
			data = rte_eth_devices[port_id[i]].data;
			txq[i] = data->tx_queues[0];
		}
	}
	return dpaa2_dev_tx_multi_txq_ordered(txq, bufs, nb_pkts);
}

/* Callback to handle sending ordered packets through WRIOP based interface */
uint16_t
dpaa2_dev_tx_ordered(void *queue, struct rte_mbuf **bufs,
	uint16_t nb_pkts)
{
	uint16_t i;
	void *mq[nb_pkts];

	for (i = 0; i < nb_pkts; i++)
		mq[i] = queue;

	return dpaa2_dev_tx_multi_txq_ordered(mq, bufs, nb_pkts);
}

#if defined(RTE_TOOLCHAIN_GCC)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
#elif defined(RTE_TOOLCHAIN_CLANG)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-qual"
#endif

/* This function loopbacks all the received packets.*/
uint16_t
dpaa2_dev_loopback_rx(void *queue,
		      struct rte_mbuf **bufs __rte_unused,
		      uint16_t nb_pkts)
{
	/* Function receive frames for a given device and VQ*/
	struct dpaa2_queue *dpaa2_q = (struct dpaa2_queue *)queue;
	struct qbman_result *dq_storage, *dq_storage1 = NULL;
	uint32_t fqid = dpaa2_q->fqid;
	int ret, num_rx = 0, num_tx = 0, pull_size;
	uint8_t pending, status;
	struct qbman_swp *swp;
	struct qbman_fd *fd[DPAA2_LX2_DQRR_RING_SIZE];
	struct qbman_pull_desc pulldesc;
	struct qbman_eq_desc eqdesc;
	struct queue_storage_info_t *q_storage;
	struct rte_eth_dev_data *eth_data = dpaa2_q->eth_data;
	struct dpaa2_dev_priv *priv = eth_data->dev_private;
	struct dpaa2_queue *tx_q = priv->tx_vq[0];
	/* todo - currently we are using 1st TX queue only for loopback*/

	q_storage = dpaa2_q->q_storage[rte_lcore_id()];
	if (unlikely(!DPAA2_PER_LCORE_ETHRX_DPIO)) {
		ret = dpaa2_affine_qbman_ethrx_swp();
		if (ret) {
			DPAA2_PMD_ERR("Failure in affining portal");
			return 0;
		}
	}
	swp = DPAA2_PER_LCORE_ETHRX_PORTAL;
	pull_size = (nb_pkts > dpaa2_dqrr_size) ? dpaa2_dqrr_size : nb_pkts;
	if (unlikely(!q_storage->active_dqs)) {
		q_storage->toggle = 0;
		dq_storage = q_storage->dq_storage[q_storage->toggle];
		q_storage->last_num_pkts = pull_size;
		qbman_pull_desc_clear(&pulldesc);
		qbman_pull_desc_set_numframes(&pulldesc,
					      q_storage->last_num_pkts);
		qbman_pull_desc_set_fq(&pulldesc, fqid);
		qbman_pull_desc_set_storage(&pulldesc, dq_storage,
			(size_t)(DPAA2_VADDR_TO_IOVA(dq_storage)), 1);
		if (check_swp_active_dqs(DPAA2_PER_LCORE_ETHRX_DPIO->index)) {
			while (!qbman_check_command_complete(
			       get_swp_active_dqs(
			       DPAA2_PER_LCORE_ETHRX_DPIO->index)))
				;
			clear_swp_active_dqs(DPAA2_PER_LCORE_ETHRX_DPIO->index);
		}
		while (1) {
			if (qbman_swp_pull(swp, &pulldesc)) {
				DPAA2_PMD_DP_DEBUG(
					"VDQ command not issued.QBMAN busy");
				/* Portal was busy, try again */
				continue;
			}
			break;
		}
		q_storage->active_dqs = dq_storage;
		q_storage->active_dpio_id = DPAA2_PER_LCORE_ETHRX_DPIO->index;
		set_swp_active_dqs(DPAA2_PER_LCORE_ETHRX_DPIO->index,
				   dq_storage);
	}

	dq_storage = q_storage->active_dqs;
	rte_prefetch0((void *)(size_t)(dq_storage));
	rte_prefetch0((void *)(size_t)(dq_storage + 1));

	/* Prepare next pull descriptor. This will give space for the
	 * prefetching done on DQRR entries
	 */
	q_storage->toggle ^= 1;
	dq_storage1 = q_storage->dq_storage[q_storage->toggle];
	qbman_pull_desc_clear(&pulldesc);
	qbman_pull_desc_set_numframes(&pulldesc, pull_size);
	qbman_pull_desc_set_fq(&pulldesc, fqid);
	qbman_pull_desc_set_storage(&pulldesc, dq_storage1,
		(size_t)(DPAA2_VADDR_TO_IOVA(dq_storage1)), 1);

	/*Prepare enqueue descriptor*/
	qbman_eq_desc_clear(&eqdesc);
	qbman_eq_desc_set_no_orp(&eqdesc, DPAA2_EQ_RESP_ERR_FQ);
	qbman_eq_desc_set_response(&eqdesc, 0, 0);
	qbman_eq_desc_set_fq(&eqdesc, tx_q->fqid);

	/* Check if the previous issued command is completed.
	 * Also seems like the SWP is shared between the Ethernet Driver
	 * and the SEC driver.
	 */
	while (!qbman_check_command_complete(dq_storage))
		;
	if (dq_storage == get_swp_active_dqs(q_storage->active_dpio_id))
		clear_swp_active_dqs(q_storage->active_dpio_id);

	pending = 1;

	do {
		/* Loop until the dq_storage is updated with
		 * new token by QBMAN
		 */
		while (!qbman_check_new_result(dq_storage))
			;
		rte_prefetch0((void *)((size_t)(dq_storage + 2)));
		/* Check whether Last Pull command is Expired and
		 * setting Condition for Loop termination
		 */
		if (qbman_result_DQ_is_pull_complete(dq_storage)) {
			pending = 0;
			/* Check for valid frame. */
			status = qbman_result_DQ_flags(dq_storage);
			if (unlikely((status & QBMAN_DQ_STAT_VALIDFRAME) == 0))
				continue;
		}
		fd[num_rx] = (struct qbman_fd *)qbman_result_DQ_fd(dq_storage);

		dq_storage++;
		num_rx++;
	} while (pending);

	while (num_tx < num_rx) {
		num_tx += qbman_swp_enqueue_multiple_fd(swp, &eqdesc,
				&fd[num_tx], 0, num_rx - num_tx);
	}

	if (check_swp_active_dqs(DPAA2_PER_LCORE_ETHRX_DPIO->index)) {
		while (!qbman_check_command_complete(
		       get_swp_active_dqs(DPAA2_PER_LCORE_ETHRX_DPIO->index)))
			;
		clear_swp_active_dqs(DPAA2_PER_LCORE_ETHRX_DPIO->index);
	}
	/* issue a volatile dequeue command for next pull */
	while (1) {
		if (qbman_swp_pull(swp, &pulldesc)) {
			DPAA2_PMD_DP_DEBUG("VDQ command is not issued."
					  "QBMAN is busy (2)");
			continue;
		}
		break;
	}
	q_storage->active_dqs = dq_storage1;
	q_storage->active_dpio_id = DPAA2_PER_LCORE_ETHRX_DPIO->index;
	set_swp_active_dqs(DPAA2_PER_LCORE_ETHRX_DPIO->index, dq_storage1);

	dpaa2_q->rx_pkts += num_rx;
	dpaa2_q->tx_pkts += num_tx;

	return 0;
}
#if defined(RTE_TOOLCHAIN_GCC)
#pragma GCC diagnostic pop
#elif defined(RTE_TOOLCHAIN_CLANG)
#pragma clang diagnostic pop
#endif

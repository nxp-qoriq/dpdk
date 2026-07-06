/* SPDX-License-Identifier: BSD-3-Clause
 *
 *   Copyright (c) 2015-2016 Freescale Semiconductor, Inc. All rights reserved.
 *   Copyright 2016-2026 NXP
 *
 */

#ifndef _DPAA2_ETHDEV_H
#define _DPAA2_ETHDEV_H

#include <rte_time.h>
#include <rte_compat.h>
#include <rte_event_eth_rx_adapter.h>
#include <rte_pmd_dpaa2.h>

#include <bus_fslmc_driver.h>
#include <dpaa2_hw_pvt.h>
#include "dpaa2_tm.h"

#include <mc/fsl_dpni.h>
#include <mc/fsl_mc_sys.h>
#include <mc/fsl_dpmac.h>

#include "base/dpaa2_hw_dpni_annot.h"
#include "dpaa2_parser_decode.h"

#define DPAA2_FLOW_FRM_REPLICATION_ACTION_MC_REV RTE_FSL_MC_REV(10, 39, 106)
#define DPAA2_FS_FLOW_HW_ACTION_UPDATE_MC_REV RTE_FSL_MC_REV(10, 39, 106)
#define DPAA2_QOS_FLOW_HW_ACTION_UPDATE_MC_REV RTE_FSL_MC_REV(10, 39, 109)
#define DPAA2_POLICER_SET_V2_MC_REV RTE_FSL_MC_REV(10, 39, 109)
#define DPAA2_POLICER_NOT_RESET_COUNTER_MC_REV DPAA2_POLICER_SET_V2_MC_REV
#define DPAA2_QOS_FLOW_TABLE_MISS_FLOW_ACTION_MC_REV RTE_FSL_MC_REV(10, 39, 109)
#define DPAA2_QOS_FLOW_TABLE_SET_V3_MC_REV RTE_FSL_MC_REV(10, 39, 109)

#define DPAA2_MIN_RX_BUF_SIZE 512
#define DPAA2_MAX_RX_PKT_LEN  10240 /*WRIOP support*/
#define NET_DPAA2_PMD_DRIVER_NAME net_dpaa2

#define MAX_TCS			DPNI_MAX_TC
#define MAX_RX_QUEUES		128
#define MAX_TX_QUEUES		128
#define MAX_DPNI		8
#define DPAA2_MAX_CHANNELS	16

#define DPAA2_DEV_PRIV_TO_DPAA2_DEV(priv) \
	container_of((((struct dpaa2_dev_priv *)priv)->eth_dev->device), \
	struct rte_dpaa2_device, device)

#define DPAA2_EXTRACT_PARAM_MAX_SIZE \
	RTE_ALIGN(sizeof(struct dpni_ext_set_rx_tc_dist), 256)

#define DPAA2_EXTRACT_ALLOC_KEY_MAX_SIZE 256

#define DPAA2_RX_DEFAULT_NBDESC 512

#define DPAA2_ETH_MAX_LEN (RTE_ETHER_MTU + \
			   RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN + \
			   VLAN_TAG_SIZE)

/*default tc to be used for ,congestion, distribution etc configuration. */
#define DPAA2_DEF_TC		0

/* Threshold for a Tx queue to *Enter* Congestion state.
 */
#define CONG_ENTER_TX_THRESHOLD   512

/* Threshold for a queue to *Exit* Congestion state.
 */
#define CONG_EXIT_TX_THRESHOLD    480

#define CONG_RETRY_COUNT 18000

/* RX queue tail drop threshold
 * currently considering 64 KB packets
 */
#define CONG_THRESHOLD_RX_BYTES_Q  (64 * 1024)
#define CONG_RX_OAL	128

/* Size of the input SMMU mapped memory required by MC */
#define DIST_PARAM_IOVA_SIZE DPAA2_EXTRACT_PARAM_MAX_SIZE

/* Enable TX Congestion control support
 * default is disable
 */
#define DPAA2_TX_CGR_OFF	RTE_BIT32(0)

/* Drop packets with parsing error in hw */
#define DPAA2_PARSE_ERR_DROP	RTE_BIT32(1)

/* Disable RX tail drop, default is enable */
#define DPAA2_RX_TAILDROP_OFF	RTE_BIT32(2)

/* Disable prefetch Rx mode to get exact requested packets */
#define DPAA2_NO_PREFETCH_RX	RTE_BIT32(3)

/* Driver level loop mode to simply transmit the ingress traffic */
#define DPAA2_RX_LOOPBACK_MODE	RTE_BIT32(4)

/* HW loopback the egress traffic to self ingress*/
#define DPAA2_TX_MAC_LOOPBACK_MODE	RTE_BIT32(5)

#define DPAA2_TX_SERDES_LOOPBACK_MODE	RTE_BIT32(6)

#define DPAA2_TX_DPNI_LOOPBACK_MODE	RTE_BIT32(7)

#define DPAA2_TX_PREFETCH_DYNAMIC_CONF	RTE_BIT32(8)

#define DPAA2_RX_ERROR_QUEUE_FLAG	RTE_BIT32(9)

#define DPAA2_RX_DATA_STASHING_OFF_FLAG	RTE_BIT32(10)

#define DPAA2_RX_SCHED_STRICT_ORDER_FLAG RTE_BIT32(11)

#define DPAA2_RX_PRINT_PSR_RESULT_FLAG RTE_BIT32(12)

#define DPAA2_IEEE1588_DEBUG_FLAG RTE_BIT32(13)

#define DPAA2_IEEE1588_TX_TS_FLAG RTE_BIT32(14)
#define DPAA2_IEEE1588_RX_TS_FLAG RTE_BIT32(15)

/* DPDMUX index for DPMAC */
#define DPAA2_DPDMUX_DPMAC_IDX 0

#define DPAA2_TX_LOOPBACK_MODE \
	(DPAA2_TX_MAC_LOOPBACK_MODE | \
	DPAA2_TX_SERDES_LOOPBACK_MODE | \
	DPAA2_TX_DPNI_LOOPBACK_MODE)

#define DPAA2_RSS_OFFLOAD_ALL ( \
	RTE_ETH_RSS_L2_PAYLOAD | \
	RTE_ETH_RSS_IP | \
	RTE_ETH_RSS_UDP | \
	RTE_ETH_RSS_TCP | \
	RTE_ETH_RSS_SCTP | \
	RTE_ETH_RSS_MPLS | \
	RTE_ETH_RSS_C_VLAN | \
	RTE_ETH_RSS_S_VLAN | \
	RTE_ETH_RSS_ESP | \
	RTE_ETH_RSS_AH | \
	RTE_ETH_RSS_PPPOE)

/* LX2 FRC Parsed values (Little Endian) */
#define DPAA2_PKT_TYPE_ETHER \
	(DPAA2_PSR_SUMMARY_NONIP << DPAA2_PSR_SUMMARY_NON_IP_L2_BIT_SIZE)
#define DPAA2_PKT_TYPE_IPV4 \
	(DPAA2_PSR_SUMMARY_IPV4 << DPAA2_PSR_SUMMARY_L4_BIT_SIZE)
#define DPAA2_PKT_TYPE_IPV6 \
	(DPAA2_PSR_SUMMARY_IPV6 << DPAA2_PSR_SUMMARY_L4_BIT_SIZE)

/**Tunnel*/
#define DPAA2_PKT_TYPE_L3_EXT \
	(DPAA2_PSR_SUMMARY_L4_EXT << DPAA2_PSR_SUMMARY_L4_EXT_L3_POS)
#define DPAA2_PKT_TYPE_L3_EXT_IPV4 \
	(DPAA2_PSR_SUMMARY_IPV4 << DPAA2_PSR_SUMMARY_L4_EXT_BIT_SIZE)
#define DPAA2_PKT_TYPE_L3_EXT_IPV6 \
	(DPAA2_PSR_SUMMARY_IPV6 << DPAA2_PSR_SUMMARY_L4_EXT_BIT_SIZE)
#define DPAA2_PKT_TYPE_IPV4_EXT \
	(DPAA2_PKT_TYPE_L3_EXT | DPAA2_PKT_TYPE_L3_EXT_IPV4)
#define DPAA2_PKT_TYPE_IPV6_EXT \
	(DPAA2_PKT_TYPE_L3_EXT | DPAA2_PKT_TYPE_L3_EXT_IPV6)
#define DPAA2_PKT_TYPE_IPV4_EXT_GRE_IPV4 \
	(DPAA2_PKT_TYPE_IPV4_EXT | DPAA2_PSR_SUMMARY_GRE_IPV4)
#define DPAA2_PKT_TYPE_IPV4_EXT_GRE_IPV4_UDP_TCP \
	(DPAA2_PKT_TYPE_IPV4_EXT | DPAA2_PSR_SUMMARY_GRE_IPV4_UDP_TCP)
#define DPAA2_PKT_TYPE_IPV4_EXT_GRE_IPV6 \
	(DPAA2_PKT_TYPE_IPV4_EXT | DPAA2_PSR_SUMMARY_GRE_IPV6)
#define DPAA2_PKT_TYPE_IPV4_EXT_GRE_IPV6_UDP_TCP \
	(DPAA2_PKT_TYPE_IPV4_EXT | DPAA2_PSR_SUMMARY_GRE_IPV6_UDP_TCP)
#define DPAA2_PKT_TYPE_IPV6_EXT_GRE_IPV4 \
	(DPAA2_PKT_TYPE_IPV6_EXT | DPAA2_PSR_SUMMARY_GRE_IPV4)
#define DPAA2_PKT_TYPE_IPV6_EXT_GRE_IPV4_UDP_TCP \
	(DPAA2_PKT_TYPE_IPV6_EXT | DPAA2_PSR_SUMMARY_GRE_IPV4_UDP_TCP)
#define DPAA2_PKT_TYPE_IPV6_EXT_GRE_IPV6 \
	(DPAA2_PKT_TYPE_IPV6_EXT | DPAA2_PSR_SUMMARY_GRE_IPV6)
#define DPAA2_PKT_TYPE_IPV6_EXT_GRE_IPV6_UDP_TCP \
	(DPAA2_PKT_TYPE_IPV6_EXT | DPAA2_PSR_SUMMARY_GRE_IPV6_UDP_TCP)

#define DPAA2_PKT_TYPE_IPV4_FRAG \
	(DPAA2_PSR_SUMMARY_IP_FRAG | DPAA2_PKT_TYPE_IPV4)
#define DPAA2_PKT_TYPE_IPV6_FRAG \
	(DPAA2_PSR_SUMMARY_IP_FRAG | DPAA2_PKT_TYPE_IPV6)
#define DPAA2_PKT_TYPE_IPV4_TCP \
	(DPAA2_PSR_SUMMARY_TCP | DPAA2_PKT_TYPE_IPV4)
#define DPAA2_PKT_TYPE_IPV6_TCP \
	(DPAA2_PSR_SUMMARY_TCP | DPAA2_PKT_TYPE_IPV6)
#define DPAA2_PKT_TYPE_IPV4_UDP \
	(DPAA2_PSR_SUMMARY_UDP | DPAA2_PKT_TYPE_IPV4)
#define DPAA2_PKT_TYPE_IPV6_UDP \
	(DPAA2_PSR_SUMMARY_UDP | DPAA2_PKT_TYPE_IPV6)
#define DPAA2_PKT_TYPE_IPV4_SCTP \
	(DPAA2_PSR_SUMMARY_SCTP | DPAA2_PKT_TYPE_IPV4)
#define DPAA2_PKT_TYPE_IPV6_SCTP \
	(DPAA2_PSR_SUMMARY_SCTP | DPAA2_PKT_TYPE_IPV6)
#define DPAA2_PKT_TYPE_IPV4_ICMP \
	(DPAA2_PSR_SUMMARY_ICMP | DPAA2_PKT_TYPE_IPV4)
#define DPAA2_PKT_TYPE_IPV6_ICMP \
	(DPAA2_PSR_SUMMARY_ICMP | DPAA2_PKT_TYPE_IPV6)
#define DPAA2_PKT_TYPE_IPV4_ESP \
	(DPAA2_PSR_SUMMARY_IPSEC_ESP | DPAA2_PKT_TYPE_IPV4)
#define DPAA2_PKT_TYPE_IPV6_ESP \
	(DPAA2_PSR_SUMMARY_IPSEC_ESP | DPAA2_PKT_TYPE_IPV6)
#define DPAA2_PKT_TYPE_IPV4_GTPU \
	(DPAA2_PSR_SUMMARY_GTPU | DPAA2_PKT_TYPE_IPV4)
#define DPAA2_PKT_TYPE_IPV6_GTPU \
	(DPAA2_PSR_SUMMARY_GTPU | DPAA2_PKT_TYPE_IPV6)
#define DPAA2_PKT_TYPE_IPV4_GTPC \
	(DPAA2_PSR_SUMMARY_GTPC | DPAA2_PKT_TYPE_IPV4)
#define DPAA2_PKT_TYPE_IPV6_GTPC \
	(DPAA2_PSR_SUMMARY_GTPC | DPAA2_PKT_TYPE_IPV6)

#define DPAA2_PKT_TYPE_VLAN_1	0x0100
#define DPAA2_PKT_TYPE_VLAN_2	0x0200
#define DPAA2_PKT_TYPE_VLAN \
	(DPAA2_PKT_TYPE_VLAN_1 | DPAA2_PKT_TYPE_VLAN_2)

/* mac counters */
#define DPAA2_MAC_NUM_STATS            (DPMAC_CNT_EGR_CONTROL_FRAME + 1)
#define DPAA2_MAC_STATS_INDEX_DMA_SIZE (DPAA2_MAC_NUM_STATS * sizeof(uint32_t))
#define DPAA2_MAC_STATS_VALUE_DMA_SIZE (DPAA2_MAC_NUM_STATS * sizeof(uint64_t))

/* Maximum SG segments */
#define DPAA2_MAX_SGS 128
/* Externally defined */
extern const struct rte_flow_ops dpaa2_flow_ops;

extern const struct rte_tm_ops dpaa2_tm_ops;

struct dpaa2_dyn_rx_protocol_pos {
	uint8_t l3_offset;
	uint8_t l4_offset;
	uint8_t l5_offset;
	uint8_t rsv;
};

#define L3_OFFSET_OF_MBUF_DYN 0
#define L4_OFFSET_OF_MBUF_DYN 1
#define L5_OFFSET_OF_MBUF_DYN 2

#define DPAA2_FS_FLC_FS_MARK_OFFSET \
	(DPAA2_FLC_DATA_STASHING + DPAA2_FLC_STASHING_MAX_BIT_SIZE)

#define DPAA2_FS_FLC_TC_OFFSET \
	(DPAA2_FS_FLC_FS_MARK_OFFSET + DPAA2_FLC_STASHING_MAX_BIT_SIZE)

#define DPAA2_FS_FLC_TC_BIT_SIZE (sizeof(uint8_t) * 8)
#define DPAA2_FS_FLC_TC_MASK ((1 << DPAA2_FS_FLC_TC_BIT_SIZE) - 1)

#define DPAA2_FS_FLC_FLOW_OFFSET \
	(DPAA2_FS_FLC_TC_OFFSET + DPAA2_FS_FLC_TC_BIT_SIZE)

#define DPAA2_ECPRI_MAX_EXTRACT_NB 8

#define DPAA2_IBTH_MAX_EXTRACT_NB 4

enum key_prot_type {
	/* HW extracts from standard protocol fields*/
	DPAA2_NET_PROT_KEY,
	/* HW extracts from FAF of PR*/
	DPAA2_FAF_KEY,
	/* HW extracts from PR other than FAF*/
	DPAA2_PR_KEY
};

struct key_prot_field {
	enum key_prot_type type;
	enum net_prot prot;
	uint32_t key_field;
};

struct dpaa2_ip_addr_extract {
	uint32_t field;
	uint8_t max_size;
};

struct dpaa2_key_profile {
	uint8_t num;
	uint8_t key_offset[DPKG_MAX_NUM_OF_EXTRACTS];
	uint8_t key_size[DPKG_MAX_NUM_OF_EXTRACTS];

	struct dpaa2_ip_addr_extract ip_addr_extracts[2];

	uint8_t l4_sp_present;
	uint8_t l4_sp_extract_idx;
	uint8_t l4_sp_key_offset;
	uint8_t l4_dp_present;
	uint8_t l4_dp_extract_idx;
	uint8_t l4_dp_key_offset;
	struct key_prot_field prot_field[DPKG_MAX_NUM_OF_EXTRACTS];
	uint16_t key_max_size;
};

struct dpaa2_flow_tbl_profile {
	struct dpkg_profile_cfg dpkg;
	struct dpaa2_key_profile key_profile;
	uint8_t *extract_param;
	int entry_num;
	uint8_t *entry_map;
	int enabled;
	int is_rss;
	void *rss_flow;
	union {
		struct dpni_qos_tbl_cfg qos_cfg;
		struct dpni_rx_dist_cfg tc_cfg;
	};
	int default_drop;
	union {
		struct rte_flow_action_jump default_jump;
		struct rte_flow_action_queue default_queue;
	};
};

struct dpaa2_flow_profile {
	struct dpaa2_flow_tbl_profile qos_profile;
	struct dpaa2_flow_tbl_profile tc_profile[MAX_TCS];
	/** Meter per TC.*/
	struct dpaa2_dev_meter_profile *tc_mtr_profile[MAX_TCS];
	void *mtr_flow[MAX_TCS];
	void *mempool[MAX_TCS];
	uint8_t bp_idx[MAX_TCS];
};

struct dpaa2_dev_meter_profile {
	LIST_ENTRY(dpaa2_dev_meter_profile) next;
	uint32_t profile_id;
	uint64_t cir;
	uint64_t cbs;
	uint64_t pir;
	uint64_t pbs;
	enum dpni_policer_mode mode;
	enum dpni_policer_unit policer_unit;
};

struct dpaa2_dev_meter_policy {
	LIST_ENTRY(dpaa2_dev_meter_policy) next;
	uint32_t policy_id;
	int red_drop;
};

struct dpaa2_dev_meter {
	LIST_ENTRY(dpaa2_dev_meter) next;
	uint32_t meter_id;
	uint32_t profile_id;
	uint32_t policy_id;
};

enum dpaa2_tx_conf_type {
	DPAA2_TX_NO_CONF,
	DPAA2_TX_ABSOLUTE_CONF,
	DPAA2_TX_DYNAMIC_CONF
};

struct dpaa2_dev_priv {
	void *hw;
	int32_t hw_id;
	int32_t qdid;
	uint16_t token;
	uint16_t tx_channels[DPAA2_MAX_CHANNELS];
	uint8_t nb_tx_queues;
	uint8_t nb_rx_queues;
	uint32_t options;
	void *rx_vq[MAX_RX_QUEUES];
	void *tx_vq[MAX_TX_QUEUES];
	struct dpaa2_bp_list *bp_list; /**<Attached buffer pool list */
	void *tx_conf_vq[MAX_TX_QUEUES];
	void *rx_err_vq;
	uint32_t flags; /*dpaa2 config flags */
	enum dpaa2_tx_conf_type tx_conf_type;
	int psr_dynfield_offset;
	uint8_t max_mac_filters;
	uint8_t max_vlan_filters;
	uint8_t num_rx_tc;
	uint8_t num_tx_tc;
	uint16_t qos_entries;
	uint16_t fs_entries;
	uint8_t dist_queues;
	uint8_t num_channels;
	uint8_t en_ordered;
	uint8_t en_loose_ordered;
	uint8_t max_cgs;
	/** RXQs in same TC share same cgid.*/
	uint8_t cgid_in_use[MAX_TCS];
	rte_spinlock_t meter_lock;

	uint16_t evq_attach_num;
	struct dpni_pools_cfg pools_cfg;

	uint16_t dpni_ver_major;
	uint16_t dpni_ver_minor;
	uint32_t speed_capa;

	enum rte_dpaa2_dev_type ep_dev_type;   /**< Endpoint Device Type */
	uint16_t ep_object_id;                 /**< Endpoint DPAA2 Object ID */
	char ep_name[RTE_DEV_NAME_MAX_LEN];

	struct dpaa2_flow_profile flow_profile;
	uint8_t nb_dcb_tcs;
	uint8_t prio_dcb_tc[RTE_ETH_DCB_NUM_USER_PRIORITIES];
	void *dcb_flow[RTE_ETH_DCB_NUM_USER_PRIORITIES];

	uint16_t ss_offset;
	uint64_t ss_iova;
	uint64_t ss_param_iova;
	/*stores timestamp of last received packet on dev*/
	uint64_t rx_timestamp;
	/*stores timestamp of last received tx confirmation packet on dev*/
	uint64_t tx_timestamp;

	int rx_ts_offset;
	uint64_t rx_ts_flag;
	/* stores next tx queue to be confirmed that should be processed,
	 * it corresponds to last packet transmitted
	 */
	struct dpaa2_queue *next_txq_to_cnf;
	bool sp_protocol;

	struct rte_eth_dev *eth_dev; /**< Pointer back to holding ethdev */
	rte_spinlock_t lpbk_qp_lock;

	bool enable_bp_flow_ctrl;
	uint8_t channel_inuse;
	/* Stores correction offset for one step timestamping,
	 * this offset varies according to current SYNC packet
	 * format. (eth/vlan/udp)
	 */
	uint16_t ptp_correction_offset;
	/* for mac counters */
	uint32_t *cnt_idx_dma_mem;
	uint64_t *cnt_values_dma_mem;
	uint64_t cnt_idx_iova, cnt_values_iova;
	uint64_t mc_rev;

	struct rte_mempool *tx_sg_pool;

	struct dpaa2_generic_flow *cur_flow;
	LIST_HEAD(, dpaa2_dev_flow) flows;
	LIST_HEAD(, dpaa2_dev_meter_profile) profiles;
	LIST_HEAD(, dpaa2_dev_meter_policy) policies;
	LIST_HEAD(, dpaa2_dev_meter) meters;
	LIST_HEAD(nodes, dpaa2_tm_node) nodes;
	LIST_HEAD(shaper_profiles, dpaa2_tm_shaper_profile) shaper_profiles;
};

#define DPNI_GET_MAC_SUPPORTED_IFS_VER_MAJOR	8
#define DPNI_GET_MAC_SUPPORTED_IFS_VER_MINOR	6

static inline int dpaa2_dev_cmp_dpni_ver(struct dpaa2_dev_priv *priv,
					 uint16_t ver_major, uint16_t ver_minor)
{
	if (priv->dpni_ver_major == ver_major)
		return priv->dpni_ver_minor - ver_minor;
	return priv->dpni_ver_major - ver_major;
}

#define DPAA2_FLOW_DUMP printf

static inline void
dpaa2_dev_rx_print_parser_result(struct dpaa2_dev_priv *priv,
	const struct qbman_fd *fd, const struct rte_mbuf *m)
{
	size_t fd_addr;
	void *hw_annot_addr;

	if (likely(!(priv->flags & DPAA2_RX_PRINT_PSR_RESULT_FLAG)))
		return;

	if (dpaa2_svr_family == SVR_LX2160A)
		dpaa2_print_fd_frc(fd);

	fd_addr = (size_t)DPAA2_IOVA_TO_VADDR(DPAA2_GET_FD_ADDR(fd));
	hw_annot_addr = (void *)(fd_addr + DPAA2_FD_PTA_SIZE);
	dpaa2_print_parse_result(hw_annot_addr, priv->sp_protocol);
	if (m->ol_flags & RTE_MBUF_F_RX_FDIR) {
		const struct rte_mbuf_sched *sched;
		uint16_t i;
		struct dpaa2_queue *rxq;

		sched = &m->hash.sched;
		for (i = 0; i < MAX_RX_QUEUES; i++) {
			rxq = priv->rx_vq[i];
			if (rxq->tc_index == sched->traffic_class &&
				rxq->flow_id == sched->queue_id)
				break;
		}
		fprintf(stdout, "Directed to %s-TC%d-flow%d(rxq%d), color(%d)\n",
			priv->eth_dev->data->name,
			sched->traffic_class, sched->queue_id, i, sched->color);
	} else if (m->ol_flags & RTE_MBUF_F_RX_RSS_HASH) {
		fprintf(stdout, "Balanced with hash(0x%08x)\n", m->hash.rss);
	}
}

static inline void
dpaa2_timestamp_debug(struct dpaa2_dev_priv *priv,
	const char *prefix, uint64_t timestamp)
{
	struct timespec ts;

	if (likely(!(priv->flags & DPAA2_IEEE1588_DEBUG_FLAG)))
		return;

	ts = rte_ns_to_timespec(timestamp);
	fprintf(stderr,
		"DPAA2 TS DBG: %s: ns(%" PRIu64 ")->%ld seconds/%ld nanoseconds\n",
		prefix, timestamp, ts.tv_sec, ts.tv_nsec);
}

static inline void
dpaa2_prot_field_string(uint32_t prot, uint32_t field,
	char *string)
{
	if (prot == NET_PROT_ETH) {
		strcpy(string, "eth");
		if (field == NH_FLD_ETH_DA)
			strcat(string, ".dst");
		else if (field == NH_FLD_ETH_SA)
			strcat(string, ".src");
		else if (field == NH_FLD_ETH_TYPE)
			strcat(string, ".type");
		else
			strcat(string, ".unknown field");
	} else if (prot == NET_PROT_VLAN) {
		strcpy(string, "vlan");
		if (field == NH_FLD_VLAN_TCI)
			strcat(string, ".tci");
		else
			strcat(string, ".unknown field");
	} else if (prot == NET_PROT_IP) {
		strcpy(string, "ip");
		if (field == NH_FLD_IP_SRC)
			strcat(string, ".src");
		else if (field == NH_FLD_IP_DST)
			strcat(string, ".dst");
		else if (field == NH_FLD_IP_PROTO)
			strcat(string, ".proto");
		else
			strcat(string, ".unknown field");
	} else if (prot == NET_PROT_TCP) {
		strcpy(string, "tcp");
		if (field == NH_FLD_TCP_PORT_SRC)
			strcat(string, ".src");
		else if (field == NH_FLD_TCP_PORT_DST)
			strcat(string, ".dst");
		else
			strcat(string, ".unknown field");
	} else if (prot == NET_PROT_UDP) {
		strcpy(string, "udp");
		if (field == NH_FLD_UDP_PORT_SRC)
			strcat(string, ".src");
		else if (field == NH_FLD_UDP_PORT_DST)
			strcat(string, ".dst");
		else
			strcat(string, ".unknown field");
	} else if (prot == NET_PROT_ICMP) {
		strcpy(string, "icmp");
		if (field == NH_FLD_ICMP_TYPE)
			strcat(string, ".type");
		else if (field == NH_FLD_ICMP_CODE)
			strcat(string, ".code");
		else
			strcat(string, ".unknown field");
	} else if (prot == NET_PROT_SCTP) {
		strcpy(string, "sctp");
		if (field == NH_FLD_SCTP_PORT_SRC)
			strcat(string, ".src");
		else if (field == NH_FLD_SCTP_PORT_DST)
			strcat(string, ".dst");
		else
			strcat(string, ".unknown field");
	} else if (prot == NET_PROT_GRE) {
		strcpy(string, "gre");
		if (field == NH_FLD_GRE_TYPE)
			strcat(string, ".type");
		else
			strcat(string, ".unknown field");
	} else if (prot == NET_PROT_GTP) {
		strcpy(string, "gtp");
		if (field == NH_FLD_GTP_TEID)
			strcat(string, ".teid");
		else
			strcat(string, ".unknown field");
	} else if (prot == NET_PROT_IPSEC_ESP) {
		strcpy(string, "esp");
		if (field == NH_FLD_IPSEC_ESP_SPI)
			strcat(string, ".spi");
		else if (field == NH_FLD_IPSEC_ESP_SEQUENCE_NUM)
			strcat(string, ".seq");
		else
			strcat(string, ".unknown field");
	} else {
		sprintf(string, "unknown protocol(%d)", prot);
	}
}

static inline void
dpaa2_dump_dpkg(const struct dpkg_profile_cfg *dpkg)
{
	int idx;
	char string[32];
	const struct dpkg_extract *extract;
	enum dpkg_extract_type type;
	enum net_prot prot;
	uint32_t field;

	for (idx = 0; idx < dpkg->num_extracts; idx++) {
		extract = &dpkg->extracts[idx];
		type = extract->type;
		if (type == DPKG_EXTRACT_FROM_HDR) {
			prot = extract->extract.from_hdr.prot;
			field = extract->extract.from_hdr.field;
			dpaa2_prot_field_string(prot, field, string);
		} else if (type == DPKG_EXTRACT_FROM_DATA) {
			sprintf(string, "raw offset/len: %d/%d",
				extract->extract.from_data.offset,
				extract->extract.from_data.size);
		} else if (type == DPKG_EXTRACT_FROM_PARSE) {
			sprintf(string, "parse offset/len: %d/%d",
				extract->extract.from_parse.offset,
				extract->extract.from_parse.size);
		}
		DPAA2_FLOW_DUMP("%s", string);
		if ((idx + 1) < dpkg->num_extracts)
			DPAA2_FLOW_DUMP(" / ");
		else
			DPAA2_FLOW_DUMP("\r\n\n");
	}
}

static inline int
dpaa2_extract_prev_ip_addr_pos(const struct dpaa2_key_profile *profile)
{
	int idx = -ENXIO;

	if (!profile->num)
		return -ENXIO;

	for (idx = profile->num - 1; idx >= 0; idx--) {
		if (!(profile->prot_field[idx].type == DPAA2_NET_PROT_KEY &&
			profile->prot_field[idx].prot == NET_PROT_IP &&
			(profile->prot_field[idx].key_field == NH_FLD_IP_SRC ||
			profile->prot_field[idx].key_field == NH_FLD_IP_DST)))
			break;
	}

	if (idx >= 0)
		return idx;
	return -ENXIO;
}

static inline int
dpaa2_extract_ip_addr_add(uint32_t field,
	struct dpaa2_key_profile *key_profile, uint8_t size,
	int *update, int *pos)
{
	struct dpaa2_ip_addr_extract *ip_addr_extracts;
	uint8_t i = 0;
	uint16_t max_size_save = key_profile->key_max_size;
	char log_buf[128];

	if (field != NH_FLD_IP_SRC && field != NH_FLD_IP_DST)
		return -EINVAL;

	max_size_save -= key_profile->ip_addr_extracts[0].max_size;
	max_size_save -= key_profile->ip_addr_extracts[1].max_size;
	ip_addr_extracts = key_profile->ip_addr_extracts;
	while (i < 2) {
		if (ip_addr_extracts[i].field == field) {
			if (size > ip_addr_extracts[i].max_size)
				ip_addr_extracts[i].max_size = size;
			break;
		}
		if (!ip_addr_extracts[i].field) {
			ip_addr_extracts[i].field = field;
			ip_addr_extracts[i].max_size = size;
			if (update)
				*update = 1;
			break;
		}
		i++;
	}
	if (i > 1) {
		sprintf(log_buf,
			"field[0](%d)/size[0](%d)/field[1](%d)/size[1](%d)",
			ip_addr_extracts[0].field,
			ip_addr_extracts[0].max_size,
			ip_addr_extracts[1].field,
			ip_addr_extracts[1].max_size);
		DPAA2_FLOW_DUMP("Invalid IP address extracts:%s\n",
			log_buf);
		return -EINVAL;
	}

	if (pos)
		*pos = i;

	max_size_save += key_profile->ip_addr_extracts[0].max_size;
	max_size_save += key_profile->ip_addr_extracts[1].max_size;
	key_profile->key_max_size = max_size_save;

	return 0;
}

static inline uint8_t
dpaa2_profile_insert_no_ipaddr_extract(struct dpaa2_key_profile *profile,
	uint8_t size, uint8_t *poffset, int *ppos,
	const struct key_prot_field *prot)
{
	uint8_t idx, ip_addr_num = 0, offset;

	if (profile->ip_addr_extracts[0].field &&
		profile->ip_addr_extracts[1].field) {
		idx = profile->num - 2;
		ip_addr_num = 2;
	} else if (profile->ip_addr_extracts[0].field) {
		idx = profile->num - 1;
		ip_addr_num = 1;
	} else {
		idx = profile->num;
	}

	if (idx > 0)
		offset = profile->key_offset[idx - 1] + profile->key_size[idx - 1];
	else
		offset = 0;

	if (idx > 0) {
		profile->key_offset[idx] =
			profile->key_offset[idx - 1] + profile->key_size[idx - 1];
	} else {
		profile->key_offset[idx] = 0;
	}
	if (ppos)
		*ppos = profile->key_offset[idx];
	profile->key_size[idx] = size;
	profile->key_max_size += size;
	profile->num++;

	if (ip_addr_num > 0) {
		memmove(&profile->prot_field[idx + 1],
			&profile->prot_field[idx],
			sizeof(struct key_prot_field) * ip_addr_num);
	}
	if (poffset)
		*poffset = offset;

	if (prot) {
		rte_memcpy(&profile->prot_field[idx], prot,
			sizeof(struct key_prot_field));
	}

	return idx;
}

static inline void
dpaa2_dpkg_insert_extract(struct dpkg_profile_cfg *kg_cfg,
	int idx, const struct dpkg_extract *extract)
{
	int i;

	if (idx != kg_cfg->num_extracts) {
		/* Not the last extract index, must have IP address extract.*/
		for (i = kg_cfg->num_extracts - 1; i >= idx; i--) {
			rte_memcpy(&kg_cfg->extracts[i + 1],
				&kg_cfg->extracts[i], sizeof(struct dpkg_extract));
		}
	}

	rte_memcpy(&kg_cfg->extracts[idx], extract, sizeof(struct dpkg_extract));
	kg_cfg->num_extracts++;
}

__rte_internal
int dpaa2_eth_eventq_attach(const struct rte_eth_dev *dev,
	uint16_t queue_id, struct dpaa2_dpcon_dev *dpcon,
	const struct rte_event_eth_rx_adapter_queue_conf *queue_conf,
	int ignore_sched_type);
__rte_internal
int
dpaa2_eth_eventq_detach_by_rxq(struct dpaa2_queue *dpaa2_ethq);
__rte_internal
int
dpaa2_eth_eventq_detach(const struct rte_eth_dev *dev,
	uint16_t queue_id);

uint16_t dpaa2_dev_rx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts);

uint16_t dpaa2_dev_loopback_rx(void *queue, struct rte_mbuf **bufs,
				uint16_t nb_pkts);

uint16_t dpaa2_dev_prefetch_rx(void *queue, struct rte_mbuf **bufs,
			       uint16_t nb_pkts);
void dpaa2_dev_process_parallel_event(struct dpaa2_dpio_dev *dpio_dev,
		const struct qbman_fd *fd, const struct qbman_result *dq,
		struct dpaa2_queue *rxq, struct rte_event *ev);
void dpaa2_dev_process_atomic_event(struct dpaa2_dpio_dev *dpio_dev,
		const struct qbman_fd *fd, const struct qbman_result *dq,
		struct dpaa2_queue *rxq, struct rte_event *ev);
void dpaa2_dev_process_ordered_event(struct dpaa2_dpio_dev *dpio_dev,
		const struct qbman_fd *fd, const struct qbman_result *dq,
		struct dpaa2_queue *rxq, struct rte_event *ev);
uint16_t
dpaa2_dev_tx(void *queue,
	struct rte_mbuf **bufs, uint16_t nb_pkts);

uint16_t dpaa2_dev_tx_ordered(void *queue, struct rte_mbuf **bufs,
			      uint16_t nb_pkts);
__rte_internal
uint16_t dpaa2_dev_tx_multi_txq_ordered(void **queue,
		struct rte_mbuf **bufs, uint16_t nb_pkts);

void dpaa2_dev_free_eqresp_buf(uint16_t eqresp_ci, struct dpaa2_queue *dpaa2_q);
void dpaa2_flow_clean(struct rte_eth_dev *dev, uint8_t tc_id);
uint16_t dpaa2_dev_tx_conf(void *txq, int drain);

void
dpaa2_dev_tx_ptp_one_step_runtime(struct rte_eth_dev *dev,
	struct rte_mbuf *buf, int *tstamp, int *set);
int dpaa2_timesync_enable(struct rte_eth_dev *dev);
int dpaa2_timesync_disable(struct rte_eth_dev *dev);
int dpaa2_timesync_read_time(struct rte_eth_dev *dev,
					struct timespec *timestamp);
int dpaa2_timesync_write_time(struct rte_eth_dev *dev,
					const struct timespec *timestamp);
int dpaa2_timesync_adjust_time(struct rte_eth_dev *dev, int64_t delta);
int dpaa2_timesync_read_rx_timestamp(struct rte_eth_dev *dev,
						struct timespec *timestamp,
						uint32_t flags __rte_unused);
int dpaa2_timesync_read_tx_timestamp(struct rte_eth_dev *dev,
					  struct timespec *timestamp);

int dpaa2_dev_recycle_config(struct rte_eth_dev *eth_dev);
int dpaa2_dev_recycle_deconfig(struct rte_eth_dev *eth_dev);

int
rte_pmd_dpaa2_dev_recycle_qp_setup(struct rte_dpaa2_device *dpaa2_dev,
	uint16_t qidx, uint64_t cntx,
	eth_tx_burst_t tx_lpbk, eth_rx_burst_t rx_lpbk,
	struct dpaa2_queue **txq,
	struct dpaa2_queue **rxq);

__rte_internal
struct rte_mbuf *__rte_hot
dpaa2_eth_fd_to_mbuf(struct dpaa2_dev_priv *priv, const struct qbman_fd *fd);
__rte_internal
struct rte_mbuf *__rte_hot
dpaa2_eth_sg_fd_to_mbuf(struct dpaa2_dev_priv *priv, const struct qbman_fd *fd);

int
dpaa2_mtr_ops_get(struct rte_eth_dev *dev, void *ops);

#endif /* _DPAA2_ETHDEV_H */

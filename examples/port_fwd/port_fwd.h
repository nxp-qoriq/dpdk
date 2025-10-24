/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2022, 2024-2025 NXP
 * Code was mostly borrowed from examples/l3fwd/l3fwd.h
 * See examples/l3fwd/l3fwd.h for additional Copyrights.
 */

#ifndef __PORT_FWD_H__
#define __PORT_FWD_H__

#define MAX_PKT_BURST     32

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_LCORE 16

/*
 * Try to avoid TX buffering if we have at least MAX_TX_BURST packets to send.
 */
#define	MAX_TX_BURST	  (MAX_PKT_BURST / 2)

#define NB_SOCKETS        8

struct mbuf_table {
	uint16_t len;
	struct rte_mbuf *m_table[MAX_PKT_BURST];
};

struct lcore_rx_queue {
	uint16_t port_id;
	uint8_t queue_id;
	void *send_q;
	void *recv_q;
	struct rte_ip_frag_tbl *tbl;
	struct rte_ip_frag_death_row dr;
} __rte_cache_aligned;

struct lcore_tx_queue {
	void *tx_ring;
	uint16_t port_id;
	uint8_t queue_id;
} __rte_cache_aligned;

struct lcore_statistic {
	uint64_t packets;
	uint64_t bytes;
	uint64_t bytes_fcs;
	uint64_t bytes_overhead;
};

#include "rte_tm.h"

#define PKTGEN_ETH_FCS_SIZE \
	(RTE_TM_ETH_FRAMING_OVERHEAD_FCS - RTE_TM_ETH_FRAMING_OVERHEAD)

#define PKTGEN_ETH_OVERHEAD_SIZE \
	RTE_TM_ETH_FRAMING_OVERHEAD_FCS

struct lcore_conf {
	uint16_t n_rx_queue;
	struct lcore_rx_queue rx_queue_list[MAX_RX_QUEUE_PER_LCORE];
	uint16_t n_tx_queue;
	struct lcore_tx_queue tx_queue_list[MAX_TX_QUEUE_PER_LCORE];
	struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];

	struct lcore_statistic tx_statistic[RTE_MAX_ETHPORTS];
	struct lcore_statistic rx_statistic[RTE_MAX_ETHPORTS];
	uint32_t tx_ip[RTE_MAX_ETHPORTS];

	uint64_t tx_jumbo_count[RTE_MAX_ETHPORTS];
	uint64_t tx_jumbo_bytes[RTE_MAX_ETHPORTS];
	uint64_t rx_reassemble_count[RTE_MAX_ETHPORTS];
	uint64_t rx_reassemble_bytes[RTE_MAX_ETHPORTS];
	char *dump_buf;
} __rte_cache_aligned;

#endif  /* __PORT_FWD_H__ */

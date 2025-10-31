/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 * Copyright 2024-2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>
#include <rte_pmd_dpaa2.h>
#include <rte_mtr.h>
#include "rte_tm.h"

#define L2FWD_POLICER_FCS_SIZE \
	(RTE_TM_ETH_FRAMING_OVERHEAD_FCS - RTE_TM_ETH_FRAMING_OVERHEAD)

#define L2FWD_POLICER_PRINT_INTERVAL 5
/* Traffic classes */
enum {
	POLICER_TC0 = 0,
	POLICER_TC1,
	POLICER_TC2,
	POLICER_TC3,
	POLICER_TC4,
	POLICER_TC5,
	POLICER_TC6,
	POLICER_TC7,
	POLICER_TC_MAX_NUM
};

#define MAX_QUEUE_NUM_PER_TC 128

#define POLICER_CIR_DEFAULT 2000
#define POLICER_CBS_DEFAULT 10240
#define POLICER_PIR_DEFAULT 2000
#define POLICER_PBS_DEFAULT 20480

#define POLICER_COLOR_BLIND 0
#define POLICER_COLOR_AWARE 1

#define POLICER_UNIT_BYTES_L3              0
#define POLICER_UNIT_FRAMES                1
#define POLICER_UNIT_BYTES_L2_WITHOUT_FCS  2

#define MAX_ITEM_NUM 4
#define MAX_ACTION_NUM 4

#define POLICER_VLAN_ID 100
#define POLICER_UPDATE_SKIP_HINT "enter to skip"

struct l2fwd_policer_meter_param {
	uint32_t *meter_id;
	uint32_t *profile_id;
	uint32_t *policy_id;

	struct rte_meter_trtcm_params trtcm;
	struct rte_flow_action red_action;
};

struct l2fwd_policer_tc_desc {
	int valid;

	/** Meter per TC.*/
	struct l2fwd_policer_meter_param meter_param;
	void **one_level_flows;
	void **fs_flows;
	struct rte_flow_item *fs_update_pattern;
	uint16_t item_update_idx;
	uint16_t action_update_idx;
	uint16_t *flow_queue_ids;
	uint16_t *tc_queue_ids;
	uint16_t fs_max_num;
	uint16_t queue_max_num;
	uint16_t default_queue;
	int miss_drop;
	void *meter_flow;
};

#ifndef VLAN_PRIO_SHIFT
#define VLAN_PRIO_SHIFT	13
#endif

#define RTE_LOGTYPE_L2FWD_POLICER RTE_LOGTYPE_USER1

#define MAX_PKT_BURST 32
#define MEMPOOL_CACHE_SIZE 256

static volatile bool force_quit;

static uint16_t s_vlan_id = POLICER_VLAN_ID;

static int s_miss_drop;

/* MAC updating enabled by default */
static int mac_updating = 1;

/* Ports set in promiscuous mode off by default. */
static int promiscuous_on;

/* Flow classification enabled by default */
static int enable_flow = 1;

static int s_flow_table_level = 2;

static int tx_multi_ports = 1;

static int s_print_stat;

#define PORT_MAX_FLOWS 128

enum {
	ACTION_POLICER_PROFILE_UPDATE = (1 << 0),
	ACTION_POLICER_POLICY_UPDATE = (1 << 1),
	ACTION_QOS_JUMP_UPDATE = (1 << 2),
	ACTION_FS_QUEUE_UPDATE = (1 << 3),
	ACTION_MISS_QOS_UPDATE = (1 << 4),
	ACTION_MISS_FS_UPDATE = (1 << 5),
	ITEM_QOS_FLOW_UPDATE = (1 << 6),
	ITEM_FS_FLOW_UPDATE = (1 << 7)
};

/* port and vlan id pair configuration */
struct l2fwd_policer_port_params {
	int enable;
	int flow_tb_level;
	void **qos_flows;
	uint8_t *tc_ids;
	struct rte_flow_item *qos_update_pattern;
	uint8_t qos_update_idx;
	uint16_t max_qos_entries;
	int miss_drop;
	uint8_t default_tc;
	struct l2fwd_policer_tc_desc *tc_descs;
	uint16_t max_tcs;
};

static struct l2fwd_policer_port_params s_port_param[RTE_MAX_ETHPORTS];

/* policer default configuration */
static int s_policer_unit = POLICER_UNIT_BYTES_L2_WITHOUT_FCS;
static int s_default_color = RTE_COLOR_GREEN;
static uint32_t s_color_option = POLICER_COLOR_AWARE;
static enum rte_flow_action_type s_red_action = RTE_FLOW_ACTION_TYPE_DROP;

static uint32_t s_cir = POLICER_CIR_DEFAULT;
static uint32_t s_cbs = POLICER_CBS_DEFAULT;
static uint32_t s_pir = POLICER_PIR_DEFAULT;
static uint32_t s_pbs = POLICER_PBS_DEFAULT;

static uint16_t s_meter_action = RTE_FLOW_ACTION_TYPE_METER_MARK;

struct policer_item_update {
	const char *item_protocol;
	const char *item_field;
	const char *input_format;
	struct rte_flow_item pattern[2];
	uint8_t spec[512];
	uint8_t mask[512];
	int (*item_parse)(const char *str, struct policer_item_update *item);
};

static int
l2fwd_policer_item_eth_parse(const char *str,
	struct policer_item_update *item_update)
{
	const char *token = str;
	char *endptr;
	uint64_t byte;
	int i = 0;
	uint8_t bytes[RTE_ETHER_ADDR_LEN];
	struct rte_flow_item_eth *spec = (void *)item_update->spec;
	struct rte_flow_item_eth *mask = (void *)item_update->mask;

	if (!str || !item_update)
		return -EINVAL;

	while (i < RTE_ETHER_ADDR_LEN && *token != '\0') {
		byte = strtoul(token, &endptr, 16);
		if (byte > 0xFF || endptr == token)
			return -EINVAL;
		if (i < (RTE_ETHER_ADDR_LEN - 1) && *endptr != ':')
			return -EINVAL;
		bytes[i] = (uint8_t)byte;
		if (*endptr == ':')
			token = endptr + 1;
		i++;
	}

	item_update->pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	memset(spec, 0, sizeof(struct rte_flow_item_eth));
	memset(mask, 0, sizeof(struct rte_flow_item_eth));
	rte_memcpy(spec->src.addr_bytes,
		bytes, RTE_ETHER_ADDR_LEN);
	memset(mask->src.addr_bytes, 0xff, RTE_ETHER_ADDR_LEN);
	item_update->pattern[0].spec = spec;
	item_update->pattern[0].mask = mask;
	item_update->pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

	return 0;
}

static int
l2fwd_policer_item_vlan_parse(const char *str,
	struct policer_item_update *item_update)
{
	char *endptr;
	uint16_t tci;
	struct rte_flow_item_vlan *spec = (void *)item_update->spec;
	struct rte_flow_item_vlan *mask = (void *)item_update->mask;

	if (!str || !item_update)
		return -EINVAL;

	tci = strtoul(str, &endptr, 16);
	if (endptr == str)
		return -EINVAL;

	item_update->pattern[0].type = RTE_FLOW_ITEM_TYPE_VLAN;
	memset(spec, 0, sizeof(struct rte_flow_item_vlan));
	memset(mask, 0, sizeof(struct rte_flow_item_vlan));
	spec->tci = rte_cpu_to_be_16(tci);
	mask->tci = 0xffff;
	item_update->pattern[0].spec = spec;
	item_update->pattern[0].mask = mask;
	item_update->pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

	return 0;
}

static int
l2fwd_policer_item_ipv4_parse(const char *str,
	struct policer_item_update *item_update)
{
	const char *token = str;
	char *endptr;
	uint64_t byte, i = 0;
	rte_be32_t ip_addr;
	uint8_t *bytes = (void *)&ip_addr;
	struct rte_flow_item_ipv4 *spec = (void *)item_update->spec;
	struct rte_flow_item_ipv4 *mask = (void *)item_update->mask;

	if (!str || !item_update)
		return -EINVAL;

	while (i < sizeof(rte_be32_t) && *token != '\0') {
		byte = strtoul(token, &endptr, 10);
		if (byte > 0xFF || endptr == token)
			return -EINVAL;
		if (i < (sizeof(rte_be32_t) - 1) && *endptr != '.')
			return -EINVAL;
		bytes[i] = (uint8_t)byte;
		if (*endptr == '.')
			token = endptr + 1;
		i++;
	}

	item_update->pattern[0].type = RTE_FLOW_ITEM_TYPE_IPV4;
	memset(spec, 0, sizeof(struct rte_flow_item_ipv4));
	memset(mask, 0, sizeof(struct rte_flow_item_ipv4));
	spec->hdr.src_addr = ip_addr;
	mask->hdr.src_addr = 0xffffffff;
	item_update->pattern[0].spec = spec;
	item_update->pattern[0].mask = mask;
	item_update->pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

	return 0;
}

struct policer_item_update s_qos_item_update[] = {
	{
		.item_protocol = "eth",
		.item_field = "src",
		.input_format = "xx:xx:xx:xx:xx:xx",
		.item_parse = l2fwd_policer_item_eth_parse
	},
	{
		.item_protocol = "vlan",
		.item_field = "tci",
		.input_format = "hex 16 bits",
		.item_parse = l2fwd_policer_item_vlan_parse
	},
	{
		.item_protocol = "ipv4",
		.item_field = "src",
		.input_format = "x.x.x.x",
		.item_parse = l2fwd_policer_item_ipv4_parse
	}
};

struct policer_item_update s_fs_item_update[] = {
	{
		.item_protocol = "eth",
		.item_field = "src",
		.input_format = "xx:xx:xx:xx:xx:xx",
		.item_parse = l2fwd_policer_item_eth_parse
	},
	{
		.item_protocol = "vlan",
		.item_field = "tci",
		.input_format = "hex 16 bits",
		.item_parse = l2fwd_policer_item_vlan_parse
	},
	{
		.item_protocol = "ipv4",
		.item_field = "src",
		.input_format = "x.x.x.x",
		.item_parse = l2fwd_policer_item_ipv4_parse
	}
};

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RX_DESC_DEFAULT 1024
#define TX_DESC_DEFAULT 1024
static uint16_t nb_rxd = RX_DESC_DEFAULT;
static uint16_t nb_txd = TX_DESC_DEFAULT;

/* ethernet addresses of ports */
static struct rte_ether_addr l2fwd_policer_ports_eth_addr[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
static uint32_t l2fwd_policer_enabled_port_mask = 0;

/* list of enabled ports */
static uint32_t l2fwd_policer_dst_ports[RTE_MAX_ETHPORTS];

#define MAX_RX_QUEUE_PER_LCORE 16
/* List of queues to be polled for a given lcore. 8< */

struct port_rxq_pair {
	uint16_t port_id;
	uint16_t queue_id;
};

struct lcore_queue_conf {
	void *sch_handle;
	uint16_t n_rx_port;
	struct port_rxq_pair rx_port_list[MAX_RX_QUEUE_PER_LCORE];
};

static struct lcore_queue_conf s_lcore_queue_conf[RTE_MAX_LCORE];
static int s_port_queue_nb[RTE_MAX_LCORE];
/* >8 End of list of queues to be polled for a given lcore. */

static struct rte_eth_conf port_conf = {
	.txmode = {
		.mq_mode = RTE_ETH_MQ_TX_NONE,
	},
};

struct rte_mempool *l2fwd_policer_pktmbuf_pool;

/* Per-port statistics struct */
struct l2fwd_policer_port_statistics {
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
} __rte_cache_aligned;

struct l2fwd_policer_byte_statistics {
	uint64_t bytes;
	uint64_t bytes_fcs;
	uint64_t bytes_overhead;
};

#define L2FWD_POLICER_MBUF_FCS(mbuf) \
	(mbuf->pkt_len + L2FWD_POLICER_FCS_SIZE * mbuf->nb_segs)

#define L2FWD_POLICER_MBUF_OVERHEAD(mbuf) \
	(mbuf->pkt_len + RTE_TM_ETH_FRAMING_OVERHEAD_FCS * mbuf->nb_segs)

static struct l2fwd_policer_port_statistics port_statistics[RTE_MAX_ETHPORTS];
static struct l2fwd_policer_byte_statistics *tc_statistics;
static struct l2fwd_policer_byte_statistics *prev_tc_statistics;

#define MAX_TIMER_PERIOD 86400 /* 1 day max */
/* A tsc-based timer responsible for triggering statistics printout */
static uint16_t timer_period = L2FWD_POLICER_PRINT_INTERVAL;

#define POLICER_UPDATE_RED_DROP "red drop"
#define POLICER_UPDATE_RED_PASS "red pass"

enum policer_id_type {
	POLICER_METER_ID_TYPE,
	POLICER_PROFILE_ID_TYPE,
	POLICER_POLICY_ID_TYPE,
	POLICER_ID_TYPE_MAX
};
static struct rte_ring *s_id_pool[RTE_MAX_ETHPORTS][POLICER_ID_TYPE_MAX];

#define POLICER_MAX_ID_NUM 64
static uint32_t s_meter_ids[RTE_MAX_ETHPORTS][POLICER_MAX_ID_NUM];
static uint32_t s_profile_ids[RTE_MAX_ETHPORTS][POLICER_MAX_ID_NUM];
static uint32_t s_policy_ids[RTE_MAX_ETHPORTS][POLICER_MAX_ID_NUM];

static inline uint16_t
l2fwd_policer_tc_map_vlan_prio(uint16_t tc)
{
	return tc << VLAN_PRIO_SHIFT;
}

/* Print out statistics on packets dropped */
static void *l2fwd_policer_print_stats(void *arg)
{
	uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
	unsigned portid;
	int i;
	struct l2fwd_policer_byte_statistics *curr, *prev;
	double tc_diff;

	RTE_SET_USED(arg);

	total_packets_dropped = 0;
	total_packets_tx = 0;
	total_packets_rx = 0;

	const char clr[] = { 27, '[', '2', 'J', '\0' };
	const char topLeft[] = { 27, '[', '1', ';', '1', 'H','\0' };

		/* Clear screen and move to top left */
again:
	if (!s_print_stat)
		goto skip_print;
	printf("%s%s", clr, topLeft);

	printf("\nPort statistics ====================================");

	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
		/* skip disabled ports */
		if ((l2fwd_policer_enabled_port_mask & (1 << portid)) == 0)
			continue;
		printf("\nStatistics for port %u ------------------------------"
			   "\nPackets sent: %24"PRIu64
			   "\nPackets received: %20"PRIu64
			   "\nPackets dropped: %21"PRIu64,
			   portid,
			   port_statistics[portid].tx,
			   port_statistics[portid].rx,
			   port_statistics[portid].dropped);

		total_packets_dropped += port_statistics[portid].dropped;
		total_packets_tx += port_statistics[portid].tx;
		total_packets_rx += port_statistics[portid].rx;
		for (i = 0; i < s_port_param[portid].max_tcs; i++) {
			if (!s_port_param[portid].tc_descs[i].valid)
				continue;
			curr = tc_statistics + portid * POLICER_TC_MAX_NUM + i;
			prev = prev_tc_statistics + portid * POLICER_TC_MAX_NUM + i;
			if (!curr->bytes_overhead)
				continue;
			tc_diff = curr->bytes_overhead - prev->bytes_overhead;
			printf("\nPort%d.TC%d: %fGbps, %ld\r\n",
				portid, i, tc_diff * 8 / timer_period /
				(1000 * 1000 * 1000),
				curr->bytes_overhead * 8);
			prev->bytes = curr->bytes;
			prev->bytes_fcs = curr->bytes_fcs;
			prev->bytes_overhead = curr->bytes_overhead;
		}
	}
	printf("\nAggregate statistics ==============================="
		   "\nTotal packets sent: %18"PRIu64
		   "\nTotal packets received: %14"PRIu64
		   "\nTotal packets dropped: %15"PRIu64,
		   total_packets_tx,
		   total_packets_rx,
		   total_packets_dropped);
	printf("\n====================================================\n");

skip_print:
	fflush(stdout);
	sleep(timer_period);
	goto again;

	return NULL;
}

static void
l2fwd_policer_mac_updating(struct rte_mbuf *m, unsigned dest_portid)
{
	struct rte_ether_hdr *eth;
	void *tmp;

	eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	/* 02:00:00:00:00:xx */
	tmp = &eth->dst_addr.addr_bytes[0];
	*((uint64_t *)tmp) = 0x000000000002 + ((uint64_t)dest_portid << 40);

	/* src addr */
	rte_ether_addr_copy(&l2fwd_policer_ports_eth_addr[dest_portid], &eth->src_addr);
}

/* Simple forward. 8< */
static void
l2fwd_policer_simple_forward(struct rte_mbuf *m, uint16_t dst_port)
{
	uint16_t sent;

	sent = rte_eth_tx_burst(dst_port, 0, &m, 1);
	if (sent)
		port_statistics[dst_port].tx += sent;
}
/* >8 End of simple forward. */

/* main processing loop */
static void
l2fwd_policer_main_loop(void)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *m;
	uint16_t sent, rx_port, lcore_id, i, nb_rx;
	struct lcore_queue_conf *qconf;
	uint16_t tx_ports[MAX_PKT_BURST];
	struct rte_mbuf_sched *sched;
	struct l2fwd_policer_byte_statistics *statics;

	lcore_id = rte_lcore_id();
	qconf = &s_lcore_queue_conf[lcore_id];

	if (qconf->n_rx_port == 0) {
		RTE_LOG(WARNING, L2FWD_POLICER,
			"lcore %u has nothing to do\n", lcore_id);
		return;
	}

	RTE_LOG(INFO, L2FWD_POLICER,
		"entering main loop on lcore %u\n", lcore_id);

	while (!force_quit) {
		nb_rx = rte_dpaa2_scheduler_rx(qconf->sch_handle,
			pkts_burst, MAX_PKT_BURST);
		if (unlikely(!nb_rx))
			continue;

		for (i = 0; i < nb_rx; i++) {
			m = pkts_burst[i];
			rx_port = m->port;
			if (m->ol_flags & RTE_MBUF_F_RX_FDIR) {
				sched = &m->hash.sched;
				statics = tc_statistics +
					rx_port * POLICER_TC_MAX_NUM + sched->traffic_class;
				statics->bytes += m->pkt_len;
				statics->bytes_fcs += L2FWD_POLICER_MBUF_FCS(m);
				statics->bytes_overhead += L2FWD_POLICER_MBUF_OVERHEAD(m);
			}
			port_statistics[rx_port].rx++;
			tx_ports[i] = l2fwd_policer_dst_ports[rx_port];
			if (mac_updating)
				l2fwd_policer_mac_updating(m, tx_ports[i]);
			if (!tx_multi_ports)
				l2fwd_policer_simple_forward(pkts_burst[i], tx_ports[i]);
		}
		if (tx_multi_ports) {
			sent = rte_dpaa2_dev_tx_multi_ports(tx_ports,
				NULL, pkts_burst, nb_rx);
			for (i = 0; i < sent; i++)
				port_statistics[tx_ports[i]].tx++;
		}
		/* End of read packet from RX queues. */
	}
}

static int
l2fwd_policer_launch_one_lcore(__rte_unused void *dummy)
{
	l2fwd_policer_main_loop();
	return 0;
}

/* display usage */
static void
l2fwd_policer_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK [-P] [-q NQ]\n"
		"  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
		"  -P : Enable promiscuous mode\n"
		"  -T PERIOD: statistics will be refreshed each PERIOD seconds (0 to disable, 10 default, 86400 maximum)\n"
		"  --no-mac-updating: Disable MAC addresses updating (enabled by default)\n"
		"      When enabled:\n"
		"       - The source MAC address is replaced by the TX port MAC address\n"
		"       - The destination MAC address is replaced by 02:00:00:00:00:TX_PORT_ID\n"
		"  --enable-flow: Enable/Disable vlan flow control (default is enable)\n"
		"  --color: configure policer color (color_aware, color_blind)\n"
		"	  Default: color_aware\n"
		"  --policer_unit: configure policer unit (bytes_l2, bytes_l3, frames)\n"
		"      Default: bytes_l2\n"
		"  --default_color: configure policer default color (red, yellow or green)\n"
		"      Default: green\n"
		"  --red_action: configure action of packet marked as red (red drop or red pass)\n"
		"      Default: red drop\n"
		"  -cir NUM in bytes/frames as selected\n"
		"  -cbs NUM bytes/frames as selected\n"
		"  -pir NUM bytes/frames as selected\n"
		"  -pbs NUM bytes/frames as selected\n"
		"  NOTE: In bytes mode, configure L3 rate(kbps) in cir and pir\n"
		"  --meter_action: Configure meter flow action type (meter_mark or meter)\n"
		"      Default: meter_mark, directly get profile and(or) policy to\n"
		"      configure flow action dynamically.\n"
		"  --vlan_id vlan ID selected to configure QoS flow\n"
		"  --queue_config: Configure (port,queue,core)\n"
		"  --tx_multi_ports: 0 disable, 1 enable, Default: enable.\n"
		"  --flow_table_level: 1 or 2.\n"
		"  --print_stat: Print port and TC traffic statistics.\n",
		prgname);
}

static int
l2fwd_policer_parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;

	return pm;
}

static int
l2fwd_policer_parse_timer_period(const char *q_arg)
{
	char *end = NULL;
	int n;

	/* parse number string */
	n = strtol(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;
	if (n >= MAX_TIMER_PERIOD)
		return -1;

	return n;
}

static void
l2fwd_policer_parse_color_option(const char *optarg)
{
	if (!strcmp(optarg, "color_aware")) {
		s_color_option = POLICER_COLOR_AWARE;
	} else if (!strcmp(optarg, "color_blind")) {
		s_color_option = POLICER_COLOR_BLIND;
	} else {
		RTE_LOG(ERR, L2FWD_POLICER,
			"Invalid color policer option: %s\n", optarg);
	}
}

static void
l2fwd_policer_parse_red_action_option(const char *optarg)
{
	if (!strcmp(optarg, POLICER_UPDATE_RED_DROP)) {
		s_red_action = RTE_FLOW_ACTION_TYPE_DROP;
	} else if (!strcmp(optarg, POLICER_UPDATE_RED_PASS)) {
		s_red_action = RTE_FLOW_ACTION_TYPE_PASSTHRU;
	} else {
		RTE_LOG(ERR, L2FWD_POLICER,
			"Invalid red action option: %s\n", optarg);
	}
}

static void
l2fwd_policer_parse_rate_unit(const char *optarg)
{
	if (!strcmp(optarg, "frames")) {
		s_policer_unit = POLICER_UNIT_FRAMES;
	} else if (!strcmp(optarg, "bytes_l3")) {
		s_policer_unit = POLICER_UNIT_BYTES_L3;
	} else if (!strcmp(optarg, "bytes_l2")) {
		s_policer_unit = POLICER_UNIT_BYTES_L2_WITHOUT_FCS;
	} else {
		s_policer_unit = POLICER_UNIT_BYTES_L2_WITHOUT_FCS;
		RTE_LOG(ERR, L2FWD_POLICER,
			"Invalid Policer Unit, default set to L2 Bytes!!\n");
	}
}

static void
l2fwd_policer_parse_default_color(const char *optarg)
{
	if (!strcmp(optarg, "red")) {
		s_default_color = RTE_COLOR_RED;
	} else if (!strcmp(optarg, "yellow")) {
		s_default_color = RTE_COLOR_YELLOW;
	} else if (!strcmp(optarg, "green")) {
		s_default_color = RTE_COLOR_GREEN;
	} else {
		RTE_LOG(ERR, L2FWD_POLICER,
			"Invalid default color, set to GREEN!\n");
		s_default_color = RTE_COLOR_GREEN;
	}
}

static int
l2fwd_policer_parse_queue_config(const char *optarg)
{
	char s[256];
	const char *p, *p0 = optarg;
	char *end;
	enum fieldnames {
		FLD_PORT = 0,
		FLD_QUEUE,
		FLD_LCORE,
		_NUM_FLD
	};
	int int_fld[_NUM_FLD];
	char *str_fld[_NUM_FLD];
	int i, num;
	unsigned int size;
	uint16_t lcore_id, port_id, queue_id;
	struct lcore_queue_conf *conf;

	p = strchr(p0, '(');
	while (p) {
		++p;
		p0 = strchr(p, ')');
		if (!p0)
			return -EINVAL;

		size = p0 - p;
		if (size >= sizeof(s))
			return -EINVAL;

		snprintf(s, sizeof(s), "%.*s", size, p);
		num = rte_strsplit(s, sizeof(s), str_fld,
			_NUM_FLD, ',');
		if (num > _NUM_FLD || num <= 0)
			return -EINVAL;
		for (i = 0; i < num; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno || end == str_fld[i])
				return -EINVAL;
		}

		lcore_id = RTE_MAX_LCORE;
		port_id = RTE_MAX_ETHPORTS;
		queue_id = 0;
		if (num > FLD_PORT) {
			port_id = int_fld[FLD_PORT];
			if (port_id >= RTE_MAX_ETHPORTS)
				return -EINVAL;
		} else {
			return -EINVAL;
		}
		if (num > FLD_QUEUE)
			queue_id = int_fld[FLD_QUEUE];
		else
			return -EINVAL;
		if (num > FLD_LCORE) {
			lcore_id = int_fld[FLD_LCORE];
			if (lcore_id >= RTE_MAX_LCORE)
				return -EINVAL;
		} else {
			return -EINVAL;
		}
		conf = &s_lcore_queue_conf[lcore_id];
		if (conf->n_rx_port >= MAX_RX_QUEUE_PER_LCORE)
			return -EINVAL;
		conf->rx_port_list[conf->n_rx_port].port_id = port_id;
		conf->rx_port_list[conf->n_rx_port].queue_id = queue_id;
		conf->n_rx_port++;
		s_port_queue_nb[port_id]++;
		p = strchr(p0, '(');
	}

	return 0;
}

static const char short_options[] =
	"p:"  /* portmask */
	"P"   /* promiscuous */
	"T:"  /* timer period */
	;

#define CMD_LINE_OPT_NO_MAC_UPDATING "no-mac-updating"
#define CMD_LINE_OPT_ENABLE_FLOW "enable-flow"
#define CMD_LINE_OPT_RATE_UNIT_CONFIG "unit"
#define CMD_LINE_OPT_RATE_COLOR_CONFIG "color"
#define CMD_LINE_OPT_RATE_DEFAULT_COLOR_CONFIG "default_color"
#define CMD_LINE_OPT_RATE_RED_ACTION_CONFIG "red_action"
#define CMD_LINE_OPT_CIR_CONFIG "cir"
#define CMD_LINE_OPT_CBS_CONFIG "cbs"
#define CMD_LINE_OPT_PIR_CONFIG "pir"
#define CMD_LINE_OPT_PBS_CONFIG "pbs"
#define CMD_LINE_OPT_METER_ACTION_CONFIG "meter_action"
#define CMD_LINE_OPT_TX_MULTI_PORTS_CONFIG "tx_multi_ports"
#define CMD_LINE_OPT_MISS_DROP_ACTION_CONFIG "miss_drop"
#define CMD_LINE_OPT_QOS_VLAN_ID_CONFIG "vlan_id"
#define CMD_LINE_OPT_QUEUE_CONFIG "queue_config"
#define CMD_LINE_OPT_FLOW_TABLE_LEVEL_CONFIG "flow_table_level"
#define CMD_LINE_OPT_PRINT_STAT_CONFIG "print_stat"

enum {
	/* long options mapped to a short option */

	/* first long only option value must be >= 256, so that we won't
	 * conflict with short options
	 */
	CMD_LINE_OPT_NO_MAC_UPDATING_NUM = 256,
	CMD_LINE_OPT_ENABLE_FLOW_CTL,
	CMD_LINE_OPT_RATE_UNIT,
	CMD_LINE_OPT_RATE_COLOR,
	CMD_LINE_OPT_RATE_DEFAULT_COLOR,
	CMD_LINE_OPT_RATE_RED_ACTION,
	CMD_LINE_OPT_CIR,
	CMD_LINE_OPT_CBS,
	CMD_LINE_OPT_PIR,
	CMD_LINE_OPT_PBS,
	CMD_LINE_OPT_METER_ACTION,
	CMD_LINE_OPT_TX_MULTI_PORTS,
	CMD_LINE_OPT_MISS_DROP_ACTION,
	CMD_LINE_OPT_QOS_VLAN_ID,
	CMD_LINE_OPT_QUEUE_CONFIG_NUM,
	CMD_LINE_OPT_FLOW_TABLE_LEVEL,
	CMD_LINE_OPT_PRINT_STAT
};

static const struct option lgopts[] = {
	{CMD_LINE_OPT_NO_MAC_UPDATING, no_argument, 0,
		CMD_LINE_OPT_NO_MAC_UPDATING_NUM},
	{CMD_LINE_OPT_PRINT_STAT_CONFIG, no_argument, 0,
		CMD_LINE_OPT_PRINT_STAT},
	{CMD_LINE_OPT_MISS_DROP_ACTION_CONFIG, no_argument, 0,
		CMD_LINE_OPT_MISS_DROP_ACTION},
	{CMD_LINE_OPT_ENABLE_FLOW, 1, 0, CMD_LINE_OPT_ENABLE_FLOW_CTL},
	{CMD_LINE_OPT_RATE_UNIT_CONFIG, 1, 0, CMD_LINE_OPT_RATE_UNIT},
	{CMD_LINE_OPT_RATE_COLOR_CONFIG, 1, 0, CMD_LINE_OPT_RATE_COLOR},
	{CMD_LINE_OPT_RATE_DEFAULT_COLOR_CONFIG, 1, 0, CMD_LINE_OPT_RATE_DEFAULT_COLOR},
	{CMD_LINE_OPT_RATE_RED_ACTION_CONFIG, 1, 0, CMD_LINE_OPT_RATE_RED_ACTION},
	{CMD_LINE_OPT_CIR_CONFIG, 1, 0, CMD_LINE_OPT_CIR},
	{CMD_LINE_OPT_CBS_CONFIG, 1, 0, CMD_LINE_OPT_CBS},
	{CMD_LINE_OPT_PIR_CONFIG, 1, 0, CMD_LINE_OPT_PIR},
	{CMD_LINE_OPT_PBS_CONFIG, 1, 0, CMD_LINE_OPT_PBS},
	{CMD_LINE_OPT_METER_ACTION_CONFIG, 1, 0, CMD_LINE_OPT_METER_ACTION},
	{CMD_LINE_OPT_TX_MULTI_PORTS_CONFIG, 1, 0, CMD_LINE_OPT_TX_MULTI_PORTS},
	{CMD_LINE_OPT_QOS_VLAN_ID_CONFIG, 1, 0, CMD_LINE_OPT_QOS_VLAN_ID},
	{CMD_LINE_OPT_QUEUE_CONFIG, 1, 0, CMD_LINE_OPT_QUEUE_CONFIG_NUM},
	{CMD_LINE_OPT_FLOW_TABLE_LEVEL_CONFIG, 1, 0,
		CMD_LINE_OPT_FLOW_TABLE_LEVEL},
	{NULL, 0, 0, 0}
};

/* Parse the argument given in the command line of the application */
static int
l2fwd_policer_parse_args(int argc, char **argv)
{
	int opt, ret, timer_secs, option_index;
	char **argvopt;
	char *prgname = argv[0];

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, short_options,
			lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* portmask */
		case 'p':
			l2fwd_policer_enabled_port_mask = l2fwd_policer_parse_portmask(optarg);
			if (!l2fwd_policer_enabled_port_mask) {
				RTE_LOG(ERR, L2FWD_POLICER,
					"invalid portmask\n");
				l2fwd_policer_usage(prgname);
				return -EINVAL;
			}
			break;

		case 'P':
			promiscuous_on = 1;
			break;

		/* timer period */
		case 'T':
			timer_secs = l2fwd_policer_parse_timer_period(optarg);
			if (timer_secs < 0) {
				RTE_LOG(ERR, L2FWD_POLICER,
					"invalid timer period\n");
				l2fwd_policer_usage(prgname);
				return -EINVAL;
			}
			timer_period = timer_secs;
			break;

		case CMD_LINE_OPT_NO_MAC_UPDATING_NUM:
			mac_updating = atoi(optarg);
			break;

		case CMD_LINE_OPT_ENABLE_FLOW_CTL:
			enable_flow = atoi(optarg);
			break;

		/* long options */
		case CMD_LINE_OPT_RATE_UNIT:
			l2fwd_policer_parse_rate_unit(optarg);
			break;

		case CMD_LINE_OPT_RATE_COLOR:
			l2fwd_policer_parse_color_option(optarg);
			break;

		case CMD_LINE_OPT_RATE_DEFAULT_COLOR:
			l2fwd_policer_parse_default_color(optarg);
			break;

		case CMD_LINE_OPT_RATE_RED_ACTION:
			l2fwd_policer_parse_red_action_option(optarg);
			break;

		case CMD_LINE_OPT_CIR:
			s_cir = (uint32_t)atoi(optarg);
			break;

		case CMD_LINE_OPT_CBS:
			s_cbs = (uint32_t)atoi(optarg);
			break;

		case CMD_LINE_OPT_PIR:
			s_pir = (uint32_t)atoi(optarg);
			break;

		case CMD_LINE_OPT_PBS:
			s_pbs = (uint32_t)atoi(optarg);
			break;

		case CMD_LINE_OPT_METER_ACTION:
			if (!strcmp(optarg, "meter_mark")) {
				s_meter_action = RTE_FLOW_ACTION_TYPE_METER_MARK;
			} else if (!strcmp(optarg, "meter")) {
				s_meter_action = RTE_FLOW_ACTION_TYPE_METER;
			} else if (!strcmp(optarg, "pass")) {
				s_meter_action = RTE_FLOW_ACTION_TYPE_PASSTHRU;
			} else {
				fprintf(stderr, "Invalid meter action: %s\n",
					optarg);
				l2fwd_policer_usage(prgname);
				return -EINVAL;
			}
			break;

		case CMD_LINE_OPT_TX_MULTI_PORTS:
			tx_multi_ports = atoi(optarg);
			break;

		case CMD_LINE_OPT_QOS_VLAN_ID:
			s_vlan_id = (uint16_t)atoi(optarg);
			break;

		case CMD_LINE_OPT_MISS_DROP_ACTION:
			s_miss_drop = true;
			break;

		case CMD_LINE_OPT_QUEUE_CONFIG_NUM:
			ret = l2fwd_policer_parse_queue_config(optarg);
			if (ret)
				return ret;
			break;

		case CMD_LINE_OPT_FLOW_TABLE_LEVEL:
			s_flow_table_level = atoi(optarg);
			if (s_flow_table_level != 1 && s_flow_table_level != 2) {
				RTE_LOG(ERR, L2FWD_POLICER,
					"Invalid flow table level(%d)\n",
					s_flow_table_level);
				return -EINVAL;
			}
			break;

		case CMD_LINE_OPT_PRINT_STAT:
			s_print_stat = true;
			break;

		default:
			l2fwd_policer_usage(prgname);
			return -ENOTSUP;
		}
	}

	if (optind >= 0)
		argv[optind - 1] = prgname;

	ret = optind - 1;
	optind = 1; /* reset getopt lib */
	return ret;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint16_t portid;
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;
	int ret;
	char link_status_text[RTE_ETH_LINK_MAX_STR_LEN];

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		if (force_quit)
			return;
		all_ports_up = 1;
		RTE_ETH_FOREACH_DEV(portid) {
			if (force_quit)
				return;
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			ret = rte_eth_link_get_nowait(portid, &link);
			if (ret < 0) {
				all_ports_up = 0;
				if (print_flag == 1)
					RTE_LOG(ERR, L2FWD_POLICER,
						"Port %u link get failed: %s\n",
						portid, rte_strerror(-ret));
				continue;
			}
			/* print link status if flag set */
			if (print_flag == 1) {
				rte_eth_link_to_str(link_status_text,
					sizeof(link_status_text), &link);
				RTE_LOG(INFO, L2FWD_POLICER,
					"Port %d %s\n", portid,
					link_status_text);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == RTE_ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

static void *
l2fwd_policer_alloc_id(uint16_t port_id, enum policer_id_type type)
{
	char nm[RTE_MEMZONE_NAMESIZE];
	struct rte_ring *r;
	int i, ret;
	void *pid;

	if (port_id >= RTE_MAX_ETHPORTS) {
		RTE_LOG(ERR, L2FWD_POLICER,
			"%s: Invalid port id(%d)\n",
			__func__, port_id);
		return NULL;
	}
	if (!s_id_pool[port_id][type]) {
		sprintf(nm, "id_pool_%d_port%d", type, port_id);
		r = rte_ring_create(nm, POLICER_MAX_ID_NUM * 2, 0, 0);
		if (!r) {
			RTE_LOG(ERR, L2FWD_POLICER,
				"Create %s failed!\n", nm);
			return NULL;
		}
		for (i = 0; i < POLICER_MAX_ID_NUM; i++) {
			if (type == POLICER_METER_ID_TYPE) {
				s_meter_ids[port_id][i] = i;
				rte_ring_enqueue(r, &s_meter_ids[port_id][i]);
			} else if (type == POLICER_PROFILE_ID_TYPE) {
				s_profile_ids[port_id][i] = i;
				rte_ring_enqueue(r, &s_profile_ids[port_id][i]);
			} else if (type == POLICER_POLICY_ID_TYPE) {
				s_policy_ids[port_id][i] = i;
				rte_ring_enqueue(r, &s_policy_ids[port_id][i]);
			}
		}
		s_id_pool[port_id][type] = r;
	}

	ret = rte_ring_dequeue(s_id_pool[port_id][type], &pid);
	if (!ret)
		return pid;

	return NULL;
}

static void
l2fwd_policer_free_id(int port_id,
	uint32_t *pid, enum policer_id_type type)
{
	struct rte_ring *r = s_id_pool[port_id][type];
	int ret;

	ret = rte_ring_enqueue(r, pid);
	if (ret) {
		rte_exit(EXIT_FAILURE,
			"Free port%d's ID(type=%d) failed(%d)\n",
			port_id, type, ret);
	}
}

static void
l2fwd_policer_meter_mark_action_config(uint16_t port_id,
	struct l2fwd_policer_meter_param *param,
	struct rte_flow_action *action,
	struct rte_flow_action_meter_mark *action_meter_mark)
{
	struct rte_flow_meter_profile *fm_profile = NULL;
	struct rte_flow_meter_policy *fm_policy = NULL;

	if (param->profile_id) {
		fm_profile = rte_mtr_meter_profile_get(port_id,
			*param->profile_id, NULL);
	}
	if (param->policy_id) {
		fm_policy = rte_mtr_meter_policy_get(port_id,
			*param->policy_id, NULL);
	}
	action_meter_mark->profile = fm_profile;
	action_meter_mark->policy = fm_policy;
	action_meter_mark->color_mode = s_color_option;
	action_meter_mark->init_color = s_default_color;
	action_meter_mark->state = 0;
	action->type = RTE_FLOW_ACTION_TYPE_METER_MARK;
	action->conf = action_meter_mark;
}

static void
l2fwd_policer_meter_action_config(uint16_t port_id,
	struct l2fwd_policer_meter_param *param,
	struct rte_flow_action *action,
	struct rte_flow_action_meter *action_meter)
{
	if (!param->meter_id) {
		rte_exit(EXIT_FAILURE,
			"Port%d's meter ID not allocated!\n",
			port_id);
	}
	action_meter->mtr_id = *param->meter_id;
	action->type = RTE_FLOW_ACTION_TYPE_METER;
	action->conf = action_meter;
}

static int
l2fwd_policer_fs_flow_action_update(uint16_t port_id,
	void *flow, uint16_t queue_id)
{
	struct rte_flow_action flow_action[MAX_ACTION_NUM];
	struct rte_flow_action_queue action_queue;

	flow_action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	action_queue.index = queue_id;
	flow_action[0].conf = &action_queue;
	flow_action[1].type = RTE_FLOW_ACTION_TYPE_END;

	return rte_flow_actions_update(port_id, flow,
		flow_action, NULL);
}

static void *
l2fwd_policer_fs_flow_item_update(uint16_t port_id,
	struct rte_flow_item *pattern, void *flow,
	uint16_t tc_id, uint16_t flow_id,
	int flow_tb_level)
{
	struct rte_flow_attr flow_attr;
	struct rte_flow_action flow_action[MAX_ACTION_NUM];
	struct rte_flow_action_queue action_queue;
	int ret;

	memset(&flow_attr, 0, sizeof(struct rte_flow_attr));
	flow_attr.ingress = 1;

	flow_attr.group = tc_id;
	flow_attr.priority = 0;

	flow_action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	action_queue.index = flow_id;
	flow_action[0].conf = &action_queue;
	flow_action[1].type = RTE_FLOW_ACTION_TYPE_END;

	ret = rte_flow_destroy(port_id, flow, NULL);
	if (ret)
		return NULL;

	if (flow_tb_level > 1)
		rte_dpaa2_fs_flow_attr_set(&flow_attr);

	return rte_flow_create(port_id, &flow_attr, pattern, flow_action, NULL);
}

static void *
l2fwd_policer_qos_flow_item_update(uint16_t port_id,
	struct rte_flow_item *pattern, void *flow, uint8_t tc,
	uint16_t max_tcs)
{
	struct rte_flow_attr flow_attr;
	struct rte_flow_action flow_action[MAX_ACTION_NUM];
	struct rte_flow_action_jump action_jump;
	int ret;

	memset(&flow_attr, 0, sizeof(struct rte_flow_attr));
	flow_attr.ingress = 1;

	/** The grounp ID > any TC ID, which means the flow is QoS flow.*/
	flow_attr.group = max_tcs;
	flow_attr.priority = 0; /** Ignore for QoS flow.*/

	flow_action[0].type = RTE_FLOW_ACTION_TYPE_JUMP;
	action_jump.group = tc;
	flow_action[0].conf = &action_jump;
	flow_action[1].type = RTE_FLOW_ACTION_TYPE_END;

	ret = rte_flow_destroy(port_id, flow, NULL);
	if (ret)
		return NULL;
	rte_dpaa2_qos_flow_attr_set(&flow_attr);

	return rte_flow_create(port_id, &flow_attr, pattern, flow_action, NULL);
}

static struct rte_flow *
l2fwd_policer_qos_flow_vlan_config(uint16_t port_id,
	uint16_t tc, uint16_t vlan_id)
{
	uint16_t prio;
	struct rte_flow_attr flow_attr;
	struct rte_flow_item_vlan vlan_item;
	struct rte_flow_item_vlan vlan_mask;
	struct rte_flow_item flow_item[MAX_ITEM_NUM];
	struct rte_flow_action flow_action[MAX_ACTION_NUM];
	struct rte_flow_action_jump action_jump;
	struct rte_flow *qos_flow;

	memset(&flow_attr, 0, sizeof(struct rte_flow_attr));
	flow_attr.ingress = 1;

	/** Ignore group and priority of attr.
	 * flow_attr.group = xxx;
	 * flow_attr.priority = xxx;
	 */
	prio = l2fwd_policer_tc_map_vlan_prio(tc);
	memset(&vlan_item, 0, sizeof(struct rte_flow_item_vlan));
	memset(&vlan_mask, 0, sizeof(struct rte_flow_item_vlan));
	vlan_item.hdr.vlan_tci = rte_cpu_to_be_16(prio + vlan_id);
	vlan_item.hdr.eth_proto = rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN);
	vlan_mask.hdr.vlan_tci = RTE_BE16(0xffff);

	flow_item[0].spec = &vlan_item;
	flow_item[0].mask = &vlan_mask;
	flow_item[0].type = RTE_FLOW_ITEM_TYPE_VLAN;
	flow_item[1].type = RTE_FLOW_ITEM_TYPE_END;

	flow_action[0].type = RTE_FLOW_ACTION_TYPE_JUMP;
	action_jump.group = tc;
	flow_action[0].conf = &action_jump;
	flow_action[1].type = RTE_FLOW_ACTION_TYPE_END;

	rte_dpaa2_qos_flow_attr_set(&flow_attr);
	qos_flow = rte_flow_create(port_id,
		&flow_attr, flow_item, flow_action, NULL);
	if (!qos_flow) {
		rte_exit(EXIT_FAILURE,
			"Cannot create QoS flow of TC%d on port=%d\n",
			tc, port_id);
	}
	RTE_LOG(INFO, L2FWD_POLICER,
		"Create port%d QoS flow to direct tci=0x%04x traffic to TC%d\n",
		port_id, prio + vlan_id, tc);
	return qos_flow;
}

static struct rte_flow *
l2fwd_policer_meter_flow_create(uint16_t port_id,
	uint16_t tc, struct l2fwd_policer_meter_param *meter_param,
	int flow_tb_level)
{
	struct rte_flow_attr flow_attr;
	struct rte_flow_action flow_action[MAX_ACTION_NUM];
	struct rte_flow_action_meter action_meter;
	struct rte_flow_action_meter_mark action_meter_mark;
	struct rte_flow *meter_flow;

	if (s_meter_action != RTE_FLOW_ACTION_TYPE_METER_MARK &&
		s_meter_action != RTE_FLOW_ACTION_TYPE_METER)
		return NULL;

	memset(&flow_attr, 0, sizeof(struct rte_flow_attr));
	flow_attr.ingress = 1;

	flow_attr.group = tc;
	flow_attr.priority = 0; /** Ignore for QoS flow.*/

	if (s_meter_action == RTE_FLOW_ACTION_TYPE_METER_MARK) {
		l2fwd_policer_meter_mark_action_config(port_id,
			meter_param, &flow_action[0], &action_meter_mark);
		flow_action[1].type = RTE_FLOW_ACTION_TYPE_END;
	} else if (s_meter_action == RTE_FLOW_ACTION_TYPE_METER) {
		l2fwd_policer_meter_action_config(port_id,
			meter_param, &flow_action[0], &action_meter);
		flow_action[1].type = RTE_FLOW_ACTION_TYPE_END;
	}

	if (flow_tb_level > 1)
		rte_dpaa2_fs_flow_attr_set(&flow_attr);
	meter_flow = rte_flow_create(port_id,
		&flow_attr, NULL, flow_action, NULL);
	if (!meter_flow) {
		rte_exit(EXIT_FAILURE,
			"Cannot create meter flow of TC%d on port=%d\n",
			tc, port_id);
	}
	RTE_LOG(INFO, L2FWD_POLICER,
		"Create meter flow of port%d-TC%d\n", port_id, tc);

	return meter_flow;
}

static struct rte_flow *
l2fwd_policer_fs_flow_config(uint16_t port_id,
	uint16_t tc, uint16_t flow_id, uint16_t queue_id)
{
	struct rte_flow_attr flow_attr;
	struct rte_flow_item_ipv4 ipv4_item;
	struct rte_flow_item_ipv4 ipv4_mask;
	struct rte_flow_item flow_item[MAX_ITEM_NUM];
	struct rte_flow_action flow_action[MAX_ACTION_NUM];
	struct rte_flow_action_queue dest_queue;
	int ret;
	struct rte_flow *fs_flow;

	memset(&flow_attr, 0, sizeof(flow_attr));
	flow_attr.ingress = 1;

	flow_attr.group = tc;
	flow_attr.priority = flow_id;
	dest_queue.index = queue_id;
	memset(&ipv4_item, 0, sizeof(struct rte_flow_item_ipv4));
	memset(&ipv4_mask, 0, sizeof(struct rte_flow_item_ipv4));
	ipv4_item.hdr.src_addr = rte_cpu_to_be_32(flow_id);
	ipv4_mask.hdr.src_addr = rte_cpu_to_be_32(0xff);

	flow_item[0].spec = &ipv4_item;
	flow_item[0].mask = &ipv4_mask;
	flow_item[0].type = RTE_FLOW_ITEM_TYPE_IPV4;
	flow_item[1].type = RTE_FLOW_ITEM_TYPE_END;
	flow_action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	flow_action[0].conf = &dest_queue;
	flow_action[1].type = RTE_FLOW_ACTION_TYPE_END;

	/* validate and create the flow rule */
	ret = rte_flow_validate(port_id, &flow_attr, flow_item,
		flow_action, NULL);
	if (ret) {
		RTE_LOG(ERR, L2FWD_POLICER,
			"flow validate failed(%d) on port%d-TC%d\n",
			ret, port_id, tc);
		return NULL;
	}

	rte_dpaa2_fs_flow_attr_set(&flow_attr);
	fs_flow = rte_flow_create(port_id,
		&flow_attr, flow_item, flow_action, NULL);
	if (fs_flow) {
		RTE_LOG(INFO, L2FWD_POLICER,
			"Create port%d-TC%d-flow%d to direct x.x.x.%d to queue%d\n",
			port_id, tc, flow_id, flow_id, queue_id);
	}

	return fs_flow;
}

static uint32_t *
l2fwd_policer_meter_profile_create(uint16_t port_id,
	struct l2fwd_policer_meter_param *param)
{
	uint32_t *new_mp_id;
	struct rte_mtr_meter_profile mp;
	int ret;

	new_mp_id = l2fwd_policer_alloc_id(port_id,
		POLICER_PROFILE_ID_TYPE);
	if (!new_mp_id) {
		RTE_LOG(ERR, L2FWD_POLICER,
			"Port %u alloc Profile ID failed\n",
			port_id);
		return NULL;
	}
	mp.alg = RTE_MTR_TRTCM_RFC2698;
	mp.trtcm_rfc2698.cir = param->trtcm.cir;
	mp.trtcm_rfc2698.pir = param->trtcm.pir;
	mp.trtcm_rfc2698.cbs = param->trtcm.cbs;
	mp.trtcm_rfc2698.pbs = param->trtcm.pbs;

	/** packet_mode = 0 is l3 byte mode.
	 * packet_mode = 1 is packet mode.
	 * packet_mode > 1 is l2 byte mode without FCS.
	 */
	mp.packet_mode = s_policer_unit;
	ret = rte_mtr_meter_profile_add(port_id, *new_mp_id,
		&mp, NULL);
	if (ret) {
		RTE_LOG(ERR, L2FWD_POLICER,
			"Port %u create Profile(%d) failed(%d)\n",
			port_id, *new_mp_id, ret);
		l2fwd_policer_free_id(port_id, new_mp_id,
			POLICER_PROFILE_ID_TYPE);
		return NULL;
	}

	return new_mp_id;
}

static void
l2fwd_policer_meter_profile_del(uint16_t port_id,
	uint32_t *profile_id)
{
	int ret;

	if (!profile_id)
		return;

	ret = rte_mtr_meter_profile_delete(port_id, *profile_id, NULL);
	if (ret) {
		rte_exit(EXIT_FAILURE,
			"Port %u meter Profile delete failed(%d)\n",
			port_id, ret);
	}
	l2fwd_policer_free_id(port_id, profile_id, POLICER_PROFILE_ID_TYPE);
}

static uint32_t *
l2fwd_policer_meter_policy_create(uint16_t port_id,
	struct l2fwd_policer_meter_param *param)
{
	uint32_t *new_mpol_id;
	struct rte_mtr_meter_policy_params mpol;
	int ret;

	new_mpol_id = l2fwd_policer_alloc_id(port_id,
		POLICER_POLICY_ID_TYPE);
	if (!new_mpol_id) {
		RTE_LOG(ERR, L2FWD_POLICER,
			"Port %u alloc Policy ID failed\n",
			port_id);
		return NULL;
	}
	mpol.actions[RTE_COLOR_GREEN] = NULL;
	mpol.actions[RTE_COLOR_YELLOW] = NULL;
	mpol.actions[RTE_COLOR_RED] = &param->red_action;
	ret = rte_mtr_meter_policy_add(port_id, *new_mpol_id,
		&mpol, NULL);
	if (ret) {
		RTE_LOG(ERR, L2FWD_POLICER,
			"Port %u create Policy(%d) failed(%d)\n",
			port_id, *new_mpol_id, ret);
		l2fwd_policer_free_id(port_id, new_mpol_id,
			POLICER_POLICY_ID_TYPE);
		return NULL;
	}

	return new_mpol_id;
}

static void
l2fwd_policer_meter_policy_del(uint16_t port_id,
	uint32_t *policy_id)
{
	int ret;

	if (!policy_id)
		return;

	ret = rte_mtr_meter_policy_delete(port_id, *policy_id, NULL);
	if (ret) {
		rte_exit(EXIT_FAILURE,
			"Port %u meter Policy delete failed(%d)\n",
			port_id, ret);
	}
	l2fwd_policer_free_id(port_id, policy_id, POLICER_POLICY_ID_TYPE);
}

static void
l2fwd_policer_meter_update(uint16_t port_id,
	struct l2fwd_policer_meter_param *param, uint8_t update,
	uint32_t **old_profile_id, uint32_t **old_policy_id)
{
	uint32_t *mpof_id, *mpol_id;
	int ret;

	if (update & ACTION_POLICER_PROFILE_UPDATE) {
		mpof_id = l2fwd_policer_meter_profile_create(port_id, param);
		if (!mpof_id) {
			rte_exit(EXIT_FAILURE,
				"Port %u meter Profile create failed!\n",
				port_id);
		}
		if (s_meter_action == RTE_FLOW_ACTION_TYPE_METER) {
			ret = rte_mtr_meter_profile_update(port_id,
				*param->meter_id, *mpof_id, NULL);
			if (ret) {
				rte_exit(EXIT_FAILURE,
					"Port %u meter Profile update failed(%d)\n",
					port_id, ret);
			}
		}
		if (old_profile_id)
			*old_profile_id = param->profile_id;
		param->profile_id = mpof_id;
	}

	if (update & ACTION_POLICER_POLICY_UPDATE) {
		mpol_id = l2fwd_policer_meter_policy_create(port_id, param);
		if (!mpol_id) {
			rte_exit(EXIT_FAILURE,
				"Port %u meter Policy create failed!\n",
				port_id);
		}
		if (s_meter_action == RTE_FLOW_ACTION_TYPE_METER) {
			ret = rte_mtr_meter_policy_update(port_id,
				*param->meter_id, *mpol_id, NULL);
			if (ret) {
				rte_exit(EXIT_FAILURE,
					"Port %u meter Policy update failed(%d)\n",
					port_id, ret);
			}
		}
		if (old_policy_id)
			*old_policy_id = param->policy_id;
		param->policy_id = mpol_id;
	}
}

static void
l2fwd_policer_meter_init(uint16_t port_id,
	struct l2fwd_policer_meter_param *param)
{
	struct rte_mtr_params mp;
	int ret;

	param->trtcm.cir = s_cir;
	param->trtcm.pir = s_pir;
	param->trtcm.cbs = s_cbs;
	param->trtcm.pbs = s_pbs;
	param->red_action.type = s_red_action;
	if (s_meter_action == RTE_FLOW_ACTION_TYPE_METER_MARK) {
		l2fwd_policer_meter_update(port_id, param,
			ACTION_POLICER_PROFILE_UPDATE |
			ACTION_POLICER_POLICY_UPDATE, NULL, NULL);
		return;
	}

	param->meter_id = l2fwd_policer_alloc_id(port_id,
		POLICER_METER_ID_TYPE);
	if (!param->meter_id) {
		rte_exit(EXIT_FAILURE,
			"Alloc port%d's meter ID failed\n", port_id);
	}
	param->profile_id = l2fwd_policer_meter_profile_create(port_id,
		param);
	if (!param->profile_id) {
		rte_exit(EXIT_FAILURE,
			"Port %u No profile ID allocated\n",
			port_id);
	}
	param->policy_id = l2fwd_policer_meter_policy_create(port_id,
		param);
	if (!param->policy_id) {
		rte_exit(EXIT_FAILURE,
			"Port %u No policy ID allocated\n",
			port_id);
	}

	memset(&mp, 0, sizeof(mp));
	mp.meter_profile_id = *param->profile_id;
	mp.meter_policy_id = *param->policy_id;
	mp.default_input_color = s_default_color;
	mp.meter_enable = true;
	ret = rte_mtr_create(port_id, *param->meter_id, &mp, true, NULL);
	if (ret) {
		rte_exit(EXIT_FAILURE,
			"Port %u create Meter(%d) failed(%d)\n",
			port_id, *param->meter_id, ret);
	}
}

static void *
l2fwd_policer_one_level_flow_config(uint16_t port_id,
	uint16_t tc, uint16_t vlan_id, uint16_t flow_id, uint16_t queue_id)
{
	struct rte_flow_attr flow_attr;
	struct rte_flow_item_vlan vlan_item;
	struct rte_flow_item_vlan vlan_mask;
	struct rte_flow_item_ipv4 ipv4_item;
	struct rte_flow_item_ipv4 ipv4_mask;
	struct rte_flow_item flow_item[MAX_ITEM_NUM];
	struct rte_flow_action flow_action[MAX_ACTION_NUM];
	struct rte_flow_action_queue dest_queue;
	int ret;
	void *_flow;
	uint16_t prio;

	memset(&flow_attr, 0, sizeof(flow_attr));
	flow_attr.ingress = 1;

	flow_attr.group = tc;
	flow_attr.priority = flow_id;
	dest_queue.index = queue_id;

	prio = l2fwd_policer_tc_map_vlan_prio(tc);
	memset(&vlan_item, 0, sizeof(struct rte_flow_item_vlan));
	memset(&vlan_mask, 0, sizeof(struct rte_flow_item_vlan));
	vlan_item.hdr.vlan_tci = rte_cpu_to_be_16(prio + vlan_id);
	vlan_item.hdr.eth_proto = rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN);
	vlan_mask.hdr.vlan_tci = RTE_BE16(0xffff);
	flow_item[0].spec = &vlan_item;
	flow_item[0].mask = &vlan_mask;
	flow_item[0].type = RTE_FLOW_ITEM_TYPE_VLAN;

	memset(&ipv4_item, 0, sizeof(struct rte_flow_item_ipv4));
	memset(&ipv4_mask, 0, sizeof(struct rte_flow_item_ipv4));
	ipv4_item.hdr.src_addr = rte_cpu_to_be_32(flow_id);
	ipv4_mask.hdr.src_addr = rte_cpu_to_be_32(0xff);
	flow_item[1].spec = &ipv4_item;
	flow_item[1].mask = &ipv4_mask;
	flow_item[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
	flow_item[2].type = RTE_FLOW_ITEM_TYPE_END;
	flow_action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	flow_action[0].conf = &dest_queue;
	flow_action[1].type = RTE_FLOW_ACTION_TYPE_END;

	/* validate and create the flow rule */
	ret = rte_flow_validate(port_id, &flow_attr, flow_item,
			flow_action, NULL);
	if (ret) {
		RTE_LOG(ERR, L2FWD_POLICER,
			"flow validate failed(%d) on port%d-TC%d\n",
			ret, port_id, tc);
		return NULL;
	}

	_flow = rte_flow_create(port_id, &flow_attr, flow_item,
		flow_action, NULL);
	if (_flow) {
		RTE_LOG(INFO, L2FWD_POLICER,
			"Create port%d-TC%d-flow%d to direct x.x.x.%d to queue%d\n",
			port_id, tc, flow_id, flow_id, queue_id);
	}

	return _flow;
}

static void
l2fwd_policer_flow_init_config(uint16_t port_id,
	struct l2fwd_policer_port_params *param)
{
	uint16_t tc, i;
	struct rte_flow_action flow_action[MAX_ACTION_NUM];
	int ret;
	struct l2fwd_policer_tc_desc *tc_desc;

	for (tc = 0; tc < param->max_tcs; tc++) {
		tc_desc = &param->tc_descs[tc];
		if (!tc_desc->valid)
			continue;

		if (s_meter_action == RTE_FLOW_ACTION_TYPE_METER ||
			s_meter_action == RTE_FLOW_ACTION_TYPE_METER_MARK)
			l2fwd_policer_meter_init(port_id, &tc_desc->meter_param);

		if (param->flow_tb_level == 1) {
			for (i = 0; i < tc_desc->queue_max_num; i++) {
				tc_desc->one_level_flows[i] =
					l2fwd_policer_one_level_flow_config(port_id, tc,
						s_vlan_id, i, tc_desc->tc_queue_ids[i]);
				tc_desc->flow_queue_ids[i] = tc_desc->tc_queue_ids[i];
			}
		} else {
			param->qos_flows[tc] = l2fwd_policer_qos_flow_vlan_config(port_id,
				tc, s_vlan_id);
			param->tc_ids[tc] = tc;
			tc_desc = &param->tc_descs[tc];
			tc_desc->meter_flow = l2fwd_policer_meter_flow_create(port_id,
				tc, &tc_desc->meter_param, param->flow_tb_level);
			for (i = 0; i < tc_desc->queue_max_num; i++) {
				tc_desc->fs_flows[i] = l2fwd_policer_fs_flow_config(port_id,
					tc, i, tc_desc->tc_queue_ids[i]);
				if (!tc_desc->fs_flows[i]) {
					rte_exit(EXIT_FAILURE,
						"Cannot create FS flow[%d] of TC%d on port=%d\n",
						i, tc, port_id);
				}
				tc_desc->flow_queue_ids[i] = tc_desc->tc_queue_ids[i];
			}
		}
		tc_desc->miss_drop = s_miss_drop;
		tc_desc->default_queue =
			tc_desc->tc_queue_ids[tc_desc->queue_max_num - 1];
		if (tc_desc->miss_drop) {
			flow_action[0].type = RTE_FLOW_ACTION_TYPE_DROP;
			flow_action[1].type = RTE_FLOW_ACTION_TYPE_END;
			ret = rte_flow_group_set_miss_actions(port_id,
				tc, NULL, flow_action, NULL);
			if (ret) {
				rte_exit(EXIT_FAILURE,
					"Set miss action of TC%d on port=%d\n", tc, port_id);
			}
		}
	}

	if (param->miss_drop) {
		flow_action[0].type = RTE_FLOW_ACTION_TYPE_DROP;
		flow_action[1].type = RTE_FLOW_ACTION_TYPE_END;
		ret = rte_flow_group_set_miss_actions(port_id,
			param->max_tcs, NULL, flow_action, NULL);
		if (ret) {
			rte_exit(EXIT_FAILURE,
				"Set miss action of QoS on port=%d\n", port_id);
		}
	}
}

static void
l2fwd_policer_meter_action_update(uint16_t port_id,
	uint8_t tc, uint32_t update, int flow_tb_level)
{
	int ret, idx;
	struct rte_flow_action flow_action[MAX_ACTION_NUM];
	struct l2fwd_policer_tc_desc *tc_desc;
	struct rte_flow_action_meter action_meter;
	struct rte_flow_action_meter_mark action_meter_mark;
	struct rte_flow_attr flow_attr;

	tc_desc = &s_port_param[port_id].tc_descs[tc];

	flow_attr.ingress = 1;
	flow_attr.group = tc;
	flow_attr.priority = 0;

	idx = 0;
	memset(&flow_action, 0, sizeof(flow_action));
	if (s_meter_action == RTE_FLOW_ACTION_TYPE_METER &&
		(update & (ACTION_POLICER_PROFILE_UPDATE |
		ACTION_POLICER_POLICY_UPDATE))) {
		l2fwd_policer_meter_action_config(port_id,
			&tc_desc->meter_param, &flow_action[idx],
			&action_meter);
		idx++;
	} else if (s_meter_action == RTE_FLOW_ACTION_TYPE_METER_MARK &&
		(update & (ACTION_POLICER_PROFILE_UPDATE |
		ACTION_POLICER_POLICY_UPDATE))) {
		l2fwd_policer_meter_mark_action_config(port_id,
			&tc_desc->meter_param, &flow_action[idx],
			&action_meter_mark);
		idx++;
	}
	flow_action[idx].type = RTE_FLOW_ACTION_TYPE_END;

	if (idx <= 0)
		return;

	if (tc_desc->meter_flow) {
		ret = rte_flow_actions_update(port_id,
			tc_desc->meter_flow, flow_action, NULL);
		if (ret) {
			RTE_LOG(ERR, L2FWD_POLICER,
				"Update port%d-tc%d flow meter failed(%d)\n",
				port_id, tc, ret);
		}
	} else {
		if (flow_tb_level > 1)
			rte_dpaa2_fs_flow_attr_set(&flow_attr);
		tc_desc->meter_flow = rte_flow_create(port_id,
			&flow_attr, NULL, flow_action, NULL);
	}
}

static void
l2fwd_policer_qos_flow_update(uint16_t portid,
	uint32_t update)
{
	uint8_t idx, tc;
	void *flow;
	int ret;
	struct rte_flow_action actions[MAX_ACTION_NUM];
	struct rte_flow_action_jump action_jump;

	if ((update & ACTION_QOS_JUMP_UPDATE) &&
		s_port_param[portid].flow_tb_level == 1) {
		RTE_LOG(WARNING, L2FWD_POLICER,
			"QoS flow jump doesn't support with one-level table\n");
	} else if (update & ACTION_QOS_JUMP_UPDATE) {
		/**TBD*/
		;
	}

	if (update & ACTION_MISS_QOS_UPDATE) {
		if (s_port_param[portid].default_tc >=
			s_port_param[portid].max_tcs) {
			actions[0].type = RTE_FLOW_ACTION_TYPE_DROP;
		} else {
			action_jump.group = s_port_param[portid].default_tc;
			actions[0].type = RTE_FLOW_ACTION_TYPE_JUMP;
			actions[0].conf = &action_jump;
		}
		actions[1].type = RTE_FLOW_ACTION_TYPE_END;
		ret = rte_flow_group_set_miss_actions(portid,
			s_port_param[portid].max_tcs, NULL, actions, NULL);
		RTE_ASSERT(!ret);
		RTE_SET_USED(ret);
	}

	if ((update & ITEM_QOS_FLOW_UPDATE) &&
		s_port_param[portid].flow_tb_level == 1) {
		RTE_LOG(WARNING, L2FWD_POLICER,
			"QoS flow item update doesn't support with one-level table\n");
	} else if (update & ITEM_QOS_FLOW_UPDATE) {
		idx = s_port_param[portid].qos_update_idx;
		tc = s_port_param[portid].tc_ids[idx];
		flow = l2fwd_policer_qos_flow_item_update(portid,
			s_port_param[portid].qos_update_pattern,
			s_port_param[portid].qos_flows[idx], tc,
			s_port_param[portid].max_tcs);
		RTE_ASSERT(flow);
		s_port_param[portid].qos_flows[idx] = flow;
	}
}

static void
l2fwd_policer_tc_meter_update(uint16_t portid,
	uint8_t tc, uint32_t update)
{
	uint32_t *old_profile_id, *old_policy_id;
	struct l2fwd_policer_tc_desc *tc_desc;

	tc_desc = &s_port_param[portid].tc_descs[tc];
	old_profile_id = NULL;
	old_policy_id = NULL;
	l2fwd_policer_meter_update(portid, &tc_desc->meter_param, update,
		&old_profile_id, &old_policy_id);
	l2fwd_policer_meter_action_update(portid, tc, update,
		s_port_param[portid].flow_tb_level);
	l2fwd_policer_meter_profile_del(portid, old_profile_id);
	l2fwd_policer_meter_policy_del(portid, old_policy_id);
}

static void
l2fwd_policer_tc_flow_update(uint16_t portid,
	uint8_t tc, uint32_t update)
{
	uint8_t idx;
	uint16_t queue_id;
	void *flow;
	int ret;
	struct l2fwd_policer_tc_desc *tc_desc;
	struct rte_flow_action actions[MAX_ACTION_NUM];
	struct rte_flow_action_queue action_queue;

	if (tc >= s_port_param[portid].max_tcs)
		return;

	tc_desc = &s_port_param[portid].tc_descs[tc];
	if (update & (ACTION_POLICER_PROFILE_UPDATE |
		ACTION_POLICER_POLICY_UPDATE))
		l2fwd_policer_tc_meter_update(portid, tc, update);

	if (update & ITEM_FS_FLOW_UPDATE) {
		idx = tc_desc->item_update_idx;
		flow = l2fwd_policer_fs_flow_item_update(portid,
			tc_desc->fs_update_pattern,
			s_port_param[portid].flow_tb_level == 1 ?
			tc_desc->one_level_flows[idx] :
			tc_desc->fs_flows[idx], tc,
			tc_desc->flow_queue_ids[idx],
			s_port_param[portid].flow_tb_level);
		RTE_ASSERT(flow);
		if (s_port_param[portid].flow_tb_level == 1)
			tc_desc->one_level_flows[idx] = flow;
		else
			tc_desc->fs_flows[idx] = flow;
	}

	if (update & ACTION_MISS_FS_UPDATE) {
		if (tc_desc->miss_drop) {
			actions[0].type = RTE_FLOW_ACTION_TYPE_DROP;
		} else {
			action_queue.index = tc_desc->default_queue;
			actions[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
			actions[0].conf = &action_queue;
		}
		actions[1].type = RTE_FLOW_ACTION_TYPE_END;
		ret = rte_flow_group_set_miss_actions(portid, tc,
			NULL, actions, NULL);
		RTE_ASSERT(!ret);
		RTE_SET_USED(ret);
	}

	if (update & ACTION_FS_QUEUE_UPDATE) {
		idx = tc_desc->action_update_idx;
		queue_id = tc_desc->flow_queue_ids[idx];
		if (s_port_param[portid].flow_tb_level == 1)
			flow = tc_desc->one_level_flows[idx];
		else
			flow = tc_desc->fs_flows[idx];
		ret = l2fwd_policer_fs_flow_action_update(portid,
			flow, queue_id);
		if (ret) {
			RTE_LOG(ERR, L2FWD_POLICER,
				"Update port%d-tc%d-flow%d action failed(%d)\n",
				portid, tc, idx, ret);
		}
	}
}

static int
l2fwd_policer_runtime_control_print_stat(int start)
{
	char command[256];

	fprintf(stdout, "%s print stat?",
		start ? "Start" : "Stop");
	if (fgets(command, 256, stdin)) {
		if (command[0] == 'y')
			return true;
	}

	return false;
}

static int
l2fwd_policer_runtime_update_select_port(uint16_t *portid)
{
	int off = 0, i, port_update = -1;
	char command[256];
	char range[1024];
	char *endp;

	memset(range, 0, sizeof(range));
	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (s_port_param[i].enable && !off)
			off += sprintf(&range[off], "%d,", i);
		else if (s_port_param[i].enable)
			off += sprintf(&range[off], " %d,", i);
	}
	off += sprintf(&range[off], " %s", POLICER_UPDATE_SKIP_HINT);
	fprintf(stdout,
		"Enter Port ID to update: range[%s]: ", range);
	if (fgets(command, 256, stdin)) {
		errno = 0;
		port_update = strtoul(command, &endp, 10);
		if (errno || command == endp)
			return -EAGAIN;
		if (port_update >= RTE_MAX_ETHPORTS ||
			!s_port_param[port_update].enable) {
			fprintf(stderr, "Invalid Port(%d)\n", port_update);
			return -EINVAL;
		}
	}

	if (port_update >= 0) {
		*portid = port_update;
		return 0;
	}

	return -EINVAL;
}

static void
l2fwd_policer_runtime_qos_miss_update(uint16_t portid,
	uint32_t *update)
{
	int off = 0, drop = false;
	char command[256];
	char range[1024];
	char *endp;
	struct l2fwd_policer_port_params *port_param;
	uint8_t default_tc;

	port_param = &s_port_param[portid];

	memset(range, 0, sizeof(range));
	off = sprintf(range, "0 ~ %d", port_param->max_tcs - 1);
	off += sprintf(&range[off], " drop >= %d,", port_param->max_tcs);
	off += sprintf(&range[off], " %s", POLICER_UPDATE_SKIP_HINT);
	default_tc = port_param->default_tc;
	if (port_param->miss_drop) {
		fprintf(stdout,
			"\r\nEnter miss TC ID of port%d to update:(default=drop) range[%s]: ",
			portid, range);
	} else {
		fprintf(stdout,
			"\r\nEnter miss TC ID of port%d to update:(default=%d) range[%s]: ",
			portid, default_tc, range);
	}
	if (fgets(command, 256, stdin)) {
		errno = 0;
		default_tc = strtoul(command, &endp, 10);
		if (errno || command == endp)
			return;
		if (default_tc >= port_param->max_tcs)
			drop = true;

		if (drop == true) {
			if (port_param->miss_drop == false) {
				*update |= ACTION_MISS_QOS_UPDATE;
				port_param->miss_drop = true;
			}
		} else if (port_param->default_tc != default_tc) {
			*update |= ACTION_MISS_QOS_UPDATE;
			port_param->default_tc = default_tc;
		}
	}
}

static void
l2fwd_policer_runtime_qos_flow_item_update(uint16_t portid,
	uint32_t *update)
{
	int off = 0, idx = -1, i, max_num = 0, item_update = -1, ret;
	char command[256];
	char range[1024];
	char *endp;
	struct l2fwd_policer_port_params *port_param;

	port_param = &s_port_param[portid];

	off = 0;
	memset(range, 0, sizeof(range));
	for (i = 0; i < port_param->max_qos_entries; i++) {
		if (port_param->qos_flows[i])
			max_num++;
	}
	off += sprintf(&range[off], "0 ~ %d,", max_num - 1);
	off += sprintf(&range[off], " %s", POLICER_UPDATE_SKIP_HINT);
	fprintf(stdout,
		"\r\nEnter QoS flow index of port%d to update item(s): range[%s]: ",
		portid, range);
	if (fgets(command, 256, stdin)) {
		errno = 0;
		idx = strtoul(command, &endp, 10);
		if (errno || command == endp)
			return;
		if (idx >= max_num) {
			fprintf(stderr, "Invalid QoS flow index(%d) >= %d\n",
				idx, max_num);
			return;
		}
	}

	if (idx < 0)
		return;

	off = 0;
	for (i = 0; i < (int)RTE_DIM(s_qos_item_update); i++) {
		off += sprintf(&range[off], "%s/%s:%d, ",
			s_qos_item_update[i].item_protocol,
			s_qos_item_update[i].item_field, i);
	}
	off += sprintf(&range[off], "%s", POLICER_UPDATE_SKIP_HINT);

	fprintf(stdout,
		"Enter index of QoS item of port%d to update item(s): [%s]: ",
		portid, range);
	if (fgets(command, 256, stdin)) {
		errno = 0;
		item_update = strtoul(command, &endp, 10);
		if (errno || command == endp ||
			item_update >= (int)RTE_DIM(s_qos_item_update))
			return;
	}
	if (item_update < 0)
		return;

	fprintf(stdout, "Enter format: %s: ",
		s_qos_item_update[item_update].input_format);
	if (fgets(command, 256, stdin)) {
		ret = s_qos_item_update[item_update].item_parse(command,
			&s_qos_item_update[item_update]);
		if (ret) {
			fprintf(stderr, "parse item failed!\n");
			return;
		}
		port_param->qos_update_pattern =
			s_qos_item_update[item_update].pattern;
		port_param->qos_update_idx = idx;
		*update |= ITEM_QOS_FLOW_UPDATE;
	}
}

static int
l2fwd_policer_runtime_update_select_tc(uint16_t portid,
	uint8_t *tc)
{
	int tc_update = -1, off = 0;
	char command[256];
	char range[1024];
	char *endp;
	struct l2fwd_policer_port_params *port_param;

	port_param = &s_port_param[portid];

	memset(range, 0, sizeof(range));
	off += sprintf(&range[off], "0 ~ %d,", port_param->max_tcs - 1);
	off += sprintf(&range[off], " %s", POLICER_UPDATE_SKIP_HINT);
	fprintf(stdout,
		"\r\nEnter TC ID to update: range[%s]: ", range);
	if (fgets(command, 256, stdin)) {
		errno = 0;
		tc_update = strtoul(command, &endp, 10);
		if (errno || command == endp)
			return -EAGAIN;
		if (tc_update >= port_param->max_tcs) {
			fprintf(stderr, "Invalid TC ID(%d) >= %d\n",
				tc_update, port_param->max_tcs);
			return -EINVAL;
		}
	}

	*tc = tc_update;
	if (tc_update >= 0)
		return 0;

	return -EINVAL;
}

static void
l2fwd_policer_runtime_fs_miss_update(uint16_t portid,
	uint16_t tc, uint32_t *update)
{
	int off = 0, i, drop = false;
	char command[256];
	char range[1024];
	char *endp;
	struct l2fwd_policer_port_params *port_param;
	struct l2fwd_policer_tc_desc *tc_desc;
	uint16_t default_queue;

	port_param = &s_port_param[portid];
	tc_desc = &port_param->tc_descs[tc];

	memset(range, 0, sizeof(range));
	off = 0;
	for (i = 0; i < tc_desc->queue_max_num; i++) {
		off += sprintf(&range[off], "%d, ",
			tc_desc->tc_queue_ids[i]);
	}
	off += sprintf(&range[off], " drop != any");
	off += sprintf(&range[off], " %s", POLICER_UPDATE_SKIP_HINT);
	default_queue = tc_desc->default_queue;
	if (tc_desc->miss_drop) {
		fprintf(stdout,
			"\r\nEnter miss queue ID of port%d-tc%d to update:(default=drop) range[%s]: ",
			portid, tc, range);
	} else {
		fprintf(stdout,
			"\r\nEnter miss queue ID of port%d-tc%d to update:(default=%d) range[%s]: ",
			portid, tc, default_queue, range);
	}
	if (fgets(command, 256, stdin)) {
		errno = 0;
		default_queue = strtoul(command, &endp, 10);
		if (errno || command == endp)
			return;
		for (i = 0; i < tc_desc->queue_max_num; i++) {
			if (default_queue == tc_desc->tc_queue_ids[i])
				break;
		}
		if (i >= tc_desc->queue_max_num)
			drop = true;

		if (drop == true) {
			if (tc_desc->miss_drop == false) {
				*update |= ACTION_MISS_FS_UPDATE;
				tc_desc->miss_drop = true;
			}
		} else if (tc_desc->default_queue != default_queue) {
			*update |= ACTION_MISS_FS_UPDATE;
			tc_desc->default_queue = default_queue;
		}
	}
}

static void
l2fwd_policer_runtime_tc_meter_update(uint16_t portid,
	uint16_t tc, uint32_t *update)
{
	char command[256];
	char *endp;
	struct l2fwd_policer_port_params *port_param;
	struct l2fwd_policer_tc_desc *tc_desc;
	uint32_t cir_update, cbs_update, pir_update, pbs_update;
	enum rte_flow_action_type red_action;

	port_param = &s_port_param[portid];
	tc_desc = &port_param->tc_descs[tc];

	cir_update = tc_desc->meter_param.trtcm.cir;
	fprintf(stdout, "\r\nEnter cir to update:(default=%d): ",
		cir_update);
	if (fgets(command, 256, stdin)) {
		errno = 0;
		cir_update = strtoul(command, &endp, 10);
		if (errno || command == endp)
			cir_update = tc_desc->meter_param.trtcm.cir;
		if (tc_desc->meter_param.trtcm.cir != cir_update) {
			*update |= ACTION_POLICER_PROFILE_UPDATE;
			tc_desc->meter_param.trtcm.cir = cir_update;
		}
	}

	cbs_update = tc_desc->meter_param.trtcm.cbs;
	fprintf(stdout, "Enter cbs to update:(default=%d): ",
		cbs_update);
	if (fgets(command, 256, stdin)) {
		errno = 0;
		cbs_update = strtoul(command, &endp, 10);
		if (errno || command == endp)
			cbs_update = tc_desc->meter_param.trtcm.cbs;
		if (tc_desc->meter_param.trtcm.cbs != cbs_update) {
			*update |= ACTION_POLICER_PROFILE_UPDATE;
			tc_desc->meter_param.trtcm.cbs = cbs_update;
		}
	}

	pir_update = tc_desc->meter_param.trtcm.pir;
	fprintf(stdout, "Enter pir to update:(default=%d): ",
		pir_update);
	if (fgets(command, 256, stdin)) {
		errno = 0;
		pir_update = strtoul(command, &endp, 10);
		if (errno || command == endp)
			pir_update = tc_desc->meter_param.trtcm.pir;
		if (tc_desc->meter_param.trtcm.pir != pir_update) {
			*update |= ACTION_POLICER_PROFILE_UPDATE;
			tc_desc->meter_param.trtcm.pir = pir_update;
		}
	}

	pbs_update = tc_desc->meter_param.trtcm.pbs;
	fprintf(stdout, "Enter pbs to update:(default=%d): ",
		pbs_update);
	if (fgets(command, 256, stdin)) {
		errno = 0;
		pbs_update = strtoul(command, &endp, 10);
		if (errno || command == endp)
			pbs_update = tc_desc->meter_param.trtcm.pbs;
		if (tc_desc->meter_param.trtcm.pbs != pbs_update) {
			*update |= ACTION_POLICER_PROFILE_UPDATE;
			tc_desc->meter_param.trtcm.pbs = pbs_update;
		}
	}

	red_action = tc_desc->meter_param.red_action.type;
	fprintf(stdout, "Enter red action to update:(default=%s): ",
		red_action == RTE_FLOW_ACTION_TYPE_DROP ?
		"drop" : "pass");
	if (fgets(command, 256, stdin)) {
		endp = command;
		while (*endp == ' ') {
			endp++;
			if (endp - command > 10)
				break;
		}
		if (!strncmp(endp, "drop", 4))
			red_action = RTE_FLOW_ACTION_TYPE_DROP;
		else if (!strncmp(endp, "pass", 4))
			red_action = RTE_FLOW_ACTION_TYPE_PASSTHRU;
		else
			red_action = tc_desc->meter_param.red_action.type;
		if (tc_desc->meter_param.red_action.type != red_action) {
			*update |= ACTION_POLICER_POLICY_UPDATE;
			tc_desc->meter_param.red_action.type = red_action;
		}
	}
}

static void
l2fwd_policer_runtime_fs_flow_item_update(uint16_t portid,
	uint8_t tc, uint32_t *update)
{
	int off = 0, i, idx = -1, max_num = 0, item_update = -1, ret;
	char command[256];
	char range[1024];
	char *endp;
	struct l2fwd_policer_port_params *port_param;
	struct l2fwd_policer_tc_desc *tc_desc;
	void **flows;

	port_param = &s_port_param[portid];
	tc_desc = &port_param->tc_descs[tc];

	if (port_param->flow_tb_level == 1)
		flows = tc_desc->one_level_flows;
	else
		flows = tc_desc->fs_flows;
	off = 0;
	memset(range, 0, sizeof(range));
	for (i = 0; i < tc_desc->fs_max_num; i++) {
		if (flows[i])
			max_num++;
	}
	off += sprintf(range, "0 ~ %d,", max_num - 1);
	off += sprintf(&range[off], " %s", POLICER_UPDATE_SKIP_HINT);
	fprintf(stdout,
		"\r\nEnter flow ID of port%d-tc%d to update item(s): range[%s]: ",
		portid, tc, range);
	if (fgets(command, 256, stdin)) {
		errno = 0;
		idx = strtoul(command, &endp, 10);
		if (errno || command == endp)
			return;
		if (idx >= max_num) {
			fprintf(stderr, "Invalid flow(%d)\n", idx);
			return;
		}
	}
	if (idx < 0)
		return;

	off = 0;
	for (i = 0; i < (int)RTE_DIM(s_fs_item_update); i++) {
		off += sprintf(&range[off], "%s/%s:%d, ",
			s_fs_item_update[i].item_protocol,
			s_fs_item_update[i].item_field, i);
	}
	off += sprintf(&range[off], "%s", POLICER_UPDATE_SKIP_HINT);

	fprintf(stdout,
		"Enter index of flow item for port%d-tc%d-flow%d update: [%s]: ",
		portid, tc, idx, range);
	if (fgets(command, 256, stdin)) {
		errno = 0;
		item_update = strtoul(command, &endp, 10);
		if (errno || command == endp ||
			item_update >= (int)RTE_DIM(s_fs_item_update) ||
			item_update < 0)
			return;
	}
	fprintf(stdout, "Enter format: %s: ",
		s_fs_item_update[item_update].input_format);
	if (fgets(command, 256, stdin)) {
		ret = s_fs_item_update[item_update].item_parse(command,
			&s_fs_item_update[item_update]);
		if (!ret) {
			tc_desc->fs_update_pattern =
				s_fs_item_update[item_update].pattern;
			tc_desc->item_update_idx = idx;
			*update |= ITEM_FS_FLOW_UPDATE;
		}
	}
}

static void
l2fwd_policer_runtime_fs_flow_action_update(uint16_t portid,
	uint8_t tc, uint32_t *update)
{
	int i, idx = -1, max_num = 0, off = 0;
	char command[256];
	char range[1024];
	char *endp;
	struct l2fwd_policer_port_params *port_param;
	struct l2fwd_policer_tc_desc *tc_desc;
	uint16_t queue_id;
	void **flows;

	port_param = &s_port_param[portid];
	tc_desc = &port_param->tc_descs[tc];
	if (port_param->flow_tb_level == 1)
		flows = tc_desc->one_level_flows;
	else
		flows = tc_desc->fs_flows;

	memset(range, 0, sizeof(range));
	for (i = 0; i < tc_desc->fs_max_num; i++) {
		if (flows[i])
			max_num++;
	}
	off += sprintf(range, "0 ~ %d,", max_num - 1);
	off += sprintf(&range[off], " %s", POLICER_UPDATE_SKIP_HINT);
	fprintf(stdout,
		"\r\nEnter flow ID of port%d-tc%d to update action: range[%s]: ",
		portid, tc, range);
	if (fgets(command, 256, stdin)) {
		errno = 0;
		idx = strtoul(command, &endp, 10);
		if (errno || command == endp)
			return;
		if (idx >= max_num) {
			fprintf(stderr, "Invalid flow(%d)\n", idx);
			return;
		}
	}
	if (idx < 0)
		return;

	memset(range, 0, sizeof(range));
	off = 0;
	for (i = 0; i < tc_desc->queue_max_num; i++) {
		off += sprintf(&range[off], "%d, ",
			tc_desc->tc_queue_ids[i]);
	}
	off += sprintf(&range[off], " %s", POLICER_UPDATE_SKIP_HINT);
	queue_id = tc_desc->flow_queue_ids[idx];
	fprintf(stdout,
		"Enter queue ID to update:(default=%d) range[%s]: ",
		queue_id, range);
	if (fgets(command, 256, stdin)) {
		errno = 0;
		queue_id = strtoul(command, &endp, 10);
		if (errno || command == endp)
			return;
		for (i = 0; i < tc_desc->queue_max_num; i++) {
			if (queue_id == tc_desc->tc_queue_ids[i])
				break;
		}
		if (i >= tc_desc->queue_max_num) {
			fprintf(stderr, "Invalid queue ID(%d)\n", queue_id);
				return;
		}

		if (tc_desc->flow_queue_ids[idx] != queue_id) {
			*update |= ACTION_FS_QUEUE_UPDATE;
			tc_desc->flow_queue_ids[idx] = queue_id;
			tc_desc->action_update_idx = idx;
		}
	}
}

static void *
l2fwd_policer_runtime_policer_update(void *arg)
{
	int ret, meter_enable = false;
	uint16_t portid;
	uint32_t update = 0;
	uint8_t tc;

	/* Set this cpu-affinity to CPU 0 */
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(0, &cpuset);

	ret = pthread_setaffinity_np(pthread_self(),
		sizeof(cpuset), &cpuset);
	if (ret) {
		RTE_LOG(ERR, L2FWD_POLICER,
			"%s thread set affinity failed(%d)\n\n",
			__func__, ret);
		pthread_exit(NULL);
	}

	if (s_meter_action == RTE_FLOW_ACTION_TYPE_METER ||
		s_meter_action == RTE_FLOW_ACTION_TYPE_METER_MARK)
		meter_enable = true;

	while (1) {
start_again:
		if (force_quit)
			return arg;
		if (s_print_stat) {
			ret = l2fwd_policer_runtime_control_print_stat(false);
			if (ret == true) {
				s_print_stat = false;
				sleep(timer_period);
			} else {
				goto start_again;
			}
		}
		ret = l2fwd_policer_runtime_control_print_stat(true);
		if (ret == true) {
			s_print_stat = true;
			sleep(timer_period);
			goto start_again;
		}
		update = 0;
		fprintf(stdout, "\r\nStart flow update:\r\n");

		ret = l2fwd_policer_runtime_update_select_port(&portid);
		if (ret)
			goto start_again;
		tc = s_port_param[portid].max_tcs;

		l2fwd_policer_runtime_qos_miss_update(portid, &update);
		if (s_port_param[portid].flow_tb_level > 1)
			l2fwd_policer_runtime_qos_flow_item_update(portid, &update);

		ret = l2fwd_policer_runtime_update_select_tc(portid, &tc);
		if (ret)
			goto start_update;
		l2fwd_policer_runtime_fs_miss_update(portid, tc, &update);
		if (s_port_param[portid].flow_tb_level > 1)
			l2fwd_policer_runtime_fs_flow_item_update(portid, tc, &update);
		l2fwd_policer_runtime_fs_flow_action_update(portid, tc, &update);

		if (!meter_enable)
			goto start_update;
		l2fwd_policer_runtime_tc_meter_update(portid, tc, &update);

start_update:
		l2fwd_policer_qos_flow_update(portid, update);
		l2fwd_policer_tc_flow_update(portid, tc, update);
	}

	return arg;
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		force_quit = true;
		RTE_LOG(INFO, L2FWD_POLICER,
		"\n\nSignal %d received, preparing to exit...\n",
		signum);
	}
}

static int
l2fwd_policer_lcore_port_queue_add(uint16_t lcore,
	uint16_t portid, uint16_t queue_id)
{
	struct lcore_queue_conf *queue_conf;
	struct rte_eth_rxq_info qinfo;
	uint16_t flow_id;
	uint8_t tc_id;
	int ret;

	ret = rte_eth_rx_queue_info_get(portid, queue_id, &qinfo);
	if (ret) {
		rte_exit(EXIT_FAILURE,
			"Get port%d-rxq%d info failed(%d).\n",
			portid, queue_id, ret);
	}
	rte_pmd_dpaa2_rxq_parse_tc_info(&qinfo, &tc_id, &flow_id);

	queue_conf = &s_lcore_queue_conf[lcore];
	queue_conf->rx_port_list[queue_conf->n_rx_port].port_id = portid;
	queue_conf->rx_port_list[queue_conf->n_rx_port].queue_id = queue_id;
	queue_conf->n_rx_port++;
	if (!queue_conf->sch_handle) {
		queue_conf->sch_handle = rte_dpaa2_scheduler_init();
		if (!queue_conf->sch_handle) {
			rte_exit(EXIT_FAILURE,
				"Init core%d's schedule failed.\n", lcore);
		}
		ret = rte_dpaa2_scheduler_start(queue_conf->sch_handle);
		if (ret) {
			rte_exit(EXIT_FAILURE,
				"rte_dpaa2_scheduler_start:err=%d,\n", ret);
		}
	}
	ret = rte_dpaa2_scheduler_add(queue_conf->sch_handle,
		portid, queue_id, tc_id);
	if (ret) {
		rte_exit(EXIT_FAILURE,
			"Schedule port%d-rxq%d failed(%d).\n",
			portid, queue_id, ret);
	}

	return 0;
}

static int
l2fwd_policer_lcore_port_queue_config(uint16_t lcore,
	uint16_t portid)
{
	struct lcore_queue_conf *queue_conf;
	struct rte_eth_rxq_info qinfo;
	uint16_t i, queue_id, flow_id;
	uint8_t tc_id;
	int ret;

	queue_conf = &s_lcore_queue_conf[lcore];
	for (i = 0; i < queue_conf->n_rx_port; i++) {
		if (queue_conf->rx_port_list[i].port_id != portid)
			continue;
		queue_id = queue_conf->rx_port_list[i].queue_id;

		ret = rte_eth_rx_queue_info_get(portid, queue_id, &qinfo);
		if (ret) {
			rte_exit(EXIT_FAILURE,
				"Get port%d-rxq%d info failed(%d).\n",
				portid, queue_id, ret);
		}
		rte_pmd_dpaa2_rxq_parse_tc_info(&qinfo,
			&tc_id, &flow_id);
		if (!queue_conf->sch_handle) {
			queue_conf->sch_handle = rte_dpaa2_scheduler_init();
			if (!queue_conf->sch_handle) {
				rte_exit(EXIT_FAILURE,
					"Init core%d's schedule failed.\n", lcore);
			}
			ret = rte_dpaa2_scheduler_start(queue_conf->sch_handle);
			if (ret) {
				rte_exit(EXIT_FAILURE,
					"rte_dpaa2_scheduler_start:err=%d,\n", ret);
			}
		}

		/* set the scheduler WQ priority
		 * TC[0] traffic in WQ prio 0, TC[1] traffic in WQ prio 1 and so on
		 */
		ret = rte_dpaa2_scheduler_add(queue_conf->sch_handle,
			portid, queue_id, tc_id);
		if (ret) {
			rte_exit(EXIT_FAILURE,
				"Schedule port%d-rxq%d failed(%d).\n",
				portid, queue_id, ret);
		}
	}

	return 0;
}

static void
l2fwd_policer_meter_free(uint16_t portid,
	struct l2fwd_policer_meter_param *meter_param)
{
	int ret;

	if (meter_param->meter_id) {
		ret = rte_mtr_destroy(portid, *meter_param->meter_id, NULL);
		if (ret) {
			rte_exit(EXIT_FAILURE,
				"Destroy port%d's meter ID(%d) failed(%d).\n",
				portid, *meter_param->meter_id, ret);
		}
		l2fwd_policer_free_id(portid, meter_param->meter_id,
			POLICER_METER_ID_TYPE);
	}
	l2fwd_policer_meter_profile_del(portid, meter_param->profile_id);
	l2fwd_policer_meter_policy_del(portid, meter_param->policy_id);
}

static void
l2fwd_policer_port_qos_init(uint16_t portid,
	uint8_t rx_tc_num, uint16_t qos_entries)
{
	struct l2fwd_policer_port_params *port_param;

	port_param = &s_port_param[portid];
	port_param->enable = true;
	port_param->qos_flows = rte_zmalloc(NULL,
		sizeof(void *) * qos_entries, 0);
	port_param->tc_ids = rte_zmalloc(NULL,
		sizeof(uint8_t) * qos_entries, 0);
	port_param->max_qos_entries = qos_entries;
	port_param->tc_descs = rte_zmalloc(NULL,
		sizeof(struct l2fwd_policer_tc_desc) *
		rx_tc_num, 0);
	port_param->max_tcs = rx_tc_num;
	port_param->miss_drop = s_miss_drop;
	port_param->default_tc = rx_tc_num - 1;
	if (!port_param->qos_flows ||
		!port_param->tc_ids ||
		!port_param->tc_descs) {
		rte_exit(EXIT_FAILURE,
			"Failed to malloc qos memory of port%d\n",
			portid);
	}
}

static void
l2fwd_policer_port_tc_fs_init(uint16_t portid, uint8_t tc,
	uint16_t fs_entries, uint16_t queues_per_tc)
{
	struct l2fwd_policer_port_params *port_param;
	struct l2fwd_policer_tc_desc *tc_desc;

	port_param = &s_port_param[portid];
	tc_desc = &port_param->tc_descs[tc];

	tc_desc->valid = true;
	tc_desc->fs_max_num = fs_entries;
	tc_desc->queue_max_num = queues_per_tc;
	tc_desc->one_level_flows = rte_zmalloc(NULL,
		sizeof(void *) * tc_desc->fs_max_num, 0);
	tc_desc->fs_flows = rte_zmalloc(NULL,
		sizeof(void *) * tc_desc->fs_max_num, 0);
	tc_desc->flow_queue_ids = rte_zmalloc(NULL,
		sizeof(uint16_t) * tc_desc->fs_max_num, 0);
	tc_desc->tc_queue_ids = rte_zmalloc(NULL,
		sizeof(uint16_t) * tc_desc->queue_max_num, 0);
	if (!tc_desc->fs_flows || !tc_desc->flow_queue_ids ||
		!tc_desc->tc_queue_ids || !tc_desc->one_level_flows) {
		rte_exit(EXIT_FAILURE,
			"Failed to malloc fs memory of port%d-tc%d\n",
			portid, tc);
	}
}

static void
l2fwd_policer_port_tc_fs_free(uint16_t portid, uint8_t tc)
{
	uint16_t i;
	int ret;
	struct l2fwd_policer_port_params *port_param;
	struct l2fwd_policer_tc_desc *tc_desc;
	void **flows;

	port_param = &s_port_param[portid];
	tc_desc = &port_param->tc_descs[tc];

	if (port_param->flow_tb_level == 1)
		flows = tc_desc->one_level_flows;
	else
		flows = tc_desc->fs_flows;

	for (i = 0; i < tc_desc->fs_max_num; i++) {
		if (!flows[i])
			continue;
		ret = rte_flow_destroy(portid, flows[i], NULL);
		if (ret) {
			rte_exit(EXIT_FAILURE,
				"Destroy port%d-tc%d-flow%d failed(%d).\n",
				portid, tc, i, ret);
		}
		flows[i] = NULL;
	}
	if (tc_desc->meter_flow) {
		ret = rte_flow_destroy(portid, tc_desc->meter_flow, NULL);
		if (ret) {
			rte_exit(EXIT_FAILURE,
				"Destroy port%d-tc%d's meter flow failed(%d).\n",
				portid, tc, ret);
		}
		tc_desc->meter_flow = NULL;
	}

	l2fwd_policer_meter_free(portid, &tc_desc->meter_param);

	rte_free(tc_desc->one_level_flows);
	rte_free(tc_desc->fs_flows);
	rte_free(tc_desc->flow_queue_ids);
	rte_free(tc_desc->tc_queue_ids);
}

static void
l2fwd_policer_port_qos_free(uint16_t portid)
{
	uint16_t i;
	int ret;
	struct l2fwd_policer_port_params *port_param;

	port_param = &s_port_param[portid];

	for (i = 0; i < port_param->max_qos_entries; i++) {
		if (!port_param->qos_flows[i])
			continue;
		ret = rte_flow_destroy(portid, port_param->qos_flows[i], NULL);
		if (ret) {
			rte_exit(EXIT_FAILURE,
				"Destroy port%d-qos.flow[%d] failed(%d).\n",
				portid, i, ret);
		}
		port_param->qos_flows[i] = NULL;
	}
	rte_free(port_param->tc_ids);
	rte_free(port_param->qos_flows);

	for (i = 0; i < port_param->max_tcs; i++)
		l2fwd_policer_port_tc_fs_free(portid, i);

	rte_free(port_param->tc_descs);
}

int
main(int argc, char **argv)
{
	uint16_t nb_ports_available = 0, nb_ports_in_mask = 0;
	uint16_t lcore_id, portid, last_port, nb_ports, i;
	uint32_t nb_mbufs;
	int ret;
	pthread_t pid;

	/* Init EAL. 8< */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* parse application arguments (after the EAL ones) */
	ret = l2fwd_policer_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid L2FWD-POLICER arguments\n");
	/* >8 End of init EAL. */

	RTE_LOG(INFO, L2FWD_POLICER,
		"MAC updating %s\n",
		mac_updating ? "enabled" : "disabled");
	RTE_LOG(INFO, L2FWD_POLICER,
		"Flow classification %s\n",
		enable_flow ? "enabled" : "disabled");

	nb_ports = rte_eth_dev_count_avail();
	if (!nb_ports)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	/* check port mask to possible port mask */
	if (l2fwd_policer_enabled_port_mask & ~((1 << nb_ports) - 1))
		rte_exit(EXIT_FAILURE, "Invalid portmask; possible (0x%x)\n",
			(1 << nb_ports) - 1);

	/* Initialization of the driver. 8< */

	/* reset l2fwd_policer_dst_ports */
	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++)
		l2fwd_policer_dst_ports[portid] = 0;
	last_port = 0;

	/* populate destination port details */
	RTE_ETH_FOREACH_DEV(portid) {
		/* skip ports that are not enabled */
		if ((l2fwd_policer_enabled_port_mask & (1 << portid)) == 0)
			continue;

		if (nb_ports_in_mask % 2) {
			l2fwd_policer_dst_ports[portid] = last_port;
			l2fwd_policer_dst_ports[last_port] = portid;
		} else {
			last_port = portid;
		}
		nb_ports_in_mask++;
	}

	if (nb_ports_in_mask % 2) {
		RTE_LOG(NOTICE, L2FWD_POLICER,
			"odd number of ports in portmask.\n");
		l2fwd_policer_dst_ports[last_port] = last_port;
	}
	/* >8 End of initialization of the driver. */

	nb_mbufs = RTE_MAX(nb_ports * (nb_rxd +
		nb_txd + MAX_PKT_BURST), (uint16_t)8192);

	/* Create the mbuf pool. 8< */
	l2fwd_policer_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs,
		MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
		rte_socket_id());
	if (l2fwd_policer_pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");
	/* >8 End of create the mbuf pool. */

	/* Initialise each port */
	RTE_ETH_FOREACH_DEV(portid) {
		struct rte_eth_rxconf rxq_conf;
		struct rte_eth_txconf txq_conf;
		struct rte_eth_conf local_port_conf = port_conf;
		struct rte_eth_dev_info dev_info;
		struct rte_eth_rxq_info qinfo;
		uint8_t tc_id;
		uint16_t flow_id, tc_num, qos_entries, fs_entries, queues_per_tc;
		uint16_t queue_num[POLICER_TC_MAX_NUM];
		struct l2fwd_policer_tc_desc *tc_desc;

		/* skip ports that are not enabled */
		if (!(l2fwd_policer_enabled_port_mask & (1 << portid))) {
			RTE_LOG(INFO, L2FWD_POLICER,
				"Skipping disabled port %u\n", portid);
			continue;
		}
		nb_ports_available++;

		/* init port */
		printf("Initializing port %u... ", portid);
		fflush(stdout);

		ret = rte_eth_dev_info_get(portid, &dev_info);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				"Error during getting device (port %u) info: %s\n",
				portid, strerror(-ret));

		if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf.txmode.offloads |=
				RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

		rte_pmd_dpaa2_dev_parse_tc_info(&dev_info, &tc_num,
			&qos_entries, &fs_entries, &queues_per_tc);
		l2fwd_policer_port_qos_init(portid, tc_num, qos_entries);
		memset(queue_num, 0, sizeof(queue_num));
		for (tc_id = 0; tc_id < tc_num; tc_id++) {
			l2fwd_policer_port_tc_fs_init(portid, tc_id,
				fs_entries, queues_per_tc);
		}

		/* Configure the number of queues for a port. */
		ret = rte_eth_dev_configure(portid, dev_info.max_rx_queues,
			dev_info.max_tx_queues, &local_port_conf);
		if (ret) {
			rte_exit(EXIT_FAILURE,
				"Cannot configure device: err=%d, port=%u\n",
				ret, portid);
		}
		/* >8 End of configuration of the number of queues for a port. */

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
		if (ret) {
			rte_exit(EXIT_FAILURE,
				 "Cannot adjust number of descriptors: err=%d, port=%u\n",
				 ret, portid);
		}

		ret = rte_eth_macaddr_get(portid,
			&l2fwd_policer_ports_eth_addr[portid]);
		if (ret) {
			rte_exit(EXIT_FAILURE,
				 "Cannot get MAC address: err=%d, port=%u\n",
				 ret, portid);
		}

		/* init one RX queue */
		fflush(stdout);

		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = local_port_conf.rxmode.offloads;

		for (i = 0; i < dev_info.max_rx_queues; i++) {
			/* RX queue setup. 8< */
			ret = rte_eth_rx_queue_setup(portid, i, nb_rxd,
				rte_eth_dev_socket_id(portid),
				&rxq_conf,
				l2fwd_policer_pktmbuf_pool);
			if (ret) {
				rte_exit(EXIT_FAILURE,
					"Setup port%d-rxq%d failed(%d).\n",
					portid, i, ret);
			}

			ret = rte_eth_rx_queue_info_get(portid, i, &qinfo);
			if (ret) {
				rte_exit(EXIT_FAILURE,
					"Get port%d-rxq%d info failed(%d).\n",
					portid, i, ret);
			}
			rte_pmd_dpaa2_rxq_parse_tc_info(&qinfo,
				&tc_id, &flow_id);
			tc_desc = &s_port_param[portid].tc_descs[tc_id];
			tc_desc->tc_queue_ids[queue_num[tc_id]] = i;
			queue_num[tc_id]++;
			/* >8 End of RX queue setup. */
		}

		if (!s_port_queue_nb[portid]) {
			lcore_id = rte_get_main_lcore();
			for (i = 0; i < dev_info.max_rx_queues; i++) {
				ret = l2fwd_policer_lcore_port_queue_add(lcore_id, portid, i);
				if (ret) {
					rte_exit(EXIT_FAILURE,
						"Add port(%d) lcore(%d) queue(%d): err=%d\n",
						portid, lcore_id, i, ret);
				}
			}
		} else {
			for (i = 0; i < RTE_MAX_LCORE; i++) {
				ret = l2fwd_policer_lcore_port_queue_config(i, portid);
				if (ret) {
					rte_exit(EXIT_FAILURE,
						"Config port(%d) i(%d): err=%d\n",
						portid, i, ret);
				}
			}
		}

		/* Init one TX queue on each port. 8< */
		fflush(stdout);
		txq_conf = dev_info.default_txconf;
		txq_conf.offloads = local_port_conf.txmode.offloads;
		ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
				rte_eth_dev_socket_id(portid),
				&txq_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
				ret, portid);
		/* >8 End of init one TX queue on each port. */

		ret = rte_eth_dev_set_ptypes(portid, RTE_PTYPE_UNKNOWN, NULL, 0);
		if (ret) {
			RTE_LOG(WARNING, L2FWD_POLICER,
				"Port %u, Failed to disable Ptype parsing\n",
				portid);
		}
		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
				  ret, portid);

		printf("done: \n");
		if (promiscuous_on) {
			ret = rte_eth_promiscuous_enable(portid);
			if (ret) {
				rte_exit(EXIT_FAILURE,
					"rte_eth_promiscuous_enable:err=%s, port=%u\n",
					rte_strerror(-ret), portid);
			}
		}

		RTE_LOG(INFO, L2FWD_POLICER,
			"Port%u: %d TCs, %d QoS entries, %d FS entries, %d queues per TC, MAC:"
			RTE_ETHER_ADDR_PRT_FMT"\n",
			portid, tc_num, qos_entries, fs_entries, queues_per_tc,
			RTE_ETHER_ADDR_BYTES(&l2fwd_policer_ports_eth_addr[portid]));

		/* initialize port stats */
		memset(&port_statistics, 0, sizeof(port_statistics));
	}

	if (enable_flow) {
		RTE_ETH_FOREACH_DEV(portid) {
			if (!s_port_param[portid].enable)
				continue;
			s_port_param[portid].flow_tb_level = s_flow_table_level;
			l2fwd_policer_flow_init_config(portid, &s_port_param[portid]);
		}

		ret = pthread_create(&pid, NULL,
			l2fwd_policer_runtime_policer_update, NULL);
		if (ret) {
			rte_exit(EXIT_FAILURE,
				"Flow action update thread create failed(%d)\n",
				ret);
		}
	}

	if (!nb_ports_available) {
		rte_exit(EXIT_FAILURE,
			"All available ports are disabled. Please set portmask.\n");
	}

	tc_statistics = rte_zmalloc(NULL,
		sizeof(struct l2fwd_policer_byte_statistics) *
		RTE_MAX_ETHPORTS * POLICER_TC_MAX_NUM, 0);
	if (!tc_statistics) {
		rte_exit(EXIT_FAILURE,
			"tc statistics malloc failed\n");
	}
	prev_tc_statistics = rte_zmalloc(NULL,
		sizeof(struct l2fwd_policer_byte_statistics) *
		RTE_MAX_ETHPORTS * POLICER_TC_MAX_NUM, 0);
	if (!prev_tc_statistics) {
		rte_exit(EXIT_FAILURE,
			"prev tc statistics malloc failed\n");
	}

	check_all_ports_link_status(l2fwd_policer_enabled_port_mask);

	ret = pthread_create(&pid, NULL, l2fwd_policer_print_stats, NULL);
	if (ret) {
		rte_exit(EXIT_FAILURE,
			"perf statistics thread create failed(%d)\n",
			ret);
	}
	ret = 0;
	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(l2fwd_policer_launch_one_lcore, NULL, CALL_MAIN);
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}

	RTE_ETH_FOREACH_DEV(portid) {
		if (!(l2fwd_policer_enabled_port_mask & (1 << portid)))
			continue;
		l2fwd_policer_port_qos_free(portid);

		for (i = POLICER_METER_ID_TYPE; i < POLICER_ID_TYPE_MAX; i++) {
			if (s_id_pool[portid][i])
				rte_ring_free(s_id_pool[portid][i]);
			s_id_pool[portid][i] = NULL;
		}
		printf("Closing port %d...", portid);
		ret = rte_eth_dev_stop(portid);
		if (ret) {
			RTE_LOG(ERR, L2FWD_POLICER,
				"Stop Port %u error(%d)\n",
				portid, ret);
		}
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}
	rte_free(tc_statistics);
	rte_free(prev_tc_statistics);

	/* clean up the EAL */
	rte_eal_cleanup();
	printf("Bye...\n");

	return ret;
}

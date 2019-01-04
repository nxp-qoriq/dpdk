/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2016 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *   Copyright 2018 NXP
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_vect.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
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
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>
#include <rte_cpuflags.h>
#include <rte_eventdev.h>
#include <rte_event_eth_rx_adapter.h>
#include <rte_string_fns.h>
#include <rte_spinlock.h>
#include <rte_malloc.h>

#include <cmdline_parse.h>
#include <cmdline_parse_etheraddr.h>

#include "l3fwd.h"

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512

#define MAX_TX_QUEUE_PER_PORT RTE_MAX_ETHPORTS
#define MAX_RX_QUEUE_PER_PORT 128

#define MAX_LCORE_PARAMS 1024

/* Static global variables used within this file. */
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

uint32_t max_pkt_burst = MAX_PKT_BURST;
uint32_t max_tx_burst = MAX_TX_BURST;
uint32_t max_rx_burst = MAX_PKT_BURST;

/**< Ports set in promiscuous mode off by default. */
static int promiscuous_on;

/* Select Longest-Prefix or Exact match. */
static int l3fwd_lpm_on;
static int l3fwd_em_on;

/* Global variables. */

static int numa_on = 1; /**< NUMA is enabled by default. */
static int parse_ptype; /**< Parse packet type using rx callback, and */
			/**< disabled by default */
static int per_port_pool = 1; /**< Use separate buffer pools per port */

volatile bool force_quit;

/* ethernet addresses of ports */
uint64_t dest_eth_addr[RTE_MAX_ETHPORTS];
struct ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

xmm_t val_eth[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
uint32_t enabled_port_mask;

struct eventdev_params {
	uint8_t num_eventqueue;
	uint8_t num_eventport;
	uint8_t eventdev_id;
};

static struct eventdev_params eventdev_config[RTE_MAX_EVENTDEV_COUNT];
static uint16_t nb_eventdev_params;
struct eventdev_info *event_devices;

struct connection_info {
	uint8_t ethdev_id;
	uint8_t eventq_id;
	uint8_t event_prio;
	uint8_t ethdev_rx_qid;
	int32_t ethdev_rx_qid_mode;
	int32_t eventdev_id;
	int32_t adapter_id;
};
struct adapter_config {
	struct connection_info connections[RTE_MAX_EVENTDEV_COUNT];
	uint8_t nb_connections;
};

struct adapter_params {
	struct adapter_config config[RTE_MAX_EVENTDEV_COUNT];
	uint8_t nb_rx_adapter;
};
static struct adapter_params rx_adapter_config;
struct link_params link_config;
enum dequeue_mode lcore_dequeue_mode[RTE_MAX_LCORE];

/* Used only in exact match mode. */
int ipv6; /**< ipv6 is false by default. */
uint32_t hash_entry_number = HASH_ENTRY_NUMBER_DEFAULT;

struct lcore_conf lcore_conf[RTE_MAX_LCORE];

struct lcore_params {
	uint16_t port_id;
	uint8_t queue_id;
	uint8_t lcore_id;
} __rte_cache_aligned;

static struct lcore_params lcore_params_array[MAX_LCORE_PARAMS];
static struct lcore_params lcore_params_array_default[] = {
	{0, 0, 2},
	{0, 1, 2},
	{0, 2, 2},
	{1, 0, 2},
	{1, 1, 2},
	{1, 2, 2},
	{2, 0, 2},
	{3, 0, 3},
	{3, 1, 3},
};

static struct lcore_params * lcore_params = lcore_params_array_default;
static uint16_t nb_lcore_params = sizeof(lcore_params_array_default) /
				sizeof(lcore_params_array_default[0]);

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = ETH_MQ_RX_RSS,
		.max_rx_pkt_len = ETHER_MAX_LEN,
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 1, /**< IP checksum offload enabled */
		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 1, /**< CRC stripped by hardware */
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = ETH_RSS_IP,
		},
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

static struct rte_mempool *pktmbuf_pool[RTE_MAX_ETHPORTS][NB_SOCKETS];
static uint8_t lkp_per_socket[NB_SOCKETS];

struct l3fwd_lkp_mode {
	void  (*setup)(int);
	int   (*check_ptype)(int);
	rte_rx_callback_fn cb_parse_ptype;
	int   (*main_loop)(void *);
	void* (*get_ipv4_lookup_struct)(int);
	void* (*get_ipv6_lookup_struct)(int);
};

static struct l3fwd_lkp_mode l3fwd_lkp;

static struct l3fwd_lkp_mode l3fwd_em_lkp = {
	.setup                  = setup_hash,
	.check_ptype		= em_check_ptype,
	.cb_parse_ptype		= em_cb_parse_ptype,
	.main_loop              = em_main_loop,
	.get_ipv4_lookup_struct = em_get_ipv4_l3fwd_lookup_struct,
	.get_ipv6_lookup_struct = em_get_ipv6_l3fwd_lookup_struct,
};

static struct l3fwd_lkp_mode l3fwd_lpm_lkp = {
	.setup                  = setup_lpm,
	.check_ptype		= lpm_check_ptype,
	.cb_parse_ptype		= lpm_cb_parse_ptype,
	.main_loop              = lpm_main_loop,
	.get_ipv4_lookup_struct = lpm_get_ipv4_l3fwd_lookup_struct,
	.get_ipv6_lookup_struct = lpm_get_ipv6_l3fwd_lookup_struct,
};

/*
 * Setup lookup methods for forwarding.
 * Currently exact-match and longest-prefix-match
 * are supported ones.
 */
static void
setup_l3fwd_lookup_tables(void)
{
	/* Setup HASH lookup functions. */
	if (l3fwd_em_on)
		l3fwd_lkp = l3fwd_em_lkp;
	/* Setup LPM lookup functions. */
	else
		l3fwd_lkp = l3fwd_lpm_lkp;
}

static int
check_lcore_params(void)
{
	uint8_t queue, lcore;
	uint16_t i;
	int socketid;

	for (i = 0; i < nb_lcore_params; ++i) {
		queue = lcore_params[i].queue_id;
		if (queue >= MAX_RX_QUEUE_PER_PORT) {
			printf("invalid queue number: %hhu\n", queue);
			return -1;
		}
		lcore = lcore_params[i].lcore_id;
		if (!rte_lcore_is_enabled(lcore)) {
			printf("error: lcore %hhu is not enabled in lcore mask\n", lcore);
			return -1;
		}
		if ((socketid = rte_lcore_to_socket_id(lcore) != 0) &&
			(numa_on == 0)) {
			printf("warning: lcore %hhu is on socket %d with numa off \n",
				lcore, socketid);
		}
	}
	return 0;
}

static int
check_port_config(const unsigned nb_ports)
{
	uint16_t portid;
	uint16_t i;

	for (i = 0; i < nb_lcore_params; ++i) {
		portid = lcore_params[i].port_id;
		if ((enabled_port_mask & (1 << portid)) == 0) {
			printf("port %u is not enabled in port mask\n", portid);
			return -1;
		}
		if (portid >= nb_ports) {
			printf("port %u is not present on the board\n", portid);
			return -1;
		}
	}
	return 0;
}

static uint8_t
get_port_n_rx_queues(const uint16_t port)
{
	int queue = -1;
	uint16_t i;

	for (i = 0; i < nb_lcore_params; ++i) {
		if (lcore_params[i].port_id == port) {
			if (lcore_params[i].queue_id == queue+1)
				queue = lcore_params[i].queue_id;
			else
				rte_exit(EXIT_FAILURE, "queue ids of the port %d must be"
						" in sequence and must start with 0\n",
						lcore_params[i].port_id);
		}
	}
	return (uint8_t)(++queue);
}

static int
init_lcore_rx_queues(void)
{
	uint16_t i, nb_rx_queue;
	uint8_t lcore;

	for (i = 0; i < nb_lcore_params; ++i) {
		lcore = lcore_params[i].lcore_id;
		nb_rx_queue = lcore_conf[lcore].n_rx_queue;
		if (nb_rx_queue >= MAX_RX_QUEUE_PER_LCORE) {
			printf("error: too many queues (%u) for lcore: %u\n",
				(unsigned)nb_rx_queue + 1, (unsigned)lcore);
			return -1;
		} else {
			lcore_conf[lcore].rx_queue_list[nb_rx_queue].port_id =
				lcore_params[i].port_id;
			lcore_conf[lcore].rx_queue_list[nb_rx_queue].queue_id =
				lcore_params[i].queue_id;
			lcore_conf[lcore].n_rx_queue++;
		}
	}
	return 0;
}

/* display usage */
static void
print_usage(const char *prgname)
{
	printf("%s [EAL options] --"
		" -p PORTMASK"
		" [-P]"
		" [-E]"
		" [-L]"
		" [-e] eventdev config (eventdev, No. of event queues, No. of event ports)"
		"			[,(eventdev,No. of event queues,No. of event ports)]"
		" [-a] adapter config (port, queue, queue mode, event queue, event priority,"
		"		eventdev)[,(port, queue, queue mode, event queue,"
		"		event priority,eventdev)]"
		" [-l] port link config (event port, event queue,eventdev,lcore)"
		"		[,(event port,event queue,eventdev,lcore)]"
		" --config (port,queue,lcore)[,(port,queue,lcore)]"
		" [--eth-dest=X,MM:MM:MM:MM:MM:MM]"
		" [--enable-jumbo [--max-pkt-len PKTLEN]]"
		" [--no-numa]"
		" [--hash-entry-num]"
		" [--ipv6]"
		" [--parse-ptype]"
		" [--disable-per-port-pool]\n\n"

		"  -p PORTMASK: Hexadecimal bitmask of ports to configure\n"
		"  -P : Enable promiscuous mode\n"
		"  -E : Enable exact match\n"
		"  -L : Enable longest prefix match (default)\n"
		"  --config (port,queue,lcore): Rx queue configuration\n"
		"  --eth-dest=X,MM:MM:MM:MM:MM:MM: Ethernet destination for port X\n"
		"  --enable-jumbo: Enable jumbo frames\n"
		"  --max-pkt-len: Under the premise of enabling jumbo,\n"
		"                 maximum packet length in decimal (64-9600)\n"
		"  --no-numa: Disable numa awareness\n"
		"  --hash-entry-num: Specify the hash entry number in hexadecimal to be setup\n"
		"  --ipv6: Set if running ipv6 packets\n"
		"  --parse-ptype: Set to use software to analyze packet type\n"
		"  --disable-per-port-pool: Disable separate buffer pool per port\n"
		"  -e : Event dev configuration\n"
		"	(Eventdev ID,Number of event queues,Number of event ports)\n"
		"  -a : Adapter configuration\n"
		"	(Ethdev Port ID,Ethdev Rx Queue ID,Ethdev Rx"
		"	QueueID mode, Event Queue ID,"
		"	Event Priority,Eventdev ID)\n"
		"  -l : Event port and Event Queue link configuration\n"
		"	(Event Port ID,Event Queue ID,Eventdev ID,lcore)\n"
		"  -b NUM: burst size for receive packet (default is 32)\n\n",
		prgname);
}

static int
parse_max_pkt_len(const char *pktlen)
{
	char *end = NULL;
	unsigned long len;

	/* parse decimal string */
	len = strtoul(pktlen, &end, 10);
	if ((pktlen[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (len == 0)
		return -1;

	return len;
}

static int
parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (pm == 0)
		return -1;

	return pm;
}

static int
parse_hash_entry_number(const char *hash_entry_num)
{
	char *end = NULL;
	unsigned long hash_en;
	/* parse hexadecimal string */
	hash_en = strtoul(hash_entry_num, &end, 16);
	if ((hash_entry_num[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (hash_en == 0)
		return -1;

	return hash_en;
}

static int
parse_config(const char *q_arg)
{
	char s[256];
	const char *p, *p0 = q_arg;
	char *end;
	enum fieldnames {
		FLD_PORT = 0,
		FLD_QUEUE,
		FLD_LCORE,
		_NUM_FLD
	};
	unsigned long int_fld[_NUM_FLD];
	char *str_fld[_NUM_FLD];
	int i;
	unsigned size;

	nb_lcore_params = 0;

	while ((p = strchr(p0,'(')) != NULL) {
		++p;
		if((p0 = strchr(p,')')) == NULL)
			return -1;

		size = p0 - p;
		if(size >= sizeof(s))
			return -1;

		snprintf(s, sizeof(s), "%.*s", size, p);
		if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
			return -1;
		for (i = 0; i < _NUM_FLD; i++){
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i] || int_fld[i] > 255)
				return -1;
		}
		if (nb_lcore_params >= MAX_LCORE_PARAMS) {
			printf("exceeded max number of lcore params: %hu\n",
				nb_lcore_params);
			return -1;
		}
		lcore_params_array[nb_lcore_params].port_id =
			(uint8_t)int_fld[FLD_PORT];
		lcore_params_array[nb_lcore_params].queue_id =
			(uint8_t)int_fld[FLD_QUEUE];
		lcore_params_array[nb_lcore_params].lcore_id =
			(uint8_t)int_fld[FLD_LCORE];
		++nb_lcore_params;
	}
	lcore_params = lcore_params_array;
	return 0;
}

static void
parse_eth_dest(const char *optarg)
{
	uint16_t portid;
	char *port_end;
	uint8_t c, *dest, peer_addr[6];

	errno = 0;
	portid = strtoul(optarg, &port_end, 10);
	if (errno != 0 || port_end == optarg || *port_end++ != ',')
		rte_exit(EXIT_FAILURE,
		"Invalid eth-dest: %s", optarg);
	if (portid >= RTE_MAX_ETHPORTS)
		rte_exit(EXIT_FAILURE,
		"eth-dest: port %d >= RTE_MAX_ETHPORTS(%d)\n",
		portid, RTE_MAX_ETHPORTS);

	if (cmdline_parse_etheraddr(NULL, port_end,
		&peer_addr, sizeof(peer_addr)) < 0)
		rte_exit(EXIT_FAILURE,
		"Invalid ethernet address: %s\n",
		port_end);
	dest = (uint8_t *)&dest_eth_addr[portid];
	for (c = 0; c < 6; c++)
		dest[c] = peer_addr[c];
	*(uint64_t *)(val_eth + portid) = dest_eth_addr[portid];
}

static int
parse_eventdev_config(const char *evq_arg)
{
	char s[256];
	const char *p, *p0 = evq_arg;
	char *end;
	enum fieldnames {
		FLD_EVENTDEV_ID = 0,
		FLD_EVENT_QUEUE,
		FLD_EVENT_PORT,
		FLD_COUNT
	};
	unsigned long int_fld[FLD_COUNT];
	char *str_fld[FLD_COUNT];
	int i;
	unsigned int size;

	/*First set all eventdev_config to default*/
	for (i = 0; i < RTE_MAX_EVENTDEV_COUNT; i++) {
		eventdev_config[i].num_eventqueue = 1;
		eventdev_config[i].num_eventport = RTE_MAX_LCORE;
	}

	nb_eventdev_params = 0;

	while ((p = strchr(p0, '(')) != NULL) {
		++p;
		if ((p0 = strchr(p, ')')) == NULL)
			return -1;

		size = p0 - p;
		if (size >= sizeof(s))
			return -1;

		snprintf(s, sizeof(s), "%.*s", size, p);
		if (rte_strsplit(s, sizeof(s), str_fld, FLD_COUNT, ',') !=
								FLD_COUNT)
			return -1;

		for (i = 0; i < FLD_COUNT; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i] || int_fld[i] > 255)
				return -1;
		}

		if (nb_eventdev_params >= RTE_MAX_EVENTDEV_COUNT) {
			printf("exceeded max number of eventdev params: %hu\n",
				nb_eventdev_params);
			return -1;
		}

		eventdev_config[nb_eventdev_params].num_eventqueue =
					(uint8_t)int_fld[FLD_EVENT_QUEUE];
		eventdev_config[nb_eventdev_params].num_eventport =
					(uint8_t)int_fld[FLD_EVENT_PORT];
		eventdev_config[nb_eventdev_params].eventdev_id =
					(uint8_t)int_fld[FLD_EVENTDEV_ID];
		++nb_eventdev_params;
	}

	return 0;
}

static int
parse_adapter_config(const char *evq_arg)
{
	char s[256];
	const char *p, *p0 = evq_arg;
	char *end;
	enum fieldnames {
		FLD_ETHDEV_ID = 0,
		FLD_ETHDEV_QID,
		FLD_EVENT_QID_MODE,
		FLD_EVENTQ_ID,
		FLD_EVENT_PRIO,
		FLD_EVENT_DEVID,
		FLD_COUNT
	};
	unsigned long int_fld[FLD_COUNT];
	char *str_fld[FLD_COUNT];
	int i, index = 0, j = 0;
	unsigned int size;

	index = rx_adapter_config.nb_rx_adapter;

	while ((p = strchr(p0, '(')) != NULL) {
		j = rx_adapter_config.config[index].nb_connections;
		++p;
		if ((p0 = strchr(p, ')')) == NULL)
			return -1;

		size = p0 - p;
		if (size >= sizeof(s))
			return -1;

		snprintf(s, sizeof(s), "%.*s", size, p);
		if (rte_strsplit(s, sizeof(s), str_fld, FLD_COUNT, ',') !=
								FLD_COUNT)
			return -1;

		for (i = 0; i < FLD_COUNT; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i] || int_fld[i] > 255)
				return -1;
		}

		if (index >= RTE_MAX_EVENTDEV_COUNT) {
			printf("exceeded max number of eventdev params: %hu\n",
				rx_adapter_config.nb_rx_adapter);
			return -1;
		}

		rx_adapter_config.config[index].connections[j].ethdev_id =
					(uint8_t)int_fld[FLD_ETHDEV_ID];
		rx_adapter_config.config[index].connections[j].ethdev_rx_qid =
					(uint8_t)int_fld[FLD_ETHDEV_QID];
		rx_adapter_config.config[index].connections[j].ethdev_rx_qid_mode =
					(uint8_t)int_fld[FLD_EVENT_QID_MODE];
		rx_adapter_config.config[index].connections[j].eventq_id =
					(uint8_t)int_fld[FLD_EVENTQ_ID];
		rx_adapter_config.config[index].connections[j].event_prio =
					(uint8_t)int_fld[FLD_EVENT_PRIO];
		rx_adapter_config.config[index].connections[j].eventdev_id =
					(uint8_t)int_fld[FLD_EVENT_DEVID];
		rx_adapter_config.config[index].nb_connections++;
	}

	return 0;
}

static int
parse_link_config(const char *evq_arg)
{
	char s[256];
	const char *p, *p0 = evq_arg;
	char *end;
	enum fieldnames {
		FLD_EVENT_PORTID = 0,
		FLD_EVENT_QID,
		FLD_EVENT_DEVID,
		FLD_LCORE_ID,
		FLD_COUNT
	};
	unsigned long int_fld[FLD_COUNT];
	char *str_fld[FLD_COUNT];
	int i, index = 0;
	unsigned int size;

	/*First set all adapter_config to default*/
	memset(&link_config, 0, sizeof(struct link_params));
	while ((p = strchr(p0, '(')) != NULL) {
		index = link_config.nb_links;
		++p;
		if ((p0 = strchr(p, ')')) == NULL)
			return -1;

		size = p0 - p;
		if (size >= sizeof(s))
			return -1;

		snprintf(s, sizeof(s), "%.*s", size, p);
		if (rte_strsplit(s, sizeof(s), str_fld, FLD_COUNT, ',') !=
								FLD_COUNT)
			return -1;

		for (i = 0; i < FLD_COUNT; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i] || int_fld[i] > 255)
				return -1;
		}

		if (index >= RTE_MAX_EVENTDEV_COUNT) {
			printf("exceeded max number of eventdev params: %hu\n",
				link_config.nb_links);
			return -1;
		}

		link_config.links[index].event_portid =
					(uint8_t)int_fld[FLD_EVENT_PORTID];
		link_config.links[index].eventq_id =
					(uint8_t)int_fld[FLD_EVENT_QID];
		link_config.links[index].eventdev_id =
					(uint8_t)int_fld[FLD_EVENT_DEVID];
		link_config.links[index].lcore_id =
					(uint8_t)int_fld[FLD_LCORE_ID];
		lcore_dequeue_mode[link_config.links[index].lcore_id] =
					EVENTDEV_DEQUEUE;
		link_config.nb_links++;
	}

	return 0;
}

static int
eventdev_configure(void)
{
	int ret = -1;
	uint8_t i, j;
	void *ports, *queues;
	struct rte_event_dev_config eventdev_conf = {0};
	struct rte_event_dev_info eventdev_def_conf = {0};
	struct rte_event_queue_conf eventq_conf = {0};
	struct rte_event_port_conf port_conf = {0};
	struct rte_event_eth_rx_adapter_queue_conf queue_conf = {0};

	/*First allocate space for event device information*/
	event_devices = rte_zmalloc("event-dev",
				sizeof(struct eventdev_info) * nb_eventdev_params, 0);
	if (event_devices == NULL) {
		printf("Error in allocating memory for event devices\n");
		return ret;
	}

	for (i = 0; i < nb_eventdev_params; i++) {
		/*Now allocate space for event ports request from user*/
		ports = rte_zmalloc("event-ports",
				sizeof(uint8_t) * eventdev_config[i].num_eventport, 0);
		if (ports == NULL) {
			printf("Error in allocating memory for event ports\n");
			rte_free(event_devices);
			return ret;
		}

		event_devices[i].port = ports;

		/*Now allocate space for event queues request from user*/
		queues = rte_zmalloc("event-queues",
				sizeof(uint8_t) * eventdev_config[i].num_eventqueue, 0);
		if (queues == NULL) {
			printf("Error in allocating memory for event queues\n");
			rte_free(event_devices[i].port);
			rte_free(event_devices);
			return ret;
		}

		event_devices[i].queue = queues;
		event_devices[i].dev_id = eventdev_config[i].eventdev_id;

		/* get default values of eventdev*/
		memset(&eventdev_def_conf, 0,
		       sizeof(struct rte_event_dev_info));
		ret = rte_event_dev_info_get(event_devices[i].dev_id,
				       &eventdev_def_conf);
		if (ret < 0) {
			printf("Error in getting event device info, devid: %d\n",
				event_devices[i].dev_id);
			return ret;
		}

		memset(&eventdev_conf, 0, sizeof(struct rte_event_dev_config));
		eventdev_conf.nb_events_limit = -1;
		eventdev_conf.nb_event_queues =
					eventdev_config[i].num_eventqueue;
		eventdev_conf.nb_event_ports =
					eventdev_config[i].num_eventport;
		eventdev_conf.nb_event_queue_flows =
				eventdev_def_conf.max_event_queue_flows;
		eventdev_conf.nb_event_port_dequeue_depth =
				eventdev_def_conf.max_event_port_dequeue_depth;
		eventdev_conf.nb_event_port_enqueue_depth =
				eventdev_def_conf.max_event_port_enqueue_depth;

		ret = rte_event_dev_configure(event_devices[i].dev_id,
					&eventdev_conf);
		if (ret < 0) {
			printf("Error in configuring event device\n");
			return ret;
		}

		memset(&eventq_conf, 0, sizeof(struct rte_event_queue_conf));
		eventq_conf.nb_atomic_flows = 1;
		eventq_conf.schedule_type = RTE_SCHED_TYPE_ATOMIC;
		for (j = 0; j < eventdev_config[i].num_eventqueue; j++) {
			ret = rte_event_queue_setup(event_devices[i].dev_id, j,
					      &eventq_conf);
			if (ret < 0) {
				printf("Error in event queue setup\n");
				return ret;
			}
			event_devices[i].queue[j] = j;
		}

		for (j = 0; j <  eventdev_config[i].num_eventport; j++) {
			ret = rte_event_port_setup(event_devices[i].dev_id, j, NULL);
			if (ret < 0) {
				printf("Error in event port setup\n");
				return ret;
			}
			event_devices[i].port[j] = j;
		}
	}

	for (i = 0; i < rx_adapter_config.nb_rx_adapter; i++) {
		for (j = 0; j < rx_adapter_config.config[i].nb_connections; j++) {
			ret = rte_event_eth_rx_adapter_create(j,
					rx_adapter_config.config[i].connections[j].eventdev_id,
					&port_conf);
			if (ret < 0) {
				printf("Error in event eth adapter creation\n");
				return ret;
			}
			rx_adapter_config.config[i].connections[j].adapter_id =
					j;
		}
	}

	for (j = 0; j <  link_config.nb_links; j++) {
		ret = rte_event_port_link(link_config.links[j].eventdev_id,
				    link_config.links[j].event_portid,
				    &link_config.links[j].eventq_id, NULL, 1);
		if (ret < 0) {
			printf("Error in event port linking\n");
			return ret;
		}
	}

	queue_conf.rx_queue_flags =
				RTE_EVENT_ETH_RX_ADAPTER_QUEUE_FLOW_ID_VALID;

	for (i = 0; i <  rx_adapter_config.nb_rx_adapter; i++) {
		for (j = 0; j < rx_adapter_config.config[i].nb_connections; j++) {
			queue_conf.ev.queue_id =
				rx_adapter_config.config[i].connections[j].eventq_id;
			queue_conf.ev.priority =
				rx_adapter_config.config[i].connections[j].event_prio;
			queue_conf.ev.flow_id =
				rx_adapter_config.config[i].connections[j].ethdev_id;
			queue_conf.ev.sched_type =
				rx_adapter_config.config[i].connections[j].ethdev_rx_qid_mode;
			ret = rte_event_eth_rx_adapter_queue_add(
				rx_adapter_config.config[i].connections[j].adapter_id,
				rx_adapter_config.config[i].connections[j].ethdev_id,
				rx_adapter_config.config[i].connections[j].ethdev_rx_qid,
				&queue_conf);
			if (ret < 0) {
				printf("Error in adding eth queue in event adapter\n");
				return ret;
			}
		}
	}

	for (i = 0; i < nb_eventdev_params; i++) {
		ret = rte_event_dev_start(event_devices[i].dev_id);
		if (ret < 0) {
			printf("Error in starting event device, devid: %d\n",
				event_devices[i].dev_id);
			return ret;
		}
	}

	return 0;
}

#define MAX_JUMBO_PKT_LEN  9600
#define MEMPOOL_CACHE_SIZE 256

static const char short_options[] =
	"p:"  /* portmask */
	"P"   /* promiscuous */
	"L"   /* enable long prefix match */
	"E"   /* enable exact match */
	"e:"  /* Event Device configuration */
	"a:"  /* Rx Adapter configuration */
	"l:"  /* Event Queue and Adapter link configuration */
	"b:"  /* burst size */
	;

#define CMD_LINE_OPT_CONFIG "config"
#define CMD_LINE_OPT_ETH_DEST "eth-dest"
#define CMD_LINE_OPT_NO_NUMA "no-numa"
#define CMD_LINE_OPT_IPV6 "ipv6"
#define CMD_LINE_OPT_ENABLE_JUMBO "enable-jumbo"
#define CMD_LINE_OPT_HASH_ENTRY_NUM "hash-entry-num"
#define CMD_LINE_OPT_PARSE_PTYPE "parse-ptype"
#define CMD_LINE_OPT_PER_PORT_POOL "disable-per-port-pool"
enum {
	/* long options mapped to a short option */

	/* first long only option value must be >= 256, so that we won't
	 * conflict with short options */
	CMD_LINE_OPT_MIN_NUM = 256,
	CMD_LINE_OPT_CONFIG_NUM,
	CMD_LINE_OPT_ETH_DEST_NUM,
	CMD_LINE_OPT_NO_NUMA_NUM,
	CMD_LINE_OPT_IPV6_NUM,
	CMD_LINE_OPT_ENABLE_JUMBO_NUM,
	CMD_LINE_OPT_HASH_ENTRY_NUM_NUM,
	CMD_LINE_OPT_PARSE_PTYPE_NUM,
	CMD_LINE_OPT_PARSE_PER_PORT_POOL,
};

static const struct option lgopts[] = {
	{CMD_LINE_OPT_CONFIG, 1, 0, CMD_LINE_OPT_CONFIG_NUM},
	{CMD_LINE_OPT_ETH_DEST, 1, 0, CMD_LINE_OPT_ETH_DEST_NUM},
	{CMD_LINE_OPT_NO_NUMA, 0, 0, CMD_LINE_OPT_NO_NUMA_NUM},
	{CMD_LINE_OPT_IPV6, 0, 0, CMD_LINE_OPT_IPV6_NUM},
	{CMD_LINE_OPT_ENABLE_JUMBO, 0, 0, CMD_LINE_OPT_ENABLE_JUMBO_NUM},
	{CMD_LINE_OPT_HASH_ENTRY_NUM, 1, 0, CMD_LINE_OPT_HASH_ENTRY_NUM_NUM},
	{CMD_LINE_OPT_PARSE_PTYPE, 0, 0, CMD_LINE_OPT_PARSE_PTYPE_NUM},
	{CMD_LINE_OPT_PER_PORT_POOL, 0, 0, CMD_LINE_OPT_PARSE_PER_PORT_POOL},
	{NULL, 0, 0, 0}
};

/*
 * This expression is used to calculate the number of mbufs needed
 * depending on user input, taking  into account memory for rx and
 * tx hardware rings, cache per lcore and mtable per port per lcore.
 * RTE_MAX is used to ensure that NB_MBUF never goes below a minimum
 * value of 2048
 */
#define NB_MBUF(nports) RTE_MAX(	\
	(nports*nb_rx_queue*nb_rxd +		\
	nports*nb_lcores*MAX_PKT_BURST +	\
	nports*n_tx_queue*nb_txd +		\
	nb_lcores*MEMPOOL_CACHE_SIZE),		\
	(unsigned)2048)

/* Parse the argument given in the command line of the application */
static int
parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	unsigned int burst_size;

	argvopt = argv;

	/* Error or normal output strings. */
	const char *str1 = "L3FWD: Invalid portmask";
	const char *str2 = "L3FWD: Promiscuous mode selected";
	const char *str3 = "L3FWD: Exact match selected";
	const char *str4 = "L3FWD: Longest-prefix match selected";
	const char *str5 = "L3FWD: Invalid config";
	const char *str6 = "L3FWD: NUMA is disabled";
	const char *str7 = "L3FWD: IPV6 is specified";
	const char *str8 =
		"L3FWD: Jumbo frame is enabled - disabling simple TX path";
	const char *str9 = "L3FWD: Invalid packet length";
	const char *str10 = "L3FWD: Set jumbo frame max packet len to ";
	const char *str11 = "L3FWD: Invalid hash entry number";
	const char *str12 =
		"L3FWD: LPM and EM are mutually exclusive, select only one";
	const char *str13 = "L3FWD: LPM or EM none selected, default LPM on";

	while ((opt = getopt_long(argc, argvopt, short_options,
				lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* portmask */
		case 'p':
			enabled_port_mask = parse_portmask(optarg);
			if (enabled_port_mask == 0) {
				printf("%s\n", str1);
				print_usage(prgname);
				return -1;
			}
			break;

		case 'P':
			printf("%s\n", str2);
			promiscuous_on = 1;
			break;

		case 'E':
			printf("%s\n", str3);
			l3fwd_em_on = 1;
			break;

		case 'L':
			printf("%s\n", str4);
			l3fwd_lpm_on = 1;
			break;

		/*Event device configuration*/
		case 'e':
			ret = parse_eventdev_config(optarg);
			if (ret < 0) {
				printf("invalid event device configuration\n");
				print_usage(prgname);
				return -1;
			}
			break;

		/*Rx adapter configuration*/
		case 'a':
			ret = parse_adapter_config(optarg);
			if (ret < 0) {
				printf("invalid Rx adapter configuration\n");
				print_usage(prgname);
				return -1;
			}
			rx_adapter_config.nb_rx_adapter++;
			break;

		/*Event Queue and Adapter Link configuration*/
		case 'l':
			ret = parse_link_config(optarg);
			if (ret < 0) {
				printf("invalid Link configuration\n");
				print_usage(prgname);
				return -1;
			}
			break;

		/* max_burst_size */
		case 'b':
			burst_size = (unsigned int)atoi(optarg);
			if (burst_size > max_pkt_burst) {
				printf("invalid burst size\n");
				print_usage(prgname);
				return -1;
			}
			max_pkt_burst = burst_size;
			max_rx_burst = max_pkt_burst;
			max_tx_burst = max_rx_burst/2;
			break;

		/* long options */
		case CMD_LINE_OPT_CONFIG_NUM:
			ret = parse_config(optarg);
			if (ret) {
				printf("%s\n", str5);
				print_usage(prgname);
				return -1;
			}
			break;

		case CMD_LINE_OPT_ETH_DEST_NUM:
			parse_eth_dest(optarg);
			break;

		case CMD_LINE_OPT_NO_NUMA_NUM:
			printf("%s\n", str6);
			numa_on = 0;
			break;

		case CMD_LINE_OPT_IPV6_NUM:
			printf("%sn", str7);
			ipv6 = 1;
			break;

		case CMD_LINE_OPT_ENABLE_JUMBO_NUM: {
			struct option lenopts = {
				"max-pkt-len", required_argument, 0, 0
			};

			printf("%s\n", str8);
			port_conf.rxmode.jumbo_frame = 1;

			/*
			 * if no max-pkt-len set, use the default
			 * value ETHER_MAX_LEN.
			 */
			if (getopt_long(argc, argvopt, "",
					&lenopts, &option_index) == 0) {
				ret = parse_max_pkt_len(optarg);
				if ((ret < 64) ||
					(ret > MAX_JUMBO_PKT_LEN)) {
					printf("%s\n", str9);
					print_usage(prgname);
					return -1;
				}
				port_conf.rxmode.max_rx_pkt_len = ret;
			}
			printf("%s %u\n", str10,
				(unsigned int)port_conf.rxmode.max_rx_pkt_len);
			break;
		}

		case CMD_LINE_OPT_HASH_ENTRY_NUM_NUM:
			ret = parse_hash_entry_number(optarg);
			if ((ret > 0) && (ret <= L3FWD_HASH_ENTRIES)) {
				hash_entry_number = ret;
			} else {
				printf("%s\n", str11);
				print_usage(prgname);
				return -1;
			}
			break;

		case CMD_LINE_OPT_PARSE_PTYPE_NUM:
			printf("soft parse-ptype is enabled\n");
			parse_ptype = 1;
			break;

		case CMD_LINE_OPT_PARSE_PER_PORT_POOL:
			printf("per port buffer pool is enabled\n");
			per_port_pool = 0;
			break;

		default:
			print_usage(prgname);
			return -1;
		}
	}

	/* If both LPM and EM are selected, return error. */
	if (l3fwd_lpm_on && l3fwd_em_on) {
		printf("%s\n", str12);
		return -1;
	}

	/*
	 * Nothing is selected, pick longest-prefix match
	 * as default match.
	 */
	if (!l3fwd_lpm_on && !l3fwd_em_on) {
		l3fwd_lpm_on = 1;
		printf("%s\n", str13);
	}

	/*
	 * ipv6 and hash flags are valid only for
	 * exact macth, reset them to default for
	 * longest-prefix match.
	 */
	if (l3fwd_lpm_on) {
		ipv6 = 0;
		hash_entry_number = HASH_ENTRY_NUMBER_DEFAULT;
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 1; /* reset getopt lib */
	return ret;
}

static void
print_ethaddr(const char *name, const struct ether_addr *eth_addr)
{
	char buf[ETHER_ADDR_FMT_SIZE];
	ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", name, buf);
}

static int
init_mem(uint16_t portid, unsigned int nb_mbuf)
{
	struct lcore_conf *qconf;
	int socketid;
	unsigned lcore_id;
	char s[64];

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		if (numa_on)
			socketid = rte_lcore_to_socket_id(lcore_id);
		else
			socketid = 0;

		if (socketid >= NB_SOCKETS) {
			rte_exit(EXIT_FAILURE,
				"Socket %d of lcore %u is out of range %d\n",
				socketid, lcore_id, NB_SOCKETS);
		}

		if (pktmbuf_pool[portid][socketid] == NULL) {
			snprintf(s, sizeof(s), "mbuf_pool_%d:%d",
				 portid, socketid);
			pktmbuf_pool[portid][socketid] =
				rte_pktmbuf_pool_create(s, nb_mbuf,
					MEMPOOL_CACHE_SIZE, 0,
					RTE_MBUF_DEFAULT_BUF_SIZE, socketid);
			if (pktmbuf_pool[portid][socketid] == NULL)
				rte_exit(EXIT_FAILURE,
					"Cannot init mbuf pool on socket %d\n",
					socketid);
			else
				printf("Allocated mbuf pool on socket %d\n",
					socketid);

			/* Setup either LPM or EM(f.e Hash). But, only once per
			 * available socket.
			 */
			if (!lkp_per_socket[socketid]) {
				l3fwd_lkp.setup(socketid);
				lkp_per_socket[socketid] = 1;
			}
		}
		qconf = &lcore_conf[lcore_id];
		qconf->ipv4_lookup_struct =
			l3fwd_lkp.get_ipv4_lookup_struct(socketid);
		qconf->ipv6_lookup_struct =
			l3fwd_lkp.get_ipv6_lookup_struct(socketid);
	}
	return 0;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint16_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint16_t portid;
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		if (force_quit)
			return;
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if (force_quit)
				return;
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf(
					"Port%d Link Up. Speed %u Mbps -%s\n",
						portid, link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n", portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == ETH_LINK_DOWN) {
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

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}

static int
prepare_ptype_parser(uint16_t portid, uint16_t queueid)
{
	if (parse_ptype) {
		printf("Port %d: softly parse packet type info\n", portid);
		if (rte_eth_add_rx_callback(portid, queueid,
					    l3fwd_lkp.cb_parse_ptype,
					    NULL))
			return 1;

		printf("Failed to add rx callback: port=%d\n", portid);
		return 0;
	}

	if (l3fwd_lkp.check_ptype(portid))
		return 1;

	printf("port %d cannot parse packet type, please add --%s\n",
	       portid, CMD_LINE_OPT_PARSE_PTYPE);
	return 0;
}

int
main(int argc, char **argv)
{
	struct lcore_conf *qconf;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf *txconf;
	int ret;
	unsigned nb_ports;
	uint16_t queueid, portid;
	unsigned lcore_id;
	uint32_t n_tx_queue, nb_lcores;
	uint8_t nb_rx_queue, queue, socketid;

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
	argc -= ret;
	argv += ret;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* pre-init dst MACs for all ports to 02:00:00:00:00:xx */
	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
		dest_eth_addr[portid] =
			ETHER_LOCAL_ADMIN_ADDR + ((uint64_t)portid << 40);
		*(uint64_t *)(val_eth + portid) = dest_eth_addr[portid];
	}

	/* parse application arguments (after the EAL ones) */
	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid L3FWD parameters\n");

	if (check_lcore_params() < 0)
		rte_exit(EXIT_FAILURE, "check_lcore_params failed\n");

	ret = init_lcore_rx_queues();
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "init_lcore_rx_queues failed\n");

	nb_ports = rte_eth_dev_count();

	if (check_port_config(nb_ports) < 0)
		rte_exit(EXIT_FAILURE, "check_port_config failed\n");

	nb_lcores = rte_lcore_count();

	/* Setup function pointers for lookup method. */
	setup_l3fwd_lookup_tables();

	/* initialize all ports */
	for (portid = 0; portid < nb_ports; portid++) {
		/* skip ports that are not enabled */
		if ((enabled_port_mask & (1 << portid)) == 0) {
			printf("\nSkipping disabled port %d\n", portid);
			continue;
		}

		/* init port */
		printf("Initializing port %d ... ", portid );
		fflush(stdout);

		nb_rx_queue = get_port_n_rx_queues(portid);
		n_tx_queue = nb_lcores;
		if (n_tx_queue > MAX_TX_QUEUE_PER_PORT)
			n_tx_queue = MAX_TX_QUEUE_PER_PORT;
		printf("Creating queues: nb_rxq=%d nb_txq=%u... ",
			nb_rx_queue, (unsigned)n_tx_queue );
		ret = rte_eth_dev_configure(portid, nb_rx_queue,
					(uint16_t)n_tx_queue, &port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				"Cannot configure device: err=%d, port=%d\n",
				ret, portid);

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd,
						       &nb_txd);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot adjust number of descriptors: err=%d, "
				 "port=%d\n", ret, portid);

		rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
		print_ethaddr(" Address:", &ports_eth_addr[portid]);
		printf(", ");
		print_ethaddr("Destination:",
			(const struct ether_addr *)&dest_eth_addr[portid]);
		printf(", ");

		/*
		 * prepare src MACs for each port.
		 */
		ether_addr_copy(&ports_eth_addr[portid],
			(struct ether_addr *)(val_eth + portid) + 1);

		/* init memory */
		if (!per_port_pool) {
			/* portid = 0; this is *not* signifying the first port,
			 * rather, it signifies that portid is ignored.
			 */
			ret = init_mem(0, NB_MBUF(nb_ports));
		} else {
			ret = init_mem(portid, NB_MBUF(1));
		}
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "init_mem failed\n");

		/* init one TX queue per couple (lcore,port) */
		queueid = 0;
		for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
			if (rte_lcore_is_enabled(lcore_id) == 0)
				continue;

			if (numa_on)
				socketid =
				(uint8_t)rte_lcore_to_socket_id(lcore_id);
			else
				socketid = 0;

			printf("txq=%u,%d,%d ", lcore_id, queueid, socketid);
			fflush(stdout);

			rte_eth_dev_info_get(portid, &dev_info);
			txconf = &dev_info.default_txconf;
			if (port_conf.rxmode.jumbo_frame)
				txconf->txq_flags = 0;
			ret = rte_eth_tx_queue_setup(portid, queueid, nb_txd,
						     socketid, txconf);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
					"rte_eth_tx_queue_setup: err=%d, "
					"port=%d\n", ret, portid);

			qconf = &lcore_conf[lcore_id];
			qconf->tx_queue_id[portid] = queueid;
			queueid++;

			qconf->tx_port_id[qconf->n_tx_port] = portid;
			qconf->n_tx_port++;
		}
		printf("\n");
	}

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		qconf = &lcore_conf[lcore_id];
		printf("\nInitializing rx queues on lcore %u ... ", lcore_id );
		fflush(stdout);
		/* init RX queues */
		for(queue = 0; queue < qconf->n_rx_queue; ++queue) {
			portid = qconf->rx_queue_list[queue].port_id;
			queueid = qconf->rx_queue_list[queue].queue_id;

			if (numa_on)
				socketid =
				(uint8_t)rte_lcore_to_socket_id(lcore_id);
			else
				socketid = 0;

			printf("rxq=%d,%d,%d ", portid, queueid, socketid);
			fflush(stdout);

			if (!per_port_pool)
				ret = rte_eth_rx_queue_setup(portid, queueid,
						nb_rxd, socketid,
						NULL,
						pktmbuf_pool[0][socketid]);
			else
				ret = rte_eth_rx_queue_setup(portid, queueid,
						nb_rxd, socketid,
						NULL,
						pktmbuf_pool[portid][socketid]);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
				"rte_eth_rx_queue_setup: err=%d, port=%d\n",
				ret, portid);
		}
	}

	printf("\n");

	if (nb_eventdev_params) {
		ret = eventdev_configure();
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				"event dev configure: err=%d\n", ret);
	}

	/* start ports */
	for (portid = 0; portid < nb_ports; portid++) {
		if ((enabled_port_mask & (1 << portid)) == 0) {
			continue;
		}
		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				"rte_eth_dev_start: err=%d, port=%d\n",
				ret, portid);

		/*
		 * If enabled, put device in promiscuous mode.
		 * This allows IO forwarding mode to forward packets
		 * to itself through 2 cross-connected  ports of the
		 * target machine.
		 */
		if (promiscuous_on)
			rte_eth_promiscuous_enable(portid);
	}

	printf("\n");

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		qconf = &lcore_conf[lcore_id];
		for (queue = 0; queue < qconf->n_rx_queue; ++queue) {
			portid = qconf->rx_queue_list[queue].port_id;
			queueid = qconf->rx_queue_list[queue].queue_id;
			if (prepare_ptype_parser(portid, queueid) == 0)
				rte_exit(EXIT_FAILURE, "ptype check fails\n");
		}
	}


	check_all_ports_link_status(nb_ports, enabled_port_mask);

	ret = 0;
	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(l3fwd_lkp.main_loop, NULL, CALL_MASTER);
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}

	/* stop ports */
	for (portid = 0; portid < nb_ports; portid++) {
		if ((enabled_port_mask & (1 << portid)) == 0)
			continue;
		printf("Closing port %d...", portid);
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}
	printf("Bye...\n");

	return ret;
}

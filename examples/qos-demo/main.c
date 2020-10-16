/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 * Copyright 2020 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
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

#include "qos.h"

static volatile bool force_quit;

/* MAC updating enabled by default */
static int mac_updating = 1;

#define RTE_LOGTYPE_L2FWD RTE_LOGTYPE_USER1

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define MEMPOOL_CACHE_SIZE 256
#define MAX_JUMBO_SIZE 9600

static int max_burst_size = MAX_PKT_BURST;
/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/* ethernet addresses of ports */
static struct rte_ether_addr l2fwd_ports_eth_addr[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
static uint32_t l2fwd_enabled_port_mask = 0;

/* list of enabled ports */
static uint32_t l2fwd_dst_ports[RTE_MAX_ETHPORTS];

static unsigned int l2fwd_rx_queue_per_lcore = 1;

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
struct lcore_queue_conf {
	unsigned n_rx_port;
	unsigned rx_port_list[MAX_RX_QUEUE_PER_LCORE];
} __rte_cache_aligned;
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.split_hdr_size = 0,
		.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
		.offloads = 0,
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

struct rte_mempool * l2fwd_pktmbuf_pool = NULL;

/* Per-port statistics struct */
struct l2fwd_port_statistics {
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
} __rte_cache_aligned;
struct l2fwd_port_statistics port_statistics[RTE_MAX_ETHPORTS];

#define MAX_TIMER_PERIOD 86400 /* 1 day max */
/* A tsc-based timer responsible for triggering statistics printout */
static uint64_t timer_period = 10; /* default period is 10 seconds */


/* QOS */
char qos_file[25];
struct qos_data q_data;
int map_l1_port[MAX_L1];

static void
cmd_help(void)
{
	printf("************** CMDline help **************\n\n");
	printf("q				: Quit the application\n");
	printf("qos				: Print all QoS data\n");
	printf("buffers				: Available buffers count and latency\n");
	printf("stats <l1_id> <que_idx> <clear>	: Per queue statistics and latency\n"
						"\t\t\t\t  l1_id  = Level1 ID\n"
						"\t\t\t\t  que_idx= Queue Index\n"
						"\t\t\t\t  clear  = Clear the statistics after read\n"
						"\t\t\t\t\t   0 means no clear, 1 means clear\n");
	printf("stats_all <clear>		: All queues statistics and latency\n"
						"\t\t\t\t  clear  = Clear the statistics after read\n"
						"\t\t\t\t\t   0 means no clear, 1 means clear\n");
	printf("move <l1_id> <l2_id>		: Move one L1 instance from one L2 to another L2 instance\n");
	printf("sched <l1_id> STRICT/WRR <weight> :\n"
						"\t\t\t\t  Switching scheduling from SP to WRR and\n"
						"\t\t\t\t  WRR to SP on Level1 dynamically.\n"
						"\t\t\t\t  e.g sched 0 STRICT\n"
						"\t\t\t\t  sched 0 WRR 100,200,300\n\n");
}

static void
print_routes(void)
{
	printf("\n######### Traffic Routes #########\n");
	for (int k = 0; k < MAX_L1; k++) {
		if (map_l1_port[k] != -1)
			printf("(VLAN ID = %d) --> Level1 ID=%d "
				"(CQ Select based on Priority field of VLAN "
				"Header)---> Level2 ID:%d --> Output port:%d\n",
				100 + k, map_l1_port[k],
				q_data.l1[map_l1_port[k]].l2_id,
				q_data.l1[map_l1_port[k]].port_idx);
	}
	printf("\n");

}

static void
print_qos(void)
{
	printf("\n######### Level 2 Scheduler data #########\n");
	for (int k = 0; k < q_data.l2_count; k++) {
		printf("L2 ID = %d: CIR = %f, CIR_SIZE = %d, EIR = %f, EIR_SIZE = %d, COUPLED = %d, Port Idx = %d\n", q_data.l2[k].id, q_data.l2[k].cir_rate, q_data.l2[k].cir_burst_size, q_data.l2[k].eir_rate, q_data.l2[k].eir_burst_size, q_data.l2[k].coupled, q_data.l2[k].port_idx);
	}

	printf("\n######### Level 1 Scheduler data #########\n");
	for (int k = 0; k < q_data.l1_count; k++) {
		printf("L1 ID = %d: CIR = %f, CIR_SIZE = %d, EIR = %f, EIR_SIZE = %d, COUPLED = %d, CQ_COUNT = %d, mode = %s, L2_ID = %d\n", q_data.l1[k].id, q_data.l1[k].cir_rate, q_data.l1[k].cir_burst_size, q_data.l1[k].eir_rate, q_data.l1[k].eir_burst_size, q_data.l1[k].coupled, q_data.l1[k].q_count, (q_data.l1[k].mode == SCHED_WRR) ? "WRR" : "STRICT", q_data.l1[k].l2_id);
		if (q_data.l1[k].mode == SCHED_WRR) {
			for (unsigned int j = 0; j < q_data.l1[k].q_count; j++)
				printf("CQ%d has weight = %d\n", j, q_data.l1[k].weight[j]);

			printf("\n");
		}
	}

	printf("\n\n");
}

static void
prepare_route_table(struct qos_data *data)
{
	int port_id, l1_count = 0, l1_idx = 0;

	memset(&map_l1_port, -1, sizeof(map_l1_port));

	for (int j = 0; j < q_data.l2_count; j++) {
		port_id = data->l2[j].port_idx;

		l1_count = 0;
		if ((l2fwd_enabled_port_mask & (1 << port_id)) == 0)
			rte_exit(EXIT_FAILURE, "Prepare route table failed, "
						"invalid port id %d\n",
						port_id);

		for (int k = 0; k < q_data.l1_count; k++) {
			if (data->l1[k].l2_id == data->l2[j].id) {
				map_l1_port[l1_idx] = data->l1[k].id;
				data->l1[k].port_idx = data->l2[j].port_idx;
				l1_count++;
				l1_idx++;

			}
		}
		printf("Port: %d have %d Level1 schedulers attached\n",
			port_id, l1_count);
	}
	print_routes();
}

static void
l2fwd_mac_updating(struct rte_mbuf *m, unsigned dest_portid)
{
	struct rte_ether_hdr *eth;
	void *tmp;

	eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	/* 02:00:00:00:00:xx */
	tmp = &eth->d_addr.addr_bytes[0];
	*((uint64_t *)tmp) = 0x000000000002 + ((uint64_t)dest_portid << 40);

	/* src addr */
	rte_ether_addr_copy(&l2fwd_ports_eth_addr[dest_portid], &eth->s_addr);
}

static int
get_vlan_id(struct rte_mbuf *m, unsigned *vlan_id, unsigned *prio)
{
	struct rte_ether_hdr *eth;

	eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	if (likely(eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN))){
		struct rte_vlan_hdr *vh = (struct rte_vlan_hdr *) (eth + 1);

		*prio = rte_be_to_cpu_16(vh->vlan_tci) >> 13;
		*vlan_id = rte_be_to_cpu_16(vh->vlan_tci) & 0xfff;
	} else {
		return -1;
	}

	return 0;
}


static void
l2fwd_simple_forward(struct rte_mbuf *m,
		     __attribute__((unused))unsigned int portid)
{
	unsigned dst_port, l1_id, priority, vlan_id;
	int ret;
	struct sched_shaper_data *c_data;

	ret = get_vlan_id(m, &vlan_id, &priority);
	if (unlikely(ret)) {
		printf("VLAN header not present, dropping it.\n");
		rte_pktmbuf_free(m);
		return;
	}

	l1_id = (vlan_id % 100);
	if (l1_id >= MAX_L1 || map_l1_port[l1_id] == -1) {
		printf("dropping packet.. Level 1 not configured for packet VLAN =%d\n", vlan_id);
		rte_pktmbuf_free(m);
		return;
	}

	c_data = &q_data.l1[map_l1_port[l1_id]];
	if (priority >= c_data->q_count) {
		printf("No queue available for priority = %d, max queues =%d in L1 sched. ID= %d, dropping it.\n", priority, c_data->q_count, c_data->id);
		rte_pktmbuf_free(m);
		return;
	}

	dst_port = c_data->port_idx;
	if (mac_updating)
		l2fwd_mac_updating(m, dst_port);

	//printf("vlan = %d, priority =%d, CQ id = %ld\n", vlan_id, priority, c_data->cq[priority]);

	ret = dpaa2_dev_qos_tx(c_data->cq[priority], &m, 1);
	if (ret == 0) {
		printf("packet drop\n");
		rte_pktmbuf_free(m);
	}
}

/* main processing loop */
static void
l2fwd_main_loop(void)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *m;
	unsigned lcore_id;
	unsigned i, j, portid, nb_rx;
	struct lcore_queue_conf *qconf;

	lcore_id = rte_lcore_id();
	qconf = &lcore_queue_conf[lcore_id];

	if (qconf->n_rx_port == 0) {
		RTE_LOG(INFO, L2FWD, "lcore %u has nothing to do\n", lcore_id);
		return;
	}

	RTE_LOG(INFO, L2FWD, "entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->n_rx_port; i++) {
		portid = qconf->rx_port_list[i];
		RTE_LOG(INFO, L2FWD, " -- lcoreid=%u portid=%u\n", lcore_id,
			portid);
	}

	while (!force_quit) {

		/*
		 * Read packet from RX queues
		 */
		for (i = 0; i < qconf->n_rx_port; i++) {

			portid = qconf->rx_port_list[i];
			nb_rx = rte_eth_rx_burst(portid, 0,
						 pkts_burst, max_burst_size);

			port_statistics[portid].rx += nb_rx;

			for (j = 0; j < nb_rx; j++) {
				m = pkts_burst[j];
				rte_prefetch0(rte_pktmbuf_mtod(m, void *));
				l2fwd_simple_forward(m, portid);
			}
		}
	}
}

static int
l2fwd_launch_one_lcore(__attribute__((unused)) void *dummy)
{
	l2fwd_main_loop();
	return 0;
}

/* display usage */
static void
l2fwd_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK [-q NQ]\n"
	       "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
	       "  -j Jumbo packet size: Enable jumbo and set packet size (max 9600)\n"
		"  -f QoS policy file\n",
	       prgname);
}

static int
l2fwd_parse_portmask(const char *portmask)
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

static unsigned int
l2fwd_parse_nqueue(const char *q_arg)
{
	char *end = NULL;
	unsigned long n;

	/* parse hexadecimal string */
	n = strtoul(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;
	if (n == 0)
		return 0;
	if (n >= MAX_RX_QUEUE_PER_LCORE)
		return 0;

	return n;
}

static int
l2fwd_parse_timer_period(const char *q_arg)
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

static const char short_options[] =
	"p:"  /* portmask */
	"q:"  /* number of queues */
	"T:"  /* timer period */
	"b:"  /* burst size */
	"j:"  /* jumbo packet size */
	"f:"  /* QoS data file */
	;

#define CMD_LINE_OPT_MAC_UPDATING "mac-updating"
#define CMD_LINE_OPT_NO_MAC_UPDATING "no-mac-updating"

enum {
	/* long options mapped to a short option */

	/* first long only option value must be >= 256, so that we won't
	 * conflict with short options */
	CMD_LINE_OPT_MIN_NUM = 256,
};

static const struct option lgopts[] = {
	{ CMD_LINE_OPT_MAC_UPDATING, no_argument, &mac_updating, 1},
	{ CMD_LINE_OPT_NO_MAC_UPDATING, no_argument, &mac_updating, 0},
	{NULL, 0, 0, 0}
};

/* Parse the argument given in the command line of the application */
static int
l2fwd_parse_args(int argc, char **argv)
{
	int opt, ret, timer_secs, burst_size, pkt_len;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, short_options,
				  lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* portmask */
		case 'p':
			l2fwd_enabled_port_mask = l2fwd_parse_portmask(optarg);
			if (l2fwd_enabled_port_mask == 0) {
				printf("invalid portmask\n");
				l2fwd_usage(prgname);
				return -1;
			}
			break;

		/* nqueue */
		case 'q':
			l2fwd_rx_queue_per_lcore = l2fwd_parse_nqueue(optarg);
			if (l2fwd_rx_queue_per_lcore == 0) {
				printf("invalid queue number\n");
				l2fwd_usage(prgname);
				return -1;
			}
			break;

		/* timer period */
		case 'T':
			timer_secs = l2fwd_parse_timer_period(optarg);
			if (timer_secs < 0) {
				printf("invalid timer period\n");
				l2fwd_usage(prgname);
				return -1;
			}
			timer_period = timer_secs;
			break;

		/* max_burst_size */
		case 'b':
			burst_size = (unsigned int)atoi(optarg);
			if (burst_size < 0 || burst_size > max_burst_size) {
				printf("invalid burst size\n");
				l2fwd_usage(prgname);
				return -1;
			}
			max_burst_size = burst_size;
			break;

		/* QoS data file */
		case 'f':
			snprintf(qos_file,
                                        sizeof(qos_file),
                                        "%s", optarg);
			printf("QoS data file name = %s\n", qos_file);
			break;

		/* Jumbo frame support */
		case 'j':
			port_conf.rxmode.offloads |=
				DEV_RX_OFFLOAD_JUMBO_FRAME;
			pkt_len = (unsigned int)atoi(optarg);
			if (pkt_len < 64 || pkt_len > MAX_JUMBO_SIZE) {
				printf("invalid pkt len,"
					"setting the value to default = %d\n",
					MAX_JUMBO_SIZE);
				pkt_len = MAX_JUMBO_SIZE;
			}
			port_conf.rxmode.max_rx_pkt_len = pkt_len;
			break;

		/* long options */
		case 0:
			break;

		default:
			l2fwd_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 1; /* reset getopt lib */
	return ret;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 200 /* 9s (90 * 100ms) in total */
	uint16_t portid;
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;
	int ret;

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
					printf("Port %u link get failed: %s\n",
						portid, rte_strerror(-ret));
				continue;
			}
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf(
					"Port%d Link Up. Speed %u Mbps - %s\n",
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

int
main(int argc, char **argv)
{
	struct lcore_queue_conf *qconf;
	int ret;
	uint16_t nb_ports;
	uint16_t nb_ports_available = 0;
	uint16_t portid, last_port;
	unsigned lcore_id, rx_lcore_id;
	unsigned nb_ports_in_mask = 0;
	unsigned int nb_lcores = 0;
	unsigned int nb_mbufs;

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	force_quit = false;
//	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* parse application arguments (after the EAL ones) */
	ret = l2fwd_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid L2FWD arguments\n");
	printf("MAC updating %s\n", mac_updating ? "enabled" : "disabled");

	/* zero core is required for command-line interface */
	if (rte_lcore_is_enabled(0) == false)
		rte_exit(EXIT_FAILURE, "Core 0 is disabled\n");

	memset(&q_data, 0, sizeof(q_data));
	ret = qos_data_read(qos_file, &q_data);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Not able to read QoS data\n");

	/* Dumping Qos data */
	print_qos();
	printf("\n######### Cogestion Mngt. #########\n");
	printf("Taildrop Threshold = %d\n\n", q_data.taildrop_th);
	/* convert to number of cycles */
	timer_period *= rte_get_timer_hz();

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	/* check port mask to possible port mask */
	if (l2fwd_enabled_port_mask & ~((1 << nb_ports) - 1))
		rte_exit(EXIT_FAILURE, "Invalid portmask; possible (0x%x)\n",
			(1 << nb_ports) - 1);

	/* reset l2fwd_dst_ports */
	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++)
		l2fwd_dst_ports[portid] = 0;
	last_port = 0;

	/*
	 * Each logical core is assigned a dedicated TX queue on each port.
	 */
	RTE_ETH_FOREACH_DEV(portid) {
		/* skip ports that are not enabled */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;

		if (nb_ports_in_mask % 2) {
			l2fwd_dst_ports[portid] = last_port;
			l2fwd_dst_ports[last_port] = portid;
		}
		else
			last_port = portid;

		nb_ports_in_mask++;
	}
	if (nb_ports_in_mask % 2) {
		printf("Notice: odd number of ports in portmask.\n");
		l2fwd_dst_ports[last_port] = last_port;
	}

	/* Reserving 0 core for main thread to accept user commands,
	 * Data threads will start from 1 */
	rx_lcore_id = 1;
	qconf = NULL;

	prepare_route_table(&q_data);

	/* Initialize the port/queue configuration of each logical core */
	RTE_ETH_FOREACH_DEV(portid) {
		/* skip ports that are not enabled */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;

		/* get the lcore_id for this port */
		while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
		       lcore_queue_conf[rx_lcore_id].n_rx_port ==
		       l2fwd_rx_queue_per_lcore) {
			rx_lcore_id++;
			if (rx_lcore_id >= RTE_MAX_LCORE)
				rte_exit(EXIT_FAILURE, "Not enough cores\n");
		}

		if (qconf != &lcore_queue_conf[rx_lcore_id]) {
			/* Assigned a new logical core in the loop above. */
			qconf = &lcore_queue_conf[rx_lcore_id];
			nb_lcores++;
		}

		qconf->rx_port_list[qconf->n_rx_port] = portid;
		qconf->n_rx_port++;
		printf("Lcore %u: RX port %u\n", rx_lcore_id, portid);
	}

	nb_mbufs = RTE_MAX(nb_ports * (nb_rxd + nb_txd + MAX_PKT_BURST +
		nb_lcores * MEMPOOL_CACHE_SIZE), 8192U);

	/* create the mbuf pool */
	l2fwd_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs,
		MEMPOOL_CACHE_SIZE, 0, port_conf.rxmode.max_rx_pkt_len
		+ RTE_PKTMBUF_HEADROOM,
		rte_socket_id());
	if (l2fwd_pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	/* Initialise each port */
	RTE_ETH_FOREACH_DEV(portid) {
		struct rte_eth_rxconf rxq_conf;
		struct rte_eth_conf local_port_conf = port_conf;
		struct rte_eth_dev_info dev_info;

		/* skip ports that are not enabled */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0) {
			printf("Skipping disabled port %u\n", portid);
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

		if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf.txmode.offloads |=
				DEV_TX_OFFLOAD_MBUF_FAST_FREE;
		ret = rte_eth_dev_configure(portid, 1, 0, &local_port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
				  ret, portid);

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd,
						       &nb_txd);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot adjust number of descriptors: err=%d, port=%u\n",
				 ret, portid);

		ret = rte_eth_macaddr_get(portid,
					  &l2fwd_ports_eth_addr[portid]);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot get MAC address: err=%d, port=%u\n",
				 ret, portid);

		/* init one RX queue */
		fflush(stdout);
		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = local_port_conf.rxmode.offloads;
		ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
					     rte_eth_dev_socket_id(portid),
					     &rxq_conf,
					     l2fwd_pktmbuf_pool);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
				  ret, portid);

		/* init one TX queue on each port */
		fflush(stdout);

		/* Intialialize QoS resources */
		ret = dpaa2_qos_init(portid);
		if (ret)
			rte_exit(EXIT_FAILURE, "Error in QoS intialisation\n");

		ret = rte_eth_dev_set_ptypes(portid, RTE_PTYPE_UNKNOWN, NULL,
					     0);
		if (ret < 0)
			printf("Port %u, Failed to disable Ptype parsing\n",
					portid);

		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
				  ret, portid);

		printf("done: \n");

		ret = rte_eth_promiscuous_enable(portid);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				 "rte_eth_promiscuous_enable:err=%s, port=%u\n",
				 rte_strerror(-ret), portid);

		printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
				portid,
				l2fwd_ports_eth_addr[portid].addr_bytes[0],
				l2fwd_ports_eth_addr[portid].addr_bytes[1],
				l2fwd_ports_eth_addr[portid].addr_bytes[2],
				l2fwd_ports_eth_addr[portid].addr_bytes[3],
				l2fwd_ports_eth_addr[portid].addr_bytes[4],
				l2fwd_ports_eth_addr[portid].addr_bytes[5]);

		/* initialize port stats */
		memset(&port_statistics, 0, sizeof(port_statistics));
	}

	if (!nb_ports_available) {
		rte_exit(EXIT_FAILURE,
			"All available ports are disabled. Please set portmask.\n");
	}

	check_all_ports_link_status(l2fwd_enabled_port_mask);

	ret = 0;

	/* Need to call for only once */
	/* Qos code starting from here */
	struct dpaa2_shaper_params shaper;

	memset(&shaper, 0, sizeof(struct dpaa2_shaper_params));

	/* configure Level 2 schedulers */
	for (int k = 0; k < q_data.l2_count; k++) {
		if ((l2fwd_enabled_port_mask & (1 << q_data.l2[k].port_idx)) != 0) {
			q_data.l2[k].lni_id = dpaa2_add_L2_sch(q_data.l2[k].port_idx);
		} else {
			rte_exit(EXIT_FAILURE, "%d port is not enabled in application. Failed L2 configuration\n",  q_data.l2[k].port_idx);
		}

		shaper.c_rate = q_data.l2[k].cir_rate;
		shaper.e_rate = q_data.l2[k].eir_rate;
		shaper.c_bs = q_data.l2[k].cir_burst_size;
		shaper.e_bs = q_data.l2[k].eir_burst_size;
		shaper.mps = 0;
		shaper.oal = 24;
		shaper.cpl = q_data.l2[k].coupled;

		dpaa2_cfg_L2_shaper(q_data.l2[k].port_idx, &shaper);
	}

	memset(&shaper, 0, sizeof(struct dpaa2_shaper_params));


	/* configure Level 1 schedulers */
	for (int k = 0; k < q_data.l1_count; k++) {
	//	int port, lni_id, l2_id;
		struct sched_shaper_data *l2_q_data = NULL;
		struct dpaa2_sch_params sch_param;

		for (int l = 0; l < q_data.l2_count; l++) {
			if (q_data.l1[k].l2_id == q_data.l2[l].id) {
				l2_q_data = &q_data.l2[l];
				break;
			}
		}
		if (l2_q_data == NULL)
			rte_exit(EXIT_FAILURE, "L2_ID not exists, please check L1 configuration\n");

		sch_param.sch_mode = q_data.l1[k].mode;
		sch_param.l2_sch_idx = l2_q_data->lni_id;
		sch_param.shaped = 1;
		sch_param.num_L1_queues = q_data.l1[k].q_count;
		sch_param.q_handle = q_data.l1[k].cq;
		for (int ii = 0; ii < sch_param.num_L1_queues; ii++) {
			sch_param.td_mode[ii] = CONGESTION_UNIT_BYTES;
			sch_param.td_thresh[ii] = q_data.taildrop_th;
			if (q_data.l1[k].mode == SCHED_WRR)
				sch_param.weight[ii] = q_data.l1[k].weight[ii];
		}

		q_data.l1[k].channel_id = dpaa2_add_L1_sch(l2_q_data->port_idx, &sch_param);

		shaper.c_rate = q_data.l1[k].cir_rate;
		shaper.e_rate = q_data.l1[k].eir_rate;
		shaper.c_bs = q_data.l1[k].cir_burst_size;
		shaper.e_bs = q_data.l1[k].eir_burst_size;
		shaper.mps = 0;
		shaper.oal = 24;
		shaper.cpl = q_data.l1[k].coupled;

		dpaa2_cfg_L1_shaper(l2_q_data->port_idx,
					q_data.l1[k].channel_id,
					&shaper);
	}


	/* launch per-lcore init on every lcore, except master */
	rte_eal_mp_remote_launch(l2fwd_launch_one_lcore, NULL, SKIP_MASTER);

	rte_delay_us(100000);
	/* Command prompt */
	printf("******* CMDline prompt: *******\n");
	while (!force_quit) {
		char cmd[100];

		memset(cmd, 0, sizeof(cmd));
		printf("==>");
		if (fgets(cmd, sizeof(cmd), stdin) != NULL) {
			printf("%s\n", cmd);
		} else {
			printf("Unable to read command\n");
			continue;
		}
		if (!strcmp(cmd, "q\n")) {
			force_quit = true;
		} else {
			char *token, *key_token, *err = NULL;
			unsigned int l1_id, l2_id;
			struct sched_shaper_data *l1_data = NULL,
						*l2_data = NULL;

			 /* get key */
			token = strtok(cmd, " ");
			key_token = token;
			if (!strcmp(key_token, "move")) {
				/* get values for key */
				token = strtok(NULL, " ");
				l1_id = strtoul(token, &err, 0);
				ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
				if (ret) {
					printf("Not a valid argument %s\n", token);
					cmd_help();
					continue;
				}

				token = strtok(NULL, "\n");
				l2_id = strtoul(token, &err, 0);
				if (ret) {
					printf("Not a valid argument %s\n", token);
					cmd_help();
					continue;
				}

				for (int k = 0; k < q_data.l1_count; k++) {
					if (q_data.l1[k].id == l1_id) {
						l1_data =  &q_data.l1[k];
						break;
					}
				}
				if (l1_data == NULL) {
					printf("%d L1 id is not present\n", l1_id);
					cmd_help();
					continue;
				}
				for (int k = 0; k < q_data.l2_count; k++) {
					if (q_data.l2[k].id == l2_id) {
						l2_data =  &q_data.l2[k];
						break;
					}
				}
				if (l2_data == NULL) {
					printf("%d L2 id is not present\n", l2_id);
					cmd_help();
					continue;
				}

				ret = dpaa2_move_L1_sch(l1_data->channel_id,
							l2_data->port_idx);
				if (ret)
					printf("failed to switch l1 instance\n");

				l1_data->port_idx = l2_data->port_idx;
				l1_data->l2_id = l2_id;
				print_routes();
			} else if (!strcmp(key_token, "sched")) {
				int prio;
				struct dpaa2_sch_params sch_param;

				token = strtok(NULL, " ");
				l1_id = strtoul(token, &err, 0);
				ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
				if (ret) {
					printf("Not a valid argument %s\n", token);
					cmd_help();
					continue;
				}

				token = strtok(NULL, " \n");
				if (!strcmp(token, "STRICT")) {
					prio = SCHED_STRICT_PRIORITY;
				} else if (!strcmp(token, "WRR")) {
					prio = SCHED_WRR;
				} else {
					printf("Not a valid argument %s\n", token);
					cmd_help();
					continue;
				}

				for (int k = 0; k < q_data.l1_count; k++) {
					if (q_data.l1[k].id == l1_id) {
						l1_data =  &q_data.l1[k];
						break;
					}
				}
				if (l1_data == NULL) {
					printf("%d L1 id is not present\n", l1_id);
					cmd_help();
					continue;
				}

				printf("Current mode = %s, new mode = %s and queues = %d\n",
					(l1_data->mode == SCHED_WRR) ? "WRR" : "STRICT",
					(prio) ? "WRR" : "STRICT",
					l1_data->q_count);
				if (prio == SCHED_WRR) {
					char *w_token;
					unsigned int ii = 0, error = 0;

					token = strtok(NULL, "\n");
					if (token == NULL) {
						printf("Weight is not given\n");
						cmd_help();
						continue;
					}
					w_token = strtok(token, ",");
					l1_data->weight[ii] = strtoul(w_token, &err, 0);
					ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
					if (ret) {
						printf("Not a valid argument %s\n", token);
						cmd_help();
						continue;
					}
					printf("weight = %d, for queue =%d\n", l1_data->weight[ii], ii); 
					ii++;
					for (;ii < l1_data->q_count; ii++) {
						w_token = strtok(NULL, ",");
						if (w_token == NULL) {
							printf("Weight is not given for all queues, Queues: %d\n", l1_data->q_count);
							cmd_help();
							error = 1;
							break;
						}

						l1_data->weight[ii] = strtoul(w_token, &err, 0);
					printf("weight = %d, for queue =%d\n", l1_data->weight[ii], ii); 
						ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
						if (ret) {
							printf("Error in reading weight\n");
							error = 1;
						}
					}
					if (error == 1)
						continue;
				}

				for (int k = 0; k < q_data.l2_count; k++) {
                                        if (q_data.l2[k].id == l1_data->l2_id) {
                                                l2_data =  &q_data.l2[k];
                                                break;
                                        }
                                }
                                if (l2_data == NULL) {
                                        printf("Unable to locate L2 data\n");
                                        cmd_help();
                                        continue;
                                }

				sch_param.sch_mode = prio;
				sch_param.l2_sch_idx = l2_data->lni_id;
				sch_param.shaped = 1;
				sch_param.num_L1_queues = l1_data->q_count;
				sch_param.q_handle = l1_data->cq;
				for (int ii = 0; ii < sch_param.num_L1_queues; ii++) {
					sch_param.td_mode[ii] = CONGESTION_UNIT_BYTES;
					sch_param.td_thresh[ii] = q_data.taildrop_th;
					if (prio == SCHED_WRR)
						sch_param.weight[ii] = l1_data->weight[ii];
				}
				l1_data->channel_id = dpaa2_reconf_L1_sch(l2_data->port_idx, l1_data->channel_id, &sch_param);
				l1_data->mode = prio;
				printf("done\n");
			} else if (!strcmp(key_token, "qos\n")) {
				print_qos();
				print_routes();
			} else if (!strcmp(key_token, "stats")) {
				uint16_t cq_idx;
				uint64_t start_time = 0, last_time = 0;
				struct dpaa2_qos_stats stats;
				int clear = 0;

				token = strtok(NULL, " ");
				l1_id = strtoul(token, &err, 0);
				ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
				if (ret) {
					printf("Not a valid argument %s\n", token);
					cmd_help();
					continue;
				}

				token = strtok(NULL, " ");
				cq_idx = strtoul(token, &err, 0);
				ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
				if (ret) {
					printf("Not a valid argument %s\n", token);
					cmd_help();
					continue;
				}

				token = strtok(NULL, "\n");
				clear = strtoul(token, &err, 0);
				ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
				if (ret) {
					printf("Not a valid argument\n");
					cmd_help();
					continue;
				}

				if (clear != 0 && clear !=1) {
					printf("Argument 'clear' is not valid = %d\n", clear);
					cmd_help();
					continue;
				}

				for (int k = 0; k < q_data.l1_count; k++) {
                                        if (q_data.l1[k].id == l1_id) {
                                                l1_data =  &q_data.l1[k];
                                                break;
                                        }
                                }
                                if (l1_data == NULL) {
                                        printf("%d L1 id is not present\n", l1_id);
                                        cmd_help();
                                        continue;
                                }

				if (cq_idx >= l1_data->q_count) {
                                        printf("CQ index %d is invalid\n", cq_idx);
                                        cmd_help();
                                        continue;
				}
				start_time = rte_rdtsc_precise();

				ret = dpaa2_get_qos_stats(l1_data->port_idx, l1_data->channel_id,
							  l1_data->cq[cq_idx], &stats, clear);
				if (ret)
					continue;

				last_time = rte_rdtsc_precise() - start_time;
				printf("Dequeued frames =\t%lu\nDequeued Bytes =\t%lu\n"
					"Frames in queue =\t%u\nBytes in queue =\t%lu\n",
					stats.dq_frames, stats.dq_bytes, stats.q_frames,
					stats.q_bytes);
				printf("Latency = %lf us\n", (double)(last_time * 1000000) /(double)rte_get_tsc_hz());
			} else if (!strcmp(key_token, "stats_all")) {
				struct dpaa2_qos_stats stats[L1_MAX_CHANNELS][L1_MAX_QUEUES];
				uint64_t start_time = 0, last_time = 0;
				FILE *fp;
				double latency;
				int clear = 0;

				token = strtok(NULL, "\n");
				clear = strtoul(token, &err, 0);
				ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
				if (ret) {
					printf("Not a valid argument\n");
					cmd_help();
					continue;
				}

				if (clear != 0 && clear !=1) {
					printf("Argument 'clear' is not valid = %d\n", clear);
					cmd_help();
					continue;
				}

				start_time = rte_rdtsc_precise();
				for (int k = 0; k < q_data.l1_count; k++) {
					for (unsigned int j = 0; j < q_data.l1[k].q_count; j++) {
						ret = dpaa2_get_qos_stats(q_data.l1[k].port_idx, q_data.l1[k].channel_id,
								q_data.l1[k].cq[j], &stats[k][j], clear);
						if (ret)
							continue;
					}
				}
				last_time = rte_rdtsc_precise() - start_time;

				latency = (double)(last_time * 1000000) /(double)rte_get_tsc_hz();
				printf("Latency = %lf us\n", latency);
				fp = fopen("qos-demo-stats", "wb");
				if (!fp) {
					printf("File open failed\n");
					fclose(fp);
					continue;
				}
				fprintf(fp, "Latency = %lf us\n\n", latency);
				fprintf(fp, "/*********************************************/\n");
				for (int k = 0; k < q_data.l1_count; k++) {
					fprintf(fp, "Level1 ID = %d\n", q_data.l1[k].id);
					for (unsigned int j = 0; j < q_data.l1[k].q_count; j++) {
						fprintf(fp, "Queue index = %d\n", j);
						fprintf(fp, "\tDequeued frames =\t%lu\n\tDequeued Bytes =\t%lu"
							"\n\tFrames in queue =\t%u\n\tBytes in queue =\t%lu\n\n",
							stats[k][j].dq_frames, stats[k][j].dq_bytes,
							stats[k][j].q_frames, stats[k][j].q_bytes);
					}
					fprintf(fp, "\n\n");
				}
				fclose(fp);
				printf("Please see the file 'qos-demo-stats' for statistics\n");
			} else if (!strcmp(key_token, "buffers\n")) {
				uint64_t start_time = 0, last_time = 0;
				double latency;
				uint32_t count;

				start_time = rte_rdtsc_precise();

				dpaa2_get_free_bufs(l2fwd_pktmbuf_pool, &count);

				last_time = rte_rdtsc_precise() - start_time;
				latency = (double)(last_time * 1000000) /(double)rte_get_tsc_hz();
				printf("Available buffers count = %d\n", count);
				printf("Latency = %lf us\n", latency);
			} else {
				printf("not a valid command\n");
				cmd_help();
				continue;
			}
		}
	}

	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}

	RTE_ETH_FOREACH_DEV(portid) {
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;
		printf("Closing port %d...", portid);
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}
	printf("Bye...\n");

	return ret;
}

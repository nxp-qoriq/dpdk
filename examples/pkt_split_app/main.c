/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020-2021 NXP
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
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip_frag.h>
#include <arpa/inet.h>

#include <rte_pmd_dpaa_oldev.h>

static volatile bool force_quit;
const char *split_port_driver_name;

/* Tap interface port id */
static int tap_interface_port = -1;

/* Split port id */
static int split_port = -1;

/* Port count */
static int nb_ports_available;

#define RTE_LOGTYPE_L2FWD RTE_LOGTYPE_USER1

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define MEMPOOL_CACHE_SIZE 256
#define MAX_JUMBO_PKT_LEN  9600
#define PKT_IPV4 0
#define PKT_IPV6 1
#define PKT_UNKNOWN 2

static int max_burst_size = MAX_PKT_BURST;
char *data_file;

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/* mask of enabled ports */
static uint32_t l2fwd_enabled_port_mask;

#define TAP_MAX_MTU	9000
/* mtu of tap interface(s) */
static uint32_t tap_mtu = RTE_ETHER_MTU;

/* list of enabled ports */
static uint32_t l2fwd_dst_ports[RTE_MAX_ETHPORTS];

static unsigned int l2fwd_rx_queue_per_lcore = 1;

/* LGW traffic */
struct rte_pmd_dpaa_lgw_info_s lgw_subnets;

struct mbuf_table {
	uint32_t len;
	uint32_t head;
	uint32_t tail;
	struct rte_mbuf *m_table[0];
};

struct rx_queue {
	struct rte_ip_frag_tbl *frag_tbl;
	struct rte_mempool *pool;
	uint16_t portid;
};

#define MAX_RX_QUEUE_PER_LCORE 16
struct lcore_queue_conf {
	unsigned int n_rx_port;
	unsigned int rx_port_list[MAX_RX_QUEUE_PER_LCORE];
	struct rx_queue rx_queue_list[MAX_RX_QUEUE_PER_LCORE];
	uint16_t tx_queue_id[RTE_MAX_ETHPORTS];
	struct rte_ip_frag_death_row death_row;
	struct mbuf_table *tx_mbufs[RTE_MAX_ETHPORTS];
} __rte_cache_aligned;
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.split_hdr_size = 0,
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

struct rte_mempool *l2fwd_pktmbuf_pool;

/* Should be power of two. */
#define IP_FRAG_TBL_BUCKET_ENTRIES      16

#define DEF_FLOW_NUM    0x1000
#define DEF_FLOW_TTL    MS_PER_S

static uint32_t max_flow_num = DEF_FLOW_NUM;
static uint32_t max_flow_ttl = DEF_FLOW_TTL;

#define RTE_LOGTYPE_IP_RSMBL RTE_LOGTYPE_USER1

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

/* Configure how many packets ahead to prefetch, when reading packets */
#define PREFETCH_OFFSET 3

uint16_t gtp_udp_port[MAX_NUM_PORTS];
uint8_t num_ports;

/* Print out statistics on packets dropped */
static void
print_stats(void)
{
	uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
	unsigned int portid;

	total_packets_dropped = 0;
	total_packets_tx = 0;
	total_packets_rx = 0;

	const char clr[] = { 27, '[', '2', 'J', '\0' };
	const char topLeft[] = { 27, '[', '1', ';', '1', 'H', '\0' };

		/* Clear screen and move to top left */
	printf("%s%s", clr, topLeft);

	printf("\nPort statistics ====================================");

	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
		/* skip disabled ports */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
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
	}
	printf("\nAggregate statistics ==============================="
		   "\nTotal packets sent: %18"PRIu64
		   "\nTotal packets received: %14"PRIu64
		   "\nTotal packets dropped: %15"PRIu64,
		   total_packets_tx,
		   total_packets_rx,
		   total_packets_dropped);
	printf("\n====================================================\n");

	fflush(stdout);
}

static bool is_lgw(struct rte_mbuf *m, uint8_t ip_type)
{
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;
	int i = 0, j = 0;

	if (ip_type == PKT_IPV4) {
		ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *,
				sizeof(struct rte_ether_hdr));
		for (i = 0; i < lgw_subnets.num_subnets; i++) {
			if ((rte_be_to_cpu_32(ipv4_hdr->dst_addr) >> (32 - lgw_subnets.subnets[i].mask)) ==
			    (lgw_subnets.subnets[i].subnet[0] >> (32 - lgw_subnets.subnets[i].mask))) {
				return true;
			}
		}
	} else if (ip_type == PKT_IPV6) {
		ipv6_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv6_hdr *,
				sizeof(struct rte_ether_hdr));
		for (i = 0; i < lgw_subnets.num_subnets; i++) {
			uint8_t mask = lgw_subnets.subnets[i].mask;

			for (j = 0; j < 4; j++) {
				uint32_t temp_addr;

				memcpy(&temp_addr, &ipv6_hdr->dst_addr[j * 4], 4);
				if (mask > 32) {
					mask -= 32;
					if ((rte_be_to_cpu_32(temp_addr) !=
					    (lgw_subnets.subnets[i].subnet[j]))) {
						break;
					}
				} else {
					if ((rte_be_to_cpu_32(temp_addr) >> (32 - mask)) !=
					    (lgw_subnets.subnets[i].subnet[j] >> (32 - mask)))
						return false;
					else
						return true;
				}
			}
			if (j == 4)
				return true;
		}
	}

	return false;
}

static bool is_gtp_packet(struct rte_mbuf *m, uint8_t ip_type)
{
	struct rte_udp_hdr *udp;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;
	uint16_t dst_port;

	if (ip_type == PKT_IPV4) {
		ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *,
				sizeof(struct rte_ether_hdr));
		if (ipv4_hdr->next_proto_id == IPPROTO_UDP ||
			ipv4_hdr->next_proto_id == IPPROTO_TCP) {
			udp = rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *,
				      sizeof(struct rte_ether_hdr) +
				      sizeof(struct rte_ipv4_hdr));
		} else {
			return false;
		}
	} else if (ip_type == PKT_IPV6) {
		ipv6_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv6_hdr *,
				sizeof(struct rte_ether_hdr));
		if (ipv6_hdr->proto == IPPROTO_UDP ||
			ipv6_hdr->proto == IPPROTO_TCP) {
			udp = rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *,
				      sizeof(struct rte_ether_hdr) +
				      sizeof(struct rte_ipv6_hdr));
		} else {
			return false;
		}
	} else {
		return false;
	}

	dst_port = rte_be_to_cpu_16(udp->dst_port);
	for (int i = 0; i < num_ports; i++) {
		if (dst_port ==  gtp_udp_port[i])
			return true;
	}

	return false;
}


static void
l2fwd_simple_forward(struct rte_mbuf *m,
		     bool is_split_port_packet, uint8_t ip_type,
		     unsigned int dst_port)
{
	int sent;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_udp_hdr *udp_hdr;
	rte_be32_t temp;
	uint8_t temp_ipv6[16];

	if (nb_ports_available == 2 && is_split_port_packet) {
		if (ip_type == PKT_IPV4) {
			ipv4_hdr = rte_pktmbuf_mtod_offset(m,
				struct rte_ipv4_hdr *,
				sizeof(struct rte_ether_hdr));
			temp = ipv4_hdr->src_addr;
			ipv4_hdr->src_addr = ipv4_hdr->dst_addr;
			ipv4_hdr->dst_addr = temp;
			if (ipv4_hdr->next_proto_id == IPPROTO_UDP) {
				udp_hdr = rte_pktmbuf_mtod_offset(m,
					struct rte_udp_hdr *,
					sizeof(struct rte_ether_hdr) +
					sizeof(struct rte_ipv4_hdr));
				temp = udp_hdr->dst_port;
				udp_hdr->dst_port = udp_hdr->src_port;
				udp_hdr->src_port = temp;
			}
		} else if (ip_type == PKT_IPV6) {
			ipv6_hdr = rte_pktmbuf_mtod_offset(m,
					struct rte_ipv6_hdr *,
				sizeof(struct rte_ether_hdr));
			ipv6_hdr->proto = ipv6_hdr->proto;
			memcpy(&temp_ipv6, &ipv6_hdr->src_addr, 16);
			memcpy(&ipv6_hdr->src_addr, &ipv6_hdr->dst_addr, 16);
			memcpy(&ipv6_hdr->dst_addr, &temp_ipv6, 16);
			if (ipv6_hdr->proto == IPPROTO_UDP) {
				udp_hdr = rte_pktmbuf_mtod_offset(m,
					struct rte_udp_hdr *,
					sizeof(struct rte_ether_hdr) +
					sizeof(struct rte_ipv6_hdr));
				temp = udp_hdr->dst_port;
				udp_hdr->dst_port = udp_hdr->src_port;
				udp_hdr->src_port = temp;
			}
		}
	}

	sent = rte_eth_tx_burst(dst_port, 0, &m, 1);
	if (sent > 0) {
		port_statistics[dst_port].tx += sent;
	} else {
		port_statistics[dst_port].dropped += 1;
		rte_pktmbuf_free(m);
	}
}

static inline void
reassemble(struct rte_mbuf *m, uint16_t portid, uint32_t queue,
		struct lcore_queue_conf *qconf, uint64_t tms)
{
	struct rte_ether_hdr *eth_hdr;
	struct rte_ip_frag_tbl *tbl;
	struct rte_ip_frag_death_row *dr;
	struct rx_queue *rxq;
	uint8_t ip_type; /* 0 = ipv4, 1 = ipv6, 2 = unknown */
	unsigned int dst_port;

	rxq = &qconf->rx_queue_list[queue];
	eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	/* if packet is IPv4 */
	if (eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
		struct rte_ipv4_hdr *ip_hdr;

		ip_type = PKT_IPV4;
		ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);

		/* if it is a fragmented packet, then try to reassemble. */
		if (rte_ipv4_frag_pkt_is_fragmented(ip_hdr)) {
			struct rte_mbuf *mo;

			tbl = rxq->frag_tbl;
			dr = &qconf->death_row;

			/* prepare mbuf: setup l2_len/l3_len. */
			m->l2_len = sizeof(*eth_hdr);
			m->l3_len = sizeof(*ip_hdr);

			/* process this fragment. */
			mo = rte_ipv4_frag_reassemble_packet(tbl, dr, m, tms,
							     ip_hdr);
			if (mo == NULL)
				/* no packet to send out. */
				return;

			/* we have our packet reassembled. */
			if (mo != m) {
				m = mo;
				eth_hdr = rte_pktmbuf_mtod(m,
						struct rte_ether_hdr *);
				ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
			}

			/* update offloading flags */
			m->ol_flags |= (PKT_TX_IPV4 | PKT_TX_IP_CKSUM);
			if (is_gtp_packet(m, ip_type) || is_lgw(m, ip_type))
				dst_port = l2fwd_dst_ports[portid];
			else
				dst_port = tap_interface_port;
		} else {
				dst_port = l2fwd_dst_ports[portid];
		}

		eth_hdr->ether_type = rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4);
	} else if (eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6)) {
		/* if packet is IPv6 */
		struct ipv6_extension_fragment *frag_hdr;
		struct rte_ipv6_hdr *ip_hdr;

		ip_type = PKT_IPV6;
		ip_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);

		frag_hdr = rte_ipv6_frag_get_ipv6_fragment_header(ip_hdr);

		if (frag_hdr != NULL) {
			struct rte_mbuf *mo;

			tbl = rxq->frag_tbl;
			dr  = &qconf->death_row;

			/* prepare mbuf: setup l2_len/l3_len. */
			m->l2_len = sizeof(*eth_hdr);
			m->l3_len = sizeof(*ip_hdr) + sizeof(*frag_hdr);

			mo = rte_ipv6_frag_reassemble_packet(tbl, dr, m, tms,
							     ip_hdr, frag_hdr);
			if (mo == NULL)
				return;

			if (mo != m) {
				m = mo;
				eth_hdr = rte_pktmbuf_mtod(m,
					struct rte_ether_hdr *);
				ip_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
			}
			if (is_gtp_packet(m, ip_type) || is_lgw(m, ip_type))
				dst_port = l2fwd_dst_ports[portid];
			else
				dst_port = tap_interface_port;
		} else {
				dst_port = l2fwd_dst_ports[portid];
		}

		eth_hdr->ether_type = rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV6);
	} else {
		dst_port = tap_interface_port;
		ip_type = PKT_UNKNOWN;
	}

	l2fwd_simple_forward(m, true, ip_type, dst_port);
}

/* main processing loop */
static void
l2fwd_main_loop(void)
{
	unsigned int dst_port;
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	unsigned int lcore_id;
	uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
	unsigned int i, portid;
	int nb_rx, j;
	struct lcore_queue_conf *qconf;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) /
			US_PER_S * BURST_TX_DRAIN_US;

	prev_tsc = 0;
	timer_tsc = 0;

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

		cur_tsc = rte_rdtsc();

		/*
		 * TX burst queue drain
		 */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {

			/* if timer is enabled */
			if (timer_period > 0) {

				/* advance the timer */
				timer_tsc += diff_tsc;

				/* if timer has reached its timeout */
				if (unlikely(timer_tsc >= timer_period)) {

					/* do this only on master core */
					if (lcore_id ==
					    rte_get_main_lcore()) {
						print_stats();
						/* reset the timer */
						timer_tsc = 0;
					}
				}
			}

			prev_tsc = cur_tsc;
		}

		/*
		 * Read packet from RX queues
		 */
		for (i = 0; i < qconf->n_rx_port; i++) {

			portid = qconf->rx_port_list[i];
			nb_rx = rte_eth_rx_burst(portid, 0,
						 pkts_burst, max_burst_size);

			port_statistics[portid].rx += nb_rx;

			if (portid == (unsigned int)split_port) {
				/* Prefetch first packets */
				for (j = 0; j < PREFETCH_OFFSET &&
						j < nb_rx; j++) {
					rte_prefetch0(rte_pktmbuf_mtod(
							pkts_burst[j], void *));
				}

				/* Prefetch and forward already prefetched
				 * packets
				 */
				for (j = 0; j < (nb_rx - PREFETCH_OFFSET);
						j++) {
					rte_prefetch0(rte_pktmbuf_mtod(
						      pkts_burst[j +
						      PREFETCH_OFFSET],
						      void *));
					reassemble(pkts_burst[j], portid,
						   i, qconf, cur_tsc);
				}

				/* Forward remaining prefetched packets */
				for (; j < nb_rx; j++) {
					reassemble(pkts_burst[j], portid,
						   i, qconf, cur_tsc);
				}

				rte_ip_frag_free_death_row(&qconf->death_row,
							   PREFETCH_OFFSET);
			} else {
				for (j = 0; j < nb_rx; j++) {
					rte_prefetch0(rte_pktmbuf_mtod(
						      pkts_burst[j], void *));
					dst_port = l2fwd_dst_ports[portid];
					l2fwd_simple_forward(pkts_burst[j],
							     false,
							     PKT_UNKNOWN,
							     dst_port);
				}
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
	printf("%s [EAL options] -- -p PORTMASK [-T PERIOD]\n"
	       "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
	       "  -T PERIOD: statistics will be refreshed each PERIOD seconds (0 to disable, 10 default, 86400 maximum)\n"
	       "  -b NUM: burst size for receive packet (default is 32)\n"
	       "  -m MTU: mtu for tap interface(s) (default is 1500)\n"
	       "  -s PORTID: split port id. Use this option when Ethernet port is split port.\n"
	       "  -f user data file: Absolute path of user data file. default file name is data.input\n"
	       "                     Valid only when using OL port as split port\n",
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
	"T:"  /* timer period */
	"b:"  /* burst size */
	"m:"  /* mtu of tap interface(s) */
	"s:"  /* split port id */
	"f:"  /* user data filename*/
	;

enum {
	/* long options mapped to a short option */

	/* first long only option value must be >= 256, so that we won't
	 * conflict with short options
	 */
	CMD_LINE_OPT_MIN_NUM = 256,
};

static const struct option lgopts[] = {
	{NULL, 0, 0, 0}
};

/* Parse the argument given in the command line of the application */
static int
l2fwd_parse_args(int argc, char **argv)
{
	int opt, ret, timer_secs, burst_size;
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

		case 'f':
			data_file = malloc(strlen(optarg) + 1);
			if (data_file == NULL) {
				printf("Failed to allocate memory for data file\n");
				return -1;
			}
			snprintf(data_file, strlen(optarg) + 1, "%s", optarg);
			printf("Data file name = %s\n", data_file);
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

		/* tap interface mtu size */
		case 'm':
			tap_mtu = (uint16_t)atoi(optarg);
			if (tap_mtu < RTE_ETHER_MIN_MTU ||
					tap_mtu > TAP_MAX_MTU) {
				printf("Invalid MTU for tap interface(s)");
				l2fwd_usage(prgname);
				return -1;
			}
			break;

		/* split port */
		case 's':
			split_port = (uint16_t)atoi(optarg);
			if (!((l2fwd_enabled_port_mask >> split_port) & 1)) {
				printf("invalid split port id\n");
				l2fwd_usage(prgname);
				return -1;
			}
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
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
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
				if (link.link_status) {
					if (link.link_speed ==
							ETH_SPEED_NUM_NONE) {
						printf("Port%d Link Up\n",
								portid);
					} else {
						printf(
					"Port%d Link Up. Speed %u Mbps - %s\n",
						portid, link.link_speed,
					(link.link_duplex ==
					 ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex"));
					}
				} else {
					printf("Port %d Link Down\n", portid);
				}
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
validate_cls_info(struct rte_pmd_dpaa_uplink_cls_info_s *cls_info)
{
	if (!(cls_info->addr_pair.flags &
			(DPDK_TELECOM_LISTEN_ON_ONLY_STATICIP |
			 DPDK_TELECOM_LISTEN_ON_BOTH_STATIC_INNER_IP |
			 DPDK_TELECOM_LISTEN_ON_ONLY_INNERIP))) {
		printf("Application Traffic Listen mode is not available\n");
		return -1;
	}
	if (!(cls_info->addr_pair.flags & DPDK_CLASSIF_INNER_IP)) {
		printf("Inner IP is missing\n");
		return -1;
	}
	if ((cls_info->addr_pair.flags &
			(DPDK_TELECOM_LISTEN_ON_ONLY_STATICIP |
			 DPDK_TELECOM_LISTEN_ON_BOTH_STATIC_INNER_IP)) &&
			(!(cls_info->addr_pair.flags & DPDK_CLASSIF_STATIC_IP))) {
		printf("Static IP is missing\n");
		return -1;
	}

	return 0;
}


#define USER_DATA_FILENAME   "data.input"

static int
get_user_data(struct rte_pmd_dpaa_uplink_cls_info_s *cls_info,
	      struct rte_pmd_dpaa_lgw_info_s *lgw_info)
{
	size_t len = 0;
	FILE *fp = NULL;
	char *line = NULL;
	char *token;
	int ret;
	struct in6_addr result;

	if (data_file == NULL) {
		fp = fopen(USER_DATA_FILENAME, "r");
		if (fp == NULL) {
			printf("File %s does not exist\n", USER_DATA_FILENAME);
			return -1;
		}
	} else {
		fp = fopen(data_file, "r");
		if (fp == NULL) {
			printf("File %s does not exist\n", data_file);
			return -1;
		}
	}

	if (cls_info == NULL)
		goto subnet_parse;

	/* enabling sec by default */
	cls_info->sec_enabled = 1;
	while (getline(&line, &len, fp) != -1) {
		if (line[0] == '#' || line[0] == '/' || line[0] == '\n' ||
		    line[0] == '\r')
			continue;

		token = strtok(line, " \n");

		if (!strcmp(token, "IPV4_INNER")) {
			token = strtok(NULL, " \n");
			cls_info->addr_pair.addr_type =
					DPA_ISC_IPV4_ADDR_TYPE;
			cls_info->addr_pair.inner_ip.ip_addr[0] =
					ntohl(inet_addr(token));
			cls_info->addr_pair.flags |= DPDK_CLASSIF_INNER_IP;
			continue;
		}

		if (!strcmp(token, "IPV6_INNER")) {
			token = strtok(NULL, " \n");
			memset(&result, 0, sizeof(struct in6_addr));
			ret = inet_pton(AF_INET6, token, &result);
			if (ret == 1) {
				cls_info->addr_pair.addr_type =
					DPA_ISC_IPV6_ADDR_TYPE;
				cls_info->addr_pair.flags |= DPDK_CLASSIF_INNER_IP;
				memcpy(&cls_info->addr_pair.inner_ip.ip_addr[0], &result.s6_addr, 16);
				cls_info->addr_pair.inner_ip.ip_addr[0] = htonl(cls_info->addr_pair.inner_ip.ip_addr[0]);
				cls_info->addr_pair.inner_ip.ip_addr[1] = htonl(cls_info->addr_pair.inner_ip.ip_addr[1]);
				cls_info->addr_pair.inner_ip.ip_addr[2] = htonl(cls_info->addr_pair.inner_ip.ip_addr[2]);
				cls_info->addr_pair.inner_ip.ip_addr[3] = htonl(cls_info->addr_pair.inner_ip.ip_addr[3]);
			} else {
				printf("IPv6 inner IP parsing failed\n");
			}
			continue;
		}

		if (!strcmp(token, "IPV4_STATIC")) {
			token = strtok(NULL, " \n");
			cls_info->addr_pair.addr_type =
					DPA_ISC_IPV4_ADDR_TYPE;
			cls_info->addr_pair.static_ip.ip_addr[0] =
					ntohl(inet_addr(token));
			cls_info->addr_pair.flags |= DPDK_CLASSIF_STATIC_IP;
			continue;
		}

		if (!strcmp(token, "IPV6_STATIC")) {
			token = strtok(NULL, " \n");
			memset(&result, 0, sizeof(struct in6_addr));
			ret = inet_pton(AF_INET6, token, &result);
			if (ret == 1) {
				cls_info->addr_pair.addr_type =
					DPA_ISC_IPV6_ADDR_TYPE;
				cls_info->addr_pair.flags |= DPDK_CLASSIF_STATIC_IP;
				memcpy(&cls_info->addr_pair.static_ip.ip_addr[0], &result.s6_addr, 16);
				cls_info->addr_pair.static_ip.ip_addr[0] = htonl(cls_info->addr_pair.static_ip.ip_addr[0]);
				cls_info->addr_pair.static_ip.ip_addr[1] = htonl(cls_info->addr_pair.static_ip.ip_addr[1]);
				cls_info->addr_pair.static_ip.ip_addr[2] = htonl(cls_info->addr_pair.static_ip.ip_addr[2]);
				cls_info->addr_pair.static_ip.ip_addr[3] = htonl(cls_info->addr_pair.static_ip.ip_addr[3]);
			} else {
				printf("IPv6 static IP parsing failed\n");
			}
			continue;
		}


		if (!strcmp(token, "DEST_PORT")) {
			for (int i = 0; i <= MAX_NUM_PORTS; i++) {
				token = strtok(NULL, " \n");
				if (!token || i >= MAX_NUM_PORTS) {
					cls_info->num_ports = i;
					break;
				}
				cls_info->gtp_udp_port[i] = (uint16_t)atoi(token);
			}
			continue;
		}

		if (!strcmp(token, "PROTOCOL_ID")) {
			token = strtok(NULL, " \n");
			cls_info->gtp_proto_id = (uint8_t)atoi(token);
			continue;
		}

		if (!strcmp(token, "LISTEN_MODE")) {
			int value;

			token = strtok(NULL, " \n");
			value = (uint8_t)atoi(token);
			if (value == 1)
				cls_info->addr_pair.flags |= DPDK_TELECOM_LISTEN_ON_ONLY_STATICIP;
			else if (value == 2)
				cls_info->addr_pair.flags |= DPDK_TELECOM_LISTEN_ON_ONLY_INNERIP;
			else
				cls_info->addr_pair.flags |= DPDK_TELECOM_LISTEN_ON_BOTH_STATIC_INNER_IP;

			continue;
		}

		if (!strcmp(token, "SEC_DISABLE")) {
			int value;

			token = strtok(NULL, " \n");
			value = (uint8_t)atoi(token);
			if (value == 1)
				cls_info->sec_enabled = 0;

			continue;
		}
	}

	if (validate_cls_info(cls_info))
		return -1;

subnet_parse:
	if (lgw_info == NULL) {
		fclose(fp);
		return 0;
	}

	while (getline(&line, &len, fp) != -1) {
		char *end_str;

		if (line[0] == '#' || line[0] == '/' || line[0] == '\n' ||
		    line[0] == '\r')
			continue;

		token = strtok_r(line, " \n", &end_str);

		if (!strcmp(token, "LGW_IPV4")) {
			char *end_token;
			char *subnet_token;

			for (int i = 0; i <= MAX_NUM_SUBNETS; i++) {
				token = strtok_r(NULL, " \n", &end_str);
				if (!token || i > 3) {
					lgw_info->num_subnets = i;
					break;
				}
				subnet_token = strtok_r(token, "/", &end_token);
				if (subnet_token != NULL) {
					lgw_info->subnets[i].subnet_type =
							DPA_ISC_IPV4_SUBNET_TYPE;
					lgw_info->subnets[i].subnet[0] =
							ntohl(inet_addr(subnet_token));
					subnet_token = strtok_r(NULL, "/", &end_token);
					if (subnet_token != NULL) {
						lgw_info->subnets[i].mask =
							(uint8_t)atoi(subnet_token);
					} else {
						lgw_info->subnets[i].mask = 32;
					}
				}
			}
			continue;
		}

		if (!strcmp(token, "LGW_IPV6")) {
			char *end_token;
			char *subnet_token;

			for (int i = 0; i <= MAX_NUM_SUBNETS; i++) {
				token = strtok_r(NULL, " \n", &end_str);
				if (!token || i > 3) {
					lgw_info->num_subnets = i;
					break;
				}
				subnet_token = strtok_r(token, "/", &end_token);
				if (subnet_token != NULL) {
					memset(&result, 0, sizeof(struct in6_addr));
					ret = inet_pton(AF_INET6, subnet_token, &result);
					if (ret == 1) {
						lgw_info->subnets[i].subnet_type =
							DPA_ISC_IPV6_SUBNET_TYPE;
						memcpy(&lgw_info->subnets[i].subnet[0], &result.s6_addr, 16);
						lgw_info->subnets[i].subnet[0] = htonl(lgw_info->subnets[i].subnet[0]);
						lgw_info->subnets[i].subnet[1] = htonl(lgw_info->subnets[i].subnet[1]);
						lgw_info->subnets[i].subnet[2] = htonl(lgw_info->subnets[i].subnet[2]);
						lgw_info->subnets[i].subnet[3] = htonl(lgw_info->subnets[i].subnet[3]);

						subnet_token = strtok_r(NULL, "/", &end_token);
						if (subnet_token != NULL) {
							lgw_info->subnets[i].mask =
								(uint8_t)atoi(subnet_token);
						} else {
							lgw_info->subnets[i].mask = 128;
						}
					} else {
						printf("IPv6 address parsing failed\n");
					}
				}
			}
			continue;
		}
	}

	fclose(fp);
	return 0;
}

static int
set_classif_info(void)
{
	struct rte_pmd_dpaa_uplink_cls_info_s cls_info;
	int ret;

	memset(&cls_info, 0, sizeof(struct rte_pmd_dpaa_uplink_cls_info_s));
	ret = get_user_data(&cls_info, NULL);
	if (ret) {
		rte_exit(EXIT_FAILURE, "Failed to paarse user data\n");
		return ret;
	}

	ret = rte_pmd_dpaa_ol_set_classif_info(&cls_info);
	if (ret) {
		rte_exit(EXIT_FAILURE, "Failed to set classification info\n");
		return ret;
	}

	printf("######### Classification Info: #####################\n");
	printf("number of destination ports = %d\n", cls_info.num_ports);
	num_ports = cls_info.num_ports;
	printf("port numbers:\n");
	for (int i = 0; i < cls_info.num_ports; i++) {
		printf("\t%d\n", cls_info.gtp_udp_port[i]);
		gtp_udp_port[i] = cls_info.gtp_udp_port[i];
	}
	printf("Protocol ID: %d\n", cls_info.gtp_proto_id);
	if (cls_info.addr_pair.flags & DPDK_CLASSIF_INNER_IP) {
		if (cls_info.addr_pair.addr_type == DPA_ISC_IPV4_ADDR_TYPE) {
			printf("\tIPv4 Inner IP address: %d.%d.%d.%d\n",
				(cls_info.addr_pair.inner_ip.ip_addr[0] >> 24) & 0xFF,
				(cls_info.addr_pair.inner_ip.ip_addr[0] >> 16) & 0xFF,
				(cls_info.addr_pair.inner_ip.ip_addr[0] >> 8) & 0xFF,
				(cls_info.addr_pair.inner_ip.ip_addr[0]) & 0xFF);
		} else if (cls_info.addr_pair.addr_type == DPA_ISC_IPV6_ADDR_TYPE) {
			uint8_t temp_addr[16];

			memcpy(&temp_addr, &cls_info.addr_pair.inner_ip.ip_addr[0], 16);
			printf("\tIPv6 Inner IP address: %02x%02x:%02x%02x:%02x%02x:%02x%02x:"
				"%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
				(int)temp_addr[3], (int)temp_addr[2],
				(int)temp_addr[1], (int)temp_addr[0],
				(int)temp_addr[7], (int)temp_addr[6],
				(int)temp_addr[5], (int)temp_addr[4],
				(int)temp_addr[11], (int)temp_addr[10],
				(int)temp_addr[9], (int)temp_addr[8],
				(int)temp_addr[15], (int)temp_addr[14],
				(int)temp_addr[13], (int)temp_addr[12]);
		}
	}
	if (cls_info.addr_pair.flags & DPDK_CLASSIF_STATIC_IP) {
		if (cls_info.addr_pair.addr_type == DPA_ISC_IPV4_ADDR_TYPE) {
			printf("\tIPv4 static IP address: %d.%d.%d.%d\n",
				(cls_info.addr_pair.static_ip.ip_addr[0] >> 24) & 0xFF,
				(cls_info.addr_pair.static_ip.ip_addr[0] >> 16) & 0xFF,
				(cls_info.addr_pair.static_ip.ip_addr[0] >> 8) & 0xFF,
				(cls_info.addr_pair.static_ip.ip_addr[0]) & 0xFF);
		} else if (cls_info.addr_pair.addr_type == DPA_ISC_IPV6_ADDR_TYPE) {
			uint8_t temp_addr[16];

			memcpy(&temp_addr, &cls_info.addr_pair.static_ip.ip_addr[0], 16);
			printf("\tIPv6 static IP address: %02x%02x:%02x%02x:%02x%02x:%02x%02x:"
				"%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
				(int)temp_addr[3], (int)temp_addr[2],
				(int)temp_addr[1], (int)temp_addr[0],
				(int)temp_addr[7], (int)temp_addr[6],
				(int)temp_addr[5], (int)temp_addr[4],
				(int)temp_addr[11], (int)temp_addr[10],
				(int)temp_addr[9], (int)temp_addr[8],
				(int)temp_addr[15], (int)temp_addr[14],
				(int)temp_addr[13], (int)temp_addr[12]);
		}
	}

	printf("IP flags = 0x%x\n", cls_info.addr_pair.flags);
	printf("Sec enabled = %d\n", cls_info.sec_enabled);
	printf("****************************************************\n");

	return ret;
}

static int
reset_classif_info(void)
{
	int ret;

	ret = rte_pmd_dpaa_ol_reset_classif_info();
	if (ret)
		rte_exit(EXIT_FAILURE, "Failed to reset classification info\n");

	return ret;
}

static int
set_lgw_info(void)
{
	struct rte_pmd_dpaa_lgw_info_s lgw_info;
	int ret;

	ret = get_user_data(NULL, &lgw_info);
	if (ret) {
		rte_exit(EXIT_FAILURE, "Failed to paarse user data\n");
		return ret;
	}

	ret = rte_pmd_dpaa_ol_set_lgw_info(&lgw_info);
	if (ret) {
		rte_exit(EXIT_FAILURE, "Failed to set LGW info\n");
		return ret;
	}

	printf("######### LGW Info: ###############################\n");
	printf("Number of subnets: %d\n", lgw_info.num_subnets);
	for (int i = 0; i <= lgw_info.num_subnets; i++) {
		if (lgw_info.subnets[i].subnet_type == DPA_ISC_IPV4_SUBNET_TYPE) {
			printf("\tIPv4 address: %d.%d.%d.%d/%d\n",
				(lgw_info.subnets[i].subnet[0] >> 24) & 0xFF,
				(lgw_info.subnets[i].subnet[0] >> 16) & 0xFF,
				(lgw_info.subnets[i].subnet[0] >> 8) & 0xFF,
				(lgw_info.subnets[i].subnet[0]) & 0xFF,
				lgw_info.subnets[i].mask);
		} else if (lgw_info.subnets[i].subnet_type == DPA_ISC_IPV6_SUBNET_TYPE) {
			uint8_t temp_addr[16];

			memcpy(&temp_addr, &lgw_info.subnets[i].subnet[0], 16);
			printf("\tIPv6 address: %02x%02x:%02x%02x:%02x%02x:%02x%02x:"
				"%02x%02x:%02x%02x:%02x%02x:%02x%02x/%d\n",
				(int)temp_addr[3], (int)temp_addr[2],
				(int)temp_addr[1], (int)temp_addr[0],
				(int)temp_addr[7], (int)temp_addr[6],
				(int)temp_addr[5], (int)temp_addr[4],
				(int)temp_addr[11], (int)temp_addr[10],
				(int)temp_addr[9], (int)temp_addr[8],
				(int)temp_addr[15], (int)temp_addr[14],
				(int)temp_addr[13], (int)temp_addr[12],
				lgw_info.subnets[i].mask);
		}
	}
	printf("****************************************************\n");

	/* save the LGW traffic subnets for floe matching */
	memcpy(&lgw_subnets, &lgw_info, sizeof(struct rte_pmd_dpaa_lgw_info_s));

	return ret;
}

static int
reset_lgw_info(void)
{
	int ret;

	ret = rte_pmd_dpaa_ol_reset_lgw_info();
	if (ret)
		rte_exit(EXIT_FAILURE, "Failed to reset LGW info\n");

	return ret;
}

int
main(int argc, char **argv)
{
	struct lcore_queue_conf *qconf;
	int ret;
	uint16_t nb_ports;
	uint16_t portid;
	unsigned int lcore_id, rx_lcore_id;
	unsigned int nb_ports_in_mask = 0;
	unsigned int nb_lcores = 0;
	unsigned int nb_mbufs;
	int socket;
	uint64_t frag_cycles;
	struct rx_queue *rxq;

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* parse application arguments (after the EAL ones) */
	ret = l2fwd_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid L2FWD arguments\n");

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

	RTE_ETH_FOREACH_DEV(portid) {
		/* skip ports that are not enabled */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;
		nb_ports_in_mask++;
	}

	if (nb_ports_in_mask < 2 || nb_ports_in_mask > 3)
		rte_exit(EXIT_FAILURE, "App needs either two or three ports\n");

	rx_lcore_id = 0;
	qconf = NULL;

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

		rxq = &qconf->rx_queue_list[0];

		socket = rte_lcore_to_socket_id(rx_lcore_id);
		if (socket == SOCKET_ID_ANY)
			socket = 0;

		frag_cycles = (rte_get_tsc_hz() + MS_PER_S - 1) / MS_PER_S *
				max_flow_ttl;

		rxq->frag_tbl = rte_ip_frag_table_create(max_flow_num,
					IP_FRAG_TBL_BUCKET_ENTRIES,
					max_flow_num, frag_cycles, socket);

		if (rxq->frag_tbl == NULL) {
			RTE_LOG(ERR, IP_RSMBL, "ip_frag_tbl_create(%u) on "
				"lcore: %u for queue: %u failed\n",
				max_flow_num, rx_lcore_id, 0);
			rte_exit(EXIT_FAILURE, "Failed to set up queue table\n");
		}
	}

	RTE_ETH_FOREACH_DEV(portid) {
		struct rte_eth_dev_info dev_info;
		int ret;

		/* skip ports that are not enabled */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0) {
			printf("Skipping disabled port %u\n", portid);
			continue;
		}
		nb_ports_available++;

		ret = rte_eth_dev_info_get(portid, &dev_info);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				"Error during getting device (port %u) info: %s\n",
				portid, strerror(-ret));

		if (!strcmp(dev_info.driver_name, "net_tap")) {
			tap_interface_port = portid;
			continue;
		}

		if (split_port == -1) {
			if (!strcmp(dev_info.driver_name, "ol_dpaa")) {
				split_port_driver_name = dev_info.driver_name;
				split_port = portid;
			}
		} else if (portid == split_port)
			split_port_driver_name = dev_info.driver_name;
	}

	if (tap_interface_port == -1)
		rte_exit(EXIT_FAILURE,
			"Tap interface not available.\n");
	else if (split_port == -1)
		rte_exit(EXIT_FAILURE,
			"split port not available.\n");

	if (nb_ports_in_mask == 2) {
		RTE_ETH_FOREACH_DEV(portid) {
			/* skip ports that are not enabled */
			if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
				continue;
			l2fwd_dst_ports[portid] = portid;
		}
	} else {
		RTE_ETH_FOREACH_DEV(portid) {
			/* skip ports that are not enabled */
			if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
				continue;
			if (portid != split_port &&
			    portid != tap_interface_port) {
				static struct rte_ether_addr l2fwd_ports_eth_addr;

				ret = rte_eth_macaddr_get(portid,
						&l2fwd_ports_eth_addr);
				if (ret < 0)
					rte_exit(EXIT_FAILURE,
					"Cannot get MAC address: err=%d, port=%u\n",
					ret, portid);

				l2fwd_dst_ports[portid] = split_port;
				l2fwd_dst_ports[split_port] = portid;
				l2fwd_dst_ports[tap_interface_port] = portid;
				printf("####################################################\n");
				printf("PCI/Demo port ID = %d\n", portid);
				printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
						portid,
						l2fwd_ports_eth_addr.addr_bytes[0],
						l2fwd_ports_eth_addr.addr_bytes[1],
						l2fwd_ports_eth_addr.addr_bytes[2],
						l2fwd_ports_eth_addr.addr_bytes[3],
						l2fwd_ports_eth_addr.addr_bytes[4],
						l2fwd_ports_eth_addr.addr_bytes[5]);

				printf("****************************************************\n");
				printf("Tap port ID = %d\nSplit port ID = %d\n",
					tap_interface_port, split_port);
				printf("****************************************************\n");
			}
		}
	}

	nb_mbufs = RTE_MAX(nb_ports * (nb_rxd + nb_txd + MAX_PKT_BURST +
		nb_lcores * MEMPOOL_CACHE_SIZE), 8192U);

	/* create the mbuf pool */
	l2fwd_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs,
		MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
		rte_socket_id());
	if (l2fwd_pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	/* Initialise each port */
	RTE_ETH_FOREACH_DEV(portid) {
		struct rte_eth_rxconf rxq_conf;
		struct rte_eth_txconf txq_conf;
		struct rte_eth_conf local_port_conf = port_conf;
		struct rte_eth_dev_info dev_info;

		/* skip ports that are not enabled */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0) {
			printf("Skipping disabled port %u\n", portid);
			continue;
		}

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

		ret = rte_eth_dev_configure(portid, 1, 1, &local_port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
				  ret, portid);

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd,
						       &nb_txd);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot adjust number of descriptors: err=%d, port=%u\n",
				 ret, portid);

		if (!strcmp(dev_info.driver_name, "net_tap")) {
			ret = rte_eth_dev_set_mtu(portid, tap_mtu);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
					 "Cannot set mtu: err=%d, port=%u\n",
					 ret, portid);
		}

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
		txq_conf = dev_info.default_txconf;
		txq_conf.offloads = local_port_conf.txmode.offloads;
		ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
				rte_eth_dev_socket_id(portid),
				&txq_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
				ret, portid);

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

		printf("done:\n");

		/* initialize port stats */
		memset(&port_statistics, 0, sizeof(port_statistics));
	}

	if (!nb_ports_available) {
		rte_exit(EXIT_FAILURE,
			"All available ports are disabled. Please set portmask.\n");
	}

	check_all_ports_link_status(l2fwd_enabled_port_mask);

	if (!strcmp(split_port_driver_name, "ol_dpaa")) {
		ret = set_classif_info();
		if (ret)
			return ret;
		ret = set_lgw_info();
		if (ret)
			printf("WARN: LGW config. set failed\n");
	}

	ret = 0;
	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(l2fwd_launch_one_lcore, NULL, CALL_MAIN);
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}

	if (!strcmp(split_port_driver_name, "ol_dpaa")) {
		ret = reset_classif_info();
		if (ret)
			return ret;

		ret = reset_lgw_info();
		if (ret)
			printf("WARN: LGW config. reset failed\n");
	}
	print_stats();

	RTE_ETH_FOREACH_DEV(portid) {
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;
		printf("Closing port %d...", portid);
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}
	if (data_file)
		free(data_file);

	printf("Bye...\n");

	return ret;
}

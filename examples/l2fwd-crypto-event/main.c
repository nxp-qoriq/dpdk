/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019,2021 NXP
 */

#include <time.h>
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
#include <fcntl.h>
#include <unistd.h>

#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_cryptodev.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_interrupts.h>
#include <rte_ip.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_per_lcore.h>
#include <rte_prefetch.h>
#include <rte_random.h>
#include <rte_security.h>
#include <rte_hexdump.h>

#include <rte_eventdev.h>
#include <rte_event_eth_rx_adapter.h>
#include <rte_event_crypto_adapter.h>

int eventdev_id;
int adapter_id;

enum cdev_type {
	CDEV_TYPE_ANY,
	CDEV_TYPE_HW,
	CDEV_TYPE_SW
};

#define RTE_LOGTYPE_L2FWD RTE_LOGTYPE_USER1

#define NB_MBUF   8192

#define MAX_STR_LEN 32
#define MAX_KEY_SIZE 128
#define MAX_IV_SIZE 16
#define MAX_AAD_SIZE 65535
#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define SESSION_POOL_CACHE_SIZE 0

#define DEFAULT_PDCP_BEARER		0x3
#define DEFAULT_PDCP_SN_SIZE		5
#define DEFAULT_PDCP_HFN_THRESHOLD	0x010fa558
#define DEFAULT_CIPHER_IV_LEN		4
#define DEFAULT_CIPHER_KEY_LEN		16
#define DEFAULT_AUTH_KEY_LEN		16

#define MAXIMUM_IV_LENGTH	16
#define IV_OFFSET		(sizeof(struct rte_crypto_op) + \
				sizeof(struct rte_crypto_sym_op))

#define EVENT_TIMEOUT_NS	(1000*1000*1)

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
static uint64_t l2fwd_enabled_port_mask;
static uint64_t l2fwd_enabled_crypto_mask;

/* list of enabled ports */
static uint16_t l2fwd_dst_ports[RTE_MAX_ETHPORTS];

struct pkt_buffer {
	unsigned int len;
	struct rte_mbuf *buffer[MAX_PKT_BURST];
};

struct op_buffer {
	unsigned int len;
	struct rte_crypto_op *buffer[MAX_PKT_BURST];
};

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16

enum l2fwd_crypto_xform_chain {
	L2FWD_CRYPTO_CIPHER_ONLY,
	L2FWD_CRYPTO_HASH_ONLY,
	L2FWD_CRYPTO_PDCP
};

enum l2fwd_forward_mode {
	L2FWD_ETH_CRYPTO,
	L2FWD_ETH_ONLY
};

struct l2fwd_key {
	uint8_t *data;
	uint32_t length;
	rte_iova_t phys_addr;
};

struct l2fwd_iv {
	uint8_t *data;
	uint16_t length;
};

struct port_params {
	uint16_t port_id;
	uint16_t num_queues;
} __rte_cache_aligned;

/** l2fwd crypto application command line options */
struct l2fwd_crypto_options {
	unsigned int portmask;
	unsigned int nb_ports_per_lcore;
	unsigned int refresh_period;
	unsigned int single_lcore:1;
	uint32_t sched_type;

	enum l2fwd_crypto_xform_chain xform_chain;

	struct rte_crypto_sym_xform cipher_xform;
	unsigned int ckey_param;
	int ckey_random_size;
	uint8_t cipher_key[MAX_KEY_SIZE];

	struct rte_crypto_sym_xform auth_xform;
	uint8_t akey_param;
	int akey_random_size;
	uint8_t auth_key[MAX_KEY_SIZE];

	int digest_size;

	enum rte_security_session_action_type action_type;
	enum rte_security_session_protocol protocol;
	struct rte_security_pdcp_xform pdcp_xform;

	struct port_params port_params[RTE_MAX_ETHPORTS];
	uint16_t nb_port_params;

	uint16_t block_size;
	char string_type[MAX_STR_LEN];

	uint64_t cryptodev_mask;

	uint8_t fwd_mode;
};

/** l2fwd crypto lcore params */
struct l2fwd_crypto_params {
	uint8_t dev_id;
	uint8_t qp_id;

	unsigned int digest_length;
	unsigned int block_size;

	struct rte_security_session *pdcp_sess;

	enum rte_crypto_cipher_algorithm cipher_algo;
	enum rte_crypto_auth_algorithm auth_algo;
};

struct l2fwd_crypto_params port_cparams[RTE_CRYPTO_MAX_DEVS];

/** lcore configuration */
struct lcore_queue_conf {
	unsigned int nb_rx_ports;
	uint16_t rx_port_list[MAX_RX_QUEUE_PER_LCORE];

	unsigned int nb_crypto_devs;
	unsigned int cryptodev_list[MAX_RX_QUEUE_PER_LCORE];

	struct op_buffer op_buf[RTE_CRYPTO_MAX_DEVS];
	struct pkt_buffer pkt_buf[RTE_MAX_ETHPORTS];

	uint8_t seq_core_id;
} __rte_cache_aligned;

struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = ETH_MQ_RX_NONE,
		.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
		.split_hdr_size = 0,
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

struct rte_mempool *l2fwd_pktmbuf_pool;
struct rte_mempool *l2fwd_crypto_op_pool;
static struct {
	struct rte_mempool *sess_mp;
	struct rte_mempool *priv_mp;
} session_pool_socket[RTE_MAX_NUMA_NODES];

/* Per-port statistics struct */
struct l2fwd_port_statistics {
	uint64_t tx;
	uint64_t rx;

	uint64_t crypto_enqueued;
	uint64_t crypto_dequeued;

	uint64_t dropped;
} __rte_cache_aligned;

struct l2fwd_crypto_statistics {
	uint64_t enqueued;
	uint64_t dequeued;

	uint64_t errors;
} __rte_cache_aligned;

struct l2fwd_port_statistics port_statistics[RTE_MAX_ETHPORTS];
struct l2fwd_crypto_statistics crypto_statistics[RTE_CRYPTO_MAX_DEVS];

/* Send the burst of packets on an output interface */
static inline int
l2fwd_send_burst(struct lcore_queue_conf *qconf, unsigned int n,
		uint16_t port)
{
	struct rte_mbuf **pkt_buffer;
	unsigned int ret;

	pkt_buffer = (struct rte_mbuf **)qconf->pkt_buf[port].buffer;

	ret = rte_eth_tx_burst(port, 0, pkt_buffer, (uint16_t)n);
	port_statistics[port].tx += ret;
	if (unlikely(ret < n)) {
		port_statistics[port].dropped += (n - ret);
		do {
			rte_pktmbuf_free(pkt_buffer[ret]);
		} while (++ret < n);
	}

	return 0;
}

/* Enqueue packets for TX and prepare them to be sent */
static inline int
l2fwd_send_packet(struct rte_mbuf *m, uint16_t port)
{
	unsigned int lcore_id, len;
	struct lcore_queue_conf *qconf;

	lcore_id = rte_lcore_id();

	qconf = &lcore_queue_conf[lcore_id];
	len = qconf->pkt_buf[port].len;
	qconf->pkt_buf[port].buffer[len] = m;
	len++;

	l2fwd_send_burst(qconf, 1/*MAX_PKT_BURST*/, port);

	return 0;
}

static inline void
l2fwd_simple_forward(struct rte_mbuf *m, uint16_t portid)
{
	uint16_t dst_port;

	dst_port = l2fwd_dst_ports[portid];

	l2fwd_send_packet(m, dst_port);
}

/** Generate random key */
static void
generate_random_key(uint8_t *key, unsigned int length)
{
	int fd;
	int ret;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		rte_exit(EXIT_FAILURE, "Failed to generate random key\n");

	ret = read(fd, key, length);
	close(fd);

	if (ret != (int)length)
		rte_exit(EXIT_FAILURE, "Failed to generate random key\n");
}

static void
l2fwd_crypto_options_print(struct l2fwd_crypto_options *options);


struct pdcp_mbuf_metadata {
	struct rte_crypto_op cop;
	struct rte_crypto_sym_op sym_cop;
	uint32_t per_pkt_hfn;
} __rte_cache_aligned;

static inline struct pdcp_mbuf_metadata *
get_priv(struct rte_mbuf *m)
{
	return RTE_PTR_ADD(m, sizeof(struct rte_mbuf));
}

static inline void *
get_sym_cop(struct rte_crypto_op *cop)
{
	return (cop + 1);
}

static inline void
eth_event_process(struct rte_mbuf *mbuf)
{
	unsigned int lcore_id = rte_lcore_id();
	struct lcore_queue_conf *qconf = &lcore_queue_conf[lcore_id];
	struct pdcp_mbuf_metadata *priv;
	struct rte_crypto_sym_op *sym_cop;
	struct rte_crypto_op *op_buffer[1];
	int ret;
	unsigned int cdev_id = qconf->cryptodev_list[0];

	priv = get_priv(mbuf);

	priv->cop.type = RTE_CRYPTO_OP_TYPE_SYMMETRIC;
	priv->cop.status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;
	priv->per_pkt_hfn = 0xdead; /* TODO to be filled for per packet HFN */

	rte_prefetch0(&priv->sym_cop);

	sym_cop = get_sym_cop(&priv->cop);
	sym_cop->m_src = mbuf;
	sym_cop->m_dst = NULL;

	rte_security_attach_session(&priv->cop,
				    port_cparams[cdev_id].pdcp_sess);
	op_buffer[0] = &priv->cop;
	ret = rte_cryptodev_enqueue_burst(cdev_id, 0/*queue_id*/, op_buffer, 1);
	if (ret < 1) {
		RTE_LOG_DP(DEBUG, L2FWD,
			   "Cryptodev %u queue %u: enqueued %u crypto ops out of %u\n",
			   cdev_id, 0/*queue_id*/, ret, 1);
		rte_pktmbuf_free(mbuf);
	}
}

static inline void
crypto_event_process(struct rte_crypto_op *cop)
{
	struct rte_mbuf *m = cop->sym->m_src;

	if (cop->status == RTE_CRYPTO_OP_STATUS_ERROR) {
		RTE_LOG_DP(DEBUG, L2FWD, "Crypto error: dropping pkt\n");
		rte_pktmbuf_free(m);
		return;
	}

	l2fwd_simple_forward(m, m->port);
}

static inline void
process_events(struct rte_event ev[MAX_PKT_BURST], uint8_t nb_events,
	       struct l2fwd_crypto_options *options)
{
	struct rte_mbuf *mbuf;
	struct rte_crypto_op *cop;
	int i;

	for (i = 0; i < nb_events; i++) {
		if (options->fwd_mode == L2FWD_ETH_ONLY) {
			mbuf = ev[i].event_ptr;
			l2fwd_simple_forward(mbuf, mbuf->port);

		} else {
			switch (ev[i].event_type) {
			case RTE_EVENT_TYPE_ETHDEV:
				mbuf = ev[i].event_ptr;
				eth_event_process(mbuf);
			break;
			case RTE_EVENT_TYPE_CRYPTODEV:
				cop = ev[i].event_ptr;
				crypto_event_process(cop);
				break;
			default:
				RTE_LOG(ERR, L2FWD,
					"event type :%d not supported\n",
					ev[i].event_type);
			}
		}
	}
}

/* main processing loop */
static void
l2fwd_main_loop(struct l2fwd_crypto_options *options)
{
	unsigned int lcore_id = rte_lcore_id();
	unsigned int i, nb_rx = 0;
	uint16_t portid = 0, ev_portid;
	struct lcore_queue_conf *qconf = &lcore_queue_conf[lcore_id];
	struct rte_security_session *pdcp_sess;
	struct rte_event ev[MAX_PKT_BURST];
	uint64_t timeout_ticks;
	int retval;
	uint8_t socket_id;

	if (qconf->nb_rx_ports == 0) {
		RTE_LOG(INFO, L2FWD, "lcore %u has nothing to do\n", lcore_id);
		return;
	}

	RTE_LOG(INFO, L2FWD, "entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->nb_rx_ports; i++) {
		portid = qconf->rx_port_list[i];
		RTE_LOG(INFO, L2FWD, " -- lcoreid=%u portid=%u\n", lcore_id,
			portid);
	}

	ev_portid = qconf->seq_core_id;

	retval = rte_event_dequeue_timeout_ticks(0, EVENT_TIMEOUT_NS,
						 &timeout_ticks);
	if (retval) {
		RTE_LOG(INFO, L2FWD,
			"rte_event_dequeue_timeout_ticks failed\n");
		return;
	}

	if (options->fwd_mode == L2FWD_ETH_ONLY)
		goto skip_crypto;

	i = qconf->seq_core_id;
	port_cparams[i].dev_id = qconf->cryptodev_list[0];
	port_cparams[i].qp_id = 0;
	struct rte_security_ctx *ctx = (struct rte_security_ctx *)
				rte_cryptodev_get_sec_ctx(
				port_cparams[i].dev_id);
	struct rte_security_session_conf sess_conf = {
		.action_type = options->action_type,
		.protocol = options->protocol,
		{.pdcp = {
			.bearer = options->pdcp_xform.bearer,
			.domain = options->pdcp_xform.domain,
			.pkt_dir = options->pdcp_xform.pkt_dir,
			.sn_size = options->pdcp_xform.sn_size,
			.hfn = options->pdcp_xform.hfn,
			.hfn_threshold = options->pdcp_xform.hfn_threshold,
			.hfn_ovrd = options->pdcp_xform.hfn_ovrd,
		} },
		.crypto_xform = &options->cipher_xform
	};


	socket_id = rte_cryptodev_socket_id(port_cparams[i].dev_id);

	/* Create security session */
	pdcp_sess = rte_security_session_create(ctx,
			&sess_conf, session_pool_socket[socket_id].sess_mp);

	if (pdcp_sess == NULL)
		rte_exit(EXIT_FAILURE, "Failed to initialize crypto session\n");

	port_cparams[i].pdcp_sess = pdcp_sess;

	RTE_LOG(INFO, L2FWD, " -- lcoreid=%u cryptoid=%u\n", lcore_id,
			port_cparams[i].dev_id);

	l2fwd_crypto_options_print(options);

skip_crypto:
	while (1) {
		/*
		 * Read packet from RX queues
		 */
		nb_rx = rte_event_dequeue_burst(0, ev_portid, ev,
				MAX_PKT_BURST, timeout_ticks);
		if (nb_rx > 0)
			process_events(ev, nb_rx, options);
		port_statistics[portid].rx += nb_rx;
	}
}

static int
l2fwd_launch_one_lcore(void *arg)
{
	l2fwd_main_loop((struct l2fwd_crypto_options *)arg);
	return 0;
}

/* Display command line arguments usage */
static void
l2fwd_crypto_usage(const char *prgname)
{
	printf("%s [EAL options] --\n"
		"  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
		"  -q NQ: number of queue (=ports) per lcore (default is 1)\n"

		"  --cipher_algo ALGO\n"
		"  --cipher_op ENCRYPT / DECRYPT\n"
		"  --cipher_key KEY (bytes separated with \":\")\n"
		"  --cipher_key_random_size SIZE: size of cipher key when generated randomly\n"

		"  --auth_algo ALGO\n"
		"  --auth_op GENERATE / VERIFY\n"
		"  --auth_key KEY (bytes separated with \":\")\n"
		"  --auth_key_random_size SIZE: size of auth key when generated randomly\n"

		"  --digest_size SIZE: size of digest to be generated/verified\n"
		"  --pdcp_sn_bits SN_SIZE: sn_size can be 5/7/12/15/18\n"
		"  --pdcp_domain mode: mode can be CONTROL/USER/SHORT_MAC\n"

		"  --cryptodev_mask MASK: hexadecimal bitmask of crypto devices to configure\n"
		"  --fwd_mode ETH_CRYPTO / ETH_ONLY: Default ETH_CRYPTO\n"
		,
	       prgname);
}

/** Parse crypto cipher algo option command line argument */
static int
parse_cipher_algo(enum rte_crypto_cipher_algorithm *algo, char *optarg)
{

	if (rte_cryptodev_get_cipher_algo_enum(algo, optarg) < 0) {
		RTE_LOG(ERR, USER1,
			"Cipher algorithm specified not supported!\n");
		return -1;
	}

	return 0;
}

/** Parse crypto cipher operation command line argument */
static int
parse_cipher_op(enum rte_crypto_cipher_operation *op, char *optarg)
{
	if (strcmp("ENCRYPT", optarg) == 0) {
		*op = RTE_CRYPTO_CIPHER_OP_ENCRYPT;
		return 0;
	} else if (strcmp("DECRYPT", optarg) == 0) {
		*op = RTE_CRYPTO_CIPHER_OP_DECRYPT;
		return 0;
	}

	printf("Cipher operation not supported!\n");
	return -1;
}

/** Parse PDCP Domain (control/user plane) command line argument */
static int
parse_pdcp_domain(enum rte_security_pdcp_domain *op, char *optarg)
{
	if (strcmp("CONTROL", optarg) == 0) {
		*op = RTE_SECURITY_PDCP_MODE_CONTROL;
		return 0;
	} else if (strcmp("USER", optarg) == 0) {
		*op = RTE_SECURITY_PDCP_MODE_DATA;
		return 0;
	} else if (strcmp("SHORT_MAC", optarg) == 0) {
		*op = RTE_SECURITY_PDCP_MODE_SHORT_MAC;
		return 0;
	}

	printf("Cipher operation not supported!\n");
	return -1;
}

/** Parse PDCP SN Size command line argument */
static int
parse_sn_size(enum rte_security_pdcp_sn_size *op, char *q_arg)
{
	char *end = NULL;
	unsigned int n;

	n = strtoul(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		n = 0;

	switch (n) {
	case 5:
		*op = RTE_SECURITY_PDCP_SN_SIZE_5;
		break;
	case 7:
		*op = RTE_SECURITY_PDCP_SN_SIZE_7;
		break;
	case 12:
		*op = RTE_SECURITY_PDCP_SN_SIZE_12;
		break;
	case 15:
		*op = RTE_SECURITY_PDCP_SN_SIZE_15;
		break;
	case 18:
		*op = RTE_SECURITY_PDCP_SN_SIZE_18;
		break;
	default:
		printf("Invalid pdcp sn size: %u\n", n);
		return -1;
	}

	return 0;
}

/** Parse bytes from command line argument */
static int
parse_bytes(uint8_t *data, char *input_arg, uint16_t max_size)
{
	unsigned int byte_count;
	char *token;

	errno = 0;
	for (byte_count = 0, token = strtok(input_arg, ":");
			(byte_count < max_size) && (token != NULL);
			token = strtok(NULL, ":")) {

		int number = (int)strtol(token, NULL, 16);

		if (errno == EINVAL || errno == ERANGE || number > 0xFF)
			return -1;

		data[byte_count++] = (uint8_t)number;
	}

	return byte_count;
}

/** Parse size param*/
static int
parse_size(int *size, const char *q_arg)
{
	char *end = NULL;
	unsigned long n;

	/* parse hexadecimal string */
	n = strtoul(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		n = 0;

	if (n == 0) {
		printf("invalid size\n");
		return -1;
	}

	*size = n;
	return 0;
}

/** Parse crypto cipher operation command line argument */
static int
parse_auth_algo(enum rte_crypto_auth_algorithm *algo, char *optarg)
{
	if (rte_cryptodev_get_auth_algo_enum(algo, optarg) < 0) {
		RTE_LOG(ERR, USER1,
			"Authentication algorithm specified not supported!\n");
		return -1;
	}

	return 0;
}

static int
parse_auth_op(enum rte_crypto_auth_operation *op, char *optarg)
{
	if (strcmp("VERIFY", optarg) == 0) {
		*op = RTE_CRYPTO_AUTH_OP_VERIFY;
		return 0;
	} else if (strcmp("GENERATE", optarg) == 0) {
		*op = RTE_CRYPTO_AUTH_OP_GENERATE;
		return 0;
	}

	printf("Authentication operation specified not supported!\n");
	return -1;
}

static int
parse_cryptodev_mask(struct l2fwd_crypto_options *options,
		const char *q_arg)
{
	char *end = NULL;
	uint64_t pm;

	/* parse hexadecimal string */
	pm = strtoul(q_arg, &end, 16);
	if ((pm == '\0') || (end == NULL) || (*end != '\0'))
		pm = 0;

	options->cryptodev_mask = pm;
	if (options->cryptodev_mask == 0) {
		printf("invalid cryptodev_mask specified\n");
		return -1;
	}

	return 0;
}

static int
parse_forwarding_mode(struct l2fwd_crypto_options *options,
		const char *optarg)
{
	if (strcmp("ETH_CRYPTO", optarg) == 0) {
		options->fwd_mode = L2FWD_ETH_CRYPTO;
		return 0;
	} else if (strcmp("ETH_ONLY", optarg) == 0) {
		options->fwd_mode = L2FWD_ETH_ONLY;
		return 0;
	}

	printf("Forwarding mode specified not supported!\n");
	return -1;
}

/** Parse long options */
static int
l2fwd_crypto_parse_args_long_options(struct l2fwd_crypto_options *options,
		struct option *lgopts, int option_index)
{
	/* Cipher options */
	if (strcmp(lgopts[option_index].name, "cipher_algo") == 0)
		return parse_cipher_algo(&options->cipher_xform.cipher.algo,
				optarg);

	else if (strcmp(lgopts[option_index].name, "cipher_op") == 0)
		return parse_cipher_op(&options->cipher_xform.cipher.op,
				optarg);

	else if (strcmp(lgopts[option_index].name, "cipher_key") == 0) {
		options->ckey_param = 1;
		options->cipher_xform.cipher.key.length =
			parse_bytes(options->cipher_key, optarg,
					MAX_KEY_SIZE);
		if (options->cipher_xform.cipher.key.length > 0)
			return 0;
		else
			return -1;
	}

	else if (strcmp(lgopts[option_index].name,
			"cipher_key_random_size") == 0)
		return parse_size(&options->ckey_random_size, optarg);

	else if (strcmp(lgopts[option_index].name, "pdcp_sn_bits") == 0)
		return parse_sn_size(&options->pdcp_xform.sn_size, optarg);

	else if (strcmp(lgopts[option_index].name, "pdcp_domain") == 0)
		return parse_pdcp_domain(&options->pdcp_xform.domain, optarg);

	/* Authentication options */
	else if (strcmp(lgopts[option_index].name, "auth_algo") == 0) {
		return parse_auth_algo(&options->auth_xform.auth.algo,
				optarg);
	}

	else if (strcmp(lgopts[option_index].name, "auth_op") == 0)
		return parse_auth_op(&options->auth_xform.auth.op,
				optarg);

	else if (strcmp(lgopts[option_index].name, "auth_key") == 0) {
		options->akey_param = 1;
		options->auth_xform.auth.key.length =
			parse_bytes(options->auth_key, optarg,
					MAX_KEY_SIZE);
		if (options->auth_xform.auth.key.length > 0)
			return 0;
		else
			return -1;
	}

	else if (strcmp(lgopts[option_index].name,
			"auth_key_random_size") == 0)
		return parse_size(&options->akey_random_size, optarg);

	else if (strcmp(lgopts[option_index].name, "cryptodev_mask") == 0)
		return parse_cryptodev_mask(options, optarg);

	else if (strcmp(lgopts[option_index].name, "fwd_mode") == 0)
		return parse_forwarding_mode(options, optarg);

	return -1;
}

/** Parse port mask */
static int
l2fwd_crypto_parse_portmask(struct l2fwd_crypto_options *options,
		const char *q_arg)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(q_arg, &end, 16);
	if ((pm == '\0') || (end == NULL) || (*end != '\0'))
		pm = 0;

	options->portmask = pm;
	if (options->portmask == 0) {
		printf("invalid portmask specified\n");
		return -1;
	}

	return pm;
}

/** Parse number of queues */
static int
l2fwd_crypto_parse_nqueue(struct l2fwd_crypto_options *options,
		const char *q_arg)
{
	char *end = NULL;
	unsigned long n;

	/* parse hexadecimal string */
	n = strtoul(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		n = 0;
	else if (n >= MAX_RX_QUEUE_PER_LCORE)
		n = 0;

	options->nb_ports_per_lcore = n;
	if (options->nb_ports_per_lcore == 0) {
		printf("invalid number of ports selected\n");
		return -1;
	}

	return 0;
}

/** Generate default options for application */
static void
l2fwd_crypto_default_options(struct l2fwd_crypto_options *options)
{
	options->portmask = 0xffffffff;
	options->nb_ports_per_lcore = 1;
	options->refresh_period = 10000;
	options->single_lcore = 0;
	options->sched_type = RTE_SCHED_TYPE_ATOMIC;

	options->action_type = RTE_SECURITY_ACTION_TYPE_LOOKASIDE_PROTOCOL;
	options->protocol = RTE_SECURITY_PROTOCOL_PDCP;
	options->xform_chain = L2FWD_CRYPTO_PDCP;

	options->pdcp_xform.domain = RTE_SECURITY_PDCP_MODE_CONTROL;
	options->pdcp_xform.bearer = DEFAULT_PDCP_BEARER;
	options->pdcp_xform.pkt_dir = 1; /* PDCP_DIR_DOWNLINK */
	options->pdcp_xform.sn_size = DEFAULT_PDCP_SN_SIZE;
	options->pdcp_xform.hfn = 0x0;
	options->pdcp_xform.hfn_threshold = DEFAULT_PDCP_HFN_THRESHOLD;
	options->pdcp_xform.hfn_ovrd = 1;

	/* Cipher Data */
	options->cipher_xform.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
	options->cipher_xform.next = &options->auth_xform;
	/* Per packet HFN which is used for IV generation in PDCP,
	 * is stored in place of IV. Max HFN can be of size 25bits,
	 * so reserving 4 bytes
	 */
	options->cipher_xform.cipher.iv.offset = IV_OFFSET;
	options->cipher_xform.cipher.iv.length = DEFAULT_CIPHER_IV_LEN;
	options->ckey_param = 0;
	options->ckey_random_size = -1;
	options->cipher_xform.cipher.key.length = DEFAULT_CIPHER_KEY_LEN;

	options->cipher_xform.cipher.algo = RTE_CRYPTO_CIPHER_NULL;
	options->cipher_xform.cipher.op = RTE_CRYPTO_CIPHER_OP_ENCRYPT;

	/* Authentication Data */
	options->auth_xform.type = RTE_CRYPTO_SYM_XFORM_AUTH;
	options->auth_xform.next = NULL;
	options->akey_param = 0;
	options->akey_random_size = -1;
	options->auth_xform.auth.key.length = DEFAULT_AUTH_KEY_LEN;

	options->auth_xform.auth.algo = RTE_CRYPTO_AUTH_NULL;
	options->auth_xform.auth.op = RTE_CRYPTO_AUTH_OP_GENERATE;

	options->cryptodev_mask = UINT64_MAX;

	/* Forwarding mode */
	options->fwd_mode = L2FWD_ETH_CRYPTO;
}

static void
display_cipher_info(struct l2fwd_crypto_options *options)
{
	printf("\n---- Cipher information ---\n");
	printf("Algorithm: %s\n",
		rte_crypto_cipher_algorithm_strings[options->cipher_xform.cipher.algo]);
	rte_hexdump(stdout, "Cipher key:",
			options->cipher_xform.cipher.key.data,
			options->cipher_xform.cipher.key.length);
}

static void
display_auth_info(struct l2fwd_crypto_options *options)
{
	printf("\n---- Authentication information ---\n");
	printf("Algorithm: %s\n",
		rte_crypto_auth_algorithm_strings[options->auth_xform.auth.algo]);
	rte_hexdump(stdout, "Auth key:",
			options->auth_xform.auth.key.data,
			options->auth_xform.auth.key.length);
}

static void
l2fwd_crypto_options_print(struct l2fwd_crypto_options *options)
{
	printf("Options:-\nn");
	printf("portmask: %x\n", options->portmask);
	printf("ports per lcore: %u\n", options->nb_ports_per_lcore);
	printf("refresh period : %u\n", options->refresh_period);

	if (options->ckey_param && (options->ckey_random_size != -1))
		printf("Cipher key already parsed, ignoring size of random key\n");

	if (options->akey_param && (options->akey_random_size != -1))
		printf("Auth key already parsed, ignoring size of random key\n");

	switch (options->xform_chain) {
	case L2FWD_CRYPTO_PDCP:
		printf("Input --> PDCP --> Output\n");
		printf("SN_SIZE: %u\n", options->pdcp_xform.sn_size);
		printf("PDCP Domain(1=USER,0=CONTROL): %u\n",
				options->pdcp_xform.domain);
		display_cipher_info(options);
		display_auth_info(options);
		break;
	case L2FWD_CRYPTO_HASH_ONLY:
		printf("Input --> HASH --> Output\n");
		display_auth_info(options);
		break;
	case L2FWD_CRYPTO_CIPHER_ONLY:
		printf("Input --> CIPHER --> Output\n");
		display_cipher_info(options);
		break;
	}
}

/* Parse the argument given in the command line of the application */
static int
l2fwd_crypto_parse_args(struct l2fwd_crypto_options *options,
		int argc, char **argv)
{
	int opt, retval, option_index;
	char **argvopt = argv, *prgname = argv[0];

	static struct option lgopts[] = {
			{ "cdev_type", required_argument, 0, 0 },
			{ "chain", required_argument, 0, 0 },

			{ "cipher_algo", required_argument, 0, 0 },
			{ "cipher_op", required_argument, 0, 0 },
			{ "cipher_key", required_argument, 0, 0 },
			{ "cipher_key_random_size", required_argument, 0, 0 },

			{ "auth_algo", required_argument, 0, 0 },
			{ "auth_op", required_argument, 0, 0 },
			{ "auth_key", required_argument, 0, 0 },
			{ "auth_key_random_size", required_argument, 0, 0 },

			{ "digest_size", required_argument, 0, 0 },

			{ "cryptodev_mask", required_argument, 0, 0},

			{ "pdcp_sn_bits", required_argument, 0, 0 },
			{ "pdcp_domain", required_argument, 0, 0 },

			{ "fwd_mode", required_argument, 0, 0 },

			{ NULL, 0, 0, 0 }
	};

	l2fwd_crypto_default_options(options);

	while ((opt = getopt_long(argc, argvopt, "p:q:m:sT:", lgopts,
			&option_index)) != EOF) {
		switch (opt) {
		/* long options */
		case 0:
			retval = l2fwd_crypto_parse_args_long_options(options,
					lgopts, option_index);
			if (retval < 0) {
				l2fwd_crypto_usage(prgname);
				return -1;
			}
			break;
		case 'm':
			retval = (uint8_t)atoi(optarg);
			if (retval != RTE_SCHED_TYPE_ORDERED &&
			    retval != RTE_SCHED_TYPE_ATOMIC &&
			    retval != RTE_SCHED_TYPE_PARALLEL) {
				printf("invalid mode\n");
				l2fwd_crypto_usage(prgname);
				return -1;
			}
			options->sched_type = retval;
			break;

		/* portmask */
		case 'p':
			retval = l2fwd_crypto_parse_portmask(options, optarg);
			if (retval < 0) {
				l2fwd_crypto_usage(prgname);
				return -1;
			}
			break;

		/* nqueue */
		case 'q':
			retval = l2fwd_crypto_parse_nqueue(options, optarg);
			if (retval < 0) {
				l2fwd_crypto_usage(prgname);
				return -1;
			}
			break;

		default:
			l2fwd_crypto_usage(prgname);
			return -1;
		}
	}


	if (optind >= 0)
		argv[optind-1] = prgname;

	retval = optind-1;
	optind = 1; /* reset getopt lib */

	return retval;
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

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		RTE_ETH_FOREACH_DEV(portid) {
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
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

static const struct rte_cryptodev_capabilities *
check_device_support_cipher_algo(const struct l2fwd_crypto_options *options,
		const struct rte_cryptodev_info *dev_info,
		uint8_t cdev_id)
{
	unsigned int i = 0;
	const struct rte_cryptodev_capabilities *cap =
		&dev_info->capabilities[0];
	enum rte_crypto_cipher_algorithm cap_cipher_algo;
	enum rte_crypto_cipher_algorithm opt_cipher_algo =
					options->cipher_xform.cipher.algo;

	while (cap->op != RTE_CRYPTO_OP_TYPE_UNDEFINED) {
		cap_cipher_algo = cap->sym.cipher.algo;
		if (cap->sym.xform_type == RTE_CRYPTO_SYM_XFORM_CIPHER) {
			if (cap_cipher_algo == opt_cipher_algo)
				break;
		}
		cap = &dev_info->capabilities[++i];
	}

	if (cap->op == RTE_CRYPTO_OP_TYPE_UNDEFINED) {
		printf("Algorithm %s not supported by cryptodev %u or device not of preferred type (%s)\n",
			rte_crypto_cipher_algorithm_strings[opt_cipher_algo],
			cdev_id,
			options->string_type);
		return NULL;
	}

	return cap;
}

static const struct rte_cryptodev_capabilities *
check_device_support_auth_algo(const struct l2fwd_crypto_options *options,
		const struct rte_cryptodev_info *dev_info,
		uint8_t cdev_id)
{
	unsigned int i = 0;
	const struct rte_cryptodev_capabilities *cap =
		&dev_info->capabilities[0];
	enum rte_crypto_auth_algorithm cap_auth_algo;
	enum rte_crypto_auth_algorithm opt_auth_algo =
					options->auth_xform.auth.algo;

	while (cap->op != RTE_CRYPTO_OP_TYPE_UNDEFINED) {
		cap_auth_algo = cap->sym.auth.algo;
		if (cap->sym.xform_type == RTE_CRYPTO_SYM_XFORM_AUTH) {
			if (cap_auth_algo == opt_auth_algo)
				break;
		}
		cap = &dev_info->capabilities[++i];
	}

	if (cap->op == RTE_CRYPTO_OP_TYPE_UNDEFINED) {
		printf("Algorithm %s not supported by cryptodev %u or device not of preferred type (%s)\n",
			rte_crypto_auth_algorithm_strings[opt_auth_algo],
			cdev_id,
			options->string_type);
		return NULL;
	}

	return cap;
}

/* Check if the device is enabled by cryptodev_mask */
static int
check_cryptodev_mask(struct l2fwd_crypto_options *options,
		uint8_t cdev_id)
{
	if (options->cryptodev_mask & (1 << cdev_id))
		return 0;

	return -1;
}

static inline int
check_supported_size(uint16_t length, uint16_t min, uint16_t max,
		uint16_t increment)
{
	uint16_t supp_size;

	/* Single value */
	if (increment == 0) {
		if (length == min)
			return 0;
		else
			return -1;
	}

	/* Range of values */
	for (supp_size = min; supp_size <= max; supp_size += increment) {
		if (length == supp_size)
			return 0;
	}

	return -1;
}

static int
check_capabilities(struct l2fwd_crypto_options *options, uint8_t cdev_id)
{
	struct rte_cryptodev_info dev_info;
	const struct rte_cryptodev_capabilities *cap;

	rte_cryptodev_info_get(cdev_id, &dev_info);

	/* SET PDCP parameters */

	/* Set cipher parameters */
	if (/*options->xform_chain == L2FWD_CRYPTO_PDCP || */
			options->xform_chain == L2FWD_CRYPTO_CIPHER_ONLY) {
		/* Check if device supports cipher algo */
		cap = check_device_support_cipher_algo(options, &dev_info,
						cdev_id);
		if (cap == NULL)
			return -1;

		/*
		 * Check if length of provided cipher key is supported
		 * by the algorithm chosen.
		 */
		if (options->ckey_param) {
			if (check_supported_size(
					options->cipher_xform.cipher.key.length,
					cap->sym.cipher.key_size.min,
					cap->sym.cipher.key_size.max,
					cap->sym.cipher.key_size.increment)
						!= 0) {
				RTE_LOG(DEBUG, USER1,
					"Device %u does not support cipher key length\n",
					cdev_id);
				return -1;
			}
		/*
		 * Check if length of the cipher key to be randomly generated
		 * is supported by the algorithm chosen.
		 */
		} else if (options->ckey_random_size != -1) {
			if (check_supported_size(options->ckey_random_size,
					cap->sym.cipher.key_size.min,
					cap->sym.cipher.key_size.max,
					cap->sym.cipher.key_size.increment)
						!= 0) {
				RTE_LOG(DEBUG, USER1,
					"Device %u does not support cipher key length\n",
					cdev_id);
				return -1;
			}
		}
	}

	/* Set auth parameters */
	if (/*options->xform_chain == L2FWD_CRYPTO_PDCP ||*/
			options->xform_chain == L2FWD_CRYPTO_HASH_ONLY) {
		/* Check if device supports auth algo */
		cap = check_device_support_auth_algo(options, &dev_info,
						cdev_id);
		if (cap == NULL)
			return -1;

		/*
		 * Check if length of provided auth key is supported
		 * by the algorithm chosen.
		 */
		if (options->akey_param) {
			if (check_supported_size(
					options->auth_xform.auth.key.length,
					cap->sym.auth.key_size.min,
					cap->sym.auth.key_size.max,
					cap->sym.auth.key_size.increment)
						!= 0) {
				RTE_LOG(DEBUG, USER1,
					"Device %u does not support auth key length\n",
					cdev_id);
				return -1;
			}
		/*
		 * Check if length of the auth key to be randomly generated
		 * is supported by the algorithm chosen.
		 */
		} else if (options->akey_random_size != -1) {
			if (check_supported_size(options->akey_random_size,
					cap->sym.auth.key_size.min,
					cap->sym.auth.key_size.max,
					cap->sym.auth.key_size.increment)
						!= 0) {
				RTE_LOG(DEBUG, USER1,
					"Device %u does not support auth key length\n",
					cdev_id);
				return -1;
			}
		}

		/* Check if digest size is supported by the algorithm. */
		if (options->digest_size != -1) {
			if (check_supported_size(options->digest_size,
					cap->sym.auth.digest_size.min,
					cap->sym.auth.digest_size.max,
					cap->sym.auth.digest_size.increment)
						!= 0) {
				RTE_LOG(DEBUG, USER1,
					"Device %u does not support digest length\n",
					cdev_id);
				return -1;
			}
		}
	}

	return 0;
}

static int
initialize_cryptodevs(struct l2fwd_crypto_options *options, unsigned int nb_ports,
		uint8_t *enabled_cdevs)
{
	uint8_t cdev_id, cdev_count, enabled_cdev_count = 0;
	unsigned int sess_sz, max_sess_sz = 0;
	uint32_t sessions_needed = 0;
	int retval;

	cdev_count = rte_cryptodev_count();
	if (cdev_count == 0) {
		printf("No crypto devices available\n");
		return -1;
	}

	for (cdev_id = 0; cdev_id < cdev_count && enabled_cdev_count < nb_ports;
			cdev_id++) {
		if (check_cryptodev_mask(options, cdev_id) < 0)
			continue;

		if (check_capabilities(options, cdev_id) < 0)
			continue;

		sess_sz = rte_cryptodev_sym_get_private_session_size(cdev_id);
		if (sess_sz > max_sess_sz)
			max_sess_sz = sess_sz;

		l2fwd_enabled_crypto_mask |= (((uint64_t)1) << cdev_id);

		enabled_cdevs[cdev_id] = 1;
		enabled_cdev_count++;
	}

	for (cdev_id = 0; cdev_id < cdev_count; cdev_id++) {
		struct rte_cryptodev_qp_conf qp_conf;
		struct rte_cryptodev_info dev_info;

		if (enabled_cdevs[cdev_id] == 0)
			continue;

		retval = rte_cryptodev_socket_id(cdev_id);

		if (retval < 0) {
			printf("Invalid crypto device id used\n");
			return -1;
		}

		uint8_t socket_id = (uint8_t) retval;

		struct rte_cryptodev_config conf = {
			.nb_queue_pairs = 1,
			.socket_id = socket_id,
		};

		rte_cryptodev_info_get(cdev_id, &dev_info);

		/*
		 * Two sessions objects are required for each session
		 * (one for the header, one for the private data)
		 */
		sessions_needed = 2 * cdev_count;

		if (session_pool_socket[socket_id].priv_mp == NULL) {
			char mp_name[RTE_MEMPOOL_NAMESIZE];

			snprintf(mp_name, RTE_MEMPOOL_NAMESIZE,
				"priv_sess_mp_%u", socket_id);

			session_pool_socket[socket_id].priv_mp =
				rte_mempool_create(mp_name, sessions_needed,
					max_sess_sz, 0, 0, NULL, NULL, NULL,
					NULL, socket_id, 0);

			if (session_pool_socket[socket_id].priv_mp == NULL) {
				printf("Cannot create pool on socket %d\n",
					socket_id);
				return -ENOMEM;
			}

			printf("Allocated pool \"%s\" on socket %d\n",
				mp_name, socket_id);
		}

		if (session_pool_socket[socket_id].sess_mp == NULL) {
			char mp_name[RTE_MEMPOOL_NAMESIZE];

			snprintf(mp_name, RTE_MEMPOOL_NAMESIZE,
				"sess_mp_%u", socket_id);

			session_pool_socket[socket_id].sess_mp =
				rte_cryptodev_sym_session_pool_create(
						mp_name, sessions_needed,
						0, 0, 0, socket_id);

			if (session_pool_socket[socket_id].sess_mp == NULL) {
				printf("Cannot create pool on socket %d\n",
					socket_id);
				return -ENOMEM;
			}

			printf("Allocated pool \"%s\" on socket %d\n",
				mp_name, socket_id);
		}

		/* Set PDCP parameters */

		/* Set cipher parameters */
		if (options->xform_chain == L2FWD_CRYPTO_PDCP) {
			options->block_size = 16;

			/* Set key if not provided from command line */
			if (options->ckey_param == 0) {
				if (options->ckey_random_size != -1)
					options->cipher_xform.cipher.key.length =
						options->ckey_random_size;
				/* No size provided, use minimum size. */
				else
					options->cipher_xform.cipher.key.length = 16;

				generate_random_key(options->cipher_key,
					options->cipher_xform.cipher.key.length);
			}
		}

		/* Set auth parameters */
		if (options->xform_chain == L2FWD_CRYPTO_PDCP) {

			/* Set key if not provided from command line */
			if (options->akey_param == 0) {
				if (options->akey_random_size != -1)
					options->auth_xform.auth.key.length =
						options->akey_random_size;
				/* No size provided, use minimum size. */
				else
					options->auth_xform.auth.key.length = 16;

				generate_random_key(options->auth_key,
					options->auth_xform.auth.key.length);
			}

			/* Set digest size if not provided from command line */
			if (options->digest_size != -1)
				options->auth_xform.auth.digest_length =
							options->digest_size;
				/* No size provided, use minimum size. */
			else
				options->auth_xform.auth.digest_length = 4;
		}

		retval = rte_cryptodev_configure(cdev_id, &conf);
		if (retval < 0) {
			printf("Failed to configure cryptodev %u", cdev_id);
			return -1;
		}

		qp_conf.nb_descriptors = 2048;
		qp_conf.mp_session = session_pool_socket[socket_id].sess_mp;
		qp_conf.mp_session_private =
				session_pool_socket[socket_id].priv_mp;

		retval = rte_cryptodev_queue_pair_setup(cdev_id, 0, &qp_conf,
				socket_id);
		if (retval < 0) {
			printf("Failed to setup queue pair %u on cryptodev %u",
					0, cdev_id);
			return -1;
		}

		retval = rte_cryptodev_start(cdev_id);
		if (retval < 0) {
			printf("Failed to start device %u: error %d\n",
					cdev_id, retval);
			return -1;
		}
	}

	return enabled_cdev_count;
}

static int
initialize_ports(struct l2fwd_crypto_options *options)
{
	uint16_t last_portid = 0, portid;
	unsigned int enabled_portcount = 0;
	unsigned int nb_ports = rte_eth_dev_count_avail();

	if (nb_ports == 0) {
		printf("No Ethernet ports - bye\n");
		return -1;
	}

	/* Reset l2fwd_dst_ports */
	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++)
		l2fwd_dst_ports[portid] = 0;

	RTE_ETH_FOREACH_DEV(portid) {
		int retval;
		struct rte_eth_dev_info dev_info;
		struct rte_eth_rxconf rxq_conf;
		struct rte_eth_txconf txq_conf;
		struct rte_eth_conf local_port_conf = port_conf;

		/* Skip ports that are not enabled */
		if ((options->portmask & (1 << portid)) == 0)
			continue;

		/* init port */
		printf("Initializing port %u... ", portid);
		fflush(stdout);
		rte_eth_dev_info_get(portid, &dev_info);
		if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf.txmode.offloads |=
				DEV_TX_OFFLOAD_MBUF_FAST_FREE;
		retval = rte_eth_dev_configure(portid, 1, 1, &local_port_conf);
		if (retval < 0) {
			printf("Cannot configure device: err=%d, port=%u\n",
				  retval, portid);
			return -1;
		}

		options->port_params[enabled_portcount].port_id = portid;
		options->port_params[enabled_portcount].num_queues = 1;
		retval = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd,
							  &nb_txd);
		if (retval < 0) {
			printf("Cannot adjust number of descriptors: err=%d, port=%u\n",
				retval, portid);
			return -1;
		}

		/* init one RX queue */
		fflush(stdout);
		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = local_port_conf.rxmode.offloads;
		retval = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
					     rte_eth_dev_socket_id(portid),
					     &rxq_conf, l2fwd_pktmbuf_pool);
		if (retval < 0) {
			printf("rte_eth_rx_queue_setup:err=%d, port=%u\n",
					retval, portid);
			return -1;
		}

		/* init one TX queue on each port */
		fflush(stdout);
		txq_conf = dev_info.default_txconf;
		txq_conf.offloads = local_port_conf.txmode.offloads;
		retval = rte_eth_tx_queue_setup(portid, 0, nb_txd,
				rte_eth_dev_socket_id(portid),
				&txq_conf);
		if (retval < 0) {
			printf("rte_eth_tx_queue_setup:err=%d, port=%u\n",
				retval, portid);

			return -1;
		}

		/* Start device */
		retval = rte_eth_dev_start(portid);
		if (retval < 0) {
			printf("rte_eth_dev_start:err=%d, port=%u\n",
					retval, portid);
			return -1;
		}

		rte_eth_promiscuous_enable(portid);

		rte_eth_macaddr_get(portid, &l2fwd_ports_eth_addr[portid]);

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

		/* Setup port forwarding table */
		if (enabled_portcount % 2) {
			l2fwd_dst_ports[portid] = last_portid;
			l2fwd_dst_ports[last_portid] = portid;
		} else {
			last_portid = portid;
		}

		l2fwd_enabled_port_mask |= (1 << portid);
		enabled_portcount++;
	}
	options->nb_port_params = enabled_portcount;

	if (enabled_portcount == 1) {
		l2fwd_dst_ports[last_portid] = last_portid;
	} else if (enabled_portcount % 2) {
		printf("odd number of ports in portmask- bye\n");
		return -1;
	}

	check_all_ports_link_status(l2fwd_enabled_port_mask);

	return enabled_portcount;
}

static void
reserve_key_memory(struct l2fwd_crypto_options *options)
{
	options->cipher_xform.cipher.key.data = options->cipher_key;

	options->auth_xform.auth.key.data = options->auth_key;

	options->cipher_xform.cipher.key.data = rte_malloc("crypto key",
						MAX_KEY_SIZE, 0);
	if (options->cipher_xform.cipher.key.data == NULL)
		rte_exit(EXIT_FAILURE,
			 "Failed to allocate memory for cipher key");

	options->auth_xform.auth.key.data = rte_malloc("auth key",
						MAX_KEY_SIZE, 0);
	if (options->auth_xform.auth.key.data == NULL)
		rte_exit(EXIT_FAILURE,
			 "Failed to allocate memory for auth key");
}

static int
eventdev_eth_configure(struct l2fwd_crypto_options *options)
{
	struct rte_event_port_conf adapter_port_config = {0};
	struct rte_event_eth_rx_adapter_queue_conf queue_conf = {0};
	uint8_t queue_id = 0, queue_prio = 0;
	int ret, i, j;

	ret = rte_event_eth_rx_adapter_create(adapter_id, eventdev_id,
					      &adapter_port_config);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			"rte_event_eth_rx_adapter_create: err=%d\n", ret);

	queue_conf.rx_queue_flags =
				RTE_EVENT_ETH_RX_ADAPTER_QUEUE_FLOW_ID_VALID;

	for (i = 0; i < options->nb_port_params; i++) {
		for (j = 0; j < options->port_params[i].num_queues; j++) {
			queue_conf.ev.queue_id = queue_id;
			queue_conf.ev.priority = queue_prio;
			queue_conf.ev.flow_id = options->port_params[i].port_id;
			queue_conf.ev.sched_type = options->sched_type;

			ret = rte_event_eth_rx_adapter_queue_add(adapter_id,
					options->port_params[i].port_id,
					j, &queue_conf);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
					"rte_event_eth_rx_adapter_queue_add: err=%d\n",
					ret);
		}
	}

	return 0;
}

static int
eventdev_crypto_configure(struct l2fwd_crypto_options *options)
{
	struct rte_event_port_conf adapter_port_config = {0};
	uint8_t queue_id = 0, queue_prio = 0;
	int ret, i;
	struct rte_event ev = {0};

	rte_event_crypto_adapter_create(adapter_id, eventdev_id,
					&adapter_port_config,
					RTE_EVENT_CRYPTO_ADAPTER_OP_NEW);

	for (i = 0; i < options->nb_port_params; i++) {
		ev.flow_id = lcore_queue_conf[i].cryptodev_list[0];
		ev.sched_type = options->sched_type;
		ev.event_type = RTE_EVENT_TYPE_CRYPTODEV;
		ev.priority = queue_prio;
		ev.queue_id = queue_id;

		ret = rte_event_crypto_adapter_queue_pair_add(adapter_id,
				ev.flow_id, 0/*cdev_qp->queue_id*/,
				&ev);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				"rte_event_crypto_adapter_queue_pair_add: err=%d\n",
				ret);
	}

	return 0;
}

static int
eventdev_configure(struct l2fwd_crypto_options *options)
{
	struct rte_event_dev_config eventdev_conf = {0};
	struct rte_event_dev_info eventdev_def_conf = {0};
	struct rte_event_queue_conf eventq_conf = {0};
	struct lcore_queue_conf *qconf;
	uint32_t nb_lcores = rte_lcore_count();
	uint8_t ev_queue_id = 0, seq_core_id;
	unsigned int rx_lcore_id;
	uint32_t i;
	int ret;

	/* get default values of eventdev*/
	ret = rte_event_dev_info_get(eventdev_id, &eventdev_def_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			"rte_event_dev_info_get: err=%d\n", ret);

	eventdev_conf.nb_events_limit = -1;
	eventdev_conf.nb_event_queues = 1;
	eventdev_conf.nb_event_ports = nb_lcores;
	eventdev_conf.nb_event_queue_flows =
			eventdev_def_conf.max_event_queue_flows;
	eventdev_conf.nb_event_port_dequeue_depth =
			eventdev_def_conf.max_event_port_dequeue_depth;
	eventdev_conf.nb_event_port_enqueue_depth =
			eventdev_def_conf.max_event_port_enqueue_depth;

	ret = rte_event_dev_configure(eventdev_id, &eventdev_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			"rte_event_dev_configure: err=%d\n", ret);

	eventq_conf.nb_atomic_order_sequences =
		eventdev_def_conf.max_event_queue_flows;
	eventq_conf.nb_atomic_flows =
		eventdev_def_conf.max_event_queue_flows;
	eventq_conf.schedule_type = options->sched_type;
	ret = rte_event_queue_setup(eventdev_id, ev_queue_id, &eventq_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			"rte_event_queue_setup: err=%d\n", ret);

	for (i = 0; i < nb_lcores; i++) {
		ret = rte_event_port_setup(eventdev_id, i, NULL);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				"rte_event_port_setup: err=%d\n", ret);
	}

	for (i = 0; i < nb_lcores; i++) {
		rte_event_port_link(eventdev_id, i, &ev_queue_id, NULL, 1);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				"rte_event_port_link: err=%d\n", ret);
	}


	for (seq_core_id = 0, rx_lcore_id = 0; seq_core_id < nb_lcores;
			seq_core_id++, rx_lcore_id++) {
		while (rte_lcore_is_enabled(rx_lcore_id) == 0)
			rx_lcore_id++;
		/* Set sequential core id -
		 * used as event port id and crypto session id
		 */
		qconf = &lcore_queue_conf[rx_lcore_id];
		qconf->seq_core_id = seq_core_id++;
	}

	eventdev_eth_configure(options);

	if (options->fwd_mode != L2FWD_ETH_ONLY)
		eventdev_crypto_configure(options);

	ret = rte_event_dev_start(eventdev_id);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			"rte_event_dev_start: err=%d\n", ret);

	return 0;
}

int
main(int argc, char **argv)
{
	struct lcore_queue_conf *qconf = NULL;
	struct l2fwd_crypto_options options;

	uint8_t nb_cryptodevs, cdev_id;
	uint16_t portid;
	unsigned int lcore_id, rx_lcore_id = 0;
	int ret, enabled_cdevcount, enabled_portcount;
	uint8_t enabled_cdevs[RTE_CRYPTO_MAX_DEVS] = {0};

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	/* reserve memory for Cipher/Auth key and IV */
	reserve_key_memory(&options);

	/* parse application arguments (after the EAL ones) */
	ret = l2fwd_crypto_parse_args(&options, argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid L2FWD-CRYPTO arguments\n");

	/* create the mbuf pool */
	l2fwd_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF, 512,
			sizeof(struct rte_crypto_op),
			RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (l2fwd_pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* create crypto op pool */
	l2fwd_crypto_op_pool = rte_crypto_op_pool_create("crypto_op_pool",
			RTE_CRYPTO_OP_TYPE_SYMMETRIC, NB_MBUF, 128,
			MAXIMUM_IV_LENGTH, rte_socket_id());
	if (l2fwd_crypto_op_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create crypto op pool\n");

	/* Enable Ethernet ports */
	enabled_portcount = initialize_ports(&options);
	if (enabled_portcount < 1)
		rte_exit(EXIT_FAILURE, "Failed to initial Ethernet ports\n");

	/* Initialize the port/queue configuration of each logical core */
	RTE_ETH_FOREACH_DEV(portid) {

		/* skip ports that are not enabled */
		if ((options.portmask & (1 << portid)) == 0)
			continue;

		if (options.single_lcore && qconf == NULL) {
			while (rte_lcore_is_enabled(rx_lcore_id) == 0) {
				rx_lcore_id++;
				if (rx_lcore_id >= RTE_MAX_LCORE)
					rte_exit(EXIT_FAILURE,
							"Not enough cores\n");
			}
		} else if (!options.single_lcore) {
			/* get the lcore_id for this port */
			while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
			       lcore_queue_conf[rx_lcore_id].nb_rx_ports ==
			       options.nb_ports_per_lcore) {
				rx_lcore_id++;
				if (rx_lcore_id >= RTE_MAX_LCORE)
					rte_exit(EXIT_FAILURE,
							"Not enough cores\n");
			}
		}

		/* Assigned a new logical core in the loop above. */
		if (qconf != &lcore_queue_conf[rx_lcore_id])
			qconf = &lcore_queue_conf[rx_lcore_id];

		qconf->rx_port_list[qconf->nb_rx_ports] = portid;
		qconf->nb_rx_ports++;

		printf("Lcore %u: RX port %u\n", rx_lcore_id, portid);
	}

	eventdev_id = rte_event_dev_get_dev_id("event_dpaa2");
	if (eventdev_id < 0)
		eventdev_id = rte_event_dev_get_dev_id("event_dpaa1");
	if (eventdev_id < 0)
		rte_exit(EXIT_FAILURE, "No event device found");

	if (options.fwd_mode == L2FWD_ETH_ONLY)
		goto skip_crypto;

	/* Enable Crypto devices */
	enabled_cdevcount = initialize_cryptodevs(&options, enabled_portcount,
			enabled_cdevs);
	if (enabled_cdevcount < 0)
		rte_exit(EXIT_FAILURE, "Failed to initialize crypto devices\n");

	if (enabled_cdevcount < enabled_portcount)
		rte_exit(EXIT_FAILURE,
			 "Number of capable crypto devices (%d) has to be more or equal to number of ports (%d)\n",
			 enabled_cdevcount, enabled_portcount);

	nb_cryptodevs = rte_cryptodev_count();

	/* Initialize the port/cryptodev configuration of each logical core */
	for (rx_lcore_id = 0, qconf = NULL, cdev_id = 0;
			cdev_id < nb_cryptodevs && enabled_cdevcount;
			cdev_id++) {
		/* Crypto op not supported by crypto device */
		if (!enabled_cdevs[cdev_id])
			continue;

		if (options.single_lcore && qconf == NULL) {
			while (rte_lcore_is_enabled(rx_lcore_id) == 0) {
				rx_lcore_id++;
				if (rx_lcore_id >= RTE_MAX_LCORE)
					rte_exit(EXIT_FAILURE,
							"Not enough cores\n");
			}
		} else if (!options.single_lcore) {
			/* get the lcore_id for this port */
			while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
			       lcore_queue_conf[rx_lcore_id].nb_crypto_devs ==
			       options.nb_ports_per_lcore) {
				rx_lcore_id++;
				if (rx_lcore_id >= RTE_MAX_LCORE)
					rte_exit(EXIT_FAILURE,
							"Not enough cores\n");
			}
		}

		/* Assigned a new logical core in the loop above. */
		if (qconf != &lcore_queue_conf[rx_lcore_id])
			qconf = &lcore_queue_conf[rx_lcore_id];

		qconf->cryptodev_list[0/*qconf->nb_crypto_devs*/] = cdev_id;
		qconf->nb_crypto_devs++;

		enabled_cdevcount--;

		printf("Lcore %u: cryptodev %u\n", rx_lcore_id,
				(unsigned int)cdev_id);
	}

skip_crypto:
	ret = eventdev_configure(&options);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			"eventdev_configure: err=%d\n", ret);

	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(l2fwd_launch_one_lcore, (void *)&options,
			CALL_MASTER);
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0)
			return -1;
	}

	return 0;
}

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2025 NXP
 * Code was mostly borrowed from examples/l3fwd/main.c
 * See examples/l3fwd/main.c for additional Copyrights.
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
#include <rte_string_fns.h>
#include <rte_spinlock.h>
#include <rte_malloc.h>
#include <rte_pmd_dpaa2.h>
#include <rte_pmd_dpaa.h>
#include <rte_mbuf_pool_ops.h>

#include <cmdline_parse.h>
#include <cmdline_parse_etheraddr.h>
#include <rte_pdump.h>
#include <rte_ip_frag.h>

#include "port_fwd.h"
#include "nxp/rte_remote_direct_flow.h"

#define RTE_LOGTYPE_port_fwd RTE_LOGTYPE_USER1

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024

#define MAX_TX_QUEUE_PER_PORT RTE_MAX_ETHPORTS
#define MAX_RX_QUEUE_PER_PORT 128

#define MAX_LCORE_PARAMS 1024

/* Static global variables used within this file. */
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

uint32_t max_pkt_burst = MAX_PKT_BURST;
uint32_t max_tx_burst = MAX_TX_BURST;
uint32_t max_rx_burst = MAX_PKT_BURST;

enum port_fwd_proc_type {
	proc_primary = 0,
	proc_attach_secondary = 1,
	proc_standalone_secondary = 2,
};
static uint8_t s_proc_type = proc_primary;
static uint8_t s_ring_fwd;
static enum rte_remote_dir_cfg s_remote_dir;

static uint32_t s_data_room_size;

#define SEC_2_PRI "SEC_2_PRI_p%d_q%d"
#define PRI_2_SEC "PRI_2_SEC_p%d_q%d"

/* Global variables. */

static bool force_quit;

/* mask of enabled ports */
static uint32_t enabled_port_mask;
static uint16_t enabled_port_num;

struct port_queue_lcore_param {
	int port_id;
	int queue_id;
	int lcore_id;
} __rte_cache_aligned;

static struct port_queue_lcore_param s_pqc[MAX_LCORE_PARAMS];
static uint16_t s_pqc_num;

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = RTE_ETH_MQ_RX_RSS,
		.max_lro_pkt_size = RTE_MBUF_DEFAULT_DATAROOM,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = RTE_ETH_RSS_IP,
		},
	},
};

static struct lcore_conf s_lcore_conf[RTE_MAX_LCORE];

static int fwd_dst_port[RTE_MAX_ETHPORTS];

static int rx_seg_port[RTE_MAX_ETHPORTS];

static struct rte_mempool *pktmbuf_pools[RTE_ETH_DPAA_RX_MAX_MPOOLS];
static struct rte_mempool *pktmbuf_per_port_pool[RTE_MAX_ETHPORTS];
static int s_default_pool[RTE_MAX_ETHPORTS];

static struct rte_mempool *pktmbuf_pool_tx_only;

#define MAX_FRAG_NUM 10

#define RTE_MAX_QUEUES 128
static uint16_t s_pq_map[RTE_MAX_ETHPORTS][RTE_MAX_QUEUES];

static uint64_t max_mbuf_addr;
static uint64_t min_mbuf_addr = (~((uint64_t)0));

static int s_dump_mbuf;
static int s_inject;
static uint16_t s_inject_pkt_size = 64;
static int s_fragment_tx_port = -1;
static int s_reassemble_rx_port = -1;

static uint8_t s_per_port_pool;

static int s_jumbo_size = 9000;

static uint16_t s_tx_seg = 1;

/** DPAA1 platform support only now.*/
static int s_mpool_select_by_size;
static int s_mpool_select_by_size_debug;

static uint8_t s_inject_pkt_base[] = {
	0x00, 0xE0, 0x0C, 0x00, 0x01, 0x00, 0x00, 0x10,
	0x94, 0x00, 0x00, 0x01, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFD,
	0xED, 0x40, 0xC0, 0xA8, 0x0B, 0x02, 0x01, 0x01,
	0x01, 0x01
};

#define PORT_FWD_EXTBUF_ZONE_SIZE \
	(RTE_PGSIZE_2M - 4 * RTE_CACHE_LINE_SIZE)

struct port_fwd_extmem_init_ctx {
	const struct rte_pktmbuf_extmem *ext_mem; /* descriptor array. */
	uint32_t ext_num; /* number of descriptors in array. */
	uint32_t ext; /* loop descriptor index. */
	size_t off; /* loop buffer offset. */
};

enum {
	PORT_FWD_TX_BUF_PLATFORM,
	PORT_FWD_TX_BUF_DEFAULT,
	PORT_FWD_TX_BUF_EXT
};

static int s_port_fwd_tx_buf_type = PORT_FWD_TX_BUF_PLATFORM;

struct loop_mode {
	int (*parse_fwd_dst)(int portid);
	rte_rx_callback_fn cb_parse_ptype;
	int (*main_loop)(void *dummy);
};

#define PORT_FWD_MBUF_FCS(mbuf) \
	(mbuf->pkt_len + PKTGEN_ETH_FCS_SIZE * mbuf->nb_segs)

#define PORT_FWD_MBUF_OVERHEAD(mbuf) \
	(mbuf->pkt_len + PKTGEN_ETH_OVERHEAD_SIZE * mbuf->nb_segs)

static int parse_port_fwd_dst(int portid)
{
	char *penv;
	char env_name[64];

	fwd_dst_port[portid] = -1;
	sprintf(env_name, "PORT%d_FWD", portid);
	penv = getenv(env_name);
	if (penv)
		fwd_dst_port[portid] = atoi(penv);

	if (fwd_dst_port[portid] < 0) {
		RTE_LOG(WARNING, port_fwd,
			"Drop packets from port %d\r\n", portid);
		return 0;
	}

	RTE_LOG(INFO, port_fwd,
		"Forward traffic from port %d to port %d\r\n",
		portid, fwd_dst_port[portid]);

	return 0;
}

static int parse_seg_rx_port(int portid)
{
	char *penv;
	char env_name[64];

	sprintf(env_name, "PORT%d_RX_SEG", portid);
	penv = getenv(env_name);
	if (penv)
		rx_seg_port[portid] = atoi(penv);

	if (rx_seg_port[portid]) {
		RTE_LOG(INFO, port_fwd,
			"Gather rx frames from port%d\r\n",
			portid);
	}

	return 0;
}

static int
port_fwd_dst_port(uint16_t src_port)
{
	return fwd_dst_port[src_port];
}

static int
port_fwd_rx_seg_port(uint16_t rx_port)
{
	return rx_seg_port[rx_port];
}

static void
port_fwd_drain_tx_cnf(struct lcore_conf *qconf)
{
	uint16_t drain, i, portid, queueid;
	int dstportid;

	for (i = 0; i < qconf->n_rx_queue; i++) {
		portid = qconf->rx_queue_list[i].port_id;
		dstportid = port_fwd_dst_port(portid);
		if (dstportid < 0)
			continue;
		queueid = qconf->tx_queue_id[dstportid];
		if (!rte_pmd_dpaa2_dev_is_dpaa2(dstportid))
			continue;
		rte_delay_us(10000);
drain_again:
		drain = rte_pmd_dpaa2_clean_tx_conf(dstportid, queueid);
		if (drain)
			goto drain_again;
	}
}

static uint32_t
port_fwd_setup_extbuf(uint32_t nb_mbufs, uint16_t mbuf_sz,
	uint32_t socket_id, char *pool_name,
	struct rte_pktmbuf_extmem **ext_mem)
{
	struct rte_pktmbuf_extmem *xmem;
	unsigned int ext_num, zone_num, elt_num;
	uint16_t elt_size;

	elt_size = RTE_ALIGN_CEIL(mbuf_sz, RTE_CACHE_LINE_SIZE);
	elt_num = PORT_FWD_EXTBUF_ZONE_SIZE / elt_size;
	zone_num = (nb_mbufs + elt_num - 1) / elt_num;

	xmem = malloc(sizeof(struct rte_pktmbuf_extmem) * zone_num);
	if (xmem == NULL) {
		RTE_LOG(ERR, port_fwd, "malloc size=%ld failed\n",
			sizeof(struct rte_pktmbuf_extmem) * zone_num);
		*ext_mem = NULL;
		return 0;
	}
	for (ext_num = 0; ext_num < zone_num; ext_num++) {
		struct rte_pktmbuf_extmem *xseg = xmem + ext_num;
		const struct rte_memzone *mz;
		char mz_name[RTE_MEMZONE_NAMESIZE];
		int ret;

		ret = snprintf(mz_name, sizeof(mz_name),
			RTE_MEMPOOL_MZ_FORMAT "_xb_%u", pool_name, ext_num);
		if (ret < 0 || ret >= (int)sizeof(mz_name)) {
			errno = ENAMETOOLONG;
			ext_num = 0;
			break;
		}
		mz = rte_memzone_reserve(mz_name, PORT_FWD_EXTBUF_ZONE_SIZE,
			socket_id, RTE_MEMZONE_IOVA_CONTIG | RTE_MEMZONE_1GB |
			RTE_MEMZONE_SIZE_HINT_ONLY);
		if (mz == NULL) {
			/*
			 * The caller exits on external buffer creation
			 * error, so there is no need to free memzones.
			 */
			errno = ENOMEM;
			ext_num = 0;
			break;
		}
		xseg->buf_ptr = mz->addr;
		xseg->buf_iova = mz->iova;
		xseg->buf_len = PORT_FWD_EXTBUF_ZONE_SIZE;
		xseg->elt_size = elt_size;
	}
	if (ext_num == 0 && xmem != NULL) {
		free(xmem);
		xmem = NULL;
	}
	*ext_mem = xmem;
	return ext_num;
}

static void
port_fwd_pktmbuf_free_pinned_extmem(void *addr, void *opaque)
{
	struct rte_mbuf *m = opaque;

	RTE_SET_USED(addr);
	RTE_ASSERT(RTE_MBUF_HAS_EXTBUF(m));
	RTE_ASSERT(RTE_MBUF_HAS_PINNED_EXTBUF(m));
	RTE_ASSERT(m->shinfo->fcb_opaque == m);

	rte_mbuf_ext_refcnt_set(m->shinfo, 1);
	m->ol_flags = RTE_MBUF_F_EXTERNAL;
	if (m->next != NULL)
		m->next = NULL;
	if (m->nb_segs != 1)
		m->nb_segs = 1;
	rte_mbuf_raw_free(m);
}

static void
port_fwd_pktmbuf_init_extmem(struct rte_mempool *mp,
	void *opaque_arg, void *_m, __rte_unused uint32_t i)
{
	struct rte_mbuf *m = _m;
	struct port_fwd_extmem_init_ctx *ctx = opaque_arg;
	const struct rte_pktmbuf_extmem *ext_mem;
	uint32_t mbuf_size, buf_len, priv_size;
	struct rte_mbuf_ext_shared_info *shinfo;

	priv_size = rte_pktmbuf_priv_size(mp);
	mbuf_size = sizeof(struct rte_mbuf) + priv_size;
	buf_len = rte_pktmbuf_data_room_size(mp);

	RTE_ASSERT(RTE_ALIGN(priv_size, RTE_MBUF_PRIV_ALIGN) == priv_size);
	RTE_ASSERT(mp->elt_size >= mbuf_size);
	RTE_ASSERT(buf_len <= UINT16_MAX);

	memset(m, 0, mbuf_size);
	m->priv_size = priv_size;
	m->buf_len = (uint16_t)buf_len;

	/* set the data buffer pointers to external memory */
	ext_mem = ctx->ext_mem + ctx->ext;

	RTE_ASSERT(ctx->ext < ctx->ext_num);
	RTE_ASSERT(ctx->off + ext_mem->elt_size <= ext_mem->buf_len);

	m->buf_addr = RTE_PTR_ADD(ext_mem->buf_ptr, ctx->off);
	rte_mbuf_iova_set(m, ext_mem->buf_iova ==
		RTE_BAD_IOVA ? RTE_BAD_IOVA : (ext_mem->buf_iova + ctx->off));

	ctx->off += ext_mem->elt_size;
	if (ctx->off + ext_mem->elt_size > ext_mem->buf_len) {
		ctx->off = 0;
		++ctx->ext;
	}
	/* keep some headroom between start of buffer and data */
	m->data_off = RTE_MIN(RTE_PKTMBUF_HEADROOM, (uint16_t)m->buf_len);

	/* init some constant fields */
	m->pool = mp;
	m->nb_segs = 1;
	m->port = RTE_MBUF_PORT_INVALID;
	m->ol_flags = RTE_MBUF_F_EXTERNAL;
	rte_mbuf_refcnt_set(m, 1);
	m->next = NULL;

	/* init external buffer shared info items */
	shinfo = RTE_PTR_ADD(m, mbuf_size);
	m->shinfo = shinfo;
	shinfo->free_cb = port_fwd_pktmbuf_free_pinned_extmem;
	shinfo->fcb_opaque = m;
	rte_mbuf_ext_refcnt_set(shinfo, 1);
}

static struct rte_mempool *
port_fwd_pktmbuf_pool_create_extbuf(const char *name, uint32_t n,
	uint32_t cache_size, uint16_t priv_size, uint16_t data_room_size,
	int socket_id, const struct rte_pktmbuf_extmem *ext_mem,
	uint32_t ext_num, const char *mp_ops_name)
{
	struct rte_mempool *mp;
	struct rte_pktmbuf_pool_private mbp_priv;
	struct port_fwd_extmem_init_ctx init_ctx;
	uint32_t elt_size, i, n_elts = 0;
	int ret;

	if (RTE_ALIGN(priv_size, RTE_MBUF_PRIV_ALIGN) != priv_size) {
		RTE_LOG(ERR, port_fwd, "mbuf priv_size=%u is not aligned\n",
			priv_size);
		rte_errno = EINVAL;
		return NULL;
	}
	/* Check the external memory descriptors. */
	for (i = 0; i < ext_num; i++) {
		const struct rte_pktmbuf_extmem *extm = ext_mem + i;

		if (!extm->elt_size || !extm->buf_len || !extm->buf_ptr) {
			RTE_LOG(ERR, port_fwd, "invalid extmem descriptor\n");
			rte_errno = EINVAL;
			return NULL;
		}
		if (data_room_size > extm->elt_size) {
			RTE_LOG(ERR, port_fwd, "ext elt_size=%u is too small\n",
				priv_size);
			rte_errno = EINVAL;
			return NULL;
		}
		n_elts += extm->buf_len / extm->elt_size;
	}
	/* Check whether enough external memory provided. */
	if (n_elts < n) {
		RTE_LOG(ERR, port_fwd, "not enough extmem\n");
		rte_errno = ENOMEM;
		return NULL;
	}
	elt_size = sizeof(struct rte_mbuf) + priv_size +
		sizeof(struct rte_mbuf_ext_shared_info);

	memset(&mbp_priv, 0, sizeof(mbp_priv));
	mbp_priv.mbuf_data_room_size = data_room_size;
	mbp_priv.mbuf_priv_size = priv_size;
	mbp_priv.flags = RTE_PKTMBUF_POOL_F_PINNED_EXT_BUF;

	mp = rte_mempool_create_empty(name, n, elt_size, cache_size,
		 sizeof(struct rte_pktmbuf_pool_private), socket_id, 0);
	if (!mp)
		return NULL;

	if (!mp_ops_name)
		mp_ops_name = rte_mbuf_best_mempool_ops();
	ret = rte_mempool_set_ops_byname(mp, mp_ops_name, NULL);
	if (ret) {
		RTE_LOG(ERR, port_fwd, "error setting mempool handler\n");
		rte_mempool_free(mp);
		rte_errno = -ret;
		return NULL;
	}
	rte_pktmbuf_pool_init(mp, &mbp_priv);

	ret = rte_mempool_populate_default(mp);
	if (ret < 0) {
		rte_mempool_free(mp);
		rte_errno = -ret;
		return NULL;
	}

	memset(&init_ctx, 0, sizeof(struct port_fwd_extmem_init_ctx));
	init_ctx.ext_mem = ext_mem;
	init_ctx.ext_num = ext_num;

	rte_mempool_obj_iter(mp, port_fwd_pktmbuf_init_extmem, &init_ctx);

	return mp;
}

static struct rte_mempool *
port_fwd_create_ext_pool(char *nm, uint32_t nb_mbufs,
	uint16_t mbuf_sz, uint16_t cache_sz)
{
	struct rte_pktmbuf_extmem *ext_mem;
	uint32_t ext_num;
	struct rte_mempool *mp;

	ext_num = port_fwd_setup_extbuf(nb_mbufs, mbuf_sz,
		0, nm, &ext_mem);
	if (!ext_num) {
		rte_exit(EXIT_FAILURE,
			"Can't create pinned data buffers\n");
	}

	mp = port_fwd_pktmbuf_pool_create_extbuf(nm, nb_mbufs, cache_sz,
		0, mbuf_sz, 0, ext_mem, ext_num, RTE_MBUF_DEFAULT_MEMPOOL_OPS);
	free(ext_mem);

	return mp;
}

static void
port_fwd_inject_gen_pkt(struct rte_mbuf *mbuf)
{
	struct rte_ether_hdr *eth_header;
	struct rte_ipv4_hdr *ipv4_header;
	uint64_t rand = rte_rand();
	uint8_t *payload = rte_pktmbuf_mtod(mbuf, void *);
	const uint16_t len = s_inject_pkt_size -
		sizeof(struct rte_ether_hdr) - PKTGEN_ETH_FCS_SIZE;

	rte_memcpy(payload, s_inject_pkt_base,
		sizeof(s_inject_pkt_base));
	eth_header = (struct rte_ether_hdr *)payload;
	ipv4_header = (struct rte_ipv4_hdr *)(eth_header + 1);
	ipv4_header->total_length = rte_cpu_to_be_16(len);
	ipv4_header->packet_id = rte_cpu_to_be_16(0x1234);
	ipv4_header->src_addr = (rte_be32_t)(rand & 0xffffffff);
	ipv4_header->dst_addr = (rte_be32_t)((rand >> 32) & 0xffffffff);
	ipv4_header->hdr_checksum = 0;
	ipv4_header->hdr_checksum = rte_ipv4_cksum(ipv4_header);

	mbuf->pkt_len = s_inject_pkt_size - PKTGEN_ETH_FCS_SIZE;
	mbuf->data_len = s_inject_pkt_size - PKTGEN_ETH_FCS_SIZE;
}

static int
port_fwd_alloc_seg_mbufs(struct rte_mempool *pools[],
	struct rte_mbuf **mbuf_hdr)
{
	uint16_t i;
	int ret = 0, same_pool = true;
	struct rte_mbuf *mbuf_segs[s_tx_seg], *mbuf;

	for (i = 1; i < s_tx_seg; i++) {
		if (pools[0] != pools[i]) {
			same_pool = false;
			break;
		}
	}
	memset(mbuf_segs, 0, sizeof(struct rte_mbuf *) * s_tx_seg);

	if (same_pool) {
		ret = rte_pktmbuf_alloc_bulk(pools[0], mbuf_segs, s_tx_seg);
	} else {
		for (i = 0; i < s_tx_seg; i++) {
			mbuf_segs[i] = rte_pktmbuf_alloc(pools[i]);
			if (!mbuf_segs[i]) {
				ret = -ENOMEM;
				break;
			}
		}
	}
	if (ret) {
		for (i = 0; i < s_tx_seg; i++) {
			if (mbuf_segs[i])
				rte_pktmbuf_free(mbuf_segs[i]);
		}
		return ret;
	}
	mbuf = mbuf_segs[0];
	mbuf->nb_segs = s_tx_seg;
	for (i = 1; i < s_tx_seg; i++) {
		mbuf->next = mbuf_segs[i];
		mbuf = mbuf_segs[i];
	}
	mbuf->next = NULL; /* Last segment of packet. */
	*mbuf_hdr = mbuf_segs[0];

	return 0;
}

static uint16_t
port_fwd_dup_mbufs(uint32_t eth_id,
	uint16_t txq_id, struct rte_mbuf *mbuf_to[],
	struct rte_mbuf *mbuf_from[], uint16_t count)
{
	uint16_t tx_clean, clean_count, alloc_count, i, start = 0;
	int ret;
	struct rte_mempool *pools[s_tx_seg];

	for (i = 0; i < s_tx_seg; i++) {
		if (!(i % 2)) {
			pools[i] = pktmbuf_pool_tx_only ?
				pktmbuf_pool_tx_only : pktmbuf_per_port_pool[eth_id];
		} else {
			pools[i] = pktmbuf_per_port_pool[eth_id];
		}
	}

	if (!mbuf_from) {
		alloc_count = 0;
alloc_again:
		if (alloc_count > 10) {
			for (i = 0; i < start; i++)
				rte_pktmbuf_free(mbuf_to[i]);
			return 0;
		}
		ret = 0;
		if (s_tx_seg > 1) {
			for (i = start; i < count; i++) {
				ret = port_fwd_alloc_seg_mbufs(pools, &mbuf_to[i]);
				if (ret)
					break;
			}
			start = i;
		} else {
			ret = rte_pktmbuf_alloc_bulk(pools[0], mbuf_to, count);
		}
		if (ret) {
			clean_count = 0;
alloc_clean_again:
			tx_clean = rte_pmd_dpaa2_clean_tx_conf(eth_id, txq_id);
			if (!tx_clean) {
				clean_count++;
				if (clean_count < 100)
					goto alloc_clean_again;
			}
			alloc_count++;
			goto alloc_again;
		}
		for (i = 0; i < count; i++)
			port_fwd_inject_gen_pkt(mbuf_to[i]);

		return count;
	}

	for (i = 0; i < count; i++) {
		alloc_count = 0;
copy_again:
		if (alloc_count > 10)
			break;
		mbuf_to[i] = rte_pktmbuf_copy(mbuf_from[i],
			pools[0], 0,
			mbuf_from[i]->pkt_len);
		if (!mbuf_to[i]) {
			clean_count = 0;
copy_clean_again:
			tx_clean = rte_pmd_dpaa2_clean_tx_conf(eth_id, txq_id);
			if (!tx_clean) {
				clean_count++;
				if (clean_count < 100)
					goto copy_clean_again;
			}
			alloc_count++;
			goto copy_again;
		}
	}

	rte_pktmbuf_free_bulk(mbuf_from, count);

	return i;
}

static void
port_fwd_reassemble_process(struct lcore_rx_queue *lc_rxq,
	struct rte_mbuf *mbufs[], uint16_t nb_rx)
{
	uint16_t i;
	uint8_t ip_offset;
	struct rte_mbuf *mo;
	int ret;
	struct rte_ipv4_hdr *ip_hdr;
	struct rte_ip_frag_tbl *tbl;
	struct rte_ip_frag_death_row *dr = &lc_rxq->dr;
	uint8_t *pay_load;
	uint32_t lcore_id = rte_lcore_id();
	struct lcore_conf *qconf;
	uint64_t frag_cycles;
	uint32_t bucket_num = 0x1000, bucket_entries = 16, max_entries = 0x1000;

	frag_cycles = (rte_get_tsc_hz() + MS_PER_S - 1) / MS_PER_S * MS_PER_S;

	qconf = &s_lcore_conf[lcore_id];

	if (!lc_rxq->tbl) {
		lc_rxq->tbl = rte_ip_frag_table_create(bucket_num,
			bucket_entries, max_entries, frag_cycles,
			rte_socket_id());
		if (!lc_rxq->tbl) {
			rte_panic("%s, line %d: Create fragment table failed\n",
				__func__, __LINE__);
		}
	}
	tbl = lc_rxq->tbl;

	for (i = 0; i < nb_rx; i++) {
		if ((mbufs[i]->packet_type & RTE_PTYPE_L4_MASK) !=
			RTE_PTYPE_L4_FRAG) {
			mo = mbufs[i];
			goto free_buf;
		}
		ip_offset = 0;
		ret = rte_pmd_dpaa2_rx_get_offset(RTE_MAX_ETHPORTS,
			mbufs[i], &ip_offset, NULL, NULL);
		if (ret)
			continue;
		pay_load = rte_pktmbuf_mtod(mbufs[i], void *);
		ip_hdr = (void *)(pay_load + ip_offset);
		mbufs[i]->l2_len = sizeof(struct rte_ether_hdr);
		mbufs[i]->l3_len = sizeof(struct rte_ipv4_hdr);
		mo = rte_ipv4_frag_reassemble_packet(tbl,
			dr, mbufs[i], rte_rdtsc(), ip_hdr);
		if (!mo)
			continue;
		qconf->rx_reassemble_count[lc_rxq->port_id]++;
		qconf->rx_reassemble_bytes[lc_rxq->port_id] += mo->pkt_len;

free_buf:
		rte_pktmbuf_free(mo);
		mo = NULL;
	}

	if (dr->cnt >= RTE_IP_FRAG_DEATH_ROW_MBUF_LEN) {
		rte_panic("%s: Mbuf count in frag death row overflows\n",
			__func__);
	}
	rte_ip_frag_free_death_row(dr, 3);
}

static int
main_frag_tx_test_loop(void)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	uint16_t tx_len[MAX_PKT_BURST * MAX_FRAG_NUM];
	unsigned int lcore_id;
	int i, j, num, k;
	uint16_t portid;
	int dstportid;
	uint8_t queueid;
	struct lcore_conf *qconf;
	char *penv;
	uint16_t burst_size = 1, frag_count, nb_tx, sent;
	uint16_t inject_size = s_inject_pkt_size - PKTGEN_ETH_FCS_SIZE;
	struct rte_mbuf *frag_pkts[MAX_PKT_BURST * MAX_FRAG_NUM], **pkts;
	struct rte_ether_hdr eth_hdr;
	struct rte_ipv4_hdr *ip_hdr;
	uint16_t wait_s = 0;

	penv = getenv("PORT_FWD_INJECTION_BURST_SIZE");
	if (penv) {
		burst_size = atoi(penv);
		if (burst_size < 1 || burst_size > MAX_PKT_BURST)
			burst_size = MAX_PKT_BURST;
	}
	penv = getenv("PORT_FWD_TX_FRAG_WAIT_TIME");
	if (penv)
		wait_s = atoi(penv);

	RTE_LOG(INFO, port_fwd,
		"Inject pkt size is %d and burst size is %d\n",
		s_inject_pkt_size, burst_size);

	lcore_id = rte_lcore_id();
	qconf = &s_lcore_conf[lcore_id];

	if (qconf->n_rx_queue == 0) {
		RTE_LOG(INFO, port_fwd,
			"lcore %u has nothing to do\n", lcore_id);
		return 0;
	}

	RTE_LOG(INFO, port_fwd,
		"entering injection test loop on lcore %u\n",
		lcore_id);

	for (i = 0; i < qconf->n_rx_queue; i++) {
		portid = qconf->rx_queue_list[i].port_id;
		queueid = qconf->rx_queue_list[i].queue_id;
		RTE_LOG(INFO, port_fwd,
			" -- lcoreid=%u portid=%u rxqueueid=%hhu\n",
			lcore_id, portid, queueid);
	}

	while (!force_quit) {
		/* Read packet from RX queues
		 */
		for (i = 0; i < qconf->n_rx_queue; i++) {
			portid = qconf->rx_queue_list[i].port_id;
			queueid = qconf->rx_queue_list[i].queue_id;

			dstportid = portid;

			if (s_fragment_tx_port != dstportid)
				continue;

			nb_tx = port_fwd_dup_mbufs(dstportid,
				qconf->tx_queue_id[dstportid],
				pkts_burst, NULL, burst_size);
			if (!nb_tx)
				continue;

			frag_count = 0;
			for (j = 0; j < nb_tx; j++) {
				pkts_burst[j]->data_off = RTE_PKTMBUF_HEADROOM;
				pkts_burst[j]->pkt_len = inject_size;
				pkts_burst[j]->data_len = inject_size;
				qconf->tx_jumbo_count[dstportid]++;
				qconf->tx_jumbo_bytes[dstportid] += inject_size;
				rte_memcpy(&eth_hdr, rte_pktmbuf_mtod(pkts_burst[j], void *),
					sizeof(struct rte_ether_hdr));
				rte_pktmbuf_adj(pkts_burst[j], sizeof(struct rte_ether_hdr));
				num = rte_ipv4_fragment_packet(pkts_burst[j],
					&frag_pkts[frag_count], MAX_FRAG_NUM, RTE_ETHER_MTU,
					pkts_burst[j]->pool, pkts_burst[j]->pool);
				rte_pktmbuf_free(pkts_burst[j]);
				if (num <= 0) {
					RTE_LOG(DEBUG, port_fwd,
						"Fragment frame err(%d)\n", num);
					continue;
				}
				pkts = &frag_pkts[frag_count];
				for (k = 0; k < num; k++) {
					ip_hdr = rte_pktmbuf_mtod(pkts[k], void *);
					ip_hdr->hdr_checksum = 0;
					rte_pktmbuf_prepend(pkts[k], sizeof(struct rte_ether_hdr));
					rte_memcpy(rte_pktmbuf_mtod(pkts[k], void *),
						&eth_hdr, sizeof(struct rte_ether_hdr));
					pkts[k]->ol_flags |=
						(RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM);
					pkts[k]->l2_len = sizeof(struct rte_ether_hdr);
					tx_len[frag_count + k] = pkts[k]->pkt_len;
				}
				frag_count += num;
			}

			sent = rte_eth_tx_burst(dstportid,
					qconf->tx_queue_id[dstportid],
					frag_pkts, frag_count);
			for (j = 0; j < sent; j++) {
				qconf->tx_statistic[dstportid].bytes +=
					tx_len[j];
				qconf->tx_statistic[dstportid].bytes_fcs +=
					tx_len[j] + PKTGEN_ETH_FCS_SIZE;
				qconf->tx_statistic[dstportid].bytes_overhead +=
					tx_len[j] + PKTGEN_ETH_OVERHEAD_SIZE;
			}
			qconf->tx_statistic[dstportid].packets += sent;

			/* Free any unsent packets. */
			for (j = sent; j < frag_count; j++)
				rte_pktmbuf_free(frag_pkts[j]);
		}

		if (wait_s)
			sleep(wait_s);
	}

	if (qconf->dump_buf) {
		rte_free(qconf->dump_buf);
		qconf->dump_buf = NULL;
	}

	if (pktmbuf_pool_tx_only)
		port_fwd_drain_tx_cnf(qconf);

	return 0;
}

static int
main_reassemble_rx_loop(void)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	unsigned int lcore_id;
	int i, j, nb_rx;
	uint16_t portid;
	uint8_t queueid;
	struct lcore_conf *qconf;

	lcore_id = rte_lcore_id();
	qconf = &s_lcore_conf[lcore_id];

	if (qconf->n_rx_queue == 0) {
		RTE_LOG(INFO, port_fwd,
			"lcore %u has nothing to do\n", lcore_id);
		return 0;
	}

	RTE_LOG(INFO, port_fwd,
		"entering injection test loop on lcore %u\n",
		lcore_id);

	for (i = 0; i < qconf->n_rx_queue; i++) {
		portid = qconf->rx_queue_list[i].port_id;
		queueid = qconf->rx_queue_list[i].queue_id;
		RTE_LOG(INFO, port_fwd,
			" -- lcoreid=%u portid=%u rxqueueid=%hhu\n",
			lcore_id, portid, queueid);
	}

	while (!force_quit) {
		/* Read packet from RX queues
		 */
		for (i = 0; i < qconf->n_rx_queue; i++) {
			portid = qconf->rx_queue_list[i].port_id;
			queueid = qconf->rx_queue_list[i].queue_id;

			nb_rx = rte_eth_rx_burst(portid, queueid, pkts_burst,
				MAX_PKT_BURST);

			for (j = 0; j < nb_rx; j++) {
				qconf->rx_statistic[portid].bytes +=
					pkts_burst[j]->pkt_len;
				qconf->rx_statistic[portid].bytes_fcs +=
					PORT_FWD_MBUF_FCS(pkts_burst[j]);
				qconf->rx_statistic[portid].bytes_overhead +=
					PORT_FWD_MBUF_OVERHEAD(pkts_burst[j]);
			}
			qconf->rx_statistic[portid].packets += nb_rx;

			if (s_reassemble_rx_port == portid) {
				if (nb_rx > 0) {
					port_fwd_reassemble_process(&qconf->rx_queue_list[i],
						pkts_burst, nb_rx);
				}
				continue;
			}
			rte_pktmbuf_free_bulk(pkts_burst, nb_rx);
		}
	}

	if (qconf->dump_buf) {
		rte_free(qconf->dump_buf);
		qconf->dump_buf = NULL;
	}

	return 0;
}

static int
main_injection_test_loop(void)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST], *pkt;
	uint16_t tx_len[MAX_PKT_BURST];
	unsigned int lcore_id;
	int i, nb_rx, j;
	uint16_t nb_tx, sent;
	uint16_t portid;
	int dstportid;
	uint8_t queueid;
	struct lcore_conf *qconf;
	char *penv;
	uint16_t burst_size = MAX_PKT_BURST, total;
	uint16_t inject_size = s_inject_pkt_size - PKTGEN_ETH_FCS_SIZE;

	penv = getenv("PORT_FWD_INJECTION_BURST_SIZE");
	if (penv) {
		burst_size = atoi(penv);
		if (burst_size < 1 || burst_size > MAX_PKT_BURST)
			burst_size = MAX_PKT_BURST;
	}
	RTE_LOG(INFO, port_fwd,
		"Inject pkt size is %d and burst size is %d\n",
		s_inject_pkt_size, burst_size);

	lcore_id = rte_lcore_id();
	qconf = &s_lcore_conf[lcore_id];

	if (qconf->n_rx_queue == 0) {
		RTE_LOG(INFO, port_fwd,
			"lcore %u has nothing to do\n", lcore_id);
		return 0;
	}

	RTE_LOG(INFO, port_fwd,
		"entering injection test loop on lcore %u\n",
		lcore_id);

	for (i = 0; i < qconf->n_rx_queue; i++) {
		portid = qconf->rx_queue_list[i].port_id;
		queueid = qconf->rx_queue_list[i].queue_id;
		RTE_LOG(INFO, port_fwd,
			" -- lcoreid=%u portid=%u rxqueueid=%hhu\n",
			lcore_id, portid, queueid);
	}

	while (!force_quit) {
		/* Read packet from RX queues
		 */
		for (i = 0; i < qconf->n_rx_queue; i++) {
			portid = qconf->rx_queue_list[i].port_id;
			queueid = qconf->rx_queue_list[i].queue_id;

			dstportid = portid;

			nb_rx = rte_eth_rx_burst(portid, queueid, pkts_burst,
				MAX_PKT_BURST);

			for (j = 0; j < nb_rx; j++) {
				qconf->rx_statistic[portid].bytes +=
					pkts_burst[j]->pkt_len;
				qconf->rx_statistic[portid].bytes_fcs +=
					PORT_FWD_MBUF_FCS(pkts_burst[j]);
				qconf->rx_statistic[portid].bytes_overhead +=
					PORT_FWD_MBUF_OVERHEAD(pkts_burst[j]);
			}
			qconf->rx_statistic[portid].packets += nb_rx;

			rte_pktmbuf_free_bulk(pkts_burst, nb_rx);

			nb_tx = port_fwd_dup_mbufs(dstportid,
				qconf->tx_queue_id[dstportid],
				pkts_burst, NULL, burst_size);
			if (!nb_tx)
				continue;

			for (j = 0; j < nb_tx; j++) {
				total = 0;
				pkts_burst[j]->data_off = RTE_PKTMBUF_HEADROOM;
				pkts_burst[j]->pkt_len = inject_size;
				pkts_burst[j]->data_len = inject_size / s_tx_seg;
				total += pkts_burst[j]->data_len;
				pkt = pkts_burst[j];
				while (pkt->next) {
					pkt = pkt->next;
					pkt->data_off = RTE_PKTMBUF_HEADROOM;
					pkt->data_len = pkt->next ?
						(inject_size / s_tx_seg) : (inject_size - total);
					total += pkt->data_len;
				}
				tx_len[j] = inject_size;
			}

			sent = rte_eth_tx_burst(dstportid,
					qconf->tx_queue_id[dstportid],
					pkts_burst, nb_tx);

			for (j = 0; j < sent; j++) {
				qconf->tx_statistic[dstportid].bytes +=
					tx_len[j];
				qconf->tx_statistic[dstportid].bytes_fcs +=
					tx_len[j] + PKTGEN_ETH_FCS_SIZE;
				qconf->tx_statistic[dstportid].bytes_overhead +=
					tx_len[j] + PKTGEN_ETH_OVERHEAD_SIZE;
			}
			qconf->tx_statistic[dstportid].packets += sent;

			/* Free any unsent packets. */
			for (j = sent; j < nb_tx; j++)
				rte_pktmbuf_free(pkts_burst[j]);
		}
	}

	if (qconf->dump_buf) {
		rte_free(qconf->dump_buf);
		qconf->dump_buf = NULL;
	}

	if (pktmbuf_pool_tx_only)
		port_fwd_drain_tx_cnf(qconf);

	return 0;
}

static inline void
dump_mbuf_data(struct rte_mbuf *pkt, int tx_rx,
	uint16_t portid, struct lcore_conf *qconf)
{
	uint32_t i, off = 0;
	uint8_t *data = (uint8_t *)pkt->buf_addr +
		pkt->data_off;

	if (likely(!s_dump_mbuf))
		return;

	if (!qconf->dump_buf)
		qconf->dump_buf = rte_malloc(NULL, 4096, 0);

	RTE_LOG(INFO, port_fwd,
		"%s %d pkt len:%d\r\n", tx_rx ?
		"Send to" : "Recv from",
		portid, pkt->pkt_len);
	if (!qconf->dump_buf)
		return;
	for (i = 0; i < pkt->pkt_len; i++) {
		off += sprintf(&qconf->dump_buf[off],
			"%02x ", data[i]);
		if ((i + 1) % 16 == 0)
			off += sprintf(&qconf->dump_buf[off], "\r\n");
	}

	RTE_LOG(INFO, port_fwd,
		"%s\r\n", qconf->dump_buf);
}

static uint16_t
port_fwd_xmit_burst(struct rte_mbuf *pkts_burst[],
	uint16_t expected_nb, uint16_t rx_portid, int dstportid,
	uint16_t queue_id, uint8_t sents[],
	int re_send_max)
{
	uint16_t nb_tx = 0, ret, burst_nb = 0, sent, re_send;
	uint32_t max_size = 0;
	int i, j;
	struct rte_mbuf **tx_pkts;

	if (dstportid < 0) {
		rte_pktmbuf_free_bulk(pkts_burst, expected_nb);

		return 0;
	}

	if (port_fwd_rx_seg_port(rx_portid)) {
		for (j = (expected_nb - 1); j >= 0; j--) {
			max_size += pkts_burst[j]->data_len;
			if ((j - 1) >= 0 &&
				(max_size + pkts_burst[j - 1]->data_len) <
				s_data_room_size) {
				pkts_burst[j - 1]->next = pkts_burst[j];
				pkts_burst[j - 1]->pkt_len +=
					pkts_burst[j]->pkt_len;
				pkts_burst[j - 1]->nb_segs +=
					pkts_burst[j]->nb_segs;
				burst_nb++;
			} else {
				max_size = 0;
				burst_nb++;
				ret = rte_eth_tx_burst(dstportid,
					queue_id,
					&pkts_burst[j], 1);
				if (unlikely(ret < 1)) {
					rte_pktmbuf_free(pkts_burst[j]);
					for (i = j; i < (j + burst_nb); i++)
						sents[i] = 0;
				} else {
					nb_tx += burst_nb;
					for (i = j; i < (j + burst_nb); i++)
						sents[i] = 1;
				}
				burst_nb = 0;
			}
		}
	} else {
		tx_pkts = pkts_burst;
		sent = 0;
		re_send = 0;
tx_again:
		nb_tx = rte_eth_tx_burst(dstportid, queue_id,
				tx_pkts, expected_nb - sent);
		sent += nb_tx;
		if (sent < expected_nb && re_send < re_send_max) {
			tx_pkts = &pkts_burst[sent];
			re_send++;
			goto tx_again;
		}
		/* Free any unsent packets. */
		if (unlikely(nb_tx < expected_nb)) {
			rte_pktmbuf_free_bulk(&pkts_burst[nb_tx],
				expected_nb - nb_tx);
		}
		for (i = 0; i < nb_tx; i++)
			sents[i] = 1;
		for (i = nb_tx; i < expected_nb; i++)
			sents[i] = 0;
	}

	return nb_tx;
}

static uint16_t
port_fwd_handle_seg_rx(struct rte_mbuf **pkts_rx,
	struct rte_mbuf *pkts_single[], struct lcore_conf *qconf,
	uint16_t rx_portid, uint16_t nb_rx,
	int re_send_max)
{
	uint16_t i, single_nb = 0, j, nb_tx, nb_tx_expected;
	struct rte_mbuf *pkts_tx[MAX_PKT_BURST];
	struct rte_mbuf *curr, *tmp;
	int dstportid = port_fwd_dst_port(rx_portid);
	uint64_t bytes_overhead[MAX_PKT_BURST];
	uint64_t bytes_fcs[MAX_PKT_BURST];
	uint64_t bytes[MAX_PKT_BURST];
	uint8_t sent[MAX_PKT_BURST];

	for (i = 0; i < nb_rx; i++) {
		if (!pkts_rx[i]->next) {
			pkts_single[single_nb] = pkts_rx[i];
			single_nb++;
			continue;
		}
		curr = pkts_rx[i];
		j = 0;
		while (curr) {
			pkts_tx[j] = curr;
			pkts_tx[j]->pkt_len = pkts_tx[j]->data_len;
			pkts_tx[j]->nb_segs = 1;
			tmp = curr;
			curr = curr->next;
			tmp->next = NULL;

			bytes[j] = pkts_tx[j]->pkt_len;
			bytes_fcs[j] = PORT_FWD_MBUF_FCS(pkts_tx[j]);
			bytes_overhead[j] = PORT_FWD_MBUF_OVERHEAD(pkts_tx[j]);
			qconf->rx_statistic[rx_portid].bytes +=
					bytes[j];
			qconf->rx_statistic[rx_portid].bytes_fcs +=
					bytes_fcs[j];
			qconf->rx_statistic[rx_portid].bytes_overhead +=
					bytes_overhead[j];
			j++;
		}
		qconf->rx_statistic[rx_portid].packets += j;
		nb_tx_expected = j;
		if (unlikely(s_dump_mbuf)) {
			for (j = 0; j < nb_tx_expected; j++)
				dump_mbuf_data(pkts_tx[j], 1, dstportid,
					qconf);
		}
		if (dstportid < 0)
			continue;
		nb_tx = port_fwd_xmit_burst(pkts_tx, nb_tx_expected,
			rx_portid, dstportid, qconf->tx_queue_id[rx_portid],
			sent, re_send_max);
		for (j = 0; j < nb_tx_expected; j++) {
			if (!sent[j])
				continue;
			qconf->tx_statistic[dstportid].bytes +=
				bytes[j];
			qconf->tx_statistic[dstportid].bytes_fcs +=
				bytes_fcs[j];
			qconf->tx_statistic[dstportid].bytes_overhead +=
				bytes_overhead[j];
		}
		qconf->tx_statistic[dstportid].packets += nb_tx;
	}

	return single_nb;
}

static int
main_loop(__attribute__((unused)) void *dummy)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *tx_burst[MAX_PKT_BURST];
	struct rte_mbuf *tx_burst_dup[MAX_PKT_BURST];
	struct rte_mbuf **tx_pkts;
	unsigned int lcore_id;
	int i, nb_rx, j;
	uint16_t idx;
	uint16_t nb_tx, rx_left, re_send, sent;
	uint16_t portid, rx_burst;
	int dstportid;
	uint8_t queueid;
	struct lcore_conf *qconf;
	char *penv;
	uint64_t bytes_overhead[MAX_PKT_BURST];
	uint64_t bytes_fcs[MAX_PKT_BURST];
	uint64_t bytes[MAX_PKT_BURST];
	struct rte_ring *tx_ring, *rx_ring;
	uint8_t sents[MAX_PKT_BURST];
	int re_send_max = 0, fragment_tx = 0, reassemble_rx = 0;

	if (s_inject) {
		main_injection_test_loop();
		return 0;
	}
	lcore_id = rte_lcore_id();
	qconf = &s_lcore_conf[lcore_id];
	if (s_fragment_tx_port >= 0) {
		for (i = 0; i < qconf->n_rx_queue; i++) {
			portid = qconf->rx_queue_list[i].port_id;
			if (portid == s_fragment_tx_port) {
				fragment_tx = 1;
				break;
			}
		}
	}
	if (s_reassemble_rx_port >= 0) {
		for (i = 0; i < qconf->n_rx_queue; i++) {
			portid = qconf->rx_queue_list[i].port_id;
			if (portid == s_reassemble_rx_port) {
				reassemble_rx = 1;
				break;
			}
		}
	}
	if (fragment_tx && reassemble_rx) {
		RTE_LOG(ERR, port_fwd,
			"fragment and reassemble can't run on same core(%d)\n",
			lcore_id);
		return 0;
	}

	if (fragment_tx) {
		main_frag_tx_test_loop();
		return 0;
	}
	if (reassemble_rx) {
		main_reassemble_rx_loop();
		return 0;
	}

	penv = getenv("PORT_FWD_RX_BURST");
	if (penv && atoi(penv) > 0 && atoi(penv) <= MAX_PKT_BURST)
		rx_burst = atoi(penv);
	else
		rx_burst = MAX_PKT_BURST;

	penv = getenv("PORT_FWD_RE_SEND_MAX");
	if (penv) {
		re_send_max = atoi(penv);
		if (re_send_max < 0)
			re_send_max = 0;
	}

	if (qconf->n_rx_queue == 0) {
		RTE_LOG(INFO, port_fwd,
			"lcore %u has nothing to do\n", lcore_id);
		return 0;
	}

	RTE_LOG(INFO, port_fwd,
		"entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->n_rx_queue; i++) {
		portid = qconf->rx_queue_list[i].port_id;
		queueid = qconf->rx_queue_list[i].queue_id;
		RTE_LOG(INFO, port_fwd,
			" -- lcoreid=%u portid=%u rxqueueid=%hhu\n",
			lcore_id, portid, queueid);
	}

	while (!force_quit) {
		if (!s_ring_fwd)
			goto port_forwarding;

		for (i = 0; i < qconf->n_rx_queue; ++i) {
			portid = qconf->rx_queue_list[i].port_id;
			queueid = qconf->rx_queue_list[i].queue_id;

			nb_rx = rte_eth_rx_burst(portid, queueid, pkts_burst,
				rx_burst);
			for (j = 0; j < nb_rx; j++) {
				bytes[j] = pkts_burst[j]->pkt_len;
				bytes_fcs[j] =
					PORT_FWD_MBUF_FCS(pkts_burst[j]);
				bytes_overhead[j] =
					PORT_FWD_MBUF_OVERHEAD(pkts_burst[j]);
				qconf->rx_statistic[portid].bytes +=
					bytes[j];
				qconf->rx_statistic[portid].bytes_fcs +=
					bytes_fcs[j];
				qconf->rx_statistic[portid].bytes_overhead +=
					bytes_overhead[j];
			}
			qconf->rx_statistic[portid].packets += nb_rx;
			if (nb_rx > 0) {
				tx_ring = qconf->rx_queue_list[i].send_q;
				nb_tx = rte_ring_enqueue_burst(tx_ring,
						(void * const *)pkts_burst,
						nb_rx, NULL);
				for (idx = nb_tx; idx < nb_rx; idx++)
					rte_pktmbuf_free(pkts_burst[idx]);
			}

			rx_ring = qconf->rx_queue_list[i].recv_q;
			nb_rx = rte_ring_dequeue_burst(rx_ring,
				(void **)pkts_burst,
				rx_burst, NULL);
			if (nb_rx == 0)
				continue;

			tx_pkts = pkts_burst;
			sent = 0;
			re_send = 0;
ring_fwd_tx_again:
			nb_tx = rte_eth_tx_burst(portid,
					qconf->tx_queue_id[portid],
					tx_pkts, nb_rx - sent);
			for (j = sent; j < sent + nb_tx; j++) {
				qconf->tx_statistic[portid].bytes +=
					bytes[j];
				qconf->tx_statistic[portid].bytes_fcs +=
					bytes_fcs[j];
				qconf->tx_statistic[portid].bytes_overhead +=
					bytes_overhead[j];
			}
			sent += nb_tx;
			qconf->tx_statistic[portid].packets += nb_tx;
			if (sent < nb_rx && re_send < re_send_max) {
				tx_pkts = &pkts_burst[sent];
				re_send++;
				goto ring_fwd_tx_again;
			}

			/* Free any unsent packets. */
			if (unlikely(sent < nb_rx)) {
				for (idx = sent; idx < nb_rx; idx++)
					rte_pktmbuf_free(pkts_burst[idx]);
			}
		}
		continue;

port_forwarding:
		/* Read packet from RX queues
		 */
		for (i = 0; i < qconf->n_rx_queue; ++i) {
			portid = qconf->rx_queue_list[i].port_id;
			queueid = qconf->rx_queue_list[i].queue_id;

			dstportid = port_fwd_dst_port(portid);

			nb_rx = rte_eth_rx_burst(portid, queueid, pkts_burst,
				rx_burst);
			if (nb_rx == 0)
				continue;
			if (unlikely(s_mpool_select_by_size &&
				s_mpool_select_by_size_debug)) {
				for (j = 0; j < nb_rx; j++) {
					RTE_LOG(INFO, port_fwd,
						"RX from port%d/rxq%d/pool(%s), size=%d\r\n",
						portid, queueid, pkts_burst[j]->pool->name,
						pkts_burst[j]->pkt_len);
				}
			}

			rx_left = port_fwd_handle_seg_rx(pkts_burst,
				tx_burst, qconf, portid, nb_rx,
				re_send_max);

			for (j = 0; j < rx_left; j++) {
				bytes[j] = tx_burst[j]->pkt_len;
				bytes_fcs[j] =
					PORT_FWD_MBUF_FCS(tx_burst[j]);
				bytes_overhead[j] =
					PORT_FWD_MBUF_OVERHEAD(tx_burst[j]);
				qconf->rx_statistic[portid].bytes +=
					bytes[j];
				qconf->rx_statistic[portid].bytes_fcs +=
					bytes_fcs[j];
				qconf->rx_statistic[portid].bytes_overhead +=
					bytes_overhead[j];
				dump_mbuf_data(tx_burst[j], 0, portid,
					qconf);
			}
			qconf->rx_statistic[portid].packets += rx_left;

			if (dstportid < 0) {
				rte_pktmbuf_free_bulk(tx_burst, rx_left);
				continue;
			}

			tx_pkts = tx_burst;
			if (pktmbuf_pool_tx_only) {
				rx_left = port_fwd_dup_mbufs(dstportid,
					qconf->tx_queue_id[dstportid],
					tx_burst_dup, tx_burst, rx_left);
				if (!rx_left)
					continue;
				tx_pkts = tx_burst_dup;
			}

			nb_tx = port_fwd_xmit_burst(tx_pkts, rx_left,
				portid, dstportid,
				qconf->tx_queue_id[dstportid], sents,
				re_send_max);
			for (j = 0; j < rx_left; j++) {
				if (!sents[j])
					continue;
				qconf->tx_statistic[dstportid].bytes +=
					bytes[j];
				qconf->tx_statistic[dstportid].bytes_fcs +=
					bytes_fcs[j];
				qconf->tx_statistic[dstportid].bytes_overhead +=
					bytes_overhead[j];
			}
			qconf->tx_statistic[dstportid].packets += nb_tx;
		}
	}

	if (pktmbuf_pool_tx_only)
		port_fwd_drain_tx_cnf(qconf);

	if (qconf->dump_buf) {
		rte_free(qconf->dump_buf);
		qconf->dump_buf = NULL;
	}

	return 0;
}

static struct loop_mode port_fwd_demo = {
	.parse_fwd_dst = parse_port_fwd_dst,
	.main_loop = main_loop,
};

static int
check_lcore_params(void)
{
	int lcore;
	uint16_t i;

	for (i = 0; i < s_pqc_num; ++i) {
		lcore = s_pqc[i].lcore_id;
		if (lcore < 0)
			continue;
		if (!rte_lcore_is_enabled(lcore)) {
			RTE_LOG(ERR, port_fwd,
				"lcore %d is not enabled\n", lcore);
			return -EINVAL;
		}
	}
	return 0;
}

static int
check_port_config(void)
{
	uint16_t portid;
	uint16_t i;

	for (i = 0; i < s_pqc_num; ++i) {
		portid = s_pqc[i].port_id;
		if ((enabled_port_mask & (1 << portid)) == 0) {
			RTE_LOG(ERR, port_fwd,
				"port %u is not enabled in port mask\n",
				portid);
			return -EINVAL;
		}
		if (!rte_eth_dev_is_valid_port(portid)) {
			RTE_LOG(ERR, port_fwd,
				"port %u is not present on the board\n",
				portid);
			return -EINVAL;
		}
	}
	return 0;
}

static uint16_t
get_port_n_rx_queues(const uint16_t port,
	uint16_t queue[])
{
	uint16_t queue_num = 0, i, j;

	for (i = 0; i < s_pqc_num; ++i) {
		if (s_pqc[i].port_id == port) {
			queue[queue_num] = s_pqc[i].queue_id;
			for (j = 0; j < queue_num; j++) {
				if (queue[j] == s_pqc[i].queue_id) {
					rte_exit(EXIT_FAILURE,
						"duplicated rxq(%d) on port%d\n",
						queue[j], port);
					return 0;
				}
			}
			queue_num++;
		}
	}

	return queue_num;
}

static int
port_fwd_port_queue_mapping(uint16_t port_id, uint16_t queue_id,
	uint16_t *port_idx, uint16_t *queue_idx)
{
	int i, j;
	uint16_t pidx = 0, qidx = 0;

	if (port_id >= RTE_MAX_ETHPORTS) {
		RTE_LOG(ERR, port_fwd,
			"Too large port ID(%d) >= %d\n",
			port_id, RTE_MAX_ETHPORTS);
		return -EINVAL;
	}

	if (queue_id >= RTE_MAX_QUEUES) {
		RTE_LOG(ERR, port_fwd,
			"Too large queue ID(%d) >= %d\n",
			queue_id, RTE_MAX_QUEUES);
		return -EINVAL;
	}

	if (s_pq_map[port_id][queue_id]) {
		for (i = 0; i <= port_id; i++) {
			for (j = 0; j <= queue_id; j++) {
				if (s_pq_map[i][j]) {
					pidx++;
					break;
				}
			}
		}
		for (j = 0; j <= queue_id; j++) {
			if (s_pq_map[port_id][j])
				qidx++;
		}
		if (port_idx)
			*port_idx = pidx;
		if (queue_idx)
			*queue_idx = qidx;

		return 0;
	}

	return -EINVAL;
}

static int
init_lcore_rxq_ring(struct lcore_rx_queue *rx_queue)
{
	char send_name[64];
	char recv_name[64];
	struct rte_ring *send_q, *recv_q;
	int err;
	uint16_t port_idx, queue_idx;

	if (s_proc_type == proc_standalone_secondary)
		return -EINVAL;

	err = port_fwd_port_queue_mapping(rx_queue->port_id,
		rx_queue->queue_id, &port_idx, &queue_idx);
	if (err) {
		rte_exit(0, "port(%d)-queue(%d) mapping failed\n",
			rx_queue->port_id, rx_queue->queue_id);

		return err;
	}

	if (s_proc_type == proc_primary) {
		snprintf(send_name, sizeof(send_name), PRI_2_SEC,
			port_idx, queue_idx);
		send_q = rte_ring_create(send_name, 512, 0, 0);
		snprintf(recv_name, sizeof(recv_name), SEC_2_PRI,
			port_idx, queue_idx);
		recv_q = rte_ring_create(recv_name, 512, 0, 0);
		rx_queue->send_q = send_q;
		rx_queue->recv_q = recv_q;
		if (!send_q) {
			RTE_LOG(ERR, port_fwd,
				"send_q(%s) created failed\n",
				send_name);
			goto clear_proxy_q;
		}
		if (!recv_q) {
			RTE_LOG(ERR, port_fwd,
				"recv_q(%s) created failed\n",
				recv_name);
			goto clear_proxy_q;
		}
		RTE_LOG(INFO, port_fwd,
			"send_q(%s):%p, recv_q(%s):%p created\r\n",
			send_name, send_q, recv_name, recv_q);
	} else if (s_proc_type == proc_attach_secondary) {
		snprintf(recv_name, sizeof(recv_name), PRI_2_SEC,
			port_idx, queue_idx);
		recv_q = rte_ring_lookup(recv_name);
		snprintf(send_name, sizeof(send_name), SEC_2_PRI,
			port_idx, queue_idx);
		send_q = rte_ring_lookup(send_name);
		rx_queue->send_q = send_q;
		rx_queue->recv_q = recv_q;
		if (!send_q) {
			RTE_LOG(ERR, port_fwd,
				"send_q(%s) lookup failed\n",
				send_name);
			goto clear_proxy_q;
		}
		if (!recv_q) {
			RTE_LOG(ERR, port_fwd,
				"recv_q(%s) lookup failed\n",
				recv_name);
			goto clear_proxy_q;
		}
		RTE_LOG(INFO, port_fwd,
			"send_q(%s):%p, recv_q(%s):%p detected\r\n",
			send_name, send_q, recv_name, recv_q);
	}

	return 0;

clear_proxy_q:
	if (rx_queue->send_q)
		rte_ring_free(rx_queue->send_q);
	if (rx_queue->recv_q)
		rte_ring_free(rx_queue->recv_q);

	if (s_proc_type == proc_primary)
		rte_exit(0, "port(%d)queue(%d) ring create failed\n",
			port_idx, queue_idx);
	else
		rte_exit(0, "port(%d)queue(%d) ring lookup failed\n",
			port_idx, queue_idx);
	return -EINVAL;
}

static int
init_lcore_rx_queues(void)
{
	uint16_t i, nb_rx_queue;
	uint8_t lcore;

	for (i = 0; i < s_pqc_num; ++i) {
		if (s_pqc[i].lcore_id < 0) {
			/**Don't handle this queue by core.*/
			continue;
		}
		lcore = s_pqc[i].lcore_id;
		nb_rx_queue = s_lcore_conf[lcore].n_rx_queue;
		if (nb_rx_queue >= MAX_RX_QUEUE_PER_LCORE) {
			RTE_LOG(ERR, port_fwd,
				"too many queues (%u) for lcore: %u\n",
				nb_rx_queue + 1, lcore);
			return -EINVAL;
		}

		s_lcore_conf[lcore].rx_queue_list[nb_rx_queue].port_id =
				s_pqc[i].port_id;
		s_lcore_conf[lcore].rx_queue_list[nb_rx_queue].queue_id =
				s_pqc[i].queue_id;
		s_lcore_conf[lcore].n_rx_queue++;
	}

	return 0;
}

static int
parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -EINVAL;

	if (pm == 0)
		return -EINVAL;

	return pm;
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
	int int_fld[_NUM_FLD];
	char *str_fld[_NUM_FLD];
	int i, num;
	unsigned int size;
	struct port_queue_lcore_param *param;

	s_pqc_num = 0;

	for (i = 0; i < MAX_LCORE_PARAMS; i++) {
		s_pqc[i].port_id = -1;
		s_pqc[i].queue_id = -1;
		s_pqc[i].lcore_id = -1;
	}
	param = s_pqc;

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
		if (s_pqc_num >= MAX_LCORE_PARAMS) {
			RTE_LOG(ERR, port_fwd,
				"exceeded max number port/queue/core params: %hu\n",
				s_pqc_num);
			return -EINVAL;
		}
		if (num > FLD_PORT)
			param->port_id = int_fld[FLD_PORT];
		if (num > FLD_QUEUE)
			param->queue_id = int_fld[FLD_QUEUE];
		if (num > FLD_LCORE)
			param->lcore_id = int_fld[FLD_LCORE];
		if (param->port_id >= 0 && param->queue_id >= 0)
			s_pq_map[param->port_id][param->queue_id] = 1;

		s_pqc_num++;
		param++;
		p = strchr(p0, '(');
	}

	return 0;
}

#define MEMPOOL_CACHE_SIZE 256

static const char short_options[] =
	"p:"  /* portmask */
	"b:"  /* burst size */
	;

#define CMD_LINE_OPT_CONFIG "config"
#define CMD_LINE_OPT_DIRECT_RSP_CONFIG "direct-rsp"
#define CMD_LINE_OPT_DIRECT_REMOTE_CONFIG "direct-remote"
#define CMD_LINE_OPT_DIRECT_DEF_CONFIG "direct-def"

#define CMD_LINE_OPT_PER_PORT_POOL "enable-per-port-pool"
#define CMD_LINE_OPT_TX_ONLY "tx-only"
#define CMD_LINE_OPT_TX_ONLY_SEG "tx-only-seg"
#define CMD_LINE_OPT_TX_ONLY_BUF_TYPE "tx-only-buf"

#define CMD_LINE_OPT_TX_FRAG_PORT "tx-frag-port"
#define CMD_LINE_OPT_RX_REASSEMBLE_PORT "rx-reassemble-port"

enum {
	/* long options mapped to a short option */

	/* first long only option value must be >= 256, so that we won't
	 * conflict with short options
	 */
	CMD_LINE_OPT_MIN_NUM = 256,
	CMD_LINE_OPT_CONFIG_NUM,
	CMD_LINE_OPT_DIRECT_RSP_CONFIG_NUM,
	CMD_LINE_OPT_DIRECT_REMOTE_CONFIG_NUM,
	CMD_LINE_OPT_DIRECT_DEF_CONFIG_NUM,
	CMD_LINE_OPT_TX_ONLY_NUM,
	CMD_LINE_OPT_TX_FRAG_PORT_NUM,
	CMD_LINE_OPT_TX_ONLY_SEG_NUM,
	CMD_LINE_OPT_TX_ONLY_BUF_TYPE_NUM,
	CMD_LINE_OPT_RX_REASSEMBLE_PORT_NUM,
	CMD_LINE_OPT_PER_PORT_POOL_NUM
};

static const struct option lgopts[] = {
	{CMD_LINE_OPT_CONFIG, 1, 0,
		CMD_LINE_OPT_CONFIG_NUM},
	{CMD_LINE_OPT_DIRECT_RSP_CONFIG, 0, 0,
		CMD_LINE_OPT_DIRECT_RSP_CONFIG_NUM},
	{CMD_LINE_OPT_DIRECT_REMOTE_CONFIG, 1, 0,
		CMD_LINE_OPT_DIRECT_REMOTE_CONFIG_NUM},
	{CMD_LINE_OPT_DIRECT_DEF_CONFIG, 1, 0,
		CMD_LINE_OPT_DIRECT_DEF_CONFIG_NUM},
	{CMD_LINE_OPT_TX_ONLY_BUF_TYPE, 1, 0,
		CMD_LINE_OPT_TX_ONLY_BUF_TYPE_NUM},
	{CMD_LINE_OPT_TX_ONLY_SEG, 1, 0,
		CMD_LINE_OPT_TX_ONLY_SEG_NUM},
	{CMD_LINE_OPT_TX_ONLY, 0, 0,
		CMD_LINE_OPT_TX_ONLY_NUM},
	{CMD_LINE_OPT_TX_FRAG_PORT, 1, 0,
		CMD_LINE_OPT_TX_FRAG_PORT_NUM},
	{CMD_LINE_OPT_RX_REASSEMBLE_PORT, 1, 0,
		CMD_LINE_OPT_RX_REASSEMBLE_PORT_NUM},
	{CMD_LINE_OPT_PER_PORT_POOL, 0, 0,
		CMD_LINE_OPT_PER_PORT_POOL_NUM},
	{NULL, 0, 0, 0}
};

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
	while ((opt = getopt_long(argc, argvopt, short_options,
				lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* portmask */
		case 'p':
			enabled_port_mask = parse_portmask(optarg);
			if (enabled_port_mask == 0) {
				RTE_LOG(ERR, port_fwd, "Invalid portmask\n");
				return -EINVAL;
			}
			break;

		/* max_burst_size */
		case 'b':
			burst_size = (unsigned int)atoi(optarg);
			if (burst_size > max_pkt_burst) {
				RTE_LOG(ERR, port_fwd,
					"invalid burst size(%d) > %d\n",
					burst_size, max_pkt_burst);
				return -EINVAL;
			}
			max_pkt_burst = burst_size;
			max_rx_burst = max_pkt_burst;
			max_tx_burst = max_rx_burst / 2;
			break;

		/* long options */
		case CMD_LINE_OPT_CONFIG_NUM:
			ret = parse_config(optarg);
			if (ret) {
				RTE_LOG(ERR, port_fwd, "Invalid config\n");
				return ret;
			}
			break;
		case CMD_LINE_OPT_DIRECT_RSP_CONFIG_NUM:
			s_remote_dir |= RTE_REMOTE_DIR_RSP;
			break;
		case CMD_LINE_OPT_DIRECT_REMOTE_CONFIG_NUM:
			ret = rte_remote_direct_parse_config(optarg, 1);
			if (ret) {
				RTE_LOG(ERR, port_fwd,
					"Invalid direct config\n");
				return ret;
			}
			s_remote_dir |= RTE_REMOTE_DIR_REQ;
			break;
		case CMD_LINE_OPT_DIRECT_DEF_CONFIG_NUM:
			ret = rte_remote_direct_parse_config(optarg, 0);
			if (ret) {
				RTE_LOG(ERR, port_fwd,
					"Invalid default direct config\n");
				return ret;
			}
			break;
		case CMD_LINE_OPT_TX_ONLY_BUF_TYPE_NUM:
			if (!strcmp(optarg, "native") ||
				!strcmp(optarg, "platform"))
				s_port_fwd_tx_buf_type = PORT_FWD_TX_BUF_PLATFORM;
			else if (!strcmp(optarg, "default"))
				s_port_fwd_tx_buf_type = PORT_FWD_TX_BUF_DEFAULT;
			else if (!strcmp(optarg, "ext"))
				s_port_fwd_tx_buf_type = PORT_FWD_TX_BUF_EXT;
			else
				return -EINVAL;
			break;
		case CMD_LINE_OPT_TX_ONLY_NUM:
			s_inject = true;
			break;
		case CMD_LINE_OPT_TX_FRAG_PORT_NUM:
			s_fragment_tx_port = atoi(optarg);
			break;
		case CMD_LINE_OPT_RX_REASSEMBLE_PORT_NUM:
			s_reassemble_rx_port = atoi(optarg);
			break;
		case CMD_LINE_OPT_TX_ONLY_SEG_NUM:
			s_tx_seg = atoi(optarg);
			break;
		case CMD_LINE_OPT_PER_PORT_POOL_NUM:
			s_per_port_pool = 1;
			break;

		default:
			return -EINVAL;
		}
	}

	if (optind >= 0)
		argv[optind - 1] = prgname;

	ret = optind - 1;
	optind = 1; /* reset getopt lib */
	return ret;
}

static void
port_fwd_mp_max_min_addr(struct rte_mempool *mp)
{
	uint32_t num = mp->size, i, alloced = 0, bulk_size;
	int ret;
	struct rte_mbuf **mbuf_arry =
		malloc(sizeof(struct rte_mbuf *) * num);

	if (!mbuf_arry)
		return;

	while (num) {
		bulk_size = num > RTE_MEMPOOL_CACHE_MAX_SIZE ?
			RTE_MEMPOOL_CACHE_MAX_SIZE : num;
		ret = rte_pktmbuf_alloc_bulk(mp,
			&mbuf_arry[alloced], bulk_size);
		if (ret) {
			RTE_LOG(ERR, port_fwd,
				"Drain %d bufs from %s failed\r\n",
				num, mp->name);
			if (alloced)
				rte_pktmbuf_free_bulk(mbuf_arry, alloced);
			free(mbuf_arry);
			return;
		}
		alloced += bulk_size;
		num -= bulk_size;
	}

	for (i = 0; i < mp->size; i++) {
		if (mbuf_arry[i]->buf_iova > max_mbuf_addr)
			max_mbuf_addr = mbuf_arry[i]->buf_iova;
		if (mbuf_arry[i]->buf_iova < min_mbuf_addr)
			min_mbuf_addr = mbuf_arry[i]->buf_iova;
	}
	rte_pktmbuf_free_bulk(mbuf_arry, mp->size);
	free(mbuf_arry);
}

static int
init_mem(unsigned int nb_mbuf, uint16_t buf_size, uint16_t nb_ports)
{
	char s[64];
	char s_tx[64];
	char s_2nd[64];
	int i, max_pool_size;
	struct rte_mempool *pktmbuf_pool;

	snprintf(s, sizeof(s), "port_fwd_mbuf_pool");
	snprintf(s_tx, sizeof(s_tx), "port_fwd_mbuf_tx_pool");
	snprintf(s_2nd, sizeof(s_2nd), "port_fwd_2nd_mbuf_pool");

	if (s_proc_type == proc_attach_secondary) {
		pktmbuf_pool = rte_mempool_lookup(s_2nd);
		if (!pktmbuf_pool) {
			pktmbuf_pool = rte_mempool_lookup(s);
			if (!pktmbuf_pool) {
				rte_exit(EXIT_FAILURE, "Lookup mbuf pool(%s) failed\n",
					s);
			}
		}
		RTE_LOG(INFO, port_fwd,
			"mbuf pool(%s)(count=%d) lookup success\n",
			pktmbuf_pool->name, pktmbuf_pool->size);
	} else if (s_proc_type == proc_standalone_secondary) {
		pktmbuf_pool = rte_pktmbuf_pool_create_by_ops(s_2nd,
				nb_mbuf,
				MEMPOOL_CACHE_SIZE, 0,
				buf_size, 0,
				RTE_MBUF_DEFAULT_MEMPOOL_OPS);
		if (pktmbuf_pool) {
			RTE_LOG(INFO, port_fwd,
				"mbuf pool(%s)(count=%d) created\n",
				s_2nd, nb_mbuf);
		}
	} else {
		if (s_mpool_select_by_size) {
			for (i = 0; i < RTE_ETH_DPAA_RX_MAX_MPOOLS; i++) {
				max_pool_size =
					buf_size / RTE_ETH_DPAA_RX_MAX_MPOOLS * (i + 1);
				snprintf(s, sizeof(s),
					"port_fwd_mbuf_pool_%d", max_pool_size);
				pktmbuf_pools[i] = rte_pktmbuf_pool_create(s,
					nb_mbuf / RTE_ETH_DPAA_RX_MAX_MPOOLS,
					MEMPOOL_CACHE_SIZE, 0, max_pool_size, 0);
				if (pktmbuf_pools[i]) {
					RTE_LOG(INFO, port_fwd,
						"mbuf pool(%s) created\n", s);
				} else {
					rte_exit(EXIT_FAILURE,
						"Cannot init mbuf pool(%s)\n", s);
				}
			}
			pktmbuf_pool = pktmbuf_pools[RTE_ETH_DPAA_RX_MAX_MPOOLS - 1];
		} else if (s_per_port_pool) {
			for (i = 0; i < nb_ports; i++) {
				snprintf(s, sizeof(s),
					"port_fwd_mbuf_pool_port%d", i);
				if (s_default_pool[i]) {
					pktmbuf_per_port_pool[i] = rte_pktmbuf_pool_create_by_ops(s,
						nb_mbuf, MEMPOOL_CACHE_SIZE, 0, buf_size, 0,
						RTE_MBUF_DEFAULT_MEMPOOL_OPS);
				} else {
					pktmbuf_per_port_pool[i] = rte_pktmbuf_pool_create(s,
						nb_mbuf, MEMPOOL_CACHE_SIZE, 0, buf_size, 0);
				}
				if (pktmbuf_per_port_pool[i]) {
					RTE_LOG(INFO, port_fwd,
						"mbuf pool(%s)(count=%d) created\n",
						s, nb_mbuf);
				}
			}
			pktmbuf_pool = pktmbuf_per_port_pool[0];
		} else {
			pktmbuf_pool = rte_pktmbuf_pool_create(s,
				nb_mbuf, MEMPOOL_CACHE_SIZE, 0, buf_size, 0);
			if (pktmbuf_pool) {
				RTE_LOG(INFO, port_fwd,
					"mbuf pool(%s)(count=%d) created\n",
					s, nb_mbuf);
			}
		}
	}

	if (s_inject || s_fragment_tx_port >= 0) {
		if (s_port_fwd_tx_buf_type == PORT_FWD_TX_BUF_PLATFORM) {
			pktmbuf_pool_tx_only = NULL;
		} else if (s_port_fwd_tx_buf_type == PORT_FWD_TX_BUF_DEFAULT) {
			pktmbuf_pool_tx_only = rte_pktmbuf_pool_create_by_ops(s_tx,
				nb_mbuf, MEMPOOL_CACHE_SIZE, 0, buf_size, 0,
				RTE_MBUF_DEFAULT_MEMPOOL_OPS);
		} else if (s_port_fwd_tx_buf_type == PORT_FWD_TX_BUF_EXT) {
			pktmbuf_pool_tx_only = port_fwd_create_ext_pool(s_tx,
				nb_mbuf, buf_size, MEMPOOL_CACHE_SIZE);
		}
	}

	if (!s_per_port_pool) {
		for (i = 0; i < nb_ports; i++)
			pktmbuf_per_port_pool[i] = pktmbuf_pool;
	}

	if (!pktmbuf_pool)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool(%s)\n", s);

	port_fwd_mp_max_min_addr(pktmbuf_pool);
	if (pktmbuf_pool_tx_only)
		port_fwd_mp_max_min_addr(pktmbuf_pool_tx_only);

	return 0;
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		RTE_LOG(INFO, port_fwd,
			"\n\nSignal %d received, preparing to exit...\n",
			signum);
		force_quit = true;
	}
}

static int
parse_dst_port(uint16_t portid)
{
	if (port_fwd_demo.parse_fwd_dst(portid))
		return 1;

	return 0;
}

#define PKTGEN_STATISTICS_INTERVAL 5

#define G_BITS_SIZE ((double)(1000 * 1000 * 1000))

#include <unistd.h>

static inline void
port_fwd_dump_port_status(struct rte_eth_stats *stats)
{
	RTE_LOG(INFO, port_fwd,
		"Output: %ld bytes, %ld packets, %ld error\n",
		(unsigned long)stats->obytes,
		(unsigned long)stats->opackets,
		(unsigned long)stats->oerrors);
	RTE_LOG(INFO, port_fwd,
		"Input: %ld bytes, %ld packets, %ld missed, %ld error\n",
		(unsigned long)stats->ibytes,
		(unsigned long)stats->ipackets,
		(unsigned long)stats->imissed,
		(unsigned long)stats->ierrors);
}

static void *perf_statistics(void *arg)
{
	cpu_set_t cpuset;
	unsigned int lcore_id, port_id;
	int port_num, ret;
	struct lcore_conf *qconf;
	struct lcore_statistic *rxs, *txs;
	uint64_t rx_pkts[RTE_MAX_ETHPORTS];
	uint64_t tx_pkts[RTE_MAX_ETHPORTS];
	uint64_t rx_bytes_fcs[RTE_MAX_ETHPORTS];
	uint64_t tx_bytes_fcs[RTE_MAX_ETHPORTS];
	uint64_t rx_bytes_oh[RTE_MAX_ETHPORTS];
	uint64_t tx_bytes_oh[RTE_MAX_ETHPORTS];
	uint64_t rx_bytes_oh_old[RTE_MAX_ETHPORTS];
	uint64_t tx_bytes_oh_old[RTE_MAX_ETHPORTS];
	uint64_t tx_jumbo_count[RTE_MAX_ETHPORTS];
	uint64_t tx_jumbo_bytes[RTE_MAX_ETHPORTS];
	uint64_t rx_reassemble_count[RTE_MAX_ETHPORTS];
	uint64_t rx_reassemble_bytes[RTE_MAX_ETHPORTS];
	uint32_t hw_count, available_count;

	memset(rx_bytes_oh_old, 0, RTE_MAX_ETHPORTS * sizeof(uint64_t));
	memset(tx_bytes_oh_old, 0, RTE_MAX_ETHPORTS * sizeof(uint64_t));

	CPU_SET(0, &cpuset);
	ret = pthread_setaffinity_np(pthread_self(),
			sizeof(cpu_set_t), &cpuset);
	RTE_LOG(INFO, port_fwd,
		"affinity statistics thread to cpu 0 %s\r\n",
		ret ? "failed" : "success");

loop:
	if (force_quit)
		return arg;

	sleep(PKTGEN_STATISTICS_INTERVAL);
	memset(rx_pkts, 0, RTE_MAX_ETHPORTS * sizeof(uint64_t));
	memset(tx_pkts, 0, RTE_MAX_ETHPORTS * sizeof(uint64_t));
	memset(rx_bytes_fcs, 0, RTE_MAX_ETHPORTS * sizeof(uint64_t));
	memset(tx_bytes_fcs, 0, RTE_MAX_ETHPORTS * sizeof(uint64_t));
	memset(rx_bytes_oh, 0, RTE_MAX_ETHPORTS * sizeof(uint64_t));
	memset(tx_bytes_oh, 0, RTE_MAX_ETHPORTS * sizeof(uint64_t));
	memset(tx_jumbo_count, 0, RTE_MAX_ETHPORTS * sizeof(uint64_t));
	memset(tx_jumbo_bytes, 0, RTE_MAX_ETHPORTS * sizeof(uint64_t));
	memset(rx_reassemble_count, 0, RTE_MAX_ETHPORTS * sizeof(uint64_t));
	memset(rx_reassemble_bytes, 0, RTE_MAX_ETHPORTS * sizeof(uint64_t));

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		qconf = &s_lcore_conf[lcore_id];
		port_num = enabled_port_num;
		for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
			rxs = &qconf->rx_statistic[port_id];
			txs = &qconf->tx_statistic[port_id];
			if (enabled_port_mask & (1 << port_id) &&
				port_num > 0) {
				rx_pkts[port_id] += rxs->packets;
				tx_pkts[port_id] += txs->packets;
				rx_bytes_fcs[port_id] += rxs->bytes_fcs;
				tx_bytes_fcs[port_id] += txs->bytes_fcs;
				rx_bytes_oh[port_id] +=	rxs->bytes_overhead;
				tx_bytes_oh[port_id] +=	txs->bytes_overhead;
				tx_jumbo_count[port_id] += qconf->tx_jumbo_count[port_id];
				tx_jumbo_bytes[port_id] += qconf->tx_jumbo_bytes[port_id];
				rx_reassemble_count[port_id] += qconf->rx_reassemble_count[port_id];
				rx_reassemble_bytes[port_id] += qconf->rx_reassemble_bytes[port_id];
				port_num--;
			}
		}
	}

	port_num = enabled_port_num;
	port_id = 0;
	while (port_num > 0) {
		if (enabled_port_mask & (1 << port_id)) {
			struct rte_eth_stats stats;
			int get_st_ret;

			RTE_LOG(INFO, port_fwd, "PORT%d:\r\n", port_id);
			get_st_ret = rte_eth_stats_get(port_id, &stats);
			if (get_st_ret)
				goto skip_print_hw_status;

			port_fwd_dump_port_status(&stats);

skip_print_hw_status:
			hw_count = rte_mempool_ops_get_count(pktmbuf_per_port_pool[port_id]);
			available_count = rte_mempool_avail_count(pktmbuf_per_port_pool[port_id]);
			RTE_LOG(INFO, port_fwd,
				"Mem pool(%s): %d packets in HW, %d packets available\r\n",
				pktmbuf_per_port_pool[port_id]->name, hw_count,
				available_count);

			if (tx_jumbo_count[port_id]) {
				RTE_LOG(INFO, port_fwd,
					"TX jumbo: %ld pkts, %ld bytes\r\n",
					(unsigned long)tx_jumbo_count[port_id],
					(unsigned long)tx_jumbo_bytes[port_id]);
			}
			if (rx_reassemble_count[port_id]) {
				RTE_LOG(INFO, port_fwd,
					"RX reassemble: %ld pkts, %ld bytes\r\n",
					(unsigned long)rx_reassemble_count[port_id],
					(unsigned long)rx_reassemble_bytes[port_id]);
			}
			RTE_LOG(INFO, port_fwd,
				"TX: %lld pkts, %lld bits, %fGbps\r\n",
				(unsigned long long)tx_pkts[port_id],
				(unsigned long long)tx_bytes_fcs[port_id] * 8,
				(double)(tx_bytes_oh[port_id] -
				tx_bytes_oh_old[port_id]) * 8 /
				(PKTGEN_STATISTICS_INTERVAL * G_BITS_SIZE));
			RTE_LOG(INFO, port_fwd,
				"RX: %lld pkts, %lld bits, %fGbps\r\n\r\n",
				(unsigned long long)rx_pkts[port_id],
				(unsigned long long)rx_bytes_fcs[port_id] * 8,
				(double)(rx_bytes_oh[port_id] -
				rx_bytes_oh_old[port_id]) * 8 /
				(PKTGEN_STATISTICS_INTERVAL * G_BITS_SIZE));
			tx_bytes_oh_old[port_id] = tx_bytes_oh[port_id];
			rx_bytes_oh_old[port_id] = rx_bytes_oh[port_id];
			port_num--;
		}
		port_id++;
	}

	goto loop;

	return arg;
}

#define CHECK_INTERVAL 1 /* 1s */

static void *
port_fwd_check_link_stat(void *arg)
{
	uint16_t portid;
	struct rte_eth_link link[32], link_get;
	int ret;

	memset(link, 0, sizeof(link));

loop:
	if (force_quit)
		goto quit;

	RTE_ETH_FOREACH_DEV(portid) {
		if (force_quit)
			goto quit;
		if (!(enabled_port_mask & (1 << portid)))
			continue;
		ret = rte_eth_link_get_nowait(portid, &link_get);
		if (ret < 0) {
			RTE_LOG(WARNING, port_fwd,
				"Port %u link get failed: %s\n",
				portid, rte_strerror(-ret));
			continue;
		}
		if (memcmp(&link_get, &link[portid],
			sizeof(struct rte_eth_link))) {
			if (link_get.link_status) {
				RTE_LOG(INFO, port_fwd,
					"Port%d Link Up. Speed %u Mbps -%s\n",
					portid, link_get.link_speed,
					(link_get.link_duplex ==
					RTE_ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") :
					("half-duplex"));
			} else {
				RTE_LOG(WARNING, port_fwd,
					"Port %d Link Down\n", portid);
			}
		}
		rte_memcpy(&link[portid], &link_get,
			sizeof(struct rte_eth_link));
	}

	sleep(CHECK_INTERVAL);
	goto loop;

quit:

	return arg;
}

int
main(int argc, char **argv)
{
	struct lcore_conf *qconf;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf *txconf;
	int ret;
	uint32_t nb_ports;
	uint16_t queueid, portid;
	uint32_t lcore_id;
	uint32_t nb_lcores;
	uint8_t queue;
	struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];
	uint16_t nb_rx_queue[RTE_MAX_ETHPORTS];
	uint16_t nb_tx_queue[RTE_MAX_ETHPORTS];
	uint32_t socketid[RTE_MAX_ETHPORTS][MAX_LCORE_PARAMS];
	uint16_t rx_queues[RTE_MAX_ETHPORTS][MAX_LCORE_PARAMS];
	uint16_t tx_queues[RTE_MAX_ETHPORTS][MAX_LCORE_PARAMS];
	uint32_t total_tx_queues = 0, total_rx_queues = 0;
	uint32_t nb_mbuf;
	struct rte_eth_conf local_port_conf[RTE_MAX_ETHPORTS];
	uint16_t data_room_size = RTE_MBUF_DEFAULT_DATAROOM;
	char *penv;
	struct lcore_rx_queue *rx_queue;
	pthread_t pid;

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
	argc -= ret;
	argv += ret;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* parse application arguments (after the EAL ones) */
	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Port fwd invalid parameters\n");

	if (check_lcore_params() < 0)
		rte_exit(EXIT_FAILURE, "check_lcore_params failed\n");

	if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
		penv = getenv("PORT_FWD_SECONDARY_STANDALONE");
		if (penv)
			s_proc_type = proc_standalone_secondary;
		else
			s_proc_type = proc_attach_secondary;
	}

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		ret = rte_pdump_init();
		if (ret) {
			rte_exit(EXIT_FAILURE, "Failed to init pdump(%d)\n",
				ret);
		}
	}

	penv = getenv("PORT_FWD_RING_FWD");
	if (penv)
		s_ring_fwd = 1;

	penv = getenv("PORT_FWD_DUMP_MBUF");
	if (penv)
		s_dump_mbuf = atoi(penv);

	penv = getenv("PORT_FWD_INJECTION_TEST");
	if (penv)
		s_inject = atoi(penv);
	if (s_inject) {
		penv = getenv("PORT_FWD_INJECTION_PKT_SIZE");
		if (penv) {
			s_inject_pkt_size = atoi(penv);
			if (s_inject_pkt_size < 64 ||
				s_inject_pkt_size > 1518)
				s_inject_pkt_size = 64;
		}
	}
	if (s_fragment_tx_port >= 0)
		s_inject_pkt_size = s_jumbo_size;

	penv = getenv("PORT_FWD_DPAA1_POOL_SELECT_BY_SIZE");
	if (penv)
		s_mpool_select_by_size = atoi(penv);
	if (s_mpool_select_by_size) {
		s_mpool_select_by_size_debug = 1;
		penv = getenv("PORT_FWD_DPAA1_POOL_SELECT_BY_SIZE_DBG");
		if (penv)
			s_mpool_select_by_size_debug = atoi(penv);
	}

	ret = init_lcore_rx_queues();
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "init_lcore_rx_queues failed\n");

	nb_ports = rte_eth_dev_count_avail();

	if (check_port_config() < 0)
		rte_exit(EXIT_FAILURE, "check_port_config failed\n");

	nb_lcores = rte_lcore_count();

	if (s_fragment_tx_port >= 0)
		data_room_size = s_jumbo_size + 100;

	penv = getenv("PORT_FWD_DATA_ROOM_SIZE");
	if (penv) {
		data_room_size = atoi(penv);
		if (data_room_size < RTE_MBUF_DEFAULT_DATAROOM)
			data_room_size = RTE_MBUF_DEFAULT_DATAROOM;
		else
			data_room_size = RTE_ALIGN(data_room_size, 1024);
	}
	port_conf.rxmode.max_lro_pkt_size = data_room_size;

	RTE_ETH_FOREACH_DEV(portid) {
		char env_name[64];

		if ((enabled_port_mask & (1 << portid)) == 0)
			continue;

		sprintf(env_name, "PORT%d_DEFAULT_MEM_POOL", portid);
		penv = getenv(env_name);
		if (penv)
			s_default_pool[portid] = atoi(penv);

		nb_rx_queue[portid] = get_port_n_rx_queues(portid,
			rx_queues[portid]);
		nb_tx_queue[portid] = nb_rx_queue[portid];
		rte_memcpy(tx_queues[portid], rx_queues[portid],
			nb_tx_queue[portid] * sizeof(uint16_t));
		total_rx_queues += nb_rx_queue[portid];
		total_tx_queues += nb_tx_queue[portid];
	}

	nb_mbuf = total_rx_queues * nb_rxd + total_tx_queues * nb_txd;
	nb_mbuf = nb_ports * nb_mbuf;
	nb_mbuf += nb_ports * nb_lcores * MAX_PKT_BURST +
		nb_lcores * MEMPOOL_CACHE_SIZE;
	nb_mbuf = nb_mbuf > 2048 ? nb_mbuf : 2048;
	s_data_room_size = data_room_size;
	ret = init_mem(nb_mbuf, data_room_size + RTE_PKTMBUF_HEADROOM, nb_ports);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			"global mem pool(count=%d) init failed\n",
			nb_mbuf);

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		qconf = &s_lcore_conf[lcore_id];
		/* init RX queues */
		for (queue = 0; queue < qconf->n_rx_queue; ++queue) {
			portid = qconf->rx_queue_list[queue].port_id;
			queueid = qconf->rx_queue_list[queue].queue_id;

			socketid[portid][queueid] =
				rte_lcore_to_socket_id(lcore_id);

			RTE_LOG(INFO, port_fwd,
				"rxq/txq=%d,%d,%d\r\n",
				portid, queueid, socketid[portid][queueid]);

			qconf->tx_queue_id[portid] = queueid;

			qconf->tx_port_id[qconf->n_tx_port] = portid;
			qconf->n_tx_port++;
		}
	}

	/* initialize all ports */
	RTE_ETH_FOREACH_DEV(portid) {
		char env_name[64];
		struct rte_eth_rxconf rxq_conf;
		uint16_t q_nb;

		memcpy(&local_port_conf[portid], &port_conf,
			sizeof(struct rte_eth_conf));
		sprintf(env_name, "PORT_FWD_PORT%d_LPBK", portid);
		penv = getenv(env_name);
		if (penv)
			local_port_conf[portid].lpbk_mode = atoi(penv);
		else
			local_port_conf[portid].lpbk_mode = 0;

		/* skip ports that are not enabled */
		if ((enabled_port_mask & (1 << portid)) == 0) {
			RTE_LOG(INFO, port_fwd,
				"\nSkipping disabled port %d\n", portid);
			continue;
		}
		enabled_port_num++;

		/* init port */
		ret = rte_eth_dev_info_get(portid, &dev_info);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				"Error during getting device (port %u) info: %s\n",
				portid, strerror(-ret));
		/* Enable Receive side SCATTER, if supported by NIC,
		 * when jumbo packet is enabled.
		 */
		if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_SCATTER)
			local_port_conf[portid].rxmode.offloads |=
				RTE_ETH_RX_OFFLOAD_SCATTER;

		if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf[portid].txmode.offloads |=
				RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

		local_port_conf[portid].rx_adv_conf.rss_conf.rss_hf &=
			dev_info.flow_type_rss_offloads;

		ret = rte_eth_dev_configure(portid, nb_rx_queue[portid],
				nb_tx_queue[portid], &local_port_conf[portid]);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				"Cannot configure device: err=%d, port=%d\n",
				ret, portid);

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd,
				&nb_txd);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				"Err(%d) adjust number of descriptors on port%d\n",
				ret, portid);
		}

		ret = rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				"Err(%d) get MAC address of port%d\n",
				ret, portid);
		}
		ret = rte_eth_dev_info_get(portid, &dev_info);
		if (ret != 0) {
			rte_exit(EXIT_FAILURE,
				"Error during getting device (port %u) info: %s\n",
				portid, strerror(-ret));
		}
		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = port_conf.rxmode.offloads;
		rxq_conf.reserved_64s[0] = min_mbuf_addr;
		rxq_conf.reserved_64s[1] = max_mbuf_addr;
		for (q_nb = 0; q_nb < nb_rx_queue[portid]; q_nb++) {
			if (s_mpool_select_by_size) {
				ret = rte_dpaa_eth_rx_queue_mp_setup(portid,
					rx_queues[portid][q_nb],
					nb_rxd, &rxq_conf,
					pktmbuf_pools, RTE_ETH_DPAA_RX_MAX_MPOOLS);
				if (ret) {
					ret = rte_eth_rx_queue_setup(portid,
						rx_queues[portid][q_nb],
						nb_rxd, socketid[portid][q_nb],
						&rxq_conf, pktmbuf_per_port_pool[portid]);
				}
			} else {
				ret = rte_eth_rx_queue_setup(portid,
					rx_queues[portid][q_nb],
					nb_rxd, socketid[portid][q_nb],
					&rxq_conf, pktmbuf_per_port_pool[portid]);
			}
			if (ret < 0) {
				rte_exit(EXIT_FAILURE,
					"port%d rxq%d setup failed(%d)\n",
					portid, rx_queues[portid][q_nb], ret);
			}
		}
		txconf = &dev_info.default_txconf;
		txconf->offloads =
				local_port_conf[portid].txmode.offloads;
		for (q_nb = 0; q_nb < nb_tx_queue[portid]; q_nb++) {
			ret = rte_eth_tx_queue_setup(portid,
				tx_queues[portid][q_nb], nb_txd,
					socketid[portid][q_nb],
					txconf);
			if (ret < 0) {
				rte_exit(EXIT_FAILURE,
					"port%d rxq%d setup failed(%d)\n",
					portid, rx_queues[portid][q_nb], ret);
			}
		}
	}

	/* start ports */
	RTE_ETH_FOREACH_DEV(portid) {
		if ((enabled_port_mask & (1 << portid)) == 0)
			continue;
		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				"rte_eth_dev_start: err=%d, port=%d\n",
				ret, portid);

		ret = rte_eth_promiscuous_enable(portid);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				"rte_eth_promiscuous_enable: err=%s, port=%u\n",
				rte_strerror(-ret), portid);
	}

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		qconf = &s_lcore_conf[lcore_id];
		for (queue = 0; queue < qconf->n_rx_queue; ++queue) {
			portid = qconf->rx_queue_list[queue].port_id;
			rx_queue = &qconf->rx_queue_list[queue];
			portid = rx_queue->port_id;
			if (s_ring_fwd) {
				init_lcore_rxq_ring(rx_queue);
			} else {
				if (parse_dst_port(portid)) {
					rte_exit(0, "port%d fwd error\n",
						portid);
				}
				if (parse_seg_rx_port(portid)) {
					rte_exit(0, "port%d seg rx error\n",
						portid);
				}
			}
		}
	}

	ret = pthread_create(&pid, NULL,
			port_fwd_check_link_stat, NULL);
	if (ret) {
		rte_exit(EXIT_FAILURE,
			"check link thread create failed(%d)\n", ret);
	}

	if (getenv("PORT_FWD_PERF_STATISTICS")) {
		ret = pthread_create(&pid, NULL, perf_statistics,
				NULL);
		if (ret) {
			rte_exit(EXIT_FAILURE,
				"perf statistics thread create failed(%d)\n",
				ret);
		}
	}

	ret = rte_remote_direct_traffic(s_remote_dir, &force_quit);
	if (ret) {
		rte_exit(EXIT_FAILURE,
			"direct traffic failed!(%d)\n", ret);
	}

	/* launch per-lcore init on every lcore */
	ret = rte_eal_mp_remote_launch(port_fwd_demo.main_loop,
			NULL, CALL_MAIN);
	if (ret) {
		rte_exit(EXIT_FAILURE,
			"remote launch thread failed!(%d)\n", ret);
	}

	if (pktmbuf_pool_tx_only) {
		uint32_t avail;

		avail = rte_mempool_avail_count(pktmbuf_pool_tx_only);
		RTE_LOG(INFO, port_fwd,
			"default pool(%s) avail=%d, total=%d\n",
			pktmbuf_pool_tx_only->name,
			avail, nb_mbuf);
		if (avail != nb_mbuf) {
			RTE_LOG(ERR, port_fwd,
				"Leak or(and) duplicated buf error!\n");
		}
	}

	/* stop ports */
	RTE_ETH_FOREACH_DEV(portid) {
		if (!(enabled_port_mask & (1 << portid)))
			continue;
		RTE_LOG(INFO, port_fwd, "Closing port %d...", portid);
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
		RTE_LOG(INFO, port_fwd, " Done\n");
	}
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		rx_queue = s_lcore_conf[lcore_id].rx_queue_list;
		for (queue = 0; queue < MAX_RX_QUEUE_PER_LCORE; queue++) {
			if (rx_queue[queue].tbl)
				rte_ip_frag_table_destroy(rx_queue[queue].tbl);
			rx_queue[queue].tbl = NULL;
		}
	}

	rte_eal_cleanup();
	RTE_LOG(INFO, port_fwd, "Bye...\n");

	return ret;
}

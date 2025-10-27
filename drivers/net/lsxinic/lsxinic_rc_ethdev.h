/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2025 NXP
 */

#ifndef _LSXINIC_RC_ETHDEV_H_
#define _LSXINIC_RC_ETHDEV_H_

#include <rte_io.h>
#include <time.h>
#include <net/if.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <stdarg.h>
#include <rte_byteorder.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <stdbool.h>
#include <inttypes.h>
#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_kvargs.h>
#include <rte_dev.h>

#include <rte_interrupts.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_pci.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_alarm.h>
#include <rte_ether.h>
#include <rte_tcp.h>
#include <ethdev_driver.h>

#include "lsxinic_rc_hw.h"
#include "lsxinic_common_pmd.h"
#include "lsxinic_common.h"

#define  LXSNIC_DEBUG_RX_TX

#undef INIC_RC_EP_DEBUG_ENABLE
#define LXSNIC_INTERRUPT_THRESHOLD  (32)
#define LXSNIC_INTERRUPT_INTERVAL   (100) /* 100ns */

#define LXSNIC_MAX_VF_FUNCTIONS          (64)
#define ETH_ALEN			(6)

/*Link Speed */
/*typedef uint32_t lxsnic_link_speed; */
#define LXSNIC_LINK_SPEED_UNKNOWN   0
#define LXSNIC_LINK_SPEED_100_FULL  0x0008
#define LXSNIC_LINK_SPEED_1GB_FULL  0x0020
#define LXSNIC_LINK_SPEED_10GB_FULL 0x0080
#define LXSNIC_COMBINE_PKT_MAX_SIZE 1280

/* TX/RX descriptor defines */
#define LXSNIC_DEFAULT_TXD      LSINIC_BD_ENTRY_COUNT
#define LXSNIC_DEFAULT_TX_WORK  256
#define LXSNIC_MAX_TXD          LSINIC_BD_ENTRY_COUNT
#define LXSNIC_MIN_TXD          64
#define LXSNIC_DEFAULT_RXD      LSINIC_BD_ENTRY_COUNT
#define LXSNIC_MAX_RXD          LSINIC_BD_ENTRY_COUNT
#define LXSNIC_MIN_RXD          64
#define MAX_MSIX_VECTORS        8
#define NUM_MSIX_VECTORS        8
#define NON_Q_VECTORS           0

#define LXSNIC_CMD_WAIT_DEFAULT_SEC 10

/* Supported Rx Buffer Sizes */
#define LXSNIC_RXBUFFER_256    256  /* Used for skb receive header */
#define LXSNIC_RXBUFFER_2K    2048
#define LXSNIC_RXBUFFER_3K    3072
#define LXSNIC_RXBUFFER_4K    4096
#define LXSNIC_MAX_RXBUFFER  16384  /* largest size for a single descriptor */
#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#endif
#define PAGE_SIZE   (sysconf(_SC_PAGESIZE))
#define PAGE_MASK   (~(PAGE_SIZE - 1))

/* Tx Descriptors needed, worst case */
#define TXD_USE_COUNT(S) DIV_ROUND_UP((S), lxsnic_MAX_DATA_PER_TXD)
/* #define DESC_NEEDED ((MAX_SKB_FRAGS * TXD_USE_COUNT(PAGE_SIZE)) + 4) */
/* NOTE: netdev_alloc_skb reserves up to 64 bytes, NET_IP_ALIGN means we
 * reserve 64 more, and skb_shared_info adds an additional 320 bytes more,
 * this adds up to 448 bytes of extra data.
 *
 * Since netdev_alloc_skb now allocates a page fragment we can use a value
 * of 256 and the resultant skb will have a truesize of 960 or less.
 */
#define LXSNIC_RX_HDR_SIZE LXSNIC_RXBUFFER_256
#define RTE_PMD_USE_PREFETCH
#ifdef RTE_PMD_USE_PREFETCH
/* Prefetch a cache line into all cache levels.
 */
#define rte_lxsnic_prefetch(p)   rte_prefetch0(p)
#else
#define rte_lxsnic_prefetch(p)   do {} while (0)
#endif
#ifdef RTE_PMD_PACKET_PREFETCH
#define rte_lxsnic_packet_prefetch(p) rte_prefetch0(p)
#else
#define rte_lxsnic_packet_prefetch(p)	do {} while (0)
#endif

typedef uint64_t dma_addr_t;

struct lxsnic_queue_stats {
	uint64_t packets;
	uint64_t bytes;
};

struct lxsnic_tx_queue_stats {
	uint64_t restart_queue;
	uint64_t tx_busy;
	uint64_t tx_done_old;
};

struct lxsnic_rx_queue_stats {
	uint64_t rsc_count;
	uint64_t rsc_flush;
	uint64_t non_eop_descs;
	uint64_t alloc_rx_page_failed;
	uint64_t alloc_rx_buff_failed;
	uint64_t alloc_rx_dma_failed;
	uint64_t csum_err;
};

enum lxsnic_ring_state_t {
	__LXSNIC_TX_FDIR_INIT_DONE,
	__LXSNIC_TX_DETECT_HANG,
	__LXSNIC_HANG_CHECK_ARMED,
	__LXSNIC_RX_RSC_ENABLED,
	__LXSNIC_RX_CSUM_UDP_ZERO_ERR,
	__LXSNIC_RX_FCOE,
};

struct lxsnic_seg_mbuf {
	struct rte_mbuf *mbufs[LSINIC_EP_TX_SEG_MAX_ENTRY];
	uint16_t count;
} __rte_aligned(16);

#define MCACHE_NUM (LSINIC_MAX_BURST_NUM * 4)
#define MCACHE_MASK (MCACHE_NUM - 1)
struct lxsnic_ring {
	struct rte_mempool  *mb_pool; /**< mbuf pool to populate RX ring. */
	struct lxsnic_ring *pair;
	enum LSINIC_QEUE_TYPE type;
	uint32_t port;
	enum LSINIC_QEUE_STATUS status;
	struct rte_ring *multi_core_ring;
	rte_spinlock_t multi_core_lock;
	uint32_t core_id;
	pthread_t pid;
	/*const struct lxsnic_queue_ops *ops; */  /**< queue ops */
	uint16_t count;			  /* amount of bd descriptors */
	uint32_t rdma;
	enum EP_MEM_BD_TYPE ep_mem_bd_type;
	/* point to EP memory */
	void *ep_bd_mapped_addr;
	/* EP_MEM_LONG_BD*/
	struct lsinic_bd_desc *ep_bd_desc;

	/* For RC TX*/
	struct lsinic_seg_desc *ep_tx_sg;
	/* EP_MEM_SRC_ADDRL_BD*/
	struct lsinic_ep_rx_src_addrl *ep_tx_addrl;
	/* EP_MEM_SRC_ADDRX_BD*/
	struct lsinic_ep_rx_src_addrx *ep_tx_addrx;

	/* For RC RX*/
	/* EP_MEM_DST_ADDR_BD*/
	struct lsinic_ep_tx_dst_addr *ep_rx_addr;
	/* DMA read source*/
	struct lsinic_ep_tx_dst_addr *rc_rx_addr;
	/* EP_MEM_DST_ADDRL_BD*/
	struct lsinic_ep_tx_dst_addrl *ep_rx_addrl;
	/* DMA read source*/
	struct lsinic_ep_tx_dst_addrl *rc_rx_addrl;
	/* EP_MEM_DST_ADDX_BD*/
	struct lsinic_ep_tx_dst_addrx *ep_rx_addrx;
	/* DMA read source*/
	struct lsinic_ep_tx_dst_addrx *rc_rx_addrx;
	/* EP_MEM_DST_ADDR_SEG*/
	struct lsinic_ep_tx_seg_dst_addr *ep_rx_addr_seg;
	struct lsinic_ep_tx_seg_dst_addr *local_rx_addr_seg;

	enum RC_MEM_BD_TYPE rc_mem_bd_type;
	void *rc_bd_shared_addr;
	/* RC_MEM_LONG_BD*/
	struct lsinic_bd_desc *rc_bd_desc;
	struct lsinic_ep_rx_src_addrl *rc_tx_addrl;
	struct lsinic_ep_rx_src_addrx *rc_tx_addrx;

	struct lsinic_seg_desc *rc_sg_desc;

	/* For RC RX*/
	/* RC_MEM_LEN_CMD*/
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	struct lsinic_rc_rx_len_cmd *rx_len_cmd;
#else
	struct lsinic_rc_rx_len_idx *rx_len_idx;
#endif
	struct lsinic_rc_rx_seg *rx_seg;

	/* For RC TX*/
	/* RC_MEM_BD_CNF*/
	struct lsinic_rc_tx_bd_cnf *tx_complete;
	/* RC_MEM_IDX_CNF by rc_reg->cir*/

	/* bd desc point to RC(local) memory */
	dma_addr_t rc_bd_desc_dma;	/* phys. address of rc_bd_shared_addr */
	struct lsinic_ring_reg *ep_reg;	  /* ring reg point to EP memory */
	struct lsinic_ring_reg *rc_reg;	  /* ring reg point to RC memory */
	dma_addr_t rc_reg_dma;		  /* phys. address of rc_reg */
	void **q_mbuf;
	struct lxsnic_seg_mbuf *seg_mbufs;
	unsigned long state;
	uint32_t ep_sr;
	uint16_t tail;			/* current value of tail */
	uint8_t queue_index;
	/* needed for multiqueue queue management */
	uint8_t reg_idx;		 /* holds the special value that gets */
	/* the hardware register offset
	 * associated with this ring, which is
	 * different for DCB and RSS modes
	 */
	/* use for manage queue */
	uint16_t last_avail_idx;
	uint16_t last_used_idx;
	union {
		uint16_t tx_free_start_idx;
		uint16_t rx_fill_start_idx;
	};
	union {
		int tx_free_len;
		int rx_fill_len;
	};
	/* statistics */
	uint64_t packets;
	uint64_t bytes;
	uint64_t bytes_fcs;
	uint64_t bytes_overhead;
	uint64_t bytes_overhead_old;
	uint64_t errors;
	uint64_t drop_packet_num;
	uint64_t ring_full;
	uint64_t sync_err;
	uint64_t loop_total;
	uint64_t loop_avail;
	struct lxsnic_queue_stats stats;
	union {
		struct lxsnic_tx_queue_stats tx_stats;
		struct lxsnic_rx_queue_stats rx_stats;
	};
	struct lxsnic_adapter *adapter;
	uint16_t mhead;
	uint16_t mtail;
	uint32_t mcnt;
	struct rte_mbuf *mcache[MCACHE_NUM];

	/* Pointer to Next instance used by q list */
	TAILQ_ENTRY(lxsnic_ring) next;
};

/* TDBA/RDBA should be aligned on 16 byte boundary. But TDLEN/RDLEN should be
 * multiple of 128 bytes. So we align TDBA/RDBA on 128 byte boundary. This will
 * also optimize cache line size effect. H/W supports up to cache line size 128.
 */

#define LXSNIC_ALIGN (128)
struct vf_data_storage {
	unsigned char vf_mac_addresses[ETH_ALEN];
	/* ETH_ALENuint16_t vf_mc_hashes[lxsnic_MAX_VF_MC_ENTRIES];
	 *  uint16_t num_vf_mc_hashes;
	 *  uint16_t default_vf_vlan_id;
	 *  uint16_t vlans_enabled;
	 */
	bool clear_to_send;
	bool pf_set_mac;
	uint16_t pf_vlan; /* When set, guest VLAN config not allowed. */
	uint16_t pf_qos;
	uint16_t tx_rate;
	uint16_t vlan_count;
	uint8_t spoofchk_enabled;
	unsigned int vf_api;
};

struct lxsnic_hw_stats {
	uint64_t rx_alloc_mbuf_fail;
	uint64_t rx_clean_count;
	uint64_t rx_desc_clean_num;
	uint64_t rx_desc_clean_fail;
	uint64_t rx_desc_err;
	uint64_t tx_mbuf_err;
	uint64_t tx_clean_count;
	uint64_t tx_desc_clean_num;
	uint64_t tx_desc_clean_fail;
	uint64_t tx_desc_err;
};

enum lxsnic_rc_self_test {
	LXSNIC_RC_SELF_NONE_TEST = 0,
	LXSNIC_RC_SELF_PMD_TEST,
	LXSNIC_RC_SELF_REMOTE_MEM_TEST,
	LXSNIC_RC_SELF_LOCAL_MEM_TEST
};

struct lxsnic_adapter {
	/* OS defined structs */
	unsigned long state;
	uint32_t rc_state;
	uint32_t ep_state;

	struct lxsnic_hw hw;
	struct rte_eth_dev *eth_dev;
	uint8_t *bd_desc_base;
	uint8_t *ep_ring_virt_base;  /* EP ring base */
	dma_addr_t ep_ring_phy_base;

	uint8_t *ep_memzone_vir;
	dma_addr_t ep_memzone_phy;
	uint64_t ep_memzone_size;

	uint8_t *rc_memzone_vir;
	dma_addr_t rc_memzone_iova;
	uint32_t rc_memzone_size;
	const struct rte_memzone *rc_mz;

	const struct rte_memzone *rc_ring_mz;
	uint8_t *rc_ring_virt_base;  /* RC ring shadow base */
	dma_addr_t rc_ring_phy_base;
	uint64_t rc_ring_win_size;
	uint16_t  num_rx_queues;
	uint16_t  config_rx_queues;
	uint16_t  num_tx_queues;
	uint16_t  config_tx_queues;
	/* Tx fast path data */
	uint8_t *rc_bd_desc_base;
	dma_addr_t rc_bd_desc_phy;

	/* hardware ring is full can't send pkt */
	uint64_t tx_busy;
	uint16_t max_qpairs;
	/*total apapter tx pkt rx pkt num */
	unsigned int tx_ring_bd_count;
	unsigned int rx_ring_bd_count;

	/* adapter link state */
	uint32_t link_speed;
	bool link_up;
	bool adapter_stopped;
	enum lxsnic_rc_self_test self_test;
	uint32_t self_test_len;
	unsigned long link_check_timeout;
	/* SR-IOV */
	DECLARE_BITMAP(active_vfs, LXSNIC_MAX_VF_FUNCTIONS);
	unsigned int num_vfs;
	struct vf_data_storage *vfinfo;
	int vf_rate_link_speed;
	struct lxsnic_hw_stats stats;
	uint32_t cap;
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	uint32_t merge_threshold;
#endif
	uint16_t max_data_room;
	uint32_t pkt_addr_interval;
	uint64_t pkt_addr_base;
};

enum lxsnic_state_t {
	__LXSNIC_TESTING,
	__LXSNIC_RESETTING,
	__LXSNIC_DOWN,
	__LXSNIC_SERVICE_SCHED,
	__LXSNIC_IN_SFP_INIT,
};

#define LXSNIC_DEV_PRIVATE(adapter) \
	((struct lxsnic_adapter *)adapter)
#define LXSNIC_DEV_PRIVATE_TO_HW(adapter)\
	(&((struct lxsnic_adapter *)adapter)->hw)

#define LXSNIC_DEV_PRIVATE_TO_EP_PHY_BASE(adapter)\
	(&((struct lxsnic_adapter *)adapter)->ep_ring_phy_base)\

#define LXSNIC_DEV_PRIVATE_TO_P_VFDATA(adapter)\
	 (&((struct lxsnic_adapter *)adapter)->vfinfo)

void lxsnic_pf_host_init(struct rte_eth_dev *eth_dev);

void lxsnic_disable_sriov(struct lxsnic_adapter *adapter);

int lxsnic_set_netdev_state(struct lxsnic_adapter *adapter,
	enum PCIDEV_COMMAND cmd);

int lxsnic_rx_bd_init_buffer(struct lxsnic_ring *rx_queue,
	uint16_t idx);

#endif /* _LSXINIC_RC_ETHDEV_H_ */

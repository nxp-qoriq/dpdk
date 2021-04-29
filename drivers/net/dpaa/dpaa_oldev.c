/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020-2021 NXP
 */

#include <stdio.h>
#include <sys/ioctl.h>

#include <rte_dpaa_bus.h>
#include <rte_dpaa_logs.h>
#include <dpaa_ethdev.h>
#include <dpaa_rxtx.h>
#include <dpaa_mempool.h>

#include <fsl_fman.h>

#include "rte_pmd_dpaa_oldev.h"

/* The ol device is a tx are queue pair, which is provided to the kernel through
 * ioctl calls. It is exposed as a virtual port to the application.
 * This ASK Device provides IOCTL calls to driver for communicating fqid's,
 * buffer pool id's and channel id's with kernel.
 */
#define ASK_PATH		"/dev/cdx_ctrl"
#define CDX_IOC_MAGIC		0xbe

static int fd = -1;
static pthread_mutex_t fd_init_lock = PTHREAD_MUTEX_INITIALIZER;

struct ask_ctrl_offline_channel {
	uint32_t channel_id;
	uint32_t ctx_a_hi_val;	/* Setting required flags(B0,A2) while creating
				 * frame queue.
				 */
	uint32_t ctx_a_lo_val;	/* EBD and VSP enable bits */
	uint32_t ctx_b_val;	/* VSP ID */
};

struct ask_ctrl_dpdk_fq_info_s {
	uint32_t tx_fq_id;		/* DPDK transmits GTP packets using FQ
					 * ID
					 */
	uint32_t rx_fq_id;		/* DPDK receives packets from FMAN */
	uint16_t buff_size;		/* Size of each buffer in DPDPK buffer
					 * pool
					 */
	uint8_t bp_id;			/* DPDK buffer pool id */
	uint8_t bh_port_name[12];	/* BH port interface name , for testing
					 * purpose
					 */
	/* below fields are taken from structure t_FmBufferPrefixContent, These
	 * fields are required for VSP creation on DPDK buffer pool ID. These
	 * fields should be set based on expected parameters from FMAN
	 */
	uint16_t privDataSize;		/* Number of bytes to be left at the
					 * beginning of the external buffer;
					 * Note that the private-area will start
					 * from the base of the buffer address.
					 */
	bool passPrsResult;		/* TRUE to pass the parse result to/from
					 * the FM; User may use
					 * FM_PORT_GetBufferPrsResult() in order
					 * to get the parser-result from a
					 * buffer.
					 */
	bool passTimeStamp;		/* < TRUE to pass the timeStamp to/from
					 * the FM User may use
					 * FM_PORT_GetBufferTimeStamp() in order
					 * to get the parser-result from a
					 * buffer.
					 */
	bool passHashResult;		/* TRUE to pass the KG hash result
					 * to/from the FM User may use
					 * FM_PORT_GetBufferHashResult() in
					 * order to get the parser-result from a
					 * buffer.
					 */
	bool passAllOtherPCDInfo;	/* Add all other Internal-Context
					 * information: AD, hash-result, key,
					 * etc.
					 */
	uint16_t dataAlign;		/* 0 to use driver's default alignment
					 * [DEFAULT_FM_SP_bufferPrefixContent_dataAlign],
					 * other value for selecting a data
					 * alignment (must be a power of 2); if
					 * write optimization is used, must be
					 * >= 16.
					 */
	uint8_t manipExtraSpace;	/* Maximum extra size needed (insertion-
					 * size minus removal-size); Note that
					 * this field impacts the size of the
					 * buffer-prefix (i.e. it pushes the
					 * data offset); This field is
					 * irrelevant if DPAA_VERSION==10
					 */
};

#define ASK_CTRL_GET_OFFLINE_CHANNEL_INFO \
	_IOWR(CDX_IOC_MAGIC, 8, struct ask_ctrl_offline_channel)
#define ASK_CTRL_SET_DPDK_INFO \
	_IOWR(CDX_IOC_MAGIC, 9, struct ask_ctrl_dpdk_fq_info_s)
#define ASK_CTRL_SET_CLASSIF_INFO \
	_IOWR(CDX_IOC_MAGIC, 10, struct rte_pmd_dpaa_uplink_cls_info_s)
#define ASK_CTRL_RESET_CLASSIF_INFO \
	_IOWR(CDX_IOC_MAGIC, 11, struct rte_pmd_dpaa_uplink_cls_info_s)
#define ASK_CTRL_SET_LGW_INFO \
	_IOWR(CDX_IOC_MAGIC, 12, struct rte_pmd_dpaa_lgw_info_s)
#define ASK_CTRL_RESET_LGW_INFO \
	_IOWR(CDX_IOC_MAGIC, 13, struct rte_pmd_dpaa_lgw_info_s)


static int check_fd(void)
{
	int ret;

	if (fd >= 0)
		return 0;
	ret = pthread_mutex_lock(&fd_init_lock);
	assert(!ret);
	/* check again with the lock held */
	if (fd < 0)
		fd = open(ASK_PATH, O_RDWR);
	ret = pthread_mutex_unlock(&fd_init_lock);
	assert(!ret);
	return (fd >= 0) ? 0 : -ENODEV;
}

static uint32_t ask_get_channel_info(struct ask_ctrl_offline_channel *ch_info)
{
	int ret = check_fd();
	if (ret)
		return ret;

	ret = ioctl(fd, ASK_CTRL_GET_OFFLINE_CHANNEL_INFO, ch_info);
	if (!ret) {
		DPAA_PMD_DEBUG("Get channel info successful");
		DPAA_PMD_DEBUG("Channel id: %x", ch_info->channel_id);
		DPAA_PMD_DEBUG("ctx_a_hi_val: %x", ch_info->ctx_a_hi_val);
		DPAA_PMD_DEBUG("ctx_a_lo_val: %x", ch_info->ctx_a_lo_val);
		DPAA_PMD_DEBUG("ctx_b_val: %x", ch_info->ctx_b_val);
	} else {
		DPAA_PMD_ERR("Get channel info ioctl failed with errno: %s",
			     strerror(errno));
	}

	return ret;
}

static int ask_set_fq_info(struct ask_ctrl_dpdk_fq_info_s *fq_info)
{
	int ret = check_fd();
	if (ret)
		return ret;

	ret = ioctl(fd, ASK_CTRL_SET_DPDK_INFO, fq_info);
	if (!ret) {
		DPAA_PMD_DEBUG("Set fq info successful");
		DPAA_PMD_DEBUG("Tx fqid: %x", fq_info->tx_fq_id);
		DPAA_PMD_DEBUG("Rx fqid: %x", fq_info->rx_fq_id);
		DPAA_PMD_DEBUG("buff_size: %d", fq_info->buff_size);
		DPAA_PMD_DEBUG("bp_id: %d", fq_info->bp_id);
		DPAA_PMD_DEBUG("Backhaul port name: %s",
			       fq_info->bh_port_name);
	} else {
		DPAA_PMD_ERR("Set FQ info ioctl failed with errno: %s",
			     strerror(errno));
	}

	return ret;
}

static int
dpaa_ol_dev_configure(__rte_unused struct rte_eth_dev *dev)
{
	PMD_INIT_FUNC_TRACE();

	return 0;
}

static int dpaa_ol_dev_info(struct rte_eth_dev *dev,
			    struct rte_eth_dev_info *dev_info)
{
	struct dpaa_if *dpaa_intf = dev->data->dev_private;

	PMD_INIT_FUNC_TRACE();

	dev_info->max_rx_queues = dpaa_intf->nb_rx_queues;
	dev_info->max_tx_queues = dpaa_intf->nb_tx_queues;
	dev_info->max_rx_pktlen = DPAA_MAX_RX_PKT_LEN;
	dev_info->max_mac_addrs = DPAA_MAX_MAC_FILTER;
	dev_info->max_hash_mac_addrs = 0;
	dev_info->max_vfs = 0;

	dev_info->speed_capa = ETH_LINK_SPEED_10M_HD | ETH_LINK_SPEED_10M |
			       ETH_LINK_SPEED_100M_HD | ETH_LINK_SPEED_100M |
			       ETH_LINK_SPEED_1G | ETH_LINK_SPEED_2_5G |
			       ETH_LINK_SPEED_10G;

	return 0;
}

int rte_pmd_dpaa_ol_set_classif_info(
			struct rte_pmd_dpaa_uplink_cls_info_s *classif_info)
{
	struct in_addr dest_addr;
	int i, ret = check_fd();
	if (ret)
		return ret;

	if (classif_info == NULL) {
		DPAA_PMD_ERR("No classification data available\n");
		return -1;
	}

	ret = ioctl(fd, ASK_CTRL_SET_CLASSIF_INFO, classif_info);
	if (!ret) {
		DPAA_PMD_DEBUG("Set classification info successful");
		for (i = 0; i < classif_info->num_ports; i++) {
			DPAA_PMD_DEBUG("UDP dest port: %d\n",
				       classif_info->gtp_udp_port[i]);
		}
		DPAA_PMD_DEBUG("Protocol ID: %d",
			       classif_info->gtp_proto_id);
		DPAA_PMD_DEBUG("No of IP address: %d",
			       classif_info->num_addresses);
		for (i = 0; i < classif_info->num_addresses; i++) {
			dest_addr.s_addr = classif_info->addrs[i].ip_addr[0];
			DPAA_PMD_DEBUG("IP Address %i: %s", i + 1,
				       inet_ntoa(dest_addr));
		}
	} else {
		DPAA_PMD_ERR("Set classification info ioctl failed with errno: %s",
			     strerror(errno));
	}

	return ret;
}

int rte_pmd_dpaa_ol_reset_classif_info(void)
{
	struct rte_pmd_dpaa_uplink_cls_info_s classif_info;
	int ret = 0;

	memset(&classif_info, 0, sizeof(classif_info));
	ret = check_fd();
	if (ret)
		return ret;

	ret = ioctl(fd, ASK_CTRL_RESET_CLASSIF_INFO, &classif_info);
	if (ret) {
		DPAA_PMD_ERR("Reset classification info ioctl failed with errno: %s",
			     strerror(errno));
	} else {
		DPAA_PMD_DEBUG("Reset classification info successful");
	}

	return ret;
}

int rte_pmd_dpaa_ol_set_lgw_info(
			struct rte_pmd_dpaa_lgw_info_s *lgw_info)
{
	int ret = check_fd();
	if (ret)
		return ret;

	if (lgw_info == NULL) {
		DPAA_PMD_ERR("No LGW data available\n");
		return -1;
	}
	ret = ioctl(fd, ASK_CTRL_SET_LGW_INFO, lgw_info);
	if (!ret) {
		DPAA_PMD_DEBUG("Set LGW info successful\n");
	} else {
		DPAA_PMD_ERR("Set LGW info ioctl failed with errno: %s",
			     strerror(errno));
	}

	return ret;
}

int rte_pmd_dpaa_ol_reset_lgw_info(void)
{
	struct rte_pmd_dpaa_lgw_info_s lgw_info;
	int ret = 0;

	PMD_INIT_FUNC_TRACE();

	memset(&lgw_info, 0, sizeof(lgw_info));
	ret = check_fd();
	if (ret)
		return ret;

	ret = ioctl(fd, ASK_CTRL_RESET_LGW_INFO, &lgw_info);
	if (ret) {
		DPAA_PMD_ERR("Reset LGW info ioctl failed with errno: %s",
			     strerror(errno));
	} else {
		DPAA_PMD_DEBUG("Reset LGW info successful");
	}

	return ret;
}

static int dpaa_ol_dev_start(struct rte_eth_dev *dev)
{
	PMD_INIT_FUNC_TRACE();

	dev->tx_pkt_burst = dpaa_eth_queue_tx;

	return 0;
}

static int dpaa_ol_dev_stop(struct rte_eth_dev *dev)
{
	PMD_INIT_FUNC_TRACE();

	dev->tx_pkt_burst = dpaa_eth_tx_drop_all;

	return 0;
}

static int dpaa_ol_dev_close(__rte_unused struct rte_eth_dev *dev)
{
	PMD_INIT_FUNC_TRACE();

	return 0;
}

static inline void
dpaa_poll_queue_default_config(struct qm_mcc_initfq *opts)
{
	memset(opts, 0, sizeof(struct qm_mcc_initfq));
	opts->we_mask = QM_INITFQ_WE_CONTEXTA;
	opts->fqd.fq_ctrl = QM_FQCTRL_AVOIDBLOCK | QM_FQCTRL_CTXASTASHING |
			    QM_FQCTRL_PREFERINCACHE;
	opts->fqd.context_a.stashing.exclusive = 0;
	if (dpaa_svr_family != SVR_LS1046A_FAMILY)
		opts->fqd.context_a.stashing.annotation_cl =
				DPAA_IF_RX_ANNOTATION_STASH;
	opts->fqd.context_a.stashing.data_cl = DPAA_IF_RX_DATA_STASH;
	opts->fqd.context_a.stashing.context_cl = DPAA_IF_RX_CONTEXT_STASH;
}

static
int dpaa_ol_rx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx,
			    __rte_unused uint16_t nb_desc,
			    unsigned int socket_id __rte_unused,
			    __rte_unused const struct rte_eth_rxconf *rx_conf,
			    struct rte_mempool *mp)
{
	struct dpaa_if *dpaa_intf = dev->data->dev_private;
	struct qman_fq *rxq = &dpaa_intf->rx_queues[queue_idx];

	PMD_INIT_FUNC_TRACE();

	if (queue_idx >= dev->data->nb_rx_queues) {
		rte_errno = EOVERFLOW;
		DPAA_PMD_ERR("%p: queue index out of range (%u >= %u)",
			     (void *)dev, queue_idx, dev->data->nb_rx_queues);
		return -rte_errno;
	}

	dpaa_intf->bp_info = DPAA_MEMPOOL_TO_POOL_INFO(mp);
	dpaa_intf->valid = 1;

	rxq->bp_array = rte_dpaa_bpid_info;
	dev->data->rx_queues[queue_idx] = rxq;

	return 0;
}

/* This API has dependency on RX queue setup */
static
int dpaa_ol_tx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx,
			   uint16_t nb_desc __rte_unused,
			   unsigned int socket_id __rte_unused,
			   const struct rte_eth_txconf *tx_conf __rte_unused)
{
	struct dpaa_if *dpaa_intf = dev->data->dev_private;
	struct qman_fq *txq = &dpaa_intf->tx_queues[queue_idx];
	struct qman_fq *rxq = &dpaa_intf->rx_queues[queue_idx];
	struct ask_ctrl_dpdk_fq_info_s fq_info;
	int ret;
	const char *bh_port_name;
	struct rte_pktmbuf_pool_private *mbp_priv;

	PMD_INIT_FUNC_TRACE();

	dev->data->tx_queues[queue_idx] = txq;

	if (dpaa_intf->bp_info == NULL || rxq == NULL)
		return 0;

	mbp_priv = (struct rte_pktmbuf_pool_private *)rte_mempool_get_priv(dpaa_intf->bp_info->mp);
	fq_info.tx_fq_id = txq->fqid;
	fq_info.rx_fq_id = rxq->fqid;
	fq_info.buff_size = mbp_priv->mbuf_data_room_size;
	fq_info.bp_id = dpaa_intf->bp_info->bpid;

/* Private area reserved by driver.
 * Aligned with "struct annotations_t". Parse results will be written from
 * the 17th byte by the HW.
 */
#define DPAA_OL_PARSERSLT_START_OFFSET 16
#define DPAA_OL_DATA_ALIGNMENT 64
/* Change this value to increase the data offset.
 * final value will be aligned by DPAA_OL_DATA_ALIGNMENT
 */
#define DPAA_OL_MAX_EXTRA_SIZE 0
#define DPAA_OL_PARSE_RESULT_REQUIRED true
#define DPAA_OL_TIME_STAMP_REQUIRED false
#define DPAA_OL_HASH_RESULT_REQUIRED false
#define DPAA_OL_PCD_INFO_REQUIRED false

	fq_info.privDataSize = DPAA_OL_PARSERSLT_START_OFFSET;
	fq_info.passPrsResult = DPAA_OL_PARSE_RESULT_REQUIRED;
	fq_info.passTimeStamp = DPAA_OL_TIME_STAMP_REQUIRED;
	fq_info.passHashResult = DPAA_OL_HASH_RESULT_REQUIRED;
	fq_info.passAllOtherPCDInfo = DPAA_OL_PCD_INFO_REQUIRED;
	fq_info.dataAlign = DPAA_OL_DATA_ALIGNMENT;
	fq_info.manipExtraSpace = DPAA_OL_MAX_EXTRA_SIZE;

	bh_port_name = getenv("BH_PORT_NAME");
	if (bh_port_name == NULL) {
		DPAA_PMD_ERR("BH_PORT_NAME not defined");
		return -1;
	}

	strcpy((char *)fq_info.bh_port_name, bh_port_name);

	ret = ask_set_fq_info(&fq_info);
	if (ret) {
		DPAA_PMD_ERR("Set FQ info failed with ret: %d", ret);
		return ret;
	}

	return 0;
}

static int dpaa_ol_link_update(struct rte_eth_dev *dev,
			       __rte_unused int wait_to_complete)
{
	struct dpaa_if *dpaa_intf = dev->data->dev_private;
	struct rte_eth_link *link = &dev->data->dev_link;

	PMD_INIT_FUNC_TRACE();

	PMD_INIT_FUNC_TRACE();

	link->link_status = dpaa_intf->valid;
	link->link_speed = ETH_SPEED_NUM_NONE;
	link->link_duplex = ETH_LINK_FULL_DUPLEX;
	link->link_autoneg = ETH_LINK_AUTONEG;

	return 0;
}

static int dpaa_ol_promiscuous_enable(__rte_unused struct rte_eth_dev *dev)
{
	PMD_INIT_FUNC_TRACE();

	return 0;
}

static int dpaa_ol_rx_queue_init(struct qman_fq *fq, uint32_t fqid)
{
	int ret;
	struct qm_mcc_initfq opts = {0};
	u32 flags = QMAN_FQ_FLAG_DYNAMIC_FQID | QMAN_FQ_FLAG_NO_ENQUEUE;

	if (unlikely(!DPAA_PER_LCORE_PORTAL)) {
		ret = rte_dpaa_portal_init(NULL);
		if (ret < 0) {
			DPAA_PMD_ERR("portal initialization failure");
			return ret;
		}
	}

	ret = qman_create_fq(fqid, flags, fq);
	if (ret) {
		DPAA_PMD_ERR("create rx fqid 0x%x failed with ret: %d", fqid,
			     ret);
		return ret;
	}
	fq->is_static = false;

	dpaa_poll_queue_default_config(&opts);

	ret = qman_init_fq(fq, 0, &opts);
	if (ret)
		DPAA_PMD_ERR("init rx fqid 0x%x failed with ret:%d", fqid, ret);
	return ret;
}

static int dpaa_ol_tx_queue_init(struct qman_fq *fq, uint32_t fqid)
{
	int ret;
	struct qm_mcc_initfq opts = {0};
	u32 flags = QMAN_FQ_FLAG_DYNAMIC_FQID | QMAN_FQ_FLAG_TO_DCPORTAL;
	struct ask_ctrl_offline_channel ch_info;

	memset(&ch_info, 0, sizeof(ch_info));

	ret = ask_get_channel_info(&ch_info);
	if (ret) {
		DPAA_PMD_ERR("Get channel info failed with ret: %d", ret);
		return ret;
	}
	ret = qman_create_fq(fqid, flags, fq);
	if (ret) {
		DPAA_PMD_ERR("Create tx fq failed with ret: %d", ret);
		return ret;
	}

	opts.we_mask = QM_INITFQ_WE_DESTWQ |
		       QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA;

	opts.fqd.dest.channel = ch_info.channel_id;

#define DPA_ISC_WQ_ID 2
	opts.fqd.dest.wq = DPA_ISC_WQ_ID;
	opts.fqd.fq_ctrl = QM_FQCTRL_PREFERINCACHE;
	opts.fqd.context_b = ch_info.ctx_b_val;
	opts.fqd.context_a.hi = ch_info.ctx_a_hi_val;
	opts.fqd.context_a.lo = ch_info.ctx_a_lo_val;

	opts.fqid = fq->fqid;
	fq->ch_id = ch_info.channel_id;
	opts.count = 1;

	ret = qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts);
	if (ret)
		DPAA_PMD_ERR("init tx fqid 0x%x failed %d", fq->fqid, ret);
	return ret;
}

static struct eth_dev_ops dpaa_ol_devops = {
		.dev_configure            = dpaa_ol_dev_configure,
		.dev_start                = dpaa_ol_dev_start,
		.dev_stop                 = dpaa_ol_dev_stop,
		.dev_close                = dpaa_ol_dev_close,
		.dev_infos_get            = dpaa_ol_dev_info,

		.rx_queue_setup           = dpaa_ol_rx_queue_setup,
		.tx_queue_setup           = dpaa_ol_tx_queue_setup,

		.link_update              = dpaa_ol_link_update,
		.promiscuous_enable       = dpaa_ol_promiscuous_enable,
};

static int dpaa_oldev_init(struct rte_eth_dev *eth_dev)
{
	int num_fqs, ret;
	struct dpaa_if *dpaa_intf;

	PMD_INIT_FUNC_TRACE();

	num_fqs = DPAA_DEFAULT_NUM_PCD_QUEUES;
	dpaa_intf = eth_dev->data->dev_private;

	dpaa_intf->rx_queues = rte_zmalloc(NULL,
					   sizeof(struct qman_fq) * num_fqs,
					   MAX_CACHELINE);
	if (!dpaa_intf->rx_queues) {
		DPAA_PMD_ERR("Failed to alloc mem for RX queues\n");
		return -ENOMEM;
	}

	ret = dpaa_ol_rx_queue_init(&dpaa_intf->rx_queues[0], 0);
	if (ret)
		goto free_rx;
	dpaa_intf->rx_queues[0].dpaa_intf = dpaa_intf;

	dpaa_intf->nb_rx_queues = num_fqs;

	dpaa_intf->tx_queues = rte_zmalloc(NULL,
					   sizeof(struct qman_fq) * num_fqs,
					   MAX_CACHELINE);
	if (!dpaa_intf->tx_queues) {
		DPAA_PMD_ERR("Failed to alloc mem for TX queues\n");
		ret = -ENOMEM;
		goto free_rx;
	}

	ret = dpaa_ol_tx_queue_init(&dpaa_intf->tx_queues[0], 0);
	if (ret)
		goto free_tx;

	dpaa_intf->nb_tx_queues = num_fqs;

	eth_dev->dev_ops = &dpaa_ol_devops;
	eth_dev->rx_pkt_burst = dpaa_eth_queue_rx;
	eth_dev->tx_pkt_burst = dpaa_eth_tx_drop_all;

	/* Allocate memory for storing MAC addresses */
	eth_dev->data->mac_addrs = rte_zmalloc("mac_addr",
			RTE_ETHER_ADDR_LEN * DPAA_MAX_MAC_FILTER, 0);
	if (eth_dev->data->mac_addrs == NULL) {
		DPAA_PMD_ERR("Failed to allocate %d bytes needed to "
			     "store MAC addresses",
			     RTE_ETHER_ADDR_LEN * DPAA_MAX_MAC_FILTER);
		ret = -ENOMEM;
		goto free_tx;
	}

	return 0;

free_tx:
	rte_free(dpaa_intf->tx_queues);
	dpaa_intf->tx_queues = NULL;
	dpaa_intf->nb_tx_queues = 0;
free_rx:
	rte_free(dpaa_intf->rx_queues);
	dpaa_intf->rx_queues = NULL;
	dpaa_intf->nb_rx_queues = 0;
	return ret;
}

static int rte_dpaa_probe(__rte_unused struct rte_dpaa_driver *dpaa_drv,
			  __rte_unused struct rte_dpaa_device *dpaa_dev)
{
	int ret;
	struct rte_eth_dev *eth_dev;

	PMD_INIT_FUNC_TRACE();

	eth_dev = rte_eth_dev_allocate(dpaa_dev->name);
	if (!eth_dev)
		return -ENOMEM;
	eth_dev->data->dev_private = rte_zmalloc("ethdev private structure",
						 sizeof(struct dpaa_if),
						 RTE_CACHE_LINE_SIZE);
	if (!eth_dev->data->dev_private) {
		DPAA_PMD_ERR("Cannot allocate memzone for port data");
		rte_eth_dev_release_port(eth_dev);
		return -ENOMEM;
	}

	eth_dev->device = &dpaa_dev->device;
	dpaa_dev->eth_dev = eth_dev;

	ret = dpaa_oldev_init(eth_dev);
	if (ret == 0) {
		rte_eth_dev_probing_finish(eth_dev);
		return 0;
	}

	rte_eth_dev_release_port(eth_dev);
	return ret;
}

static int rte_dpaa_remove(__rte_unused struct rte_dpaa_device *dpaa_dev)
{
	PMD_INIT_FUNC_TRACE();

	return 0;
}

static struct rte_dpaa_driver rte_dpaa_ol_pmd = {
		.drv_type = FSL_DPAA_OL,
		.probe = rte_dpaa_probe,
		.remove = rte_dpaa_remove,
};

RTE_PMD_REGISTER_DPAA(ol_dpaa, rte_dpaa_ol_pmd);

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2025 NXP
 */

#include <time.h>
#include <net/if.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <stdarg.h>
#include <inttypes.h>
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
#include <rte_atomic.h>
#include <rte_errno.h>
#include <rte_version.h>
#include <rte_eal_memconfig.h>
#include <rte_net.h>
#include <portal/dpaa2_hw_pvt.h>
#include <rte_pmd_lsxinic.h>

#include <rte_lsx_pciep_bus.h>
#include "lsxinic_common_pmd.h"
#include "lsxinic_common_reg.h"
#include "lsxinic_common_helper.h"
#include "lsxinic_ep_ethdev.h"
#include "lsxinic_ep_rxtx.h"
#include "lsxinic_ep_dma.h"
#include "lsxinic_ep_ethtool.h"
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
#include <dpaa2_ethdev.h>
#endif

static struct rte_lsx_pciep_driver rte_lsinic_pmd;

static int
lsinic_dev_configure(struct rte_eth_dev *dev);
static int
lsinic_dev_start(struct rte_eth_dev *dev);
static int
lsinic_dev_stop(struct rte_eth_dev *dev);
static int
lsinic_dev_close(struct rte_eth_dev *dev);
static int
lsinic_dev_info_get(struct rte_eth_dev *dev,
	struct rte_eth_dev_info *dev_info);
static int
lsinic_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu);
static int
lsinic_dev_link_update(struct rte_eth_dev *dev,
	int wait_to_complete);
static int
lsinic_dev_promiscuous_enable(struct rte_eth_dev *dev);
static int
lsinic_dev_promiscuous_disable(struct rte_eth_dev *dev);
static int
lsinic_dev_allmulticast_enable(struct rte_eth_dev *dev);
static int
lsinic_dev_allmulticast_disable(struct rte_eth_dev *dev);
static int
lsinic_dev_stats_get(struct rte_eth_dev *dev,
	struct rte_eth_stats *stats);
static int
lsinic_dev_stats_reset(struct rte_eth_dev *dev);

static const struct rte_eth_desc_lim rx_desc_lim = {
	.nb_max = LSINIC_BD_ENTRY_COUNT,
	.nb_min = LSINIC_BD_ENTRY_COUNT,
	.nb_align = 8,
};

static const struct rte_eth_desc_lim tx_desc_lim = {
	.nb_max = LSINIC_BD_ENTRY_COUNT,
	.nb_min = LSINIC_BD_ENTRY_COUNT,
	.nb_align = 8,
};

static struct eth_dev_ops lsinic_eth_dev_ops = {
	.dev_configure        = lsinic_dev_configure,
	.dev_start            = lsinic_dev_start,
	.dev_stop             = lsinic_dev_stop,
	.dev_close            = lsinic_dev_close,
	.dev_infos_get        = lsinic_dev_info_get,
	.mtu_set	      = lsinic_dev_mtu_set,
	.rx_queue_setup       = lsinic_dev_rx_queue_setup,
	.rx_queue_release     = lsinic_dev_rx_queue_release,
	.tx_queue_setup       = lsinic_dev_tx_queue_setup,
	.tx_queue_release     = lsinic_dev_tx_queue_release,
	.link_update          = lsinic_dev_link_update,
	.promiscuous_enable   = lsinic_dev_promiscuous_enable,
	.promiscuous_disable  = lsinic_dev_promiscuous_disable,
	.allmulticast_enable  = lsinic_dev_allmulticast_enable,
	.allmulticast_disable = lsinic_dev_allmulticast_disable,
	.stats_get            = lsinic_dev_stats_get,
	.stats_reset          = lsinic_dev_stats_reset,
};

/**
 * lsinic_sw_init - Initialize general software structures
 *                   (struct lsinic_adapter)
 * @adapter: board private structure to initialize
 *
 * lsinic_sw_init initializes the Adapter private data structure.
 * Fields are initialized based on PCI device information and
 * OS network device settings (MTU size).
 **/
static int
lsinic_sw_init(struct lsinic_adapter *adapter)
{
	struct lsinic_eth_reg *eth_reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_ETH_REG_OFFSET);

	/* get ring setting */
	adapter->tx_ring_bd_count = LSINIC_READ_REG(&eth_reg->tx_entry_num);
	adapter->rx_ring_bd_count = LSINIC_READ_REG(&eth_reg->rx_entry_num);

	adapter->num_tx_queues = 0;
	adapter->num_rx_queues = 0;

	return 0;
}

static int
lsinic_txrx_queues_create(struct lsinic_adapter *adapter)
{
	adapter->txqs = rte_zmalloc_socket("ethdev queue",
					sizeof(struct lsinic_queue) *
					adapter->max_qpairs,
					RTE_CACHE_LINE_SIZE, 0);
	adapter->rxqs = rte_zmalloc_socket("ethdev queue",
					sizeof(struct lsinic_queue) *
					adapter->max_qpairs,
					RTE_CACHE_LINE_SIZE, 0);
	if (!adapter->txqs || !adapter->rxqs) {
		LSXINIC_PMD_ERR("Cannot allocate txqs/rxqs");
		return -ENODEV;
	}

	return 0;
}

/* lsinic_set_netdev
 *
 * Send command to netdev to init/start/stop/remove device
 */
static int
lsinic_set_netdev(struct lsinic_adapter *adapter, int cmd)
{
	struct lsinic_dev_reg *reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_DEV_REG_OFFSET);

	switch (cmd) {
	case PCIDEV_COMMAND_START:
		adapter->ep_state = LSINIC_DEV_UP;
		break;
	case PCIDEV_COMMAND_STOP:
		adapter->ep_state = LSINIC_DEV_DOWN;
		break;
	case PCIDEV_COMMAND_REMOVE:
		adapter->ep_state = LSINIC_DEV_REMOVED;
		break;
	case PCIDEV_COMMAND_INIT:
		adapter->ep_state = LSINIC_DEV_INITED;
		break;
	default:
		break;
	}

	LSINIC_WRITE_REG(&reg->ep_state, adapter->ep_state);

	/* To Do notify Host driver that the status has been changed */

	return 0;
}

static int
lsinic_set_init_flag(struct lsinic_adapter *adapter, int single_bar)
{
	struct lsinic_dev_reg *reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_DEV_REG_OFFSET);

	LSINIC_WRITE_REG(&reg->init_flag, LSINIC_INIT_FLAG);
	LSINIC_WRITE_REG(&reg->single_bar, single_bar);

	return 0;
}

static int
lsinic_init_bar_addr(struct rte_lsx_pciep_device *lsinic_dev)
{
	struct rte_eth_dev *eth_dev = lsinic_dev->eth_dev;
	struct lsinic_adapter *adapter = eth_dev->process_private;
	int sim, rbp, ret;
	uint8_t *base_vir;
	uint64_t size_reg, size_ring, total_size, base_phy;
	void *vir_ob;

	adapter->pf_idx = lsinic_dev->pf;
	adapter->is_vf = lsinic_dev->is_vf;
	if (lsinic_dev->is_vf)
		adapter->vf_idx = lsinic_dev->vf;
	adapter->pcie_idx = lsinic_dev->pcie_id;

	sim = rte_lsx_pciep_hw_sim_get(adapter->pcie_idx);
	rbp = rte_lsx_pciep_hw_rbp_get(adapter->pcie_idx);

	if (!rbp && !sim) {
		/* OB setting does NOT depend on RC for NORBP.*/
		vir_ob = rte_lsx_pciep_set_ob_win(lsinic_dev, 0, 0, NULL);
		if (!vir_ob)
			return -ENOMEM;
	}

	size_reg = lsinic_reg_bar_size();
	size_ring = lsinic_ring_bar_size();

	if (lsinic_dev->single_bar) {
		total_size = lsinic_reg_ring_bar_size();
		ret = rte_lsx_pciep_set_ib_win(lsinic_dev,
			LSX_PCIEP_REG_BAR_IDX, total_size);
		if (ret) {
			LSXINIC_PMD_ERR("%s: IB win[%d] size(0x%lx) set failed",
				lsinic_dev->name, LSX_PCIEP_REG_BAR_IDX,
				total_size);

			return ret;
		}
	} else {
		ret = rte_lsx_pciep_set_ib_win(lsinic_dev,
			LSX_PCIEP_REG_BAR_IDX, size_reg);
		if (ret) {
			LSXINIC_PMD_ERR("%s: IB win[%d] size(0x%lx) set failed",
				lsinic_dev->name, LSX_PCIEP_REG_BAR_IDX, size_reg);

			return ret;
		}

		ret = rte_lsx_pciep_set_ib_win(lsinic_dev,
			LSX_PCIEP_RING_BAR_IDX, size_ring);
		if (ret) {
			LSXINIC_PMD_ERR("%s: IB win[%d] size(0x%lx) set failed",
				lsinic_dev->name, LSX_PCIEP_RING_BAR_IDX, size_ring);

			return ret;
		}
	}

	/**Always mark reg bar noncache.*/
	rte_lsx_pciep_ib_cache_mark(lsinic_dev, LSX_PCIEP_REG_BAR_IDX, 0);

	if (sim && !lsinic_dev->is_vf &&
		!(adapter->cap & LSINIC_CAP_XFER_HOST_ACCESS_EP_MEM)) {
		ret = rte_lsx_pciep_sim_dev_map_inbound(lsinic_dev);
		if (ret) {
			LSXINIC_PMD_ERR("%s: sim map IB failed(%d)",
				lsinic_dev->name, ret);
			return ret;
		}
	}

	if (lsinic_dev->single_bar) {
		base_vir = lsinic_dev->virt_addr[LSX_PCIEP_REG_BAR_IDX];
		base_phy = lsinic_dev->iov_addr[LSX_PCIEP_REG_BAR_IDX];
		adapter->hw_addr = base_vir;
		adapter->ep_ring_virt_base = base_vir + lsinic_reg_ring_bar_offset(0);
		adapter->ep_ring_phy_base = base_phy + lsinic_reg_ring_bar_offset(0);
		adapter->bd_desc_base =
			adapter->ep_ring_virt_base + LSINIC_RING_BD_OFFSET;

		return 0;
	}

	adapter->hw_addr =
		lsinic_dev->virt_addr[LSX_PCIEP_REG_BAR_IDX];
	adapter->ep_ring_virt_base =
		lsinic_dev->virt_addr[LSX_PCIEP_RING_BAR_IDX];
	adapter->ep_ring_phy_base =
		lsinic_dev->iov_addr[LSX_PCIEP_RING_BAR_IDX];
	adapter->bd_desc_base =
		adapter->ep_ring_virt_base + LSINIC_RING_BD_OFFSET;

	return 0;
}

static int
lsinic_uninit_bar_addr(struct rte_lsx_pciep_device *lsinic_dev)
{
	struct rte_eth_dev *eth_dev = lsinic_dev->eth_dev;
	struct lsinic_adapter *adapter = eth_dev->process_private;
	int sim = rte_lsx_pciep_hw_sim_get(adapter->pcie_idx), ret;

	if (adapter->rc_ring_bus_base && !sim) {
		ret = rte_lsx_pciep_unset_ob_win(lsinic_dev,
			adapter->rc_ring_bus_base);
		if (ret) {
			LSXINIC_PMD_ERR("%s: unset PCIe addr(0x%lx) failed(%d)",
				lsinic_dev->name,
				adapter->rc_ring_bus_base, ret);
			return ret;
		}
	}
	adapter->rc_ring_bus_base = 0;
	adapter->rc_ring_phy_base = 0;
	adapter->rc_ring_size = 0;
	adapter->rc_ring_virt_base = NULL;

	ret = rte_lsx_pciep_unset_ib_win(lsinic_dev,
			LSX_PCIEP_REG_BAR_IDX);
	if (ret) {
		LSXINIC_PMD_ERR("%s: unset IB(%d) failed(%d)",
			lsinic_dev->name,
			LSX_PCIEP_REG_BAR_IDX, ret);
		return ret;
	}
	ret = rte_lsx_pciep_unset_ib_win(lsinic_dev,
			LSX_PCIEP_RING_BAR_IDX);
	if (ret) {
		LSXINIC_PMD_ERR("%s: unset IB(%d) failed(%d)",
			lsinic_dev->name,
			LSX_PCIEP_RING_BAR_IDX, ret);
		return ret;
	}
	/*memzone for LSX_PCIEP_XFER_MEM_BAR_IDX is maintained by apps*/

	adapter->hw_addr = NULL;
	adapter->bd_desc_base = NULL;
	adapter->ep_ring_virt_base = NULL;
	adapter->pf_idx = 0;
	adapter->is_vf = 0;
	adapter->vf_idx = 0;
	adapter->pcie_idx = 0;

	return 0;
}

static int
lsinic_release_dma(struct rte_lsx_pciep_device *lsinic_dev)
{
	struct rte_eth_dev *eth_dev = lsinic_dev->eth_dev;
	struct lsinic_adapter *adapter = (struct lsinic_adapter *)
		eth_dev->process_private;
	int ret;

	ret = lsinic_dma_release(adapter->txq_dma_id);
	if (ret)
		return ret;
	adapter->txq_dma_id = -1;
	adapter->txq_dma_vchan_used = 0;
	adapter->txq_dma_started = 0;

	ret = lsinic_dma_release(adapter->rxq_dma_id);
	if (ret)
		return ret;
	adapter->rxq_dma_id = -1;
	adapter->rxq_dma_vchan_used = 0;
	adapter->rxq_dma_started = 0;

	return 0;
}

static int
lsinic_dev_config_init(struct lsinic_adapter *adapter)
{
	uint64_t size;
	struct lsinic_dev_reg *cfg = LSINIC_REG_OFFSET(adapter->hw_addr,
			LSINIC_DEV_REG_OFFSET);
	struct rte_lsx_pciep_device *lsinic_dev = adapter->lsinic_dev;

	cfg->rev = INIC_VERSION;
	cfg->rx_ring_max_num = adapter->max_qpairs;
	cfg->rx_entry_max_num = LSINIC_BD_ENTRY_COUNT;
	cfg->tx_ring_max_num = adapter->max_qpairs;
	cfg->tx_entry_max_num = LSINIC_BD_ENTRY_COUNT;
	cfg->dev_reg_offset = LSINIC_ETH_REG_OFFSET;
	if (adapter->is_vf)
		cfg->vf_idx = adapter->vf_idx | LSXINIC_VF_AVAILABLE;
	else
		cfg->vf_idx = 0;
	cfg->pf_idx = adapter->pf_idx;
	cfg->vf_num = PCIE_MAX_VF_NUM;

	size = rte_lsx_pciep_bus_ob_dma_size(lsinic_dev);
	cfg->obwin_size = rte_log2_u64(size);

	return 0;
}

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
int
lsinic_split_dev_flow_create(struct lsinic_adapter *adapter)
{
	struct rte_dpaa2_device *split_dev = adapter->split_dev;
	struct rte_dpaa2_device *split_dst_dev = adapter->split_dst_dev;
	uint16_t split_id, dst_id;
	struct rte_flow_attr flow_attr;
	struct rte_flow_item flow_item[2];
	struct rte_flow_action flow_action[2];
	struct rte_flow_item_eth spec, mask;
	struct rte_flow_action_port_id dst_port;
	char dst_name[RTE_ETH_NAME_MAX_LEN];
	char split_name[RTE_ETH_NAME_MAX_LEN];

	if (split_dev && split_dst_dev) {
		split_id = split_dev->eth_dev->data->port_id;
		dst_id = split_dst_dev->eth_dev->data->port_id;
		memcpy(dst_name, split_dst_dev->eth_dev->data->name,
			RTE_ETH_NAME_MAX_LEN);
		memcpy(split_name, split_dev->eth_dev->data->name,
			RTE_ETH_NAME_MAX_LEN);
		memset(&flow_attr, 0, sizeof(struct rte_flow_attr));
		memset(flow_item, 0, 2 * sizeof(struct rte_flow_item));
		memset(flow_action, 0, 2 * sizeof(struct rte_flow_action));
		memset(&spec, 0, sizeof(struct rte_flow_item_eth));
		memset(&mask, 0, sizeof(struct rte_flow_item_eth));
		memset(&dst_port, 0, sizeof(struct rte_flow_action_port_id));

		flow_attr.group = 0;
		flow_attr.priority = 0;
		flow_attr.egress = 1;

		flow_item[0].type = RTE_FLOW_ITEM_TYPE_ETH;
		spec.type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
		mask.type = 0xffff;
		flow_item[0].spec = &spec;
		flow_item[0].mask = &mask;
		flow_item[1].type = RTE_FLOW_ITEM_TYPE_END;

		flow_action[0].type = RTE_FLOW_ACTION_TYPE_PORT_ID;
		dst_port.original = 0;
		dst_port.id = dst_id;
		flow_action[0].conf = &dst_port;
		flow_action[1].type = RTE_FLOW_ACTION_TYPE_END;

		if (rte_flow_create(split_id, &flow_attr, &flow_item[0],
			&flow_action[0], NULL))
			LSXINIC_PMD_INFO("Redirect ipv4 to %s by %s",
				dst_name, split_name);
		else
			LSXINIC_PMD_ERR("Unable redirect ipv4 to %s by %s",
				dst_name, split_name);

		return 0;
	}

	return -1;
}

static inline struct rte_dpaa2_device *
lsinic_dev_id_to_dpaa2_dev(int eth_id)
{
	struct rte_dpaa2_device *dpaa2_dev = NULL;
	struct rte_device *rdev;

	if (eth_id >= 0 && eth_id < RTE_MAX_ETHPORTS &&
		rte_pmd_dpaa2_dev_is_dpaa2(eth_id)) {
		rdev = rte_eth_devices[eth_id].device;
		dpaa2_dev = container_of(rdev,
			struct rte_dpaa2_device, device);
	}

	return dpaa2_dev;
}
#endif

static void
lsinic_parse_rxq_cnf_type(const char *cnf_env,
	struct lsinic_adapter *adapter)
{
	char *penv = getenv(cnf_env);

	if (!penv)
		return;

	if (atoi(penv) == RC_XMIT_BD_CNF) {
		LSINIC_CAP_XFER_RC_XMIT_CNF_TYPE_SET(adapter->cap,
			RC_XMIT_BD_CNF);
	} else if (atoi(penv) == RC_XMIT_RING_CNF) {
		LSINIC_CAP_XFER_RC_XMIT_CNF_TYPE_SET(adapter->cap,
			RC_XMIT_RING_CNF);
	} else if (atoi(penv) == RC_XMIT_INDEX_CNF) {
		LSINIC_CAP_XFER_RC_XMIT_CNF_TYPE_SET(adapter->cap,
			RC_XMIT_INDEX_CNF);
	} else {
		LSXINIC_PMD_INFO("%s:%d-%s,%d-%s,%d-%s",
			cnf_env,
			RC_XMIT_BD_CNF, "BD confirm",
			RC_XMIT_RING_CNF, "RING confirm",
			RC_XMIT_INDEX_CNF, "INDEX confirm");
	}
}

static void
lsinic_parse_txq_notify_type(const char *notify_env,
	struct lsinic_adapter *adapter)
{
	char *penv = getenv(notify_env);

	if (!penv)
		return;

	if (atoi(penv) == EP_XMIT_LBD_TYPE) {
		LSINIC_CAP_XFER_EP_XMIT_BD_TYPE_SET(adapter->cap,
			EP_XMIT_LBD_TYPE);
	} else if (atoi(penv) == EP_XMIT_SBD_TYPE) {
		LSINIC_CAP_XFER_EP_XMIT_BD_TYPE_SET(adapter->cap,
			EP_XMIT_SBD_TYPE);
	} else {
		LSXINIC_PMD_INFO("%s:%d-%s,%d-%s",
			notify_env,
			EP_XMIT_LBD_TYPE, "LBD notify",
			EP_XMIT_SBD_TYPE, "SBD notify");
	}
}

static int
lsinic_netdev_env_init(struct rte_eth_dev *eth_dev)
{
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	char env_name[128];
#endif
	char *penv;
	uint16_t max_qpairs;
	struct lsinic_adapter *adapter = eth_dev->process_private;
	struct rte_lsx_pciep_device *lsinic_dev = adapter->lsinic_dev;
	enum PEX_TYPE pex_type =
		rte_lsx_pciep_type_get(lsinic_dev->pcie_id);
	const char *cnf_env = "LSINIC_EP_RXQ_CONFIRM";
	const char *notify_env = "LSINIC_EP_TXQ_NOTIFY";

	penv = getenv("LSINIC_SINGLE_BAR");
	if (penv && atoi(penv) > 0)
		lsinic_dev->single_bar = true;

	adapter->max_qpairs = LSINIC_RING_DEFAULT_MAX_QP;
	penv = getenv("LSINIC_RING_MAX_QUEUE_PAIRS");
	if (penv && atoi(penv) > 0) {
		max_qpairs = atoi(penv);
		if (rte_is_power_of_2(max_qpairs)) {
			if (max_qpairs > LSINIC_RING_MAX_COUNT) {
				LSXINIC_PMD_ERR("Max qpair(%d) > MAX(%d)",
					max_qpairs, LSINIC_RING_MAX_COUNT);
			} else {
				adapter->max_qpairs = max_qpairs;
			}
		} else {
			LSXINIC_PMD_ERR("Max qpair(%d) is not power of 2",
				max_qpairs);
		}
	}
	adapter->ep_cap = LSINIC_EP_CAP_TXQ_SG_DMA;
	adapter->ep_cap |= LSINIC_EP_CAP_RXQ_SG_DMA;
	adapter->ep_cap |= LSINIC_EP_CAP_TXQ_BD_DMA_UPDATE;

	penv = getenv("LSINIC_QDMA_SG_ENABLE");
	if (penv && atoi(penv)) {
		adapter->ep_cap |= LSINIC_EP_CAP_TXQ_SG_DMA;
		adapter->ep_cap |= LSINIC_EP_CAP_RXQ_SG_DMA;
	} else if (penv && !atoi(penv)) {
		adapter->ep_cap &= ~LSINIC_EP_CAP_TXQ_SG_DMA;
		adapter->ep_cap &= ~LSINIC_EP_CAP_RXQ_SG_DMA;
	}

	/* NO TX DMA RSP and write BD to RC by DMA as well.*/
	penv = getenv("LSINIC_TXQ_QDMA_NO_RESPONSE");
	if (penv && atoi(penv)) {
		adapter->ep_cap |= LSINIC_EP_CAP_TXQ_DMA_NO_RSP;
		adapter->ep_cap |= LSINIC_EP_CAP_TXQ_SG_DMA;
		adapter->ep_cap |= LSINIC_EP_CAP_TXQ_BD_DMA_UPDATE;
	} else if (penv && !atoi(penv)) {
		adapter->ep_cap &= ~LSINIC_EP_CAP_TXQ_DMA_NO_RSP;
	}

	penv = getenv("LSINIC_TXQ_QDMA_BD_UPDATE");
	if (penv && atoi(penv)) {
		adapter->ep_cap |= LSINIC_EP_CAP_TXQ_SG_DMA;
		adapter->ep_cap |= LSINIC_EP_CAP_TXQ_BD_DMA_UPDATE;
	} else if (penv && !atoi(penv)) {
		adapter->ep_cap &= LSINIC_EP_CAP_TXQ_BD_DMA_UPDATE;
	}

	/* Above capability is handled only on EP side and no sensible to RC.*/

	if (0) {
		/* Disable BD read by DMA by default,
		 * this is workaround to fix one-way traffic halt between PFs.
		 */
		adapter->cap = LSINIC_CAP_RC_XFER_BD_DMA_UPDATE;
		adapter->cap |= LSINIC_CAP_RC_RECV_ADDR_DMA_UPDATE;
	}

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	penv = getenv("LSINIC_MERGE_PACKETS");
	if (penv && atoi(penv))
		adapter->cap |= LSINIC_CAP_XFER_PKT_MERGE;
#endif
	penv = getenv("LSINIC_RC_XFER_SEGMENT_OFFLOAD");
	if (penv && atoi(penv))
		adapter->cap |= LSINIC_CAP_RC_XFER_SEGMENT_OFFLOAD;

	penv = getenv("LSINIC_RC_RECV_SEGMENT_OFFLOAD");
	if (penv && atoi(penv))
		adapter->cap |= LSINIC_CAP_RC_RECV_SEGMENT_OFFLOAD;

	penv = getenv("LSINIC_RXQ_QDMA_BD_UPDATE");
	if (penv && atoi(penv))
		adapter->cap |= LSINIC_CAP_RC_XFER_BD_DMA_UPDATE;
	else if (penv && !atoi(penv))
		adapter->cap &= ~LSINIC_CAP_RC_XFER_BD_DMA_UPDATE;

	if (adapter->cap & LSINIC_CAP_RC_XFER_BD_DMA_UPDATE) {
		penv = getenv("LSINIC_RXQ_QDMA_BD_UPDATE_DBG");
		if (penv && atoi(penv))
			adapter->ep_cap |= LSINIC_EP_CAP_RXQ_BD_DMA_UPDATE_DBG;
	}

	penv = getenv("LSINIC_TXQ_QDMA_ADDR_READ");
	if (penv && atoi(penv))
		adapter->cap |= LSINIC_CAP_RC_RECV_ADDR_DMA_UPDATE;
	else if (penv && !atoi(penv))
		adapter->cap &= ~LSINIC_CAP_RC_RECV_ADDR_DMA_UPDATE;

	if (adapter->cap & LSINIC_CAP_RC_RECV_ADDR_DMA_UPDATE) {
		penv = getenv("LSINIC_TXQ_QDMA_ADDR_READ_DBG");
		if (penv && atoi(penv))
			adapter->ep_cap |= LSINIC_EP_CAP_TXQ_ADDR_DMA_READ_DBG;
	}

	penv = getenv("LSINIC_RXQ_QDMA_NO_RESPONSE");
	if (penv && atoi(penv))
		adapter->cap |= LSINIC_CAP_XFER_COMPLETE;

	if (adapter->cap & LSINIC_CAP_XFER_COMPLETE) {
		/** Index confirm as default*/
		LSINIC_CAP_XFER_RC_XMIT_CNF_TYPE_SET(adapter->cap,
			RC_XMIT_INDEX_CNF);
		lsinic_parse_rxq_cnf_type(cnf_env, adapter);
	}

	LSINIC_CAP_XFER_EP_XMIT_BD_TYPE_SET(adapter->cap,
		EP_XMIT_SBD_TYPE);
	lsinic_parse_txq_notify_type(notify_env, adapter);

	penv = getenv(LSINIC_EP_MAP_MEM_ENV);
	if (penv && atoi(penv))
		adapter->cap |= LSINIC_CAP_XFER_HOST_ACCESS_EP_MEM;

	if ((adapter->ep_cap & LSINIC_EP_CAP_TXQ_BD_DMA_UPDATE) &&
		LSINIC_CAP_XFER_EP_XMIT_BD_TYPE_GET(adapter->cap) ==
		EP_XMIT_SBD_TYPE)
		adapter->cap |= LSINIC_CAP_XFER_ORDER_PRSV;

	if (adapter->rbp_enable && pex_type == PEX_LX2160_REV1 &&
		(adapter->ep_cap &
		(LSINIC_EP_CAP_TXQ_SG_DMA |
		LSINIC_EP_CAP_RXQ_SG_DMA)))
		return -ENOTSUP;

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	if (!(adapter->cap & LSINIC_CAP_XFER_PKT_MERGE))
		return 0;

	penv = getenv("LSXINIC_PMD_RCV_MERGE_RECYCLE_DEV");
	if (penv && atoi(penv))
		adapter->ep_cap |= LSINIC_EP_CAP_RCV_MERGE_RECYCLE_RX;

	penv = getenv("LSXINIC_PMD_RCV_SPLIT_RECYCLE_DEV");
	if (penv && atoi(penv))
		adapter->ep_cap |= LSINIC_EP_CAP_RCV_SPLIT_RECYCLE_RX;

	/** Direct MAC egress. */
	if (lsinic_dev->is_vf) {
		sprintf(env_name, "LSXINIC_PCIE%d_PF%d_VF%d_EGRESS",
			lsinic_dev->pcie_id, lsinic_dev->pf,
			lsinic_dev->vf);
	} else {
		sprintf(env_name, "LSXINIC_PCIE%d_PF%d_EGRESS",
			lsinic_dev->pcie_id, lsinic_dev->pf);
	}
	penv = getenv(env_name);
	if (penv) {
		adapter->split_dev =
			lsinic_dev_id_to_dpaa2_dev(atoi(penv));
		if (adapter->split_dev)
			adapter->ep_cap |= LSINIC_EP_CAP_HW_DIRECT_EGRESS;
	}

	/** Split traffic from PCIe host by recycle port. */
	if (!adapter->split_dev) {
		if (lsinic_dev->is_vf) {
			sprintf(env_name, "LSXINIC_PCIE%d_PF%d_VF%d_HW_SPLIT",
				lsinic_dev->pcie_id, lsinic_dev->pf,
				lsinic_dev->vf);
		} else {
			sprintf(env_name, "LSXINIC_PCIE%d_PF%d_HW_SPLIT",
				lsinic_dev->pcie_id, lsinic_dev->pf);
		}

		penv = getenv(env_name);
		if (penv) {
			adapter->split_dev =
				lsinic_dev_id_to_dpaa2_dev(atoi(penv));
		}

		/** Apply rule on recycle port to fwd traffic by HW. */
		if (adapter->is_vf) {
			sprintf(env_name, "LSXINIC_PCIE%d_PF%d_VF%d_SPLIT_DST",
				lsinic_dev->pcie_id, lsinic_dev->pf,
				lsinic_dev->vf);
		} else {
			sprintf(env_name, "LSXINIC_PCIE%d_PF%d_SPLIT_DST",
				lsinic_dev->pcie_id, lsinic_dev->pf);
		}
		penv = getenv(env_name);
		if (penv) {
			adapter->split_dst_dev =
				lsinic_dev_id_to_dpaa2_dev(atoi(penv));
		}
	}

	if (adapter->split_dev) {
		adapter->ep_cap |= LSINIC_EP_CAP_HW_SPLIT_PKTS;
		if (adapter->ep_cap & LSINIC_EP_CAP_HW_DIRECT_EGRESS) {
			LSXINIC_PMD_INFO("Traffic from %s is directed to %s",
				eth_dev->data->name,
				adapter->split_dev->eth_dev->data->name);
		} else {
			LSXINIC_PMD_INFO("Traffic from %s is splited by %s",
				eth_dev->data->name,
				adapter->split_dev->eth_dev->data->name);
		}
	}

	if (lsinic_dev->is_vf) {
		sprintf(env_name, "LSXINIC_PCIE%d_PF%d_VF%d_HW_MERGE",
			lsinic_dev->pcie_id, lsinic_dev->pf,
			lsinic_dev->vf);
	} else {
		sprintf(env_name, "LSXINIC_PCIE%d_PF%d_HW_MERGE",
			lsinic_dev->pcie_id, lsinic_dev->pf);
	}
	penv = getenv(env_name);
	if (penv) {
		adapter->merge_dev = lsinic_dev_id_to_dpaa2_dev(atoi(penv));
		if (adapter->merge_dev)
			adapter->ep_cap |= LSINIC_EP_CAP_HW_MERGE_PKTS;
	}

	if (lsinic_dev->is_vf) {
		sprintf(env_name, "LSXINIC_PCIE%d_PF%d_VF%d_MERGE_THRESHOLD",
			lsinic_dev->pcie_id, lsinic_dev->pf,
			lsinic_dev->vf);
	} else {
		sprintf(env_name, "LSXINIC_PCIE%d_PF%d_MERGE_THRESHOLD",
			lsinic_dev->pcie_id, lsinic_dev->pf);
	}
	penv = getenv(env_name);
	if (penv) {
		adapter->merge_threshold = atoi(penv);
		if (adapter->merge_threshold <
			(RTE_ETHER_MIN_LEN - RTE_ETHER_CRC_LEN)) {
			LSXINIC_PMD_WARN("Invalid merge threshold %d",
				adapter->merge_threshold);
			adapter->merge_threshold =
				LSINIC_MERGE_DEFAULT_THRESHOLD;
		}
	} else {
		adapter->merge_threshold =
			LSINIC_MERGE_DEFAULT_THRESHOLD;
	}

	if (!(adapter->ep_cap & LSINIC_EP_CAP_HW_SPLIT_PKTS)) {
		if (lsinic_dev->is_vf) {
			sprintf(env_name,
				"LSXINIC_PCIE%d_PF%d_VF%d_CLONE_SPLIT",
				lsinic_dev->pcie_id, lsinic_dev->pf,
				lsinic_dev->vf);
		} else {
			sprintf(env_name,
				"LSXINIC_PCIE%d_PF%d_CLONE_SPLIT",
				lsinic_dev->pcie_id, lsinic_dev->pf);
		}
		penv = getenv(env_name);
		if (penv && atoi(penv) > 0)
			adapter->ep_cap |= LSINIC_EP_CAP_MBUF_CLONE_SPLIT_PKTS;
	}

	if (!(adapter->ep_cap & LSINIC_EP_CAP_HW_MERGE_PKTS))
		adapter->ep_cap |= LSINIC_EP_CAP_SW_MERGE_PKTS;

	if (!((adapter->ep_cap & LSINIC_EP_CAP_HW_SPLIT_PKTS) ||
		(adapter->ep_cap & LSINIC_EP_CAP_MBUF_CLONE_SPLIT_PKTS)))
		adapter->ep_cap |= LSINIC_EP_CAP_SW_SPLIT_PKTS;

	if (adapter->ep_cap & LSINIC_EP_CAP_HW_DIRECT_EGRESS)
		adapter->ep_cap &= ~LSINIC_EP_CAP_RCV_SPLIT_RECYCLE_RX;
#endif

	return 0;
}

static void
lsinic_netdev_reg_init(struct lsinic_adapter *adapter)
{
	int i;
	uint32_t macaddrl = 0;
	uint32_t macaddrh = 0;
	struct lsinic_eth_reg *reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_ETH_REG_OFFSET);
	struct rte_eth_dev *eth_dev = adapter->lsinic_dev->eth_dev;

	lsinic_byte_memset(reg, 0, sizeof(*reg));

	LSINIC_WRITE_REG(&reg->max_qpairs, adapter->max_qpairs);
	LSINIC_WRITE_REG(&reg->rev, INIC_VERSION);
	if (adapter->is_vf) {
		LSINIC_WRITE_REG(&reg->fmidx,
			(adapter->pcie_idx << 24) |
			(adapter->pf_idx << 16) |
			LSXINIC_VF_AVAILABLE | adapter->vf_idx);
		LSINIC_WRITE_REG(&reg->macidx,
			(adapter->pcie_idx << 24) |
			(adapter->pf_idx << 16) |
			LSXINIC_VF_AVAILABLE | adapter->vf_idx);
	} else {
		LSINIC_WRITE_REG(&reg->fmidx,
			(adapter->pcie_idx << 24) |
			(adapter->pf_idx << 16));
		LSINIC_WRITE_REG(&reg->macidx,
			(adapter->pcie_idx << 24) |
			(adapter->pf_idx << 16));
	}

	LSINIC_WRITE_REG(&reg->tx_ring_num, 0);
	LSINIC_WRITE_REG(&reg->rx_ring_num, 0);
	LSINIC_WRITE_REG(&reg->tx_entry_num, LSINIC_BD_ENTRY_COUNT);
	LSINIC_WRITE_REG(&reg->rx_entry_num, LSINIC_BD_ENTRY_COUNT);

	LSINIC_WRITE_REG(&reg->cap, adapter->cap);

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	LSINIC_WRITE_REG(&reg->merge_threshold, adapter->merge_threshold);
#endif

	memcpy(adapter->mac_addr,
		eth_dev->data->mac_addrs->addr_bytes,
		RTE_ETHER_ADDR_LEN);

	/* write mac */
	for (i = 0; i < 4; i++)
		macaddrl |= (uint32_t)adapter->mac_addr[5 - i]
				 << (i * 8);
	for (i = 0; i < 2; i++)
		macaddrh |= (uint32_t)adapter->mac_addr[1 - i]
				 << (i * 8);

	LSINIC_WRITE_REG(&reg->macaddrh, macaddrh);
	LSINIC_WRITE_REG(&reg->macaddrl, macaddrl);
}

static void
lsinic_mac_init(struct rte_ether_addr *mac_addrs,
	struct rte_lsx_pciep_device *lsinic_dev)
{
	int pf_idx = lsinic_dev->pf;
	int vf_idx = lsinic_dev->vf;
	int is_vf = lsinic_dev->is_vf;

	/* 00:e0:0c:fm_idx-mac_idx:mac_type-PF index: VF index */
	mac_addrs->addr_bytes[0] = 0x00;
	mac_addrs->addr_bytes[1] = 0xe0;
	mac_addrs->addr_bytes[2] = 0x0c;
	mac_addrs->addr_bytes[3] = pf_idx + 1;
	mac_addrs->addr_bytes[4] = is_vf;
	mac_addrs->addr_bytes[5] = vf_idx;
}

/* rte_lsinic_probe:
 *
 * Interrupt is used only for link status notification on dpdk.
 * we don't think about the interrupt handlle situation right now.
 * we can port our MSIX interrupt in iNIC host driver to dpdk,
 * need to test the performance.
 */

static int
rte_lsinic_probe(struct rte_lsx_pciep_driver *lsinic_drv,
	struct rte_lsx_pciep_device *lsinic_dev)
{
	struct rte_eth_dev *eth_dev = NULL;
	struct lsinic_adapter *adapter = NULL;
	int err, end;

	end = LSINIC_RING_REG_OFFSET + sizeof(struct lsinic_bdr_reg);
	if (end > LSINIC_RING_BD_OFFSET) {
		rte_panic("%s(%d) > %s(%d)", "RING REG end",
			end, "RING BD offset", LSINIC_RING_BD_OFFSET);
	}

	end = LSINIC_DEV_REG_OFFSET + sizeof(struct lsinic_dev_reg);
	if (end > LSINIC_RCS_REG_OFFSET) {
		rte_panic("%s(%d) > %s(%d)", "DEV REG end",
			end, "RCS REG offset", LSINIC_RCS_REG_OFFSET);
	}

	end = LSINIC_RCS_REG_OFFSET + sizeof(struct lsinic_rcs_reg);
	if (end > LSINIC_ETH_REG_OFFSET) {
		rte_panic("%s(%d) > %s(%d)", "RCS REG end",
			end, "ETH REG offset", LSINIC_ETH_REG_OFFSET);
	}

	if (lsinic_dev->init_flag) {
		LSXINIC_PMD_ERR("pf:%d vf:%d has been initialized!",
			lsinic_dev->pf, lsinic_dev->vf);
		return 0;
	}

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		eth_dev = rte_eth_dev_allocate(lsinic_dev->device.name);
		if (!eth_dev) {
			LSXINIC_PMD_ERR("Cannot allocate eth_dev");
			return -ENODEV;
		}
	} else {
		eth_dev = rte_eth_dev_attach_secondary(lsinic_dev->device.name);
		if (!eth_dev) {
			LSXINIC_PMD_ERR("Cannot attach eth_dev");
			return -ENODEV;
		}
	}

	adapter = rte_zmalloc("ethdev process private adapter",
				sizeof(struct lsinic_adapter),
				RTE_CACHE_LINE_SIZE);
	if (!adapter) {
		LSXINIC_PMD_ERR("Cannot allocate memzone for private data");
		rte_eth_dev_release_port(eth_dev);
		return -ENOMEM;
	}
	eth_dev->process_private = adapter;

	adapter->dev_type = LSINIC_NXP_DEV;
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	adapter->merge_dev = NULL;
	adapter->split_dev = NULL;
	rte_spinlock_init(&adapter->merge_dev_cfg_lock);
	rte_spinlock_init(&adapter->split_dev_cfg_lock);
	adapter->merge_dev_cfg_done = 0;
	adapter->split_dev_cfg_done = 0;
#endif
	rte_spinlock_init(&adapter->cap_lock);
	rte_spinlock_init(&adapter->txq_dma_start_lock);
	rte_spinlock_init(&adapter->rxq_dma_start_lock);
	adapter->lsinic_dev = lsinic_dev;

	eth_dev->device = &lsinic_dev->device;
	eth_dev->device->driver = &lsinic_drv->driver;
	lsinic_dev->driver = lsinic_drv;
	lsinic_dev->eth_dev = eth_dev;
	lsinic_dev->chk_eth_status = lsinic_dev_chk_eth_status;
	eth_dev->data->rx_mbuf_alloc_failed = 0;

	eth_dev->dev_ops = &lsinic_eth_dev_ops;
	eth_dev->rx_pkt_burst = lsinic_recv_pkts;
	eth_dev->tx_pkt_burst = lsinic_xmit_pkts;

	/* Allocate memory for storing MAC addresses */
	if (!eth_dev->data->mac_addrs) {
		eth_dev->data->mac_addrs =
			rte_zmalloc("lsinic", RTE_ETHER_ADDR_LEN, 0);
		if (!eth_dev->data->mac_addrs) {
			LSXINIC_PMD_ERR("Failed to allocate MAC address");
			return -ENOMEM;
		}

		lsinic_mac_init(eth_dev->data->mac_addrs, lsinic_dev);
	}
	err = lsinic_netdev_env_init(eth_dev);
	if (err) {
		LSXINIC_PMD_ERR("%s init env failed(%d)",
			eth_dev->data->name, err);
		return err;
	}
	lsinic_dev->init_flag = 1;

	rte_eth_dev_probing_finish(eth_dev);
	return 0;
}

#ifdef LSXINIC_LATENCY_PROFILING
static uint64_t s_cycs_per_us;
static uint64_t
calculate_cycles_per_us(void)
{
	uint64_t start_cycles, end_cycles;

	if (s_cycs_per_us)
		return s_cycs_per_us;

	start_cycles = rte_get_timer_cycles();
	rte_delay_ms(1000);
	end_cycles = rte_get_timer_cycles();
	s_cycs_per_us = (end_cycles - start_cycles) / (1000 * 1000);
	LSXINIC_PMD_INFO("Cycles per us is: %ld",
		(unsigned long)s_cycs_per_us);

	return s_cycs_per_us;
}
#endif

static inline uint16_t
lsinic_dev_pcie_dev_id(void)
{
	FILE *svr_file = NULL;
	uint32_t svr_ver, i, num;

	svr_file = fopen("/sys/devices/soc0/soc_id", "r");
	if (!svr_file) {
		LSXINIC_PMD_ERR("Unable to open SoC device.");
		return 0;
	}
	if (fscanf(svr_file, "svr:%x", &svr_ver) < 0) {
		LSXINIC_PMD_ERR("Unable to read SoC device");
		fclose(svr_file);
		return 0;
	}

	fclose(svr_file);

	num = sizeof(s_lsinic_rev2_id_map) /
		sizeof(struct lsinic_pcie_svr_map);

	for (i = 0; i < num; i++) {
		if (s_lsinic_rev2_id_map[i].svr_id == svr_ver)
			return s_lsinic_rev2_id_map[i].pci_dev_id;
	}

	return 0;
}

static int
lsinic_dev_configure(struct rte_eth_dev *eth_dev)
{
	struct lsinic_adapter *adapter = eth_dev->process_private;
	struct rte_lsx_pciep_device *lsinic_dev = adapter->lsinic_dev;
	uint16_t vendor_id, device_id, class_id;
	enum PEX_TYPE pex_type =
		rte_lsx_pciep_type_get(lsinic_dev->pcie_id);
	char env_name[128];
	char *penv;
	int err, dma_silent;

	vendor_id = NXP_PCI_VENDOR_ID;
	class_id = NXP_PCI_CLASS_ID;
	if (pex_type == PEX_LX2160_REV2)
		device_id = lsinic_dev_pcie_dev_id();
	else if (pex_type == PEX_LX2160_REV1)
		device_id = NXP_PCI_DEV_ID_LX2160A_DEFAULT;
	else if (pex_type == PEX_LS208X)
		device_id = NXP_PCI_DEV_ID_LS2088A;
	else
		device_id = NXP_PCI_DEV_ID_NULL;

	if (!lsinic_dev->is_vf) {
		sprintf(env_name, "LSINIC_PCIE%d_PF%d_VENDOR_ID",
			lsinic_dev->pcie_id, lsinic_dev->pf);
		penv = getenv(env_name);
		if (penv)
			vendor_id = strtol(penv, 0, 16);
		sprintf(env_name, "LSINIC_PCIE%d_PF%d_DEVICE_ID",
			lsinic_dev->pcie_id, lsinic_dev->pf);
		penv = getenv(env_name);
		if (penv)
			device_id = strtol(penv, 0, 16);
		sprintf(env_name, "LSINIC_PCIE%d_PF%d_CLASS_ID",
			lsinic_dev->pcie_id, lsinic_dev->pf);
		penv = getenv(env_name);
		if (penv)
			class_id = strtol(penv, 0, 16);
	} else {
		sprintf(env_name, "LSINIC_PCIE%d_PF%d_VF_DEVICE_ID",
			lsinic_dev->pcie_id, lsinic_dev->pf);
		penv = getenv(env_name);
		if (penv)
			device_id = strtol(penv, 0, 16);
	}

	err = rte_lsx_pciep_fun_config(vendor_id,
			device_id, class_id,
			/** Reuse vendor ID and device ID for
			 * sub vendor ID and sub device ID.
			 */
			vendor_id, device_id,
			lsinic_dev->pcie_id,
			lsinic_dev->pf, lsinic_dev->is_vf,
			lsinic_dev->vf);
	if (err)
		return err;

	err = lsinic_init_bar_addr(lsinic_dev);
	if (err)
		return err;

	adapter->rbp_enable = rte_lsx_pciep_hw_rbp_get(adapter->pcie_idx);

	if (adapter->ep_cap & LSINIC_EP_CAP_TXQ_DMA_NO_RSP)
		dma_silent = 1;
	else
		dma_silent = 0;
	err = lsinic_dma_acquire(dma_silent,
		adapter->max_qpairs,
		LSINIC_BD_ENTRY_COUNT,
		LSINIC_DMA_MEM_TO_PCIE,
		&adapter->txq_dma_id);
	if (err)
		return err;
	adapter->txq_dma_silent = dma_silent;

	if (adapter->cap & LSINIC_CAP_XFER_COMPLETE)
		dma_silent = 1;
	else
		dma_silent = 0;
	err = lsinic_dma_acquire(dma_silent,
		adapter->max_qpairs,
		LSINIC_BD_ENTRY_COUNT,
		LSINIC_DMA_PCIE_TO_MEM,
		&adapter->rxq_dma_id);
	if (err)
		return err;
	adapter->rxq_dma_silent = dma_silent;

	lsinic_netdev_reg_init(adapter);
	lsinic_dev_config_init(adapter);

	err = lsinic_txrx_queues_create(adapter);
	if (err)
		return -ENODEV;

	/* setup the private structure */
	err = lsinic_sw_init(adapter);
	if (err) {
		LSXINIC_PMD_ERR("lsinic_sw_init failed");
		return -ENODEV;
	}
	lsinic_set_init_flag(adapter, lsinic_dev->single_bar);
	lsinic_set_netdev(adapter, PCIDEV_COMMAND_INIT);
#ifdef LSXINIC_LATENCY_PROFILING
	adapter->cycs_per_us = calculate_cycles_per_us();
#endif

	return 0;
}

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
static int
lsinic_dev_recycle_start(struct rte_eth_dev *recycle_dev,
	int nb_tx_queues, int nb_rx_queues,
	uint16_t nb_tx_desc, uint16_t nb_rx_desc,
	const struct rte_eth_conf *port_conf,
	struct rte_mempool *mb_pool)
{
	const struct eth_dev_ops *dev_ops;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rxconf rxconf;
	struct rte_eth_txconf txconf;
	int ret, qnb;

	if (recycle_dev->data->dev_started)
		return 0;

	dev_ops = recycle_dev->dev_ops;
	RTE_ASSERT(dev_ops);
	ret = -ENOTSUP;
	if (dev_ops->dev_infos_get)
		ret = dev_ops->dev_infos_get(recycle_dev, &dev_info);
	if (ret) {
		LSXINIC_PMD_ERR("Recycle device gets info failed!");
		return ret;
	}

	memcpy(&recycle_dev->data->dev_conf, port_conf,
			sizeof(struct rte_eth_conf));

	recycle_dev->data->rx_queues = rte_zmalloc(NULL,
				sizeof(void *) * nb_rx_queues,
				RTE_CACHE_LINE_SIZE);
	if (!recycle_dev->data->rx_queues) {
		LSXINIC_PMD_ERR("Recycle device alloc rxqs failed!");
		return -ENOMEM;
	}
	recycle_dev->data->nb_rx_queues = nb_rx_queues;

	recycle_dev->data->tx_queues = rte_zmalloc(NULL,
				sizeof(void *) * nb_tx_queues,
				RTE_CACHE_LINE_SIZE);
	if (!recycle_dev->data->tx_queues) {
		LSXINIC_PMD_ERR("Recycle device alloc txqs failed!");
		return -ENOMEM;
	}
	recycle_dev->data->nb_tx_queues = nb_tx_queues;

	ret = -ENOTSUP;
	if (dev_ops->dev_configure) {
		recycle_dev->data->dev_conf.lpbk_mode = 1;
		ret = dev_ops->dev_configure(recycle_dev);
	}
	if (ret) {
		LSXINIC_PMD_ERR("Recycle device conf failed!");
		return ret;
	}

	for (qnb = 0; qnb < recycle_dev->data->nb_tx_queues; qnb++) {
		memcpy(&txconf, &dev_info.default_txconf,
			sizeof(struct rte_eth_txconf));
		txconf.offloads = port_conf->txmode.offloads;
		ret = dev_ops->tx_queue_setup(recycle_dev, qnb,
						nb_tx_desc,
						0, &txconf);
		if (ret < 0) {
			LSXINIC_PMD_ERR("Failed to set %s txq%d",
				recycle_dev->data->name, qnb);
			return ret;
		}
	}

	for (qnb = 0; qnb < recycle_dev->data->nb_rx_queues; qnb++) {
		rte_memcpy(&rxconf, &dev_info.default_rxconf,
			sizeof(struct rte_eth_rxconf));
		rxconf.offloads = port_conf->rxmode.offloads;
		ret = dev_ops->rx_queue_setup(recycle_dev, qnb,
						nb_rx_desc,
						0, &rxconf, mb_pool);
		if (ret < 0) {
			LSXINIC_PMD_ERR("Failed to set %s rxq%d",
				recycle_dev->data->name, qnb);
			return ret;
		}
	}

	ret = dev_ops->dev_start(recycle_dev);
	if (ret) {
		LSXINIC_PMD_ERR("Recycle device start failed!");
		return ret;
	}
	recycle_dev->data->dev_started = 1;

	ret = dev_ops->promiscuous_enable(recycle_dev);
	if (ret) {
		LSXINIC_PMD_ERR("Recycle device promiscuous enable failed!");
		return ret;
	}

	return 0;
}
#endif

/* Configure device link speed and setup link.
 * It returns 0 on success.
 */
static int
lsinic_dev_start(struct rte_eth_dev *eth_dev)
{
	int err;
	pthread_t thread;
	static uint32_t thread_init_flag;
	struct lsinic_adapter *adapter = eth_dev->process_private;

	adapter->rc_ring_phy_base = 0;
	adapter->rc_ring_virt_base = 0;

	/* initialize transmission unit */
	lsinic_dev_tx_init(eth_dev);

	/* This can fail when allocating mbufs for descriptor rings */
	err = lsinic_dev_rx_init(eth_dev);
	if (err) {
		LSXINIC_PMD_ERR("Unable to initialize RX hardware");
		lsinic_dev_clear_queues(eth_dev);
		return -EIO;
	}

	lsinic_dev_rx_tx_bind(eth_dev);

	if (!thread_init_flag) {
		if (pthread_create(&thread, NULL, lsinic_poll_dev_cmd, NULL)) {
			LSXINIC_PMD_ERR("Failed to create poll thread");
			return -EIO;
		}

		thread_init_flag = 1;
	}

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	if (adapter->ep_cap & LSINIC_EP_CAP_RCV_MERGE_RECYCLE_RX ||
		adapter->ep_cap & LSINIC_EP_CAP_RCV_SPLIT_RECYCLE_RX) {
		struct rte_eth_dev *recycle_eth_dev;

		if (eth_dev->data->nb_tx_queues !=
			eth_dev->data->nb_rx_queues &&
			(adapter->merge_dev || adapter->split_dev)) {
			LSXINIC_PMD_ERR("Recycle(%s) nb_txq(%d)!=nb_rxq(%d)",
				eth_dev->data->name,
				eth_dev->data->nb_tx_queues,
				eth_dev->data->nb_rx_queues);
			return -ENOTSUP;
		}
		if (adapter->merge_dev &&
			(adapter->ep_cap &
			LSINIC_EP_CAP_RCV_MERGE_RECYCLE_RX)) {
			recycle_eth_dev = adapter->merge_dev->eth_dev;
			err = lsinic_dev_recycle_start(recycle_eth_dev,
					eth_dev->data->nb_tx_queues,
					eth_dev->data->nb_rx_queues,
					adapter->txqs[0].nb_desc,
					adapter->rxqs[0].nb_desc,
					&eth_dev->data->dev_conf,
					adapter->rxqs[0].mb_pool);
			if (err) {
				LSXINIC_PMD_ERR("Start merge dev %s",
					recycle_eth_dev->data->name);
				return -EIO;
			}
		}
		if (adapter->split_dev &&
			(adapter->ep_cap &
			LSINIC_EP_CAP_RCV_SPLIT_RECYCLE_RX)) {
			recycle_eth_dev = adapter->split_dev->eth_dev;
			err = lsinic_dev_recycle_start(recycle_eth_dev,
					eth_dev->data->nb_tx_queues,
					eth_dev->data->nb_rx_queues,
					adapter->txqs[0].nb_desc,
					adapter->rxqs[0].nb_desc,
					&eth_dev->data->dev_conf,
					adapter->rxqs[0].mb_pool);
			if (err) {
				LSXINIC_PMD_ERR("Start split dev %s",
					recycle_eth_dev->data->name);
				return -EIO;
			}
		}
	}
#endif

	lsinic_set_netdev(adapter, PCIDEV_COMMAND_START);

	return 0;
}

#ifdef RTE_ARCH_ARM64
#define dccivac(p) \
	{ asm volatile("dc civac, %0" : : "r"(p) : "memory"); }
#else
#define dccivac(p) RTE_SET_USED(p)
#endif

#define PCI_WRITE_CODE 0x12
#define PCI_INIT_CODE 0x34

static int
lsinic_dma_config_fromlocal(struct lsinic_adapter *adapter)
{
	uint64_t rc_dma_addr = 0, phy_addr = RTE_BAD_IOVA;
	struct rte_lsx_pciep_device *lsinic_dev = adapter->lsinic_dev;
	uint32_t size, miss = 0;
	const struct rte_memzone *local_mz;
	void *pci_vir, *local_vir;
	uint64_t start, end, wr_time, st_time, ns_per_cyc;
	char msg[512];

	local_mz = rte_eth_dma_zone_reserve(lsinic_dev->eth_dev,
			"local_mz", 0, 32 * 1024 * 1024,
			32 * 1024 * 1024,
			lsinic_dev->eth_dev->data->numa_node);
	if (!local_mz) {
		LSXINIC_PMD_ERR("local mz reserve failed");
		return -ENOMEM;
	}

	local_vir = local_mz->addr;
	rc_dma_addr = rte_mem_virt2phy(local_vir);
	if (rc_dma_addr == RTE_BAD_IOVA) {
		LSXINIC_PMD_ERR("VIR(%p)->PHY failed!",
			local_vir);

		return -EIO;
	}
	size = local_mz->len;
	LSXINIC_PMD_INFO("Config from LOCAL DMA base:%lX, size:0x%08x",
		rc_dma_addr, size);

	pci_vir = rte_lsx_pciep_set_ob_win(lsinic_dev,
			rc_dma_addr, size, &phy_addr);
	if (!pci_vir || phy_addr == RTE_BAD_IOVA) {
		LSXINIC_PMD_ERR("Set PCI OB with bus(0x%lx) failed",
			rc_dma_addr);
		return -EIO;
	}

	start = rte_get_timer_cycles();
	rte_delay_ms(1000);
	end = rte_get_timer_cycles();

	ns_per_cyc = (1000 * 1000 * 1000) / (end - start);
	*((uint8_t *)local_vir) = PCI_INIT_CODE;
	start = rte_get_timer_cycles();
	*((uint8_t *)pci_vir) = PCI_WRITE_CODE;
	wr_time = rte_get_timer_cycles();
	rte_wmb();
	st_time = rte_get_timer_cycles();
	while (*((uint8_t *)local_vir) != PCI_WRITE_CODE) {
		dccivac(local_vir);
		miss++;
		if (miss > (1000 * 1000)) {
			LSXINIC_PMD_ERR("PCIe to PCIe loopback failed!");
			rte_eth_dma_zone_free(lsinic_dev->eth_dev,
				local_mz->name, 0);
			return -EIO;
		}
	}
	end = rte_get_timer_cycles();
	sprintf(msg,
		"ns wr: %ld, wmb: %ld, rd local: %ld, total: %ld",
		(wr_time - start) * ns_per_cyc,
		(st_time - wr_time) * ns_per_cyc,
		(end - st_time) * ns_per_cyc,
		(end - start) * ns_per_cyc);
	LSXINIC_PMD_INFO("One byte over PCI:%s, cyc:%ld ns, miss:%d",
		msg, ns_per_cyc, miss);

	if (getenv("LSINIC_PCIE_VIR_REMOTE_MAP"))
		adapter->rc_dma_vir = pci_vir;
	else
		adapter->rc_dma_vir = local_vir;
	adapter->rc_dma_phy = phy_addr;
	adapter->rc_dma_elt_size = size;
	adapter->rc_dma_base = rc_dma_addr;
	adapter->local_mz = local_mz;

	return 0;
}

int
rte_lsinic_dev_get_rc_dma(void *_dev,
	void **pci_vir, uint64_t *pci_phy,
	uint64_t *pci_bus, uint64_t *pci_size,
	int *pci_id, int *pf_id, int *is_vf, int *vf_id)
{
	struct lsinic_adapter *adapter;
	struct rte_eth_dev *eth_dev = _dev;
	int ret;

	if (eth_dev->device->driver != &rte_lsinic_pmd.driver)
		return -EPERM;

	adapter = eth_dev->process_private;
	if (getenv("LSINIC_PCIE_TO_PCIE_LOOPBACK")) {
		ret = lsinic_dma_config_fromlocal(adapter);
		if (ret)
			return ret;
	}
	if (pci_vir)
		*pci_vir = adapter->rc_dma_vir;
	if (pci_phy)
		*pci_phy = adapter->rc_dma_phy;
	if (pci_bus)
		*pci_bus = adapter->rc_dma_base;
	if (pci_size)
		*pci_size = adapter->rc_dma_elt_size;
	if (pci_id)
		*pci_id = adapter->pcie_idx;
	if (pf_id)
		*pf_id = adapter->pf_idx;
	if (is_vf)
		*is_vf = adapter->is_vf;
	if (vf_id)
		*vf_id = adapter->vf_idx;

	return 0;
}

int
rte_lsinic_dev_start_poll_rc(void *_dev)
{
	pthread_t thread;
	static uint32_t thread_init_flag;
	struct lsinic_adapter *adapter;
	struct rte_eth_dev *eth_dev = _dev;

	if (eth_dev->device->driver != &rte_lsinic_pmd.driver)
		return -EPERM;

	adapter = eth_dev->process_private;

	if (!thread_init_flag) {
		if (pthread_create(&thread, NULL, lsinic_poll_dev_cmd, NULL)) {
			LSXINIC_PMD_ERR("Failed to create poll thread");
			return -EIO;
		}

		thread_init_flag = 1;
	}

	lsinic_set_netdev(adapter, PCIDEV_COMMAND_START);

	return 0;
}

/* Stop device: disable rx and tx functions to allow for reconfiguring.
 */
static int
lsinic_dev_stop(struct rte_eth_dev *dev)
{
	struct lsinic_adapter *adapter = dev->process_private;
	int ret;
	uint16_t rx_stop, tx_stop;

	/* disable the netdev receive */
	ret = lsinic_set_netdev(adapter, PCIDEV_COMMAND_STOP);
	if (ret)
		return ret;

	/* disable all enabled rx & tx queues */
	rx_stop = lsinic_dev_rx_stop(dev, 0);
	tx_stop = lsinic_dev_tx_stop(dev, 0);
	if (rx_stop == dev->data->nb_rx_queues &&
		tx_stop == dev->data->nb_tx_queues) {
		/* disable the netdev receive */
		lsinic_set_netdev(adapter, PCIDEV_COMMAND_STOP);
	}

	lsinic_dev_clear_queues(dev);

	return 0;
}

/* Reest and stop device.
 */
static int
lsinic_dev_close(struct rte_eth_dev *dev)
{
	struct lsinic_adapter *adapter = dev->process_private;
	int ret;

	ret = lsinic_dev_stop(dev);
	if (ret)
		return ret;

	ret = lsinic_set_netdev(adapter, PCIDEV_COMMAND_REMOVE);
	if (adapter->complete_src) {
		rte_free(adapter->complete_src);
		adapter->complete_src = NULL;
	}
	if (adapter->local_mz) {
		rte_eth_dma_zone_free(dev,
			adapter->local_mz->name, 0);
		adapter->local_mz = NULL;
	}

	return ret;
}

static int
lsinic_dev_info_get(struct rte_eth_dev *dev,
	struct rte_eth_dev_info *dev_info)
{
	struct lsinic_adapter *adapter = dev->process_private;

	dev_info->device = dev->device;
	dev_info->max_rx_queues = adapter->max_qpairs;
	dev_info->max_tx_queues = adapter->max_qpairs;
	dev_info->min_rx_bufsize = 1024; /* cf BSIZEPACKET in SRRCTL register */
	dev_info->max_rx_pktlen = 15872; /* includes CRC, cf MAXFRS register */
	dev_info->max_vfs = PCIE_MAX_VF_NUM;

	dev_info->rx_desc_lim = rx_desc_lim;
	dev_info->tx_desc_lim = tx_desc_lim;
	dev_info->rx_offload_capa = RTE_ETH_RX_OFFLOAD_CHECKSUM;

	return 0;
}

static int
lsinic_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
	/* TODO: Add proper implementation */

	RTE_SET_USED(dev);
	RTE_SET_USED(mtu);

	return 0;
}

/**
 * Atomically writes the link status information into global
 * structure rte_eth_dev.
 *
 * @param dev
 *   - Pointer to the structure rte_eth_dev to read from.
 *   - Pointer to the buffer to be saved with the link status.
 *
 * @return
 *   - On success, zero.
 *   - On failure, negative value.
 */
static inline int
rte_lsinic_dev_atomic_write_link_status(struct rte_eth_dev *dev,
	struct rte_eth_link *link)
{
	struct rte_eth_link *dst = &dev->data->dev_link;
	struct rte_eth_link *src = link;

	if (rte_atomic64_cmpset((uint64_t *)dst, *(uint64_t *)dst,
			*(uint64_t *)src) == 0)
		return -1;

	return 0;
}

static int
lsinic_dev_map_rc_ring(struct lsinic_adapter *adapter,
	uint64_t rc_reg_addr)
{
	int sim;
	void *vir_addr;
	uint64_t mask, size;
	struct rte_lsx_pciep_device *lsinic_dev = adapter->lsinic_dev;

	size = LSINIC_RING_PAIR_SIZE(adapter->max_qpairs);
	size += LSINIC_RING_BD_OFFSET;
	sim = rte_lsx_pciep_hw_sim_get(adapter->pcie_idx);
	if (sim) {
		vir_addr = DPAA2_IOVA_TO_VADDR_AND_CHECK(rc_reg_addr, 0);
		if (!vir_addr) {
			LSXINIC_PMD_ERR("Sim RC addr(%lx) no IOMMU mapped",
				rc_reg_addr);
			return -ENOBUFS;
		}

		adapter->rc_ring_virt_base = vir_addr;
		adapter->rc_ring_phy_base = rc_reg_addr;
		vir_addr = rte_lsx_pciep_set_ob_win(lsinic_dev,
			rc_reg_addr, size, NULL);
		if (vir_addr != adapter->rc_ring_virt_base) {
			LSXINIC_PMD_ERR("Simulator: vir mapped from RC(%p!=%p)",
				vir_addr, adapter->rc_ring_virt_base);
			return -EIO;
		}
	} else {
		mask = rte_lsx_pciep_bus_win_mask(lsinic_dev);
		if (mask && (rc_reg_addr & mask)) {
			LSXINIC_PMD_ERR("Bus(0x%lx) not aligned with 0x%lx",
				rc_reg_addr, mask + 1);
			return -EINVAL;
		}
		if (mask && (size & mask)) {
			LSXINIC_PMD_ERR("OB size(0x%lx) not aligned with 0x%lx",
				size, mask + 1);
			return -EINVAL;
		}
		adapter->rc_ring_virt_base =
			rte_lsx_pciep_set_ob_win(lsinic_dev,
				rc_reg_addr, size,
				&adapter->rc_ring_phy_base);
	}

	if (!adapter->rc_ring_virt_base)
		return -EIO;

	if (!rte_lsx_pciep_bus_ob_mapped(lsinic_dev, rc_reg_addr + size))
		return -EIO;

	adapter->rc_ring_bus_base = rc_reg_addr;
	adapter->rc_ring_size = size;

	return 0;
}

int
lsinic_dma_config_fromrc(struct lsinic_adapter *adapter)
{
	uint64_t rc_dma_addr = 0, phy_addr = RTE_BAD_IOVA;
	struct rte_lsx_pciep_device *lsinic_dev = adapter->lsinic_dev;
	struct lsinic_rcs_reg *rcs_reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_RCS_REG_OFFSET);
	uint32_t size;

	rc_dma_addr = LSINIC_READ_REG_64B(&rcs_reg->r_dma_base);
	size = LSINIC_READ_REG(&rcs_reg->r_dma_elt_size);
	LSXINIC_PMD_INFO("Config from RC DMA base:%lX, size:0x%08x",
		rc_dma_addr, size);

	adapter->rc_dma_vir = rte_lsx_pciep_set_ob_win(lsinic_dev,
			rc_dma_addr, size, &phy_addr);
	if (!adapter->rc_dma_vir || phy_addr == RTE_BAD_IOVA) {
		LSXINIC_PMD_ERR("Set PCI OB with bus(0x%lx) failed",
			rc_dma_addr);
		return -EIO;
	}

	adapter->rc_dma_phy = phy_addr;
	adapter->rc_dma_elt_size = size;
	adapter->rc_dma_base = rc_dma_addr;

	return 0;
}

int
lsinic_reset_config_fromrc(struct lsinic_adapter *adapter)
{
	uint64_t rc_reg_addr = 0;
	struct rte_lsx_pciep_device *lsinic_dev = adapter->lsinic_dev;
	struct lsinic_dev_reg *dev_reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_DEV_REG_OFFSET);
	struct lsinic_eth_reg *eth_reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_ETH_REG_OFFSET);
	struct lsinic_rcs_reg *rcs_reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_RCS_REG_OFFSET);
	int sim, ret = 0;
	uint32_t i, snoop;
	struct lsinic_queue *q;
	struct lsx_pciep_outbound *ob_win;
	uint64_t ob_base;

	snoop = LSINIC_READ_REG(&dev_reg->snoop);
	if (!snoop) {
		LSXINIC_PMD_WARN("NoSnoop TLP impacts performance.");
		/**Mark ring bar noncache.*/
		rte_lsx_pciep_ib_cache_mark(lsinic_dev,
			LSX_PCIEP_RING_BAR_IDX, 0);
	}
	sim = rte_lsx_pciep_hw_sim_get(adapter->pcie_idx);
	/* get ring setting */
	if (1) {
		adapter->rx_ring_bd_count = LSINIC_BD_ENTRY_COUNT;
		adapter->tx_ring_bd_count = LSINIC_BD_ENTRY_COUNT;
	} else {
		adapter->rx_ring_bd_count =
			LSINIC_READ_REG(&eth_reg->tx_entry_num);
		adapter->tx_ring_bd_count =
			LSINIC_READ_REG(&eth_reg->rx_entry_num);
	}

	/* Note: ep-tx == rc-rx and ep-rx == rc-tx */
	adapter->num_rx_queues = LSINIC_READ_REG(&eth_reg->tx_ring_num);
	adapter->num_tx_queues = LSINIC_READ_REG(&eth_reg->rx_ring_num);
	lsinic_dev->mmsi_flag = LSINIC_READ_REG(&rcs_reg->msi_flag);

	if (lsinic_dev->mmsi_flag == LSX_PCIEP_DONT_INT) {
		for (i = 0; i < LSINIC_DEV_MSIX_MAX_NB; i++)
			LSINIC_WRITE_REG(&rcs_reg->msix_mask[i], 0x01);
	}

	LSXINIC_PMD_INFO("rx-tx queues:%d-%d BDs:%d-%d mmsi_flag:%d",
		adapter->num_rx_queues, adapter->num_tx_queues,
		adapter->rx_ring_bd_count, adapter->tx_ring_bd_count,
		lsinic_dev->mmsi_flag);

	rc_reg_addr = LSINIC_READ_REG_64B((uint64_t *)(&rcs_reg->r_regl));
	LSXINIC_PMD_INFO("Config from RC rc ring base:%lX",
		rc_reg_addr);
	if (adapter->rc_ring_bus_base) {
		LSXINIC_PMD_WARN("RC ring(bus=%lx) has been mapped",
			adapter->rc_ring_bus_base);
		goto skip_map_rc_ring;
	}

	if (rc_reg_addr)
		ret = lsinic_dev_map_rc_ring(adapter, rc_reg_addr);
	else
		ret = -EIO;
	if (ret) {
		LSXINIC_PMD_ERR("Map RC ring failed");

		return ret;
	}

skip_map_rc_ring:
	if (adapter->rbp_enable || sim) {
		ob_base = 0;
	} else {
		ob_win = &lsinic_dev->ob_win[0];
		ob_base = ob_win->ob_iova_base;
		if (ob_base == RTE_BAD_IOVA) {
			LSXINIC_PMD_ERR("Map %p to IOVA failed!",
				ob_win->ob_virt_base);
			return -EIO;
		}
	}
	for (i = 0; i < adapter->num_rx_queues; i++) {
		q = &adapter->rxqs[i];
		q->ob_base = ob_base;
	}
	for (i = 0; i < adapter->num_tx_queues; i++) {
		q = &adapter->txqs[i];
		q->ob_base = ob_base;
	}

	if (LSINIC_CAP_XFER_RC_XMIT_CNF_TYPE_GET(adapter->cap) ==
		RC_XMIT_RING_CNF) {
		adapter->complete_src = rte_malloc(NULL,
			LSINIC_BD_CNF_RING_SIZE,
			LSINIC_BD_CNF_RING_SIZE);
		if (adapter->complete_src) {
			memset(adapter->complete_src, RING_BD_HW_COMPLETE,
				LSINIC_BD_CNF_RING_SIZE);
		} else {
			LSXINIC_PMD_ERR("complete src malloc failed");
			return -ENOMEM;
		}
	} else {
		adapter->complete_src = NULL;
	}

	adapter->rc_dma_base = LSINIC_READ_REG_64B(&rcs_reg->r_dma_base);
	adapter->rc_dma_elt_size = LSINIC_READ_REG(&rcs_reg->r_dma_elt_size);

	if (!sim) {
		ret = rte_lsx_pciep_multi_msix_init(lsinic_dev,
			LSINIC_DEV_MSIX_MAX_NB);
		if (ret) {
			LSXINIC_PMD_ERR("%s MSI(x) init failed(%d)",
				lsinic_dev->name, ret);
			return ret;
		}
	}

	return 0;
}

/* Disconnect to RC, unmap rc address.*/
int
lsinic_remove_config_fromrc(struct lsinic_adapter *adapter)
{
	int sim = rte_lsx_pciep_hw_sim_get(adapter->pcie_idx), ret;
	struct rte_lsx_pciep_device *lsinic_dev = adapter->lsinic_dev;

	if (adapter->rc_ring_bus_base && !sim) {
		ret = rte_lsx_pciep_unset_ob_win(lsinic_dev,
			adapter->rc_ring_bus_base);
		if (ret) {
			LSXINIC_PMD_ERR("%s: unset PCIe addr(0x%lx) failed(%d)",
				lsinic_dev->name,
				adapter->rc_ring_bus_base, ret);
			return ret;
		}
	}
	if (!sim) {
		ret = rte_lsx_pciep_multi_msix_remove(lsinic_dev);
		if (ret) {
			LSXINIC_PMD_ERR("%s: remove msi(x) failed(%d)",
				lsinic_dev->name, ret);
			return ret;
		}
	}
	adapter->rc_ring_bus_base = 0;
	adapter->rc_ring_phy_base = 0;
	adapter->rc_ring_size = 0;
	adapter->rc_ring_virt_base = NULL;

	return 0;
}

/* return 0 means link status changed, -1 means not changed */
static int
lsinic_dev_link_update(struct rte_eth_dev *dev,
	int wait_to_complete __rte_unused)
{
	struct lsinic_adapter *adapter;
	struct rte_eth_link link;

	adapter = dev->process_private;
	if (adapter->rc_state == LSINIC_DEV_UP) {
		link.link_status = RTE_ETH_LINK_UP;
		link.link_duplex = RTE_ETH_LINK_FULL_DUPLEX;
		link.link_speed = RTE_ETH_SPEED_NUM_25G;
	} else {
		link.link_status = RTE_ETH_LINK_DOWN;
		link.link_duplex = RTE_ETH_LINK_HALF_DUPLEX;
		link.link_speed = RTE_ETH_SPEED_NUM_NONE;
	}

	rte_lsinic_dev_atomic_write_link_status(dev, &link);

	return 0;
}

int
lsinic_dev_chk_eth_status(struct rte_eth_dev *dev)
{
	struct lsinic_adapter *adapter = dev->process_private;

	if (adapter->ep_state == LSINIC_DEV_INITING ||
		adapter->ep_state == LSINIC_DEV_INITED ||
		adapter->ep_state == LSINIC_DEV_REMOVED)
		return 0;
	else
		return 1;
}

static int
lsinic_dev_promiscuous_enable(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}

static int
lsinic_dev_promiscuous_disable(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}

static int
lsinic_dev_allmulticast_enable(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}

static int
lsinic_dev_allmulticast_disable(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}

/* Staticstic related function
 */
static int
lsinic_dev_stats_get(struct rte_eth_dev *dev,
	struct rte_eth_stats *stats)
{
	uint64_t total_ipackets, total_ibytes, total_ierrors;
	uint64_t total_opackets, total_obytes, total_oerrors;
	struct lsinic_tx_queue *txq, *txtmp;
	struct lsinic_rx_queue *rxq, *rxtmp;
	uint32_t i, j;

	total_ipackets = 0;
	total_ibytes = 0;
	total_ierrors = 0;
	total_opackets = 0;
	total_obytes = 0;
	total_oerrors = 0;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txq = dev->data->tx_queues[i];
		txtmp = txq;
		for (j = 0; j < txq->nb_q; j++) {
			total_opackets += txtmp->packets;
			total_obytes += txtmp->bytes;
			total_oerrors += txtmp->errors;
			txtmp = txtmp->sibling;
		}
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxq = dev->data->rx_queues[i];
		rxtmp = rxq;
		for (j = 0; j < rxq->nb_q; j++) {
			total_ipackets += rxtmp->packets;
			total_ibytes += rxtmp->bytes;
			total_ierrors += rxtmp->errors;
			rxtmp = rxtmp->sibling;
		}
	}

	stats->ipackets = total_ipackets;
	stats->opackets = total_opackets;
	stats->ibytes = total_ibytes;
	stats->obytes = total_obytes;
	stats->ierrors = total_ierrors;
	stats->oerrors = total_oerrors;

	return 0;
}

static int
lsinic_dev_stats_reset(struct rte_eth_dev *dev)
{
	struct lsinic_tx_queue *txq;
	struct lsinic_rx_queue *rxq;
	uint32_t i, j;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txq = dev->data->tx_queues[i];
		for (j = 0; j < txq->nb_q; j++) {
			txq->packets = 0;
			txq->bytes = 0;
			txq->errors = 0;
			txq = txq->sibling;
		}
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxq = dev->data->rx_queues[i];
		for (j = 0; j < rxq->nb_q; j++) {
			rxq->packets = 0;
			rxq->bytes = 0;
			rxq->errors = 0;
			rxq = rxq->sibling;
		}
	}

	return 0;
}

static int
lsinic_dev_uninit(struct rte_eth_dev *eth_dev)
{
	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	/* free memory for storing MAC addresses */
	if (eth_dev->data->mac_addrs) {
		rte_free(eth_dev->data->mac_addrs);
		eth_dev->data->mac_addrs = NULL;
	}

	eth_dev->dev_ops = NULL;
	eth_dev->rx_pkt_burst = NULL;
	eth_dev->tx_pkt_burst = NULL;

	LSXINIC_PMD_INFO("%s: netdev destroyed", eth_dev->data->name);

	return 0;
}

static int
rte_lsinic_remove(struct rte_lsx_pciep_device *lsinic_dev)
{
	struct rte_eth_dev *eth_dev;

	eth_dev = lsinic_dev->eth_dev;

	lsinic_dev_uninit(eth_dev);

	lsinic_uninit_bar_addr(lsinic_dev);

	lsinic_release_dma(lsinic_dev);

	if (lsinic_dev->msix_addr)
		free(lsinic_dev->msix_addr);
	if (lsinic_dev->msix_data)
		free(lsinic_dev->msix_data);

	rte_free(eth_dev->process_private);

	rte_eth_dev_release_port(eth_dev);
	lsinic_dev->init_flag = 0;

	return 0;
}

static struct rte_lsx_pciep_driver rte_lsinic_pmd = {
	.drv_type = 0,
	.name = LSX_PCIEP_NXP_NAME_PREFIX "_driver",
	.probe = rte_lsinic_probe,
	.remove = rte_lsinic_remove,
};

RTE_PMD_REGISTER_LSX_PCIEP(net_lsinic, rte_lsinic_pmd);

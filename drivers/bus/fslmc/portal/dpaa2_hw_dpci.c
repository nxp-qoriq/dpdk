/* SPDX-License-Identifier: BSD-3-Clause
 *
 *   Copyright 2017, 2020, 2023-2025 NXP
 *
 */

#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>

#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_kvargs.h>
#include <dev_driver.h>
#include <ethdev_driver.h>

#include <fslmc_logs.h>
#include <bus_fslmc_driver.h>
#include <mc/fsl_dpci.h>
#include "portal/dpaa2_hw_pvt.h"
#include "portal/dpaa2_hw_dpio.h"

TAILQ_HEAD(dpci_dev_list, dpaa2_dpci_dev);
static struct dpci_dev_list dpci_dev_list
	= TAILQ_HEAD_INITIALIZER(dpci_dev_list); /*!< DPCI device list */

static struct dpaa2_dpci_dev *get_dpci_from_id(uint32_t dpci_id)
{
	struct dpaa2_dpci_dev *dpci_dev = NULL;

	/* Get DPCI dev handle from list using index */
	TAILQ_FOREACH(dpci_dev, &dpci_dev_list, next) {
		if (dpci_dev->dpci_id == dpci_id)
			break;
	}

	return dpci_dev;
}

static int
dpaa2_create_dpci_device(int vdev_fd __rte_unused,
	struct vfio_device_info *obj_info __rte_unused,
	struct rte_dpaa2_device *obj)
{
	struct dpaa2_dpci_dev *dpci_node;
	struct dpci_attr attr;
	struct dpci_peer_attr peer_attr;
	struct dpci_rx_queue_cfg rx_queue_cfg;
	struct dpci_rx_queue_attr rx_attr;
	struct dpci_tx_queue_attr tx_attr;
	int ret, i, dpci_id = obj->object_id;
	char pool_name[64];
	uint64_t pool_size;

	memset(&attr, 0, sizeof(struct dpci_attr));
	memset(&peer_attr, 0, sizeof(struct dpci_peer_attr));

	/* Allocate DPAA2 dpci handle */
	dpci_node = rte_zmalloc(NULL, sizeof(struct dpaa2_dpci_dev), 0);
	if (!dpci_node) {
		DPAA2_BUS_ERR("Memory allocation failed for DPCI Device");
		return -ENOMEM;
	}

	/* Open the dpci object */
	dpci_node->dpci.regs = dpaa2_get_mcp_ptr(MC_PORTAL_INDEX);
	ret = dpci_open(&dpci_node->dpci, CMD_PRI_LOW, dpci_id, &dpci_node->token);
	if (ret) {
		DPAA2_BUS_ERR("Resource alloc failure with err code: %d", ret);
		goto open_err;
	}

	/* Get the device attributes */
	ret = dpci_get_attributes(&dpci_node->dpci,
		CMD_PRI_LOW, dpci_node->token, &attr);
	if (ret) {
		DPAA2_BUS_ERR("Reading device failed with err code: %d", ret);
		goto open_err;
	} else {
		RTE_ASSERT(dpci_id == attr.id);
		dpci_node->dpci_id = attr.id;
		dpci_node->rx_queue_num = attr.num_of_priorities;
	}

	if (dpci_node->rx_queue_num) {
		dpci_node->rx_queue = rte_zmalloc(NULL,
			sizeof(struct dpaa2_queue) * dpci_node->rx_queue_num, 0);
		if (!dpci_node->rx_queue) {
			DPAA2_BUS_ERR("DPCI.%d alloc rxq failed!", dpci_id);
			ret = -ENOMEM;
			goto open_err;
		}
	}

	for (i = 0; i < dpci_node->rx_queue_num; i++) {
		memset(&rx_queue_cfg, 0, sizeof(struct dpci_rx_queue_cfg));
		rx_queue_cfg.user_ctx = (uint64_t)&dpci_node->rx_queue[i];
		rx_queue_cfg.dest_cfg.dest_type = DPCI_DEST_NONE;
		ret = dpci_set_rx_queue(&dpci_node->dpci, CMD_PRI_LOW,
			dpci_node->token, i, &rx_queue_cfg);
		if (ret) {
			DPAA2_BUS_ERR("Setting Rx queue failed with err code: %d", ret);
			goto queue_err;
		}

		ret = dpci_get_rx_queue(&dpci_node->dpci, CMD_PRI_LOW,
			dpci_node->token, i, &rx_attr);
		if (ret) {
			DPAA2_BUS_ERR("Rx queue fetch failed with err code: %d", ret);
			goto queue_err;
		}
		dpci_node->rx_queue[i].fqid = rx_attr.fqid;
		snprintf(pool_name, sizeof(pool_name),
			"dpci%d_qid%d_env", dpci_id, i);
		pool_size = RTE_ALIGN(sizeof(struct rte_event), 1024);
		dpci_node->rx_queue[i].env_pool = rte_mempool_create(pool_name,
			1024, pool_size, 512, 0, NULL, NULL, NULL, NULL,
			SOCKET_ID_ANY, 0);
		if (ret) {
			DPAA2_BUS_ERR("Rx queue event pool create(%s) failed",
				pool_name);
			ret = -ENOMEM;
			goto queue_err;
		}
	}

	/* Enable the device */
	ret = dpci_enable(&dpci_node->dpci, CMD_PRI_LOW, dpci_node->token);
	if (ret) {
		DPAA2_BUS_ERR("Enabling device failed with err code: %d", ret);
		goto enable_err;
	}

	ret = dpci_get_peer_attributes(&dpci_node->dpci,
		CMD_PRI_LOW, dpci_node->token, &peer_attr);
	if (ret || peer_attr.peer_id < 0) {
		DPAA2_BUS_WARN("DPCI.%d has no peer, self connected.",
			dpci_node->dpci_id);
		/** Connect to self.*/
		dpci_node->peer_id = dpci_node->dpci_id;
		dpci_node->tx_queue_num = dpci_node->rx_queue_num;
	} else {
		dpci_node->peer_id = peer_attr.peer_id;
		dpci_node->tx_queue_num = peer_attr.num_of_priorities;
	}

	if (dpci_node->tx_queue_num) {
		dpci_node->tx_queue = rte_zmalloc(NULL,
			sizeof(struct dpaa2_queue) * dpci_node->tx_queue_num, 0);
		if (!dpci_node->tx_queue) {
			DPAA2_BUS_ERR("DPCI.%d alloc txq failed!", dpci_id);
			ret = -ENOMEM;
			goto enable_err;
		}
	}

	for (i = 0; i < dpci_node->tx_queue_num; i++) {
		if (dpci_node->peer_id != dpci_node->dpci_id) {
			ret = dpci_get_tx_queue(&dpci_node->dpci, CMD_PRI_LOW,
				dpci_node->token, i, &tx_attr);
			if (ret) {
				DPAA2_BUS_ERR("Tx queue fetch failed with err code: %d", ret);
				goto enable_err;
			}
			dpci_node->tx_queue[i].fqid = tx_attr.fqid;
		} else {
			dpci_node->tx_queue[i].fqid = dpci_node->rx_queue[i].fqid;
		}
	}

	rte_atomic16_init(&dpci_node->in_use);

	TAILQ_INSERT_TAIL(&dpci_dev_list, dpci_node, next);

	return 0;

enable_err:
	if (dpci_node->tx_queue)
		rte_free(dpci_node->tx_queue);
	dpci_disable(&dpci_node->dpci, CMD_PRI_LOW, dpci_node->token);
queue_err:
	if (dpci_node->rx_queue) {
		for (i = 0; i < dpci_node->rx_queue_num; i++) {
			if (dpci_node->rx_queue[i].env_pool)
				rte_mempool_free(dpci_node->rx_queue[i].env_pool);
		}
		rte_free(dpci_node->rx_queue);
	}
open_err:
	dpci_close(&dpci_node->dpci, CMD_PRI_LOW, dpci_node->token);

	rte_free(dpci_node);

	return ret;
}

struct dpaa2_dpci_dev *rte_dpaa2_alloc_dpci_dev(void)
{
	struct dpaa2_dpci_dev *dpci_dev = NULL;

	/* Get DPCI dev handle from list using index */
	TAILQ_FOREACH(dpci_dev, &dpci_dev_list, next) {
		if (dpci_dev && rte_atomic16_test_and_set(&dpci_dev->in_use))
			break;
	}

	return dpci_dev;
}

void rte_dpaa2_free_dpci_dev(struct dpaa2_dpci_dev *dpci)
{
	struct dpaa2_dpci_dev *dpci_dev = NULL;

	/* Match DPCI handle and mark it free */
	TAILQ_FOREACH(dpci_dev, &dpci_dev_list, next) {
		if (dpci_dev == dpci) {
			rte_atomic16_dec(&dpci_dev->in_use);
			return;
		}
	}
}

static void
dpaa2_close_dpci_device(int object_id)
{
	struct dpaa2_dpci_dev *dpci_dev = NULL;
	int i;

	dpci_dev = get_dpci_from_id((uint32_t)object_id);

	if (dpci_dev) {
		dpci_disable(&dpci_dev->dpci, CMD_PRI_LOW, dpci_dev->token);
		for (i = 0; i < dpci_dev->rx_queue_num; i++) {
			if (dpci_dev->rx_queue[i].env_pool)
				rte_mempool_free(dpci_dev->rx_queue[i].env_pool);
		}
		rte_free(dpci_dev->rx_queue);
		rte_free(dpci_dev->tx_queue);
		dpci_close(&dpci_dev->dpci, CMD_PRI_LOW, dpci_dev->token);
		TAILQ_REMOVE(&dpci_dev_list, dpci_dev, next);
		rte_free(dpci_dev);
	}
}

__rte_internal
int
rte_dpaa2_dpci_link_attach(struct dpaa2_dpci_dev *dpci_dev,
	enum dpci_dest dest_type, uint32_t dest_id, uint8_t priority,
	dpaa2_queue_cb_dqrr_t *rx_cb, struct dpaa2_queue **txq)
{
	struct dpci_rx_queue_cfg rx_queue_cfg;
	uint16_t i;
	int ret;
	struct dpaa2_dpci_dev *peer_dpci;

	if (dpci_dev->dpci_id == dpci_dev->peer_id) {
		peer_dpci = dpci_dev;
	} else {
		peer_dpci = get_dpci_from_id(dpci_dev->peer_id);
		if (!peer_dpci) {
			DPAA2_BUS_ERR("Get peer of DPCI.%d failed",
				dpci_dev->dpci_id);
			return -ENODEV;
		}
	}

	/*Do settings to get the frame on a DPCON object*/
	rx_queue_cfg.options = DPCI_QUEUE_OPT_DEST |
		  DPCI_QUEUE_OPT_USER_CTX;
	rx_queue_cfg.dest_cfg.dest_type = dest_type;
	rx_queue_cfg.dest_cfg.dest_id = dest_id;
	rx_queue_cfg.dest_cfg.priority = priority;
	rx_queue_cfg.order_preservation_en = 0;

	for (i = 0; i < dpci_dev->rx_queue_num; i++) {
		if (!dpci_dev->rx_queue[i].cb)
			break;
	}
	if (i == dpci_dev->rx_queue_num) {
		DPAA2_BUS_ERR("DPCI.%d No rxq available!", dpci_dev->dpci_id);
		return -EBUSY;
	}

	dpci_dev->rx_queue[i].cb = rx_cb;
	rx_queue_cfg.user_ctx = (size_t)(&dpci_dev->rx_queue[i]);
	ret = dpci_set_rx_queue(&dpci_dev->dpci, CMD_PRI_LOW,
		dpci_dev->token, i, &rx_queue_cfg);
	if (ret) {
		DPAA2_BUS_ERR("DPCI.%d Rx queue%d setup failed: err(%d)",
			dpci_dev->dpci_id, i, ret);
		return ret;
	}
	dpci_dev->tx_queue[i].env_pool = peer_dpci->rx_queue[i].env_pool;

	if (txq)
		*txq = &dpci_dev->tx_queue[i];

	return 0;
}

static struct rte_dpaa2_object rte_dpaa2_dpci_obj = {
	.dev_type = DPAA2_CI,
	.create = dpaa2_create_dpci_device,
	.close = dpaa2_close_dpci_device,
};

RTE_PMD_REGISTER_DPAA2_OBJECT(dpci, rte_dpaa2_dpci_obj);

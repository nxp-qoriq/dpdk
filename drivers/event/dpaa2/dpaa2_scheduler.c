/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024-2025 NXP
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

#include <bus_fslmc_driver.h>
#include <mc/fsl_dpcon.h>
#include <portal/dpaa2_hw_pvt.h>
#include <dpaa2_hw_dpio.h>
#include <compat.h>
#include "dpaa2_ethdev.h"
#include "dpaa2_eventdev.h"
#include "dpaa2_eventdev_logs.h"
#include "rte_pmd_dpaa2.h"

static inline void
dpaa2_qbman_pull_desc_channel_set(struct qbman_pull_desc *pulldesc,
	uint32_t num, uint16_t ch_id, struct qbman_result *dq_sch_storage,
	uint64_t iova_storage)
{
	qbman_pull_desc_clear(pulldesc);
	qbman_pull_desc_set_numframes(pulldesc, num);
	qbman_pull_desc_set_channel(pulldesc, ch_id,
		qbman_pull_type_active_noics);
	qbman_pull_desc_set_storage(pulldesc, dq_sch_storage,
		iova_storage, 1);
}

static uint16_t
dpaa2_scheduler_recv(struct dpaa2_dpcon_dev *dpcon_dev,
	struct rte_mbuf **mbuf, uint16_t nb_pkts)
{
	uint16_t ch_id = dpcon_dev->qbman_ch_id;
	struct qbman_result *dq_sch_storage;
	uint16_t total_nb_pkts = nb_pkts;
	struct qbman_pull_desc pulldesc;
	const struct qbman_fd *fd;
	struct dpaa2_queue *rvq;
	bool is_last, next_pull;
	int ret, rcvd_pkts = 0;
	struct qbman_swp *swp;
	uint8_t status;
	struct queue_storage_info_t *q_storage;
	uint64_t iova_storage;
	struct dpaa2_dev_priv *priv;

	if (unlikely(!DPAA2_PER_LCORE_ETHRX_DPIO)) {
		ret = dpaa2_affine_qbman_ethrx_swp();
		if (ret) {
			DPAA2_EVENTDEV_ERR("Failure(%d) in affining portal", ret);
			return 0;
		}
	}
	swp = DPAA2_PER_LCORE_ETHRX_PORTAL;
	q_storage = &dpcon_dev->q_storage[rte_lcore_id()];
	dq_sch_storage = q_storage->dq_storage[0];
	iova_storage = q_storage->iova_dq_storage[0];

	do {
		is_last = false;
		next_pull = false;
		dpaa2_qbman_pull_desc_channel_set(&pulldesc, nb_pkts, ch_id,
			dq_sch_storage, iova_storage);

		while (1) {
			if (qbman_swp_pull(swp, &pulldesc)) {
				DPAA2_EVENTDEV_DP_DEBUG("QBMAN is busy (1)");
				/* Portal was busy, try again */
				continue;
			}
			break;
		}
		/* Receive the packets till Last Dequeue entry is found with
		 * respect to the above issues PULL command.
		 */
		while (!is_last) {
			/* Loop until the dq_storage is updated with
			 * new result by QBMAN
			 */
			while (!qbman_result_has_new_result(swp, dq_sch_storage))
				;

			/* Check whether Last Pull command is Expired and
			 * setting Condition for Loop termination
			 */
			if (qbman_result_DQ_is_pull_complete(dq_sch_storage)) {
				is_last = true;
				/* Check for valid frame. */
				status = qbman_result_DQ_flags(dq_sch_storage);
				if (unlikely(!(status & QBMAN_DQ_STAT_VALIDFRAME))) {
					next_pull = true;
					DPAA2_EVENTDEV_DP_DEBUG("No frame is delivered\n");
					break;
				}
				nb_pkts = total_nb_pkts - (rcvd_pkts + 1);
				if (!nb_pkts)
					next_pull = true;
			}

			fd = qbman_result_DQ_fd(dq_sch_storage);
			rvq = (void *)qbman_result_DQ_fqd_ctx(dq_sch_storage);
			priv = rvq->eth_data->dev_private;
			if (unlikely(DPAA2_FD_GET_FORMAT(fd) == qbman_fd_sg))
				mbuf[rcvd_pkts] = dpaa2_eth_sg_fd_to_mbuf(priv, fd);
			else
				mbuf[rcvd_pkts] = dpaa2_eth_fd_to_mbuf(priv, fd);
			dpaa2_dev_rx_print_parser_result(priv, fd, mbuf[rcvd_pkts]);
			rcvd_pkts++;
			dq_sch_storage++;
			iova_storage += sizeof(struct qbman_result);
		}
	} while (!next_pull);
	/* End of Packet Rx loop */
	DPAA2_EVENTDEV_DP_DEBUG("DPCONC Received %d Packets\n", rcvd_pkts);

	return rcvd_pkts;
}

static uint16_t
dpaa2_scheduler_prefetch_recv(struct dpaa2_dpcon_dev *dpcon_dev,
	struct rte_mbuf **mbuf, uint16_t nb_pkts)
{
	uint16_t ch_id = dpcon_dev->qbman_ch_id, pull_size;
	struct qbman_result *dq_storage, *dq_storage1 = NULL, *active;
	struct qbman_pull_desc pulldesc;
	struct queue_storage_info_t *q_storage;
	uint64_t iova_storage;
	const struct qbman_fd *fd;
	struct dpaa2_queue *rvq;
	int ret, rcvd_pkts = 0;
	struct qbman_swp *swp;
	struct dpaa2_dpio_dev *ethrx_dpio_dev;
	uint8_t status, pending;
	struct dpaa2_dev_priv *priv;

	if (unlikely(!DPAA2_PER_LCORE_ETHRX_DPIO)) {
		ret = dpaa2_affine_qbman_ethrx_swp();
		if (ret) {
			DPAA2_EVENTDEV_ERR("Failure(%d) in affining portal", ret);
			return 0;
		}
	}
	swp = DPAA2_PER_LCORE_ETHRX_PORTAL;
	ethrx_dpio_dev = DPAA2_PER_LCORE_ETHRX_DPIO;
	q_storage = &dpcon_dev->q_storage[rte_lcore_id()];

	pull_size = (nb_pkts > dpaa2_dqrr_size) ?
		dpaa2_dqrr_size : nb_pkts;
	if (likely(q_storage->active_dqs))
		goto pull_active_dqs;

	q_storage->toggle = 0;
	dq_storage = q_storage->dq_storage[q_storage->toggle];
	iova_storage = q_storage->iova_dq_storage[q_storage->toggle];
	q_storage->last_num_pkts = pull_size;
	dpaa2_qbman_pull_desc_channel_set(&pulldesc, nb_pkts,
		ch_id, dq_storage, iova_storage);
	if (check_swp_active_dqs(ethrx_dpio_dev->index)) {
		do {
			active = get_swp_active_dqs(ethrx_dpio_dev->index);
			if (qbman_check_command_complete(active))
				break;
		} while (1);
		clear_swp_active_dqs(ethrx_dpio_dev->index);
	}
	while (1) {
		if (qbman_swp_pull(swp, &pulldesc)) {
			DPAA2_EVENTDEV_DP_DEBUG("QBMAN is busy (1)");
			/* Portal was busy, try again */
			continue;
		}
		break;
	}
	q_storage->active_dqs = dq_storage;
	q_storage->active_dpio_id = ethrx_dpio_dev->index;
	set_swp_active_dqs(ethrx_dpio_dev->index, dq_storage);

pull_active_dqs:

	dq_storage = q_storage->active_dqs;
	rte_prefetch0((void *)(size_t)(dq_storage));
	rte_prefetch0((void *)(size_t)(dq_storage + 1));

	/* Prepare next pull descriptor. This will give space for the
	 * prefetching done on DQRR entries
	 */
	q_storage->toggle ^= 1;
	dq_storage1 = q_storage->dq_storage[q_storage->toggle];
	iova_storage = q_storage->iova_dq_storage[q_storage->toggle];
	dpaa2_qbman_pull_desc_channel_set(&pulldesc, nb_pkts,
		ch_id, dq_storage1, iova_storage);

	while (!qbman_check_command_complete(dq_storage))
		;
	active = get_swp_active_dqs(q_storage->active_dpio_id);
	if (dq_storage == active)
		clear_swp_active_dqs(q_storage->active_dpio_id);

	pending = 1;

	do {
		/* Loop until the dq_storage is updated with
		 * new token by QBMAN
		 */
		while (!qbman_check_new_result(dq_storage))
			;
		rte_prefetch0((void *)((size_t)(dq_storage + 2)));
		/* Check whether Last Pull command is Expired and
		 * setting Condition for Loop termination
		 */
		if (qbman_result_DQ_is_pull_complete(dq_storage)) {
			pending = 0;
			/* Check for valid frame. */
			status = qbman_result_DQ_flags(dq_storage);
			if (unlikely(!(status & QBMAN_DQ_STAT_VALIDFRAME)))
				continue;
		}

		fd = qbman_result_DQ_fd(dq_storage);
		rvq = (void *)qbman_result_DQ_fqd_ctx(dq_storage);
		priv = rvq->eth_data->dev_private;
		if (unlikely(DPAA2_FD_GET_FORMAT(fd) == qbman_fd_sg))
			mbuf[rcvd_pkts] = dpaa2_eth_sg_fd_to_mbuf(priv, fd);
		else
			mbuf[rcvd_pkts] = dpaa2_eth_fd_to_mbuf(priv, fd);
		dpaa2_dev_rx_print_parser_result(priv, fd, mbuf[rcvd_pkts]);
		rcvd_pkts++;

		dq_storage++;
	} while (pending);

	if (check_swp_active_dqs(ethrx_dpio_dev->index)) {
		do {
			active = get_swp_active_dqs(ethrx_dpio_dev->index);
			if (qbman_check_command_complete(active))
				break;
		} while (1);
		clear_swp_active_dqs(ethrx_dpio_dev->index);
	}
	/* issue a volatile dequeue command for next pull */
	while (1) {
		if (qbman_swp_pull(swp, &pulldesc)) {
			DPAA2_EVENTDEV_DP_DEBUG("QBMAN is busy (2)");
			continue;
		}
		break;
	}
	q_storage->active_dqs = dq_storage1;
	q_storage->active_dpio_id = ethrx_dpio_dev->index;
	set_swp_active_dqs(ethrx_dpio_dev->index, dq_storage1);

	return rcvd_pkts;
}

__rte_experimental
void *
rte_dpaa2_scheduler_init(void)
{
	struct dpaa2_dpcon_dev *dpcon_dev;
	char *env = getenv("DPAA2_SCHEDULE_RX_PREFETCH");
	int prefetch_enable = env ? atoi(env) : 1;

	dpcon_dev = rte_dpaa2_alloc_dpcon_dev();
	if (!dpcon_dev)
		DPAA2_EVENTDEV_ERR("Failed to allocate dpcon device!!");

	if (prefetch_enable)
		dpcon_dev->rx_schedule = dpaa2_scheduler_prefetch_recv;
	else
		dpcon_dev->rx_schedule = dpaa2_scheduler_recv;

	return dpcon_dev;
}

__rte_experimental
int
rte_dpaa2_scheduler_start(void *scheduler_handle)
{
	struct dpaa2_dpcon_dev *dpcon_dev = scheduler_handle;
	int32_t ret;

	ret = rte_dpaa2_dpcon_start(dpcon_dev);
	if (ret) {
		DPAA2_EVENTDEV_ERR("Failed(%d) Conc - dpaa2_dev_start\n", ret);
		return ret;
	}
	return 0;
}

__rte_experimental
int
rte_dpaa2_scheduler_destroy(void *scheduler_handle)
{
	struct dpaa2_dpcon_dev *dpcon_dev = scheduler_handle;
	int32_t ret;

	ret = rte_dpaa2_dpcon_stop(dpcon_dev);
	if (ret) {
		DPAA2_EVENTDEV_ERR("Failed(%d) Conc - rte_dpaa2_schedule_destroy\n",
			ret);
		return ret;
	}
	dpcon_dev = NULL;

	return 0;
}

__rte_experimental
int
rte_dpaa2_scheduler_add(void *scheduler_handle,
	uint16_t port_id, uint16_t rxq_id, uint8_t priority)
{
	struct dpaa2_dpcon_dev *dpcon_dev = scheduler_handle;
	struct rte_eth_dev *dev;
	struct dpaa2_dev_priv *priv;
	struct rte_event_eth_rx_adapter_queue_conf queue_conf;
	uint8_t priority_step;

	if (!rte_pmd_dpaa2_dev_is_dpaa2(port_id))
		return -ENODEV;

	dev = &rte_eth_devices[port_id];
	priv = dev->data->dev_private;
	if (rxq_id >= priv->nb_rx_queues) {
		DPAA2_EVENTDEV_ERR("rxq_id(%d) >= queue number(%d)\n",
			rxq_id, priv->nb_rx_queues);
		return -EINVAL;
	}
	priority_step = (RTE_EVENT_DEV_PRIORITY_LOWEST + 1 -
		RTE_EVENT_DEV_PRIORITY_HIGHEST) / dpcon_dev->num_priorities;
	memset(&queue_conf, 0, sizeof(struct rte_event_eth_rx_adapter_queue_conf));
	queue_conf.ev.priority = priority * priority_step;

	return dpaa2_eth_eventq_attach(dev, rxq_id, dpcon_dev, &queue_conf, true);
}

__rte_experimental
uint16_t
rte_dpaa2_scheduler_rx(void *scheduler_handle, struct rte_mbuf **mbuf,
	uint16_t nb_pkts)
{
	struct dpaa2_dpcon_dev *dpcon_dev = scheduler_handle;

	return dpcon_dev->rx_schedule(dpcon_dev, mbuf, nb_pkts);
}

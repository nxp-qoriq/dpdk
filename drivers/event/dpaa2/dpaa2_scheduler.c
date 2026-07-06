/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024-2026 NXP
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
#include <rte_event_eth_rx_adapter.h>

#include <eal_export.h>
#include <bus_fslmc_driver.h>
#include <mc/fsl_dpcon.h>
#include <portal/dpaa2_hw_pvt.h>
#include <dpaa2_hw_dpio.h>
#include <compat.h>
#include "dpaa2_ethdev.h"
#include "dpaa2_eventdev.h"
#include "dpaa2_eventdev_logs.h"
#include "rte_pmd_dpaa2.h"

#define DPAA2_SCH_PORT_QUEUE_MAX_NUM 64
struct dpaa2_sch_port_queue {
	struct rte_eth_dev *eth_dev;
	uint16_t port_id;
	uint16_t rxq_id;
	uint8_t priority;
	struct rte_event_eth_rx_adapter_queue_conf queue_conf;
	int configured;
};

struct dpaa2_sch_dev {
	struct dpaa2_dpcon_dev *dpcon_dev[RTE_MAX_LCORE];
	struct dpaa2_dpci_dev *dpci_dev[RTE_MAX_LCORE];
	struct dpaa2_dpio_dev *dpio_dev[RTE_MAX_LCORE];
	uint8_t linked[RTE_MAX_LCORE];
	struct dpaa2_sch_port_queue port_queue[DPAA2_SCH_PORT_QUEUE_MAX_NUM];
	uint8_t port_queue_num;
	enum rte_dpaa2_sch_mode sch_mode;
	int rx_buf_sch_set;
	struct queue_storage_info_t q_storage[RTE_MAX_LCORE];
	uint16_t (*rx_schedule)(struct dpaa2_sch_dev *dev,
		struct rte_mbuf **rx_pkts, uint16_t nb_pkts);
};

static int
dpaa2_scheduler_dq_storage_init(struct dpaa2_sch_dev *sch_dev)
{
	int i, ret = 0;

	memset(&sch_dev->q_storage, 0,
		sizeof(struct queue_storage_info_t) * RTE_MAX_LCORE);

	for (i = 0; i < RTE_MAX_LCORE; i++) {
		ret = dpaa2_alloc_dq_storage(&sch_dev->q_storage[i]);
		if (ret)
			goto err;
	}
	return 0;
err:
	for (i = 0; i < RTE_MAX_LCORE; i++)
		dpaa2_free_dq_storage(&sch_dev->q_storage[i]);

	return ret;
}

static inline void
dpaa2_qbman_pull_desc_channel_set(struct qbman_pull_desc *pulldesc,
	uint32_t num, uint16_t ch_id, struct qbman_result *dq_sch_storage,
	uint64_t iova_storage)
{
	qbman_pull_desc_clear(pulldesc);
	qbman_pull_desc_set_numframes(pulldesc, num);
	qbman_pull_desc_set_channel(pulldesc, ch_id,
		qbman_pull_type_prio);
	qbman_pull_desc_set_storage(pulldesc, dq_sch_storage,
		iova_storage, 1);
}

static inline struct rte_mbuf *
dpaa2_scheduler_swp_mbuf_dq(struct dpaa2_sch_dev *sch_dev,
	struct qbman_swp *swp)
{
	const struct qbman_result *dq;
	const struct qbman_fd *fd;
	struct dpaa2_queue *rxq;
	struct dpaa2_dev_priv *priv;
	struct rte_mbuf *mbuf;

	dq = qbman_swp_dqrr_next(swp);
	if (!dq) {
		/** Flush*/
		qbman_swp_dqrr_consume(swp, NULL);
		return NULL;
	}

	qbman_swp_prefetch_dqrr_next(swp);
	fd = qbman_result_DQ_fd(dq);
	rxq = (struct dpaa2_queue *)(uintptr_t)qbman_result_DQ_fqd_ctx(dq);
	priv = rxq->eth_data->dev_private;
	if (unlikely(DPAA2_FD_GET_FORMAT(fd) == qbman_fd_sg))
		mbuf = dpaa2_eth_sg_fd_to_mbuf(priv, fd);
	else
		mbuf = dpaa2_eth_fd_to_mbuf(priv, fd);
	if (unlikely(!(mbuf->ol_flags & RTE_MBUF_F_RX_FDIR) &&
		sch_dev->rx_buf_sch_set)) {
		mbuf->hash.rss = 0;
		rte_mbuf_sched_set(mbuf, rxq->flow_id, rxq->tc_index,
			DPAA2_GET_FD_DROPP(fd));
		mbuf->ol_flags |= RTE_MBUF_F_RX_FDIR;
	}
	dpaa2_dev_rx_print_parser_result(priv, fd, mbuf);
	qbman_swp_dqrr_consume(swp, dq);

	return mbuf;
}

static uint32_t
dpaa2_scheduler_dpio_drain(struct dpaa2_sch_dev *sch_dev,
	struct dpaa2_dpio_dev *dpio_dev)
{
	struct qbman_swp *swp;
	uint32_t num_pkts = 0;
	struct rte_mbuf *mbuf;

	swp = dpio_dev->sw_portal;

dq_again:
	rte_delay_us(1000);
	mbuf = dpaa2_scheduler_swp_mbuf_dq(sch_dev, swp);
	if (mbuf) {
		rte_pktmbuf_free(mbuf);
		num_pkts++;
		goto dq_again;
	}

	return num_pkts;
}

static uint16_t
dpaa2_scheduler_dpci_recv(struct dpaa2_sch_dev *sch_dev,
	struct rte_mbuf **mbuf, uint16_t nb_pkts)
{
	struct dpaa2_dpcon_dev *dpcon_dev;
	struct dpaa2_dpci_dev *dpci_dev;
	struct dpaa2_dpio_dev *dpio_dev;
	struct qbman_swp *swp;
	struct dpaa2_sch_port_queue *port_queue;
	struct rte_event_eth_rx_adapter_queue_conf *queue_conf;
	uint16_t num_pkts = 0, i = 0;
	uint8_t priority_step;
	int ret;
	uint32_t cpu = rte_lcore_id();

	if (unlikely(!DPAA2_PER_LCORE_ETHRX_DPIO)) {
		ret = dpaa2_affine_qbman_ethrx_swp();
		if (ret) {
			DPAA2_EVENTDEV_ERR("Failure(%d) in affining portal", ret);
			return 0;
		}
	}
	dpio_dev = DPAA2_PER_LCORE_ETHRX_DPIO;
	swp = DPAA2_PER_LCORE_ETHRX_PORTAL;
	if (likely(sch_dev->linked[cpu] == sch_dev->port_queue_num))
		goto start_dq;
	if (!sch_dev->dpcon_dev[cpu])
		sch_dev->dpcon_dev[cpu] = rte_dpaa2_alloc_dpcon_dev();
	if (!sch_dev->dpci_dev[cpu])
		sch_dev->dpci_dev[cpu] = rte_dpaa2_alloc_dpci_dev();
	if (!sch_dev->dpcon_dev[cpu] || !sch_dev->dpci_dev[cpu])
		return 0;
	dpcon_dev = sch_dev->dpcon_dev[cpu];
	dpci_dev = sch_dev->dpci_dev[cpu];
	ret = rte_dpaa2_dpci_link_attach(dpci_dev, DPCI_DEST_DPCON,
		dpcon_dev->dpcon_id, 0, NULL, NULL);
	if (ret) {
		DPAA2_EVENTDEV_ERR("DPCI link attaches dpcon failed: err(%d)", ret);
		return 0;
	}
	for (i = 0; i < sch_dev->port_queue_num; i++) {
		port_queue = &sch_dev->port_queue[i];
		if (port_queue->configured)
			continue;
		queue_conf = &port_queue->queue_conf;
		priority_step = (RTE_EVENT_DEV_PRIORITY_LOWEST + 1 -
			RTE_EVENT_DEV_PRIORITY_HIGHEST) / dpcon_dev->num_priorities;
		queue_conf->ev.priority = port_queue->priority * priority_step;
		ret = dpaa2_eth_eventq_attach(port_queue->eth_dev,
			port_queue->rxq_id, dpcon_dev, queue_conf, true);
		if (ret) {
			DPAA2_EVENTDEV_ERR("Failure(%d) attaching %s-rxq%d to eventq",
				ret, port_queue->eth_dev->data->name,
				port_queue->rxq_id);
			return 0;
		}
		port_queue->configured = true;
	}
	ret = dpio_add_static_dequeue_channel(dpio_dev->dpio,
			CMD_PRI_LOW, dpio_dev->token,
			dpcon_dev->dpcon_id,
			&dpcon_dev->ch_idx[dpcon_dev->ch_idx_num]);
	if (ret) {
		DPAA2_EVENTDEV_ERR("Failure(%d) adding dpcon%d to static dq channel",
			ret, dpcon_dev->dpcon_id);
		return 0;
	}
	dpcon_dev->dpio_idx[dpcon_dev->ch_idx_num] = dpio_dev->index;

	qbman_swp_push_set(swp, dpcon_dev->ch_idx[dpcon_dev->ch_idx_num], 1);
	sch_dev->linked[cpu] = sch_dev->port_queue_num;
	sch_dev->dpio_dev[cpu] = dpio_dev;
	dpcon_dev->ch_idx_num++;

start_dq:
	while (num_pkts < nb_pkts) {
		mbuf[num_pkts] = dpaa2_scheduler_swp_mbuf_dq(sch_dev, swp);
		if (likely(mbuf[num_pkts]))
			num_pkts++;
		else
			break;
	}

	return num_pkts;
}

static uint16_t
dpaa2_scheduler_recv(struct dpaa2_sch_dev *sch_dev,
	struct rte_mbuf **mbuf, uint16_t nb_pkts)
{
	struct dpaa2_dpcon_dev *dpcon_dev = sch_dev->dpcon_dev[0];
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
	q_storage = &sch_dev->q_storage[rte_lcore_id()];
	dq_sch_storage = q_storage->dq_storage[0];
	iova_storage = q_storage->iova_dq_storage[0];

	do {
		is_last = false;
		next_pull = false;
		dpaa2_qbman_pull_desc_channel_set(&pulldesc, nb_pkts, ch_id,
			dq_sch_storage, iova_storage);

		while (1) {
			if (qbman_swp_pull(swp, &pulldesc)) {
				DPAA2_EVENTDEV_DEBUG("QBMAN is busy (1)");
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
					DPAA2_EVENTDEV_DEBUG("No frame is delivered");
					break;
				}
				nb_pkts = total_nb_pkts - (rcvd_pkts + 1);
				if (!nb_pkts)
					next_pull = true;
			}

			fd = qbman_result_DQ_fd(dq_sch_storage);
			rvq = (struct dpaa2_queue *)(uintptr_t)qbman_result_DQ_fqd_ctx(dq_sch_storage);
			priv = rvq->eth_data->dev_private;
			if (unlikely(DPAA2_FD_GET_FORMAT(fd) == qbman_fd_sg))
				mbuf[rcvd_pkts] = dpaa2_eth_sg_fd_to_mbuf(priv, fd);
			else
				mbuf[rcvd_pkts] = dpaa2_eth_fd_to_mbuf(priv, fd);
			if (unlikely(!(mbuf[rcvd_pkts]->ol_flags & RTE_MBUF_F_RX_FDIR) &&
				sch_dev->rx_buf_sch_set)) {
				mbuf[rcvd_pkts]->hash.rss = 0;
				rte_mbuf_sched_set(mbuf[rcvd_pkts], rvq->flow_id, rvq->tc_index,
					DPAA2_GET_FD_DROPP(fd));
				mbuf[rcvd_pkts]->ol_flags |= RTE_MBUF_F_RX_FDIR;
			}
			dpaa2_dev_rx_print_parser_result(priv, fd, mbuf[rcvd_pkts]);
			rcvd_pkts++;
			dq_sch_storage++;
			iova_storage += sizeof(struct qbman_result);
		}
	} while (!next_pull);
	/* End of Packet Rx loop */
	DPAA2_EVENTDEV_DEBUG("DPCONC Received %d Packets", rcvd_pkts);

	return rcvd_pkts;
}

static uint16_t
dpaa2_scheduler_prefetch_recv(struct dpaa2_sch_dev *sch_dev,
	struct rte_mbuf **mbuf, uint16_t nb_pkts)
{
	struct dpaa2_dpcon_dev *dpcon_dev = sch_dev->dpcon_dev[0];
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
	q_storage = &sch_dev->q_storage[rte_lcore_id()];

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
			DPAA2_EVENTDEV_DEBUG("QBMAN is busy (1)");
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
		rvq = (struct dpaa2_queue *)(uintptr_t)qbman_result_DQ_fqd_ctx(dq_storage);
		priv = rvq->eth_data->dev_private;
		if (unlikely(DPAA2_FD_GET_FORMAT(fd) == qbman_fd_sg))
			mbuf[rcvd_pkts] = dpaa2_eth_sg_fd_to_mbuf(priv, fd);
		else
			mbuf[rcvd_pkts] = dpaa2_eth_fd_to_mbuf(priv, fd);
		if (unlikely(!(mbuf[rcvd_pkts]->ol_flags & RTE_MBUF_F_RX_FDIR) &&
			sch_dev->rx_buf_sch_set)) {
			mbuf[rcvd_pkts]->hash.rss = 0;
			rte_mbuf_sched_set(mbuf[rcvd_pkts], rvq->flow_id, rvq->tc_index,
				DPAA2_GET_FD_DROPP(fd));
			mbuf[rcvd_pkts]->ol_flags |= RTE_MBUF_F_RX_FDIR;
		}
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
			DPAA2_EVENTDEV_DEBUG("QBMAN is busy (2)");
			continue;
		}
		break;
	}
	q_storage->active_dqs = dq_storage1;
	q_storage->active_dpio_id = ethrx_dpio_dev->index;
	set_swp_active_dqs(ethrx_dpio_dev->index, dq_storage1);

	return rcvd_pkts;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_dpaa2_scheduler_init, 25.11)
void *
rte_dpaa2_scheduler_init(enum rte_dpaa2_sch_mode sch_mode)
{
	struct dpaa2_dpcon_dev *dpcon_dev = NULL;
	struct dpaa2_sch_dev *sch_dev = NULL;
	char *env = getenv("DPAA2_SCHEDULE_RX_PREFETCH");
	int prefetch_enable = env ? atoi(env) : 1, ret, i;

	sch_dev = rte_zmalloc(NULL, sizeof(struct dpaa2_sch_dev), 0);
	if (!sch_dev) {
		DPAA2_EVENTDEV_ERR("Failed alloc scheduler device!!");
		goto err;
	}

	ret = dpaa2_scheduler_dq_storage_init(sch_dev);
	if (ret)
		goto err;

	if (sch_mode == RTE_DPAA2_SCH_PULL) {
		dpcon_dev = rte_dpaa2_alloc_dpcon_dev();
		if (!dpcon_dev) {
			DPAA2_EVENTDEV_ERR("Failed alloc dpcon device!!");
			goto err;
		}
		sch_dev->dpcon_dev[0] = dpcon_dev;
		if (prefetch_enable)
			sch_dev->rx_schedule = dpaa2_scheduler_prefetch_recv;
		else
			sch_dev->rx_schedule = dpaa2_scheduler_recv;
	} else if (sch_mode == RTE_DPAA2_SCH_PUSH) {
		sch_dev->rx_schedule = dpaa2_scheduler_dpci_recv;
	} else {
		DPAA2_EVENTDEV_ERR("Invalid schedule mode(%d)!!", sch_mode);
		goto err;
	}
	sch_dev->sch_mode = sch_mode;

	env = getenv("DPAA2_SCHEDULE_RX_BUF_SCH_SET");
	if (env)
		sch_dev->rx_buf_sch_set = atoi(env);

	return sch_dev;
err:
	if (dpcon_dev)
		rte_dpaa2_free_dpcon_dev(dpcon_dev);
	if (sch_dev) {
		for (i = 0; i < RTE_MAX_LCORE; i++)
			dpaa2_free_dq_storage(&sch_dev->q_storage[i]);
		rte_free(sch_dev);
	}

	return NULL;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_dpaa2_scheduler_start, 25.11)
int
rte_dpaa2_scheduler_start(void *scheduler_handle)
{
	struct dpaa2_sch_dev *sch_dev = scheduler_handle;
	struct dpaa2_dpcon_dev *dpcon_dev = scheduler_handle;
	int32_t ret;

	if (sch_dev->sch_mode == RTE_DPAA2_SCH_PUSH)
		return 0;

	dpcon_dev = sch_dev->dpcon_dev[0];

	ret = rte_dpaa2_dpcon_start(dpcon_dev);
	if (ret) {
		DPAA2_EVENTDEV_ERR("Failed(%d) to start dpcon", ret);
		return ret;
	}
	sch_dev->linked[0] = 1;

	return 0;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_dpaa2_scheduler_destroy, 25.11)
int
rte_dpaa2_scheduler_destroy(void *scheduler_handle)
{
	struct dpaa2_sch_dev *sch_dev = scheduler_handle;
	struct dpaa2_dpcon_dev *dpcon_dev;
	struct dpaa2_dpci_dev *dpci_dev;
	struct dpaa2_dpio_dev *dpio_dev;
	int32_t ret, i;
	uint16_t drain_num, rx, un_attach_num = 0;
	struct rte_mbuf *mbufs[16];

	if (sch_dev->sch_mode == RTE_DPAA2_SCH_PUSH) {
		/** Make sure all data threads quit.*/
		for (i = 0; i < RTE_MAX_LCORE; i++) {
			if (!sch_dev->dpio_dev[i])
				continue;

			dpio_dev = sch_dev->dpio_dev[i];
			dpcon_dev = sch_dev->dpcon_dev[i];
			RTE_ASSERT(dpcon_dev);
			drain_num = dpaa2_scheduler_dpio_drain(sch_dev, dpio_dev);
			if (drain_num > 0) {
				DPAA2_EVENTDEV_WARN("%s: Drain %d buffer(s) from core%d",
					__func__, drain_num, i);
			}
			qbman_swp_push_set(dpio_dev->sw_portal,
				dpcon_dev->ch_idx[dpcon_dev->ch_idx_num - 1], 0);
			ret = dpio_remove_static_dequeue_channel(dpio_dev->dpio,
				0, dpio_dev->token, dpcon_dev->dpcon_id);
			if (ret) {
				DPAA2_EVENTDEV_ERR("%s: Remove channel from core%d failed(%d)",
					__func__, i, ret);
			}
			un_attach_num += sch_dev->linked[i];
			dpcon_dev->ch_idx_num--;
		}
	} else {
		drain_num = 0;
		do {
			rte_delay_ms(1);
			rx = sch_dev->rx_schedule(sch_dev, mbufs, 16);
			for (i = 0; i < rx; i++)
				rte_pktmbuf_free(mbufs[i]);
			drain_num += rx;
		} while (rx > 0);
		if (drain_num > 0) {
			DPAA2_EVENTDEV_WARN("%s: Drain %d buffer(s) from scheduler.",
				__func__, drain_num);
		}
		un_attach_num = sch_dev->port_queue_num;
	}

	for (i = 0; i < un_attach_num; i++) {
		ret = dpaa2_eth_eventq_detach(sch_dev->port_queue[i].eth_dev,
			sch_dev->port_queue[i].rxq_id);
		if (ret) {
			DPAA2_EVENTDEV_ERR("Unattach %s's rxq%d failed(%d)",
				sch_dev->port_queue[i].eth_dev->data->name,
				sch_dev->port_queue[i].rxq_id, ret);
		}
	}

	for (i = 0; i < RTE_MAX_LCORE; i++) {
		dpcon_dev = sch_dev->dpcon_dev[i];
		dpci_dev = sch_dev->dpci_dev[i];
		if (dpcon_dev) {
			if (sch_dev->linked[i]) {
				ret = rte_dpaa2_dpcon_stop(dpcon_dev);
				if (ret) {
					DPAA2_EVENTDEV_ERR("%s: stop dpcon[%d] failed(%d)",
						__func__, i, ret);
					/** Free anyway.*/
				}
			}
			rte_dpaa2_free_dpcon_dev(dpcon_dev);
		}
		if (dpci_dev)
			rte_dpaa2_free_dpci_dev(dpci_dev);
		sch_dev->linked[i] = 0;
	}

	rte_free(sch_dev);

	return 0;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_dpaa2_scheduler_add, 25.11)
int
rte_dpaa2_scheduler_add(void *scheduler_handle,
	uint16_t port_id, uint16_t rxq_id, uint8_t priority)
{
	struct dpaa2_sch_dev *sch_dev = scheduler_handle;
	struct dpaa2_dpcon_dev *dpcon_dev;
	struct rte_eth_dev *dev;
	struct dpaa2_dev_priv *priv;
	struct rte_event_eth_rx_adapter_queue_conf queue_conf;
	uint8_t priority_step;
	int ret;

	if (!rte_pmd_dpaa2_dev_is_dpaa2(port_id))
		return -ENODEV;

	dev = &rte_eth_devices[port_id];
	priv = dev->data->dev_private;
	if (rxq_id >= priv->nb_rx_queues) {
		DPAA2_EVENTDEV_ERR("rxq_id(%d) >= queue number(%d)",
			rxq_id, priv->nb_rx_queues);
		return -EINVAL;
	}

	if (sch_dev->port_queue_num >= DPAA2_SCH_PORT_QUEUE_MAX_NUM) {
		DPAA2_EVENTDEV_ERR("Too many schedule queues");
		return -EINVAL;
	}

	memset(&queue_conf, 0, sizeof(struct rte_event_eth_rx_adapter_queue_conf));
	ret = 0;
	if (sch_dev->sch_mode == RTE_DPAA2_SCH_PULL) {
		dpcon_dev = sch_dev->dpcon_dev[0];
		priority_step = (RTE_EVENT_DEV_PRIORITY_LOWEST + 1 -
			RTE_EVENT_DEV_PRIORITY_HIGHEST) / dpcon_dev->num_priorities;
		queue_conf.ev.priority = priority * priority_step;
		ret = dpaa2_eth_eventq_attach(dev, rxq_id, dpcon_dev, &queue_conf, true);
	}
	if (!ret) {
		sch_dev->port_queue[sch_dev->port_queue_num].eth_dev = dev;
		sch_dev->port_queue[sch_dev->port_queue_num].rxq_id = rxq_id;
		sch_dev->port_queue[sch_dev->port_queue_num].priority = priority;
		rte_memcpy(&sch_dev->port_queue[sch_dev->port_queue_num].queue_conf,
			&queue_conf, sizeof(struct rte_event_eth_rx_adapter_queue_conf));
		if (sch_dev->sch_mode == RTE_DPAA2_SCH_PULL)
			sch_dev->port_queue[sch_dev->port_queue_num].configured = true;
		sch_dev->port_queue_num++;
	}

	return ret;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_dpaa2_scheduler_rx, 25.11)
uint16_t
rte_dpaa2_scheduler_rx(void *scheduler_handle, struct rte_mbuf **mbuf,
	uint16_t nb_pkts)
{
	struct dpaa2_sch_dev *sch_dev = scheduler_handle;

	return sch_dev->rx_schedule(sch_dev, mbuf, nb_pkts);
}

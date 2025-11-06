/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2017,2019-2025 NXP
 */

#include <assert.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/epoll.h>

#include <rte_atomic.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_debug.h>
#include <dev_driver.h>
#include <rte_eal.h>
#include <bus_fslmc_driver.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_memory.h>
#include <rte_pci.h>
#include <bus_vdev_driver.h>
#include <ethdev_driver.h>
#include <cryptodev_pmd.h>
#include <rte_event_crypto_adapter.h>
#include <rte_event_eth_rx_adapter.h>
#include <rte_event_eth_tx_adapter.h>

#include <fslmc_vfio.h>
#include <dpaa2_hw_pvt.h>
#include <dpaa2_hw_mempool.h>
#include <dpaa2_hw_dpio.h>
#include <dpaa2_ethdev.h>
#include <dpaa2_sec_event.h>
#include "dpaa2_eventdev.h"
#include "dpaa2_eventdev_logs.h"
#include <portal/dpaa2_hw_pvt.h>
#include <mc/fsl_dpci.h>

static int
dpaa2_eventdev_attach_eth_rxq(const struct rte_eth_dev *dev,
	struct dpaa2_eventdev *priv, uint16_t rxq_id,
	const struct rte_event_eth_rx_adapter_queue_conf *queue_conf)
{
	int ret;
	uint8_t ev_qid = queue_conf->ev.queue_id;
	uint8_t idx = priv->evq_info[ev_qid].dpni_rxq_num;
	struct dpaa2_dpcon_dev *dpcon = priv->evq_info[ev_qid].dpcon;

	if (idx >= DPAA2_EVENTQ_DPNI_RXQ_ATTACH_MAX) {
		DPAA2_EVENTDEV_ERR("Too many queues to attach.");
		return -ENOMEM;
	}
	ret = dpaa2_eth_eventq_attach(dev, rxq_id, dpcon, queue_conf, false);
	if (ret) {
		DPAA2_EVENTDEV_ERR("Event queue attach failed: err(%d)",
			ret);

		return ret;
	}
	priv->evq_info[ev_qid].dpni_rxqs[idx] = dev->data->rx_queues[rxq_id];
	priv->evq_info[ev_qid].dpni_rxq_num++;

	return 0;
}

/* Clarifications
 * Evendev = SoC Instance
 * Eventport = DPIO Instance
 * Eventqueue = DPCON Instance
 * 1 Eventdev can have N Eventqueue
 * Soft Event Flow is DPCI Instance
 */

#define DPAA2_EV_TX_RETRY_COUNT 10000

static uint16_t
dpaa2_eventdev_enqueue_burst(void *port, const struct rte_event ev[],
	uint16_t nb_events)
{
	struct dpaa2_port *dpaa2_portal = port;
	struct dpaa2_dpio_dev *dpio_dev;
	struct rte_eventdev *eventdev = dpaa2_portal->eventdev;
	struct dpaa2_eventdev *priv = eventdev->data->dev_private;
	struct dpaa2_eventq *evq_info;
	uint32_t queue_id, retry_count, loop, frames_to_send;
	struct qbman_swp *swp;
	struct qbman_fd fd_arr[MAX_TX_RING_SLOTS];
	struct qbman_eq_desc eqdesc[MAX_TX_RING_SLOTS];
	uint16_t num_tx = 0;
	int ret;
	uint8_t dqrr_index;
	const struct rte_event *event;
	struct dpaa2_queue *dpci_txq;
	struct rte_event *ev_tx;

	if (unlikely(!dpaa2_portal->dpio_dev)) {
		DPAA2_EVENTDEV_ERR("Event port%d not setup\n", dpaa2_portal->port_id);
		return 0;
	}

	if (unlikely(!dpaa2_portal->num_linked_evq)) {
		DPAA2_EVENTDEV_ERR("%s: Event port%d no queue linked\n",
			__func__, dpaa2_portal->port_id);
		return 0;
	}

	if (dpaa2_portal->port_atomic)
		rte_spinlock_lock(&dpaa2_portal->port_lock);
	else if (unlikely(dpaa2_portal->cpu_affine < 0))
		dpaa2_portal->cpu_affine = rte_lcore_id();

	if (unlikely(!dpaa2_portal->port_atomic &&
		dpaa2_portal->cpu_affine != (int)rte_lcore_id())) {
		DPAA2_EVENTDEV_WARN("%s: Data path cpu(%d) != event port%d's cpu(%d)\n",
			__func__, rte_lcore_id(), dpaa2_portal->port_id,
			dpaa2_portal->cpu_affine);
	}

	dpio_dev = dpaa2_portal->dpio_dev;
	swp = dpio_dev->sw_portal;

	while (nb_events) {
		frames_to_send = (nb_events > dpaa2_eqcr_size) ?
			dpaa2_eqcr_size : nb_events;

		for (loop = 0; loop < frames_to_send; loop++) {
			event = &ev[num_tx + loop];
			queue_id = event->queue_id;
			evq_info = &priv->evq_info[queue_id];
			if (unlikely(evq_info->event_port != dpaa2_portal)) {
				DPAA2_EVENTDEV_ERR("Event queue%d is not handled by port%d\n",
					queue_id, dpaa2_portal->port_id);
				goto send_partial;
			}
			dpci_txq = evq_info->dpci_txqs[event->sched_type];

			/* Prepare enqueue descriptor */
			qbman_eq_desc_clear(&eqdesc[loop]);
			qbman_eq_desc_set_fq(&eqdesc[loop], dpci_txq->fqid);
			qbman_eq_desc_set_no_orp(&eqdesc[loop], 0);
			qbman_eq_desc_set_response(&eqdesc[loop], 0, 0);

			if (event->sched_type == RTE_SCHED_TYPE_ATOMIC &&
				*dpaa2_seqn(event->mbuf)) {
				dqrr_index = *dpaa2_seqn(event->mbuf) - 1;
				qbman_eq_desc_set_dca(&eqdesc[loop], 1, dqrr_index, 0);
				dpio_dev->dpaa2_held_bufs.dqrr_size--;
				dpio_dev->dpaa2_held_bufs.dqrr_held &= ~(1 << dqrr_index);
			}

			memset(&fd_arr[loop], 0, sizeof(struct qbman_fd));

			/*
			 * todo - need to align with hw context data
			 * to avoid copy
			 */
			ret = rte_mempool_get(dpci_txq->env_pool, (void **)&ev_tx);
			if (ret) {
				DPAA2_EVENTDEV_ERR("Allocate event object failed from %s",
					dpci_txq->env_pool->name);
				goto send_partial;
			}

			rte_memcpy(ev_tx, event, sizeof(struct rte_event));
			DPAA2_SET_FD_ADDR((&fd_arr[loop]), (size_t)ev_tx);
			DPAA2_SET_FD_LEN((&fd_arr[loop]), sizeof(struct rte_event));
		}
send_partial:
		loop = 0;
		retry_count = 0;
		while (loop < frames_to_send) {
			ret = qbman_swp_enqueue_multiple_desc(swp,
					&eqdesc[loop], &fd_arr[loop],
					frames_to_send - loop);
			if (unlikely(ret < 0)) {
				retry_count++;
				if (retry_count > DPAA2_EV_TX_RETRY_COUNT) {
					num_tx += loop;
					nb_events -= loop;
					goto quit;
				}
			} else {
				loop += ret;
				retry_count = 0;
			}
		}
		num_tx += loop;
		nb_events -= loop;
	}

quit:
	if (dpaa2_portal->port_atomic)
		rte_spinlock_unlock(&dpaa2_portal->port_lock);
	return num_tx;
}

static uint16_t
dpaa2_eventdev_enqueue(void *port, const struct rte_event *ev)
{
	return dpaa2_eventdev_enqueue_burst(port, ev, 1);
}

static void dpaa2_eventdev_dequeue_wait(uint64_t timeout_ticks)
{
	struct epoll_event epoll_ev;

	qbman_swp_interrupt_clear_status(DPAA2_PER_LCORE_PORTAL,
					 QBMAN_SWP_INTERRUPT_DQRI);

	epoll_wait(DPAA2_PER_LCORE_DPIO->epoll_fd,
			 &epoll_ev, 1, timeout_ticks);
}

static void dpaa2_eventdev_process_parallel(struct dpaa2_dpio_dev *dpio_dev,
	const struct qbman_fd *fd, const struct qbman_result *dq,
	struct dpaa2_queue *rxq, struct rte_event *ev)
{
	struct rte_event *rx_ev = (void *)DPAA2_GET_FD_ADDR(fd);
	struct qbman_swp *swp = dpio_dev->sw_portal;

	rte_memcpy(ev, rx_ev, sizeof(struct rte_event));
	rte_mempool_put(rxq->env_pool, rx_ev);

	qbman_swp_dqrr_consume(swp, dq);
}

static void dpaa2_eventdev_process_atomic(struct dpaa2_dpio_dev *dpio_dev,
	const struct qbman_fd *fd, const struct qbman_result *dq,
	struct dpaa2_queue *rxq, struct rte_event *ev)
{
	struct rte_event *rx_ev = (void *)DPAA2_GET_FD_ADDR(fd);
	uint8_t dqrr_index = qbman_get_dqrr_idx(dq);

	rte_memcpy(ev, rx_ev, sizeof(struct rte_event));
	rte_mempool_put(rxq->env_pool, rx_ev);
	*dpaa2_seqn(ev->mbuf) = dqrr_index + 1;
	dpio_dev->dpaa2_held_bufs.dqrr_size++;
	dpio_dev->dpaa2_held_bufs.dqrr_held |= 1 << dqrr_index;
	dpio_dev->dpaa2_held_bufs.mbuf[dqrr_index] = ev->mbuf;
}

static uint16_t
dpaa2_eventdev_dequeue_burst(void *port, struct rte_event ev[],
	uint16_t nb_events, uint64_t timeout_ticks)
{
	const struct qbman_result *dq;
	struct dpaa2_dpio_dev *dpio_dev = NULL;
	struct dpaa2_port *dpaa2_portal = port;
	struct qbman_swp *swp;
	const struct qbman_fd *fd;
	struct dpaa2_queue *rxq;
	uint16_t num_pkts = 0, i = 0;

	if (unlikely(!dpaa2_portal->dpio_dev)) {
		DPAA2_EVENTDEV_ERR("Event port%d not setup\n", dpaa2_portal->port_id);
		return 0;
	}

	if (unlikely(!dpaa2_portal->num_linked_evq)) {
		DPAA2_EVENTDEV_WARN("%s: Event port%d no queue linked",
			__func__, dpaa2_portal->port_id);
		rte_delay_us(10000);
		return 0;
	}

	if (dpaa2_portal->port_atomic)
		rte_spinlock_lock(&dpaa2_portal->port_lock);
	else if (unlikely(dpaa2_portal->cpu_affine < 0))
		dpaa2_portal->cpu_affine = rte_lcore_id();

	if (unlikely(!dpaa2_portal->port_atomic &&
		dpaa2_portal->cpu_affine != (int)rte_lcore_id())) {
		DPAA2_EVENTDEV_WARN("%s: Data path cpu(%d) != event port%d's cpu(%d)\n",
			__func__, rte_lcore_id(), dpaa2_portal->port_id,
			dpaa2_portal->cpu_affine);
	}

	dpio_dev = dpaa2_portal->dpio_dev;
	swp = dpio_dev->sw_portal;

	/* Check if there are atomic contexts to be released */
	while (dpio_dev->dpaa2_held_bufs.dqrr_size) {
		if (dpio_dev->dpaa2_held_bufs.dqrr_held & (1 << i)) {
			qbman_swp_dqrr_idx_consume(swp, i);
			dpio_dev->dpaa2_held_bufs.dqrr_size--;
			*dpaa2_seqn(dpio_dev->dpaa2_held_bufs.mbuf[i]) =
				DPAA2_INVALID_MBUF_SEQN;
		}
		i++;
	}
	dpio_dev->dpaa2_held_bufs.dqrr_held = 0;

	do {
		dq = qbman_swp_dqrr_next(swp);
		if (!dq) {
			if (!num_pkts && timeout_ticks) {
				dpaa2_eventdev_dequeue_wait(timeout_ticks);
				timeout_ticks = 0;
				continue;
			}
			goto quit;
		}
		qbman_swp_prefetch_dqrr_next(swp);

		fd = qbman_result_DQ_fd(dq);
		rxq = (void *)qbman_result_DQ_fqd_ctx(dq);
		if (rxq && rxq->cb)
			rxq->cb(dpio_dev, fd, dq, rxq, &ev[num_pkts]);
		else
			qbman_swp_dqrr_consume(swp, dq);

		num_pkts++;
	} while (num_pkts < nb_events);

quit:
	if (dpaa2_portal->port_atomic)
		rte_spinlock_unlock(&dpaa2_portal->port_lock);
	return num_pkts;
}

static uint16_t
dpaa2_eventdev_dequeue(void *port, struct rte_event *ev,
		       uint64_t timeout_ticks)
{
	return dpaa2_eventdev_dequeue_burst(port, ev, 1, timeout_ticks);
}

static void
dpaa2_eventdev_info_get(struct rte_eventdev *dev,
	struct rte_event_dev_info *dev_info)
{
	struct dpaa2_eventdev *priv = dev->data->dev_private;

	EVENTDEV_INIT_FUNC_TRACE();

	memset(dev_info, 0, sizeof(struct rte_event_dev_info));
	dev_info->min_dequeue_timeout_ns =
		DPAA2_EVENT_MIN_DEQUEUE_TIMEOUT;
	dev_info->max_dequeue_timeout_ns =
		DPAA2_EVENT_MAX_DEQUEUE_TIMEOUT;
	dev_info->dequeue_timeout_ns =
		DPAA2_EVENT_PORT_DEQUEUE_TIMEOUT_NS;
	dev_info->max_event_queues = priv->max_event_queues;
	dev_info->max_event_queue_flows =
		DPAA2_EVENT_MAX_QUEUE_FLOWS;
	dev_info->max_event_queue_priority_levels =
		DPAA2_EVENT_MAX_QUEUE_PRIORITY_LEVELS;
	dev_info->max_event_priority_levels =
		DPAA2_EVENT_MAX_EVENT_PRIORITY_LEVELS;
	dev_info->max_event_ports = rte_fslmc_get_device_count(DPAA2_IO);
	if (dev_info->max_event_ports > dev_info->max_event_queues)
		dev_info->max_event_ports = dev_info->max_event_queues;
	/* we only support dpio up to number of cores */
	if (dev_info->max_event_ports > rte_lcore_count())
		dev_info->max_event_ports = rte_lcore_count();
	dev_info->max_event_port_dequeue_depth =
		DPAA2_EVENT_MAX_PORT_DEQUEUE_DEPTH;
	dev_info->max_event_port_enqueue_depth =
		DPAA2_EVENT_MAX_PORT_ENQUEUE_DEPTH;
	dev_info->max_num_events = DPAA2_EVENT_MAX_NUM_EVENTS;
	dev_info->event_dev_cap = RTE_EVENT_DEV_CAP_DISTRIBUTED_SCHED |
		RTE_EVENT_DEV_CAP_BURST_MODE|
		RTE_EVENT_DEV_CAP_RUNTIME_PORT_LINK |
		RTE_EVENT_DEV_CAP_MULTIPLE_QUEUE_PORT |
		RTE_EVENT_DEV_CAP_NONSEQ_MODE |
		RTE_EVENT_DEV_CAP_QUEUE_ALL_TYPES |
		RTE_EVENT_DEV_CAP_CARRY_FLOW_ID |
		RTE_EVENT_DEV_CAP_MAINTENANCE_FREE;

}

static int
dpaa2_eventdev_configure(const struct rte_eventdev *dev)
{
	struct dpaa2_eventdev *priv = dev->data->dev_private;
	struct rte_event_dev_config *conf = &dev->data->dev_conf;

	EVENTDEV_INIT_FUNC_TRACE();

	priv->nb_event_queues = conf->nb_event_queues;
	priv->nb_event_ports = conf->nb_event_ports;
	priv->nb_event_queue_flows = conf->nb_event_queue_flows;
	priv->nb_event_port_dequeue_depth = conf->nb_event_port_dequeue_depth;
	priv->nb_event_port_enqueue_depth = conf->nb_event_port_enqueue_depth;
	priv->event_dev_cfg = conf->event_dev_cfg;

	/* Check dequeue timeout method is per dequeue or global */
	if (priv->event_dev_cfg & RTE_EVENT_DEV_CFG_PER_DEQUEUE_TIMEOUT) {
		/*
		 * Use timeout value as given in dequeue operation.
		 * So invalidating this timeout value.
		 */
		priv->dequeue_timeout_ns = 0;

	} else if (conf->dequeue_timeout_ns == 0) {
		priv->dequeue_timeout_ns = DPAA2_EVENT_PORT_DEQUEUE_TIMEOUT_NS;
	} else {
		priv->dequeue_timeout_ns = conf->dequeue_timeout_ns;
	}

	DPAA2_EVENTDEV_DEBUG("Configured eventdev devid=%d",
			     dev->data->dev_id);
	return 0;
}

static int
dpaa2_eventdev_start(struct rte_eventdev *dev)
{
	struct dpaa2_eventdev *priv = dev->data->dev_private;

	EVENTDEV_INIT_FUNC_TRACE();

	priv->status = DPAA2_EVENTDEV_STARTED;

	return 0;
}

static void
dpaa2_eventdev_stop(struct rte_eventdev *dev)
{
	struct dpaa2_eventdev *priv = dev->data->dev_private;
	uint16_t num, i;
	struct rte_event ev;
	struct dpaa2_port *dpaa2_portal;
	int cpu_affine;

	EVENTDEV_INIT_FUNC_TRACE();

	for (i = 0; i < dev->data->nb_ports; i++) {
		dpaa2_portal = dev->data->ports[i];
		if (!dpaa2_portal || !dpaa2_portal->num_linked_evq)
			continue;
dq_agin:
		rte_delay_ms(1);
		cpu_affine = dpaa2_portal->cpu_affine;
		dpaa2_portal->cpu_affine = rte_lcore_id();
		num = dpaa2_eventdev_dequeue_burst(dpaa2_portal, &ev, 1, 0);
		dpaa2_portal->cpu_affine = cpu_affine;
		if (!num)
			continue;
		if (dev->dev_ops->dev_stop_flush) {
			dev->dev_ops->dev_stop_flush(dev->data->dev_id,
				ev, dev->data->dev_stop_flush_arg);
		}
		goto dq_agin;
	}

	priv->status = DPAA2_EVENTDEV_STOPED;
}

static void
dpaa2_eventdev_port_release(void *port)
{
	struct dpaa2_port *portal = port;
	uint8_t port_id = portal->port_id;
	struct rte_eventdev *eventdev = portal->eventdev;
	int ret;

	EVENTDEV_INIT_FUNC_TRACE();

	if (!portal)
		return;

	/* TODO: Cleanup is required when ports are in linked state. */
	if (portal->num_linked_evq) {
		ret = rte_event_port_unlink(eventdev->data->dev_id, port_id, NULL, 0);
		if (ret < 0) {
			DPAA2_EVENTDEV_ERR("Event port.%d unlink all failed(%d)\n",
				portal->port_id, ret);
		}
	}

	rte_dpaa2_free_dpio_device(portal->dpio_dev);

	rte_free(portal);
	eventdev->data->ports[port_id] = NULL;
}

static int
dpaa2_eventdev_eth_queue_del(const struct rte_eventdev *dev,
	const struct rte_eth_dev *eth_dev, int32_t rx_queue_id)
{
	struct dpaa2_eventdev *priv = dev->data->dev_private;
	struct dpaa2_eventq *evq;
	uint8_t i, j, k, found = false;
	int ret;

	EVENTDEV_INIT_FUNC_TRACE();

	if (!eth_dev || rx_queue_id < 0) {
		for (i = 0; i < priv->max_event_queues; i++) {
			if (!priv->evq_info[i].valid)
				continue;
			evq = &priv->evq_info[i];
			for (j = 0; j < evq->dpni_rxq_num; j++) {
				ret = dpaa2_eth_eventq_detach_by_rxq(evq->dpni_rxqs[j]);
				if (ret)
					return ret;
			}
			evq->dpni_rxq_num = 0;
		}

		return 0;
	}

	for (i = 0; i < priv->max_event_queues; i++) {
		if (!priv->evq_info[i].valid)
			continue;
		evq = &priv->evq_info[i];
		for (j = 0; j < evq->dpni_rxq_num; j++) {
			if (evq->dpni_rxqs[j] == eth_dev->data->rx_queues[rx_queue_id]) {
				found = true;
				for (k = j + 1; k < evq->dpni_rxq_num; k++)
					evq->dpni_rxqs[k - 1] = evq->dpni_rxqs[k];
				evq->dpni_rxq_num--;
				goto start_detach;
			}
		}
	}

start_detach:
	if (found)
		return dpaa2_eth_eventq_detach(eth_dev, rx_queue_id);

	return -ENODEV;
}

static int
dpaa2_eventdev_close(struct rte_eventdev *dev)
{
	struct dpaa2_eventdev *priv = dev->data->dev_private;
	int i, ret;

	EVENTDEV_INIT_FUNC_TRACE();

	if (priv->status == DPAA2_EVENTDEV_CREATED)
		return 0;
	if (priv->status == DPAA2_EVENTDEV_STARTED)
		dpaa2_eventdev_stop(dev);

	for (i = 0; i < dev->data->nb_ports; i++) {
		if (dev->data->ports[i])
			dpaa2_eventdev_port_release(dev->data->ports[i]);
	}

	ret = dpaa2_eventdev_eth_queue_del(dev, NULL, -1);
	if (!ret)
		priv->status = DPAA2_EVENTDEV_CREATED;

	return ret;
}

static void
dpaa2_eventdev_queue_def_conf(struct rte_eventdev *dev, uint8_t queue_id,
			      struct rte_event_queue_conf *queue_conf)
{
	EVENTDEV_INIT_FUNC_TRACE();

	RTE_SET_USED(dev);
	RTE_SET_USED(queue_id);

	queue_conf->nb_atomic_flows = DPAA2_EVENT_QUEUE_ATOMIC_FLOWS;
	queue_conf->nb_atomic_order_sequences =
				DPAA2_EVENT_QUEUE_ORDER_SEQUENCES;
	queue_conf->schedule_type = RTE_SCHED_TYPE_PARALLEL;
	queue_conf->priority = RTE_EVENT_DEV_PRIORITY_NORMAL;
}

static int
dpaa2_eventdev_queue_setup(struct rte_eventdev *dev, uint8_t queue_id,
			   const struct rte_event_queue_conf *queue_conf)
{
	struct dpaa2_eventdev *priv = dev->data->dev_private;
	struct dpaa2_eventq *evq_info = &priv->evq_info[queue_id];

	EVENTDEV_INIT_FUNC_TRACE();

	switch (queue_conf->schedule_type) {
	case RTE_SCHED_TYPE_PARALLEL:
	case RTE_SCHED_TYPE_ATOMIC:
	case RTE_SCHED_TYPE_ORDERED:
		break;
	default:
		DPAA2_EVENTDEV_ERR("Schedule type is not supported.");
		return -1;
	}
	evq_info->event_queue_cfg = queue_conf->event_queue_cfg;
	evq_info->event_queue_id = queue_id;

	return 0;
}

static void
dpaa2_eventdev_queue_release(struct rte_eventdev *dev, uint8_t queue_id)
{
	EVENTDEV_INIT_FUNC_TRACE();

	RTE_SET_USED(dev);
	RTE_SET_USED(queue_id);
}

static void
dpaa2_eventdev_port_def_conf(struct rte_eventdev *dev, uint8_t port_id,
			     struct rte_event_port_conf *port_conf)
{
	EVENTDEV_INIT_FUNC_TRACE();

	RTE_SET_USED(dev);
	RTE_SET_USED(port_id);

	port_conf->new_event_threshold =
		DPAA2_EVENT_MAX_NUM_EVENTS;
	port_conf->dequeue_depth =
		DPAA2_EVENT_MAX_PORT_DEQUEUE_DEPTH;
	port_conf->enqueue_depth =
		DPAA2_EVENT_MAX_PORT_ENQUEUE_DEPTH;
	port_conf->event_port_cfg = 0;
}

static int
dpaa2_eventdev_port_unlink(struct rte_eventdev *dev, void *port,
	uint8_t queues[], uint16_t nb_unlinks)
{
	struct dpaa2_port *dpaa2_portal = port;
	int i, j, ret, num = 0, idx = 0;
	struct dpaa2_dpio_dev *dpio_dev = NULL;
	struct dpaa2_eventq *evq_info;
	struct qbman_swp *swp;
	uint8_t total_queues[DPAA2_EVENT_MAX_QUEUES];
	struct dpaa2_eventq *evq_infos[DPAA2_EVENT_MAX_QUEUES];

	EVENTDEV_INIT_FUNC_TRACE();

	RTE_SET_USED(dev);
	if (!queues) {
		queues = total_queues;
		nb_unlinks = dpaa2_portal->num_linked_evq;
		for (i = 0; i < nb_unlinks; i++)
			queues[i] = dpaa2_portal->evq_info[i]->event_queue_id;
	}

	for (i = 0; i < nb_unlinks; i++) {
		for (j = 0; j < dpaa2_portal->num_linked_evq; j++) {
			evq_info = dpaa2_portal->evq_info[j];
			if (evq_info && evq_info->event_queue_id == queues[i]) {
				dpio_dev = dpaa2_portal->dpio_dev;
				swp = dpio_dev->sw_portal;
				qbman_swp_push_set(swp, evq_info->dpcon->channel_index, 0);
				ret = dpio_remove_static_dequeue_channel(dpio_dev->dpio,
					0, dpio_dev->token, evq_info->dpcon->dpcon_id);
				if (ret)
					return ret;
				evq_info->event_port = NULL;
				dpaa2_portal->evq_info[j] = NULL;
				num++;
				break;
			}
		}
		if (j == dpaa2_portal->num_linked_evq) {
			DPAA2_EVENTDEV_WARN("%s: Event port%d doesn't handle queue[%d]:%d",
				__func__, dpaa2_portal->port_id, i, queues[i]);
		}
	}

	for (i = 0; i < dpaa2_portal->num_linked_evq; i++) {
		if (dpaa2_portal->evq_info[i]) {
			evq_infos[idx] = dpaa2_portal->evq_info[i];
			idx++;
			dpaa2_portal->evq_info[i] = NULL;
		}
	}
	for (i = 0; i < idx; i++)
		dpaa2_portal->evq_info[i] = evq_infos[i];

	dpaa2_portal->num_linked_evq -= num;

	return num;
}

static int
dpaa2_eventdev_port_link(struct rte_eventdev *dev, void *port,
	const uint8_t queues[], const uint8_t priorities[],
	uint16_t nb_links)
{
	struct dpaa2_eventdev *priv = dev->data->dev_private;
	struct dpaa2_port *dpaa2_portal = port;
	struct dpaa2_dpio_dev *dpio_dev = dpaa2_portal->dpio_dev;
	struct dpaa2_eventq *evq_info;
	int ret = 0;
	uint16_t i;
	uint8_t channel_index;

	EVENTDEV_INIT_FUNC_TRACE();

	RTE_SET_USED(priorities);

	if (dpaa2_portal->num_linked_evq > 0) {
		ret = rte_event_port_unlink(dev->data->dev_id,
			dpaa2_portal->port_id, NULL, 0);
		if (ret)
			return ret;
	}

	for (i = 0; i < nb_links; i++) {
		evq_info = &priv->evq_info[queues[i]];
		if (!evq_info->valid) {
			DPAA2_EVENTDEV_WARN("%s: Event port%d.queue%d is not valid!",
				__func__, dpaa2_portal->port_id, queues[i]);
			return -EINVAL;
		}
		if (evq_info->event_port) {
			dpaa2_portal = evq_info->event_port;
			DPAA2_EVENTDEV_WARN("%s: queue%d is occupied by event port%d",
				__func__, queues[i], dpaa2_portal->port_id);
			return -ENODEV;
		}
	}

	for (i = 0; i < nb_links; i++) {
		evq_info = &priv->evq_info[queues[i]];
		ret = dpio_add_static_dequeue_channel(dpio_dev->dpio,
			CMD_PRI_LOW, dpio_dev->token,
			evq_info->dpcon->dpcon_id, &channel_index);
		if (ret) {
			DPAA2_EVENTDEV_ERR("Event port%d.queue%d static dequeue config failed(%d)",
				dpaa2_portal->port_id, queues[i], ret);
			goto err;
		}

		qbman_swp_push_set(dpio_dev->sw_portal, channel_index, 1);
		evq_info->dpcon->channel_index = channel_index;

		dpaa2_portal->evq_info[dpaa2_portal->num_linked_evq] = evq_info;
		evq_info->event_port = dpaa2_portal;
		dpaa2_portal->num_linked_evq++;
	}

err:
	if (ret) {
		nb_links = i;
		for (i = 0; i < nb_links; i++) {
			evq_info = &priv->evq_info[queues[i]];
			evq_info->event_port = NULL;
			qbman_swp_push_set(dpio_dev->sw_portal, channel_index, 0);
			if (dpio_remove_static_dequeue_channel(dpio_dev->dpio,
				0, dpio_dev->token, evq_info->dpcon->dpcon_id)) {
				DPAA2_EVENTDEV_ERR("Event port%d.queue%d remove failed!",
					dpaa2_portal->port_id, queues[i]);
			}
		}
		return ret;
	}

	return (int)nb_links;
}

static int
dpaa2_eventdev_port_setup(struct rte_eventdev *dev, uint8_t port_id,
	const struct rte_event_port_conf *port_conf)
{
	char event_port_name[32];
	struct dpaa2_port *portal;

	EVENTDEV_INIT_FUNC_TRACE();

	if (dev->data->ports[port_id]) {
		DPAA2_EVENTDEV_WARN("Event port%d exists!", port_id);
		dpaa2_eventdev_port_release(dev->data->ports[port_id]);
	}

	sprintf(event_port_name, "event-port-%d", port_id);
	portal = rte_zmalloc(event_port_name, sizeof(struct dpaa2_port), 0);
	if (!portal) {
		DPAA2_EVENTDEV_ERR("Memory allocation failure");
		return -ENOMEM;
	}

	portal->dpio_dev = rte_dpaa2_alloc_dpio_device();
	if (!portal->dpio_dev)
		return -ENODEV;
	if (port_conf &&
		(port_conf->event_port_cfg & RTE_DPAA2_EVENT_PORT_CFG_ATOMIC)) {
		portal->port_atomic = true;
		rte_spinlock_init(&portal->port_lock);
	}
	portal->cpu_affine = -1;
	portal->eventdev = dev;

	portal->port_id = port_id;
	dev->data->ports[port_id] = portal;
	return 0;
}

static int
dpaa2_eventdev_timeout_ticks(struct rte_eventdev *dev, uint64_t ns,
			     uint64_t *timeout_ticks)
{
	uint32_t scale = 1000 * 1000;

	EVENTDEV_INIT_FUNC_TRACE();

	RTE_SET_USED(dev);
	*timeout_ticks = ns / scale;

	return 0;
}

static void
dpaa2_eventdev_dump(struct rte_eventdev *dev, FILE *f)
{
	EVENTDEV_INIT_FUNC_TRACE();

	RTE_SET_USED(dev);
	RTE_SET_USED(f);
}

static int
dpaa2_eventdev_eth_caps_get(const struct rte_eventdev *dev,
	const struct rte_eth_dev *eth_dev, uint32_t *caps)
{
	EVENTDEV_INIT_FUNC_TRACE();

	RTE_SET_USED(dev);

	if (rte_pmd_dpaa2_dev_is_dpaa2(eth_dev->data->port_id))
		*caps = RTE_EVENT_ETH_RX_ADAPTER_DPAA2_CAP;
	else
		*caps = RTE_EVENT_ETH_RX_ADAPTER_SW_CAP;

	return 0;
}

static int
dpaa2_eventdev_eth_queue_add_all(const struct rte_eventdev *dev,
		const struct rte_eth_dev *eth_dev,
		const struct rte_event_eth_rx_adapter_queue_conf *queue_conf)
{
	struct dpaa2_eventdev *priv = dev->data->dev_private;
	int i, ret;

	EVENTDEV_INIT_FUNC_TRACE();

	for (i = 0; i < eth_dev->data->nb_rx_queues; i++) {
		ret = dpaa2_eventdev_attach_eth_rxq(eth_dev, priv, i, queue_conf);
		if (ret)
			return ret;
	}
	return 0;
}

static int
dpaa2_eventdev_eth_queue_add(const struct rte_eventdev *dev,
		const struct rte_eth_dev *eth_dev,
		int32_t rx_queue_id,
		const struct rte_event_eth_rx_adapter_queue_conf *queue_conf)
{
	struct dpaa2_eventdev *priv = dev->data->dev_private;

	EVENTDEV_INIT_FUNC_TRACE();

	if (rx_queue_id < 0) {
		return dpaa2_eventdev_eth_queue_add_all(dev,
				eth_dev, queue_conf);
	}

	return dpaa2_eventdev_attach_eth_rxq(eth_dev, priv, rx_queue_id, queue_conf);
}

static int
dpaa2_eventdev_eth_start(const struct rte_eventdev *dev,
			 const struct rte_eth_dev *eth_dev)
{
	EVENTDEV_INIT_FUNC_TRACE();

	RTE_SET_USED(dev);
	RTE_SET_USED(eth_dev);

	return 0;
}

static int
dpaa2_eventdev_eth_stop(const struct rte_eventdev *dev,
	const struct rte_eth_dev *eth_dev)
{
	struct dpaa2_eventdev *priv = dev->data->dev_private;
	int i, j, k, ret;
	struct dpaa2_eventq *evq;
	struct rte_eventdev _dev;

	EVENTDEV_INIT_FUNC_TRACE();

	/** Drain ingress traffic.*/
	rte_memcpy(&_dev, dev, sizeof(struct rte_eventdev));
	dpaa2_eventdev_stop(&_dev);
	dpaa2_eventdev_start(&_dev);

	for (i = 0; i < priv->max_event_queues; i++) {
		evq = &priv->evq_info[i];
		if (!evq->valid)
			continue;
search_again:
		for (j = 0; j < evq->dpni_rxq_num; j++) {
			if (evq->dpni_rxqs[j]->eth_data == eth_dev->data) {
				ret = dpaa2_eth_eventq_detach_by_rxq(evq->dpni_rxqs[j]);
				if (ret) {
					DPAA2_EVENTDEV_ERR("detach rxq failed(%d)\n", ret);
					return ret;
				}
				for (k = j + 1; k < evq->dpni_rxq_num; k++)
					evq->dpni_rxqs[k - 1] = evq->dpni_rxqs[k];
				evq->dpni_rxq_num--;
				goto search_again;
			}
		}
	}

	return 0;
}

static int
dpaa2_eventdev_crypto_caps_get(const struct rte_eventdev *dev,
			    const struct rte_cryptodev *cdev,
			    uint32_t *caps)
{
	const char *name = cdev->data->name;

	EVENTDEV_INIT_FUNC_TRACE();

	RTE_SET_USED(dev);

	if (!strncmp(name, "dpsec-", 6))
		*caps = RTE_EVENT_CRYPTO_ADAPTER_DPAA2_CAP;
	else
		return -1;

	return 0;
}

static int
dpaa2_eventdev_crypto_queue_add_all(const struct rte_eventdev *dev,
		const struct rte_cryptodev *cryptodev,
		const struct rte_event *ev)
{
	struct dpaa2_eventdev *priv = dev->data->dev_private;
	uint8_t ev_qid = ev->queue_id;
	struct dpaa2_dpcon_dev *dpcon = priv->evq_info[ev_qid].dpcon;
	int i, ret;

	EVENTDEV_INIT_FUNC_TRACE();

	for (i = 0; i < cryptodev->data->nb_queue_pairs; i++) {
		ret = dpaa2_sec_eventq_attach(cryptodev, i, dpcon, ev);
		if (ret) {
			DPAA2_EVENTDEV_ERR("dpaa2_sec_eventq_attach failed: ret %d\n", ret);
			return ret;
		}
	}
	return 0;
}

static int
dpaa2_eventdev_crypto_queue_add(const struct rte_eventdev *dev,
		const struct rte_cryptodev *cryptodev,
		int32_t rx_queue_id,
		const struct rte_event_crypto_adapter_queue_conf *conf)
{
	struct dpaa2_eventdev *priv = dev->data->dev_private;
	uint8_t ev_qid = conf->ev.queue_id;
	struct dpaa2_dpcon_dev *dpcon = priv->evq_info[ev_qid].dpcon;
	int ret;

	EVENTDEV_INIT_FUNC_TRACE();

	if (rx_queue_id == -1)
		return dpaa2_eventdev_crypto_queue_add_all(dev,
				cryptodev, &conf->ev);

	ret = dpaa2_sec_eventq_attach(cryptodev, rx_queue_id,
				      dpcon, &conf->ev);
	if (ret) {
		DPAA2_EVENTDEV_ERR(
			"dpaa2_sec_eventq_attach failed: ret: %d\n", ret);
		return ret;
	}
	return 0;
}

static int
dpaa2_eventdev_crypto_queue_del(const struct rte_eventdev *dev,
			     const struct rte_cryptodev *cryptodev,
			     int32_t rx_queue_id)
{
	EVENTDEV_INIT_FUNC_TRACE();

	RTE_SET_USED(dev);
	RTE_SET_USED(cryptodev);
	RTE_SET_USED(rx_queue_id);

	return 0;
}

static int
dpaa2_eventdev_crypto_start(const struct rte_eventdev *dev,
			    const struct rte_cryptodev *cryptodev)
{
	EVENTDEV_INIT_FUNC_TRACE();

	RTE_SET_USED(dev);
	RTE_SET_USED(cryptodev);

	return 0;
}

static int
dpaa2_eventdev_crypto_stop(const struct rte_eventdev *dev,
			   const struct rte_cryptodev *cryptodev)
{
	EVENTDEV_INIT_FUNC_TRACE();

	RTE_SET_USED(dev);
	RTE_SET_USED(cryptodev);

	return 0;
}

static int
dpaa2_eventdev_tx_adapter_create(uint8_t id,
				 const struct rte_eventdev *dev)
{
	RTE_SET_USED(id);
	RTE_SET_USED(dev);

	/* Nothing to do. Simply return. */
	return 0;
}

static int
dpaa2_eventdev_tx_adapter_caps(const struct rte_eventdev *dev,
			       const struct rte_eth_dev *eth_dev,
			       uint32_t *caps)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(eth_dev);

	*caps = RTE_EVENT_ETH_TX_ADAPTER_CAP_INTERNAL_PORT;
	return 0;
}

static uint16_t
dpaa2_eventdev_txa_enqueue_same_dest(void *port,
	struct rte_event ev[], uint16_t nb_events)
{
	struct rte_mbuf *m[DPAA2_EVENT_MAX_PORT_ENQUEUE_DEPTH], *m0;
	uint8_t qid, i;

	RTE_SET_USED(port);

	m0 = ev[0].mbuf;
	qid = rte_event_eth_tx_adapter_txq_get(m0);

	for (i = 0; i < nb_events; i++) {
		m[i] = ev[i].mbuf;
		if (unlikely(m[i]->port != m0->port)) {
			DPAA2_EVENTDEV_ERR("m[%d]->port(%d) != port(%d)",
				i, m[i]->port, m0->port);
			return 0;
		}
	}

	return rte_eth_tx_burst(m0->port, qid, m, nb_events);
}

static uint16_t
dpaa2_eventdev_txa_enqueue(void *port,
	struct rte_event ev[], uint16_t nb_events)
{
	void *txq[DPAA2_EVENT_MAX_PORT_ENQUEUE_DEPTH];
	struct rte_mbuf *m[DPAA2_EVENT_MAX_PORT_ENQUEUE_DEPTH];
	uint8_t qid, i;

	RTE_SET_USED(port);

	for (i = 0; i < nb_events; i++) {
		m[i] = ev[i].mbuf;
		qid = rte_event_eth_tx_adapter_txq_get(m[i]);
		txq[i] = rte_eth_devices[m[i]->port].data->tx_queues[qid];
	}

	return dpaa2_dev_tx_multi_txq_ordered(txq, m, nb_events);
}

static struct eventdev_ops dpaa2_eventdev_ops = {
	.dev_infos_get    = dpaa2_eventdev_info_get,
	.dev_configure    = dpaa2_eventdev_configure,
	.dev_start        = dpaa2_eventdev_start,
	.dev_stop         = dpaa2_eventdev_stop,
	.dev_close        = dpaa2_eventdev_close,
	.queue_def_conf   = dpaa2_eventdev_queue_def_conf,
	.queue_setup      = dpaa2_eventdev_queue_setup,
	.queue_release    = dpaa2_eventdev_queue_release,
	.port_def_conf    = dpaa2_eventdev_port_def_conf,
	.port_setup       = dpaa2_eventdev_port_setup,
	.port_release     = dpaa2_eventdev_port_release,
	.port_link        = dpaa2_eventdev_port_link,
	.port_unlink      = dpaa2_eventdev_port_unlink,
	.timeout_ticks    = dpaa2_eventdev_timeout_ticks,
	.dump             = dpaa2_eventdev_dump,
	.dev_selftest     = test_eventdev_dpaa2,
	.eth_rx_adapter_caps_get	= dpaa2_eventdev_eth_caps_get,
	.eth_rx_adapter_queue_add	= dpaa2_eventdev_eth_queue_add,
	.eth_rx_adapter_queue_del	= dpaa2_eventdev_eth_queue_del,
	.eth_rx_adapter_start		= dpaa2_eventdev_eth_start,
	.eth_rx_adapter_stop		= dpaa2_eventdev_eth_stop,
	.eth_tx_adapter_caps_get	= dpaa2_eventdev_tx_adapter_caps,
	.eth_tx_adapter_create		= dpaa2_eventdev_tx_adapter_create,
	.crypto_adapter_caps_get	= dpaa2_eventdev_crypto_caps_get,
	.crypto_adapter_queue_pair_add	= dpaa2_eventdev_crypto_queue_add,
	.crypto_adapter_queue_pair_del	= dpaa2_eventdev_crypto_queue_del,
	.crypto_adapter_start		= dpaa2_eventdev_crypto_start,
	.crypto_adapter_stop		= dpaa2_eventdev_crypto_stop,
};

static int
dpaa2_eventdev_create(const char *name, struct rte_vdev_device *vdev)
{
	struct rte_eventdev *eventdev;
	struct dpaa2_eventdev *priv;
	struct dpaa2_dpcon_dev *dpcon_dev = NULL;
	struct dpaa2_dpci_dev *dpci_dev = NULL;
	struct dpaa2_eventq *evq_info;
	int ret;

	eventdev = rte_event_pmd_vdev_init(name,
		sizeof(struct dpaa2_eventdev), rte_socket_id(), vdev);
	if (!eventdev) {
		DPAA2_EVENTDEV_ERR("Failed to create Event device %s", name);
		goto fail;
	}

	eventdev->dev_ops = &dpaa2_eventdev_ops;
	eventdev->enqueue = dpaa2_eventdev_enqueue;
	eventdev->enqueue_burst = dpaa2_eventdev_enqueue_burst;
	eventdev->enqueue_new_burst = dpaa2_eventdev_enqueue_burst;
	eventdev->enqueue_forward_burst = dpaa2_eventdev_enqueue_burst;
	eventdev->dequeue = dpaa2_eventdev_dequeue;
	eventdev->dequeue_burst = dpaa2_eventdev_dequeue_burst;
	eventdev->txa_enqueue = dpaa2_eventdev_txa_enqueue;
	eventdev->txa_enqueue_same_dest = dpaa2_eventdev_txa_enqueue_same_dest;

	/* For secondary processes, the primary has done all the work */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		goto done;

	priv = eventdev->data->dev_private;
	memset(priv, 0, sizeof(struct dpaa2_eventdev));

	do {
		evq_info = &priv->evq_info[priv->max_event_queues];
		dpcon_dev = rte_dpaa2_alloc_dpcon_dev();
		if (!dpcon_dev)
			break;
		evq_info->dpcon = dpcon_dev;

		dpci_dev = rte_dpaa2_alloc_dpci_dev();
		if (!dpci_dev) {
			rte_dpaa2_free_dpcon_dev(dpcon_dev);
			break;
		}
		evq_info->dpci = dpci_dev;

		ret = rte_dpaa2_dpci_link_attach(dpci_dev, DPCI_DEST_DPCON,
				dpcon_dev->dpcon_id, 0,
				dpaa2_eventdev_process_parallel,
				&evq_info->dpci_txqs[RTE_SCHED_TYPE_PARALLEL]);
		if (ret) {
			DPAA2_EVENTDEV_ERR("DPCI attach parallel RX failed: err(%d)", ret);
			return ret;
		}

		ret = rte_dpaa2_dpci_link_attach(dpci_dev, DPCI_DEST_DPCON,
				dpcon_dev->dpcon_id, 0,
				dpaa2_eventdev_process_atomic,
				&evq_info->dpci_txqs[RTE_SCHED_TYPE_ATOMIC]);
		if (ret) {
			DPAA2_EVENTDEV_ERR("DPCI attach parallel RX failed: err(%d)", ret);
			return ret;
		}
		/** TO DO: order schedule.*/
		/** Borrow atomic tx.*/
		evq_info->dpci_txqs[RTE_SCHED_TYPE_ORDERED] =
			evq_info->dpci_txqs[RTE_SCHED_TYPE_ATOMIC];

		evq_info->valid = true;
		evq_info->event_port = NULL;

		priv->max_event_queues++;
		if (priv->max_event_queues >= DPAA2_EVENT_MAX_QUEUES)
			break;
	} while (dpcon_dev && dpci_dev);

	RTE_LOG(INFO, PMD, "%s eventdev created\n", name);

done:
	event_dev_probing_finish(eventdev);
	return 0;
fail:
	return -EFAULT;
}

static int
dpaa2_eventdev_destroy(const char *name)
{
	struct rte_eventdev *eventdev;
	struct dpaa2_eventdev *priv;
	int i;

	eventdev = rte_event_pmd_get_named_dev(name);
	if (eventdev == NULL) {
		RTE_EDEV_LOG_ERR("eventdev with name %s not allocated", name);
		return -1;
	}

	/* For secondary processes, the primary has done all the work */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	priv = eventdev->data->dev_private;
	for (i = 0; i < priv->max_event_queues; i++) {
		if (priv->evq_info[i].dpcon)
			rte_dpaa2_free_dpcon_dev(priv->evq_info[i].dpcon);

		if (priv->evq_info[i].dpci)
			rte_dpaa2_free_dpci_dev(priv->evq_info[i].dpci);
	}
	priv->max_event_queues = 0;

	RTE_LOG(INFO, PMD, "%s eventdev cleaned\n", name);
	return 0;
}

static int
dpaa2_eventdev_probe(struct rte_vdev_device *vdev)
{
	const char *name;

	name = rte_vdev_device_name(vdev);
	DPAA2_EVENTDEV_INFO("Initializing %s", name);
	return dpaa2_eventdev_create(name, vdev);
}

static int
dpaa2_eventdev_remove(struct rte_vdev_device *vdev)
{
	const char *name;

	name = rte_vdev_device_name(vdev);
	DPAA2_EVENTDEV_INFO("Closing %s", name);

	dpaa2_eventdev_destroy(name);

	return rte_event_pmd_vdev_uninit(name);
}

static struct rte_vdev_driver vdev_eventdev_dpaa2_pmd = {
	.probe = dpaa2_eventdev_probe,
	.remove = dpaa2_eventdev_remove
};

RTE_PMD_REGISTER_VDEV(EVENTDEV_NAME_DPAA2_PMD, vdev_eventdev_dpaa2_pmd);
RTE_LOG_REGISTER_DEFAULT(dpaa2_logtype_event, NOTICE);

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
#include <rte_mbuf.h>
#include <dev_driver.h>
#include <rte_hexdump.h>
#include <dev_driver.h>
#include <ethdev_driver.h>
#include <compat.h>

#include <bus_fslmc_driver.h>
#include <mc/fsl_dpcon.h>
#include <portal/dpaa2_hw_pvt.h>
#include <dpaa2_hw_dpio.h>
#include "dpaa2_ethdev.h"
#include "dpaa2_pmd_logs.h"

TAILQ_HEAD(dpcon_dev_list, dpaa2_dpcon_dev);
static struct dpcon_dev_list dpcon_dev_list =
		TAILQ_HEAD_INITIALIZER(dpcon_dev_list); /*!< DPCON device list */

static int
dpaa2_dpcon_dq_storage_init(struct dpaa2_dpcon_dev *dpcon_dev)
{
	int i, ret = 0;

	memset(&dpcon_dev->q_storage, 0,
		sizeof(struct queue_storage_info_t) * RTE_MAX_LCORE);

	for (i = 0; i < RTE_MAX_LCORE; i++) {
		ret = dpaa2_alloc_dq_storage(&dpcon_dev->q_storage[i]);
		if (ret)
			goto err;
	}
	return 0;
err:
	for (i = 0; i < RTE_MAX_LCORE; i++)
		dpaa2_free_dq_storage(&dpcon_dev->q_storage[i]);

	return ret;
}

int32_t
dpaa2_dpcon_start(struct dpaa2_dpcon_dev *dpcon_dev)
{
	int32_t ret;

	ret = dpcon_enable(&dpcon_dev->dpcon, CMD_PRI_LOW, dpcon_dev->token);
	if (ret) {
		DPAA2_PMD_ERR("DPCONC is not enabled at MC: Error code = %0x\n",
			ret);
	}

	return ret;
}

int32_t
dpaa2_dpcon_stop(struct dpaa2_dpcon_dev *dpcon_dev)
{
	int32_t ret;

	ret = dpcon_disable(&dpcon_dev->dpcon, CMD_PRI_LOW, dpcon_dev->token);
	if (ret) {
		DPAA2_PMD_ERR("Device cannot be disabled:Error Code = %0x\n",
			ret);
	}

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
		qbman_pull_type_active_noics);
	qbman_pull_desc_set_storage(pulldesc, dq_sch_storage,
		iova_storage, 1);
}

static uint16_t
dpaa2_dpcon_recv(struct dpaa2_dpcon_dev *dpcon_dev,
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
			DPAA2_PMD_ERR("Failure(%d) in affining portal", ret);
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
				DPAA2_PMD_DP_DEBUG("QBMAN is busy (1)");
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
			while (!qbman_result_has_new_result(swp,
				dq_sch_storage))
				;

			/* Check whether Last Pull command is Expired and
			 * setting Condition for Loop termination
			 */
			if (qbman_result_DQ_is_pull_complete(dq_sch_storage)) {
				is_last = true;
				/* Check for valid frame. */
				status = qbman_result_DQ_flags(dq_sch_storage);
				if (unlikely(!(status &
					QBMAN_DQ_STAT_VALIDFRAME))) {
					next_pull = true;
					DPAA2_PMD_DP_DEBUG("No frame is delivered\n");
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
				mbuf[rcvd_pkts] = eth_sg_fd_to_mbuf(priv, fd);
			else
				mbuf[rcvd_pkts] = eth_fd_to_mbuf(priv, fd);
			rcvd_pkts++;
			dq_sch_storage++;
			iova_storage += sizeof(struct qbman_result);
		}
	} while (!next_pull);
	/* End of Packet Rx loop */
	DPAA2_PMD_DP_DEBUG("DPCONC Received %d Packets\n", rcvd_pkts);

	return rcvd_pkts;
}

static uint16_t
dpaa2_dpcon_prefetch_recv(struct dpaa2_dpcon_dev *dpcon_dev,
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
			DPAA2_PMD_ERR("Failure(%d) in affining portal", ret);
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
			DPAA2_PMD_DP_DEBUG("QBMAN is busy (1)");
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
			mbuf[rcvd_pkts] = eth_sg_fd_to_mbuf(priv, fd);
		else
			mbuf[rcvd_pkts] = eth_fd_to_mbuf(priv, fd);
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
			DPAA2_PMD_DP_DEBUG("QBMAN is busy (2)");
			continue;
		}
		break;
	}
	q_storage->active_dqs = dq_storage1;
	q_storage->active_dpio_id = ethrx_dpio_dev->index;
	set_swp_active_dqs(ethrx_dpio_dev->index, dq_storage1);

	return rcvd_pkts;
}

static int
dpaa2_create_dpcon_device(int dev_fd __rte_unused,
	struct vfio_device_info *obj_info __rte_unused,
	struct rte_dpaa2_device *obj)
{
	struct dpaa2_dpcon_dev *dpcon_dev;
	struct dpcon_attr attr;
	int ret = 0, dpcon_id = obj->object_id;

	/* Allocate DPAA2 dpcon handle */
	dpcon_dev = rte_malloc(NULL, sizeof(struct dpaa2_dpcon_dev), 0);
	if (!dpcon_dev) {
		DPAA2_PMD_ERR("Memory allocation failed for dpcon device");
		return -ENOMEM;
	}

	/* Open the dpcon object via MC and save handle for further use */
	dpcon_dev->dpcon.regs = dpaa2_get_mcp_ptr(MC_PORTAL_INDEX);
	ret = dpcon_open(&dpcon_dev->dpcon,
			CMD_PRI_LOW, dpcon_id, &dpcon_dev->token);
	if (ret) {
		DPAA2_PMD_ERR("Unable to open dpcon device: err(%d)", ret);
		rte_free(dpcon_dev);
		return ret;
	}

	/* Get the resource information i.e. Channel ID, dpconc ID, priority*/
	ret = dpcon_get_attributes(&dpcon_dev->dpcon,
		CMD_PRI_LOW, dpcon_dev->token, &attr);
	if (ret) {
		DPAA2_PMD_ERR("dpcon attribute fetch failed: err(%d)", ret);
		goto get_attr_failure;
	}

	/* Updating device specific private information*/
	dpcon_dev->dpcon_id = dpcon_id;
	dpcon_dev->qbman_ch_id = attr.qbman_ch_id;
	dpcon_dev->num_priorities = attr.num_priorities;
	DPAA2_PMD_DEBUG("Channel ID = %d\t Priority Num = %d Object ID = %d",
			dpcon_dev->qbman_ch_id, dpcon_dev->num_priorities,
			dpcon_dev->dpcon_id);

	ret = dpaa2_dpcon_dq_storage_init(dpcon_dev);
	if (ret) {
		DPAA2_PMD_ERR("dpcon init storage info failed: err(%d)", ret);
		goto get_attr_failure;
	}

	rte_atomic16_init(&dpcon_dev->in_use);
	TAILQ_INSERT_TAIL(&dpcon_dev_list, dpcon_dev, next);
	return ret;

get_attr_failure:
	dpcon_close(&dpcon_dev->dpcon, CMD_PRI_LOW, dpcon_dev->token);
	rte_free(dpcon_dev);
	return ret;
}

struct dpaa2_dpcon_dev *dpaa2_alloc_dpcon_dev(void)
{
	struct dpaa2_dpcon_dev *dpcon_dev = NULL;
	char *env = getenv("DPAA2_SCHEDULE_RX_PREFETCH");
	int prefetch_enable = env ? atoi(env) : 1;

	/* Get DPCON dev handle from list using index */
	TAILQ_FOREACH(dpcon_dev, &dpcon_dev_list, next) {
		if (dpcon_dev && rte_atomic16_test_and_set(&dpcon_dev->in_use))
			break;
	}
	if (dpcon_dev) {
		if (prefetch_enable)
			dpcon_dev->rx_schedule = dpaa2_dpcon_prefetch_recv;
		else
			dpcon_dev->rx_schedule = dpaa2_dpcon_recv;
	}

	return dpcon_dev;
}

void
dpaa2_free_dpcon_dev(struct dpaa2_dpcon_dev *dpcon)
{
	struct dpaa2_dpcon_dev *dpcon_dev = NULL;

	/* Match DPCON handle and mark it free */
	TAILQ_FOREACH(dpcon_dev, &dpcon_dev_list, next) {
		if (dpcon_dev == dpcon) {
			rte_atomic16_dec(&dpcon_dev->in_use);
			return;
		}
	}
}

static struct dpaa2_dpcon_dev
*get_dpcon_from_id(uint32_t dpcon_id)
{
	struct dpaa2_dpcon_dev *dpcon_dev = NULL;

	/* Get DPCONC dev handle from list using index */
	TAILQ_FOREACH(dpcon_dev, &dpcon_dev_list, next) {
		if (dpcon_dev->dpcon_id == dpcon_id)
			break;
	}

	return dpcon_dev;
}

static void
dpaa2_close_dpcon_device(int object_id)
{
	struct dpaa2_dpcon_dev *dpcon_dev = NULL;
	int32_t ret, i;

	dpcon_dev = get_dpcon_from_id((uint32_t)object_id);
	if (dpcon_dev) {
		/*Reset the device to it's default state*/
		ret = dpcon_reset(&dpcon_dev->dpcon, CMD_PRI_LOW, dpcon_dev->token);
		if (ret)
			DPAA2_PMD_ERR("Error in resetting  the device: err(%d)", ret);

		dpaa2_free_dpcon_dev(dpcon_dev);
		dpcon_close(&dpcon_dev->dpcon, CMD_PRI_LOW, dpcon_dev->token);
		if (ret)
			DPAA2_PMD_ERR("Error in closing the device: err(%d)", ret);
		TAILQ_REMOVE(&dpcon_dev_list, dpcon_dev, next);
		for (i = 0; i < RTE_MAX_LCORE; i++)
			dpaa2_free_dq_storage(&dpcon_dev->q_storage[i]);
		rte_free(dpcon_dev);
	}
}

static struct rte_dpaa2_object rte_dpaa2_dpcon_obj = {
	.dev_type = DPAA2_CON,
	.create = dpaa2_create_dpcon_device,
	.close = dpaa2_close_dpcon_device,
};

RTE_PMD_REGISTER_DPAA2_OBJECT(dpaa2_dpcon, rte_dpaa2_dpcon_obj);

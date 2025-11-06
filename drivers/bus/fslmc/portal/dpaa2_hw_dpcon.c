/* SPDX-License-Identifier: BSD-3-Clause
 *
 *   Copyright 2017, 2020, 2023, 2025 NXP
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

#include <bus_fslmc_driver.h>
#include <fslmc_logs.h>
#include <mc/fsl_dpcon.h>
#include <portal/dpaa2_hw_dpio.h>
#include <portal/dpaa2_hw_pvt.h>

TAILQ_HEAD(dpcon_dev_list, dpaa2_dpcon_dev);
static struct dpcon_dev_list dpcon_dev_list
	= TAILQ_HEAD_INITIALIZER(dpcon_dev_list); /*!< DPCON device list */

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

__rte_internal
int32_t
rte_dpaa2_dpcon_start(struct dpaa2_dpcon_dev *dpcon_dev)
{
	int32_t ret;

	ret = dpcon_enable(&dpcon_dev->dpcon, CMD_PRI_LOW, dpcon_dev->token);
	if (ret) {
		DPAA2_BUS_ERR("DPCONC is not enabled at MC: Error code = %0x\n",
			ret);
	}

	return ret;
}

__rte_internal
int32_t
rte_dpaa2_dpcon_stop(struct dpaa2_dpcon_dev *dpcon_dev)
{
	int32_t ret;

	ret = dpcon_disable(&dpcon_dev->dpcon, CMD_PRI_LOW, dpcon_dev->token);
	if (ret) {
		DPAA2_BUS_ERR("Device cannot be disabled:Error Code = %0x\n",
			ret);
	}

	return ret;
}

static struct dpaa2_dpcon_dev *get_dpcon_from_id(uint32_t dpcon_id)
{
	struct dpaa2_dpcon_dev *dpcon_dev = NULL;

	/* Get DPCONC dev handle from list using index */
	TAILQ_FOREACH(dpcon_dev, &dpcon_dev_list, next) {
		if (dpcon_dev->dpcon_id == dpcon_id)
			break;
	}

	return dpcon_dev;
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
		DPAA2_BUS_ERR("Memory allocation failed for dpcon device");
		return -ENOMEM;
	}

	/* Open the dpcon object via MC and save handle for further use */
	dpcon_dev->dpcon.regs = dpaa2_get_mcp_ptr(MC_PORTAL_INDEX);
	ret = dpcon_open(&dpcon_dev->dpcon,
			CMD_PRI_LOW, dpcon_id, &dpcon_dev->token);
	if (ret) {
		DPAA2_BUS_ERR("Unable to open dpcon device: err(%d)", ret);
		rte_free(dpcon_dev);
		return ret;
	}

	/* Get the resource information i.e. Channel ID, dpconc ID, priority*/
	ret = dpcon_get_attributes(&dpcon_dev->dpcon,
		CMD_PRI_LOW, dpcon_dev->token, &attr);
	if (ret) {
		DPAA2_BUS_ERR("dpcon attribute fetch failed: err(%d)", ret);
		goto get_attr_failure;
	}

	/* Updating device specific private information*/
	dpcon_dev->dpcon_id = dpcon_id;
	dpcon_dev->qbman_ch_id = attr.qbman_ch_id;
	dpcon_dev->num_priorities = attr.num_priorities;
	DPAA2_BUS_DEBUG("Channel ID = %d\t Priority Num = %d Object ID = %d",
			dpcon_dev->qbman_ch_id, dpcon_dev->num_priorities,
			dpcon_dev->dpcon_id);

	ret = dpaa2_dpcon_dq_storage_init(dpcon_dev);
	if (ret) {
		DPAA2_BUS_ERR("dpcon init storage info failed: err(%d)", ret);
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

__rte_internal
struct dpaa2_dpcon_dev *rte_dpaa2_alloc_dpcon_dev(void)
{
	struct dpaa2_dpcon_dev *dpcon_dev = NULL;

	/* Get DPCON dev handle from list using index */
	TAILQ_FOREACH(dpcon_dev, &dpcon_dev_list, next) {
		if (dpcon_dev && rte_atomic16_test_and_set(&dpcon_dev->in_use))
			break;
	}

	return dpcon_dev;
}

__rte_internal
void rte_dpaa2_free_dpcon_dev(struct dpaa2_dpcon_dev *dpcon)
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

static void
dpaa2_close_dpcon_device(int object_id)
{
	struct dpaa2_dpcon_dev *dpcon_dev = NULL;

	dpcon_dev = get_dpcon_from_id((uint32_t)object_id);

	if (dpcon_dev) {
		rte_dpaa2_free_dpcon_dev(dpcon_dev);
		dpcon_close(&dpcon_dev->dpcon, CMD_PRI_LOW, dpcon_dev->token);
		TAILQ_REMOVE(&dpcon_dev_list, dpcon_dev, next);
		rte_free(dpcon_dev);
	}
}

static struct rte_dpaa2_object rte_dpaa2_dpcon_obj = {
	.dev_type = DPAA2_CON,
	.create = dpaa2_create_dpcon_device,
	.close = dpaa2_close_dpcon_device,
};

RTE_PMD_REGISTER_DPAA2_OBJECT(dpcon, rte_dpaa2_dpcon_obj);

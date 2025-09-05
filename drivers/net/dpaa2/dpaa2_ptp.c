/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019, 2023-2025 NXP
 */

#include <sys/queue.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>

#include <ethdev_driver.h>
#include <rte_log.h>
#include <rte_eth_ctrl.h>
#include <rte_malloc.h>
#include <rte_time.h>

#include <bus_fslmc_driver.h>
#include <fsl_dprtc.h>
#include <fsl_dpkg.h>

#include <dpaa2_ethdev.h>
#include <dpaa2_pmd_logs.h>
#include <dpaax_ptp.h>

struct dpaa2_dprtc_dev {
	struct fsl_mc_io dprtc;  /** handle to DPRTC portal object */
	uint16_t token;
	uint32_t dprtc_id; /*HW ID for DPRTC object */
};
static struct dpaa2_dprtc_dev *dprtc_dev;

static int
dpaa2_timesync_set_one_step(struct rte_eth_dev *dev,
	uint16_t offset, int udp)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = dev->process_private;
	struct dpni_single_step_cfg cfg;
	int err;

	memset(&cfg, 0, sizeof(struct dpni_single_step_cfg));
	cfg.en = 1;
	cfg.ch_update = udp;
	cfg.offset = offset;
	cfg.peer_delay = 0;

	err = dpni_set_single_step_cfg(dpni, CMD_PRI_LOW, priv->token, &cfg);
	if (err)
		return err;

	priv->ptp_correction_offset = offset;

	return 0;
}

void
dpaa2_dev_tx_ptp_one_step_runtime(struct rte_eth_dev *dev,
	struct rte_mbuf *buf, int *tstamp, int *set)
{
	uint16_t ts_offset;
	int is_udp = false, ret = 0;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;

	if (tstamp)
		*tstamp = false;
	if (set)
		*set = false;

	if (!dpaax_timesync_ptp_parse_header(buf,
		&ts_offset, &is_udp)) {
		DPAA2_PMD_WARN("Tx packet is not PTP frame.\n");
		ret = -EINVAL;
	} else {
		if (ts_offset != priv->ptp_correction_offset) {
			ret = dpaa2_timesync_set_one_step(dev, ts_offset, is_udp);
			if (ret) {
				DPAA2_PMD_WARN("Change one step failed(%d)\n", ret);
			} else {
				DPAA2_PMD_INFO("Change one step from offset %d to %d\n",
					priv->ptp_correction_offset, ts_offset);
				priv->ptp_correction_offset = ts_offset;
				if (set)
					*set = true;
			}
		}
	}

	if (!ret && tstamp)
		*tstamp = true;
}

int dpaa2_timesync_enable(struct rte_eth_dev *dev)
{
	uint16_t default_offset;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	int ret;

	default_offset = RTE_ETHER_HDR_LEN +
		offsetof(struct rte_dpaax_ptp_header, correction);

	ret = dpaa2_timesync_set_one_step(dev, default_offset, false);
	if (ret) {
		DPAA2_PMD_ERR("%s one step timesyc set failed(%d)\n",
			dev->data->name, ret);
	} else {
		priv->flags |= DPAA2_IEEE1588_TX_TS_FLAG;
	}
	priv->flags |= DPAA2_IEEE1588_RX_TS_FLAG;
	if (priv->tx_conf_type == DPAA2_TX_NO_CONF) {
		DPAA2_PMD_WARN("%s Unable to read TX timestamp\n",
			dev->data->name);
	}
	if (getenv("DPAA2_IEEE1588_DEBUG_ENABLE"))
		priv->flags |= DPAA2_IEEE1588_DEBUG_FLAG;

	return 0;
}

int dpaa2_timesync_disable(struct rte_eth_dev *dev)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;

	priv->ptp_correction_offset = 0;
	priv->flags &= ~DPAA2_IEEE1588_RX_TS_FLAG;
	priv->flags &= ~DPAA2_IEEE1588_TX_TS_FLAG;
	return 0;
}

int dpaa2_timesync_read_time(struct rte_eth_dev *dev,
	struct timespec *timestamp)
{
	uint64_t ns;
	int ret = 0;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;

	if (!dprtc_dev)
		return -ENODEV;

	ret = dprtc_get_time(&dprtc_dev->dprtc, CMD_PRI_LOW,
			dprtc_dev->token, &ns);
	if (ret) {
		DPAA2_PMD_ERR("dprtc_get_time failed ret: %d", ret);
		return ret;
	}

	*timestamp = rte_ns_to_timespec(ns);
	dpaa2_timestamp_debug(priv, __func__, ns);

	return 0;
}

int dpaa2_timesync_write_time(struct rte_eth_dev *dev,
	const struct timespec *ts)
{
	uint64_t ns;
	int ret = 0;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;

	if (!dprtc_dev)
		return -ENODEV;

	ns = rte_timespec_to_ns(ts);
	ret = dprtc_set_time(&dprtc_dev->dprtc, CMD_PRI_LOW,
			dprtc_dev->token, ns);
	if (ret) {
		DPAA2_PMD_ERR("dprtc_set_time failed ret: %d", ret);
		return ret;
	}
	dpaa2_timestamp_debug(priv, __func__, ns);

	return 0;
}

int dpaa2_timesync_adjust_time(struct rte_eth_dev *dev, int64_t delta)
{
	uint64_t ns;
	int ret = 0;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;

	if (!dprtc_dev)
		return -ENODEV;

	ret = dprtc_get_time(&dprtc_dev->dprtc, CMD_PRI_LOW,
			dprtc_dev->token, &ns);
	if (ret) {
		DPAA2_PMD_ERR("dprtc_get_time failed ret: %d", ret);
		return ret;
	}

	ns += delta;

	ret = dprtc_set_time(&dprtc_dev->dprtc, CMD_PRI_LOW,
			     dprtc_dev->token, ns);
	if (ret) {
		DPAA2_PMD_ERR("dprtc_set_time failed ret: %d", ret);
		return ret;
	}
	dpaa2_timestamp_debug(priv, "adjust delata", delta);
	dpaa2_timestamp_debug(priv, "adjust absolute", ns);

	return 0;
}

int dpaa2_timesync_read_tx_timestamp(struct rte_eth_dev *dev,
	struct timespec *timestamp)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;

	if (!(priv->flags & DPAA2_IEEE1588_TX_TS_FLAG) ||
		priv->tx_conf_type == DPAA2_TX_NO_CONF)
		return -EINVAL;

	while (priv->next_txq_to_cnf &&
		priv->next_txq_to_cnf->ts_to_cnfd > 0)
		dpaa2_dev_tx_conf(priv->next_txq_to_cnf, false);

	*timestamp = rte_ns_to_timespec(priv->tx_timestamp);
	dpaa2_timestamp_debug(priv, __func__, priv->tx_timestamp);

	return 0;
}

int dpaa2_timesync_read_rx_timestamp(struct rte_eth_dev *dev,
	struct timespec *timestamp, uint32_t flags __rte_unused)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;

	if (!(priv->flags & DPAA2_IEEE1588_RX_TS_FLAG))
		return -EINVAL;

	*timestamp = rte_ns_to_timespec(priv->rx_timestamp);
	dpaa2_timestamp_debug(priv, __func__, priv->rx_timestamp);

	return 0;
}

static int
dpaa2_create_dprtc_device(int vdev_fd __rte_unused,
	struct vfio_device_info *obj_info __rte_unused,
	struct rte_dpaa2_device *obj)
{
	struct dprtc_attr attr;
	int ret = 0, dprtc_id = obj->object_id;

	PMD_INIT_FUNC_TRACE();

	/* Allocate DPAA2 dprtc handle */
	dprtc_dev = rte_zmalloc(NULL, sizeof(struct dpaa2_dprtc_dev), 0);
	if (!dprtc_dev) {
		DPAA2_PMD_ERR("Memory allocation failed for DPRTC Device");
		return -ENOMEM;
	}

	/* Open the dprtc object */
	dprtc_dev->dprtc.regs = dpaa2_get_mcp_ptr(MC_PORTAL_INDEX);
	ret = dprtc_open(&dprtc_dev->dprtc, CMD_PRI_LOW, dprtc_id,
			&dprtc_dev->token);
	if (ret) {
		DPAA2_PMD_ERR("Unable to open dprtc object: err(%d)", ret);
		goto init_err;
	}

	ret = dprtc_get_attributes(&dprtc_dev->dprtc, CMD_PRI_LOW,
			dprtc_dev->token, &attr);
	if (ret) {
		DPAA2_PMD_ERR("Unable to get dprtc attr: err(%d)", ret);
		goto init_err;
	}

	dprtc_dev->dprtc_id = dprtc_id;

	return 0;

init_err:
	rte_free(dprtc_dev);

	return ret;
}

static struct rte_dpaa2_object rte_dpaa2_dprtc_obj = {
	.dev_type = DPAA2_DPRTC,
	.create = dpaa2_create_dprtc_device,
};

RTE_PMD_REGISTER_DPAA2_OBJECT(dprtc, rte_dpaa2_dprtc_obj);

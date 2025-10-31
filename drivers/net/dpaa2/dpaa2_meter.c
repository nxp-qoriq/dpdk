/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#include <sys/queue.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/mman.h>

#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_flow_driver.h>
#include <rte_tailq.h>
#include <rte_mtr.h>
#include <rte_mtr_driver.h>

#include <fsl_dpni.h>
#include <fsl_dpkg.h>

#include <dpaa2_ethdev.h>
#include <dpaa2_pmd_logs.h>

static char s_err_msg[128];

static struct rte_mtr_capabilities s_dpaa2_mtr_capa = {
	.color_aware_trtcm_rfc2698_supported = true,
	.color_aware_trtcm_rfc4115_supported = true,
	.trtcm_rfc2698_byte_mode_supported = true,
	.trtcm_rfc2698_packet_mode_supported = true,
	.trtcm_rfc4115_byte_mode_supported = true,
	.trtcm_rfc4115_packet_mode_supported = true
};

static int
dpaa2_mtr_capabilities_get(struct rte_eth_dev *dev,
	struct rte_mtr_capabilities *capa,
	struct rte_mtr_error *error)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;

	if (!capa) {
		return -rte_mtr_error_set(error, EINVAL,
				RTE_MTR_ERROR_TYPE_MTR_PARAMS, NULL,
				"NULL input parameter\n");
	}

	rte_spinlock_lock(&priv->meter_lock);
	s_dpaa2_mtr_capa.n_max = priv->num_rx_tc;
	s_dpaa2_mtr_capa.n_shared_max = priv->num_rx_tc;
	s_dpaa2_mtr_capa.meter_trtcm_rfc2698_n_max = priv->num_rx_tc;
	s_dpaa2_mtr_capa.meter_trtcm_rfc4115_n_max = priv->num_rx_tc;
	s_dpaa2_mtr_capa.meter_policy_n_max = priv->num_rx_tc;
	s_dpaa2_mtr_capa.shared_n_flows_per_mtr_max = priv->fs_entries;
	rte_spinlock_unlock(&priv->meter_lock);

	*capa = s_dpaa2_mtr_capa;

	return 0;
}

static int
dpaa2_mtr_profile_add(struct rte_eth_dev *dev,
	uint32_t profile_id, struct rte_mtr_meter_profile *profile,
	struct rte_mtr_error *error)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_dev_meter_profile *dpaa2_profile;
	struct dpaa2_dev_meter_profile *curr;
	int ret = 0;

	dpaa2_profile = rte_zmalloc(NULL,
		sizeof(struct dpaa2_dev_meter_profile), 0);
	if (!dpaa2_profile) {
		return -rte_mtr_error_set(error, ENOMEM,
				RTE_MTR_ERROR_TYPE_UNSPECIFIED, NULL,
				"Meter profile memory alloc failed!\n");
	}
	if (profile->alg == RTE_MTR_NONE) {
		dpaa2_profile->mode = DPNI_POLICER_MODE_PASS_THROUGH;
	} else if (profile->alg == RTE_MTR_TRTCM_RFC2698) {
		dpaa2_profile->mode = DPNI_POLICER_MODE_RFC_2698;
	} else if (profile->alg == RTE_MTR_TRTCM_RFC4115) {
		dpaa2_profile->mode = DPNI_POLICER_MODE_RFC_4115;
	} else {
		DPAA2_PMD_ERR("Policer profile alg(%d) not supported!",
			profile->alg);
		ret = -ENOTSUP;
		goto err;
	}

	if (profile->alg == RTE_MTR_TRTCM_RFC2698) {
		dpaa2_profile->cir = profile->trtcm_rfc2698.cir;
		dpaa2_profile->cbs = profile->trtcm_rfc2698.cbs;
		dpaa2_profile->pir = profile->trtcm_rfc2698.pir;
		dpaa2_profile->pbs = profile->trtcm_rfc2698.pbs;
	} else if (profile->alg == RTE_MTR_TRTCM_RFC4115) {
		dpaa2_profile->cir = profile->trtcm_rfc4115.cir;
		dpaa2_profile->cbs = profile->trtcm_rfc4115.cbs;
		dpaa2_profile->pir = profile->trtcm_rfc4115.eir;
		dpaa2_profile->pbs = profile->trtcm_rfc4115.ebs;
	}

	/** Align with DPNI policy.*/
	if (!profile->packet_mode) {
		dpaa2_profile->policer_unit = DPNI_POLICER_UNIT_BYTES_L3;
	} else if (profile->packet_mode > DPNI_POLICER_UNIT_FRAMES) {
		dpaa2_profile->policer_unit =
			DPNI_POLICER_UNIT_BYTES_L2_WITHOUT_FCS;
	} else {
		dpaa2_profile->policer_unit = DPNI_POLICER_UNIT_FRAMES;
	}

	dpaa2_profile->profile_id = profile_id;

	rte_spinlock_lock(&priv->meter_lock);
	curr = LIST_FIRST(&priv->profiles);
	if (!curr) {
		LIST_INSERT_HEAD(&priv->profiles, dpaa2_profile, next);
	} else {
		while (LIST_NEXT(curr, next))
			curr = LIST_NEXT(curr, next);
		LIST_INSERT_AFTER(curr, dpaa2_profile, next);
	}
	rte_spinlock_unlock(&priv->meter_lock);

err:
	if (ret)
		rte_free(profile);

	return ret;
}

static int
dpaa2_mtr_policy_add(struct rte_eth_dev *dev,
	uint32_t policy_id, struct rte_mtr_meter_policy_params *policy,
	struct rte_mtr_error *error)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_dev_meter_policy *dpaa2_policy;
	struct dpaa2_dev_meter_policy *curr;
	const struct rte_flow_action *red_action;
	int red_drop = 0;

	if (policy->actions[RTE_COLOR_GREEN]) {
		return -rte_mtr_error_set(error, ENOMEM,
				RTE_MTR_ERROR_TYPE_POLICER_ACTION_GREEN, NULL,
				"Meter green policy action not supported!\n");
	}
	if (policy->actions[RTE_COLOR_YELLOW]) {
		return -rte_mtr_error_set(error, ENOMEM,
				RTE_MTR_ERROR_TYPE_POLICER_ACTION_YELLOW, NULL,
				"Meter yellow policy action not supported!\n");
	}

	red_action = policy->actions[RTE_COLOR_RED];

	if (red_action) {
		if (red_action->type == RTE_FLOW_ACTION_TYPE_DROP) {
			red_drop = 1;
		} else if (red_action->type != RTE_FLOW_ACTION_TYPE_PASSTHRU) {
			sprintf(s_err_msg,
				"Meter red policy action(%d) NOT supported!\n",
				red_action->type);
			return -rte_mtr_error_set(error, ENOMEM,
				RTE_MTR_ERROR_TYPE_POLICER_ACTION_RED, NULL,
				s_err_msg);
		}
	}

	dpaa2_policy = rte_zmalloc(NULL,
		sizeof(struct dpaa2_dev_meter_policy), 0);
	if (!dpaa2_policy) {
		return -rte_mtr_error_set(error, ENOMEM,
				RTE_MTR_ERROR_TYPE_UNSPECIFIED, NULL,
				"Meter profile memory alloc failed!\n");
	}

	dpaa2_policy->policy_id = policy_id;
	dpaa2_policy->red_drop = red_drop;

	rte_spinlock_lock(&priv->meter_lock);
	curr = LIST_FIRST(&priv->policies);
	if (!curr) {
		LIST_INSERT_HEAD(&priv->policies, dpaa2_policy, next);
	} else {
		while (LIST_NEXT(curr, next))
			curr = LIST_NEXT(curr, next);
		LIST_INSERT_AFTER(curr, dpaa2_policy, next);
	}
	rte_spinlock_unlock(&priv->meter_lock);

	return 0;
}

static struct rte_flow_meter_profile *
dpaa2_mtr_profile_get(struct rte_eth_dev *dev,
	uint32_t meter_profile_id, struct rte_mtr_error *error)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_dev_meter_profile *dpaa2_profile;

	RTE_SET_USED(error);

	rte_spinlock_lock(&priv->meter_lock);
	dpaa2_profile = LIST_FIRST(&priv->profiles);
	while (dpaa2_profile) {
		if (dpaa2_profile->profile_id == meter_profile_id) {
			rte_spinlock_unlock(&priv->meter_lock);
			return (struct rte_flow_meter_profile *)dpaa2_profile;
		}
		dpaa2_profile = LIST_NEXT(dpaa2_profile, next);
	}
	rte_spinlock_unlock(&priv->meter_lock);

	return NULL;
}

static struct rte_flow_meter_policy *
dpaa2_mtr_policy_get(struct rte_eth_dev *dev,
	uint32_t policy_id, struct rte_mtr_error *error)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_dev_meter_policy *dpaa2_policy;

	RTE_SET_USED(error);

	rte_spinlock_lock(&priv->meter_lock);
	dpaa2_policy = LIST_FIRST(&priv->policies);
	while (dpaa2_policy) {
		if (dpaa2_policy->policy_id == policy_id) {
			rte_spinlock_unlock(&priv->meter_lock);
			return (struct rte_flow_meter_policy *)dpaa2_policy;
		}
		dpaa2_policy = LIST_NEXT(dpaa2_policy, next);
	}
	rte_spinlock_unlock(&priv->meter_lock);

	return NULL;
}

static int
dpaa2_mtr_profile_tc_check(struct dpaa2_dev_priv *priv,
	struct dpaa2_dev_meter_profile *dpaa2_profile)
{
	int i;

	for (i = 0; i < MAX_TCS; i++) {
		if (priv->extract.tc_mtr_profile[i] == dpaa2_profile) {
			DPAA2_PMD_ERR("The TC[%d]'s meter flow is referring this profile.",
				i);
			DPAA2_PMD_ERR("The TC[%d]'s meter flow should be destroyed by user.",
				i);
			return -EINVAL;
		}
	}

	return 0;
}

static int
dpaa2_mtr_profile_delete(struct rte_eth_dev *dev,
	uint32_t profile_id, struct rte_mtr_error *error)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_dev_meter_profile *dpaa2_profile = NULL, *curr;
	struct dpaa2_dev_meter *meter, *tmp;
	int ret;

	rte_spinlock_lock(&priv->meter_lock);
	curr = LIST_FIRST(&priv->profiles);
	while (curr) {
		if (curr->profile_id == profile_id) {
			dpaa2_profile = curr;
			break;
		}
		curr = LIST_NEXT(curr, next);
	}
	if (!dpaa2_profile) {
		rte_spinlock_unlock(&priv->meter_lock);
		return -rte_mtr_error_set(error, ENOENT,
			RTE_MTR_ERROR_TYPE_METER_PROFILE_ID,
			&profile_id, "Meter profile is invalid.");
	}

	ret = dpaa2_mtr_profile_tc_check(priv, dpaa2_profile);
	if (ret) {
		return -rte_mtr_error_set(error, -ret,
			RTE_MTR_ERROR_TYPE_METER_PROFILE,
			dpaa2_profile, "Meter profile is referred.");
	}

	meter = LIST_FIRST(&priv->meters);
	while (meter) {
		if (meter->profile_id == profile_id) {
			DPAA2_PMD_INFO("Meter(id=%d) with profile(%d) is removed!",
				meter->meter_id, profile_id);
			tmp = meter;
			meter = LIST_NEXT(meter, next);
			LIST_REMOVE(tmp, next);
			rte_free(tmp);
		} else {
			meter = LIST_NEXT(meter, next);
		}
	}

	LIST_REMOVE(dpaa2_profile, next);
	rte_free(dpaa2_profile);
	rte_spinlock_unlock(&priv->meter_lock);

	return ret;
}

static int
dpaa2_mtr_policy_delete(struct rte_eth_dev *dev,
	uint32_t policy_id, struct rte_mtr_error *error)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_dev_meter_policy *dpaa2_policy = NULL, *curr;
	struct dpaa2_dev_meter *meter, *tmp;

	rte_spinlock_lock(&priv->meter_lock);
	curr = LIST_FIRST(&priv->policies);
	while (curr) {
		if (curr->policy_id == policy_id) {
			dpaa2_policy = curr;
			break;
		}
		curr = LIST_NEXT(curr, next);
	}
	if (!dpaa2_policy) {
		rte_spinlock_unlock(&priv->meter_lock);
		return -rte_mtr_error_set(error, ENOENT,
			RTE_MTR_ERROR_TYPE_METER_POLICY_ID,
			NULL, "Meter policy is invalid.\n");
	}

	meter = LIST_FIRST(&priv->meters);
	while (meter) {
		if (meter->policy_id == policy_id) {
			DPAA2_PMD_INFO("Meter(id=%d) with policy(%d) is removed!",
				meter->meter_id, policy_id);
			tmp = meter;
			meter = LIST_NEXT(meter, next);
			LIST_REMOVE(tmp, next);
			rte_free(tmp);
		} else {
			meter = LIST_NEXT(meter, next);
		}
	}

	LIST_REMOVE(dpaa2_policy, next);
	rte_free(dpaa2_policy);
	rte_spinlock_unlock(&priv->meter_lock);

	return 0;
}

static int
dpaa2_mtr_meter_create(struct rte_eth_dev *dev,
	uint32_t mtr_id, struct rte_mtr_params *params,
	int shared, struct rte_mtr_error *error)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_dev_meter_profile *profile;
	struct dpaa2_dev_meter_policy *policy;
	struct dpaa2_dev_meter *meter, *curr;
	uint32_t profile_id, policy_id;
	int found = 0, ret = 0;
	enum rte_mtr_error_type err_type = RTE_MTR_ERROR_TYPE_NONE;

	RTE_SET_USED(shared);
	profile_id = params->meter_profile_id;
	policy_id = params->meter_policy_id;

	rte_spinlock_lock(&priv->meter_lock);
	profile = LIST_FIRST(&priv->profiles);
	while (profile) {
		if (profile->profile_id == profile_id) {
			found = 1;
			break;
		}
		profile = LIST_NEXT(profile, next);
	}
	if (!found) {
		sprintf(s_err_msg, "Meter profile ID(%d) not exist!\n",
			profile_id);
		ret = ENOENT;
		err_type = RTE_MTR_ERROR_TYPE_METER_PROFILE_ID;
		goto quit;
	}

	found = 0;
	policy = LIST_FIRST(&priv->policies);
	while (policy) {
		if (policy->policy_id == policy_id) {
			found = 1;
			break;
		}
		policy = LIST_NEXT(policy, next);
	}
	if (!found) {
		sprintf(s_err_msg, "Meter policy ID(%d) not exist!\n",
			policy_id);
		ret = ENOENT;
		err_type = RTE_MTR_ERROR_TYPE_METER_POLICY_ID;
		goto quit;
	}

	meter = LIST_FIRST(&priv->meters);
	while (meter) {
		if (meter->meter_id == mtr_id) {
			sprintf(s_err_msg, "Meter ID(%d) exist!\n", mtr_id);
			ret = EEXIST;
			err_type = RTE_MTR_ERROR_TYPE_MTR_ID;
			goto quit;
		} else {
			meter = LIST_NEXT(meter, next);
		}
	}
	meter = rte_zmalloc(NULL, sizeof(struct dpaa2_dev_meter), 0);
	if (!meter) {
		sprintf(s_err_msg, "Meter memory alloc failed!\n");
		ret = ENOMEM;
		err_type = RTE_MTR_ERROR_TYPE_UNSPECIFIED;
		goto quit;
	}
	meter->meter_id = mtr_id;
	meter->profile_id = profile_id;
	meter->policy_id = policy_id;

	curr = LIST_FIRST(&priv->meters);
	if (!curr) {
		LIST_INSERT_HEAD(&priv->meters, meter, next);
	} else {
		while (LIST_NEXT(curr, next))
			curr = LIST_NEXT(curr, next);
		LIST_INSERT_AFTER(curr, meter, next);
	}

quit:
	rte_spinlock_unlock(&priv->meter_lock);
	if (ret)
		return -rte_mtr_error_set(error, ret, err_type, NULL, s_err_msg);

	return 0;
}

static int
dpaa2_mtr_meter_destroy(struct rte_eth_dev *dev,
	uint32_t mtr_id, struct rte_mtr_error *error)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_dev_meter *meter;

	rte_spinlock_lock(&priv->meter_lock);
	meter = LIST_FIRST(&priv->meters);
	while (meter) {
		if (meter->meter_id == mtr_id) {
			LIST_REMOVE(meter, next);
			rte_free(meter);
			rte_spinlock_unlock(&priv->meter_lock);

			return 0;
		}
		meter = LIST_NEXT(meter, next);
	}
	sprintf(s_err_msg, "Meter ID(%d) does not exist!\n", mtr_id);
	rte_spinlock_unlock(&priv->meter_lock);
	return -rte_mtr_error_set(error, ENOENT,
		RTE_MTR_ERROR_TYPE_MTR_ID, NULL, s_err_msg);
}

static int
dpaa2_mtr_meter_profile_update(struct rte_eth_dev *dev,
	uint32_t mtr_id, uint32_t profile_id,
	struct rte_mtr_error *error)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_dev_meter_profile *profile;
	struct dpaa2_dev_meter *meter;
	int found = 0, ret = 0;
	enum rte_mtr_error_type err_type = RTE_MTR_ERROR_TYPE_NONE;

	rte_spinlock_lock(&priv->meter_lock);
	meter = LIST_FIRST(&priv->meters);
	while (meter) {
		if (meter->meter_id == mtr_id) {
			found = 1;
			break;
		}
		meter = LIST_NEXT(meter, next);
	}
	if (!found) {
		sprintf(s_err_msg, "Meter ID(%d) not found!\n", mtr_id);
		ret = ENOENT;
		err_type = RTE_MTR_ERROR_TYPE_MTR_ID;
		goto quit;
	}

	found = 0;
	profile = LIST_FIRST(&priv->profiles);
	while (profile) {
		if (profile->profile_id == profile_id) {
			found = 1;
			break;
		}
		profile = LIST_NEXT(profile, next);
	}
	if (!found) {
		sprintf(s_err_msg, "Profile ID(%d) not found!\n", profile_id);
		ret = ENOENT;
		err_type = RTE_MTR_ERROR_TYPE_METER_PROFILE_ID;
		goto quit;
	}
	meter->profile_id = profile_id;

quit:
	rte_spinlock_unlock(&priv->meter_lock);
	if (ret)
		return -rte_mtr_error_set(error, ret, err_type, NULL, s_err_msg);

	return 0;
}

static int
dpaa2_mtr_meter_policy_update(struct rte_eth_dev *dev,
	uint32_t mtr_id, uint32_t policy_id,
	struct rte_mtr_error *error)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_dev_meter_policy *policy;
	struct dpaa2_dev_meter *meter;
	int found = 0, ret = 0;
	enum rte_mtr_error_type err_type = RTE_MTR_ERROR_TYPE_NONE;

	meter = LIST_FIRST(&priv->meters);
	while (meter) {
		if (meter->meter_id == mtr_id) {
			found = 1;
			break;
		}
		meter = LIST_NEXT(meter, next);
	}
	if (!found) {
		sprintf(s_err_msg, "Meter ID(%d) not found!\n", mtr_id);
		ret = ENOENT;
		err_type = RTE_MTR_ERROR_TYPE_MTR_ID;
		goto quit;
	}

	found = 0;
	policy = LIST_FIRST(&priv->policies);
	while (policy) {
		if (policy->policy_id == policy_id) {
			found = 1;
			break;
		}
		policy = LIST_NEXT(policy, next);
	}
	if (!found) {
		sprintf(s_err_msg, "Profile ID(%d) not found!\n", policy_id);
		ret = ENOENT;
		err_type = RTE_MTR_ERROR_TYPE_METER_POLICY_ID;
		goto quit;
	}
	meter->policy_id = policy_id;

quit:
	rte_spinlock_unlock(&priv->meter_lock);
	if (ret)
		return -rte_mtr_error_set(error, ret, err_type, NULL, s_err_msg);

	return 0;
}

static const struct rte_mtr_ops dpaa2_meter_ops = {
	.capabilities_get = dpaa2_mtr_capabilities_get,
	.meter_profile_add = dpaa2_mtr_profile_add,
	.meter_profile_delete = dpaa2_mtr_profile_delete,
	.meter_policy_add = dpaa2_mtr_policy_add,
	.meter_policy_delete = dpaa2_mtr_policy_delete,
	.meter_profile_get = dpaa2_mtr_profile_get,
	.meter_policy_get = dpaa2_mtr_policy_get,
	.create = dpaa2_mtr_meter_create,
	.destroy = dpaa2_mtr_meter_destroy,
	.meter_profile_update = dpaa2_mtr_meter_profile_update,
	.meter_policy_update = dpaa2_mtr_meter_policy_update,
};

int
dpaa2_mtr_ops_get(struct rte_eth_dev *dev, void *ops)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;

	rte_spinlock_init(&priv->meter_lock);

	*(const void **)ops = &dpaa2_meter_ops;
	return 0;
}

/* SPDX-License-Identifier: BSD-3-Clause
 *
 *   Copyright 2020 NXP
 *
 */

#ifndef _DPAA2_QOS_H
#define _DPAA2_QOS_H

#include <time.h>
#include <net/if.h>

#include <rte_mbuf.h>
#include <rte_ethdev_driver.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_string_fns.h>
#include <rte_dev.h>

#include <rte_fslmc.h>
#include <fslmc_vfio.h>
#include <dpaa2_hw_pvt.h>
#include <dpaa2_hw_dpio.h>
#include <dpaa2_hw_mempool.h>

#include "dpaa2_pmd_logs.h"
#include "dpaa2_ethdev.h"
//#include <mc/fsl_dpni.h>
//#include <mc/fsl_dpio.h>
//#include <mc/fsl_mc_sys.h>
#include "qbman_portal.h"
#include "qbman_portal_ex.h"
#include <fsl_qbman_portal_ex.h>
#include <rte_pmd_dpaa2_qos.h>

/* SACHIN TODO */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

#define MAX_LFQID_PER_CEETM	2
#define MAX_CH_PER_CEETM	32	/*  For PHASE-1 */


#define DRV_UT		0

struct class_q {
	uint32_t cqid;
	uint32_t lfqid;
	uint32_t vrid;
	uint32_t ccgrid;
	uint16_t portid; /* Tx Port */
	uint16_t conf_q_id;
};

struct class_sch {
	uint32_t cs_lfqid_base;
	uint32_t cq_count;
	struct class_q  cq[L1_MAX_QUEUES];
	uint32_t cq_inuse;
	enum scheduler_mode mode;
	uint8_t chid;
};

struct ceetm_res {
	uint32_t lfqid_base;
	uint32_t lfq_vrid_base;
	uint32_t cqid_base;
	uint32_t chid_base;
	uint32_t cs_count;
	struct class_sch cs[MAX_CH_PER_CEETM];
	uint32_t cs_inuse;
} ceetm[2] = {0};

/* Global Privileged portal */
struct qbman_swp *p_swp;

static inline uint8_t get_ceetm_instid(uint32_t ceetm_id)
{
	uint8_t dcpid, instanceid;

	qbman_ceetmid_decompose(ceetm_id, &dcpid, &instanceid);

	printf("%s: CEETM id %d instanceid %d\n", __func__, ceetm_id, instanceid);
	return instanceid;
}

static inline
struct dpaa2_dev_priv *dpaa2_get_dev_priv(uint16_t port_id)
{
	struct rte_eth_dev *eth_dev;
	struct rte_eth_dev_data *data;

	if (!rte_eth_dev_is_valid_port(port_id)) {
		DPAA2_PMD_ERR("Invalid or unused  port\n");
		return NULL;
	}
	eth_dev = &rte_eth_devices[port_id];
	if (!eth_dev) {
		DPAA2_PMD_ERR("Port is not configured\n");
		return NULL;
	}
	data = eth_dev->data;
	return data->dev_private;
}
#if DRV_UT
void mc_test(void);
#endif
int init_ceetm_res(uint16_t portid, uint16_t q_id);

int32_t dpaa2_qos_init(void)
{

	/* Validate whether PRIVILAGED QBMAn portal is available else return error */
	p_swp = dpaa2_get_priv_qbman_swp();
	if (NULL == p_swp) {
		DPAA2_PMD_ERR("Privileged Portal not found\n");
		return -EINVAL;
	}
	DPAA2_PMD_INFO("%s: Privileged Portal is avialble\n", __func__);

	/* Test with MC resources */
#if DRV_UT
	mc_test();
#endif
	return 0;
}

int init_ceetm_res(uint16_t portid, uint16_t conf_q_id)
{

	struct rte_eth_dev *eth_dev = &rte_eth_devices[portid];
        struct rte_eth_dev_data *eth_data = eth_dev->data;
        struct dpaa2_dev_priv *priv = eth_data->dev_private;
	struct dpaa2_queue *dpaa2_q = (struct dpaa2_queue *)
                priv->tx_vq[conf_q_id];
	uint32_t ceetmid, cs_count, cq_idx = 0, q_id, cq_id;

	ceetmid = priv->ceetm_id;
	cq_id = dpaa2_q->real_cqid;
	q_id = dpaa2_q->fqid;
	cs_count =  ceetm[ceetmid].cs_count;

	if ((cq_id % 16) != 0)
		return 0;

	ceetmid = get_ceetm_instid((uint32_t)ceetmid);

	/* TODO Initialize with resources created by MC */
	ceetm[ceetmid].lfqid_base = 15745088;
	ceetm[ceetmid].lfq_vrid_base = 414;
	ceetm[ceetmid].cqid_base = 16;
	ceetm[ceetmid].chid_base = 1;
	ceetm[ceetmid].cs[cs_count].mode = SCHED_STRICT_PRIORITY;
	ceetm[ceetmid].cs[cs_count].cs_lfqid_base = 0; /* TODO */
	ceetm[ceetmid].cs[cs_count].chid = cq_id >> 4;

	cq_idx = ceetm[ceetmid].cs[cs_count].cq_count;
	for (int i = 0; i < L1_MAX_QUEUES; i++) {
		ceetm[ceetmid].cs[cs_count].cq[cq_idx].conf_q_id = conf_q_id;
		ceetm[ceetmid].cs[cs_count].cq[cq_idx].lfqid = 0;
		ceetm[ceetmid].cs[cs_count].cq[cq_idx].vrid = q_id;
		ceetm[ceetmid].cs[cs_count].cq[cq_idx].portid = portid;
		ceetm[ceetmid].cs[cs_count].cq[cq_idx].cqid = cq_id & 0xF;
		/* TODO MC configure CCGRID same as TC index */
		ceetm[ceetmid].cs[cs_count].cq[cq_idx].ccgrid = cq_idx;
		printf("%s:ceetm_inst[%d]  fqid %d cqid %d chid %u\n", __func__,
			ceetmid, ceetm[ceetmid].cs[cs_count].cq[cq_idx].vrid,
			ceetm[ceetmid].cs[cs_count].cq[cq_idx].cqid,
			ceetm[ceetmid].cs[cs_count].chid);

		q_id++;
		conf_q_id++;
		cq_id++;
		cq_idx++;
	}
	ceetm[ceetmid].cs_count++;
	ceetm[ceetmid].cs[cs_count].cq_count = cq_idx;

	printf("%s:cs_count = %d  cq_count = %d\n", __func__,
		ceetm[ceetmid].cs_count, ceetm[ceetmid].cs[cs_count].cq_count);
	return 0;
}

#if DRV_UT
void mc_test(void)
{
	/* Applying on port-2/ DPNI.3 */
	uint16_t portid = 1;
	int32_t l2_schidx;
	handle_t cq_handle[1], l1_sch_handle;
	struct dpaa2_shaper_params sh_param;
	struct dpaa2_sch_params sch_param;
//	struct dpaa2_dev_priv *priv;

//	priv = dpaa2_get_dev_priv(portid);
	/* TODO Set temporary till MC FLIB is not functional */
	//priv->ceetm_id = 16;
	//priv->lni = 4;

	l2_schidx = dpaa2_add_L2_sch(portid);

	memset(&sh_param, 0, sizeof(struct dpaa2_shaper_params));
	sh_param.c_rate = 6;
	sh_param.c_bs = 0;
	sh_param.oal = 24;
	dpaa2_cfg_L2_shaper(portid, &sh_param);

	sch_param.sch_mode = SCHED_STRICT_PRIORITY;
	sch_param.l2_sch_idx = l2_schidx;
	sch_param.shaped = 1;
	sch_param.num_L1_queues = 1;
	sch_param.td_thresh[0] = 4;
	sch_param.td_mode[0] = CONGESTION_UNIT_FRAMES;
	sch_param.q_handle = (qhandle_t *)&cq_handle;
	l1_sch_handle = dpaa2_add_L1_sch(portid, &sch_param);

	sh_param.c_rate = 40; /* 20 Mbps */
	dpaa2_cfg_L1_shaper(portid, l1_sch_handle, &sh_param);

}
#endif

void dpaa2_qos_deinit(void)
{
	/* TODO */
}


int32_t dpaa2_add_L2_sch(uint16_t portid)
{
	struct dpaa2_dev_priv *priv;

	priv = dpaa2_get_dev_priv(portid);
	if (NULL == priv)
		return -EINVAL;

	/* Get the LNI index from the given port and validate */
	DPAA2_PMD_INFO("%s: PortId %d [dpni.%d]-- LNI Id %d CEETM Id %d\n", __func__,
				portid, priv->hw_id, priv->lni, priv->ceetm_id);

	/* Return result to user */
	return priv->lni;
}

int32_t dpaa2_cfg_L2_shaper(uint16_t portid,
			struct dpaa2_shaper_params *sh_param)
{
	struct qbman_attr attr;
	struct dpaa2_dev_priv *priv;
	uint32_t burst_size;
	uint64_t bps;
	int err;

	/* Get the device data to fetch CEETM, LNI index etc. from the given port
	   and validate */
	priv = dpaa2_get_dev_priv(portid);
	if (NULL == priv)
		return -EINVAL;

	qbman_shaper_attr_clear(&attr);
	bps = (uint64_t)(sh_param->c_rate * 1000000.0);
	qbman_shaper_set_commit_rate(&attr, bps);
	burst_size = qbman_fix_burst_size(sh_param->c_bs * 1000, bps);
	qbman_shaper_set_crtbl(&attr, burst_size);
	printf("%s: PortId %d - cr %ld cbs %d\n", __func__,
					portid, bps, burst_size);
	bps = (uint64_t)(sh_param->e_rate * 1000000.0);
	qbman_shaper_set_excess_rate(&attr, bps);
	burst_size = qbman_fix_burst_size(sh_param->e_bs * 1000, bps);
	qbman_shaper_set_ertbl(&attr, burst_size);
	DPAA2_PMD_INFO("%s: er %fMbps ebs %dKbps\n", __func__,
					sh_param->e_rate, sh_param->e_bs);
	qbman_shaper_set_coupling(&attr, sh_param->cpl);
	qbman_shaper_set_lni_mps(&attr, sh_param->mps);
	qbman_shaper_set_lni_oal(&attr, sh_param->oal);
	DPAA2_PMD_INFO("%s: cpl %d mps %d oal %d\n", __func__,
				sh_param->cpl, sh_param->mps, sh_param->oal);

	err = qbman_lni_shaper_configure(p_swp, priv->ceetm_id, priv->lni, &attr);
	if (err)
		return -EINVAL;

	return 0;
}

int32_t dpaa2_reconf_L1_sch(uint16_t portid, uint8_t channel_id,
			struct dpaa2_sch_params *sch_param)
{
	struct qbman_attr attr;
	struct dpaa2_dev_priv *priv;
	uint8_t instid;
	struct class_sch *cs = NULL;
	uint32_t  i;
	int err, csms;

	/* Get the device data to fetch CEETM, LNI index etc. from the given port
	   and validate */
	priv = dpaa2_get_dev_priv(portid);
	if (NULL == priv)
		return -EINVAL;

	if (priv->lni != sch_param->l2_sch_idx) {
		DPAA2_PMD_ERR("%s: l2_sch_idx %d is not associated with port %d\n",
				__func__, sch_param->l2_sch_idx, portid);
		return -EINVAL;
	}

	/* Get Next available cs/channel */
	instid = get_ceetm_instid((uint32_t)priv->ceetm_id);
	
	for (unsigned int k = 0; k < ceetm[instid].cs_inuse; k++) {
		if (channel_id == ceetm[instid].cs[k].chid)
			cs = &(ceetm[instid].cs[k]);
	}

	if (cs == NULL) {
		printf("%d channel id not exist\n", channel_id);
		return -EINVAL;
	}

#if 0
	printf("%s: ceetm %d lin %d chid %d shaped %d \n", __func__,
		priv->ceetm_id, priv->lni, cs->chid, sch_param->shaped);
	err = qbman_cchannel_configure(p_swp, priv->ceetm_id,
			cs->chid, priv->lni, sch_param->shaped);
	if (err) {
		printf("%s: qbman_cchannel_configure failed err %d\n",
							__func__, err);
		return -EINVAL;
	}
#endif

	/* Clear schedulaer attributes */
	qbman_cscheduler_attr_clear(&attr);
	/* fetch current scheduler configuration */
	qbman_cscheduler_query(p_swp, priv->ceetm_id,
			cs->chid, 1, &attr);
	/* Configure scheduler */
	for (i = 0; i < sch_param->num_L1_queues; i++) {
		qbman_cscheduler_set_crem_cq(&attr, i, sch_param->shaped ? 1 : 0);
		qbman_cscheduler_set_erem_cq(&attr, i, sch_param->shaped ? 1 : 0);
	}

	if (sch_param->sch_mode == SCHED_WRR) {
		/* enable all queues for WRR */
		qbman_cscheduler_set_csms(&attr, 1);
		qbman_cscheduler_get_csms(&attr, &csms);
		for (i = 0; i < sch_param->num_L1_queues; i++)
			qbman_cscheduler_set_cq_weight(&attr, i, sch_param->weight[i], csms);

		/* 1 means the groups A and B are combined */
		qbman_cscheduler_set_group_b(&attr, 1);
		/* Set the priority of group A 0-7*/
		qbman_cscheduler_set_prio_a(&attr, 7);

		qbman_cscheduler_set_crem_group_a(&attr, 1);
		qbman_cscheduler_set_crem_group_b(&attr, 1);
		qbman_cscheduler_set_erem_group_a(&attr, 1);
		qbman_cscheduler_set_erem_group_b(&attr, 1);
	} else {
		qbman_cscheduler_set_csms(&attr, 0);
	}

	err = qbman_cscheduler_configure(p_swp, priv->ceetm_id,
			cs->chid, &attr);
	if (err) {
		printf("%s: qbman_cscheduler_configure failed err %d\n",
							__func__, err);
		return -EINVAL;
	}

	for (i = 0; i < sch_param->num_L1_queues; i++) {
		int rej_cnt_mode, td_en;
		uint32_t mode, td_thresh;

		sch_param->q_handle[i] = (qhandle_t) &cs->cq[i];
		printf("%s: Updated Tc[%d] handle %ld fqid = %d\n", __func__,
					i, sch_param->q_handle[i], cs->cq[i].vrid);
		/* CCGR */
		qbman_ccgr_query(p_swp,  priv->ceetm_id, cs->chid,
						cs->cq[i].ccgrid, &attr);
		qbman_cgr_attr_get_mode(&attr, &mode, &rej_cnt_mode);
		qbman_cgr_attr_get_td_ctrl(&attr, &td_en);
		qbman_cgr_attr_get_td_thres(&attr, &td_thresh);
		printf("%s:ccgrid %d: existing: rej_cnt_mode %d mode %d td_en %d td_thresh %d\n",
				__func__, cs->cq[i].ccgrid, rej_cnt_mode, mode, td_en, td_thresh);
		if (sch_param->td_thresh[i]) {
			mode = sch_param->td_mode[i];
			td_thresh = sch_param->td_thresh[i];
			td_en = 1;
			rej_cnt_mode = 1;
		} else {
			td_thresh = 0;
			td_en = 0;
		}
		qbman_cgr_attr_set_mode(&attr, mode, rej_cnt_mode);
		qbman_cgr_attr_set_td_ctrl(&attr, td_en);
		qbman_cgr_attr_set_td_thres(&attr, td_thresh);
		err = qbman_ccgr_configure(p_swp, priv->ceetm_id, cs->chid,
							cs->cq[i].ccgrid, &attr);
		if (err) {
			printf("%s: qbman_cchannel_configure failed err %d\n",
							__func__, err);
			return -EINVAL;
		}
		qbman_ccgr_query(p_swp,  priv->ceetm_id, cs->chid,
						cs->cq[i].ccgrid, &attr);
		qbman_cgr_attr_get_mode(&attr, &mode, &rej_cnt_mode);
		qbman_cgr_attr_get_td_ctrl(&attr, &td_en);
		qbman_cgr_attr_get_td_thres(&attr, &td_thresh);
		printf("%s:NEW : ccgrid %d rej_cnt_mode %d mode %d td_en %d td_thresh %d\n",
			__func__, cs->cq[i].ccgrid, rej_cnt_mode, mode, td_en, td_thresh);
	}

	return cs->chid;
}




int32_t dpaa2_add_L1_sch(uint16_t portid,
			struct dpaa2_sch_params *sch_param)
{
	struct qbman_attr attr;
	struct dpaa2_dev_priv *priv;
	uint8_t instid;
	struct class_sch *cs;
	uint32_t cur_idx, i;
	int err, csms;

	/* Get the device data to fetch CEETM, LNI index etc. from the given port
	   and validate */
	priv = dpaa2_get_dev_priv(portid);
	if (NULL == priv)
		return -EINVAL;

	if (priv->lni != sch_param->l2_sch_idx) {
		DPAA2_PMD_ERR("%s: l2_sch_idx %d is not associated with port %d\n",
				__func__, sch_param->l2_sch_idx, portid);
		return -EINVAL;
	}

	/* Get Next available cs/channel */
	instid = get_ceetm_instid((uint32_t)priv->ceetm_id);
	if (ceetm[instid].cs_inuse == ceetm[instid].cs_count) {
		printf("%s: No more resources left\n", __func__);
		return -EINVAL;
	}
	cur_idx = ceetm[instid].cs_inuse;
	cs = &(ceetm[instid].cs[cur_idx]);
	if (cs->cq_inuse + sch_param->num_L1_queues > 8) {
		printf("%s: Not enough CQs left\n", __func__);
		return -EINVAL;
	}

	printf("%s: ceetm %d lin %d chid %d shaped %d \n", __func__,
		priv->ceetm_id, priv->lni, cs->chid, sch_param->shaped);
	err = qbman_cchannel_configure(p_swp, priv->ceetm_id,
			cs->chid, priv->lni, sch_param->shaped);
	if (err) {
		printf("%s: qbman_cchannel_configure failed err %d\n",
							__func__, err);
		return -EINVAL;
	}

	/* Clear schedulaer attributes */
	qbman_cscheduler_attr_clear(&attr);
	/* fetch current scheduler configuration */
	qbman_cscheduler_query(p_swp, priv->ceetm_id,
			cs->chid, 1, &attr);
	/* Configure scheduler */
	for (i = 0; i < sch_param->num_L1_queues; i++) {
		qbman_cscheduler_set_crem_cq(&attr, i, sch_param->shaped ? 1 : 0);
		qbman_cscheduler_set_erem_cq(&attr, i, sch_param->shaped ? 1 : 0);
	}

	if (sch_param->sch_mode == SCHED_WRR) {
		/* enable all queues for WRR */
		qbman_cscheduler_set_csms(&attr, 1);
		qbman_cscheduler_get_csms(&attr, &csms);

		for (i = 0; i < sch_param->num_L1_queues; i++)
			qbman_cscheduler_set_cq_weight(&attr, i, sch_param->weight[i], csms);

		/* 1 means the groups A and B are combined */
		qbman_cscheduler_set_group_b(&attr, 1);
		/* Set the priority of group A 0-7*/
		qbman_cscheduler_set_prio_a(&attr, 7);

		qbman_cscheduler_set_crem_group_a(&attr, 1);
		qbman_cscheduler_set_crem_group_b(&attr, 1);
		qbman_cscheduler_set_erem_group_a(&attr, 1);
		qbman_cscheduler_set_erem_group_b(&attr, 1);
	} else {
		qbman_cscheduler_set_csms(&attr, 0);
	}

	err = qbman_cscheduler_configure(p_swp, priv->ceetm_id,
			cs->chid, &attr);
	if (err) {
		printf("%s: qbman_cscheduler_configure failed err %d\n",
							__func__, err);
		return -EINVAL;
	}

	for (i = 0; i < sch_param->num_L1_queues; i++) {
		int rej_cnt_mode, td_en;
		uint32_t mode, td_thresh;

		/* Update  Tx port in Queue handle 
		 * FIXME: below changes are required for offloads,
		 * and in case different mempool for each DPNI */
		//cs->cq[i].portid = portid;
		sch_param->q_handle[i] = (qhandle_t) &cs->cq[i];
		printf("%s: Updated Tc[%d] handle %ld fqid = %d\n", __func__,
					i, sch_param->q_handle[i], cs->cq[i].vrid);
		/* CCGR */
		qbman_ccgr_query(p_swp,  priv->ceetm_id, cs->chid,
						cs->cq[i].ccgrid, &attr);
		qbman_cgr_attr_get_mode(&attr, &mode, &rej_cnt_mode);
		qbman_cgr_attr_get_td_ctrl(&attr, &td_en);
		qbman_cgr_attr_get_td_thres(&attr, &td_thresh);
		printf("%s:ccgrid %d: existing: rej_cnt_mode %d mode %d td_en %d td_thresh %d\n",
				__func__, cs->cq[i].ccgrid, rej_cnt_mode, mode, td_en, td_thresh);
		if (sch_param->td_thresh[i]) {
			mode = sch_param->td_mode[i];
			td_thresh = sch_param->td_thresh[i];
			td_en = 1;
			rej_cnt_mode = 1;
		} else {
			td_thresh = 0;
			td_en = 0;
		}
		qbman_cgr_attr_set_mode(&attr, mode, rej_cnt_mode);
		qbman_cgr_attr_set_td_ctrl(&attr, td_en);
		qbman_cgr_attr_set_td_thres(&attr, td_thresh);
		err = qbman_ccgr_configure(p_swp, priv->ceetm_id, cs->chid,
							cs->cq[i].ccgrid, &attr);
		if (err) {
			printf("%s: qbman_cchannel_configure failed err %d\n",
							__func__, err);
			return -EINVAL;
		}
		qbman_ccgr_query(p_swp,  priv->ceetm_id, cs->chid,
						cs->cq[i].ccgrid, &attr);
		qbman_cgr_attr_get_mode(&attr, &mode, &rej_cnt_mode);
		qbman_cgr_attr_get_td_ctrl(&attr, &td_en);
		qbman_cgr_attr_get_td_thres(&attr, &td_thresh);
		printf("%s:NEW : ccgrid %d rej_cnt_mode %d mode %d td_en %d td_thresh %d\n",
			__func__, cs->cq[i].ccgrid, rej_cnt_mode, mode, td_en, td_thresh);
	}
	cs->cq_inuse += sch_param->num_L1_queues;
	ceetm[instid].cs_inuse++;

	return cs->chid;
}

int32_t dpaa2_cfg_L1_shaper(uint16_t portid,
			handle_t sch_idx,
			struct dpaa2_shaper_params *sh_param)
{
	struct qbman_attr attr;
	struct dpaa2_dev_priv *priv;
	uint32_t burst_size;
	uint64_t bps;
	int err = 0;

	/* Get the device data to fetch CEETM, LNI index etc. from the given port
	   and validate */
	priv = dpaa2_get_dev_priv(portid);
	if (NULL == priv)
		return -EINVAL;

	qbman_shaper_attr_clear(&attr);
	bps = (uint64_t)(sh_param->c_rate * 1000000.0);
	qbman_shaper_set_commit_rate(&attr, bps);
	burst_size = qbman_fix_burst_size(sh_param->c_bs * 1000, bps);
	qbman_shaper_set_crtbl(&attr, burst_size);
	printf("%s: PortId %d - cr %ld cbs %d\n", __func__,
					portid, bps, burst_size);
	bps = (uint64_t)(sh_param->e_rate * 1000000.0);
	qbman_shaper_set_excess_rate(&attr, bps);
	burst_size = qbman_fix_burst_size(sh_param->e_bs * 1000, bps);
	qbman_shaper_set_ertbl(&attr, burst_size);
	qbman_shaper_set_coupling(&attr, sh_param->cpl);
	DPAA2_PMD_INFO("%s: cpl %d\n", __func__, sh_param->cpl);

	err = qbman_cchannel_shaper_configure(p_swp, priv->ceetm_id, sch_idx, &attr);
	if (err)
		return -EINVAL;
	return 0;
}

int dpaa2_move_L1_sch(handle_t l1_sch_handle, uint16_t dst_portid)
{
	struct dpaa2_dev_priv *priv;
	int err;

	/* Get the device data to fetch CEETM, LNI index etc. from the given port
	   and validate */
	priv = dpaa2_get_dev_priv(dst_portid);
	if (NULL == priv)
		return -EINVAL;


	err = qbman_cchannel_configure(p_swp, priv->ceetm_id,
			l1_sch_handle, priv->lni, 1);
	if (err) {
		printf("%s: qbman_cchannel_configure failed err %d\n",
							__func__, err);
		return -EINVAL;
	}
	printf("%s: ceetm %d lni %d chid %d shaped %d \n", __func__,
		priv->ceetm_id, priv->lni, l1_sch_handle, 1);
	return 0;
}

#define DPAA2_MBUF_TO_CONTIG_FD(_mbuf, _fd, _bpid)  do { \
	DPAA2_SET_FD_ADDR(_fd, DPAA2_MBUF_VADDR_TO_IOVA(_mbuf)); \
	DPAA2_SET_FD_LEN(_fd, _mbuf->data_len); \
	DPAA2_SET_ONLY_FD_BPID(_fd, _bpid); \
	DPAA2_SET_FD_OFFSET(_fd, _mbuf->data_off); \
	DPAA2_SET_FD_FRC(_fd, 0);		\
	DPAA2_RESET_FD_CTRL(_fd);		\
	DPAA2_RESET_FD_FLC(_fd);		\
} while (0)

extern void
eth_mbuf_to_fd(struct rte_mbuf *mbuf,
	       struct qbman_fd *fd, uint16_t bpid) __attribute__((unused));

uint16_t dpaa2_dev_qos_tx( qhandle_t q_handle,
			struct rte_mbuf **bufs,
			uint16_t nb_pkts)
{
	/* Function to transmit the frames to given device and VQ*/
	struct class_q *cq = (struct class_q *)q_handle;
	uint16_t portid = cq->portid;
	uint32_t loop, retry_count;
	int32_t ret;
	struct qbman_fd fd_arr[MAX_TX_RING_SLOTS];
	struct rte_mbuf *mi;
	uint32_t frames_to_send;
	struct rte_mempool *mp;
	struct qbman_eq_desc eqdesc;
	struct qbman_swp *swp;
	uint16_t num_tx = 0;
	uint16_t bpid;
	struct rte_eth_dev *eth_dev = &rte_eth_devices[portid];
	struct rte_eth_dev_data *eth_data = eth_dev->data;
	struct dpaa2_dev_priv *priv = eth_data->dev_private;
	uint32_t flags[MAX_TX_RING_SLOTS] = {0};


	struct dpaa2_queue *dpaa2_q = eth_data->tx_queues[cq->conf_q_id];
	priv->next_tx_conf_queue = dpaa2_q->tx_conf_queue;
	dpaa2_dev_tx_conf(dpaa2_q->tx_conf_queue);

	DPAA2_PMD_DP_DEBUG("%s: sending traffic on dev %s port %d hw_id %d \n",
			__func__, eth_data->name , eth_data->port_id, priv->hw_id);
	if (unlikely(!DPAA2_PER_LCORE_DPIO)) {
		ret = dpaa2_affine_qbman_swp();
		if (ret) {
			DPAA2_PMD_ERR(
				"Failed to allocate IO portal, tid: %d\n",
				rte_gettid());
			return 0;
		}
	}
	swp = DPAA2_PER_LCORE_PORTAL;

	DPAA2_PMD_DP_DEBUG("===> eth_data =%p, fqid =%d\n",
			eth_data, cq->vrid);

	if (priv->flags & DPAA2_TX_CONF_ENABLE)
		dpaa2_dev_tx_conf(priv->tx_conf_vq[cq->cqid]);
	/*Prepare enqueue descriptor*/
	qbman_eq_desc_clear(&eqdesc);
	qbman_eq_desc_set_no_orp(&eqdesc, DPAA2_EQ_RESP_ERR_FQ);
	qbman_eq_desc_set_fq(&eqdesc, cq->vrid);

	/*Clear the unused FD fields before sending*/
	while (nb_pkts) {
		/*Check if the queue is congested*/
		retry_count = 0;
#if 0
		while (qbman_result_SCN_state(dpaa2_q->cscn)) {
			retry_count++;
			/* Retry for some time before giving up */
			if (retry_count > CONG_RETRY_COUNT)
				goto skip_tx;
		}
#endif
		frames_to_send = (nb_pkts > dpaa2_eqcr_size) ?
			dpaa2_eqcr_size : nb_pkts;

		for (loop = 0; loop < frames_to_send; loop++) {
			if ((*bufs)->seqn) {
				uint8_t dqrr_index = (*bufs)->seqn - 1;

				flags[loop] = QBMAN_ENQUEUE_FLAG_DCA |
						dqrr_index;
				DPAA2_PER_LCORE_DQRR_SIZE--;
				DPAA2_PER_LCORE_DQRR_HELD &= ~(1 << dqrr_index);
				(*bufs)->seqn = DPAA2_INVALID_MBUF_SEQN;
			}

			if (likely(RTE_MBUF_DIRECT(*bufs))) {
				mp = (*bufs)->pool;
				/* Check the basic scenario and set
				 * the FD appropriately here itself.
				 */
				if (likely(mp && mp->ops_index ==
				    priv->bp_list->dpaa2_ops_index &&
				    (*bufs)->nb_segs == 1 &&
				    rte_mbuf_refcnt_read((*bufs)) == 1)) {
					if (unlikely(((*bufs)->ol_flags
						& PKT_TX_VLAN_PKT) ||
						(eth_data->dev_conf.txmode.offloads
						& DEV_TX_OFFLOAD_VLAN_INSERT))) {
						ret = rte_vlan_insert(bufs);
						if (ret)
							goto send_n_return;
					}
					DPAA2_MBUF_TO_CONTIG_FD((*bufs),
					&fd_arr[loop], mempool_to_bpid(mp));
					bufs++;
					continue;
				}
			} else {
				mi = rte_mbuf_from_indirect(*bufs);
				mp = mi->pool;
			}
			/* Not a hw_pkt pool allocated frame */
			if (unlikely(!mp || !priv->bp_list)) {
				DPAA2_PMD_ERR("Err: No buffer pool attached");
				goto send_n_return;
			}

			if (unlikely(((*bufs)->ol_flags & PKT_TX_VLAN_PKT) ||
				(eth_data->dev_conf.txmode.offloads
				& DEV_TX_OFFLOAD_VLAN_INSERT))) {
				int ret = rte_vlan_insert(bufs);
				if (ret)
					goto send_n_return;
			}
			if (mp->ops_index != priv->bp_list->dpaa2_ops_index) {
				DPAA2_PMD_WARN("Non DPAA2 buffer pool not supported");
				goto send_n_return;
			} else {
				bpid = mempool_to_bpid(mp);
				if (unlikely((*bufs)->nb_segs > 1)) {
					DPAA2_PMD_WARN("S/G not supported");
					goto send_n_return;
				} else {
					eth_mbuf_to_fd(*bufs,
						       &fd_arr[loop], bpid);
				}
			}
			bufs++;
		}

		loop = 0;
		retry_count = 0;
		while (loop < frames_to_send) {
			ret = qbman_swp_enqueue_multiple(swp, &eqdesc,
					&fd_arr[loop], &flags[loop],
					frames_to_send - loop);
			if (unlikely(ret < 0)) {
				retry_count++;
				if (retry_count > DPAA2_MAX_TX_RETRY_COUNT) {
					num_tx += loop;
					nb_pkts -= loop;
					goto send_n_return;
				}
			} else {
				loop += ret;
				retry_count = 0;
			}
		}

		num_tx += loop;
		nb_pkts -= loop;
	}
	return num_tx;

send_n_return:
	/* send any already prepared fd */
	if (loop) {
		unsigned int i = 0;

		retry_count = 0;
		while (i < loop) {
			ret = qbman_swp_enqueue_multiple(swp, &eqdesc,
							 &fd_arr[i],
							 &flags[i],
							 loop - i);
			if (unlikely(ret < 0)) {
				retry_count++;
				if (retry_count > DPAA2_MAX_TX_RETRY_COUNT)
					break;
			} else {
				i += ret;
				retry_count = 0;
			}
		}
		num_tx += i;
	}
//skip_tx:
	return num_tx;
}
#pragma GCC diagnostic pop

#endif /* _DPAA2_QOS_H */

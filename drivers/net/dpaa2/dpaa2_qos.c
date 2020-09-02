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
#define MAX_CH_PER_CEETM	2	/*  For PHASE-1 */
#define MAX_LFQ_PER_CH		1	/* Will be 16 later on */

struct class_sch {
	uint32_t cs_lfqid_base;
	uint32_t cq_count;
	struct {
		uint32_t cqid;
		uint32_t lfqid;
		uint32_t vrid;
	} cq[MAX_LFQ_PER_CH];
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
} ceetm[2];

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

//void mc_test(void);
int init_ceetm_res(uint32_t ceetmid, uint32_t cqid, uint32_t fqid);

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
//	mc_test();
	return 0;
}

int init_ceetm_res(uint32_t ceetmid, uint32_t cqid, uint32_t fqid)
{

	uint32_t cs_count =  ceetm[ceetmid].cs_count;
	uint32_t cq_idx;

	ceetmid = get_ceetm_instid((uint32_t)ceetmid);

	/* TODO Initialize with resources created by MC */
	ceetm[ceetmid].lfqid_base = 15745088;
	ceetm[ceetmid].lfq_vrid_base = 414;
	ceetm[ceetmid].cqid_base = 16;
	ceetm[ceetmid].chid_base = 1;
	ceetm[ceetmid].cs[cs_count].mode = SCHED_STRICT_PRIORITY;
	ceetm[ceetmid].cs[cs_count].cs_lfqid_base = 0; /* TODO */
	ceetm[ceetmid].cs[cs_count].chid = cqid >> 4;

	cq_idx = ceetm[ceetmid].cs[cs_count].cq_count;
	ceetm[ceetmid].cs[cs_count].cq[cq_idx].lfqid = 0;
	ceetm[ceetmid].cs[cs_count].cq[cq_idx].vrid = fqid;
	ceetm[ceetmid].cs[cs_count].cq[cq_idx].cqid = cqid;

	ceetm[ceetmid].cs[cs_count].cq_count++;
	ceetm[ceetmid].cs_count++;

	printf("%s:ceetm_inst[%d]  fqid %d cqid %d chid %u\n", __func__,
			ceetmid, ceetm[ceetmid].cs[cs_count].cq[cq_idx].vrid,
			ceetm[ceetmid].cs[cs_count].cq[cq_idx].cqid,
			ceetm[ceetmid].cs[cs_count].chid);
	printf("%s:cs_count = %d  cq_count = %d\n", __func__,
		ceetm[ceetmid].cs_count, ceetm[ceetmid].cs[cs_count].cq_count);
	return 0;
}

#if 0
void mc_test(void)
{
	/* Applying on port-2/ DPNI.3 */
	uint16_t portid = 1;
	int32_t l2_schidx;
	handle_t cq_handle[1], l1_sch_handle;
	struct dpaa2_shaper_params sh_param;
	struct dpaa2_sch_params sch_param;
	struct dpaa2_dev_priv *priv;

	priv = dpaa2_get_dev_priv(portid);
	/* TODO Set temporary till MC FLIB is not functional */
	priv->ceetm_id = 16;
	priv->lni = 4;

	l2_schidx = dpaa2_add_L2_sch(portid);

	memset(&sh_param, 0, sizeof(struct dpaa2_shaper_params));
	sh_param.c_rate = 20;
	sh_param.c_bs = 0;
	sh_param.oal = 24;
	dpaa2_cfg_L2_shaper(portid, &sh_param);

	sch_param.sch_mode = SCHED_STRICT_PRIORITY;
	sch_param.l2_sch_idx = l2_schidx;
	sch_param.shaped = 1;
	sch_param.num_L1_queues = 1;
	sch_param.q_handle = (handle_t *)&cq_handle;
	l1_sch_handle = dpaa2_add_L1_sch(portid, &sch_param);

	sh_param.c_rate = 40; /* 20 Mbps */
	dpaa2_cfg_L1_shaper(portid, l1_sch_handle, &sh_param);

#if 0
	/* CCGR */
	int rej_cnt_mode, td_en;
	uint32_t mode, td_thresh;
	qbman_ccgr_query(p_swp, ceetmid, chid, ccgid, &attr);
	qbman_cgr_attr_get_mode(&attr, &mode, &rej_cnt_mode);
	qbman_cgr_attr_get_td_ctrl(&attr, &td_en);
	qbman_cgr_attr_get_td_thres(&attr, &td_thresh);
	printf("%s:ccgid %d rej_cnt_mode %d mode %d td_en %d td_thresh %d\n",
			__func__, ccgid, rej_cnt_mode, mode, td_en, td_thresh);
	qbman_cgr_attr_set_mode(&attr, 1, 0);
	qbman_cgr_attr_set_td_ctrl(&attr, 1);
	qbman_cgr_attr_set_td_thres(&attr, 512);
	err = qbman_ccgr_configure(p_swp, ceetmid, chid, ccgid, &attr);
	if (err) {
		printf("%s: qbman_cchannel_configure failed err %d\n",
							__func__, err);
		return;
	}
	qbman_ccgr_query(p_swp, ceetmid, chid, ccgid, &attr);
	qbman_cgr_attr_get_mode(&attr, &mode, &rej_cnt_mode);
	qbman_cgr_attr_get_td_ctrl(&attr, &td_en);
	qbman_cgr_attr_get_td_thres(&attr, &td_thresh);
	printf("%s:NEW : ccgid %d rej_cnt_mode %d mode %d td_en %d td_thresh %d\n",
			__func__, ccgid, rej_cnt_mode, mode, td_en, td_thresh);
#endif
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
	bps = (uint64_t)sh_param->c_rate * 1000000;
	qbman_shaper_set_commit_rate(&attr, bps);
	burst_size = qbman_fix_burst_size(sh_param->c_bs * 1000, bps);
	qbman_shaper_set_crtbl(&attr, burst_size);
	printf("%s: PortId %d - cr %ld cbs %d\n", __func__,
					portid, bps, burst_size);
	bps = (uint64_t)sh_param->e_rate * 1000000;
	qbman_shaper_set_excess_rate(&attr, bps);
	burst_size = qbman_fix_burst_size(sh_param->e_bs * 1000, bps);
	qbman_shaper_set_ertbl(&attr, burst_size);
	DPAA2_PMD_INFO("%s: er %dMbps ebs %dKbps\n", __func__,
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

int32_t dpaa2_add_L1_sch(uint16_t portid,
			struct dpaa2_sch_params *sch_param)
{
	struct qbman_attr attr;
	struct dpaa2_dev_priv *priv;
	uint8_t instid;
	struct class_sch *cs;
	uint32_t cur_idx, i;
	struct dpaa2_queue *dpaa2_q;
	int err;

	/* Get the device data to fetch CEETM, LNI index etc. from the given port
	   and validate */
	priv = dpaa2_get_dev_priv(portid);
	if (NULL == priv)
		return -EINVAL;

	/* WRR TODO */
	if (sch_param->sch_mode != SCHED_STRICT_PRIORITY) {
		DPAA2_PMD_ERR("%s: Only PRIO mode is supported\n", __func__);
		return -EINVAL;
	}
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
	//for (i = 0; i < sch_param->num_L1_queues; i++) {
	for (i = 0; i < 8; i++) {
		qbman_cscheduler_set_crem_cq(&attr, i, sch_param->shaped ? 1 : 0);
		qbman_cscheduler_set_erem_cq(&attr, i, sch_param->shaped ? 1 : 0);
	}
	/* WRR TODO */
	/* 1 means the groups A and B are combined */
	qbman_cscheduler_set_group_b(&attr, 1);
	/* Set the priority of group A 0-7*/
	qbman_cscheduler_set_prio_a(&attr, 7);

	err = qbman_cscheduler_configure(p_swp, priv->ceetm_id,
			cs->chid, &attr);
	if (err) {
		printf("%s: qbman_cscheduler_configure failed err %d\n",
							__func__, err);
		return -EINVAL;
	}

	for (i = 0; i < sch_param->num_L1_queues; i++) {
		/* Update existing Tx queue fqid */
		dpaa2_q = (struct dpaa2_queue *)priv->tx_vq[i];
		dpaa2_q->fqid = cs->cq[i].vrid;
		/* TODO optional for now, may not need it */
		sch_param->q_handle[i] = cs->cq[i].vrid;
		printf("%s: Updated Tc[%d] fqid = %d\n", __func__, i, dpaa2_q->fqid);
	}
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
	bps = (uint64_t)sh_param->c_rate * 1000000;
	qbman_shaper_set_commit_rate(&attr, bps);
	burst_size = qbman_fix_burst_size(sh_param->c_bs * 1000, bps);
	qbman_shaper_set_crtbl(&attr, burst_size);
	printf("%s: PortId %d - cr %ld cbs %d\n", __func__,
					portid, bps, burst_size);
	bps = (uint64_t)sh_param->e_rate * 1000000;
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

int8_t dpaa2_cfg_taildrop_profile(uint8_t  td_mode,
				uint32_t td_thres,
				uint32_t oal)
{
	/* Get the CEETM, LNI index etc. from the given port and validate */
	/* Will need to call following QBMan APIs */
//	qbman_ccgr_attr_clear()
//	qbman_cgr_attr_set_td_thres()
//	qbman_cgr_attr_set_td_ctrl()
//	qbman_cgr_attr_set_td_ctrl()
//	qbman_cgr_attr_set_mode()
//	qbman_ccgr_attr_set_oal()
//	qbman_ccgr_configure()
	return 0;

}

uint16_t dpaa2_dev_qos_tx(uint16_t portid,
			uint16_t q_handle,
			struct rte_mbuf **bufs,
			uint16_t nb_pkts)
{
	return 0;
}
#pragma GCC diagnostic pop

#endif /* _DPAA2_QOS_H */

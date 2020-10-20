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
#include "qbman_portal.h"
#include "qbman_portal_ex.h"
#include <fsl_qbman_portal_ex.h>
#include <rte_pmd_dpaa2_qos.h>

/* SACHIN TODO */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

#define MAX_CH_PER_CEETM	32	/*  For PHASE-1 */

#define DRV_UT		0

uint32_t ceetm_ch_base0, ceetm_ch_base1, ceetm_ch_max0, ceetm_ch_max1;
uint32_t ceetm_lfq_base0, ceetm_lfq_base1, ceetm_lfq_max0, ceetm_lfq_max1;

struct class_q {
	uint32_t cqid;
	uint32_t lfqid;
	uint32_t lfqidx;
	uint32_t vrid;
	uint32_t ccgrid;
	uint16_t portid; /* Tx Port */
};

struct class_sch {
	uint32_t cq_count;
	struct class_q  cq[L1_MAX_QUEUES];
	uint32_t cq_inuse;
	uint8_t chid;
};

struct ceetm_res {
	uint32_t chid_base;
	uint32_t cs_count;
	uint32_t lfq_count;
	struct class_sch cs[MAX_CH_PER_CEETM];
	uint32_t cs_inuse;
	uint8_t init;
} ceetm[2] = {0};

struct dpaa2_queue *reject_frames_queue = NULL;

/* Global Privileged portal */
struct qbman_swp *p_swp = NULL;

static inline uint8_t get_ceetm_instid(uint32_t ceetm_id)
{
	uint8_t dcpid, instanceid;

	qbman_ceetmid_decompose(ceetm_id, &dcpid, &instanceid);

	DPAA2_PMD_DEBUG("%s: CEETM id %d instanceid %d\n", __func__, ceetm_id, instanceid);
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
int init_ceetm_res(uint16_t portid);

int32_t dpaa2_qos_init(uint16_t portid)
{
	/* Validate whether PRIVILAGED QBMAn portal is available else return error */
	if (p_swp == NULL) {

		p_swp = dpaa2_get_priv_qbman_swp();
		if (NULL == p_swp) {
			DPAA2_PMD_ERR("Privileged Portal not found\n");
			return -EINVAL;
		}
		DPAA2_PMD_INFO("%s: Privileged Portal is avialble\n", __func__);

	}
	init_ceetm_res(portid);

	return 0;
}

int init_ceetm_res(uint16_t portid)
{
	struct rte_eth_dev *eth_dev = &rte_eth_devices[portid];
        struct rte_eth_dev_data *eth_data = eth_dev->data;
        struct dpaa2_dev_priv *priv = eth_data->dev_private;
	struct fsl_mc_io *dpni = eth_dev->process_private;
	uint32_t ceetmid, k, lfq_count, cq_idx = 0, channel_base;
	int err, ret;
	uint32_t channel_number, ceetm_lfq_max, ceetm_ch_max;
	uint8_t ps = 1; // PFDR Stashing enable, optimisation
	uint8_t pps = 0; // Pool selection, optimisation
	uint32_t bdi = 0;
	uint32_t va = 0;
	uint32_t pl = 0;
	uint32_t icid = priv->icid;
	uint8_t instanceid;

	if (reject_frames_queue == NULL) {
		struct dpni_queue_id qid;
		struct dpni_queue tx_conf_cfg;

		reject_frames_queue = rte_malloc(NULL, sizeof(struct dpaa2_queue),
						RTE_CACHE_LINE_SIZE);
		reject_frames_queue->eth_data = eth_data;
		reject_frames_queue->tc_index = 0;
		reject_frames_queue->flow_id = 0;
		reject_frames_queue->q_storage = rte_malloc("dq_storage", sizeof(struct queue_storage_info_t),
					RTE_CACHE_LINE_SIZE);
		if (!reject_frames_queue->q_storage) {
			printf("failed to allocate dq storage \n");
			rte_free(reject_frames_queue);
			reject_frames_queue = NULL;
			return -1;
		}

		memset(reject_frames_queue->q_storage, 0, sizeof(struct queue_storage_info_t));

		if (dpaa2_alloc_dq_storage(reject_frames_queue->q_storage)) {
			printf("failed to allocate dq storage \n");
			rte_free(reject_frames_queue);
			reject_frames_queue = NULL;
			return -1;
		}

		ret = dpni_get_queue(dpni, CMD_PRI_LOW, priv->token,
                             DPNI_QUEUE_TX_CONFIRM, reject_frames_queue->tc_index,
                             reject_frames_queue->flow_id, &tx_conf_cfg, &qid);
                if (ret) {
                        printf("Error in getting LFQID err=%d", ret);
                        return -1;
                }
                reject_frames_queue->fqid = qid.fqid;
                reject_frames_queue->real_cqid = qid.real_fqid;
                printf("\nReject queue  real id =%d and fqid =%d\n", qid.real_fqid, qid.fqid);
	}

	ceetmid = priv->ceetm_id;  /*LNI is already avaialable in priv*/
	instanceid = get_ceetm_instid((uint32_t)ceetmid);
	if (ceetm[instanceid].init == 1)
		return 0;

	lfq_count =  ceetm[instanceid].lfq_count;
	if (instanceid == 0) {
		if (ceetm_ch_base0 == 0xff || ceetm_lfq_base0 == 0xffff) {
			printf("No resources available \n");
			return -1;
		}
		channel_base = ceetm_ch_base0;
		ceetm_ch_max = ceetm_ch_max0;
		ceetm_lfq_max = ceetm_lfq_max0;
	} else {
		if (ceetm_ch_base1 == 0xff || ceetm_lfq_base1 == 0xffff) {
			printf("No resources available \n");
			return -1;
		}
		channel_base = ceetm_ch_base1;
		ceetm_ch_max = ceetm_ch_max1;
		ceetm_lfq_max = ceetm_lfq_max1;
	}

	ceetm[instanceid].chid_base = channel_base;
	channel_number = channel_base;

	if (ceetm_ch_max == 0xff) {
		printf("Maximum channel ID is invalid = %x\n", ceetm_ch_max);
		return -1;
	}

	for (k = 0; k < ((ceetm_ch_max + 1) - channel_base); k++) {
		ceetm[instanceid].cs[k].chid = channel_number & 0x1f;
		cq_idx = ceetm[instanceid].cs[k].cq_count;
		if (ceetm_lfq_max == 0xffff) {
			printf("No free LFQs available\n");
			return -1;
		}

		for (int i = 0; i < L1_MAX_QUEUES; i++) {
			if (instanceid == 0) {
				if ((ceetm_lfq_base0 + lfq_count) > (ceetm_lfq_max + 1)) {
					printf("No LFQ resources left\n");
					return -1;
				}
				ceetm[instanceid].cs[k].cq[cq_idx].lfqidx = ceetm_lfq_base0 + lfq_count;
			} else {
				if ((ceetm_lfq_base1 + lfq_count) > (ceetm_lfq_max + 1)) {
					printf("No LFQ resources left\n");
					return -1;
				}
				ceetm[instanceid].cs[k].cq[cq_idx].lfqidx = ceetm_lfq_base1 + lfq_count;
			}
			ceetm[instanceid].cs[k].cq[cq_idx].lfqid = qbman_lfqid_compose_ex(ceetmid,
						ceetm[instanceid].cs[k].cq[cq_idx].lfqidx);
			err = qbman_auth_add_find(p_swp, icid, qbman_auth_type_fqid,
						&ceetm[instanceid].cs[k].cq[cq_idx].vrid,
						ceetm[instanceid].cs[k].cq[cq_idx].lfqid,
						QBMAN_AUTH_SWP | QBMAN_AUTH_DCP);
			if (err != 0)
				printf("qbman_auth_add_find() failed for TX-Q\n");

			/* Configure DCT assuming one Sender */
			/* TODO MC configure CCGRID same as TC index, only one per CEETM is required */
			ceetm[instanceid].cs[k].cq[cq_idx].ccgrid = cq_idx;
			ceetm[instanceid].cs[k].cq[cq_idx].portid = portid;
			ceetm[instanceid].cs[k].cq[cq_idx].cqid = (channel_number << 4) + cq_idx;

			err = qbman_cq_configure(p_swp, ceetmid, ceetm[instanceid].cs[k].cq[cq_idx].cqid,
						/*ccgid*/ cq_idx, ps, pps);
			if (err != 0)
				printf("qbman_CQ_configure() failed for TX-Q\n");

			/* We are using same LFQIDX for DCTIDX */
			err = qbman_lfq_configure(p_swp,
						ceetm[instanceid].cs[k].cq[cq_idx].lfqid,
						ceetm[instanceid].cs[k].cq[cq_idx].cqid,
						ceetm[instanceid].cs[k].cq[cq_idx].lfqidx,
						reject_frames_queue->real_cqid);
			if (err != 0) {
				printf("qbman_lfq_configure failed\n");
				return -1;
			}

			/* TODO: ifpid , may call this API in scheduler configure*/
			/* We are using same LFQIDX for DCTIDX */
			err = qbman_dct_configure(p_swp, ceetmid,
						ceetm[instanceid].cs[k].cq[cq_idx].lfqidx,
						bdi, va, icid, pl, /*ctx*/((uint64_t)priv->ifpid << 48));
			if (err != 0) {
				printf("qbman_dct_configure failed\n");
				return -1;
			}

#if 0
			printf("cidx %d fqid %d cqid %d chid %u lfqid %d, lfqidx %d, ifpid %d\n", k,
				ceetm[instanceid].cs[k].cq[cq_idx].vrid,
				ceetm[instanceid].cs[k].cq[cq_idx].cqid,
				ceetm[instanceid].cs[k].chid,
				ceetm[instanceid].cs[k].cq[cq_idx].lfqid,
				ceetm[instanceid].cs[k].cq[cq_idx].lfqidx,
				priv->ifpid);
#endif

			ceetm[instanceid].cs[k].cq_count++;
			cq_idx++;
			lfq_count++;
		}

		channel_number++;
	}
	ceetm[instanceid].cs_count += k;
	ceetm[instanceid].lfq_count += lfq_count;

	ceetm[instanceid].init = 1;

	return 0;
}

void dpaa2_print_ceetm_res(void)
{
	printf("CEETM instance0 resources:\n");
	printf("~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
	if (ceetm_ch_base0 == 0xff) {
		printf("\tchannels count = 0\n");
		printf("\tclass queues count = 0\n");
	} else {
		printf("\tchannels count = %d\n",
				(ceetm_ch_max0 + 1) - ceetm_ch_base0);
		printf("\tclass queues count = %d\n",
				((ceetm_ch_max0 + 1) - ceetm_ch_base0) * 8);
	}

	if (ceetm_lfq_base0 == 0xffff)
		printf("\tLFQs count = 0\n");
	else
		printf("\tLFQs count = %d\n",
				(ceetm_lfq_max0 + 1) - ceetm_lfq_base0);

	printf("\nCEETM instance1 resources:\n");
	printf("~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
	if (ceetm_ch_base1 == 0xff) {
		printf("\tchannels count = 0\n");
		printf("\tclass queues count = 0\n");
	} else {
		printf("\tchannels count = %d\n",
				(ceetm_ch_max1 + 1) - ceetm_ch_base1);
		printf("\tclass queues count = %d\n",
				((ceetm_ch_max1 + 1) - ceetm_ch_base1) * 8);
	}

	if (ceetm_lfq_base1 == 0xffff)
		printf("\tLFQs count = 0\n");
	else
		printf("\tLFQs count = %d\n",
				(ceetm_lfq_max1 + 1) - ceetm_lfq_base1);

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

void dpaa2_qos_deinit(__rte_unused uint16_t portid)
{
	/* TODO */
}

void dpaa2_get_free_bufs(const struct rte_mempool *mp, uint32_t *bufs)
{
	struct dpaa2_bp_info *bp_info;
        uint32_t bpid;

	/* Assuming mp is a valid mempool */
	bp_info = (struct dpaa2_bp_info *)mp->pool_data;
	bpid = bp_info->bp_list->buf_pool.bpid;

	qbman_bp_query_num_free_bufs(p_swp, bpid, bufs);
}

int32_t dpaa2_get_qos_stats(uint16_t portid, handle_t ch_id,
			    qhandle_t q_handle,
			    struct dpaa2_qos_stats *stats, int clear)
{
	int ret;
	struct class_q *cq = (struct class_q *)q_handle;
	struct dpaa2_dev_priv *priv;

	priv = dpaa2_get_dev_priv(portid);
	if (NULL == priv)
		return -EINVAL;

	/* clear == 0 == query_dq_statistics
	 * clear == 1 == query_and_clear_dq_statistics
	 */
	ret = qbman_ceetm_statistics_query(p_swp, priv->ceetm_id, cq->cqid, clear,
				     &stats->dq_frames, &stats->dq_bytes);
	if (ret) {
		printf("Unable to retrieve statistics\n");
		return ret;
	}
	ret = qbman_cq_query_pending_frame(p_swp, priv->ceetm_id, cq->cqid, &stats->q_frames);
	if (ret) {
		printf("Unable to retrieve queue statistics\n");
		return ret;
	}

	ret = qbman_ccgr_query_i_cnt(p_swp, priv->ceetm_id, ch_id, cq->ccgrid,
			       &stats->q_bytes);
	if (ret) {
		printf("Unable to retrieve bytes in the queue\n");
		return ret;
	}

	return 0;
}

int32_t dpaa2_add_L2_sch(uint16_t portid)
{
	struct dpaa2_dev_priv *priv;

	priv = dpaa2_get_dev_priv(portid);
	if (NULL == priv)
		return -EINVAL;

	/* Get the LNI index from the given port and validate */
	DPAA2_PMD_DEBUG("%s: PortId %d [dpni.%d]-- LNI Id %d CEETM Id %d\n", __func__,
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
	DPAA2_PMD_INFO("%s: PortId %d - cr %ld cbs %d\n", __func__,
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
	uint32_t bdi = 0;
	uint32_t va = 0;
	uint32_t pl = 0;

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

	for (i = 0; i < sch_param->num_L1_queues; i++) {
		err = qbman_dct_configure(p_swp, priv->ceetm_id,
					cs->cq[i].lfqidx,
					bdi, va, priv->icid, pl, /*ctx*/((uint64_t)priv->ifpid << 48));
		if (err != 0) {
			printf("qbman_dct_configure failed\n");
			return -1;
		}
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

		cs->cq[i].portid = portid;
		sch_param->q_handle[i] = (qhandle_t) &cs->cq[i];
		DPAA2_PMD_DP_DEBUG("%s: Updated Tc[%d] handle %ld fqid = %d\n", __func__,
					i, sch_param->q_handle[i], cs->cq[i].vrid);
		/* CCGR */
		qbman_ccgr_query(p_swp,  priv->ceetm_id, cs->chid,
						cs->cq[i].ccgrid, &attr);
		qbman_cgr_attr_get_mode(&attr, &mode, &rej_cnt_mode);
		qbman_cgr_attr_get_td_ctrl(&attr, &td_en);
		qbman_cgr_attr_get_td_thres(&attr, &td_thresh);
		DPAA2_PMD_DP_DEBUG("%s:ccgrid %d: existing: rej_cnt_mode %d mode %d td_en %d td_thresh %d\n",
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
			DPAA2_PMD_DP_DEBUG("%s: qbman_cchannel_configure failed err %d\n",
							__func__, err);
			return -EINVAL;
		}
		qbman_ccgr_query(p_swp,  priv->ceetm_id, cs->chid,
						cs->cq[i].ccgrid, &attr);
		qbman_cgr_attr_get_mode(&attr, &mode, &rej_cnt_mode);
		qbman_cgr_attr_get_td_ctrl(&attr, &td_en);
		qbman_cgr_attr_get_td_thres(&attr, &td_thresh);
		DPAA2_PMD_DP_DEBUG("%s:NEW : ccgrid %d rej_cnt_mode %d mode %d td_en %d td_thresh %d\n",
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
	uint32_t bdi = 0;
	uint32_t va = 0;
	uint32_t pl = 0;

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

	for (i = 0; i < sch_param->num_L1_queues; i++) {
		err = qbman_dct_configure(p_swp, priv->ceetm_id,
					cs->cq[i].lfqidx,
					bdi, va, priv->icid, pl, /*ctx*/((uint64_t)priv->ifpid << 48));
		if (err != 0) {
			printf("qbman_dct_configure failed\n");
			return -1;
		}
	}

	DPAA2_PMD_DEBUG("%s: ceetm %d lin %d chid %d shaped %d \n", __func__,
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

		cs->cq[i].portid = portid;
		sch_param->q_handle[i] = (qhandle_t) &cs->cq[i];
		DPAA2_PMD_DP_DEBUG("%s: Updated Tc[%d] handle %ld fqid = %d\n", __func__,
					i, sch_param->q_handle[i], cs->cq[i].vrid);
		/* CCGR */
		qbman_ccgr_query(p_swp,  priv->ceetm_id, cs->chid,
						cs->cq[i].ccgrid, &attr);
		qbman_cgr_attr_get_mode(&attr, &mode, &rej_cnt_mode);
		qbman_cgr_attr_get_td_ctrl(&attr, &td_en);
		qbman_cgr_attr_get_td_thres(&attr, &td_thresh);
		DPAA2_PMD_DP_DEBUG("%s:ccgrid %d: existing: rej_cnt_mode %d mode %d td_en %d td_thresh %d\n",
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
		DPAA2_PMD_DP_DEBUG("%s:NEW : ccgrid %d rej_cnt_mode %d mode %d td_en %d td_thresh %d\n",
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
	DPAA2_PMD_INFO("%s: PortId %d - cr %ld cbs %d\n", __func__,
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
	DPAA2_PMD_DEBUG("%s: ceetm %d lni %d chid %d shaped %d \n", __func__,
		priv->ceetm_id, priv->lni, l1_sch_handle, 1);
	printf("done\n");

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

static uint16_t dpaa2_dev_tx_reject(void *queue)
{
	/* Function receive frames for a given device and VQ */
	struct dpaa2_queue *dpaa2_q = (struct dpaa2_queue *)queue;
	struct qbman_result *dq_storage;
	uint32_t fqid = dpaa2_q->fqid;
	int ret, num_pulled;
	uint8_t pending, status;
	struct qbman_swp *swp;
	const struct qbman_fd *fd, *next_fd;
	struct qbman_pull_desc pulldesc;
	struct qbman_release_desc releasedesc;
	uint32_t bpid;
	uint64_t buf;

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

	rte_spinlock_lock(&err_q_lock);
	do {
		dq_storage = dpaa2_q->q_storage->dq_storage[0];
		qbman_pull_desc_clear(&pulldesc);
		qbman_pull_desc_set_fq(&pulldesc, fqid);
		qbman_pull_desc_set_storage(&pulldesc, dq_storage,
			(size_t)(DPAA2_VADDR_TO_IOVA(dq_storage)), 1);
		qbman_pull_desc_set_numframes(&pulldesc, dpaa2_dqrr_size);

		while (1) {
			if (qbman_swp_pull(swp, &pulldesc)) {
				DPAA2_PMD_DP_DEBUG("VDQ command is not issued."
					"QBMAN is busy\n");
				/* Portal was busy, try again */
				continue;
			}
			break;
		}

		rte_prefetch0((void *)((size_t)(dq_storage + 1)));
		/* Check if the previous issued command is completed. */
		while (!qbman_check_command_complete(dq_storage))
			;

		num_pulled = 0;
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
				if (unlikely((status &
					QBMAN_DQ_STAT_VALIDFRAME) == 0))
					continue;
			}
			fd = qbman_result_DQ_fd(dq_storage);

			next_fd = qbman_result_DQ_fd(dq_storage + 1);
			/* Prefetch Annotation address for the parse results */
			rte_prefetch0((void *)(size_t)
				(DPAA2_GET_FD_ADDR(next_fd) +
				DPAA2_FD_PTA_SIZE + 16));

			bpid = DPAA2_GET_FD_BPID(fd);

			/* Create a release descriptor required for releasing
			 * buffers into QBMAN
			 */
			qbman_release_desc_clear(&releasedesc);
			qbman_release_desc_set_bpid(&releasedesc, bpid);

			buf = DPAA2_GET_FD_ADDR(fd);
			/* feed them to bman */
			do {
				ret = qbman_swp_release(swp, &releasedesc,
							&buf, 1);
			} while (ret == -EBUSY);

			dq_storage++;
			num_pulled++;
		} while (pending);

	/* Last VDQ provided all packets and more packets are requested */
	} while (num_pulled == dpaa2_dqrr_size);
	rte_spinlock_unlock(&err_q_lock);

	return 0;
}

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

	dpaa2_dev_tx_reject(reject_frames_queue);

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

/* SPDX-License-Identifier: BSD-3-Clause
 *
 *   Copyright 2020 NXP
 *
 */

#ifndef _RTE_PMD_DPAA2_QOS_H
#define _RTE_PMD_DPAA2_QOS_H

#include <rte_mbuf.h>

#define INVALD_VAL		0xFF
#define L1_MAX_QUEUES		8

typedef int32_t handle_t;
typedef int64_t qhandle_t;


enum scheduler_mode {
	SCHED_STRICT_PRIORITY = 0,
	SCHED_WRR
};

enum td_unit {
	CONGESTION_UNIT_BYTES = 0,
	CONGESTION_UNIT_FRAMES
};

/**
 * Schduler parameters
 */
struct dpaa2_sch_params {
	uint8_t sch_mode;	/* PRIO or WRR */
	uint8_t shaped;		/*  Whether Shaper is required */
	uint8_t num_L1_queues;	/*  Number of required input queues */
	int32_t l2_sch_idx;	/* Index of target Level-2 scheduler
				   instance to which this will associate. */
	uint32_t td_thresh[L1_MAX_QUEUES]; /* Tail-Drop threshold for each
					     queue. 0 means disable */
	enum td_unit td_mode[L1_MAX_QUEUES];	/* Byte or packet */
	/* Pointer to array of queue handles for 'num_L1_queues' queues.
	   This queue handles to be used while transmitting packets */
	qhandle_t *q_handle;
};

/**
 * Shaper (rate limiter) parameters
 */
struct dpaa2_shaper_params {
	float	 c_rate;	/* Commited Rate in Mbps */
	uint32_t c_bs;		/* Token Bucket size for Commited Rate in Kbps */
	float	 e_rate;	/* Excess Rate in Mbps */
	uint32_t e_bs;		/* Token Bucket size for Excess Rate in Kbps */
	uint32_t mps;		/* Minimum packet size; 0: Disable */
	uint32_t oal;		/* Overhead accounting length, requires for shaper adjusment */
	int32_t  cpl;		/* 1: CR and ER are coupled;  0: CR and ER are not coupled. */
};
/**
 * @warning
 * @b EXPERIMENTAL: this APIs is for specific propritary use case and may change without prior notice
 *
 * Initialize DPAA2 CEETM/QoS resources.
 *
 * @return
 *    0 in case of success, Negative in case of failure.
 */
int32_t dpaa2_qos_init(void);


/**
 * @warning
 * @b EXPERIMENTAL: this APIs is for specific propritary use case and may change without prior notice
 *
 * De-initialize and reset all the allocated DPAA2 CEETM/QoS resources.
 *
 * @return
 *    none
 */
void dpaa2_qos_deinit(void);


/**
 * @warning
 * @b EXPERIMENTAL: this APIs is for specific propritary use case and may change without prior notice
 *
 * Inititalize a Level-2 Scheduler instance.
 *
 * @param portid
 *    ID of the port in context.
 *
 * @return
 *    A valid index of Level-2 instance in case of success, Negative in case of failure.
 */
int32_t dpaa2_add_L2_sch(uint16_t portid);


/**
 * @warning
 * @b EXPERIMENTAL: this APIs is for specific propritary use case and may change without prior notice
 *
 * Configure a Level-2 Shaper instance.
 *
 * @param portid
 *    ID of the port in context.
 *
 * @param sh_param
 *    Associated Shaper configuration parameters.
 *
 * @return
 *    0 in case of success, Negative in case of failure.
 */
int32_t dpaa2_cfg_L2_shaper(uint16_t portid,
			struct dpaa2_shaper_params *sh_param);

/**
 * @warning
 * @b EXPERIMENTAL: this APIs is for specific propritary use case and may change without prior notice
 *
 * Inititalize a Level-1 Scheduler instance.
 *
 * @param portid
 *    ID of the port in context.
 *
 * @param sh_param
 *    Scheduler configuration parameters.
 *
 * @return
 *    valid handle in case of success, Negative in case of failure.
 */
handle_t dpaa2_add_L1_sch(uint16_t portid,
			struct dpaa2_sch_params *sch_param);

/**
 * @warning
 * @b EXPERIMENTAL: this APIs is for specific propritary use case and may change without prior notice
 *
 * Configure a Level-1 Shaper instance.
 *
 * @param portid
 *    ID of the port in context.
 *
 * @param sch_idx
 *    Level-1 scheduler index.
 *
 * @param sh_param
 *    Associated Shaper configuration parameters.
 *
 * @return
 *    0 in case of success, Negative in case of failure.
 */
int32_t dpaa2_cfg_L1_shaper(uint16_t portid,
			handle_t sch_handle,
			struct dpaa2_shaper_params *sh_param);

/**
 * @warning
 * @b EXPERIMENTAL: this APIs is for specific propritary use case and may change without prior notice
 *
 * Packet trasmit function through DPAA2 QoS datapath.
 *
 * @param portid
 *    ID of the port in context.
 *
 * @param q_handle
 *    The respective queue handle that belongs to a queue with index [0-7].
 *
 * @param bufs
 *    List of buffers
 *
 * @param nb_pkts
 *    Number of buffers in the list.
 *
 * @return
 *   Number of packets transmitted successfully.
 */
uint16_t dpaa2_dev_qos_tx(uint16_t portid,
			qhandle_t q_handle,
			struct rte_mbuf **bufs,
			uint16_t nb_pkts);

#endif /* _DPAA2_QOS_H */

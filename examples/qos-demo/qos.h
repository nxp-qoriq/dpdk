/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 NXP
 */

#include <rte_pmd_dpaa2_qos.h>

#define MAX_L1  32
#define MAX_L2  6
#define ENTRY_DELIMITER "="

struct sched_shaper_data {
	unsigned int id;
        float cir_rate;
        float eir_rate;
        unsigned int cir_burst_size;
        unsigned int eir_burst_size;
	unsigned int coupled;
	int lni_id; /* Internal and applicable for L2 */
	qhandle_t channel_id; /* Internal and applicable for l1 */
	unsigned int q_count; /* for l1 */
	unsigned int mode;  /* 0 for strict and 1 for WRR */
	unsigned int weight[L1_MAX_QUEUES];  /* number of values must be equal to q_count */
	qhandle_t cq[L1_MAX_QUEUES];
	unsigned int l2_id;
	unsigned int port_idx;
};

struct qos_data {
        struct sched_shaper_data l1[MAX_L1];
        struct sched_shaper_data l2[MAX_L2];
	int l1_count;
	int l2_count;
	int taildrop_th;
};

int
qos_data_read(const char *filename,
              struct qos_data *vector);

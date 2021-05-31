/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020-2021 NXP
 */

#ifndef _ENET_LOGS_H_
#define _ENET_LOGS_H_

extern int enetfec_logtype_pmd;

/* PMD related logs */
#define ENET_PMD_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, enetfec_logtype_pmd, "\nfec_net: %s()" \
		fmt "\n", __func__, ##args)

#define PMD_INIT_FUNC_TRACE() ENET_PMD_LOG(DEBUG, " >>")

#define ENET_PMD_DEBUG(fmt, args...) \
	ENET_PMD_LOG(DEBUG, fmt, ## args)
#define ENET_PMD_ERR(fmt, args...) \
	ENET_PMD_LOG(ERR, fmt, ## args)
#define ENET_PMD_INFO(fmt, args...) \
	ENET_PMD_LOG(INFO, fmt, ## args)

#define ENET_PMD_WARN(fmt, args...) \
	ENET_PMD_LOG(WARNING, fmt, ## args)

/* DP Logs, toggled out at compile time if level lower than current level */
#define ENET_DP_LOG(level, fmt, args...) \
	RTE_LOG_DP(level, PMD, fmt, ## args)

#endif /* _ENET_LOGS_H_ */

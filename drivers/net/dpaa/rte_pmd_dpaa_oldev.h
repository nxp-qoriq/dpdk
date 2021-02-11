/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 NXP
 */

#ifndef _RTE_PMD_DPAA_OLDEV_H
#define _RTE_PMD_DPAA_OLDEV_H

#define DPA_ISC_IPV4_ADDR_TYPE  0x04
#define DPA_ISC_IPV6_ADDR_TYPE  0x06
#define MAX_NUM_IP_ADDRS 5

struct rte_pmd_dpaa_ip_addr_s {
	uint8_t		ip_addr_type;
	uint32_t	ip_addr[4];
};

__rte_experimental
int rte_pmd_dpaa_ol_set_classif_info(uint16_t udp_port, uint8_t proto_id,
			     uint8_t num_addresses,
			     struct rte_pmd_dpaa_ip_addr_s ip_addr_list[]);

__rte_experimental
int rte_pmd_dpaa_ol_reset_classif_info(void);

#endif

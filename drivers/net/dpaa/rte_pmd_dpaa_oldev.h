/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 NXP
 */

#ifndef _RTE_PMD_DPAA_OLDEV_H
#define _RTE_PMD_DPAA_OLDEV_H

#define DPA_ISC_IPV4_ADDR_TYPE  0x04
#define DPA_ISC_IPV6_ADDR_TYPE  0x06
#define MAX_NUM_IP_ADDRS 5
#define MAX_NUM_PORTS 2

#define DPA_ISC_IPV4_SUBNET_TYPE  0x04
#define DPA_ISC_IPV6_SUBNET_TYPE  0x06
#define MAX_NUM_SUBNETS 4

struct ip_addr_s {
	uint8_t		ip_addr_type;
	uint32_t	ip_addr[4];
};

struct lgw_subnet_s {
	uint32_t subnet[4];
	uint8_t mask;
	uint8_t subnet_type;
	uint8_t pad[2];
} __attribute__((packed));

struct rte_pmd_dpaa_uplink_cls_info_s {
	struct		ip_addr_s addrs[MAX_NUM_IP_ADDRS];
	uint16_t	gtp_udp_port[MAX_NUM_PORTS]; /* DPDK app listens on this GTP ports */
	uint8_t		gtp_proto_id; /* DPDK app listens on UDP protocol */
	uint8_t		num_addresses;
	uint8_t		num_ports;
};

struct rte_pmd_dpaa_lgw_info_s {
	struct lgw_subnet_s subnets[MAX_NUM_SUBNETS];
	uint8_t  	num_subnets;
	uint8_t		pad[3];
} __attribute__((packed));

__rte_experimental
int rte_pmd_dpaa_ol_set_classif_info(
			struct rte_pmd_dpaa_uplink_cls_info_s *cls_info);

__rte_experimental
int rte_pmd_dpaa_ol_reset_classif_info(void);

__rte_experimental
int rte_pmd_dpaa_ol_set_lgw_info(struct rte_pmd_dpaa_lgw_info_s *lgw_info);

__rte_experimental
int rte_pmd_dpaa_ol_reset_lgw_info(void);

#endif

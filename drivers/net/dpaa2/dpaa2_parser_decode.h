/* SPDX-License-Identifier: BSD-3-Clause
 *
 *   Copyright 2022-2025 NXP
 *
 */

#ifndef _DPAA2_PARSE_DECODE_H
#define _DPAA2_PARSE_DECODE_H

#include <rte_flow.h>
#include <rte_event_eth_rx_adapter.h>
#include <rte_pmd_dpaa2.h>

#include <bus_fslmc_driver.h>
#include <dpaa2_hw_pvt.h>
#include "dpaa2_tm.h"

#include <mc/fsl_dpni.h>
#include <mc/fsl_mc_sys.h>

#include "base/dpaa2_hw_dpni_annot.h"

#define DPAA2_PR_PRINT printf

#define BIT_SIZE(t) (sizeof(t) * 8)
#define BIT_OFFSET(t, m) (offsetof(t, m) * 8)
#define BIT_LAST_OFFSET(t) (BIT_SIZE(t) - 1)

enum dpaa2_parser_protocol_id {
	DPAA2_PARSER_MAC_ID,
	DPAA2_PARSER_VLAN_ID,
	DPAA2_PARSER_ICMP_ID,
	DPAA2_PARSER_IP_ID,
	DPAA2_PARSER_IPV4_ID,
	DPAA2_PARSER_IPV6_ID,
	DPAA2_PARSER_IP_FRAG_ID,
	DPAA2_PARSER_GRE_ID,
	DPAA2_PARSER_UDP_ID,
	DPAA2_PARSER_TCP_ID,
	DPAA2_PARSER_SCTP_ID,
	DPAA2_PARSER_GTP_ID,
	DPAA2_PARSER_IPSEC_AH_ID,
	DPAA2_PARSER_IPSEC_ESP_ID,
	DPAA2_PARSER_VXLAN_ID,
	DPAA2_PARSER_TUNNEL_VLAN_ID,
	DPAA2_PARSER_TUNNEL_IPV4_ID,
	DPAA2_PARSER_TUNNEL_IPV6_ID,
	DPAA2_PARSER_TUNNEL_UDP_ID,
	DPAA2_PARSER_TUNNEL_TCP_ID,
	DPAA2_PARSER_ECPRI_ID,
	DPAA2_PARSER_ROCEV2_ID,
	DPAA2_PARSER_GENEVE_ID
};

#define DPAA2_PSR_SUMMARY_NONIP 6
#define DPAA2_PSR_SUMMARY_ARP 3
#define DPAA2_PSR_SUMMARY_NONIP_PTP 4
#define DPAA2_PSR_SUMMARY_MPLS 6

#define DPAA2_PSR_SUMMARY_L4_EXT 2
#define DPAA2_PSR_SUMMARY_IPV4 0
#define DPAA2_PSR_SUMMARY_IPV6 1

#define DPAA2_PSR_SUMMARY_GRE_IPV4 0
#define DPAA2_PSR_SUMMARY_GRE_IPV4_UDP_TCP 1
#define DPAA2_PSR_SUMMARY_GRE_IPV6 2
#define DPAA2_PSR_SUMMARY_GRE_IPV6_UDP_TCP 3

#define DPAA2_PSR_SUMMARY_IP_FRAG 1
#define DPAA2_PSR_SUMMARY_ICMP 3
#define DPAA2_PSR_SUMMARY_IPSEC_ESP 5
#define DPAA2_PSR_SUMMARY_TCP 14
#define DPAA2_PSR_SUMMARY_SCTP 15
#define DPAA2_PSR_SUMMARY_UDP 16
#define DPAA2_PSR_SUMMARY_PTP 18
#define DPAA2_PSR_SUMMARY_UDP_ESP_IKE 19
#define DPAA2_PSR_SUMMARY_GTPU 20
#define DPAA2_PSR_SUMMARY_GTPC 21
#define DPAA2_PSR_SUMMARY_VXLAN 27

#define DPAA2_PSR_SUMMARY_L4_BIT_SIZE 5
#define DPAA2_PSR_SUMMARY_L3_BIT_SIZE 2

#define DPAA2_PSR_SUMMARY_L4_EXT_BIT_SIZE 4
#define DPAA2_PSR_SUMMARY_L4_EXT_IP_BIT_SIZE 1
#define DPAA2_PSR_SUMMARY_L4_EXT_L3_BIT_SIZE 2
#define DPAA2_PSR_SUMMARY_L4_EXT_L3_POS \
	(DPAA2_PSR_SUMMARY_L4_EXT_BIT_SIZE + \
	DPAA2_PSR_SUMMARY_L4_EXT_IP_BIT_SIZE)

#define DPAA2_PSR_SUMMARY_NON_IP_L2_BIT_SIZE 4
#define DPAA2_PSR_SUMMARY_NON_IP_NON_IP_BIT_SIZE 3

union dpaa2_psr_summary_l {
	struct {
		uint8_t l4:DPAA2_PSR_SUMMARY_L4_BIT_SIZE;
		uint8_t l3:DPAA2_PSR_SUMMARY_L3_BIT_SIZE;
		uint8_t fafe3:1;
	} l4;
	struct {
		uint8_t l4_ext:DPAA2_PSR_SUMMARY_L4_EXT_BIT_SIZE;
		uint8_t ip:DPAA2_PSR_SUMMARY_L4_EXT_IP_BIT_SIZE;
		uint8_t l3:DPAA2_PSR_SUMMARY_L4_EXT_L3_BIT_SIZE;
		uint8_t fafe3:1;
	} l4_ext;
	struct {
		uint8_t l2:DPAA2_PSR_SUMMARY_NON_IP_L2_BIT_SIZE;
		uint8_t non_ip:DPAA2_PSR_SUMMARY_NON_IP_NON_IP_BIT_SIZE;
		uint8_t fafe3:1;
	} non_ip;
} __rte_packed;

struct dpaa2_psr_summary {
	union dpaa2_psr_summary_l sum_l;
	uint8_t vlan:2;
	uint8_t l2_l2_ext:2;
	uint8_t fafe2:1;
	uint8_t fafe1:1;
	uint8_t fafe0:1;
	uint8_t checksum_err:1;
} __rte_packed;

union dpaa2_psr_sum_16b {
	uint16_t sum_16b;
	struct dpaa2_psr_summary sum;
} __rte_packed;

struct dpaa2_ingress_frc {
	uint32_t rsv0:10;

	uint32_t faicfdv:1;
	uint32_t faswov:1;
	uint32_t faiadv:1;
	uint32_t faprv:1;
	uint32_t faeadv:1;
	uint32_t fasv:1;
	union dpaa2_psr_sum_16b psr_sum;
} __rte_packed;

/* Frame annotation status */
struct dpaa2_fas_parse {
	uint32_t status:8;
	uint32_t ppid:6;
	uint32_t rsv4:2;
	uint32_t ifpid:12;
	uint32_t rsv3:4;
	uint32_t l4ce:1;
	uint32_t l4cv:1;
	uint32_t l3ce:1;
	uint32_t l3cv:1;
	uint32_t ble:1;
	uint32_t phe:1;
	uint32_t isp:1;
	uint32_t pte:1;
	uint32_t rsv2:4;
	uint32_t fpe:1;
	uint32_t fle:1;
	uint32_t piee:1;
	uint32_t tide:1;
	uint32_t mnle:1;
	uint32_t eofhe:1;
	uint32_t kse:1;
	uint32_t rsv1:6;
	uint32_t broadcast:1;
	uint32_t multicast:1;
	uint32_t ptp:1;
	uint32_t rsv0:2;
	uint32_t macsec:1;
	uint32_t discard:1;
} __rte_packed;

union dpaa2_fas_parse_32b {
	uint32_t fas_32b;
	struct dpaa2_fas_parse fas;
} __rte_packed;

struct dpaa2_sp_fafe_ecpri {
	uint8_t msg_type:5;
	uint8_t non_used:2;
	uint8_t ecpri:1; /**Always 1, FRC FAFE0*/
} __rte_packed;

struct dpaa2_sp_fafe_rocev2_tunnel {
	uint8_t in_vlan:1;
	uint8_t in_udp:1;
	uint8_t in_tcp:1;
	uint8_t in_ipv6:1;
	uint8_t in_ipv4:1; /**FRC FAFE3*/
	uint8_t geneve:1; /**FRC FAFE2*/
	uint8_t rocev2:1; /**FRC FAFE1*/
	uint8_t non_used:1;
} __rte_packed;

union dpaa2_sp_fafe_parse {
	struct dpaa2_sp_fafe_ecpri ecpri;
	struct dpaa2_sp_fafe_rocev2_tunnel rocev2_tunnel;
	uint8_t fafe_8b;
} __rte_packed;

struct dpaa2_faf_l_parse {
	uint32_t arp_err:1;
	uint32_t arp:1;
	uint32_t mpls_err:1;
	uint32_t mpls_n:1;
	uint32_t mpls_1:1;
	uint32_t pppoe_ppp_err:1;
	uint32_t pppoe_ppp:1;
	uint32_t vlan_err:1;

	uint32_t gre_eth:1;
	uint32_t vlan_n:1;
	uint32_t vlan_1:1;
	uint32_t llc_snap_err:1;
	uint32_t unknown_llc_oui:1;
	uint32_t llc_snap:1;
	uint32_t eth_err:1;
	uint32_t fip:1;

	uint32_t fcoe:1;
	uint32_t bpdu:1;
	uint32_t broadcast:1;
	uint32_t multicast:1;
	uint32_t unicast:1;
	uint32_t mac:1;
	uint32_t psr_err:1;
	uint32_t spsr_err:1;

	uint32_t ike:1;
	uint32_t eth_slow:1;
	uint32_t vxlan_err:1;
	uint32_t vxlan:1;
	uint32_t ptp:1;
	uint32_t vlan_prio:1;
	uint32_t gtp_prim:1;
	uint32_t i6_r_hdr2:1;
} __rte_packed;

struct dpaa2_faf_l_parse_be {
	uint32_t ike:1;
	uint32_t eth_slow:1;
	uint32_t vxlan_err:1;
	uint32_t vxlan:1;
	uint32_t ptp:1;
	uint32_t vlan_prio:1;
	uint32_t gtp_prim:1;
	uint32_t i6_r_hdr2:1;

	uint32_t fcoe:1;
	uint32_t bpdu:1;
	uint32_t broadcast:1;
	uint32_t multicast:1;
	uint32_t unicast:1;
	uint32_t mac:1;
	uint32_t psr_err:1;
	uint32_t spsr_err:1;

	uint32_t gre_eth:1;
	uint32_t vlan_n:1;
	uint32_t vlan_1:1;
	uint32_t llc_snap_err:1;
	uint32_t unknown_llc_oui:1;
	uint32_t llc_snap:1;
	uint32_t eth_err:1;
	uint32_t fip:1;

	uint32_t arp_err:1;
	uint32_t arp:1;
	uint32_t mpls_err:1;
	uint32_t mpls_n:1;
	uint32_t mpls_1:1;
	uint32_t pppoe_ppp_err:1;
	uint32_t pppoe_ppp:1;
	uint32_t vlan_err:1;
} __rte_packed;

struct dpaa2_faf_h_parse {
	uint32_t i6_r_hdr1:1;
	uint32_t l5_spsr:1;
	uint32_t capwap_data:1;
	uint32_t capwap_ctl:1;
	uint32_t iscsi:1;
	uint32_t esp_err:1;
	uint32_t esp:1;
	uint32_t gtp_err:1;

	uint32_t gtp:1;
	uint32_t l4_spsr_err:1;
	uint32_t l4_unknown:1;
	uint32_t dccp_err:1;
	uint32_t dccp:1;
	uint32_t sctp_err:1;
	uint32_t sctp:1;
	uint32_t ipsec_err:1;

	uint32_t ipsec_ah:1;
	uint32_t ipsec_esp:1;
	uint32_t ipsec:1;
	uint32_t tcp_err:1;
	uint32_t tcp_3_5:1;
	uint32_t tcp_6_11:1;
	uint32_t tcp_opt:1;
	uint32_t tcp:1;

	uint32_t udp_err:1;
	uint32_t udp:1;
	uint32_t l3_spsr_err:1;
	uint32_t l3_unknown:1;
	uint32_t gre_err:1;
	uint32_t gre_k:1;
	uint32_t gre:1;
	uint32_t min_encp_err:1;

	uint32_t min_encp_s:1;
	uint32_t min_encp:1;
	uint32_t ip_n_err:1;
	uint32_t udp_light:1;
	uint32_t icmp_v6:1;
	uint32_t igmp:1;
	uint32_t icmp:1;
	uint32_t ip_n_init_frag:1;

	uint32_t ip_n_frag:1;
	uint32_t ip_n_unknown:1;
	uint32_t ip_n_opt:1;
	uint32_t ip_1_err:1;
	uint32_t ip_1_init_frag:1;
	uint32_t ip_1_frag:1;
	uint32_t ip_1_unknown:1;
	uint32_t ip_1_opt:1;

	uint32_t ipv6_n_multicast:1;
	uint32_t ipv6_n_unicast:1;
	uint32_t ipv6_n:1;
	uint32_t ipv6_1_multicast:1;
	uint32_t ipv6_1_unicast:1;
	uint32_t ipv6_1:1;
	uint32_t ipv4_n_broadcast:1;
	uint32_t ipv4_n_multicast:1;

	uint32_t ipv4_n_unicast:1;
	uint32_t ipv4_n:1;
	uint32_t ipv4_1_broadcast:1;
	uint32_t ipv4_1_multicast:1;
	uint32_t ipv4_1_unicast:1;
	uint32_t ipv4_1:1;
	uint32_t l2_spsr_err:1;
	uint32_t l2_unknown:1;
} __rte_packed;

struct dpaa2_faf_h_parse_be {
	uint32_t ipv4_n_unicast:1;
	uint32_t ipv4_n:1;
	uint32_t ipv4_1_broadcast:1;
	uint32_t ipv4_1_multicast:1;
	uint32_t ipv4_1_unicast:1;
	uint32_t ipv4_1:1;
	uint32_t l2_spsr_err:1;
	uint32_t l2_unknown:1;

	uint32_t ipv6_n_multicast:1;
	uint32_t ipv6_n_unicast:1;
	uint32_t ipv6_n:1;
	uint32_t ipv6_1_multicast:1;
	uint32_t ipv6_1_unicast:1;
	uint32_t ipv6_1:1;
	uint32_t ipv4_n_broadcast:1;
	uint32_t ipv4_n_multicast:1;

	uint32_t ip_n_frag:1;
	uint32_t ip_n_unknown:1;
	uint32_t ip_n_opt:1;
	uint32_t ip_1_err:1;
	uint32_t ip_1_init_frag:1;
	uint32_t ip_1_frag:1;
	uint32_t ip_1_unknown:1;
	uint32_t ip_1_opt:1;

	uint32_t min_encp_s:1;
	uint32_t min_encp:1;
	uint32_t ip_n_err:1;
	uint32_t udp_light:1;
	uint32_t icmp_v6:1;
	uint32_t igmp:1;
	uint32_t icmp:1;
	uint32_t ip_n_init_frag:1;

	uint32_t udp_err:1;
	uint32_t udp:1;
	uint32_t l3_spsr_err:1;
	uint32_t l3_unknown:1;
	uint32_t gre_err:1;
	uint32_t gre_k:1;
	uint32_t gre:1;
	uint32_t min_encp_err:1;

	uint32_t ipsec_ah:1;
	uint32_t ipsec_esp:1;
	uint32_t ipsec:1;
	uint32_t tcp_err:1;
	uint32_t tcp_3_5:1;
	uint32_t tcp_6_11:1;
	uint32_t tcp_opt:1;
	uint32_t tcp:1;

	uint32_t gtp:1;
	uint32_t l4_spsr_err:1;
	uint32_t l4_unknown:1;
	uint32_t dccp_err:1;
	uint32_t dccp:1;
	uint32_t sctp_err:1;
	uint32_t sctp:1;
	uint32_t ipsec_err:1;

	uint32_t i6_r_hdr1:1;
	uint32_t l5_spsr:1;
	uint32_t capwap_data:1;
	uint32_t capwap_ctl:1;
	uint32_t iscsi:1;
	uint32_t esp_err:1;
	uint32_t esp:1;
	uint32_t gtp_err:1;
} __rte_packed;

struct dpaa2_annot_word3_parse {
	struct dpaa2_faf_l_parse faf_l;
	uint8_t rsv;
	union dpaa2_sp_fafe_parse fafe;
	rte_be16_t nxthdr;
} __rte_packed;

struct dpaa2_ecpri_msg_rm_access {
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
	uint32_t ele_id:16;		/**< Element ID */
	uint32_t rr:4;			/**< Req/Resp */
	uint32_t rw:4;			/**< Read/Write */
	uint32_t rma_id:8;		/**< Remote Memory Access ID */
#elif RTE_BYTE_ORDER == RTE_BIG_ENDIAN
	uint32_t rma_id:8;		/**< Remote Memory Access ID */
	uint32_t rw:4;			/**< Read/Write */
	uint32_t rr:4;			/**< Req/Resp */
	uint32_t ele_id:16;		/**< Element ID */
#endif
} __rte_packed;

union dpaa2_sp_ecpri_msg {
	struct rte_ecpri_msg_iq_data type0;
	struct rte_ecpri_msg_bit_seq type1;
	struct rte_ecpri_msg_rtc_ctrl type2;
	struct rte_ecpri_msg_bit_seq type3;
	struct dpaa2_ecpri_msg_rm_access type4;
	struct rte_ecpri_msg_delay_measure type5;
	struct rte_ecpri_msg_remote_reset type6;
	struct rte_ecpri_msg_event_ind type7;
} __rte_packed;

#define DPAA2_SP_PSR_CTX_LEN 5

struct dpaa2_sp_rocev2 {
	uint8_t opcode;
	uint8_t dest_qp[ROCEV2_DEST_QP_SIZE];
} __rte_packed;

struct dpaa2_sp_geneve {
	rte_be16_t protocol;
	uint8_t geneve_vni[3];
} __rte_packed;

struct dpaa2_psr_result_word3 {
	rte_be16_t nxthdr;
	union dpaa2_sp_fafe_parse fafe;
	uint8_t rsv;
	struct dpaa2_faf_l_parse_be faf_l_be;
};

struct dpaa2_psr_result_word4 {
	struct dpaa2_faf_h_parse_be faf_h_be;
};

struct dpaa2_psr_result_word5 {
	union {
		struct {
			uint8_t shim_off1;
			uint8_t shim_off2;
		};
		rte_be16_t vxlan_vlan_tci;
	};
	uint8_t ip_1_pid_off;
	uint8_t eth_off;
	union {
		uint8_t llc_snap_off;
		uint8_t vxlan_in_daddr0;
	};
	uint8_t vlan_tci_1_off;
	union {
		uint8_t vlan_tci_n_off;
		uint8_t vxlan_in_daddr1;
	};
	uint8_t last_etype_off;
};

struct dpaa2_psr_result_word6 {
	union {
		uint8_t pppoe_off;
		uint8_t vxlan_in_daddr2;
	};
	union {
		uint8_t mpls_1_off;
		uint8_t vxlan_in_daddr3;
	};
	union {
		uint8_t mpls_n_off;
		uint8_t vxlan_in_daddr4;
	};
	uint8_t l3_off;
	union {
		uint8_t ip_n_off;
		uint8_t vxlan_in_daddr5;
	};
	union {
		uint8_t gre_off;
		uint8_t vxlan_in_saddr0;
	};
	uint8_t l4_off;
	uint8_t l5_off;
};

struct dpaa2_psr_result_word7 {
	union {
		uint8_t route_hdr1_off;
		uint8_t vxlan_in_saddr1;
	};
	union {
		uint8_t route_hdr2_off;
		uint8_t vxlan_in_saddr2;
	};
	uint8_t nxthdr_off;
	union {
		uint8_t ipv6_frag_off;
		uint8_t vxlan_in_saddr3;
	};
	rte_be16_t gross_running_sum;
	rte_be16_t running_sum;
};

struct dpaa2_psr_result_word8 {
	uint8_t psr_err;
	union {
		uint8_t nxthdr_frag_off;
		uint8_t vxlan_in_saddr4;
	};
	union {
		uint8_t ip_n_pid_off;
		uint8_t vxlan_in_saddr5;
	};
	union {
		uint8_t sp_psr_ctx[DPAA2_SP_PSR_CTX_LEN];
		struct {
			uint8_t vxlan_vni[3];
			rte_be16_t vxlan_eth_type;
		} __rte_packed;
		union dpaa2_sp_ecpri_msg ecpri_msg;
		struct dpaa2_sp_rocev2 rocev2;
		struct dpaa2_sp_geneve geneve;
	} __rte_packed;
};

struct dpaa2_psr_result_parse {
	struct dpaa2_psr_result_word3 word3;
	struct dpaa2_psr_result_word4 word4;
	struct dpaa2_psr_result_word5 word5;
	struct dpaa2_psr_result_word6 word6;
	struct dpaa2_psr_result_word7 word7;
	struct dpaa2_psr_result_word8 word8;
} __rte_packed;

#define DPAA2_PSR_RESULT_SIZE sizeof(struct dpaa2_psr_result_parse)

#define DPAA2_FAFE_PSR_RESULT_OFFSET \
	offsetof(struct dpaa2_psr_result_parse, word3.fafe)

union dpaa2_sp_fafe_parse_8b {
	uint8_t fafe_8b;
	union dpaa2_sp_fafe_parse fafe;
} __rte_packed;

union dpaa2_faf_l_parse_32b {
	uint32_t faf_l_32b;
	struct dpaa2_faf_l_parse faf_l;
} __rte_packed;

union dpaa2_faf_h_parse_64b {
	uint64_t faf_h_64b;
	struct dpaa2_faf_h_parse faf_h;
} __rte_packed;

/* Set by SP for vxlan distribution start*/
#define DPAA2_VXLAN_IN_TCI_OFFSET \
	offsetof(struct dpaa2_psr_result_parse, word5.vxlan_vlan_tci)
#define DPAA2_VXLAN_IN_DADDR0_OFFSET \
	offsetof(struct dpaa2_psr_result_parse, word5.vxlan_in_daddr0)
#define DPAA2_VXLAN_IN_DADDR1_OFFSET \
	offsetof(struct dpaa2_psr_result_parse, word5.vxlan_in_daddr1)
#define DPAA2_VXLAN_IN_DADDR2_OFFSET \
	offsetof(struct dpaa2_psr_result_parse, word6.vxlan_in_daddr2)
#define DPAA2_VXLAN_IN_DADDR3_OFFSET \
	offsetof(struct dpaa2_psr_result_parse, word6.vxlan_in_daddr3)
#define DPAA2_VXLAN_IN_DADDR4_OFFSET \
	offsetof(struct dpaa2_psr_result_parse, word6.vxlan_in_daddr4)
#define DPAA2_VXLAN_IN_DADDR5_OFFSET \
	offsetof(struct dpaa2_psr_result_parse, word6.vxlan_in_daddr5)

#define DPAA2_VXLAN_IN_SADDR0_OFFSET \
	offsetof(struct dpaa2_psr_result_parse, word6.vxlan_in_saddr0)
#define DPAA2_VXLAN_IN_SADDR1_OFFSET \
	offsetof(struct dpaa2_psr_result_parse, word7.vxlan_in_saddr1)
#define DPAA2_VXLAN_IN_SADDR2_OFFSET \
	offsetof(struct dpaa2_psr_result_parse, word7.vxlan_in_saddr2)
#define DPAA2_VXLAN_IN_SADDR3_OFFSET \
	offsetof(struct dpaa2_psr_result_parse, word7.vxlan_in_saddr3)
#define DPAA2_VXLAN_IN_SADDR4_OFFSET \
	offsetof(struct dpaa2_psr_result_parse, word8.vxlan_in_saddr4)
#define DPAA2_VXLAN_IN_SADDR5_OFFSET \
	offsetof(struct dpaa2_psr_result_parse, word8.vxlan_in_saddr5)

#define DPAA2_VXLAN_VNI_OFFSET \
	offsetof(struct dpaa2_psr_result_parse, word8.vxlan_vni[0])
#define DPAA2_VXLAN_IN_TYPE_OFFSET \
	offsetof(struct dpaa2_psr_result_parse, word8.vxlan_eth_type)
/* Set by SP for vxlan distribution end*/

#define DPAA2_ECPRI_MSG_OFFSET \
	offsetof(struct dpaa2_psr_result_parse, word8.ecpri_msg)

#define DPAA2_ROCEV2_OPCODE_OFFSET \
	offsetof(struct dpaa2_psr_result_parse, word8.rocev2.opcode)

#define DPAA2_ROCEV2_DST_QP_OFFSET \
	offsetof(struct dpaa2_psr_result_parse, word8.rocev2.dest_qp[0])

#define DPAA2_GENEVE_PROTOCOL_OFFSET \
	offsetof(struct dpaa2_psr_result_parse, word8.geneve.protocol)

#define DPAA2_GENEVE_VNI_OFFSET \
	offsetof(struct dpaa2_psr_result_parse, word8.geneve.geneve_vni[0])

static inline uint32_t
dpaa2_spsr_fafe_bit_offset(union dpaa2_sp_fafe_parse fafe)
{
	union dpaa2_sp_fafe_parse_8b fafe_tmp;
	uint32_t offset = BIT_LAST_OFFSET(union dpaa2_sp_fafe_parse_8b);

	memset(&fafe_tmp, 0, sizeof(union dpaa2_sp_fafe_parse_8b));
	fafe_tmp.fafe_8b = 1;
	while (memcmp(&fafe_tmp.fafe, &fafe,
		sizeof(union dpaa2_sp_fafe_parse))) {
		fafe_tmp.fafe_8b = fafe_tmp.fafe_8b << 1;
		offset--;
	}
	return offset + BIT_OFFSET(struct dpaa2_psr_result_parse, word3.fafe);
}

static inline uint32_t
dpaa2_psr_faf_l_bit_offset(struct dpaa2_faf_l_parse *faf_l)
{
	union dpaa2_faf_l_parse_32b faf_l_tmp;
	uint32_t offset = BIT_LAST_OFFSET(union dpaa2_faf_l_parse_32b);

	memset(&faf_l_tmp, 0, sizeof(union dpaa2_faf_l_parse_32b));
	faf_l_tmp.faf_l_32b = 1;
	while (memcmp(&faf_l_tmp.faf_l, faf_l,
		sizeof(struct dpaa2_faf_l_parse))) {
		faf_l_tmp.faf_l_32b = faf_l_tmp.faf_l_32b << 1;
		offset--;
	}
	return offset + BIT_OFFSET(struct dpaa2_psr_result_parse,
		word3.faf_l_be);
}

static inline uint32_t
dpaa2_psr_faf_h_bit_offset(struct dpaa2_faf_h_parse *faf_h)
{
	union dpaa2_faf_h_parse_64b faf_h_tmp;
	uint32_t offset = BIT_LAST_OFFSET(union dpaa2_faf_h_parse_64b);

	memset(&faf_h_tmp, 0, sizeof(union dpaa2_faf_h_parse_64b));
	faf_h_tmp.faf_h_64b = 1;
	while (memcmp(&faf_h_tmp.faf_h, faf_h,
		sizeof(struct dpaa2_faf_h_parse))) {
		faf_h_tmp.faf_h_64b = faf_h_tmp.faf_h_64b << 1;
		offset--;
	}
	return offset + BIT_OFFSET(struct dpaa2_psr_result_parse,
		word4.faf_h_be);
}

static inline int
dpaa2_protocol_psr_bit_offset(uint32_t *bit_offset,
	enum dpaa2_parser_protocol_id protocol)
{
	struct dpaa2_faf_l_parse faf_l;
	struct dpaa2_faf_h_parse faf_h;
	union dpaa2_sp_fafe_parse fafe;

	memset(&faf_l, 0, sizeof(faf_l));
	memset(&faf_h, 0, sizeof(faf_h));
	memset(&fafe, 0, sizeof(fafe));

	if (protocol == DPAA2_PARSER_MAC_ID) {
		faf_l.mac = 1;
		*bit_offset = dpaa2_psr_faf_l_bit_offset(&faf_l);
	} else if (protocol == DPAA2_PARSER_VLAN_ID) {
		faf_l.vlan_1 = 1;
		*bit_offset = dpaa2_psr_faf_l_bit_offset(&faf_l);
	} else if (protocol == DPAA2_PARSER_ICMP_ID) {
		faf_h.icmp = 1;
		*bit_offset = dpaa2_psr_faf_h_bit_offset(&faf_h);
	} else if (protocol == DPAA2_PARSER_IP_ID) {
		faf_h.ip_1_opt = 1;
		*bit_offset = dpaa2_psr_faf_h_bit_offset(&faf_h);
	} else if (protocol == DPAA2_PARSER_IPV4_ID) {
		faf_h.ipv4_1 = 1;
		*bit_offset = dpaa2_psr_faf_h_bit_offset(&faf_h);
	} else if (protocol == DPAA2_PARSER_IP_FRAG_ID) {
		faf_h.ip_1_frag = 1;
		*bit_offset = dpaa2_psr_faf_h_bit_offset(&faf_h);
	} else if (protocol == DPAA2_PARSER_IPV6_ID) {
		faf_h.ipv6_1 = 1;
		*bit_offset = dpaa2_psr_faf_h_bit_offset(&faf_h);
	} else if (protocol == DPAA2_PARSER_GRE_ID) {
		faf_h.gre = 1;
		*bit_offset = dpaa2_psr_faf_h_bit_offset(&faf_h);
	} else if (protocol == DPAA2_PARSER_UDP_ID) {
		faf_h.udp = 1;
		*bit_offset = dpaa2_psr_faf_h_bit_offset(&faf_h);
	} else if (protocol == DPAA2_PARSER_TCP_ID) {
		faf_h.tcp = 1;
		*bit_offset = dpaa2_psr_faf_h_bit_offset(&faf_h);
	} else if (protocol == DPAA2_PARSER_SCTP_ID) {
		faf_h.sctp = 1;
		*bit_offset = dpaa2_psr_faf_h_bit_offset(&faf_h);
	} else if (protocol == DPAA2_PARSER_GTP_ID) {
		faf_h.gtp = 1;
		*bit_offset = dpaa2_psr_faf_h_bit_offset(&faf_h);
	} else if (protocol == DPAA2_PARSER_IPSEC_ESP_ID) {
		faf_h.ipsec_esp = 1;
		*bit_offset = dpaa2_psr_faf_h_bit_offset(&faf_h);
	} else if (protocol == DPAA2_PARSER_IPSEC_AH_ID) {
		faf_h.ipsec_ah = 1;
		*bit_offset = dpaa2_psr_faf_h_bit_offset(&faf_h);
	} else if (protocol == DPAA2_PARSER_VXLAN_ID) {
		faf_l.vxlan = 1;
		*bit_offset = dpaa2_psr_faf_l_bit_offset(&faf_l);
	} else if (protocol == DPAA2_PARSER_TUNNEL_VLAN_ID) {
		fafe.rocev2_tunnel.in_vlan = 1;
		*bit_offset = dpaa2_spsr_fafe_bit_offset(fafe);
	} else if (protocol == DPAA2_PARSER_TUNNEL_IPV4_ID) {
		fafe.rocev2_tunnel.in_ipv4 = 1;
		*bit_offset = dpaa2_spsr_fafe_bit_offset(fafe);
	} else if (protocol == DPAA2_PARSER_TUNNEL_IPV6_ID) {
		fafe.rocev2_tunnel.in_ipv6 = 1;
		*bit_offset = dpaa2_spsr_fafe_bit_offset(fafe);
	} else if (protocol == DPAA2_PARSER_TUNNEL_UDP_ID) {
		fafe.rocev2_tunnel.in_udp = 1;
		*bit_offset = dpaa2_spsr_fafe_bit_offset(fafe);
	} else if (protocol == DPAA2_PARSER_TUNNEL_TCP_ID) {
		fafe.rocev2_tunnel.in_tcp = 1;
		*bit_offset = dpaa2_spsr_fafe_bit_offset(fafe);
	} else if (protocol == DPAA2_PARSER_ECPRI_ID) {
		fafe.ecpri.ecpri = 1;
		*bit_offset = dpaa2_spsr_fafe_bit_offset(fafe);
	} else if (protocol == DPAA2_PARSER_ROCEV2_ID) {
		fafe.rocev2_tunnel.rocev2 = 1;
		*bit_offset = dpaa2_spsr_fafe_bit_offset(fafe);
	} else if (protocol == DPAA2_PARSER_GENEVE_ID) {
		fafe.rocev2_tunnel.geneve = 1;
		*bit_offset = dpaa2_spsr_fafe_bit_offset(fafe);
	} else {
		DPAA2_PMD_ERR("Unsupported parser protocol(%d)", protocol);
		return -ENOTSUP;
	}

	return 0;
}

#define ECPRI(type) (void)(type)
#define ROCEv2(type) (void)(type)

static inline uint32_t __attribute__((hot))
dpaa2_dev_rx_parse_frc(const struct qbman_fd *fd,
	struct rte_mbuf *m,
	const struct dpaa2_annot_hdr *annotation)
{
	const struct dpaa2_ingress_frc *frc = (const void *)&fd->simple.frc;
	const struct dpaa2_psr_summary *sum = &frc->psr_sum.sum;
	const union dpaa2_psr_summary_l *sum_l = &sum->sum_l;
	int ip4_6 = 0, vxlan = 0;
	struct dpaa2_annot_hdr annot_convert;
	const struct dpaa2_psr_result_parse *psr;
	const struct dpaa2_fas_parse *fas;
	uint32_t packet_type = RTE_PTYPE_L4_NONFRAG;
	uint8_t vlan_offset;
	rte_be16_t *vlan_tci;

	/**Access annotation only for vlan and checksum error.*/

	if (sum->vlan) {
		annot_convert.word5 = annotation->word5;
		annot_convert.word5 = rte_cpu_to_be_64(annot_convert.word5);
		psr = (const void *)&annot_convert.word3;
		packet_type |= RTE_PTYPE_L2_ETHER_VLAN;
		m->ol_flags |= RTE_MBUF_F_RX_VLAN;
		if (sum->vlan > 1) {
			vlan_offset = psr->word5.vlan_tci_n_off;
			packet_type |= RTE_PTYPE_L2_ETHER_QINQ;
			m->ol_flags |= RTE_MBUF_F_RX_QINQ;
		} else {
			vlan_offset = psr->word5.vlan_tci_1_off;
		}
		vlan_tci = rte_pktmbuf_mtod_offset(m, void *, vlan_offset);
		m->vlan_tci = rte_be_to_cpu_16(*vlan_tci);
	}
	if (sum_l->l4.l3 == DPAA2_PSR_SUMMARY_IPV4) {
		packet_type |= RTE_PTYPE_L3_IPV4;
		ip4_6 = 1;
	} else if (sum_l->l4.l3 == DPAA2_PSR_SUMMARY_IPV6) {
		packet_type |= RTE_PTYPE_L3_IPV6;
		ip4_6 = 1;
	}

	if (ip4_6) {
		if (sum_l->l4.l4 == DPAA2_PSR_SUMMARY_IP_FRAG) {
			packet_type &= ~RTE_PTYPE_L4_NONFRAG;
			packet_type |= RTE_PTYPE_L4_FRAG;
		} else if (sum_l->l4.l4 == DPAA2_PSR_SUMMARY_ICMP) {
			packet_type |= RTE_PTYPE_L4_ICMP;
		} else if (sum_l->l4.l4 == DPAA2_PSR_SUMMARY_IPSEC_ESP) {
			packet_type |= RTE_PTYPE_TUNNEL_ESP;
		} else if (sum_l->l4.l4 == DPAA2_PSR_SUMMARY_TCP) {
			packet_type |= RTE_PTYPE_L4_TCP;
		} else if (sum_l->l4.l4 == DPAA2_PSR_SUMMARY_UDP) {
			packet_type |= RTE_PTYPE_L4_UDP;
		} else if (sum_l->l4.l4 == DPAA2_PSR_SUMMARY_SCTP) {
			packet_type |= RTE_PTYPE_L4_SCTP;
		} else if (sum_l->l4.l4 == DPAA2_PSR_SUMMARY_GTPU) {
			packet_type |= RTE_PTYPE_TUNNEL_GTPU;
		} else if (sum_l->l4.l4 == DPAA2_PSR_SUMMARY_GTPC) {
			packet_type |= RTE_PTYPE_TUNNEL_GTPC;
		} else if (sum_l->l4.l4 == DPAA2_PSR_SUMMARY_VXLAN) {
			packet_type |= RTE_PTYPE_TUNNEL_VXLAN;
			vxlan = 1;
		}
	} else if (sum_l->l4_ext.l3 == DPAA2_PSR_SUMMARY_L4_EXT) {
		if (sum_l->l4_ext.ip == DPAA2_PSR_SUMMARY_IPV4)
			packet_type |= RTE_PTYPE_L3_IPV4;
		else if (sum_l->l4_ext.ip == DPAA2_PSR_SUMMARY_IPV6)
			packet_type |= RTE_PTYPE_L3_IPV6;
		if (sum_l->l4_ext.l4_ext == DPAA2_PSR_SUMMARY_GRE_IPV4 ||
			sum_l->l4_ext.l4_ext == DPAA2_PSR_SUMMARY_GRE_IPV6)
			packet_type |= RTE_PTYPE_TUNNEL_GRE;
		else if (sum_l->l4_ext.l4_ext ==
			DPAA2_PSR_SUMMARY_GRE_IPV4_UDP_TCP ||
			sum_l->l4_ext.l4_ext ==
			DPAA2_PSR_SUMMARY_GRE_IPV6_UDP_TCP)
			packet_type |= RTE_PTYPE_TUNNEL_NVGRE;
	} else if (sum_l->non_ip.non_ip == DPAA2_PSR_SUMMARY_NONIP) {
		if (sum_l->non_ip.l2 == DPAA2_PSR_SUMMARY_ARP) {
			packet_type |= RTE_PTYPE_L2_ETHER_ARP;
		} else if (sum_l->non_ip.l2 == DPAA2_PSR_SUMMARY_NONIP_PTP) {
			packet_type |= RTE_PTYPE_L2_ETHER_TIMESYNC;
			m->ol_flags |= RTE_MBUF_F_RX_IEEE1588_PTP;
		} else if (sum_l->non_ip.l2 == DPAA2_PSR_SUMMARY_MPLS) {
			packet_type |= RTE_PTYPE_L2_ETHER_MPLS;
		}
	}

	if (unlikely(sum->checksum_err)) {
		fas = (const void *)&annotation->word1;
		if (fas->l3ce)
			m->ol_flags |= RTE_MBUF_F_RX_IP_CKSUM_BAD;
		if (fas->l4ce)
			m->ol_flags |= RTE_MBUF_F_RX_L4_CKSUM_BAD;
	}

	if (sum->fafe0) {
		ECPRI(packet_type);
	} else if (sum->fafe1) {
		ROCEv2(packet_type);
	} else if (vxlan && sum->fafe2) {
		packet_type |= RTE_PTYPE_INNER_L2_ETHER;
		packet_type |= RTE_PTYPE_INNER_L3_IPV4;
	} else if (vxlan && sum_l->l4.fafe3) {
		packet_type |= RTE_PTYPE_INNER_L2_ETHER;
		packet_type |= RTE_PTYPE_INNER_L3_IPV6;
	}

	return packet_type;
}

static inline int
dpaa2_parser_ecpri_extract(const struct rte_flow_item_ecpri *spec,
	const struct rte_flow_item_ecpri *mask,
	uint64_t rule_data[], uint64_t mask_data[],
	uint8_t extract_size[], uint8_t extract_off[],
	union dpaa2_sp_fafe_parse *fafe)
{
	int extract_nb = 0;

	if (mask->hdr.common.type != 0xff) {
		DPAA2_PR_PRINT("ECPRI header type not specified.");

		return -EINVAL;
	}

	if (spec->hdr.common.type > RTE_ECPRI_MSG_TYPE_IWF_DCTRL) {
		DPAA2_PR_PRINT("ECPRI header type(%d) not supported.",
			spec->hdr.common.type);

		return -ENOTSUP;
	}

	/** Extract eCPRI type from FAFE.*/
	fafe->ecpri.ecpri = 1;
	fafe->ecpri.msg_type = spec->hdr.common.type;
	rule_data[extract_nb] = fafe->fafe_8b;
	mask_data[extract_nb] = 0xff;
	extract_size[extract_nb] = sizeof(uint8_t);
	extract_off[extract_nb] = DPAA2_FAFE_PSR_RESULT_OFFSET;
	extract_nb++;

	if (spec->hdr.common.type == RTE_ECPRI_MSG_TYPE_IQ_DATA) {
		if (mask->hdr.type0.pc_id) {
			rule_data[extract_nb] = spec->hdr.type0.pc_id;
			mask_data[extract_nb] = mask->hdr.type0.pc_id;
			extract_size[extract_nb] = sizeof(rte_be16_t);
			extract_off[extract_nb] =
				DPAA2_ECPRI_MSG_OFFSET +
				offsetof(struct rte_ecpri_msg_iq_data, pc_id);
			extract_nb++;
		}
		if (mask->hdr.type0.seq_id) {
			rule_data[extract_nb] = spec->hdr.type0.seq_id;
			mask_data[extract_nb] = mask->hdr.type0.seq_id;
			extract_size[extract_nb] = sizeof(rte_be16_t);
			extract_off[extract_nb] =
				DPAA2_ECPRI_MSG_OFFSET +
				offsetof(struct rte_ecpri_msg_iq_data, seq_id);
			extract_nb++;
		}
	} else if (spec->hdr.common.type == RTE_ECPRI_MSG_TYPE_BIT_SEQ) {
		if (mask->hdr.type1.pc_id) {
			rule_data[extract_nb] = spec->hdr.type1.pc_id;
			mask_data[extract_nb] = mask->hdr.type1.pc_id;
			extract_size[extract_nb] = sizeof(rte_be16_t);
			extract_off[extract_nb] =
				DPAA2_ECPRI_MSG_OFFSET +
				offsetof(struct rte_ecpri_msg_bit_seq, pc_id);
			extract_nb++;
		}
		if (mask->hdr.type1.seq_id) {
			rule_data[extract_nb] = spec->hdr.type1.seq_id;
			mask_data[extract_nb] = mask->hdr.type1.seq_id;
			extract_size[extract_nb] = sizeof(rte_be16_t);
			extract_off[extract_nb] =
				DPAA2_ECPRI_MSG_OFFSET +
				offsetof(struct rte_ecpri_msg_bit_seq, seq_id);
			extract_nb++;
		}
	} else if (spec->hdr.common.type == RTE_ECPRI_MSG_TYPE_RTC_CTRL) {
		if (mask->hdr.type2.rtc_id) {
			rule_data[extract_nb] = spec->hdr.type2.rtc_id;
			mask_data[extract_nb] = mask->hdr.type2.rtc_id;
			extract_size[extract_nb] = sizeof(rte_be16_t);
			extract_off[extract_nb] =
				DPAA2_ECPRI_MSG_OFFSET +
				offsetof(struct rte_ecpri_msg_rtc_ctrl, rtc_id);
			extract_nb++;
		}
		if (mask->hdr.type2.seq_id) {
			rule_data[extract_nb] = spec->hdr.type2.seq_id;
			mask_data[extract_nb] = mask->hdr.type2.seq_id;
			extract_size[extract_nb] = sizeof(rte_be16_t);
			extract_off[extract_nb] =
				DPAA2_ECPRI_MSG_OFFSET +
				offsetof(struct rte_ecpri_msg_rtc_ctrl, seq_id);
			extract_nb++;
		}
	} else if (spec->hdr.common.type == RTE_ECPRI_MSG_TYPE_GEN_DATA) {
		if (mask->hdr.type3.pc_id || mask->hdr.type3.seq_id)
			DPAA2_PMD_WARN("Extract type3 msg not support.");
	} else if (spec->hdr.common.type == RTE_ECPRI_MSG_TYPE_RM_ACC) {
		if (mask->hdr.type4.rma_id) {
			rule_data[extract_nb] = spec->hdr.type4.rma_id;
			mask_data[extract_nb] = mask->hdr.type4.rma_id;
			extract_size[extract_nb] = sizeof(uint8_t);
			extract_off[extract_nb] =
				DPAA2_ECPRI_MSG_OFFSET + 0;
				/** Compiler not support to take address
				 * of bit-field
				 * offsetof(struct rte_ecpri_msg_rm_access,
				 * rma_id);
				 */
			extract_nb++;
		}
		if (mask->hdr.type4.ele_id) {
			rule_data[extract_nb] = spec->hdr.type4.ele_id;
			mask_data[extract_nb] = mask->hdr.type4.ele_id;
			extract_size[extract_nb] = sizeof(rte_be16_t);
			extract_off[extract_nb] =
				DPAA2_ECPRI_MSG_OFFSET + 2;
				/** Compiler not support to take address
				 * of bit-field
				 * offsetof(struct rte_ecpri_msg_rm_access,
				 * ele_id);
				 */
			extract_nb++;
		}
	} else if (spec->hdr.common.type == RTE_ECPRI_MSG_TYPE_DLY_MSR) {
		if (mask->hdr.type5.msr_id) {
			rule_data[extract_nb] = spec->hdr.type5.msr_id;
			mask_data[extract_nb] = mask->hdr.type5.msr_id;
			extract_size[extract_nb] = sizeof(uint8_t);
			extract_off[extract_nb] =
				DPAA2_ECPRI_MSG_OFFSET +
				offsetof(struct rte_ecpri_msg_delay_measure,
					msr_id);
			extract_nb++;
		}
		if (mask->hdr.type5.act_type) {
			rule_data[extract_nb] = spec->hdr.type5.act_type;
			mask_data[extract_nb] = mask->hdr.type5.act_type;
			extract_size[extract_nb] = sizeof(uint8_t);
			extract_off[extract_nb] =
				DPAA2_ECPRI_MSG_OFFSET +
				offsetof(struct rte_ecpri_msg_delay_measure,
					act_type);
			extract_nb++;
		}
	} else if (spec->hdr.common.type == RTE_ECPRI_MSG_TYPE_RMT_RST) {
		if (mask->hdr.type6.rst_id) {
			rule_data[extract_nb] = spec->hdr.type6.rst_id;
			mask_data[extract_nb] = mask->hdr.type6.rst_id;
			extract_size[extract_nb] = sizeof(rte_be16_t);
			extract_off[extract_nb] =
				DPAA2_ECPRI_MSG_OFFSET +
				offsetof(struct rte_ecpri_msg_remote_reset,
					rst_id);
			extract_nb++;
		}
		if (mask->hdr.type6.rst_op) {
			rule_data[extract_nb] = spec->hdr.type6.rst_op;
			mask_data[extract_nb] = mask->hdr.type6.rst_op;
			extract_size[extract_nb] = sizeof(uint8_t);
			extract_off[extract_nb] =
				DPAA2_ECPRI_MSG_OFFSET +
				offsetof(struct rte_ecpri_msg_remote_reset,
					rst_op);
			extract_nb++;
		}
	} else if (spec->hdr.common.type == RTE_ECPRI_MSG_TYPE_EVT_IND) {
		if (mask->hdr.type7.evt_id) {
			rule_data[extract_nb] = spec->hdr.type7.evt_id;
			mask_data[extract_nb] = mask->hdr.type7.evt_id;
			extract_size[extract_nb] = sizeof(uint8_t);
			extract_off[extract_nb] =
				DPAA2_ECPRI_MSG_OFFSET +
				offsetof(struct rte_ecpri_msg_event_ind,
					evt_id);
			extract_nb++;
		}
		if (mask->hdr.type7.evt_type) {
			rule_data[extract_nb] = spec->hdr.type7.evt_type;
			mask_data[extract_nb] = mask->hdr.type7.evt_type;
			extract_size[extract_nb] = sizeof(uint8_t);
			extract_off[extract_nb] =
				DPAA2_ECPRI_MSG_OFFSET +
				offsetof(struct rte_ecpri_msg_event_ind,
					evt_type);
			extract_nb++;
		}
		if (mask->hdr.type7.seq) {
			rule_data[extract_nb] = spec->hdr.type7.seq;
			mask_data[extract_nb] = mask->hdr.type7.seq;
			extract_size[extract_nb] = sizeof(uint8_t);
			extract_off[extract_nb] =
				DPAA2_ECPRI_MSG_OFFSET +
				offsetof(struct rte_ecpri_msg_event_ind,
					seq);
			extract_nb++;
		}
		if (mask->hdr.type7.number) {
			rule_data[extract_nb] = spec->hdr.type7.number;
			mask_data[extract_nb] = mask->hdr.type7.number;
			extract_size[extract_nb] = sizeof(uint8_t);
			extract_off[extract_nb] =
				DPAA2_ECPRI_MSG_OFFSET +
				offsetof(struct rte_ecpri_msg_event_ind,
					number);
			extract_nb++;
		}
	} else {
		DPAA2_PR_PRINT("Unsupported ecpri header type(%d)",
			spec->hdr.common.type);
		return -ENOTSUP;
	}

	return extract_nb;
}

static inline void
dpaa2_print_rocev2_parse_result(const struct dpaa2_psr_result_parse *psr)
{
	int i;

	DPAA2_PR_PRINT("ROCEv2 opcode: 0x%02x\r\n", psr->word8.rocev2.opcode);
	DPAA2_PR_PRINT("ROCEv2 qp: ");
	for (i = 0; i < ROCEV2_DEST_QP_SIZE; i++)
		DPAA2_PR_PRINT("0x%02x ", psr->word8.rocev2.dest_qp[i]);

	DPAA2_PR_PRINT("\r\n");
}

static inline void
dpaa2_print_geneve_parse_result(const struct dpaa2_psr_result_parse *psr)
{
	DPAA2_PR_PRINT("GENEVE protocol: 0x%04x\r\n",
		rte_be_to_cpu_16(psr->word8.geneve.protocol));
	DPAA2_PR_PRINT("GENEVE vni: %02x %02x %02x\r\n",
		psr->word8.geneve.geneve_vni[0],
		psr->word8.geneve.geneve_vni[1],
		psr->word8.geneve.geneve_vni[2]);
}

static inline void
dpaa2_print_vxlan_parse_result(const struct dpaa2_psr_result_parse *psr)
{
	struct rte_ether_hdr vxlan_in_eth;
	uint16_t vxlan_vlan_tci, i;

	vxlan_in_eth.dst_addr.addr_bytes[0] = psr->word5.vxlan_in_daddr0;
	vxlan_in_eth.dst_addr.addr_bytes[1] = psr->word5.vxlan_in_daddr1;
	vxlan_in_eth.dst_addr.addr_bytes[2] = psr->word6.vxlan_in_daddr2;
	vxlan_in_eth.dst_addr.addr_bytes[3] = psr->word6.vxlan_in_daddr3;
	vxlan_in_eth.dst_addr.addr_bytes[4] = psr->word6.vxlan_in_daddr4;
	vxlan_in_eth.dst_addr.addr_bytes[5] = psr->word6.vxlan_in_daddr5;

	vxlan_in_eth.src_addr.addr_bytes[0] = psr->word6.vxlan_in_saddr0;
	vxlan_in_eth.src_addr.addr_bytes[1] = psr->word7.vxlan_in_saddr1;
	vxlan_in_eth.src_addr.addr_bytes[2] = psr->word7.vxlan_in_saddr2;
	vxlan_in_eth.src_addr.addr_bytes[3] = psr->word7.vxlan_in_saddr3;
	vxlan_in_eth.src_addr.addr_bytes[4] = psr->word8.vxlan_in_saddr4;
	vxlan_in_eth.src_addr.addr_bytes[5] = psr->word8.vxlan_in_saddr5;

	vxlan_in_eth.ether_type = psr->word8.vxlan_eth_type;
	vxlan_in_eth.ether_type = rte_be_to_cpu_16(vxlan_in_eth.ether_type);

	DPAA2_PR_PRINT("VXLAN inner eth:\r\n");
	DPAA2_PR_PRINT("dst addr: ");
	for (i = 0; i < RTE_ETHER_ADDR_LEN; i++) {
		if (i != 0)
			DPAA2_PR_PRINT(":");
		DPAA2_PR_PRINT("%02x", vxlan_in_eth.dst_addr.addr_bytes[i]);
	}
	DPAA2_PR_PRINT("\r\n");
	DPAA2_PR_PRINT("src addr: ");
	for (i = 0; i < RTE_ETHER_ADDR_LEN; i++) {
		if (i != 0)
			DPAA2_PR_PRINT(":");
		DPAA2_PR_PRINT("%02x", vxlan_in_eth.src_addr.addr_bytes[i]);
	}
	DPAA2_PR_PRINT("\r\n");
	DPAA2_PR_PRINT("type: 0x%04x\r\n", vxlan_in_eth.ether_type);
	if (vxlan_in_eth.ether_type == RTE_ETHER_TYPE_VLAN) {
		rte_memcpy(&vxlan_vlan_tci,
			&psr->word5.vxlan_vlan_tci, sizeof(uint16_t));
		vxlan_vlan_tci = rte_be_to_cpu_16(vxlan_vlan_tci);
		DPAA2_PR_PRINT("vlan tci: 0x%04x\r\n", vxlan_vlan_tci);
	}
}

static inline void
dpaa2_print_ecpri_parse_result(const struct dpaa2_psr_result_parse *psr)
{
	uint8_t msg_type;
	struct rte_ecpri_combined_msg_hdr ecpri_msg;

	msg_type = psr->word3.fafe.ecpri.msg_type;
	if (msg_type > RTE_ECPRI_MSG_TYPE_IWF_DCTRL) {
		DPAA2_PR_PRINT("Invalid ECPRI message type(0x%02x)\r\n",
			msg_type);
		return;
	}

	DPAA2_PR_PRINT("ECPRI type %d present\r\n", msg_type);
	rte_memcpy(ecpri_msg.dummy, psr->word8.sp_psr_ctx,
		DPAA2_SP_PSR_CTX_LEN);
	if (msg_type == RTE_ECPRI_MSG_TYPE_IQ_DATA ||
		msg_type == RTE_ECPRI_MSG_TYPE_BIT_SEQ) {
		DPAA2_PR_PRINT("pc_id(0x%04x) seq_id(0x%04x)\r\n",
			rte_be_to_cpu_16(ecpri_msg.type0.pc_id),
			rte_be_to_cpu_16(ecpri_msg.type0.seq_id));
	} else if (msg_type == RTE_ECPRI_MSG_TYPE_RTC_CTRL) {
		DPAA2_PR_PRINT("rtc_id(0x%04x) seq_id(0x%04x)\r\n",
			rte_be_to_cpu_16(ecpri_msg.type2.rtc_id),
			rte_be_to_cpu_16(ecpri_msg.type2.seq_id));
	} else if (msg_type == RTE_ECPRI_MSG_TYPE_GEN_DATA) {
		DPAA2_PR_PRINT("ECPRI type3 extract not support\r\n");
	} else if (msg_type == RTE_ECPRI_MSG_TYPE_RM_ACC) {
		DPAA2_PR_PRINT("rma_id(0x%02x) rw(0x%02x)",
			ecpri_msg.type4.rma_id, ecpri_msg.type4.rw);
		DPAA2_PR_PRINT(" rr(0x%02x) ele_id(0x%04x)\r\n",
			ecpri_msg.type4.rr,
			rte_be_to_cpu_16(ecpri_msg.type4.ele_id));
	} else if (msg_type == RTE_ECPRI_MSG_TYPE_DLY_MSR) {
		DPAA2_PR_PRINT("rma_id(0x%02x) rw(0x%02x)\r\n",
			ecpri_msg.type5.msr_id,
			ecpri_msg.type5.act_type);
	} else if (msg_type == RTE_ECPRI_MSG_TYPE_RMT_RST) {
		DPAA2_PR_PRINT("rst_id(0x%04x) rst_op(0x%02x)\r\n",
			rte_be_to_cpu_16(ecpri_msg.type6.rst_id),
			ecpri_msg.type6.rst_op);
	} else if (msg_type == RTE_ECPRI_MSG_TYPE_EVT_IND) {
		DPAA2_PR_PRINT("evt_id(0x%02x) evt_type(0x%02x)",
			ecpri_msg.type7.evt_id,
			ecpri_msg.type7.evt_type);
		DPAA2_PR_PRINT(" seq(0x%02x) number(0x%02x)\r\n",
			ecpri_msg.type7.seq,
			ecpri_msg.type7.number);
	}
}

static inline void
dpaa2_print_fd_frc(const struct qbman_fd *fd)
{
	const struct dpaa2_ingress_frc *frc;
	const struct dpaa2_psr_summary *sum;
	const union dpaa2_psr_summary_l *sum_l;
	const char *l4_nm;

	frc = (const void *)&fd->simple.frc;
	DPAA2_PR_PRINT("FRC faicfdv: %d\r\n", frc->faicfdv);
	DPAA2_PR_PRINT("FRC faswov: %d\r\n", frc->faswov);
	DPAA2_PR_PRINT("FRC faiadv: %d\r\n", frc->faiadv);
	DPAA2_PR_PRINT("FRC faprv: %d\r\n", frc->faprv);
	DPAA2_PR_PRINT("FRC faeadv: %d\r\n", frc->faeadv);
	DPAA2_PR_PRINT("FRC fasv: %d\r\n", frc->fasv);

	sum = &frc->psr_sum.sum;
	sum_l = &sum->sum_l;
	DPAA2_PR_PRINT("FRC Check sum err: %d\r\n", sum->checksum_err);
	DPAA2_PR_PRINT("FRC vlan: %d\r\n", sum->vlan);
	if (sum_l->non_ip.non_ip == DPAA2_PSR_SUMMARY_NONIP) {
		DPAA2_PR_PRINT("FRC NON IP %s detected, l2: %d\r\n",
			sum_l->non_ip.l2 == DPAA2_PSR_SUMMARY_ARP ?
			"arp" :
			sum_l->non_ip.l2 == DPAA2_PSR_SUMMARY_NONIP_PTP ?
			"ptp" : "",
			sum_l->non_ip.l2);
	} else if (sum_l->l4_ext.l3 == DPAA2_PSR_SUMMARY_L4_EXT) {
		DPAA2_PR_PRINT("FRC L4 ext %s (%d) detected\r\n",
			sum_l->l4_ext.ip == DPAA2_PSR_SUMMARY_IPV4 ?
			"ipv4" : "ipv6", sum_l->l4_ext.l4_ext);
	} else {
		if (sum_l->l4.l4 == DPAA2_PSR_SUMMARY_IP_FRAG)
			l4_nm = "fragment";
		else if (sum_l->l4.l4 == DPAA2_PSR_SUMMARY_ICMP)
			l4_nm = "icmp";
		else if (sum_l->l4.l4 == DPAA2_PSR_SUMMARY_IPSEC_ESP)
			l4_nm = "IPSec ESP";
		else if (sum_l->l4.l4 == DPAA2_PSR_SUMMARY_TCP)
			l4_nm = "tcp";
		else if (sum_l->l4.l4 == DPAA2_PSR_SUMMARY_SCTP)
			l4_nm = "sctp";
		else if (sum_l->l4.l4 == DPAA2_PSR_SUMMARY_UDP)
			l4_nm = "udp";
		else if (sum_l->l4.l4 == DPAA2_PSR_SUMMARY_PTP)
			l4_nm = "ptp";
		else if (sum_l->l4.l4 == DPAA2_PSR_SUMMARY_UDP_ESP_IKE)
			l4_nm = "udp/esp/ike";
		else if (sum_l->l4.l4 == DPAA2_PSR_SUMMARY_GTPU)
			l4_nm = "gtpu";
		else if (sum_l->l4.l4 == DPAA2_PSR_SUMMARY_GTPC)
			l4_nm = "gtpc";
		else if (sum_l->l4.l4 == DPAA2_PSR_SUMMARY_VXLAN)
			l4_nm = "vxlan";
		else
			l4_nm = "";
		DPAA2_PR_PRINT("FRC %s(%d) %s(%d) detected\r\n",
			sum_l->l4.l3 == DPAA2_PSR_SUMMARY_IPV4 ?
			"ipv4" : "ipv6", sum_l->l4.l3,
			l4_nm, sum_l->l4.l4);
	}

	DPAA2_PR_PRINT("FRC FAFE bit0~3: %d%d%d%d\r\n",
		sum->fafe0, sum->fafe1, sum->fafe2, sum_l->l4.fafe3);
}

static inline void
dpaa2_print_parse_result(const struct dpaa2_annot_hdr *annotation,
	int is_sp)
{
	struct dpaa2_annot_hdr annot_convert;
	uint64_t annot_size = sizeof(struct dpaa2_annot_hdr), offset = 0;
	uint64_t *word;
	const struct dpaa2_psr_result_parse *psr;
	const struct dpaa2_fas_parse *fas;

	rte_memcpy(&annot_convert, annotation, sizeof(struct dpaa2_annot_hdr));
	while (annot_size) {
		word = (uint64_t *)&annot_convert + offset;
		*word = rte_cpu_to_be_64(*word);
		offset++;
		annot_size -= sizeof(uint64_t);
	}
	fas = (const void *)&annotation->word1;
	psr = (const void *)&annot_convert.word3;

	if (fas->discard)
		DPAA2_PR_PRINT("FAS discard\r\n");
	if (fas->macsec)
		DPAA2_PR_PRINT("FAS MACSEC present\r\n");
	if (fas->ptp)
		DPAA2_PR_PRINT("FAS PTP present\r\n");
	if (fas->multicast)
		DPAA2_PR_PRINT("FAS Multicast present\r\n");
	if (fas->broadcast)
		DPAA2_PR_PRINT("FAS Broadcast present\r\n");
	if (fas->kse)
		DPAA2_PR_PRINT("FAS Invalid key or key size error\r\n");
	if (fas->eofhe)
		DPAA2_PR_PRINT("FAS extract out of frame header\r\n");
	if (fas->mnle)
		DPAA2_PR_PRINT("FAS Max number of chained lookups reached\r\n");
	if (fas->tide)
		DPAA2_PR_PRINT("FAS Invalid table ID\r\n");
	if (fas->piee)
		DPAA2_PR_PRINT("FAS Policer Initialization Entry Error\r\n");
	if (fas->fle)
		DPAA2_PR_PRINT("FAS Frame Length Error\r\n");
	if (fas->fpe)
		DPAA2_PR_PRINT("FAS Frame physical Error\r\n");
	if (fas->pte)
		DPAA2_PR_PRINT("FAS Parser terminate early\r\n");
	if (fas->isp)
		DPAA2_PR_PRINT("FAS Invalid SP instruction is encountered\r\n");
	if (fas->phe)
		DPAA2_PR_PRINT("FAS Error during parsing\r\n");
	if (fas->ble)
		DPAA2_PR_PRINT("FAS block limit is exceeded\r\n");
	if (fas->l3cv)
		DPAA2_PR_PRINT("FAS L3 checksum validation is performed\r\n");
	if (fas->l3ce)
		DPAA2_PR_PRINT("FAS L3 checksum error detected\r\n");
	if (fas->l4cv)
		DPAA2_PR_PRINT("FAS L4 checksum validation is performed\r\n");
	if (fas->l4ce)
		DPAA2_PR_PRINT("FAS L4 checksum error detected\r\n");
	DPAA2_PR_PRINT("FAS IFPID:%d PPID:%d, status:%02x\r\n",
		fas->ifpid, fas->ppid, fas->status);

	/** FAF error dump.*/
	if (psr->word3.faf_l_be.arp_err)
		DPAA2_PR_PRINT("FAF ARP error detected\r\n");
	if (psr->word3.faf_l_be.mpls_err)
		DPAA2_PR_PRINT("FAF MPLS error detected\r\n");
	if (psr->word3.faf_l_be.pppoe_ppp_err)
		DPAA2_PR_PRINT("FAF PPPOE/PPP error detected\r\n");
	if (psr->word3.faf_l_be.vlan_err)
		DPAA2_PR_PRINT("FAF vLAN error detected\r\n");
	if (psr->word3.faf_l_be.llc_snap_err)
		DPAA2_PR_PRINT("FAF LLC/SNAP error detected\r\n");
	if (psr->word3.faf_l_be.eth_err)
		DPAA2_PR_PRINT("FAF Ethernet error detected\r\n");
	if (psr->word3.faf_l_be.psr_err)
		DPAA2_PR_PRINT("FAF Parser error detected\r\n");
	if (psr->word3.faf_l_be.spsr_err)
		DPAA2_PR_PRINT("FAF Soft Parser error detected\r\n");
	if (psr->word3.faf_l_be.vxlan_err)
		DPAA2_PR_PRINT("FAF VXLan error detected\r\n");
	if (psr->word4.faf_h_be.esp_err)
		DPAA2_PR_PRINT("FAF ESP error detected\r\n");
	if (psr->word4.faf_h_be.gtp_err)
		DPAA2_PR_PRINT("FAF GTP error detected\r\n");
	if (psr->word4.faf_h_be.gtp_err)
		DPAA2_PR_PRINT("FAF GTP error detected\r\n");
	if (psr->word4.faf_h_be.l4_spsr_err)
		DPAA2_PR_PRINT("FAF L4 soft Parser error detected\r\n");
	if (psr->word4.faf_h_be.sctp_err)
		DPAA2_PR_PRINT("FAF SCTP error detected\r\n");
	if (psr->word4.faf_h_be.ipsec_err)
		DPAA2_PR_PRINT("FAF IPSec error detected\r\n");
	if (psr->word4.faf_h_be.tcp_err)
		DPAA2_PR_PRINT("FAF TCP error detected\r\n");
	if (psr->word4.faf_h_be.udp_err)
		DPAA2_PR_PRINT("FAF UDP error detected\r\n");
	if (psr->word4.faf_h_be.l3_spsr_err)
		DPAA2_PR_PRINT("FAF L3 soft Parser error detected\r\n");
	if (psr->word4.faf_h_be.gre_err)
		DPAA2_PR_PRINT("FAF GRE error detected\r\n");
	if (psr->word4.faf_h_be.min_encp_err)
		DPAA2_PR_PRINT("FAF Min.Encap error detected\r\n");
	if (psr->word4.faf_h_be.ip_n_err)
		DPAA2_PR_PRINT("FAF IP.n error detected\r\n");
	if (psr->word4.faf_h_be.ip_1_err)
		DPAA2_PR_PRINT("FAF IP.1 error detected\r\n");
	if (psr->word4.faf_h_be.l2_spsr_err)
		DPAA2_PR_PRINT("FAF L2 soft parser error detected\r\n");

	DPAA2_PR_PRINT("Next Header: %04x\r\n",
		rte_be_to_cpu_16(psr->word3.nxthdr));

	if (is_sp) {
		if (psr->word3.fafe.ecpri.ecpri) {
			DPAA2_PR_PRINT("FAFE ECPRI present, msg: %d\r\n",
				psr->word3.fafe.ecpri.msg_type);
		} else if (psr->word3.fafe.rocev2_tunnel.rocev2) {
			DPAA2_PR_PRINT("FAFE ROCEV2 present\r\n");
		} else if (psr->word3.fafe.rocev2_tunnel.geneve) {
			DPAA2_PR_PRINT("FAFE GENEVE present\r\n");
		} else {
			if (psr->word3.fafe.rocev2_tunnel.in_vlan)
				DPAA2_PR_PRINT("FAFE TUNNEL vLAN present\r\n");
			if (psr->word3.fafe.rocev2_tunnel.in_ipv4)
				DPAA2_PR_PRINT("FAFE TUNNEL IPv4 present\r\n");
			if (psr->word3.fafe.rocev2_tunnel.in_ipv6)
				DPAA2_PR_PRINT("FAFE TUNNEL IPv6 present\r\n");
			if (psr->word3.fafe.rocev2_tunnel.in_udp)
				DPAA2_PR_PRINT("FAFE TUNNEL UDP present\r\n");
			if (psr->word3.fafe.rocev2_tunnel.in_tcp)
				DPAA2_PR_PRINT("FAFE TUNNEL TCP present\r\n");
		}
	} else {
		DPAA2_PR_PRINT("FAFE: 0x%02x\r\n", psr->word3.fafe.fafe_8b);
	}

	/** FAF popular protocol dump.*/
	if (psr->word3.faf_l_be.arp)
		DPAA2_PR_PRINT("FAF ARP Present\r\n");
	if (psr->word3.faf_l_be.mac)
		DPAA2_PR_PRINT("FAF Ethernet MAC Present\r\n");
	if (psr->word3.faf_l_be.vxlan)
		DPAA2_PR_PRINT("FAF VXLan Present\r\n");
	if (psr->word3.faf_l_be.ike)
		DPAA2_PR_PRINT("FAF IKE Present\r\n");
	if (psr->word3.faf_l_be.ptp)
		DPAA2_PR_PRINT("FAF PTP Present\r\n");
	if (psr->word4.faf_h_be.gtp)
		DPAA2_PR_PRINT("FAF GTP Present\r\n");
	if (psr->word4.faf_h_be.sctp)
		DPAA2_PR_PRINT("FAF SCTP Present\r\n");
	if (psr->word4.faf_h_be.ipsec)
		DPAA2_PR_PRINT("FAF IPSec Present\r\n");
	if (psr->word4.faf_h_be.ipsec_esp)
		DPAA2_PR_PRINT("FAF IPSec ESP Present\r\n");
	if (psr->word4.faf_h_be.ipsec_ah)
		DPAA2_PR_PRINT("FAF IPSec AH Present\r\n");
	if (psr->word4.faf_h_be.gre)
		DPAA2_PR_PRINT("FAF GRE Present\r\n");
	if (psr->word4.faf_h_be.icmp)
		DPAA2_PR_PRINT("FAF ICMP Present\r\n");
	if (psr->word4.faf_h_be.ipv6_1)
		DPAA2_PR_PRINT("FAF IPv6 Present\r\n");
	if (psr->word4.faf_h_be.ipv6_n)
		DPAA2_PR_PRINT("FAF last IPv6 Present\r\n");
	if (psr->word4.faf_h_be.ipv4_1)
		DPAA2_PR_PRINT("FAF IPv4 Present\r\n");
	if (psr->word4.faf_h_be.ipv4_n)
		DPAA2_PR_PRINT("FAF last IPv4 Present\r\n");
	if (psr->word4.faf_h_be.ip_1_opt)
		DPAA2_PR_PRINT("FAF IP Present\r\n");
	if (psr->word4.faf_h_be.ip_1_init_frag)
		DPAA2_PR_PRINT("FAF IP first fragment Present\r\n");
	if (psr->word4.faf_h_be.ip_1_frag)
		DPAA2_PR_PRINT("FAF IP fragment Present\r\n");
	if (psr->word4.faf_h_be.tcp)
		DPAA2_PR_PRINT("FAF TCP Present\r\n");
	if (psr->word4.faf_h_be.udp)
		DPAA2_PR_PRINT("FAF UDP Present\r\n");

	DPAA2_PR_PRINT("Parser result eth header offset: %02x\r\n",
		psr->word5.eth_off);
	DPAA2_PR_PRINT("Parser result TCI1 offset: %02x\r\n",
		psr->word5.vlan_tci_1_off);
	DPAA2_PR_PRINT("Parser result last eth type offset: %02x\r\n",
		psr->word5.last_etype_off);
	DPAA2_PR_PRINT("Parser result l3 header offset: %02x\r\n",
		psr->word6.l3_off);
	DPAA2_PR_PRINT("Parser result l4 header offset: %02x\r\n",
		psr->word6.l4_off);
	DPAA2_PR_PRINT("Parser result l5 header offset: %02x\r\n",
		psr->word6.l5_off);
	DPAA2_PR_PRINT("Parser result next header offset: %02x\r\n",
		psr->word7.nxthdr_off);

	if (is_sp) {
		if (psr->word3.faf_l_be.vxlan)
			dpaa2_print_vxlan_parse_result(psr);
		if (psr->word3.fafe.ecpri.ecpri)
			dpaa2_print_ecpri_parse_result(psr);
		if (psr->word3.fafe.rocev2_tunnel.rocev2)
			dpaa2_print_rocev2_parse_result(psr);
		if (psr->word3.fafe.rocev2_tunnel.geneve)
			dpaa2_print_geneve_parse_result(psr);
	}
}

#endif /* _DPAA2_PARSE_DECODE_H */

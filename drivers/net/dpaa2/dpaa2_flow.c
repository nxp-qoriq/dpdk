/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2025 NXP
 */

#include <sys/queue.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>

#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_flow_driver.h>
#include <rte_tailq.h>

#include <fsl_dpni.h>
#include <fsl_dpkg.h>

#include <dpaa2_ethdev.h>
#include <dpaa2_pmd_logs.h>
#include "dpaa2_parser_decode.h"

static bool dpaa2_flow_control_log;

/* Default size of a key */
#define DPNI_DEFAULT_KEY_SIZE                   24

enum dpaa2_flow_entry_size {
	DPAA2_FLOW_ENTRY_MIN_SIZE = DPNI_DEFAULT_KEY_SIZE,
	DPAA2_FLOW_ENTRY_MAX_SIZE = DPNI_MAX_KEY_SIZE
};

enum dpaa2_flow_dist_type {
	DPAA2_FLOW_NULL_TYPE,
	DPAA2_FLOW_QOS_TYPE,
	DPAA2_FLOW_FS_TYPE
};

#define DPAA2_FLOW_RAW_OFFSET_FIELD_SHIFT	16
#define DPAA2_FLOW_MAX_KEY_SIZE			16

#define VXLAN_HF_VNI 0x08

struct dpaa2_dev_flow_fs_action {
	enum rte_flow_action_type action_type;
	union {
		uint16_t rss_queues;
		struct dpni_fs_action_cfg fs_action_cfg;
	};
	char dst_name[RTE_ETH_NAME_MAX_LEN];
};

union dpaa2_dev_flow_action {
	uint8_t fs_tc_id;
	struct dpaa2_dev_flow_fs_action fs_action;
};

struct dpaa2_generic_flow {
	struct dpni_rule_cfg rule_cfg;
	uint8_t *key_addr;
	uint8_t *mask_addr;
	uint16_t rule_size;
	uint16_t entry_index;
	/** This flow has IPv4 or IPv6 extracts.*/
	enum net_prot ip_key;
	/** This flow has IPv4 or IPv6 source extract.*/
	enum net_prot ip_src;
	/** This flow has IPv4 or IPv6 destination extract.*/
	enum net_prot ip_dst;
	struct dpaa2_dev_priv *priv;
	uint8_t tc_id; /** For FS flow only.*/
	union dpaa2_dev_flow_action flow_action;
};

struct dpaa2_dev_flow {
	LIST_ENTRY(dpaa2_dev_flow) next;
	struct dpaa2_generic_flow *qos_flow;
	struct dpaa2_generic_flow *fs_flow;
	struct dpaa2_dev_priv *priv;
};

struct rte_dpaa2_flow_item {
	struct rte_flow_item generic_item;
	int in_tunnel;
};

static const
enum rte_flow_item_type dpaa2_hp_supported_pattern_type[] = {
	RTE_FLOW_ITEM_TYPE_END,
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_VLAN,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_ICMP,
	RTE_FLOW_ITEM_TYPE_UDP,
	RTE_FLOW_ITEM_TYPE_TCP,
	RTE_FLOW_ITEM_TYPE_SCTP,
	RTE_FLOW_ITEM_TYPE_GRE,
	RTE_FLOW_ITEM_TYPE_GTP,
	RTE_FLOW_ITEM_TYPE_ESP,
	RTE_FLOW_ITEM_TYPE_AH,
	RTE_FLOW_ITEM_TYPE_RAW,
	/** Hardware parser supports vlan protocol only.*/
	RTE_FLOW_ITEM_TYPE_VXLAN
};

static const
enum rte_flow_item_type dpaa2_sp_supported_pattern_type[] = {
	RTE_FLOW_ITEM_TYPE_ECPRI,
	RTE_FLOW_ITEM_TYPE_ROCEV2,
	RTE_FLOW_ITEM_TYPE_GENEVE
};

static const
enum rte_flow_action_type dpaa2_supported_action_type[] = {
	RTE_FLOW_ACTION_TYPE_END,
	RTE_FLOW_ACTION_TYPE_QUEUE,
	RTE_FLOW_ACTION_TYPE_PORT_ID,
	RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT,
	RTE_FLOW_ACTION_TYPE_RSS,
	RTE_FLOW_ACTION_TYPE_DROP,
	RTE_FLOW_ACTION_TYPE_METER_MARK,
	RTE_FLOW_ACTION_TYPE_METER
};

#define DPAA2_FLOW_HDR_HEX_DUMP_SIZE \
	(RTE_MAX(sizeof(struct rte_flow_item_eth), \
	RTE_MAX(sizeof(struct rte_flow_item_vlan), \
	RTE_MAX(sizeof(struct rte_flow_item_ipv4), \
	RTE_MAX(sizeof(struct rte_flow_item_ipv6), \
	RTE_MAX(sizeof(struct rte_flow_item_icmp), \
	RTE_MAX(sizeof(struct rte_flow_item_udp), \
	RTE_MAX(sizeof(struct rte_flow_item_tcp), \
	RTE_MAX(sizeof(struct rte_flow_item_sctp), \
	RTE_MAX(sizeof(struct rte_flow_item_gre), \
	RTE_MAX(sizeof(struct rte_flow_item_ah), \
	RTE_MAX(sizeof(struct rte_flow_item_esp), \
	RTE_MAX(sizeof(struct rte_flow_item_vxlan), \
	RTE_MAX(sizeof(struct rte_flow_item_ecpri), \
	RTE_MAX(sizeof(struct rte_flow_item_gtp), \
	sizeof(struct rte_flow_item_rocev2))))))))))))))) * 10)

#ifndef __cplusplus
static const struct rte_flow_item_eth dpaa2_flow_item_eth_mask = {
	.dst.addr_bytes = "\xff\xff\xff\xff\xff\xff",
	.src.addr_bytes = "\xff\xff\xff\xff\xff\xff",
	.type = RTE_BE16(0xffff),
};

static const struct rte_flow_item_vlan dpaa2_flow_item_vlan_mask = {
	.tci = RTE_BE16(0xffff),
};

static const struct rte_flow_item_ipv4 dpaa2_flow_item_ipv4_mask = {
	.hdr.src_addr = RTE_BE32(0xffffffff),
	.hdr.dst_addr = RTE_BE32(0xffffffff),
	.hdr.next_proto_id = 0xff,
	.hdr.packet_id = 0xffff,
	.hdr.fragment_offset = 0xffff,
};

static const struct rte_flow_item_ipv6 dpaa2_flow_item_ipv6_mask = {
	.hdr = {
		.src_addr =
			"\xff\xff\xff\xff\xff\xff\xff\xff"
			"\xff\xff\xff\xff\xff\xff\xff\xff",
		.dst_addr =
			"\xff\xff\xff\xff\xff\xff\xff\xff"
			"\xff\xff\xff\xff\xff\xff\xff\xff",
		.proto = 0xff
	},
};

static const struct rte_flow_item_icmp dpaa2_flow_item_icmp_mask = {
	.hdr.icmp_type = 0xff,
	.hdr.icmp_code = 0xff,
};

static const struct rte_flow_item_udp dpaa2_flow_item_udp_mask = {
	.hdr = {
		.src_port = RTE_BE16(0xffff),
		.dst_port = RTE_BE16(0xffff),
	},
};

static const struct rte_flow_item_tcp dpaa2_flow_item_tcp_mask = {
	.hdr = {
		.src_port = RTE_BE16(0xffff),
		.dst_port = RTE_BE16(0xffff),
	},
};

static const struct rte_flow_item_sctp dpaa2_flow_item_sctp_mask = {
	.hdr = {
		.src_port = RTE_BE16(0xffff),
		.dst_port = RTE_BE16(0xffff),
	},
};

static const struct rte_flow_item_esp dpaa2_flow_item_esp_mask = {
	.hdr = {
		.spi = RTE_BE32(0xffffffff),
		.seq = RTE_BE32(0xffffffff),
	},
};

static const struct rte_flow_item_ah dpaa2_flow_item_ah_mask = {
	.spi = RTE_BE32(0xffffffff),
};

static const struct rte_flow_item_gre dpaa2_flow_item_gre_mask = {
	.protocol = RTE_BE16(0xffff),
};

static const struct rte_flow_item_vxlan dpaa2_flow_item_vxlan_mask = {
	.flags = 0xff,
	.vni = "\xff\xff\xff",
};

static const struct rte_flow_item_geneve dpaa2_flow_item_geneve_mask = {
	.protocol = RTE_BE16(0xffff),
	.vni = "\xff\xff\xff",
};

static const struct rte_flow_item_ecpri dpaa2_flow_item_ecpri_mask = {
	.hdr.common.type = 0xff,
	.hdr.dummy[0] = RTE_BE32(0xffffffff),
	.hdr.dummy[1] = RTE_BE32(0xffffffff),
	.hdr.dummy[2] = RTE_BE32(0xffffffff),
};

static const struct rte_flow_item_gtp dpaa2_flow_item_gtp_mask = {
	.teid = RTE_BE32(0xffffffff),
};

static const struct rte_flow_item_rocev2 dpaa2_flow_item_rocev2_mask = {
	.opcode = 0xff,
	.dest_qp = "\xff\xff\xff",
};
#endif

static inline uint8_t
dpaa2_flow_entry_map_get(const uint8_t *entry_map,
	uint16_t index)
{
	uint16_t byte_pos = index / 8;
	uint16_t bit_pos = index % 8;

	return entry_map[byte_pos] & (1 << bit_pos);
}

static inline void
dpaa2_flow_entry_map_set(uint8_t *entry_map,
	uint16_t index, int set)
{
	uint16_t byte_pos = index / 8;
	uint16_t bit_pos = index % 8;

	if (set)
		entry_map[byte_pos] |= (1 << bit_pos);
	else
		entry_map[byte_pos] &= ~(((uint8_t)1) << bit_pos);
}

static inline void
dpaa2_flow_extracts_log(const struct dpaa2_dev_priv *priv,
	const char *prefix, uint8_t tc_id)
{
	char string[1024];
	const struct dpaa2_key_extract *extract;
	int offset = 0;

	if (!dpaa2_flow_control_log)
		return;

	if (tc_id >= MAX_TCS && priv->num_rx_tc <= 1) {
		/** No QoS table.*/
		return;
	}

	offset += sprintf(&string[offset],
		"%s's", priv->eth_dev->data->name);
	if (tc_id >= MAX_TCS) {
		extract = &priv->extract.qos_key_extract;
		offset += sprintf(&string[offset], " QoS");
	} else {
		extract = &priv->extract.tc_key_extract[tc_id];
		offset += sprintf(&string[offset], " FS[%d]", tc_id);
	}
	offset += sprintf(&string[offset],
		" table: %d extracts/%d entries\n",
		extract->dpkg.num_extracts, extract->entry_num);
	DPAA2_FLOW_DUMP("\n%s %s", prefix, string);
	dpaa2_dump_dpkg(&extract->dpkg);
}

static inline void
dpaa2_flow_qos_entry_log(const char *log_info,
	const struct dpaa2_generic_flow *flow, uint16_t index)
{
	int idx;
	struct rte_eth_dev *dev = flow->priv->eth_dev;

	if (!dpaa2_flow_control_log || flow->priv->num_rx_tc <= 1)
		return;

	DPAA2_FLOW_DUMP("%s: %s QoS entry[%d](size %d/%d) to select FS[%d]\n",
		dev->data->name, log_info, index, flow->rule_size,
		flow->rule_cfg.key_size, flow->flow_action.fs_tc_id);

	DPAA2_FLOW_DUMP("key:\r\n");
	for (idx = 0; idx < flow->rule_size; idx++)
		DPAA2_FLOW_DUMP("%02x ", flow->key_addr[idx]);

	DPAA2_FLOW_DUMP("\r\nmask:\r\n");
	for (idx = 0; idx < flow->rule_size; idx++)
		DPAA2_FLOW_DUMP("%02x ", flow->mask_addr[idx]);
	DPAA2_FLOW_DUMP("\r\n\n");
}

static inline void
dpaa2_flow_fs_entry_log(const char *log_info,
	const struct dpaa2_generic_flow *flow)
{
	int idx;
	struct rte_eth_dev *dev = flow->priv->eth_dev;
	const struct dpaa2_dev_flow_fs_action *fs_action;

	if (!dpaa2_flow_control_log)
		return;

	DPAA2_FLOW_DUMP("%s: %s FS[%d]/entry[%d](size %d/%d)\r\n",
		dev->data->name, log_info, flow->tc_id,
		flow->entry_index, flow->rule_size,
		flow->rule_cfg.key_size);

	fs_action = &flow->flow_action.fs_action;

	DPAA2_FLOW_DUMP("key:\r\n");
	for (idx = 0; idx < flow->rule_size; idx++)
		DPAA2_FLOW_DUMP("%02x ", flow->key_addr[idx]);

	DPAA2_FLOW_DUMP("\r\nmask:\r\n");
	for (idx = 0; idx < flow->rule_size; idx++)
		DPAA2_FLOW_DUMP("%02x ", flow->mask_addr[idx]);
	DPAA2_FLOW_DUMP("\r\nAction: ");
	if (fs_action->action_type == RTE_FLOW_ACTION_TYPE_QUEUE) {
		DPAA2_FLOW_DUMP("Receive to flow%d\r\n\n",
			fs_action->fs_action_cfg.flow_id);
	} else if (fs_action->action_type == RTE_FLOW_ACTION_TYPE_PORT_ID ||
		fs_action->action_type == RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT) {
		DPAA2_FLOW_DUMP("Re-direct to port %s\r\n\n",
			fs_action->dst_name);
	} else if (fs_action->action_type == RTE_FLOW_ACTION_TYPE_DROP) {
		DPAA2_FLOW_DUMP("Drop\r\n\n");
	} else {
		DPAA2_FLOW_DUMP("Un-supported action type(%d)\r\n\n",
			fs_action->action_type);
	}
}

static inline void
dpaa2_dump_extract_map(const struct dpaa2_dev_priv *priv,
	const char *prefix)
{
	int idx, offset, i, valid_fs = 0;
	char string[2048];
	const struct dpaa2_key_extract *extract;

	if (!dpaa2_flow_control_log)
		return;

	DPAA2_FLOW_DUMP("%s: %s\n", priv->eth_dev->data->name, prefix);

	if (priv->num_rx_tc <= 1)
		goto skip_dump_qos;

	extract = &priv->extract.qos_key_extract;
	offset = 0;
	offset += sprintf(&string[offset], "QoS entry map:");
	if (!extract->entry_num) {
		offset += sprintf(&string[offset], " empty\n");
		goto start_dump_qos;
	} else {
		offset += sprintf(&string[offset], "\n");
	}
	for (idx = 0; idx < priv->qos_entries; idx++) {
		offset += sprintf(&string[offset], "%d ",
			dpaa2_flow_entry_map_get(extract->entry_map, idx) ?
			1 : 0);
		if (!((idx + 1) % 16) || (idx + 1) == priv->qos_entries)
			offset += sprintf(&string[offset], "\n");
	}

start_dump_qos:
	DPAA2_FLOW_DUMP("%s", string);

skip_dump_qos:
	for (i = 0; i < MAX_TCS; i++) {
		extract = &priv->extract.tc_key_extract[i];
		if (!extract->entry_num)
			continue;
		valid_fs++;
		offset = 0;
		offset += sprintf(&string[offset],
			"FS[%d] %d entries:\n", i, extract->entry_num);
		for (idx = 0; idx < priv->fs_entries; idx++) {
			offset += sprintf(&string[offset], "%d ",
				dpaa2_flow_entry_map_get(extract->entry_map,
					idx) ? 1 : 0);
			if (!((idx + 1) % 16) || (idx + 1) == priv->fs_entries)
				offset += sprintf(&string[offset], "\n");
		}
		DPAA2_FLOW_DUMP("%s", string);
	}
	if (valid_fs)
		DPAA2_FLOW_DUMP("\n");
	else
		DPAA2_FLOW_DUMP("No FS table extracts\n\n");
}

static int
dpaa2_flow_ip_address_extract(enum net_prot prot,
	uint32_t field)
{
	if (prot == NET_PROT_IPV4 &&
		(field == NH_FLD_IPV4_SRC_IP ||
		field == NH_FLD_IPV4_DST_IP))
		return true;
	else if (prot == NET_PROT_IPV6 &&
		(field == NH_FLD_IPV6_SRC_IP ||
		field == NH_FLD_IPV6_DST_IP))
		return true;
	else if (prot == NET_PROT_IP &&
		(field == NH_FLD_IP_SRC ||
		field == NH_FLD_IP_DST))
		return true;

	return false;
}

static int
dpaa2_flow_l4_src_port_extract(enum net_prot prot,
	uint32_t field)
{
	if (prot == NET_PROT_TCP &&
		field == NH_FLD_TCP_PORT_SRC)
		return true;
	else if (prot == NET_PROT_UDP &&
		field == NH_FLD_UDP_PORT_SRC)
		return true;
	else if (prot == NET_PROT_SCTP &&
		field == NH_FLD_SCTP_PORT_SRC)
		return true;

	return false;
}

static int
dpaa2_flow_l4_dst_port_extract(enum net_prot prot,
	uint32_t field)
{
	if (prot == NET_PROT_TCP &&
		field == NH_FLD_TCP_PORT_DST)
		return true;
	else if (prot == NET_PROT_UDP &&
		field == NH_FLD_UDP_PORT_DST)
		return true;
	else if (prot == NET_PROT_SCTP &&
		field == NH_FLD_SCTP_PORT_DST)
		return true;

	return false;
}

static int
dpaa2_flow_add_qos_rule(struct dpaa2_dev_priv *priv,
	struct dpaa2_generic_flow *flow, const struct rte_flow_attr *attr)
{
	struct dpaa2_key_extract *extract;
	int ret;
	struct fsl_mc_io *dpni = priv->hw;

	if (priv->num_rx_tc <= 1) {
		DPAA2_PMD_WARN("No QoS Table for FS");
		return -EINVAL;
	}

	/* QoS entry added is only effective for multiple TCs.*/
	if (attr) {
		/** New added.*/
		flow->entry_index = attr->group * priv->fs_entries + attr->priority;
		flow->flow_action.fs_tc_id = attr->group;
	}
	if (flow->entry_index >= priv->qos_entries) {
		DPAA2_PMD_ERR("QoS table full(%d >= %d)",
			flow->entry_index, priv->qos_entries);
		return -EINVAL;
	}
	extract = &priv->extract.qos_key_extract;
	if (dpaa2_flow_entry_map_get(extract->entry_map,
		flow->entry_index)) {
		DPAA2_PMD_ERR("QoS entry[%d] has been occupied",
			flow->entry_index);
		return -EINVAL;
	}

	dpaa2_flow_qos_entry_log("Add", flow, flow->entry_index);

	ret = dpni_add_qos_entry(dpni, CMD_PRI_LOW,
			priv->token, &flow->rule_cfg,
			flow->flow_action.fs_tc_id, flow->entry_index,
			0, 0);
	if (ret < 0) {
		DPAA2_PMD_ERR("Add entry(%d)->FS(%d) to QoS table failed",
			flow->entry_index, flow->flow_action.fs_tc_id);
		return ret;
	}
	dpaa2_flow_entry_map_set(extract->entry_map, flow->entry_index, 1);
	extract->entry_num++;

	return 0;
}

static int
dpaa2_flow_add_fs_rule(struct dpaa2_dev_priv *priv,
	struct dpaa2_generic_flow *flow)
{
	struct dpaa2_key_extract *extract;
	int ret;
	struct fsl_mc_io *dpni = priv->hw;

	extract = &priv->extract.tc_key_extract[flow->tc_id];
	if (dpaa2_flow_entry_map_get(extract->entry_map,
		flow->entry_index)) {
		DPAA2_PMD_ERR("FS[%d].entry[%d] has been occupied",
			flow->tc_id, flow->entry_index);
		return -EINVAL;
	}

	dpaa2_flow_fs_entry_log("Add", flow);

	ret = dpni_add_fs_entry(dpni, CMD_PRI_LOW,
		priv->token, flow->tc_id, flow->entry_index,
		&flow->rule_cfg, &flow->flow_action.fs_action.fs_action_cfg);
	if (ret < 0) {
		DPAA2_PMD_ERR("Add rule(%d) to FS table(%d) failed",
			flow->entry_index, flow->tc_id);
		return ret;
	}

	dpaa2_flow_entry_map_set(extract->entry_map, flow->entry_index, 1);
	extract->entry_num++;

	return 0;
}

static int
dpaa2_flow_rule_insert_hole(struct dpaa2_generic_flow *flow,
	int offset, int size)
{
	if (offset < flow->rule_size) {
		memmove(flow->key_addr + offset + size,
			flow->key_addr + offset,
			flow->rule_size - offset);
		memset(flow->key_addr + offset, 0, size);

		memmove(flow->mask_addr + offset + size,
			flow->mask_addr + offset,
			flow->rule_size - offset);
		memset(flow->mask_addr + offset, 0, size);
		flow->rule_size += size;
	} else {
		flow->rule_size = offset + size;
	}

	return 0;
}

static int
dpaa2_flow_rule_add_all(struct dpaa2_dev_priv *priv,
	enum dpaa2_flow_dist_type dist_type,
	uint16_t entry_size, uint8_t tc_id)
{
	struct dpaa2_dev_flow *curr = LIST_FIRST(&priv->flows);
	struct dpaa2_generic_flow *qos_flow;
	struct dpaa2_generic_flow *fs_flow;
	struct dpaa2_dev_flow_fs_action *fs_action;
	int ret;

	while (curr) {
		fs_action = NULL;
		qos_flow = curr->qos_flow;
		fs_flow = curr->fs_flow;
		if (fs_flow)
			fs_action = &fs_flow->flow_action.fs_action;
		if (qos_flow && dist_type == DPAA2_FLOW_QOS_TYPE &&
			(priv->num_rx_tc > 1 ||
			(fs_action && fs_action->action_type ==
			RTE_FLOW_ACTION_TYPE_RSS))) {
			qos_flow->rule_cfg.key_size = entry_size;
			ret = dpaa2_flow_add_qos_rule(priv, qos_flow, NULL);
			if (ret)
				return ret;
		} else if (dist_type == DPAA2_FLOW_FS_TYPE &&
			fs_flow && fs_flow->tc_id == tc_id) {
			fs_flow->rule_cfg.key_size = entry_size;
			ret = dpaa2_flow_add_fs_rule(priv, fs_flow);
			if (ret)
				return ret;
		}
		curr = LIST_NEXT(curr, next);
	}

	return 0;
}

static void
dpaa2_flow_qos_rule_insert_hole(struct dpaa2_dev_priv *priv,
	int offset, int size)
{
	struct dpaa2_dev_flow *curr;

	curr = priv->curr;
	if (curr)
		dpaa2_flow_rule_insert_hole(curr->qos_flow, offset, size);

	curr = LIST_FIRST(&priv->flows);
	while (curr) {
		if (curr->qos_flow->ip_src || curr->qos_flow->ip_dst)
			dpaa2_flow_rule_insert_hole(curr->qos_flow, offset, size);

		curr = LIST_NEXT(curr, next);
	}
}

static void
dpaa2_flow_fs_rule_insert_hole(struct dpaa2_dev_priv *priv,
	int offset, int size, int tc_id)
{
	struct dpaa2_dev_flow *curr;

	curr = priv->curr;
	if (curr && curr->fs_flow->tc_id == tc_id)
		dpaa2_flow_rule_insert_hole(curr->fs_flow, offset, size);

	curr = LIST_FIRST(&priv->flows);
	while (curr) {
		if (curr->fs_flow->tc_id != tc_id)
			goto continue_next;

		if (curr->fs_flow->ip_src || curr->fs_flow->ip_dst)
			dpaa2_flow_rule_insert_hole(curr->fs_flow, offset, size);

continue_next:
		curr = LIST_NEXT(curr, next);
	}
}

static int
dpaa2_flow_faf_advance(struct dpaa2_dev_priv *priv,
	int faf_byte, enum dpaa2_flow_dist_type dist_type, int tc_id,
	int *insert_offset)
{
	struct dpaa2_key_profile *key_profile;
	uint8_t idx, offset = 0xff;
	struct key_prot_field prot;

	if (dist_type == DPAA2_FLOW_QOS_TYPE)
		key_profile = &priv->extract.qos_key_extract.key_profile;
	else
		key_profile = &priv->extract.tc_key_extract[tc_id].key_profile;

	if (key_profile->num >= DPKG_MAX_NUM_OF_EXTRACTS) {
		DPAA2_PMD_ERR("Number of extracts overflows");
		return -EINVAL;
	}

	prot.type = DPAA2_FAF_KEY;
	prot.key_field = faf_byte;
	idx = dpaa2_profile_insert_no_ipaddr_extract(key_profile,
		1, &offset, insert_offset, &prot);
	if (offset != 0xff) {
		if (dist_type == DPAA2_FLOW_QOS_TYPE)
			dpaa2_flow_qos_rule_insert_hole(priv, offset, 1);
		else
			dpaa2_flow_fs_rule_insert_hole(priv, offset, 1, tc_id);
	}

	return idx;
}

static int
dpaa2_flow_pr_advance(struct dpaa2_dev_priv *priv,
	uint32_t pr_offset, uint32_t pr_size,
	enum dpaa2_flow_dist_type dist_type, int tc_id,
	int *insert_offset)
{
	struct dpaa2_key_profile *key_profile;
	uint8_t idx, offset = 0xff;
	struct key_prot_field prot;

	if (dist_type == DPAA2_FLOW_QOS_TYPE)
		key_profile = &priv->extract.qos_key_extract.key_profile;
	else
		key_profile = &priv->extract.tc_key_extract[tc_id].key_profile;

	if (key_profile->num >= DPKG_MAX_NUM_OF_EXTRACTS) {
		DPAA2_PMD_ERR("Number of extracts overflows");
		return -EINVAL;
	}

	prot.type = DPAA2_PR_KEY;
	prot.key_field = (pr_offset << 16) | pr_size;
	idx = dpaa2_profile_insert_no_ipaddr_extract(key_profile,
		pr_size, &offset, insert_offset, &prot);
	if (offset != 0xff) {
		if (dist_type == DPAA2_FLOW_QOS_TYPE) {
			dpaa2_flow_qos_rule_insert_hole(priv, offset,
				pr_size);
		} else {
			dpaa2_flow_fs_rule_insert_hole(priv, offset,
				pr_size, tc_id);
		}
	}

	return idx;
}

/* Move IPv4/IPv6 addresses to fill new extract previous IP address.
 * Current MC/WRIOP only support generic IP extract but IP address
 * is not fixed, so we have to put them at end of extracts, otherwise,
 * the extracts position following them can't be identified.
 */
static int
dpaa2_flow_key_profile_advance(enum net_prot prot,
	uint32_t field, uint8_t field_size,
	struct dpaa2_dev_priv *priv,
	enum dpaa2_flow_dist_type dist_type, int tc_id,
	int *insert_offset)
{
	struct dpaa2_key_profile *key_profile;
	uint8_t idx, offset = 0xff;
	struct key_prot_field prot_field;

	if (dpaa2_flow_ip_address_extract(prot, field)) {
		DPAA2_PMD_ERR("%s only for none IP address extract",
			__func__);
		return -EINVAL;
	}

	if (dist_type == DPAA2_FLOW_QOS_TYPE)
		key_profile = &priv->extract.qos_key_extract.key_profile;
	else
		key_profile = &priv->extract.tc_key_extract[tc_id].key_profile;

	if (key_profile->num >= DPKG_MAX_NUM_OF_EXTRACTS) {
		DPAA2_PMD_ERR("Number of extracts overflows");
		return -EINVAL;
	}

	prot_field.type = DPAA2_NET_PROT_KEY;
	prot_field.prot = prot;
	prot_field.key_field = field;
	idx = dpaa2_profile_insert_no_ipaddr_extract(key_profile,
		field_size, &offset, insert_offset, &prot_field);
	if (offset != 0xff) {
		if (dist_type == DPAA2_FLOW_QOS_TYPE) {
			dpaa2_flow_qos_rule_insert_hole(priv, offset,
				field_size);
		} else {
			dpaa2_flow_fs_rule_insert_hole(priv, offset,
				field_size, tc_id);
		}
	}

	if (dpaa2_flow_l4_src_port_extract(prot, field)) {
		key_profile->l4_sp_present = 1;
		key_profile->l4_sp_extract_idx = idx;
		key_profile->l4_sp_key_offset =
			key_profile->key_offset[idx];
	} else if (dpaa2_flow_l4_dst_port_extract(prot, field)) {
		key_profile->l4_dp_present = 1;
		key_profile->l4_dp_extract_idx = idx;
		key_profile->l4_dp_key_offset =
			key_profile->key_offset[idx];
	}

	return idx;
}

static int
dpaa2_flow_faf_add_hdr(int faf_byte,
	struct dpaa2_dev_priv *priv,
	enum dpaa2_flow_dist_type dist_type, int tc_id,
	int *insert_offset)
{
	int extract_idx;
	struct dpaa2_key_extract *key_extract;
	struct dpkg_profile_cfg *dpkg;
	struct dpkg_extract extract;

	if (dist_type == DPAA2_FLOW_QOS_TYPE)
		key_extract = &priv->extract.qos_key_extract;
	else
		key_extract = &priv->extract.tc_key_extract[tc_id];

	dpkg = &key_extract->dpkg;

	if (dpkg->num_extracts >= DPKG_MAX_NUM_OF_EXTRACTS) {
		DPAA2_PMD_ERR("Number of extracts overflows");
		return -EINVAL;
	}

	extract_idx = dpaa2_flow_faf_advance(priv,
			faf_byte, dist_type, tc_id,
			insert_offset);
	if (extract_idx < 0)
		return extract_idx;

	memset(&extract, 0, sizeof(extract));
	extract.type = DPKG_EXTRACT_FROM_PARSE;
	extract.extract.from_parse.offset = faf_byte;
	extract.extract.from_parse.size = 1;
	dpaa2_dpkg_insert_extract(dpkg, extract_idx, &extract);

	return 0;
}

static int
dpaa2_flow_pr_add_hdr(uint32_t pr_offset,
	uint32_t pr_size, struct dpaa2_dev_priv *priv,
	enum dpaa2_flow_dist_type dist_type, int tc_id,
	int *insert_offset)
{
	int extract_idx;
	struct dpaa2_key_extract *key_extract;
	struct dpkg_profile_cfg *dpkg;
	struct dpkg_extract extract;

	if ((pr_offset + pr_size) > DPAA2_PSR_RESULT_SIZE) {
		DPAA2_PMD_ERR("PR extracts(%d:%d) overflow",
			pr_offset, pr_size);
		return -EINVAL;
	}

	if (dist_type == DPAA2_FLOW_QOS_TYPE)
		key_extract = &priv->extract.qos_key_extract;
	else
		key_extract = &priv->extract.tc_key_extract[tc_id];

	dpkg = &key_extract->dpkg;

	if (dpkg->num_extracts >= DPKG_MAX_NUM_OF_EXTRACTS) {
		DPAA2_PMD_ERR("Number of extracts overflows");
		return -EINVAL;
	}

	extract_idx = dpaa2_flow_pr_advance(priv,
			pr_offset, pr_size, dist_type, tc_id,
			insert_offset);
	if (extract_idx < 0)
		return extract_idx;

	memset(&extract, 0, sizeof(extract));
	extract.type = DPKG_EXTRACT_FROM_PARSE;
	extract.extract.from_parse.offset = pr_offset;
	extract.extract.from_parse.size = pr_size;
	dpaa2_dpkg_insert_extract(dpkg, extract_idx, &extract);

	return 0;
}

static int
dpaa2_flow_extract_add_hdr(enum net_prot prot,
	uint32_t field, uint8_t field_size,
	struct dpaa2_dev_priv *priv,
	enum dpaa2_flow_dist_type dist_type, int tc_id,
	int *insert_offset)
{
	int extract_idx;
	struct dpaa2_key_extract *key_extract;
	struct dpkg_profile_cfg *dpkg;
	struct dpkg_extract extract;

	if (dist_type == DPAA2_FLOW_QOS_TYPE)
		key_extract = &priv->extract.qos_key_extract;
	else
		key_extract = &priv->extract.tc_key_extract[tc_id];

	dpkg = &key_extract->dpkg;

	if (dpaa2_flow_ip_address_extract(prot, field)) {
		DPAA2_PMD_ERR("%s only for none IP address extract",
			__func__);
		return -EINVAL;
	}

	if (dpkg->num_extracts >= DPKG_MAX_NUM_OF_EXTRACTS) {
		DPAA2_PMD_ERR("Number of extracts overflows");
		return -EINVAL;
	}

	extract_idx = dpaa2_flow_key_profile_advance(prot,
			field, field_size, priv,
			dist_type, tc_id,
			insert_offset);
	if (extract_idx < 0)
		return extract_idx;

	memset(&extract, 0, sizeof(extract));
	extract.type = DPKG_EXTRACT_FROM_HDR;
	extract.extract.from_hdr.prot = prot;
	extract.extract.from_hdr.type = DPKG_FULL_FIELD;
	extract.extract.from_hdr.field = field;
	dpaa2_dpkg_insert_extract(dpkg, extract_idx, &extract);

	return 0;
}

static inline int
dpaa2_flow_extract_search(struct dpaa2_key_profile *key_profile,
	enum key_prot_type type, enum net_prot prot, uint32_t key_field)
{
	int extract_idx;
	struct key_prot_field *prot_field;

	if (dpaa2_flow_ip_address_extract(prot, key_field)) {
		DPAA2_PMD_ERR("%s only for none IP address extract",
			__func__);
		return -EINVAL;
	}

	prot_field = key_profile->prot_field;
	for (extract_idx = 0; extract_idx < key_profile->num; extract_idx++) {
		if (type == DPAA2_NET_PROT_KEY &&
			prot_field[extract_idx].prot == prot &&
			prot_field[extract_idx].key_field == key_field &&
			prot_field[extract_idx].type == type)
			return extract_idx;
		else if (type == DPAA2_FAF_KEY &&
			prot_field[extract_idx].key_field == key_field &&
			prot_field[extract_idx].type == type)
			return extract_idx;
		else if (type == DPAA2_PR_KEY &&
			prot_field[extract_idx].key_field == key_field &&
			prot_field[extract_idx].type == type)
			return extract_idx;
	}

	if (type == DPAA2_NET_PROT_KEY &&
		dpaa2_flow_l4_src_port_extract(prot, key_field)) {
		if (key_profile->l4_sp_present)
			return key_profile->l4_sp_extract_idx;
	} else if (type == DPAA2_NET_PROT_KEY &&
		dpaa2_flow_l4_dst_port_extract(prot, key_field)) {
		if (key_profile->l4_dp_present)
			return key_profile->l4_dp_extract_idx;
	}

	return -ENXIO;
}

static int
_dpaa2_flow_extract_add_raw(struct dpaa2_dev_priv *priv,
	int offset, int size,
	enum dpaa2_flow_dist_type dist_type, int tc_id)
{
	struct dpaa2_key_extract *key_extract;
	struct dpkg_profile_cfg *dpkg;
	struct dpaa2_key_profile *key_profile;
	int last_extract_size, index, raw_idx, item_size;
	uint8_t num_extracts;
	uint32_t field;
	int ret;

	if (dist_type == DPAA2_FLOW_QOS_TYPE &&
		priv->num_rx_tc <= 1) {
		/** No QoS table.*/
		return 0;
	}

	if (dist_type == DPAA2_FLOW_QOS_TYPE)
		key_extract = &priv->extract.qos_key_extract;
	else
		key_extract = &priv->extract.tc_key_extract[tc_id];

	dpkg = &key_extract->dpkg;
	key_profile = &key_extract->key_profile;

	last_extract_size = (size % DPAA2_FLOW_MAX_KEY_SIZE);
	num_extracts = (size / DPAA2_FLOW_MAX_KEY_SIZE);
	if (last_extract_size)
		num_extracts++;
	else
		last_extract_size = DPAA2_FLOW_MAX_KEY_SIZE;

	if ((key_profile->num + num_extracts) >
		DPKG_MAX_NUM_OF_EXTRACTS) {
		DPAA2_PMD_ERR("%s Failed to expand raw extracts",
			__func__);
		return -EINVAL;
	}

	for (index = 0; index < num_extracts; index++) {
		if (index == num_extracts - 1)
			item_size = last_extract_size;
		else
			item_size = DPAA2_FLOW_MAX_KEY_SIZE;
		field = offset << DPAA2_FLOW_RAW_OFFSET_FIELD_SHIFT;
		field |= item_size;

		ret = dpaa2_flow_extract_search(key_profile,
			DPAA2_NET_PROT_KEY, NET_PROT_PAYLOAD, field);
		if (ret >= 0) {
			offset += item_size;
			continue;
		}

		raw_idx = dpaa2_flow_key_profile_advance(NET_PROT_PAYLOAD,
				field, item_size, priv, dist_type,
				tc_id, NULL);
		if (raw_idx < 0)
			return raw_idx;

		dpkg->extracts[raw_idx].type = DPKG_EXTRACT_FROM_DATA;
		dpkg->extracts[raw_idx].extract.from_data.size = item_size;
		dpkg->extracts[raw_idx].extract.from_data.offset = offset;

		offset += item_size;
		dpkg->num_extracts++;
	}

	return 0;
}

static int
dpaa2_flow_extract_add_raw(struct dpaa2_dev_priv *priv,
	int offset, int size, enum dpaa2_flow_dist_type dist_type,
	int tc_id, int *recfg)
{
	int ret;

	if (dist_type == DPAA2_FLOW_QOS_TYPE &&
		priv->num_rx_tc <= 1) {
		/** No QoS table.*/
		return 0;
	}

	ret = _dpaa2_flow_extract_add_raw(priv, offset, size,
			dist_type, tc_id);
	if (!ret && recfg)
		(*recfg) |= true;

	return ret;
}

static inline int
dpaa2_flow_extract_key_offset(struct dpaa2_key_profile *key_profile,
	enum key_prot_type type, enum net_prot prot, uint32_t key_field)
{
	int i;

	i = dpaa2_flow_extract_search(key_profile, type, prot, key_field);
	if (i >= 0)
		return key_profile->key_offset[i];
	else
		return i;
}

static int
dpaa2_flow_faf_add_rule(struct dpaa2_dev_priv *priv,
	struct dpaa2_generic_flow *flow, uint32_t faf_bit_off,
	int group, enum dpaa2_flow_dist_type dist_type)
{
	int offset;
	uint8_t *key_addr;
	uint8_t *mask_addr;
	struct dpaa2_key_extract *key_extract;
	struct dpaa2_key_profile *key_profile;
	uint8_t faf_byte = faf_bit_off / 8;
	uint8_t faf_bit_in_byte = faf_bit_off % 8;

	faf_bit_in_byte = 7 - faf_bit_in_byte;
	if (dist_type == DPAA2_FLOW_QOS_TYPE)
		key_extract = &priv->extract.qos_key_extract;
	else
		key_extract = &priv->extract.tc_key_extract[group];
	key_profile = &key_extract->key_profile;
	offset = dpaa2_flow_extract_key_offset(key_profile,
			DPAA2_FAF_KEY, NET_PROT_NONE, faf_byte);
	if (offset < 0) {
		DPAA2_PMD_ERR("%s QoS key extract failed", __func__);
		return -EINVAL;
	}
	key_addr = flow->key_addr + offset;
	mask_addr = flow->mask_addr + offset;

	if (!(*key_addr) &&
		!(flow->ip_src || flow->ip_dst) &&
		offset >= flow->rule_size)
		flow->rule_size = offset + sizeof(uint8_t);

	*key_addr |=  (1 << faf_bit_in_byte);
	*mask_addr |=  (1 << faf_bit_in_byte);

	return 0;
}

static inline int
dpaa2_flow_pr_rule_data_set(struct dpaa2_generic_flow *flow,
	struct dpaa2_key_profile *key_profile,
	uint32_t pr_offset, uint32_t pr_size,
	const void *key, const void *mask,
	enum dpaa2_flow_dist_type dist_type)
{
	int offset;
	uint32_t pr_field = pr_offset << 16 | pr_size;
	char offset_info[64], size_info[64], rule_size_info[64];

	offset = dpaa2_flow_extract_key_offset(key_profile,
			DPAA2_PR_KEY, NET_PROT_NONE, pr_field);
	if (offset < 0) {
		DPAA2_PMD_ERR("PR off(%d)/size(%d) does not exist!",
			pr_offset, pr_size);
		return -EINVAL;
	}
	sprintf(offset_info, "offset(%d)", offset);
	sprintf(size_info, "size(%d)", pr_size);

	sprintf(rule_size_info, "%s rule size(%d)",
		dist_type == DPAA2_FLOW_QOS_TYPE ?
		"QoS" : "FS", flow->rule_size);
	memcpy((flow->key_addr + offset), key, pr_size);
	memcpy((flow->mask_addr + offset), mask, pr_size);
	if (!(flow->ip_src || flow->ip_dst)) {
		if (offset >= flow->rule_size) {
			flow->rule_size = offset + pr_size;
		} else if ((offset + pr_size) > flow->rule_size) {
			DPAA2_PMD_ERR("%s < %s, but %s + %s > %s",
			offset_info, rule_size_info,
			offset_info, size_info,
			rule_size_info);
			return -EINVAL;
		}
	}

	return 0;
}

static inline int
dpaa2_flow_hdr_rule_data_set(struct dpaa2_generic_flow *flow,
	struct dpaa2_key_profile *key_profile,
	enum net_prot prot, uint32_t field, int size,
	const void *key, const void *mask,
	enum dpaa2_flow_dist_type dist_type)
{
	int offset;
	char offset_info[64], size_info[64], rule_size_info[64];

	if (dpaa2_flow_ip_address_extract(prot, field)) {
		DPAA2_PMD_ERR("%s only for none IP address extract",
			__func__);
		return -EINVAL;
	}

	offset = dpaa2_flow_extract_key_offset(key_profile,
			DPAA2_NET_PROT_KEY, prot, field);
	if (offset < 0) {
		DPAA2_PMD_ERR("P(%d)/F(%d) does not exist!",
			prot, field);
		return -EINVAL;
	}
	sprintf(offset_info, "offset(%d)", offset);
	sprintf(size_info, "size(%d)", size);

	sprintf(rule_size_info, "%s rule size(%d)",
		dist_type == DPAA2_FLOW_QOS_TYPE ? "QoS" : "FS",
		flow->rule_size);

	memcpy((flow->key_addr + offset), key, size);
	memcpy((flow->mask_addr + offset), mask, size);
	if (!(flow->ip_src || flow->ip_dst)) {
		if (offset >= flow->rule_size) {
			flow->rule_size = offset + size;
		} else if ((offset + size) > flow->rule_size) {
			DPAA2_PMD_ERR("%s: %s < %s, but %s + %s > %s",
				__func__, offset_info, rule_size_info,
				offset_info, size_info, rule_size_info);
			return -EINVAL;
		}
	}

	return 0;
}

static inline int
dpaa2_flow_raw_rule_data_set(struct dpaa2_generic_flow *flow,
	struct dpaa2_key_profile *key_profile,
	uint32_t extract_offset, int size,
	const void *key, const void *mask,
	enum dpaa2_flow_dist_type dist_type)
{
	int extract_size = size > DPAA2_FLOW_MAX_KEY_SIZE ?
		DPAA2_FLOW_MAX_KEY_SIZE : size;
	int offset, field;
	char offset_info[64], size_info[64], rule_size_info[64];

	field = extract_offset << DPAA2_FLOW_RAW_OFFSET_FIELD_SHIFT;
	field |= extract_size;
	offset = dpaa2_flow_extract_key_offset(key_profile,
			DPAA2_NET_PROT_KEY, NET_PROT_PAYLOAD, field);
	if (offset < 0) {
		DPAA2_PMD_ERR("offset(%d)/size(%d) raw extract failed",
			extract_offset, size);
		return -EINVAL;
	}
	sprintf(offset_info, "offset(%d)", offset);
	sprintf(size_info, "size(%d)", size);

	sprintf(rule_size_info, "%s rule size(%d)",
		dist_type == DPAA2_FLOW_QOS_TYPE ?
		"QoS" : "FS", flow->rule_size);

	memcpy((flow->key_addr + offset), key, size);
	memcpy((flow->mask_addr + offset), mask, size);
	if (offset >= flow->rule_size) {
		flow->rule_size = offset + size;
	} else if ((offset + size) > flow->rule_size) {
		DPAA2_PMD_ERR("%s: %s < %s, but %s + %s > %s",
			__func__, offset_info, rule_size_info,
			offset_info, size_info, rule_size_info);
		return -EINVAL;
	}

	return 0;
}

static int
dpaa2_flow_extract_support(const uint8_t *mask_src,
	enum rte_flow_item_type type)
{
	char mask[64];
	int i, size = 0;
	const char *mask_support = 0;

	switch (type) {
	case RTE_FLOW_ITEM_TYPE_ETH:
		mask_support = (const char *)&dpaa2_flow_item_eth_mask;
		size = sizeof(struct rte_flow_item_eth);
		break;
	case RTE_FLOW_ITEM_TYPE_VLAN:
		mask_support = (const char *)&dpaa2_flow_item_vlan_mask;
		size = sizeof(struct rte_flow_item_vlan);
		break;
	case RTE_FLOW_ITEM_TYPE_IPV4:
		mask_support = (const char *)&dpaa2_flow_item_ipv4_mask;
		size = sizeof(struct rte_flow_item_ipv4);
		break;
	case RTE_FLOW_ITEM_TYPE_IPV6:
		mask_support = (const char *)&dpaa2_flow_item_ipv6_mask;
		size = sizeof(struct rte_flow_item_ipv6);
		break;
	case RTE_FLOW_ITEM_TYPE_ICMP:
		mask_support = (const char *)&dpaa2_flow_item_icmp_mask;
		size = sizeof(struct rte_flow_item_icmp);
		break;
	case RTE_FLOW_ITEM_TYPE_UDP:
		mask_support = (const char *)&dpaa2_flow_item_udp_mask;
		size = sizeof(struct rte_flow_item_udp);
		break;
	case RTE_FLOW_ITEM_TYPE_TCP:
		mask_support = (const char *)&dpaa2_flow_item_tcp_mask;
		size = sizeof(struct rte_flow_item_tcp);
		break;
	case RTE_FLOW_ITEM_TYPE_ESP:
		mask_support = (const char *)&dpaa2_flow_item_esp_mask;
		size = sizeof(struct rte_flow_item_esp);
		break;
	case RTE_FLOW_ITEM_TYPE_AH:
		mask_support = (const char *)&dpaa2_flow_item_ah_mask;
		size = sizeof(struct rte_flow_item_ah);
		break;
	case RTE_FLOW_ITEM_TYPE_SCTP:
		mask_support = (const char *)&dpaa2_flow_item_sctp_mask;
		size = sizeof(struct rte_flow_item_sctp);
		break;
	case RTE_FLOW_ITEM_TYPE_GRE:
		mask_support = (const char *)&dpaa2_flow_item_gre_mask;
		size = sizeof(struct rte_flow_item_gre);
		break;
	case RTE_FLOW_ITEM_TYPE_VXLAN:
		mask_support = (const char *)&dpaa2_flow_item_vxlan_mask;
		size = sizeof(struct rte_flow_item_vxlan);
		break;
	case RTE_FLOW_ITEM_TYPE_ECPRI:
		mask_support = (const char *)&dpaa2_flow_item_ecpri_mask;
		size = sizeof(struct rte_flow_item_ecpri);
		break;
	case RTE_FLOW_ITEM_TYPE_GTP:
		mask_support = (const char *)&dpaa2_flow_item_gtp_mask;
		size = sizeof(struct rte_flow_item_gtp);
		break;
	case RTE_FLOW_ITEM_TYPE_ROCEV2:
		mask_support = (const char *)&dpaa2_flow_item_rocev2_mask;
		size = sizeof(struct rte_flow_item_rocev2);
		break;
	case RTE_FLOW_ITEM_TYPE_GENEVE:
		mask_support = (const char *)&dpaa2_flow_item_geneve_mask;
		size = sizeof(struct rte_flow_item_geneve);
		break;
	default:
		return -EINVAL;
	}

	memcpy(mask, mask_support, size);

	for (i = 0; i < size; i++)
		mask[i] = (mask[i] | mask_src[i]);

	if (memcmp(mask, mask_support, size))
		return -ENOTSUP;

	return 0;
}

static int
dpaa2_flow_identify_by_faf(struct dpaa2_dev_priv *priv,
	struct dpaa2_generic_flow *flow, uint32_t faf_bit_off,
	enum dpaa2_flow_dist_type dist_type, int group, int *recfg)
{
	int ret, index, local_cfg = false;
	struct dpaa2_key_extract *extract;
	struct dpaa2_key_profile *key_profile;
	uint8_t faf_byte = faf_bit_off / 8;

	if ((dist_type == DPAA2_FLOW_QOS_TYPE) &&
		priv->num_rx_tc > 1) {
		extract = &priv->extract.qos_key_extract;
		key_profile = &extract->key_profile;

		index = dpaa2_flow_extract_search(key_profile,
				DPAA2_FAF_KEY, NET_PROT_NONE, faf_byte);
		if (index < 0) {
			ret = dpaa2_flow_faf_add_hdr(faf_byte,
					priv, DPAA2_FLOW_QOS_TYPE, group,
					NULL);
			if (ret) {
				DPAA2_PMD_ERR("QOS faf extract add failed");

				return -EINVAL;
			}
			local_cfg = true;
		}

		ret = dpaa2_flow_faf_add_rule(priv, flow, faf_bit_off, group,
				DPAA2_FLOW_QOS_TYPE);
		if (ret) {
			DPAA2_PMD_ERR("QoS faf rule set failed");
			return ret;
		}
	} else if (dist_type == DPAA2_FLOW_FS_TYPE) {
		extract = &priv->extract.tc_key_extract[group];
		key_profile = &extract->key_profile;

		index = dpaa2_flow_extract_search(key_profile,
				DPAA2_FAF_KEY, NET_PROT_NONE, faf_byte);
		if (index < 0) {
			ret = dpaa2_flow_faf_add_hdr(faf_byte,
					priv, DPAA2_FLOW_FS_TYPE, group,
					NULL);
			if (ret) {
				DPAA2_PMD_ERR("FS[%d] faf extract add failed",
					group);

				return -EINVAL;
			}
			local_cfg = true;
		}

		ret = dpaa2_flow_faf_add_rule(priv, flow, faf_bit_off, group,
				DPAA2_FLOW_FS_TYPE);
		if (ret) {
			DPAA2_PMD_ERR("FS[%d] faf rule set failed",
				group);
			return -EINVAL;
		}
	}

	if (recfg)
		(*recfg) |= local_cfg;

	return 0;
}

static int
dpaa2_flow_add_pr_extract_rule(struct dpaa2_generic_flow *flow,
	uint32_t pr_offset, uint32_t pr_size,
	const void *key, const void *mask,
	struct dpaa2_dev_priv *priv, int tc_id, int *recfg,
	enum dpaa2_flow_dist_type dist_type)
{
	int index, ret, local_cfg = false;
	struct dpaa2_key_extract *key_extract;
	struct dpaa2_key_profile *key_profile;
	uint32_t pr_field = pr_offset << 16 | pr_size;

	if (dist_type == DPAA2_FLOW_QOS_TYPE &&
		priv->num_rx_tc <= 1) {
		/** No QoS table.*/
		return 0;
	}

	if (dist_type == DPAA2_FLOW_QOS_TYPE)
		key_extract = &priv->extract.qos_key_extract;
	else
		key_extract = &priv->extract.tc_key_extract[tc_id];

	key_profile = &key_extract->key_profile;

	index = dpaa2_flow_extract_search(key_profile,
			DPAA2_PR_KEY, NET_PROT_NONE, pr_field);
	if (index < 0) {
		ret = dpaa2_flow_pr_add_hdr(pr_offset,
				pr_size, priv,
				dist_type, tc_id, NULL);
		if (ret) {
			DPAA2_PMD_ERR("PR add off(%d)/size(%d) failed",
				pr_offset, pr_size);

			return ret;
		}
		local_cfg = true;
	}

	ret = dpaa2_flow_pr_rule_data_set(flow, key_profile,
			pr_offset, pr_size, key, mask, dist_type);
	if (ret) {
		DPAA2_PMD_ERR("PR off(%d)/size(%d) rule data set failed",
			pr_offset, pr_size);

		return ret;
	}

	if (recfg)
		(*recfg) |= local_cfg;

	return 0;
}

static int
dpaa2_flow_add_hdr_extract_rule(struct dpaa2_generic_flow *flow,
	enum net_prot prot, uint32_t field,
	const void *key, const void *mask, int size,
	struct dpaa2_dev_priv *priv, int tc_id, int *recfg,
	enum dpaa2_flow_dist_type dist_type)
{
	int index, ret, local_cfg = false;
	struct dpaa2_key_extract *key_extract;
	struct dpaa2_key_profile *key_profile;

	if (dist_type == DPAA2_FLOW_QOS_TYPE &&
		priv->num_rx_tc <= 1) {
		/** No QoS table.*/
		return 0;
	}

	if (dpaa2_flow_ip_address_extract(prot, field))
		return -EINVAL;

	if (dist_type == DPAA2_FLOW_QOS_TYPE)
		key_extract = &priv->extract.qos_key_extract;
	else
		key_extract = &priv->extract.tc_key_extract[tc_id];

	key_profile = &key_extract->key_profile;

	index = dpaa2_flow_extract_search(key_profile,
			DPAA2_NET_PROT_KEY, prot, field);
	if (index < 0) {
		ret = dpaa2_flow_extract_add_hdr(prot,
				field, size, priv,
				dist_type, tc_id, NULL);
		if (ret) {
			DPAA2_PMD_ERR("QoS Extract P(%d)/F(%d) failed",
				prot, field);

			return ret;
		}
		local_cfg = true;
	}

	ret = dpaa2_flow_hdr_rule_data_set(flow, key_profile,
			prot, field, size, key, mask, dist_type);
	if (ret) {
		DPAA2_PMD_ERR("QoS P(%d)/F(%d) rule data set failed",
			prot, field);

		return ret;
	}

	if (recfg)
		(*recfg) |= local_cfg;

	return 0;
}

static int
dpaa2_flow_add_ipaddr_extract_rule(struct dpaa2_generic_flow *flow,
	enum net_prot prot, uint32_t field,
	const void *key, const void *mask, int size,
	struct dpaa2_dev_priv *priv, int tc_id, int *recfg,
	enum dpaa2_flow_dist_type dist_type)
{
	int local_cfg = false, update = 0, ret, pos = 0;
	struct dpaa2_key_extract *key_extract;
	struct dpaa2_key_profile *key_profile;
	struct dpkg_profile_cfg *dpkg;
	uint8_t *key_addr, *mask_addr, num;
	uint8_t ip_addr_offset = 0;

	if (dist_type == DPAA2_FLOW_QOS_TYPE &&
		priv->num_rx_tc <= 1) {
		/** No QoS table.*/
		return 0;
	}

	if (prot != NET_PROT_IPV4 && prot != NET_PROT_IPV6) {
		DPAA2_PMD_ERR("%s: Invalid protocol(%d)",
			__func__, prot);
		return -EINVAL;
	}

	if (prot == NET_PROT_IPV4) {
		if (field != NH_FLD_IPV4_SRC_IP &&
			field != NH_FLD_IPV4_DST_IP) {
			DPAA2_PMD_ERR("%s: Invalid ipv4 filed(%d)",
				__func__, field);
			return -EINVAL;
		}
		if (size != sizeof(rte_be32_t)) {
			DPAA2_PMD_ERR("%s: Invalid ipv4 address size(%d)",
				__func__, size);
			return -EINVAL;
		}
	} else {
		if (field != NH_FLD_IPV6_SRC_IP &&
			field != NH_FLD_IPV6_DST_IP) {
			DPAA2_PMD_ERR("%s: Invalid ipv6 filed(%d)",
				__func__, field);
			return -EINVAL;
		}
		if (size != NH_FLD_IPV6_ADDR_SIZE) {
			DPAA2_PMD_ERR("%s: Invalid ipv6 address size(%d)",
				__func__, size);
			return -EINVAL;
		}
	}

	if (prot == NET_PROT_IPV4 &&
		field == NH_FLD_IPV4_SRC_IP) {
		prot = NET_PROT_IP;
		field = NH_FLD_IP_SRC;
	} else if (prot == NET_PROT_IPV4 &&
		field == NH_FLD_IPV4_DST_IP) {
		prot = NET_PROT_IP;
		field = NH_FLD_IP_DST;
	} else if (prot == NET_PROT_IPV6 &&
		field == NH_FLD_IPV6_SRC_IP) {
		prot = NET_PROT_IP;
		field = NH_FLD_IP_SRC;
	} else if (prot == NET_PROT_IPV6 &&
		field == NH_FLD_IPV6_DST_IP) {
		prot = NET_PROT_IP;
		field = NH_FLD_IP_DST;
	} else {
		DPAA2_PMD_ERR("Inval P(%d)/F(%d) to extract ip address",
			prot, field);
		return -EINVAL;
	}

	if (dist_type == DPAA2_FLOW_QOS_TYPE)
		key_extract = &priv->extract.qos_key_extract;
	else
		key_extract = &priv->extract.tc_key_extract[tc_id];

	key_profile = &key_extract->key_profile;
	dpkg = &key_extract->dpkg;
	num = key_profile->num;
	key_addr = flow->key_addr;
	mask_addr = flow->mask_addr;

	if (num >= DPKG_MAX_NUM_OF_EXTRACTS) {
		DPAA2_PMD_ERR("Number of extracts overflows");
		return -EINVAL;
	}

	pos = dpaa2_extract_prev_ip_addr_pos(key_profile);
	if (pos >= 0) {
		ip_addr_offset = key_profile->key_offset[pos] +
			key_profile->key_size[pos];
	}

	ret = dpaa2_extract_ip_addr_add(field,
		key_profile, size, &update, &pos);
	if (ret) {
		DPAA2_PMD_ERR("Add IP address extract failed(%d)", ret);
		return ret;
	}
	if (pos > 1) {
		DPAA2_PMD_ERR("Invalid IP address extract position(%d)", pos);
		return -EINVAL;
	}
	if (update) {
		key_profile->num++;
		key_profile->prot_field[num].type = DPAA2_NET_PROT_KEY;
		key_profile->prot_field[num].prot = prot;
		key_profile->prot_field[num].key_field = field;

		dpkg->extracts[num].type = DPKG_EXTRACT_FROM_HDR;
		dpkg->extracts[num].extract.from_hdr.prot = prot;
		dpkg->extracts[num].extract.from_hdr.field = field;
		dpkg->extracts[num].extract.from_hdr.type = DPKG_FULL_FIELD;
		dpkg->num_extracts++;

		local_cfg = true;
	}

	key_addr += ip_addr_offset;
	mask_addr += ip_addr_offset;

	if (pos == 0) {
		rte_memcpy(key_addr, key, size);
		rte_memcpy(mask_addr, mask, size);
	} else {
		rte_memcpy(key_addr + size, key, size);
		rte_memcpy(mask_addr + size, mask, size);
	}

	flow->rule_size = ip_addr_offset + size * (pos + 1);

	if (recfg)
		(*recfg) |= local_cfg;

	return 0;
}

static void dpaa2_flow_hdr_hexdump(char *dump_buf,
	const uint8_t *hdr, uint32_t size)
{
	uint32_t i;

	for (i = 0; i < size; i++)
		sprintf(&dump_buf[i], "%02x ", hdr[i]);
}

static int
dpaa2_flow_tunnel_eth_extract_rule_set(struct dpaa2_generic_flow *flow,
	const struct rte_flow_attr *attr,
	const struct rte_flow_item *pattern, int *extract_cfg,
	enum dpaa2_flow_dist_type dist_type)
{
	int ret, local_cfg = false;
	uint32_t group;
	const struct rte_flow_item_eth *spec, *mask;
	struct dpaa2_dev_priv *priv = flow->priv;
	const char zero_cmp[RTE_ETHER_ADDR_LEN] = {0};
	char hex_dump[DPAA2_FLOW_HDR_HEX_DUMP_SIZE];

	if (!pattern->spec)
		return 0;

	group = attr->group;

	/* Parse pattern list to get the matching parameters */
	spec = pattern->spec;
	mask = pattern->mask ?
		pattern->mask : &dpaa2_flow_item_eth_mask;

	ret = dpaa2_flow_extract_support((const uint8_t *)mask,
		RTE_FLOW_ITEM_TYPE_ETH);
	if (ret) {
		dpaa2_flow_hdr_hexdump(hex_dump, (const uint8_t *)mask,
			sizeof(struct rte_flow_item_eth));
		DPAA2_PMD_WARN("Extract ethernet(%s) failed(%d)",
			hex_dump, ret);

		return ret;
	}

	if (memcmp((const char *)&mask->src,
		zero_cmp, RTE_ETHER_ADDR_LEN)) {
		/*SRC[0:1]*/
		ret = dpaa2_flow_add_pr_extract_rule(flow,
			DPAA2_VXLAN_IN_SADDR0_OFFSET,
			1, &spec->src.addr_bytes[0],
			&mask->src.addr_bytes[0],
			priv, group, &local_cfg, dist_type);
		if (ret)
			return ret;
		/*SRC[1:2]*/
		ret = dpaa2_flow_add_pr_extract_rule(flow,
			DPAA2_VXLAN_IN_SADDR1_OFFSET,
			2, &spec->src.addr_bytes[1],
			&mask->src.addr_bytes[1],
			priv, group, &local_cfg, dist_type);
		if (ret)
			return ret;
		/*SRC[3:1]*/
		ret = dpaa2_flow_add_pr_extract_rule(flow,
			DPAA2_VXLAN_IN_SADDR3_OFFSET,
			1, &spec->src.addr_bytes[3],
			&mask->src.addr_bytes[3],
			priv, group, &local_cfg, dist_type);
		if (ret)
			return ret;
		/*SRC[4:2]*/
		ret = dpaa2_flow_add_pr_extract_rule(flow,
			DPAA2_VXLAN_IN_SADDR4_OFFSET,
			2, &spec->src.addr_bytes[4],
			&mask->src.addr_bytes[4],
			priv, group, &local_cfg, dist_type);
		if (ret)
			return ret;
	}

	if (memcmp((const char *)&mask->dst,
		zero_cmp, RTE_ETHER_ADDR_LEN)) {
		/*DST[0:1]*/
		ret = dpaa2_flow_add_pr_extract_rule(flow,
			DPAA2_VXLAN_IN_DADDR0_OFFSET,
			1, &spec->dst.addr_bytes[0],
			&mask->dst.addr_bytes[0],
			priv, group, &local_cfg, dist_type);
		if (ret)
			return ret;
		/*DST[1:1]*/
		ret = dpaa2_flow_add_pr_extract_rule(flow,
			DPAA2_VXLAN_IN_DADDR1_OFFSET,
			1, &spec->dst.addr_bytes[1],
			&mask->dst.addr_bytes[1],
			priv, group, &local_cfg, dist_type);
		if (ret)
			return ret;
		/*DST[2:3]*/
		ret = dpaa2_flow_add_pr_extract_rule(flow,
			DPAA2_VXLAN_IN_DADDR2_OFFSET,
			3, &spec->dst.addr_bytes[2],
			&mask->dst.addr_bytes[2],
			priv, group, &local_cfg, dist_type);
		if (ret)
			return ret;
		/*DST[5:1]*/
		ret = dpaa2_flow_add_pr_extract_rule(flow,
			DPAA2_VXLAN_IN_DADDR5_OFFSET,
			1, &spec->dst.addr_bytes[5],
			&mask->dst.addr_bytes[5],
			priv, group, &local_cfg, dist_type);
		if (ret)
			return ret;
	}

	if (memcmp((const char *)&mask->type,
		zero_cmp, sizeof(rte_be16_t))) {
		ret = dpaa2_flow_add_pr_extract_rule(flow,
			DPAA2_VXLAN_IN_TYPE_OFFSET,
			sizeof(rte_be16_t), &spec->type, &mask->type,
			priv, group, &local_cfg, dist_type);
		if (ret)
			return ret;
	}

	if (extract_cfg)
		(*extract_cfg) |= local_cfg;

	return 0;
}

static int
dpaa2_flow_eth_extract_rule_set(struct dpaa2_generic_flow *flow,
	const struct rte_flow_attr *attr,
	const struct rte_dpaa2_flow_item *dpaa2_pattern,
	int *extract_cfg, enum dpaa2_flow_dist_type dist_type)
{
	int ret, local_cfg = 0;
	uint32_t bit_offset;
	const struct rte_flow_item_eth *spec, *mask;
	struct dpaa2_dev_priv *priv = flow->priv;
	const char zero_cmp[RTE_ETHER_ADDR_LEN] = {0};
	const struct rte_flow_item *pattern =
		&dpaa2_pattern->generic_item;
	char hex_dump[DPAA2_FLOW_HDR_HEX_DUMP_SIZE];

	if (dpaa2_pattern->in_tunnel) {
		return dpaa2_flow_tunnel_eth_extract_rule_set(flow,
				attr, pattern, extract_cfg,
				dist_type);
	}

	/* Parse pattern list to get the matching parameters */
	spec = pattern->spec;
	mask = pattern->mask ?
		pattern->mask : &dpaa2_flow_item_eth_mask;

	if (!spec) {
		ret = dpaa2_protocol_psr_bit_offset(&bit_offset,
			DPAA2_PARSER_MAC_ID);
		if (ret)
			return ret;

		ret = dpaa2_flow_identify_by_faf(priv, flow,
				bit_offset, dist_type,
				attr->group, &local_cfg);

		return ret;
	}

	ret = dpaa2_flow_extract_support((const uint8_t *)mask,
		RTE_FLOW_ITEM_TYPE_ETH);
	if (ret) {
		dpaa2_flow_hdr_hexdump(hex_dump, (const uint8_t *)mask,
			sizeof(struct rte_flow_item_eth));
		DPAA2_PMD_WARN("Extract ethernet(%s) failed(%d)",
			hex_dump, ret);

		return ret;
	}

	if (memcmp((const char *)&mask->src,
		zero_cmp, RTE_ETHER_ADDR_LEN)) {
		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_ETH,
			NH_FLD_ETH_SA, &spec->src.addr_bytes,
			&mask->src.addr_bytes, RTE_ETHER_ADDR_LEN,
			priv, attr->group, &local_cfg, dist_type);
		if (ret)
			return ret;
	}

	if (memcmp((const char *)&mask->dst,
		zero_cmp, RTE_ETHER_ADDR_LEN)) {
		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_ETH,
			NH_FLD_ETH_DA, &spec->dst.addr_bytes,
			&mask->dst.addr_bytes, RTE_ETHER_ADDR_LEN,
			priv, attr->group, &local_cfg, dist_type);
		if (ret)
			return ret;
	}

	if (memcmp((const char *)&mask->type,
		zero_cmp, sizeof(rte_be16_t))) {
		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_ETH,
			NH_FLD_ETH_TYPE, &spec->type,
			&mask->type, sizeof(rte_be16_t),
			priv, attr->group, &local_cfg, dist_type);
		if (ret)
			return ret;
	}

	if (extract_cfg)
		(*extract_cfg) |= local_cfg;

	return 0;
}

static int
dpaa2_flow_tunnel_vlan_extract_rule_set(struct dpaa2_generic_flow *flow,
	const struct rte_flow_attr *attr,
	const struct rte_flow_item *pattern, int *extract_cfg,
	enum dpaa2_flow_dist_type dist_type)
{
	int ret, local_cfg = false;
	uint32_t group, bit_offset;
	const struct rte_flow_item_vlan *spec, *mask;
	struct dpaa2_dev_priv *priv = flow->priv;
	char hex_dump[DPAA2_FLOW_HDR_HEX_DUMP_SIZE];

	group = attr->group;

	/* Parse pattern list to get the matching parameters */
	spec = pattern->spec;
	mask = pattern->mask ?
		pattern->mask : &dpaa2_flow_item_vlan_mask;

	if (!spec) {
		ret = dpaa2_protocol_psr_bit_offset(&bit_offset,
			DPAA2_PARSER_TUNNEL_VLAN_ID);
		if (ret)
			return ret;

		ret = dpaa2_flow_identify_by_faf(priv, flow,
				bit_offset, dist_type,
				attr->group, &local_cfg);
		if (ret)
			return ret;

		if (extract_cfg)
			(*extract_cfg) |= local_cfg;
		return 0;
	}

	ret = dpaa2_flow_extract_support((const uint8_t *)mask,
		RTE_FLOW_ITEM_TYPE_VLAN);
	if (ret) {
		dpaa2_flow_hdr_hexdump(hex_dump, (const uint8_t *)mask,
			sizeof(struct rte_flow_item_vlan));
		DPAA2_PMD_WARN("Extract vlan(%s) failed(%d)",
			hex_dump, ret);

		return ret;
	}

	if (!mask->tci)
		return 0;

	ret = dpaa2_flow_add_pr_extract_rule(flow,
			DPAA2_VXLAN_IN_TCI_OFFSET,
			sizeof(rte_be16_t), &spec->tci, &mask->tci,
			priv, group, &local_cfg, dist_type);
	if (ret)
		return ret;

	if (extract_cfg)
		(*extract_cfg) |= local_cfg;

	return 0;
}

static int
dpaa2_flow_vlan_extract_rule_set(struct dpaa2_generic_flow *flow,
	const struct rte_flow_attr *attr,
	const struct rte_dpaa2_flow_item *dpaa2_pattern,
	int *extract_cfg, enum dpaa2_flow_dist_type dist_type)
{
	int ret, local_cfg = 0;
	uint32_t bit_offset;
	const struct rte_flow_item_vlan *spec, *mask;
	struct dpaa2_dev_priv *priv = flow->priv;
	const struct rte_flow_item *pattern =
		&dpaa2_pattern->generic_item;
	char hex_dump[DPAA2_FLOW_HDR_HEX_DUMP_SIZE];

	if (dpaa2_pattern->in_tunnel) {
		return dpaa2_flow_tunnel_vlan_extract_rule_set(flow,
			attr, pattern, extract_cfg,
			dist_type);
	}

	/* Parse pattern list to get the matching parameters */
	spec = pattern->spec;
	mask = pattern->mask ? pattern->mask : &dpaa2_flow_item_vlan_mask;

	if (!spec) {
		ret = dpaa2_protocol_psr_bit_offset(&bit_offset,
			DPAA2_PARSER_VLAN_ID);
		if (ret)
			return ret;

		ret = dpaa2_flow_identify_by_faf(priv, flow,
			bit_offset, dist_type, attr->group, &local_cfg);
		if (ret)
			return ret;

		if (extract_cfg)
			(*extract_cfg) |= local_cfg;
		return 0;
	}

	ret = dpaa2_flow_extract_support((const uint8_t *)mask,
			RTE_FLOW_ITEM_TYPE_VLAN);
	if (ret) {
		dpaa2_flow_hdr_hexdump(hex_dump, (const uint8_t *)mask,
			sizeof(struct rte_flow_item_vlan));
		DPAA2_PMD_WARN("Extract vlan(%s) failed(%d)",
			hex_dump, ret);

		return ret;
	}

	if (!mask->tci)
		return 0;

	ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_VLAN,
			NH_FLD_VLAN_TCI, &spec->tci,
			&mask->tci, sizeof(rte_be16_t),
			priv, attr->group, &local_cfg, dist_type);
	if (ret)
		return ret;

	if (extract_cfg)
		(*extract_cfg) |= local_cfg;
	return 0;
}

static int
dpaa2_flow_ipv4_extract_rule_set(struct dpaa2_generic_flow *flow,
	const struct rte_flow_attr *attr,
	const struct rte_dpaa2_flow_item *dpaa2_pattern,
	int *extract_cfg, enum dpaa2_flow_dist_type dist_type)
{
	int ret, local_cfg = 0;
	uint32_t bit_offset;
	const struct rte_flow_item_ipv4 *spec_ipv4 = 0, *mask_ipv4 = 0;
	const void *key, *mask;
	struct dpaa2_dev_priv *priv = flow->priv;
	int size;
	const struct rte_flow_item *pattern = &dpaa2_pattern->generic_item;
	char hex_dump[DPAA2_FLOW_HDR_HEX_DUMP_SIZE];

	/* Parse pattern list to get the matching parameters */
	spec_ipv4 = pattern->spec;
	mask_ipv4 = pattern->mask ?
		pattern->mask : &dpaa2_flow_item_ipv4_mask;

	if (dpaa2_pattern->in_tunnel) {
		if (spec_ipv4) {
			DPAA2_PMD_ERR("Tunnel-IPv4 distribution not support");
			return -ENOTSUP;
		}

		ret = dpaa2_protocol_psr_bit_offset(&bit_offset,
			DPAA2_PARSER_TUNNEL_IPV4_ID);
		if (ret)
			return ret;

		ret = dpaa2_flow_identify_by_faf(priv, flow,
				bit_offset, dist_type,
				attr->group, &local_cfg);
		if (ret)
			return ret;
	}

	ret = dpaa2_protocol_psr_bit_offset(&bit_offset,
		DPAA2_PARSER_IPV4_ID);
	if (ret)
		return ret;

	ret = dpaa2_flow_identify_by_faf(priv, flow,
			bit_offset, dist_type,
			attr->group, &local_cfg);
	if (ret)
		return ret;

	if (!spec_ipv4) {
		if (flow->ip_key == NET_PROT_IPV6) {
			DPAA2_PMD_ERR("IPv6 flow has been configured");
			return -EINVAL;
		}
		flow->ip_key = NET_PROT_IPV4;
		if (extract_cfg)
			(*extract_cfg) |= local_cfg;
		return 0;
	}

	ret = dpaa2_flow_extract_support((const uint8_t *)mask_ipv4,
			RTE_FLOW_ITEM_TYPE_IPV4);
	if (ret) {
		dpaa2_flow_hdr_hexdump(hex_dump, (const uint8_t *)mask_ipv4,
			sizeof(struct rte_flow_item_ipv4));
		DPAA2_PMD_WARN("Extract IPv4(%s) failed(%d)",
			hex_dump, ret);

		return ret;
	}

	if (mask_ipv4->hdr.src_addr) {
		key = &spec_ipv4->hdr.src_addr;
		mask = &mask_ipv4->hdr.src_addr;
		size = sizeof(rte_be32_t);

		ret = dpaa2_flow_add_ipaddr_extract_rule(flow, NET_PROT_IPV4,
			NH_FLD_IPV4_SRC_IP, key, mask, size, priv,
			attr->group, &local_cfg, dist_type);
		if (ret)
			return ret;
		flow->ip_src = NET_PROT_IPV4;
	}

	if (mask_ipv4->hdr.dst_addr) {
		key = &spec_ipv4->hdr.dst_addr;
		mask = &mask_ipv4->hdr.dst_addr;
		size = sizeof(rte_be32_t);

		ret = dpaa2_flow_add_ipaddr_extract_rule(flow, NET_PROT_IPV4,
			NH_FLD_IPV4_DST_IP, key, mask, size, priv,
			attr->group, &local_cfg, dist_type);
		if (ret)
			return ret;
		flow->ip_dst = NET_PROT_IPV4;
	}

	if (mask_ipv4->hdr.packet_id) {
		key = &spec_ipv4->hdr.packet_id;
		mask = &mask_ipv4->hdr.packet_id;
		size = sizeof(rte_be16_t);
		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_IP,
			NH_FLD_IP_ID, key, mask, size,
			priv, attr->group, &local_cfg, dist_type);
		if (ret)
			return ret;
	}

	if (mask_ipv4->hdr.fragment_offset) {
		key = &spec_ipv4->hdr.fragment_offset;
		mask = &mask_ipv4->hdr.fragment_offset;
		size = sizeof(rte_be16_t);

		ret = dpaa2_protocol_psr_bit_offset(&bit_offset,
			DPAA2_PARSER_IP_FRAG_ID);
		if (ret)
			return ret;

		ret = dpaa2_flow_identify_by_faf(priv, flow,
			bit_offset, dist_type, attr->group, &local_cfg);
		if (ret)
			return ret;

		if (spec_ipv4->hdr.fragment_offset)
			DPAA2_PMD_WARN("Unsupport Extract of frag offset");
	}

	if (mask_ipv4->hdr.next_proto_id) {
		key = &spec_ipv4->hdr.next_proto_id;
		mask = &mask_ipv4->hdr.next_proto_id;
		size = sizeof(uint8_t);

		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_IP,
			NH_FLD_IP_PROTO, key, mask, size, priv, attr->group,
			&local_cfg, dist_type);
		if (ret)
			return ret;
	}
	if (flow->ip_key == NET_PROT_IPV6) {
		DPAA2_PMD_ERR("IPv6 flow has been configured");
		return -EINVAL;
	}
	flow->ip_key = NET_PROT_IPV4;

	if (extract_cfg)
		(*extract_cfg) |= local_cfg;
	return 0;
}

static int
dpaa2_flow_ipv6_extract_rule_set(struct dpaa2_generic_flow *flow,
	const struct rte_flow_attr *attr,
	const struct rte_dpaa2_flow_item *dpaa2_pattern,
	int *extract_cfg, enum dpaa2_flow_dist_type dist_type)
{
	int ret, local_cfg = 0;
	uint32_t bit_offset;
	const struct rte_flow_item_ipv6 *spec_ipv6 = 0, *mask_ipv6 = 0;
	const void *key, *mask;
	struct dpaa2_dev_priv *priv = flow->priv;
	const char zero_cmp[NH_FLD_IPV6_ADDR_SIZE] = {0};
	int size;
	const struct rte_flow_item *pattern = &dpaa2_pattern->generic_item;
	char hex_dump[DPAA2_FLOW_HDR_HEX_DUMP_SIZE];

	/* Parse pattern list to get the matching parameters */
	spec_ipv6 = pattern->spec;
	mask_ipv6 = pattern->mask ? pattern->mask : &dpaa2_flow_item_ipv6_mask;

	if (dpaa2_pattern->in_tunnel) {
		if (spec_ipv6) {
			DPAA2_PMD_ERR("Tunnel-IPv6 distribution not support");
			return -ENOTSUP;
		}

		ret = dpaa2_protocol_psr_bit_offset(&bit_offset,
			DPAA2_PARSER_TUNNEL_IPV6_ID);
		if (ret)
			return ret;

		ret = dpaa2_flow_identify_by_faf(priv, flow,
			bit_offset, dist_type,
			attr->group, &local_cfg);
		if (ret)
			return ret;
	}

	ret = dpaa2_protocol_psr_bit_offset(&bit_offset,
		DPAA2_PARSER_IPV6_ID);
	if (ret)
		return ret;

	ret = dpaa2_flow_identify_by_faf(priv, flow,
		bit_offset, dist_type, attr->group, &local_cfg);
	if (ret)
		return ret;

	if (!spec_ipv6) {
		if (flow->ip_key == NET_PROT_IPV4) {
			DPAA2_PMD_ERR("IPv4 flow has been configured");
			return -EINVAL;
		}
		flow->ip_key = NET_PROT_IPV6;

		if (extract_cfg)
			(*extract_cfg) |= local_cfg;
		return 0;
	}

	ret = dpaa2_flow_extract_support((const uint8_t *)mask_ipv6,
			RTE_FLOW_ITEM_TYPE_IPV6);
	if (ret) {
		dpaa2_flow_hdr_hexdump(hex_dump, (const uint8_t *)mask_ipv6,
			sizeof(struct rte_flow_item_ipv6));
		DPAA2_PMD_WARN("Extract IPv6(%s) failed(%d)",
			hex_dump, ret);

		return ret;
	}

	if (memcmp(mask_ipv6->hdr.src_addr, zero_cmp, NH_FLD_IPV6_ADDR_SIZE)) {
		key = &spec_ipv6->hdr.src_addr[0];
		mask = &mask_ipv6->hdr.src_addr[0];
		size = NH_FLD_IPV6_ADDR_SIZE;

		ret = dpaa2_flow_add_ipaddr_extract_rule(flow, NET_PROT_IPV6,
			NH_FLD_IPV6_SRC_IP, key, mask, size, priv,
			attr->group, &local_cfg, dist_type);
		if (ret)
			return ret;
		flow->ip_src = NET_PROT_IPV6;
	}

	if (memcmp(mask_ipv6->hdr.dst_addr, zero_cmp, NH_FLD_IPV6_ADDR_SIZE)) {
		key = &spec_ipv6->hdr.dst_addr[0];
		mask = &mask_ipv6->hdr.dst_addr[0];
		size = NH_FLD_IPV6_ADDR_SIZE;

		ret = dpaa2_flow_add_ipaddr_extract_rule(flow, NET_PROT_IPV6,
			NH_FLD_IPV6_DST_IP, key, mask, size, priv,
			attr->group, &local_cfg, dist_type);
		if (ret)
			return ret;
		flow->ip_dst = NET_PROT_IPV6;
	}

	if (mask_ipv6->hdr.proto) {
		key = &spec_ipv6->hdr.proto;
		mask = &mask_ipv6->hdr.proto;
		size = sizeof(uint8_t);

		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_IP,
			NH_FLD_IP_PROTO, key, mask, size, priv, attr->group,
			&local_cfg, dist_type);
		if (ret)
			return ret;
	}
	if (flow->ip_key == NET_PROT_IPV4) {
		DPAA2_PMD_ERR("IPv4 flow has been configured");
		return -EINVAL;
	}
	flow->ip_key = NET_PROT_IPV6;

	if (extract_cfg)
		(*extract_cfg) |= local_cfg;
	return 0;
}

static int
dpaa2_flow_icmp_extract_rule_set(struct dpaa2_generic_flow *flow,
	const struct rte_flow_attr *attr,
	const struct rte_dpaa2_flow_item *dpaa2_pattern,
	int *extract_cfg, enum dpaa2_flow_dist_type dist_type)
{
	int ret, local_cfg = 0;
	uint32_t bit_offset;
	const struct rte_flow_item_icmp *spec, *mask;
	struct dpaa2_dev_priv *priv = flow->priv;
	const struct rte_flow_item *pattern = &dpaa2_pattern->generic_item;
	char hex_dump[DPAA2_FLOW_HDR_HEX_DUMP_SIZE];

	/* Parse pattern list to get the matching parameters */
	spec = pattern->spec;
	mask = pattern->mask ?
		pattern->mask : &dpaa2_flow_item_icmp_mask;

	if (dpaa2_pattern->in_tunnel) {
		DPAA2_PMD_ERR("Tunnel-ICMP distribution not support");
		return -ENOTSUP;
	}

	if (!spec) {
		ret = dpaa2_protocol_psr_bit_offset(&bit_offset,
			DPAA2_PARSER_ICMP_ID);
		if (ret)
			return ret;

		ret = dpaa2_flow_identify_by_faf(priv, flow,
			bit_offset, dist_type, attr->group, &local_cfg);
		if (ret)
			return ret;

		if (extract_cfg)
			(*extract_cfg) |= local_cfg;
		return 0;
	}

	ret = dpaa2_flow_extract_support((const uint8_t *)mask,
		RTE_FLOW_ITEM_TYPE_ICMP);
	if (ret) {
		dpaa2_flow_hdr_hexdump(hex_dump, (const uint8_t *)mask,
			sizeof(struct rte_flow_item_icmp));
		DPAA2_PMD_WARN("Extract ICMP(%s) failed(%d)",
			hex_dump, ret);

		return ret;
	}

	if (mask->hdr.icmp_type) {
		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_ICMP,
			NH_FLD_ICMP_TYPE, &spec->hdr.icmp_type,
			&mask->hdr.icmp_type, sizeof(uint8_t),
			priv, attr->group, &local_cfg, dist_type);
		if (ret)
			return ret;
	}

	if (mask->hdr.icmp_code) {
		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_ICMP,
			NH_FLD_ICMP_CODE, &spec->hdr.icmp_code,
			&mask->hdr.icmp_code, sizeof(uint8_t),
			priv, attr->group, &local_cfg, dist_type);
		if (ret)
			return ret;
	}

	if (extract_cfg)
		(*extract_cfg) |= local_cfg;

	return 0;
}

static int
dpaa2_flow_udp_extract_rule_set(struct dpaa2_generic_flow *flow,
	const struct rte_flow_attr *attr,
	const struct rte_dpaa2_flow_item *dpaa2_pattern,
	int *extract_cfg, enum dpaa2_flow_dist_type dist_type)
{
	int ret, local_cfg = 0;
	uint32_t bit_offset;
	const struct rte_flow_item_udp *spec, *mask;
	struct dpaa2_dev_priv *priv = flow->priv;
	const struct rte_flow_item *pattern = &dpaa2_pattern->generic_item;
	char hex_dump[DPAA2_FLOW_HDR_HEX_DUMP_SIZE];

	/* Parse pattern list to get the matching parameters */
	spec = pattern->spec;
	mask = pattern->mask ?
		pattern->mask : &dpaa2_flow_item_udp_mask;

	if (dpaa2_pattern->in_tunnel) {
		if (spec) {
			DPAA2_PMD_ERR("Tunnel-UDP distribution not support");
			return -ENOTSUP;
		}

		ret = dpaa2_protocol_psr_bit_offset(&bit_offset,
			DPAA2_PARSER_TUNNEL_UDP_ID);
		if (ret)
			return ret;

		ret = dpaa2_flow_identify_by_faf(priv, flow,
			bit_offset, dist_type, attr->group, &local_cfg);
		if (ret)
			return ret;
	}

	ret = dpaa2_protocol_psr_bit_offset(&bit_offset,
		DPAA2_PARSER_UDP_ID);
	if (ret)
		return ret;

	ret = dpaa2_flow_identify_by_faf(priv, flow,
		bit_offset, dist_type, attr->group, &local_cfg);
	if (ret)
		return ret;

	if (!spec) {
		if (extract_cfg)
			(*extract_cfg) |= local_cfg;
		return 0;
	}

	ret = dpaa2_flow_extract_support((const uint8_t *)mask,
		RTE_FLOW_ITEM_TYPE_UDP);
	if (ret) {
		dpaa2_flow_hdr_hexdump(hex_dump, (const uint8_t *)mask,
			sizeof(struct rte_flow_item_udp));
		DPAA2_PMD_ERR("Extract UDP(%s) failed(%d)",
			hex_dump, ret);

		return ret;
	}

	if (mask->hdr.src_port) {
		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_UDP,
			NH_FLD_UDP_PORT_SRC, &spec->hdr.src_port,
			&mask->hdr.src_port, sizeof(rte_be16_t),
			priv, attr->group, &local_cfg, dist_type);
		if (ret)
			return ret;
	}

	if (mask->hdr.dst_port) {
		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_UDP,
			NH_FLD_UDP_PORT_DST, &spec->hdr.dst_port,
			&mask->hdr.dst_port, sizeof(rte_be16_t),
			priv, attr->group, &local_cfg, dist_type);
		if (ret)
			return ret;
	}

	if (extract_cfg)
		(*extract_cfg) |= local_cfg;

	return 0;
}

static int
dpaa2_flow_tcp_extract_rule_set(struct dpaa2_generic_flow *flow,
	const struct rte_flow_attr *attr,
	const struct rte_dpaa2_flow_item *dpaa2_pattern,
	int *extract_cfg, enum dpaa2_flow_dist_type dist_type)
{
	int ret, local_cfg = 0;
	uint32_t bit_offset;
	const struct rte_flow_item_tcp *spec, *mask;
	struct dpaa2_dev_priv *priv = flow->priv;
	const struct rte_flow_item *pattern = &dpaa2_pattern->generic_item;
	char hex_dump[DPAA2_FLOW_HDR_HEX_DUMP_SIZE];

	/* Parse pattern list to get the matching parameters */
	spec = pattern->spec;
	mask = pattern->mask ?
		pattern->mask : &dpaa2_flow_item_tcp_mask;

	if (dpaa2_pattern->in_tunnel) {
		if (spec) {
			DPAA2_PMD_ERR("Tunnel-TCP distribution not support");
			return -ENOTSUP;
		}

		ret = dpaa2_protocol_psr_bit_offset(&bit_offset,
			DPAA2_PARSER_TUNNEL_TCP_ID);
		if (ret)
			return ret;

		ret = dpaa2_flow_identify_by_faf(priv, flow,
			bit_offset, dist_type, attr->group, &local_cfg);
		if (ret)
			return ret;
	}

	ret = dpaa2_protocol_psr_bit_offset(&bit_offset,
		DPAA2_PARSER_TCP_ID);
	if (ret)
		return ret;

	ret = dpaa2_flow_identify_by_faf(priv, flow,
		bit_offset, dist_type, attr->group, &local_cfg);
	if (ret)
		return ret;

	if (!spec) {
		if (extract_cfg)
			(*extract_cfg) |= local_cfg;
		return 0;
	}

	ret = dpaa2_flow_extract_support((const uint8_t *)mask,
		RTE_FLOW_ITEM_TYPE_TCP);
	if (ret) {
		dpaa2_flow_hdr_hexdump(hex_dump, (const uint8_t *)mask,
			sizeof(struct rte_flow_item_tcp));
		DPAA2_PMD_ERR("Extract TCP(%s) failed(%d)",
			hex_dump, ret);

		return ret;
	}

	if (mask->hdr.src_port) {
		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_TCP,
			NH_FLD_TCP_PORT_SRC, &spec->hdr.src_port,
			&mask->hdr.src_port, sizeof(rte_be16_t),
			priv, attr->group, &local_cfg, dist_type);
		if (ret)
			return ret;
	}

	if (mask->hdr.dst_port) {
		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_TCP,
			NH_FLD_TCP_PORT_DST, &spec->hdr.dst_port,
			&mask->hdr.dst_port, sizeof(rte_be16_t),
			priv, attr->group, &local_cfg, dist_type);
		if (ret)
			return ret;
	}

	if (extract_cfg)
		(*extract_cfg) |= local_cfg;

	return 0;
}

static int
dpaa2_flow_esp_extract_rule_set(struct dpaa2_generic_flow *flow,
	const struct rte_flow_attr *attr,
	const struct rte_dpaa2_flow_item *dpaa2_pattern,
	int *extract_cfg, enum dpaa2_flow_dist_type dist_type)
{
	int ret, local_cfg = 0;
	uint32_t bit_offset;
	const struct rte_flow_item_esp *spec, *mask;
	struct dpaa2_dev_priv *priv = flow->priv;
	const struct rte_flow_item *pattern =
		&dpaa2_pattern->generic_item;
	char hex_dump[DPAA2_FLOW_HDR_HEX_DUMP_SIZE];

	/* Parse pattern list to get the matching parameters */
	spec = pattern->spec;
	mask = pattern->mask ?
		pattern->mask : &dpaa2_flow_item_esp_mask;

	if (dpaa2_pattern->in_tunnel) {
		DPAA2_PMD_ERR("Tunnel-ESP distribution not support");
		return -ENOTSUP;
	}

	ret = dpaa2_protocol_psr_bit_offset(&bit_offset,
		DPAA2_PARSER_IPSEC_ESP_ID);
	if (ret)
		return ret;

	ret = dpaa2_flow_identify_by_faf(priv, flow,
		bit_offset, dist_type, attr->group, &local_cfg);
	if (ret)
		return ret;

	if (!spec) {
		if (extract_cfg)
			(*extract_cfg) |= local_cfg;
		return 0;
	}

	ret = dpaa2_flow_extract_support((const uint8_t *)mask,
		RTE_FLOW_ITEM_TYPE_ESP);
	if (ret) {
		dpaa2_flow_hdr_hexdump(hex_dump, (const uint8_t *)mask,
			sizeof(struct rte_flow_item_esp));
		DPAA2_PMD_ERR("Extract IPSEC ESP(%s) failed(%d)",
			hex_dump, ret);

		return ret;
	}

	if (mask->hdr.spi) {
		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_IPSEC_ESP,
			NH_FLD_IPSEC_ESP_SPI, &spec->hdr.spi,
			&mask->hdr.spi, sizeof(rte_be32_t),
			priv, attr->group, &local_cfg, dist_type);
		if (ret)
			return ret;
	}

	if (mask->hdr.seq) {
		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_IPSEC_ESP,
			NH_FLD_IPSEC_ESP_SEQUENCE_NUM, &spec->hdr.seq,
			&mask->hdr.seq, sizeof(rte_be32_t),
			priv, attr->group, &local_cfg, dist_type);
		if (ret)
			return ret;
	}

	if (extract_cfg)
		(*extract_cfg) |= local_cfg;

	return 0;
}

static int
dpaa2_flow_ah_extract_rule_set(struct dpaa2_generic_flow *flow,
	const struct rte_flow_attr *attr,
	const struct rte_dpaa2_flow_item *dpaa2_pattern,
	int *extract_cfg, enum dpaa2_flow_dist_type dist_type)
{
	int ret, local_cfg = 0;
	uint32_t bit_offset;
	const struct rte_flow_item_ah *spec, *mask;
	struct dpaa2_dev_priv *priv = flow->priv;
	const struct rte_flow_item *pattern =
		&dpaa2_pattern->generic_item;
	char hex_dump[DPAA2_FLOW_HDR_HEX_DUMP_SIZE];

	/* Parse pattern list to get the matching parameters */
	spec = pattern->spec;
	mask = pattern->mask ?
		pattern->mask : &dpaa2_flow_item_ah_mask;

	if (dpaa2_pattern->in_tunnel) {
		DPAA2_PMD_ERR("Tunnel-AH distribution not support");
		return -ENOTSUP;
	}

	ret = dpaa2_protocol_psr_bit_offset(&bit_offset,
		DPAA2_PARSER_IPSEC_AH_ID);
	if (ret)
		return ret;

	ret = dpaa2_flow_identify_by_faf(priv, flow,
		bit_offset, dist_type, attr->group, &local_cfg);
	if (ret)
		return ret;

	if (!spec) {
		if (extract_cfg)
			(*extract_cfg) |= local_cfg;
		return 0;
	}

	ret = dpaa2_flow_extract_support((const uint8_t *)mask,
		RTE_FLOW_ITEM_TYPE_AH);
	if (ret) {
		dpaa2_flow_hdr_hexdump(hex_dump, (const uint8_t *)mask,
			sizeof(struct rte_flow_item_ah));
		DPAA2_PMD_ERR("Extract IPSEC AH(%s) failed(%d)",
			hex_dump, ret);

		return ret;
	}

	if (mask->spi) {
		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_IPSEC_AH,
			NH_FLD_IPSEC_AH_SPI, &spec->spi,
			&mask->spi, sizeof(rte_be32_t),
			priv, attr->group, &local_cfg, dist_type);
		if (ret)
			return ret;
	}

	if (mask->seq_num) {
		DPAA2_PMD_ERR("AH seq distribution not support");
		return -ENOTSUP;
	}

	if (extract_cfg)
		(*extract_cfg) |= local_cfg;

	return 0;
}

static int
dpaa2_flow_sctp_extract_rule_set(struct dpaa2_generic_flow *flow,
	const struct rte_flow_attr *attr,
	const struct rte_dpaa2_flow_item *dpaa2_pattern,
	int *extract_cfg, enum dpaa2_flow_dist_type dist_type)
{
	int ret, local_cfg = 0;
	uint32_t bit_offset;
	const struct rte_flow_item_sctp *spec, *mask;
	struct dpaa2_dev_priv *priv = flow->priv;
	const struct rte_flow_item *pattern = &dpaa2_pattern->generic_item;
	char hex_dump[DPAA2_FLOW_HDR_HEX_DUMP_SIZE];

	/* Parse pattern list to get the matching parameters */
	spec = pattern->spec;
	mask = pattern->mask ?
		pattern->mask : &dpaa2_flow_item_sctp_mask;

	if (dpaa2_pattern->in_tunnel) {
		DPAA2_PMD_ERR("Tunnel-SCTP distribution not support");
		return -ENOTSUP;
	}

	ret = dpaa2_protocol_psr_bit_offset(&bit_offset,
			DPAA2_PARSER_SCTP_ID);
	if (ret)
		return ret;

	ret = dpaa2_flow_identify_by_faf(priv, flow,
		bit_offset, dist_type, attr->group, &local_cfg);
	if (ret)
		return ret;

	if (!spec) {
		if (extract_cfg)
			(*extract_cfg) |= local_cfg;
		return 0;
	}

	ret = dpaa2_flow_extract_support((const uint8_t *)mask,
		RTE_FLOW_ITEM_TYPE_SCTP);
	if (ret) {
		dpaa2_flow_hdr_hexdump(hex_dump, (const uint8_t *)mask,
			sizeof(struct rte_flow_item_sctp));
		DPAA2_PMD_ERR("Extract SCTP(%s) failed(%d)",
			hex_dump, ret);

		return ret;
	}

	if (mask->hdr.src_port) {
		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_SCTP,
			NH_FLD_SCTP_PORT_SRC, &spec->hdr.src_port,
			&mask->hdr.src_port, sizeof(rte_be16_t),
			priv, attr->group, &local_cfg, dist_type);
		if (ret)
			return ret;
	}

	if (mask->hdr.dst_port) {
		ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_SCTP,
			NH_FLD_SCTP_PORT_DST, &spec->hdr.dst_port,
			&mask->hdr.dst_port, sizeof(rte_be16_t),
			priv, attr->group, &local_cfg, dist_type);
		if (ret)
			return ret;
	}

	if (extract_cfg)
		(*extract_cfg) |= local_cfg;

	return 0;
}

static int
dpaa2_flow_gre_extract_rule_set(struct dpaa2_generic_flow *flow,
	const struct rte_flow_attr *attr,
	const struct rte_dpaa2_flow_item *dpaa2_pattern,
	int *extract_cfg, enum dpaa2_flow_dist_type dist_type)
{
	int ret, local_cfg = 0;
	uint32_t bit_offset;
	const struct rte_flow_item_gre *spec, *mask;
	struct dpaa2_dev_priv *priv = flow->priv;
	const struct rte_flow_item *pattern = &dpaa2_pattern->generic_item;
	char hex_dump[DPAA2_FLOW_HDR_HEX_DUMP_SIZE];

	/* Parse pattern list to get the matching parameters */
	spec = pattern->spec;
	mask = pattern->mask ?
		pattern->mask : &dpaa2_flow_item_gre_mask;

	if (dpaa2_pattern->in_tunnel) {
		DPAA2_PMD_ERR("Tunnel-GRE distribution not support");
		return -ENOTSUP;
	}

	if (!spec) {
		ret = dpaa2_protocol_psr_bit_offset(&bit_offset,
			DPAA2_PARSER_GRE_ID);
		if (ret)
			return ret;

		ret = dpaa2_flow_identify_by_faf(priv, flow,
			bit_offset, dist_type, attr->group, &local_cfg);
		if (ret)
			return ret;

		if (extract_cfg)
			(*extract_cfg) |= local_cfg;
		return 0;
	}

	ret = dpaa2_flow_extract_support((const uint8_t *)mask,
		RTE_FLOW_ITEM_TYPE_GRE);
	if (ret) {
		dpaa2_flow_hdr_hexdump(hex_dump, (const uint8_t *)mask,
			sizeof(struct rte_flow_item_gre));
		DPAA2_PMD_ERR("Extract GRE(%s) failed(%d)",
			hex_dump, ret);

		return ret;
	}

	if (!mask->protocol)
		return 0;

	ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_GRE,
		NH_FLD_GRE_TYPE, &spec->protocol, &mask->protocol,
		sizeof(rte_be16_t), priv, attr->group, &local_cfg, dist_type);
	if (ret)
		return ret;

	if (extract_cfg)
		(*extract_cfg) |= local_cfg;

	return 0;
}

static int
dpaa2_flow_vxlan_extract_rule_set(struct dpaa2_generic_flow *flow,
	const struct rte_flow_attr *attr,
	const struct rte_dpaa2_flow_item *dpaa2_pattern,
	int *extract_cfg, enum dpaa2_flow_dist_type dist_type)
{
	int ret, local_cfg = 0;
	uint32_t bit_offset;
	const struct rte_flow_item_vxlan *spec, *mask;
	struct dpaa2_dev_priv *priv = flow->priv;
	const struct rte_flow_item *pattern = &dpaa2_pattern->generic_item;
	char hex_dump[DPAA2_FLOW_HDR_HEX_DUMP_SIZE];

	/* Parse pattern list to get the matching parameters */
	spec = pattern->spec;
	mask = pattern->mask ?
		pattern->mask : &dpaa2_flow_item_vxlan_mask;

	if (dpaa2_pattern->in_tunnel) {
		DPAA2_PMD_ERR("Tunnel-VXLAN distribution not support");
		return -ENOTSUP;
	}

	ret = dpaa2_protocol_psr_bit_offset(&bit_offset,
		DPAA2_PARSER_VXLAN_ID);
	if (ret)
		return ret;

	ret = dpaa2_flow_identify_by_faf(priv, flow,
		bit_offset, dist_type, attr->group, &local_cfg);
	if (ret)
		return ret;

	if (!spec)
		goto quit;

	if (!priv->sp_protocol) {
		DPAA2_PMD_ERR("vXLAN flow with spec is not supported without SP.");
		return -ENOTSUP;
	}

	ret = dpaa2_flow_extract_support((const uint8_t *)mask,
		RTE_FLOW_ITEM_TYPE_VXLAN);
	if (ret) {
		dpaa2_flow_hdr_hexdump(hex_dump, (const uint8_t *)mask,
			sizeof(struct rte_flow_item_vxlan));
		DPAA2_PMD_ERR("Extract vXLAN(%s) failed(%d)",
			hex_dump, ret);

		return ret;
	}

	if (mask->flags) {
		if (spec->flags != VXLAN_HF_VNI) {
			DPAA2_PMD_ERR("vxlan flag(0x%02x) must be 0x%02x.",
				spec->flags, VXLAN_HF_VNI);
			return -EINVAL;
		}
		if (mask->flags != 0xff) {
			DPAA2_PMD_ERR("Not support to extract vxlan flag.");
			return -EINVAL;
		}
	}

	if (mask->vni[0] || mask->vni[1] || mask->vni[2]) {
		ret = dpaa2_flow_add_pr_extract_rule(flow,
			DPAA2_VXLAN_VNI_OFFSET,
			sizeof(mask->vni), spec->vni, mask->vni,
			priv, attr->group, &local_cfg, dist_type);
		if (ret)
			return ret;
	}

quit:
	if (extract_cfg)
		(*extract_cfg) |= local_cfg;

	return 0;
}

static int
dpaa2_flow_ecpri_extract_rule_set(struct dpaa2_generic_flow *flow,
	const struct rte_flow_attr *attr,
	const struct rte_dpaa2_flow_item *dpaa2_pattern,
	int *extract_cfg, enum dpaa2_flow_dist_type dist_type)
{
	int ret, local_cfg = 0;
	uint32_t bit_offset;
	const struct rte_flow_item_ecpri *spec, *mask;
	struct rte_flow_item_ecpri local_mask;
	struct dpaa2_dev_priv *priv = flow->priv;
	const struct rte_flow_item *pattern =
		&dpaa2_pattern->generic_item;
	int extract_nb, i;
	uint64_t rule_data[DPAA2_ECPRI_MAX_EXTRACT_NB];
	uint64_t mask_data[DPAA2_ECPRI_MAX_EXTRACT_NB];
	uint8_t extract_size[DPAA2_ECPRI_MAX_EXTRACT_NB];
	uint8_t extract_off[DPAA2_ECPRI_MAX_EXTRACT_NB];
	union dpaa2_sp_fafe_parse fafe;
	char hex_dump[DPAA2_FLOW_HDR_HEX_DUMP_SIZE];

	if (!priv->sp_protocol) {
		DPAA2_PMD_ERR("eCPRI flow is not supported without SP.");
		return -ENOTSUP;
	}

	/* Parse pattern list to get the matching parameters */
	spec = pattern->spec;
	if (pattern->mask) {
		memcpy(&local_mask, pattern->mask,
			sizeof(struct rte_flow_item_ecpri));
		local_mask.hdr.common.u32 =
			rte_be_to_cpu_32(local_mask.hdr.common.u32);
		mask = &local_mask;
	} else {
		mask = &dpaa2_flow_item_ecpri_mask;
	}

	if (dpaa2_pattern->in_tunnel) {
		DPAA2_PMD_ERR("Tunnel-ECPRI distribution not support");
		return -ENOTSUP;
	}

	ret = dpaa2_protocol_psr_bit_offset(&bit_offset,
		DPAA2_PARSER_ECPRI_ID);
	if (ret)
		return ret;

	ret = dpaa2_flow_identify_by_faf(priv, flow,
		bit_offset, dist_type,
		attr->group, &local_cfg);
	if (ret)
		return ret;

	if (!spec)
		goto quit;

	ret = dpaa2_flow_extract_support((const uint8_t *)mask,
		RTE_FLOW_ITEM_TYPE_ECPRI);
	if (ret) {
		dpaa2_flow_hdr_hexdump(hex_dump, (const uint8_t *)mask,
			sizeof(struct rte_flow_item_ecpri));
		DPAA2_PMD_ERR("Extract eCPRI(%s) failed(%d)",
			hex_dump, ret);

		return ret;
	}

	memset(&fafe, 0, sizeof(union dpaa2_sp_fafe_parse));
	extract_nb = dpaa2_parser_ecpri_extract(spec, mask,
		rule_data, mask_data, extract_size, extract_off,
		&fafe);
	if (extract_nb < 0) {
		DPAA2_PMD_ERR("Extract eCPRI from spec/mask failed(%d)",
			extract_nb);

		return extract_nb;
	}

	for (i = 0; i < extract_nb; i++) {
		ret = dpaa2_flow_add_pr_extract_rule(flow,
			extract_off[i], extract_size[i],
			&rule_data[i], &mask_data[i],
			priv, attr->group, extract_cfg,
			dist_type);
		if (ret)
			return ret;
	}

quit:
	if (extract_cfg)
		(*extract_cfg) |= local_cfg;

	return 0;
}

static int
dpaa2_flow_rocev2_extract_rule_set(struct dpaa2_generic_flow *flow,
	const struct rte_flow_attr *attr,
	const struct rte_dpaa2_flow_item *dpaa2_pattern,
	int *extract_cfg, enum dpaa2_flow_dist_type dist_type)
{
	int ret, local_cfg = 0;
	uint32_t bit_offset;
	const struct rte_flow_item_rocev2 *spec, *mask;
	struct rte_flow_item_rocev2 local_mask;
	struct dpaa2_dev_priv *priv = flow->priv;
	const struct rte_flow_item *pattern =
		&dpaa2_pattern->generic_item;
	uint8_t extract_nb = 0, i;
	uint64_t rule_data[DPAA2_IBTH_MAX_EXTRACT_NB];
	uint64_t mask_data[DPAA2_IBTH_MAX_EXTRACT_NB];
	uint8_t extract_size[DPAA2_IBTH_MAX_EXTRACT_NB];
	uint8_t extract_off[DPAA2_IBTH_MAX_EXTRACT_NB];
	char hex_dump[DPAA2_FLOW_HDR_HEX_DUMP_SIZE];

	if (!priv->sp_protocol) {
		DPAA2_PMD_ERR("ROCEV2 flow is not supported without SP.");
		return -ENOTSUP;
	}

	/* Parse pattern list to get the matching parameters */
	spec = pattern->spec;
	if (pattern->mask) {
		memcpy(&local_mask, pattern->mask,
			sizeof(struct rte_flow_item_rocev2));
		mask = &local_mask;
	} else {
		mask = &dpaa2_flow_item_rocev2_mask;
	}

	if (dpaa2_pattern->in_tunnel) {
		DPAA2_PMD_ERR("Tunnel-ROCEV2 distribution not support");
		return -ENOTSUP;
	}

	ret = dpaa2_protocol_psr_bit_offset(&bit_offset,
		DPAA2_PARSER_ROCEV2_ID);
	if (ret)
		return ret;

	ret = dpaa2_flow_identify_by_faf(priv, flow,
		bit_offset, dist_type, attr->group, &local_cfg);
	if (ret)
		return ret;

	if (!spec)
		goto quit;

	ret = dpaa2_flow_extract_support((const uint8_t *)mask,
		RTE_FLOW_ITEM_TYPE_ROCEV2);
	if (ret) {
		dpaa2_flow_hdr_hexdump(hex_dump, (const uint8_t *)mask,
			sizeof(struct rte_flow_item_rocev2));
		DPAA2_PMD_ERR("Extract ROCEv2(%s) failed(%d)",
			hex_dump, ret);

		return ret;
	}

	if (mask->opcode) {
		rule_data[extract_nb] = spec->opcode;
		mask_data[extract_nb] = mask->opcode;
		extract_size[extract_nb] = sizeof(uint8_t);
		extract_off[extract_nb] = DPAA2_ROCEV2_OPCODE_OFFSET;
		extract_nb++;
	}

	for (i = 0; i < ROCEV2_DEST_QP_SIZE; i++) {
		if (mask->dest_qp[i])
			break;
	}

	if (i < ROCEV2_DEST_QP_SIZE) {
		memcpy(&rule_data[extract_nb],
			&spec->dest_qp, ROCEV2_DEST_QP_SIZE);
		memcpy(&mask_data[extract_nb],
			&mask->dest_qp, ROCEV2_DEST_QP_SIZE);
		extract_size[extract_nb] = ROCEV2_DEST_QP_SIZE;
		extract_off[extract_nb] = DPAA2_ROCEV2_DST_QP_OFFSET;
		extract_nb++;
	}

	for (i = 0; i < extract_nb; i++) {
		ret = dpaa2_flow_add_pr_extract_rule(flow,
			extract_off[i], extract_size[i],
			&rule_data[i], &mask_data[i], priv,
			attr->group, extract_cfg, dist_type);
		if (ret)
			return ret;
	}

quit:
	if (extract_cfg)
		(*extract_cfg) |= local_cfg;

	return 0;
}

static int
dpaa2_flow_gtp_extract_rule_set(struct dpaa2_generic_flow *flow,
	const struct rte_flow_attr *attr,
	const struct rte_dpaa2_flow_item *dpaa2_pattern,
	int *extract_cfg, enum dpaa2_flow_dist_type dist_type)
{
	int ret, local_cfg = 0;
	uint32_t bit_offset;
	const struct rte_flow_item_gtp *spec, *mask;
	struct dpaa2_dev_priv *priv = flow->priv;
	const struct rte_flow_item *pattern =
		&dpaa2_pattern->generic_item;
	char hex_dump[DPAA2_FLOW_HDR_HEX_DUMP_SIZE];

	/* Parse pattern list to get the matching parameters */
	spec = pattern->spec;
	mask = pattern->mask ?
		pattern->mask : &dpaa2_flow_item_gtp_mask;

	if (dpaa2_pattern->in_tunnel) {
		DPAA2_PMD_ERR("Tunnel-GTP distribution not support");
		return -ENOTSUP;
	}

	if (!spec) {
		ret = dpaa2_protocol_psr_bit_offset(&bit_offset,
			DPAA2_PARSER_GTP_ID);
		if (ret)
			return ret;

		ret = dpaa2_flow_identify_by_faf(priv, flow,
			bit_offset, dist_type, attr->group, &local_cfg);
		if (ret)
			return ret;

		if (extract_cfg)
			(*extract_cfg) |= local_cfg;
		return 0;
	}

	ret = dpaa2_flow_extract_support((const uint8_t *)mask,
		RTE_FLOW_ITEM_TYPE_GTP);
	if (ret) {
		dpaa2_flow_hdr_hexdump(hex_dump, (const uint8_t *)mask,
			sizeof(struct rte_flow_item_gtp));
		DPAA2_PMD_ERR("Extract GTP(%s) failed(%d)",
			hex_dump, ret);

		return ret;
	}

	if (!mask->teid)
		return 0;

	ret = dpaa2_flow_add_hdr_extract_rule(flow, NET_PROT_GTP,
		NH_FLD_GTP_TEID, &spec->teid, &mask->teid,
		sizeof(rte_be32_t), priv, attr->group,
		&local_cfg, dist_type);
	if (ret)
		return ret;

	if (extract_cfg)
		(*extract_cfg) |= local_cfg;

	return 0;
}

static int
dpaa2_flow_raw_extract_rule_set(struct dpaa2_generic_flow *flow,
	const struct rte_flow_attr *attr,
	const struct rte_dpaa2_flow_item *dpaa2_pattern,
	int *extract_cfg, enum dpaa2_flow_dist_type dist_type)
{
	struct dpaa2_dev_priv *priv = flow->priv;
	int local_cfg = 0, ret;
	struct dpaa2_key_extract *key_extract;
	const struct rte_flow_item *pattern = &dpaa2_pattern->generic_item;
	const struct rte_flow_item_raw *spec = pattern->spec;
	const struct rte_flow_item_raw *mask = pattern->mask;

	/* Need both spec and mask */
	if (!spec || !mask) {
		DPAA2_PMD_ERR("spec or mask not present.");
		return -EINVAL;
	}

	if (spec->relative) {
		/* TBD: relative offset support.
		 * To support relative offset of previous L3 protocol item,
		 * extracts should be expanded to identify if the frame is:
		 * vlan or none-vlan.
		 *
		 * To support relative offset of previous L4 protocol item,
		 * extracts should be expanded to identify if the frame is:
		 * vlan/IPv4 or vlan/IPv6 or none-vlan/IPv4 or none-vlan/IPv6.
		 */
		DPAA2_PMD_ERR("relative not supported.");
		return -EINVAL;
	}

	if (spec->search) {
		DPAA2_PMD_ERR("search not supported.");
		return -EINVAL;
	}

	/* Spec len and mask len should be same */
	if (spec->length != mask->length) {
		DPAA2_PMD_ERR("Spec len and mask len mismatch.");
		return -EINVAL;
	}

	if (dist_type == DPAA2_FLOW_QOS_TYPE)
		key_extract = &priv->extract.qos_key_extract;
	else
		key_extract = &priv->extract.tc_key_extract[attr->group];

	ret = dpaa2_flow_extract_add_raw(priv,
		spec->offset, spec->length, dist_type,
		attr->group, &local_cfg);
	if (ret) {
		DPAA2_PMD_ERR("QoS Extract RAW add failed(%d).", ret);
		return ret;
	}

	if ((priv->num_rx_tc > 1 &&
		dist_type == DPAA2_FLOW_QOS_TYPE) ||
		dist_type == DPAA2_FLOW_FS_TYPE) {
		ret = dpaa2_flow_raw_rule_data_set(flow,
			&key_extract->key_profile,
			spec->offset, spec->length,
			spec->pattern, mask->pattern,
			dist_type);
		if (ret) {
			DPAA2_PMD_ERR("QoS RAW rule data set failed(%d)", ret);
			return ret;
		}
	}

	if (extract_cfg)
		(*extract_cfg) |= local_cfg;

	return 0;
}

static int
dpaa2_flow_geneve_extract_rule_set(struct dpaa2_generic_flow *flow,
	const struct rte_flow_attr *attr,
	const struct rte_dpaa2_flow_item *dpaa2_pattern,
	int *extract_cfg, enum dpaa2_flow_dist_type dist_type)
{
	int ret, local_cfg = 0;
	uint32_t bit_offset;
	const struct rte_flow_item_geneve *spec, *mask;
	struct dpaa2_dev_priv *priv = flow->priv;
	const struct rte_flow_item *pattern = &dpaa2_pattern->generic_item;
	char hex_dump[DPAA2_FLOW_HDR_HEX_DUMP_SIZE];

	if (!priv->sp_protocol) {
		DPAA2_PMD_ERR("GENEVE flow is not supported without SP.");
		return -ENOTSUP;
	}

	/* Parse pattern list to get the matching parameters */
	spec = pattern->spec;
	mask = pattern->mask ?
		pattern->mask : &dpaa2_flow_item_geneve_mask;

	if (dpaa2_pattern->in_tunnel) {
		DPAA2_PMD_ERR("Tunnel-GENEVE distribution not support");
		return -ENOTSUP;
	}

	ret = dpaa2_protocol_psr_bit_offset(&bit_offset,
		DPAA2_PARSER_GENEVE_ID);
	if (ret)
		return ret;

	ret = dpaa2_flow_identify_by_faf(priv, flow,
		bit_offset, dist_type, attr->group, &local_cfg);
	if (ret)
		return ret;

	if (!spec)
		goto quit;

	ret = dpaa2_flow_extract_support((const uint8_t *)mask,
		RTE_FLOW_ITEM_TYPE_GENEVE);
	if (ret) {
		dpaa2_flow_hdr_hexdump(hex_dump, (const uint8_t *)mask,
			sizeof(struct rte_flow_item_geneve));
		DPAA2_PMD_ERR("Extract GENEVE(%s) failed(%d)",
			hex_dump, ret);

		return ret;
	}

	if (mask->protocol && mask->protocol != 0xffff) {
		DPAA2_PMD_ERR("Not support to extract geneve protocol.");
		return -EINVAL;
	}

	if (mask->protocol) {
		ret = dpaa2_flow_add_pr_extract_rule(flow,
			DPAA2_GENEVE_PROTOCOL_OFFSET,
			sizeof(mask->protocol), &spec->protocol,
			&mask->protocol, priv, attr->group, &local_cfg,
			dist_type);
		if (ret)
			return ret;
	}

	if (mask->vni[0] || mask->vni[1] || mask->vni[2]) {
		ret = dpaa2_flow_add_pr_extract_rule(flow,
			DPAA2_GENEVE_VNI_OFFSET,
			sizeof(mask->vni), spec->vni,
			mask->vni,
			priv, attr->group, &local_cfg, dist_type);
		if (ret)
			return ret;
	}

quit:
	if (extract_cfg)
		(*extract_cfg) |= local_cfg;

	return 0;
}

static inline int
dpaa2_flow_verify_entry(struct dpaa2_dev_priv *priv,
	const struct rte_flow_attr *attr)
{
	struct dpaa2_dev_flow *curr = LIST_FIRST(&priv->flows);

	while (curr) {
		if (curr->qos_flow && curr->qos_flow->entry_index ==
			(attr->group * priv->fs_entries + attr->priority)) {
			DPAA2_PMD_ERR("Flow QoS.entry[%d] exists",
				curr->qos_flow->entry_index);
			return -EINVAL;
		}
		if (curr->fs_flow &&
			curr->fs_flow->tc_id == attr->group &&
			curr->fs_flow->entry_index == attr->priority) {
			DPAA2_PMD_ERR("Flow FS[%d].entry[%d] exists",
				attr->group, curr->fs_flow->entry_index);
			return -EINVAL;
		}
		curr = LIST_NEXT(curr, next);
	}

	return 0;
}

static inline struct rte_eth_dev *
dpaa2_flow_redirect_dev(struct dpaa2_dev_priv *priv,
	const struct rte_flow_action *action)
{
	const struct rte_flow_action_port_id *port_id;
	const struct rte_flow_action_ethdev *ethdev;
	int idx = -1;
	struct rte_eth_dev *dest_dev;

	if (action->type == RTE_FLOW_ACTION_TYPE_PORT_ID) {
		port_id = action->conf;
		if (!port_id->original)
			idx = port_id->id;
	} else if (action->type == RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT) {
		ethdev = action->conf;
		idx = ethdev->port_id;
	} else {
		return NULL;
	}

	if (idx >= 0) {
		if (!rte_eth_dev_is_valid_port(idx))
			return NULL;
		if (!rte_pmd_dpaa2_dev_is_dpaa2(idx))
			return NULL;
		dest_dev = &rte_eth_devices[idx];
	} else {
		dest_dev = priv->eth_dev;
	}

	return dest_dev;
}

static inline int
dpaa2_flow_verify_action(struct dpaa2_dev_priv *priv,
	const struct rte_flow_attr *attr,
	const struct rte_flow_action actions[])
{
	int end_of_list = 0, i, j = 0;
	const struct rte_flow_action_queue *dest_queue;
	const struct rte_flow_action_rss *rss_conf;
	struct dpaa2_queue *rxq;

	while (!end_of_list) {
		switch (actions[j].type) {
		case RTE_FLOW_ACTION_TYPE_QUEUE:
			dest_queue = actions[j].conf;
			if (dest_queue->index >= MAX_RX_QUEUES ||
				!priv->rx_vq[dest_queue->index]) {
				DPAA2_PMD_ERR("Invalid FSQ index(%d)",
					dest_queue->index);

				return -EINVAL;
			}
			rxq = priv->rx_vq[dest_queue->index];
			if (attr->group != rxq->tc_index) {
				DPAA2_PMD_ERR("FSQ(%d.%d) not in TC[%d]",
					rxq->tc_index, rxq->flow_id,
					attr->group);

				return -EINVAL;
			}
			break;
		case RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT:
		case RTE_FLOW_ACTION_TYPE_PORT_ID:
			if (!dpaa2_flow_redirect_dev(priv, &actions[j])) {
				DPAA2_PMD_ERR("Invalid port id of action");
				return -EINVAL;
			}
			break;
		case RTE_FLOW_ACTION_TYPE_RSS:
			rss_conf = actions[j].conf;
			if (rss_conf->queue_num > priv->dist_queues) {
				DPAA2_PMD_ERR("RSS number too large");
				return -EINVAL;
			}
			for (i = 0; i < (int)rss_conf->queue_num; i++) {
				if (rss_conf->queue[i] >= priv->nb_rx_queues) {
					DPAA2_PMD_ERR("RSS queue not in range");
					return -EINVAL;
				}
				rxq = priv->rx_vq[rss_conf->queue[i]];
				if (rxq->tc_index != attr->group) {
					DPAA2_PMD_ERR("RSS queue not in group");
					return -EINVAL;
				}
			}

			break;
		case RTE_FLOW_ACTION_TYPE_PF:
			/* Skip this action, have to add for vxlan*/
		case RTE_FLOW_ACTION_TYPE_DROP:
			break;
		case RTE_FLOW_ACTION_TYPE_METER_MARK:
			break;
		case RTE_FLOW_ACTION_TYPE_METER:
			break;
		case RTE_FLOW_ACTION_TYPE_END:
			end_of_list = 1;
			break;
		default:
			DPAA2_PMD_ERR("Invalid action type");
			return -EINVAL;
		}
		j++;
	}

	return 0;
}

static int
dpaa2_flow_fs_action_config(struct dpaa2_dev_priv *priv,
	struct dpaa2_generic_flow *flow,
	const struct rte_flow_action *rte_action)
{
	struct rte_eth_dev *dest_dev;
	struct dpaa2_dev_priv *dest_priv;
	const struct rte_flow_action_queue *dest_queue;
	struct dpaa2_queue *dest_q;
	uint64_t flc = 0;
	struct dpaa2_dev_flow_fs_action *fs_action;

	memset(&flow->flow_action, 0,
		sizeof(union dpaa2_dev_flow_action));
	fs_action = &flow->flow_action.fs_action;
	fs_action->action_type = rte_action->type;

	if (fs_action->action_type == RTE_FLOW_ACTION_TYPE_QUEUE) {
		dest_queue = rte_action->conf;
		if (dest_queue->index >= MAX_RX_QUEUES ||
			!priv->rx_vq[dest_queue->index]) {
			DPAA2_PMD_ERR("Invalid FSQ index(%d)",
				dest_queue->index);

			return -EINVAL;
		}
		dest_q = priv->rx_vq[dest_queue->index];
		if (flow->tc_id != dest_q->tc_index) {
			DPAA2_PMD_ERR("RXQ[%d](%d.%d) not in TC[%d]",
				dest_queue->index,
				dest_q->tc_index, dest_q->flow_id,
				flow->tc_id);

			return -EINVAL;
		}
		fs_action->fs_action_cfg.options =
			DPNI_FS_OPT_SET_FLC | DPNI_FS_OPT_SET_STASH_CONTROL;

		if (dest_q->data_stashing_off) {
			dpaa2_flc_stashing_set(DPAA2_FLC_DATA_STASHING,
				0, &flc);
		} else {
			dpaa2_flc_stashing_set(DPAA2_FLC_DATA_STASHING,
				1, &flc);
		}
		if ((dpaa2_svr_family & 0xffff0000) != SVR_LX2160A) {
			dpaa2_flc_stashing_set(DPAA2_FLC_ANNO_STASHING,
				1, &flc);
		}

		flc |= ((uint64_t)1) << DPAA2_FS_FLC_FS_MARK_OFFSET;
		flc |= ((uint64_t)dest_q->tc_index) << DPAA2_FS_FLC_TC_OFFSET;
		flc |= ((uint64_t)dest_q->flow_id) << DPAA2_FS_FLC_FLOW_OFFSET;
		fs_action->fs_action_cfg.flc = flc;
		fs_action->fs_action_cfg.flow_id = dest_q->flow_id;
	} else if (fs_action->action_type == RTE_FLOW_ACTION_TYPE_PORT_ID ||
		fs_action->action_type == RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT) {
		dest_dev = dpaa2_flow_redirect_dev(priv, rte_action);
		if (!dest_dev) {
			DPAA2_PMD_ERR("Invalid device to redirect");
			return -EINVAL;
		}

		dest_priv = dest_dev->data->dev_private;
		dest_q = dest_priv->tx_vq[0];
		fs_action->fs_action_cfg.options =
			DPNI_FS_OPT_REDIRECT_TO_DPNI_TX;
		fs_action->fs_action_cfg.redirect_obj_token =
			dest_priv->token;
		fs_action->fs_action_cfg.flow_id = dest_q->flow_id;
		strcpy(fs_action->dst_name, dest_priv->eth_dev->data->name);
	} else if (fs_action->action_type == RTE_FLOW_ACTION_TYPE_DROP) {
		fs_action->fs_action_cfg.options = DPNI_FS_OPT_DISCARD;
	} else {
		DPAA2_PMD_ERR("Flow action(%d) not supported!",
			fs_action->action_type);
		return -ENOTSUP;
	}

	return 0;
}

static inline uint16_t
dpaa2_flow_entry_size(uint16_t key_max_size)
{
	if (key_max_size > DPAA2_FLOW_ENTRY_MAX_SIZE) {
		DPAA2_PMD_ERR("Key size(%d) > max(%d)",
			key_max_size,
			DPAA2_FLOW_ENTRY_MAX_SIZE);

		return 0;
	}

	if (key_max_size > DPAA2_FLOW_ENTRY_MIN_SIZE)
		return DPAA2_FLOW_ENTRY_MAX_SIZE;

	return DPAA2_FLOW_ENTRY_MIN_SIZE;
}

static inline int
dpaa2_flow_clear_fs_table(struct dpaa2_dev_priv *priv,
	uint8_t tc_id)
{
	struct dpaa2_dev_flow *curr = LIST_FIRST(&priv->flows);
	int need_clear = 0, ret;
	struct fsl_mc_io *dpni = priv->hw;

	while (curr) {
		if (curr->fs_flow && curr->fs_flow->tc_id == tc_id) {
			need_clear = 1;
			break;
		}
		curr = LIST_NEXT(curr, next);
	}

	if (need_clear) {
		ret = dpni_clear_fs_entries(dpni, CMD_PRI_LOW,
				priv->token, tc_id);
		if (ret) {
			DPAA2_PMD_ERR("TC[%d] clear failed", tc_id);
			return ret;
		}
		priv->extract.tc_key_extract[tc_id].entry_num = 0;
		memset(priv->extract.tc_key_extract[tc_id].entry_map,
			0, priv->fs_entries);
	}

	return 0;
}

static int
dpaa2_flow_fs_rss_table_config(struct dpaa2_dev_priv *priv,
	uint8_t tc_id, uint16_t dist_size, int rss_dist)
{
	struct dpaa2_key_extract *tc_extract;
	uint8_t *key_cfg_buf;
	uint64_t key_cfg_iova;
	int ret;
	struct dpni_rx_dist_cfg tc_cfg;
	struct fsl_mc_io *dpni = priv->hw;
	uint16_t entry_size;
	uint16_t key_max_size;

	ret = dpaa2_flow_clear_fs_table(priv, tc_id);
	if (ret < 0) {
		DPAA2_PMD_ERR("TC[%d] clear failed", tc_id);
		return ret;
	}

	tc_extract = &priv->extract.tc_key_extract[tc_id];
	if (!tc_extract->dpkg.num_extracts)
		return 0;

	key_cfg_buf = priv->extract.tc_key_extract[tc_id].extract_param;
	key_cfg_iova = DPAA2_VADDR_TO_IOVA_AND_CHECK(key_cfg_buf,
		DPAA2_EXTRACT_PARAM_MAX_SIZE);
	if (key_cfg_iova == RTE_BAD_IOVA) {
		DPAA2_PMD_ERR("%s: No IOMMU map for key cfg(%p)",
			__func__, key_cfg_buf);

		return -ENOBUFS;
	}

	key_max_size = tc_extract->key_profile.key_max_size;
	entry_size = dpaa2_flow_entry_size(key_max_size);

	dpaa2_flow_extracts_log(priv, "Configure", tc_id);
	ret = dpkg_prepare_key_cfg(&tc_extract->dpkg,
			key_cfg_buf);
	if (ret < 0) {
		DPAA2_PMD_ERR("TC[%d] prepare key failed", tc_id);
		return ret;
	}

	memset(&tc_cfg, 0, sizeof(struct dpni_rx_dist_cfg));
	tc_cfg.dist_size = dist_size;
	tc_cfg.key_cfg_iova = key_cfg_iova;
	if (rss_dist)
		tc_cfg.enable = true;
	else
		tc_cfg.enable = false;
	tc_cfg.tc = tc_id;
	ret = dpni_set_rx_hash_dist(dpni, CMD_PRI_LOW,
			priv->token, &tc_cfg);
	if (ret < 0) {
		if (rss_dist) {
			DPAA2_PMD_ERR("RSS TC[%d] set failed",
				tc_id);
		} else {
			DPAA2_PMD_ERR("FS TC[%d] hash disable failed",
				tc_id);
		}

		return ret;
	}

	if (rss_dist)
		return 0;

	tc_cfg.enable = true;
	tc_cfg.fs_miss_flow_id = priv->default_flow;
	ret = dpni_set_rx_fs_dist(dpni, CMD_PRI_LOW,
			priv->token, &tc_cfg);
	if (ret < 0) {
		DPAA2_PMD_ERR("TC[%d] FS configured failed", tc_id);
		return ret;
	}

	ret = dpaa2_flow_rule_add_all(priv, DPAA2_FLOW_FS_TYPE,
			entry_size, tc_id);
	if (ret)
		return ret;

	return 0;
}

static int
dpaa2_flow_qos_table_config(struct dpaa2_dev_priv *priv,
	int rss_dist)
{
	struct dpaa2_key_extract *qos_extract;
	uint8_t *key_cfg_buf;
	uint64_t key_cfg_iova;
	int ret;
	struct dpni_qos_tbl_cfg qos_cfg;
	struct fsl_mc_io *dpni = priv->hw;
	uint16_t entry_size;
	uint16_t key_max_size;
	struct dpaa2_dev_flow *flow;

	if (!rss_dist && priv->num_rx_tc <= 1) {
		/* QoS table is effecitive for FS multiple TCs or RSS.*/
		return 0;
	}

	flow = LIST_FIRST(&priv->flows);
	while (flow) {
		if (!flow->qos_flow) {
			flow = LIST_NEXT(flow, next);
			continue;
		}
		/** Clear existing QoS table if there is qos flow configured.*/
		ret = dpni_clear_qos_table(dpni, CMD_PRI_LOW,
				priv->token);
		if (ret < 0) {
			DPAA2_PMD_ERR("QoS table clear failed(%d)", ret);
			return ret;
		}
		priv->extract.qos_key_extract.entry_num = 0;
		memset(priv->extract.qos_key_extract.entry_map,
			0, priv->qos_entries);
		break;
	}

	qos_extract = &priv->extract.qos_key_extract;
	if (!qos_extract->dpkg.num_extracts)
		return 0;

	key_cfg_buf = priv->extract.qos_key_extract.extract_param;
	key_cfg_iova = DPAA2_VADDR_TO_IOVA_AND_CHECK(key_cfg_buf,
		DPAA2_EXTRACT_PARAM_MAX_SIZE);
	if (key_cfg_iova == RTE_BAD_IOVA) {
		DPAA2_PMD_ERR("%s: No IOMMU map for key cfg(%p)",
			__func__, key_cfg_buf);

		return -ENOBUFS;
	}

	key_max_size = qos_extract->key_profile.key_max_size;
	entry_size = dpaa2_flow_entry_size(key_max_size);

	dpaa2_flow_extracts_log(priv, "Configure", MAX_TCS);

	ret = dpkg_prepare_key_cfg(&qos_extract->dpkg,
			key_cfg_buf);
	if (ret < 0) {
		DPAA2_PMD_ERR("QoS prepare extract failed");
		return ret;
	}
	memset(&qos_cfg, 0, sizeof(struct dpni_qos_tbl_cfg));
	qos_cfg.keep_entries = true;
	qos_cfg.key_cfg_iova = key_cfg_iova;
	if (rss_dist) {
		qos_cfg.discard_on_miss = true;
	} else {
		qos_cfg.discard_on_miss = false;
		qos_cfg.default_tc = priv->default_tc;
	}

	ret = dpni_set_qos_table(dpni, CMD_PRI_LOW,
			priv->token, &qos_cfg);
	if (ret < 0) {
		DPAA2_PMD_ERR("QoS table set failed");
		return ret;
	}

	ret = dpaa2_flow_rule_add_all(priv, DPAA2_FLOW_QOS_TYPE,
			entry_size, 0);
	if (ret)
		return ret;

	return 0;
}

static int
dpaa2_flow_item_convert(const struct rte_flow_item pattern[],
	struct rte_dpaa2_flow_item **dpaa2_pattern, int sp_protocol)
{
	struct rte_dpaa2_flow_item *new_pattern;
	int num = 0, tunnel_start = 0;

	while (1) {
		num++;
		if (pattern[num].type == RTE_FLOW_ITEM_TYPE_END)
			break;
	}

	new_pattern = rte_malloc(NULL, sizeof(struct rte_dpaa2_flow_item) * num,
			RTE_CACHE_LINE_SIZE);
	if (!new_pattern) {
		DPAA2_PMD_ERR("Failed to alloc %d flow items", num);
		return -ENOMEM;
	}

	num = 0;
	while (pattern[num].type != RTE_FLOW_ITEM_TYPE_END) {
		rte_memcpy(&new_pattern[num].generic_item, &pattern[num],
			sizeof(struct rte_flow_item));
		new_pattern[num].in_tunnel = 0;

		if (pattern[num].type == RTE_FLOW_ITEM_TYPE_VXLAN)
			tunnel_start = 1;
		else if (tunnel_start && sp_protocol)
			new_pattern[num].in_tunnel = 1;
		num++;
	}

	new_pattern[num].generic_item.type = RTE_FLOW_ITEM_TYPE_END;
	*dpaa2_pattern = new_pattern;

	return 0;
}

static int
dpaa2_flow_table_update(struct dpaa2_dev_priv *priv,
	uint16_t dist_size, enum dpaa2_flow_dist_type dist_type,
	uint8_t tc_id, int is_rss)
{
	int ret;

	if (dist_type == DPAA2_FLOW_FS_TYPE) {
		ret = dpaa2_flow_fs_rss_table_config(priv, tc_id,
			dist_size, is_rss);
		if (ret)
			return ret;
	} else if (dist_type == DPAA2_FLOW_QOS_TYPE) {
		ret = dpaa2_flow_qos_table_config(priv, false);
		if (ret)
			return ret;
	} else {
		DPAA2_PMD_ERR("Invalid dist type(%d)!", dist_type);
		return -EINVAL;
	}

	return 0;
}

static int
dpaa2_flow_action_meter_mark_init(struct dpaa2_dev_priv *priv,
	uint32_t mtr_id, struct rte_flow_action_meter_mark *meter_mark)
{
	struct dpaa2_dev_meter *meter;
	struct dpaa2_dev_meter_profile *profile;
	struct dpaa2_dev_meter_policy *policy;
	int found = 0;

	meter = LIST_FIRST(&priv->meters);
	while (meter) {
		if (meter->meter_id == mtr_id) {
			found = 1;
			break;
		}
		meter = LIST_NEXT(meter, next);
	}

	if (!found) {
		DPAA2_PMD_ERR("Meter ID(%d) is not found!", mtr_id);
		return -ENXIO;
	}

	found = 0;
	profile = LIST_FIRST(&priv->profiles);
	while (profile) {
		if (profile->profile_id == meter->profile_id) {
			found = 1;
			break;
		}
		profile = LIST_NEXT(profile, next);
	}
	if (!found) {
		DPAA2_PMD_ERR("Meter ID(%d)'s profile(%d) not exist!",
			mtr_id, meter->profile_id);
		return -ENXIO;
	}

	found = 0;
	policy = LIST_FIRST(&priv->policies);
	while (policy) {
		if (policy->policy_id == meter->policy_id) {
			found = 1;
			break;
		}
		policy = LIST_NEXT(policy, next);
	}
	if (!found) {
		/** Option.*/
		DPAA2_PMD_WARN("Meter ID(%d)'s policy(%d) not exist!",
			mtr_id, meter->policy_id);
		policy = NULL;
	}

	meter_mark->profile = (void *)profile;
	meter_mark->policy = (void *)policy;
	meter_mark->color_mode = 1;
	meter_mark->init_color = RTE_COLOR_GREEN;

	return 0;
}

static int
dpaa2_flow_set_police_action(struct dpaa2_dev_priv *priv,
	uint8_t tc_id, const struct rte_flow_action_meter_mark *meter_mark)
{
	struct dpni_rx_tc_policing_cfg policing_cfg;
	const struct dpaa2_dev_meter_profile *dpaa2_profile;
	const struct dpaa2_dev_meter_policy *dpaa2_policy = NULL;
	int ret;

	dpaa2_profile = (void *)meter_mark->profile;
	if (!dpaa2_profile) {
		DPAA2_PMD_ERR("Meter profile not specified!");
		return -EINVAL;
	}

	/** Blind as default.*/
	policing_cfg.options = 0;
	if (meter_mark->color_mode)
		policing_cfg.options = DPNI_POLICER_OPT_COLOR_AWARE;
	if (meter_mark->policy)
		dpaa2_policy = (void *)meter_mark->policy;
	if (dpaa2_policy && dpaa2_policy->red_drop) {
		policing_cfg.options |= DPNI_POLICER_OPT_DISCARD_RED;
	} else if (!dpaa2_policy) {
		/** Default: Red is discarded if no policy specified.*/
		policing_cfg.options |= DPNI_POLICER_OPT_DISCARD_RED;
	}

	if (meter_mark->init_color == RTE_COLOR_GREEN) {
		policing_cfg.default_color = DPNI_POLICER_COLOR_GREEN;
	} else if (meter_mark->init_color == RTE_COLOR_YELLOW) {
		policing_cfg.default_color = DPNI_POLICER_COLOR_YELLOW;
	} else if (meter_mark->init_color == RTE_COLOR_RED) {
		policing_cfg.default_color = DPNI_POLICER_COLOR_RED;
	} else {
		DPAA2_PMD_ERR("Invalid meter init color(%d)",
			meter_mark->init_color);
		return -EINVAL;
	}

	policing_cfg.mode = dpaa2_profile->mode;
	if (policing_cfg.mode < DPNI_POLICER_MODE_NONE ||
		policing_cfg.mode > DPNI_POLICER_MODE_RFC_4115) {
		DPAA2_PMD_ERR("Invalid policer mode(%d)",
			policing_cfg.mode);
		return -EINVAL;
	}
	policing_cfg.units = dpaa2_profile->policer_unit;
	if (policing_cfg.units < DPNI_POLICER_UNIT_BYTES_L3 ||
		policing_cfg.units > DPNI_POLICER_UNIT_BYTES_L2_WITHOUT_FCS) {
		DPAA2_PMD_ERR("Invalid policer units(%d)",
			policing_cfg.units);
		return -EINVAL;
	}
	policing_cfg.cir = dpaa2_profile->cir;
	policing_cfg.cbs = dpaa2_profile->cbs;
	policing_cfg.eir = dpaa2_profile->pir;
	policing_cfg.ebs = dpaa2_profile->pbs;

	ret = dpni_set_rx_tc_policing(priv->hw, CMD_PRI_LOW,
		priv->token, tc_id, &policing_cfg);
	DPAA2_PMD_INFO("%s RX TC%d policer configure %s.",
		priv->eth_dev->data->name, tc_id,
		ret ? "failed" : "successfully");

	return ret;
}

static int
dpaa2_flow_action_is_rss(const struct rte_flow_action actions[])
{
	int end_of_list = 0, i = 0;
	int is_rss = false;

	while (!end_of_list) {
		switch (actions[i].type) {
		case RTE_FLOW_ACTION_TYPE_QUEUE:
		case RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT:
		case RTE_FLOW_ACTION_TYPE_PORT_ID:
		case RTE_FLOW_ACTION_TYPE_DROP:
			is_rss = false;
			break;
		case RTE_FLOW_ACTION_TYPE_RSS:
			is_rss = true;
			break;
		case RTE_FLOW_ACTION_TYPE_METER_MARK:
			is_rss = false;
			break;
		case RTE_FLOW_ACTION_TYPE_METER:
			is_rss = false;
			break;
		case RTE_FLOW_ACTION_TYPE_PF:
			/* Skip this action, have to add for vxlan*/
			break;
		case RTE_FLOW_ACTION_TYPE_END:
			end_of_list = 1;
			break;
		default:
			DPAA2_PMD_ERR("Invalid action[%d]'s type(%d)",
				i, actions[i].type);
		}
		i++;
	}

	return is_rss;
}

static int
dpaa2_flow_fs_action_update(struct dpaa2_dev_priv *priv,
	struct dpaa2_generic_flow *flow,
	const struct rte_flow_action actions[],
	struct dpkg_profile_cfg *kg_cfg)
{
	int end_of_list = 0, ret = 0, i = 0;
	struct dpaa2_dev_flow_fs_action *fs_action;
	const struct rte_flow_action_rss *rss_conf;
	const struct rte_flow_action_meter *meter;
	struct rte_flow_action_meter_mark meter_mark;

	fs_action = &flow->flow_action.fs_action;

	while (!end_of_list) {
		switch (actions[i].type) {
		case RTE_FLOW_ACTION_TYPE_QUEUE:
		case RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT:
		case RTE_FLOW_ACTION_TYPE_PORT_ID:
		case RTE_FLOW_ACTION_TYPE_DROP:
			ret = dpaa2_flow_fs_action_config(priv, flow,
					&actions[i]);
			if (ret)
				goto end_action_set;

			break;
		case RTE_FLOW_ACTION_TYPE_RSS:
			rss_conf = actions[i].conf;
			ret = dpaa2_distset_to_dpkg_profile_cfg(rss_conf->types,
					kg_cfg);
			if (ret) {
				DPAA2_PMD_ERR("TC[%d] distset RSS failed(%d)",
					flow->tc_id, ret);
				goto end_action_set;
			}
			fs_action->action_type = RTE_FLOW_ACTION_TYPE_RSS;
			fs_action->rss_queues = priv->dist_queues;

			break;
		case RTE_FLOW_ACTION_TYPE_METER_MARK:
			rte_memcpy(&meter_mark, actions[i].conf,
				sizeof(meter_mark));
			ret = dpaa2_flow_set_police_action(priv,
				flow->tc_id, &meter_mark);
			if (ret)
				goto end_action_set;
			break;
		case RTE_FLOW_ACTION_TYPE_METER:
			meter = actions[i].conf;
			ret = dpaa2_flow_action_meter_mark_init(priv,
				meter->mtr_id, &meter_mark);
			if (ret)
				goto end_action_set;
			ret = dpaa2_flow_set_police_action(priv,
				flow->tc_id, &meter_mark);
			if (ret)
				goto end_action_set;

			break;
		case RTE_FLOW_ACTION_TYPE_PF:
			/* Skip this action, have to add for vxlan*/
			break;
		case RTE_FLOW_ACTION_TYPE_END:
			end_of_list = 1;
			break;
		default:
			DPAA2_PMD_ERR("Invalid action[%d]'s type(%d)",
				i, actions[i].type);
			ret = -ENOTSUP;
			goto end_action_set;
		}
		i++;
	}

end_action_set:
	if (ret)
		return ret;
	if (i < 1) {
		DPAA2_PMD_ERR("No action is set!");
		return -EINVAL;
	}
	if (i > 2) {
		DPAA2_PMD_WARN("Only last of %d actions is applied",
			i - 1);
	}

	return 0;
}

static int
dpaa2_flow_generic_extract_rule_set(struct dpaa2_generic_flow *flow,
	const struct rte_flow_attr *attr,
	const struct rte_flow_item pattern[], int is_rss,
	enum dpaa2_flow_dist_type dist_type)
{
	int extract_cfg = 0, end_of_list = 0;
	int ret = 0, i = 0;
	struct dpaa2_dev_priv *priv = flow->priv;
	uint16_t key_size;
	struct dpaa2_key_extract *key_extract;
	struct rte_dpaa2_flow_item *dpaa2_pattern = NULL;

	ret = dpaa2_flow_item_convert(pattern, &dpaa2_pattern,
		priv->sp_protocol);
	if (ret)
		return ret;

	flow->ip_key = NET_PROT_NONE;
	flow->ip_src = NET_PROT_NONE;
	flow->ip_dst = NET_PROT_NONE;

	/* Parse pattern list to get the matching parameters */
	while (!end_of_list) {
		switch (pattern[i].type) {
		case RTE_FLOW_ITEM_TYPE_ETH:
			ret = dpaa2_flow_eth_extract_rule_set(flow, attr,
				&dpaa2_pattern[i], &extract_cfg, dist_type);
			if (ret) {
				DPAA2_PMD_ERR("ETH flow config failed!");
				goto end_extract_set;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_VLAN:
			ret = dpaa2_flow_vlan_extract_rule_set(flow, attr,
				&dpaa2_pattern[i], &extract_cfg, dist_type);
			if (ret) {
				DPAA2_PMD_ERR("vLan flow config failed!");
				goto end_extract_set;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_IPV4:
			ret = dpaa2_flow_ipv4_extract_rule_set(flow, attr,
				&dpaa2_pattern[i], &extract_cfg, dist_type);
			if (ret) {
				DPAA2_PMD_ERR("IPV4 flow config failed!");
				goto end_extract_set;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_IPV6:
			ret = dpaa2_flow_ipv6_extract_rule_set(flow, attr,
				&dpaa2_pattern[i], &extract_cfg, dist_type);
			if (ret) {
				DPAA2_PMD_ERR("IPV6 flow config failed!");
				goto end_extract_set;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_ICMP:
			ret = dpaa2_flow_icmp_extract_rule_set(flow, attr,
				&dpaa2_pattern[i], &extract_cfg, dist_type);
			if (ret) {
				DPAA2_PMD_ERR("ICMP flow config failed!");
				goto end_extract_set;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_UDP:
			ret = dpaa2_flow_udp_extract_rule_set(flow, attr,
				&dpaa2_pattern[i], &extract_cfg, dist_type);
			if (ret) {
				DPAA2_PMD_ERR("UDP flow config failed!");
				goto end_extract_set;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_TCP:
			ret = dpaa2_flow_tcp_extract_rule_set(flow, attr,
				&dpaa2_pattern[i], &extract_cfg, dist_type);
			if (ret) {
				DPAA2_PMD_ERR("TCP flow config failed!");
				goto end_extract_set;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_SCTP:
			ret = dpaa2_flow_sctp_extract_rule_set(flow, attr,
				&dpaa2_pattern[i], &extract_cfg, dist_type);
			if (ret) {
				DPAA2_PMD_ERR("SCTP flow config failed!");
				goto end_extract_set;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_ESP:
			ret = dpaa2_flow_esp_extract_rule_set(flow, attr,
				&dpaa2_pattern[i], &extract_cfg, dist_type);
			if (ret) {
				DPAA2_PMD_ERR("ESP flow config failed!");
				goto end_extract_set;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_AH:
			ret = dpaa2_flow_ah_extract_rule_set(flow, attr,
				&dpaa2_pattern[i], &extract_cfg, dist_type);
			if (ret) {
				DPAA2_PMD_ERR("AH flow config failed!");
				goto end_extract_set;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_GRE:
			ret = dpaa2_flow_gre_extract_rule_set(flow, attr,
				&dpaa2_pattern[i], &extract_cfg, dist_type);
			if (ret) {
				DPAA2_PMD_ERR("GRE flow config failed!");
				goto end_extract_set;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_VXLAN:
			ret = dpaa2_flow_vxlan_extract_rule_set(flow, attr,
				&dpaa2_pattern[i], &extract_cfg, dist_type);
			if (ret) {
				DPAA2_PMD_ERR("VXLAN flow config failed!");
				goto end_extract_set;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_ECPRI:
			ret = dpaa2_flow_ecpri_extract_rule_set(flow, attr,
				&dpaa2_pattern[i], &extract_cfg, dist_type);
			if (ret) {
				DPAA2_PMD_ERR("ECPRI flow config failed!");
				goto end_extract_set;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_GTP:
			ret = dpaa2_flow_gtp_extract_rule_set(flow, attr,
				&dpaa2_pattern[i], &extract_cfg, dist_type);
			if (ret) {
				DPAA2_PMD_ERR("GTP flow config failed!");
				goto end_extract_set;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_ROCEV2:
			ret = dpaa2_flow_rocev2_extract_rule_set(flow, attr,
				&dpaa2_pattern[i], &extract_cfg, dist_type);
			if (ret) {
				DPAA2_PMD_ERR("RoCEV2 flow config failed!");
				goto end_extract_set;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_GENEVE:
			ret = dpaa2_flow_geneve_extract_rule_set(flow, attr,
				&dpaa2_pattern[i], &extract_cfg, dist_type);
			if (ret) {
				DPAA2_PMD_ERR("GENEVE flow config failed!");
				goto end_extract_set;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_RAW:
			ret = dpaa2_flow_raw_extract_rule_set(flow, attr,
				&dpaa2_pattern[i], &extract_cfg, dist_type);
			if (ret) {
				DPAA2_PMD_ERR("RAW flow config failed!");
				goto end_extract_set;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_END:
			end_of_list = 1;
			break; /*End of List*/
		default:
			DPAA2_PMD_ERR("Invalid flow item[%d] type(%d)",
				i, pattern[i].type);
			ret = -ENOTSUP;
			goto end_extract_set;
		}
		i++;
	}

	if (dist_type == DPAA2_FLOW_QOS_TYPE)
		key_extract = &priv->extract.qos_key_extract;
	else
		key_extract = &priv->extract.tc_key_extract[attr->group];

	key_size = key_extract->key_profile.key_max_size;
	flow->rule_cfg.key_size = dpaa2_flow_entry_size(key_size);

	if (!extract_cfg)
		goto end_extract_set;

	ret = dpaa2_flow_table_update(priv, priv->dist_queues,
		dist_type, attr->group, is_rss);

end_extract_set:
	if (dpaa2_pattern)
		rte_free(dpaa2_pattern);

	return ret;
}

static inline int
dpaa2_flow_verify_attr(struct dpni_attr *dpni_attr,
	const struct rte_flow_attr *attr)
{
	int ret = 0;

	if (unlikely(attr->group >= dpni_attr->num_rx_tcs)) {
		DPAA2_PMD_ERR("Group/TC(%d) is out of range(%d)",
			attr->group, dpni_attr->num_rx_tcs);
		ret = -ENOTSUP;
	}
	if (unlikely(attr->priority >= dpni_attr->fs_entries)) {
		DPAA2_PMD_ERR("Priority(%d) within group is out of range(%d)",
			attr->priority, dpni_attr->fs_entries);
		ret = -ENOTSUP;
	}
	if (unlikely(attr->egress)) {
		DPAA2_PMD_ERR("Egress flow configuration is not supported");
		ret = -ENOTSUP;
	}
	if (unlikely(!attr->ingress)) {
		DPAA2_PMD_ERR("Ingress flag must be configured");
		ret = -EINVAL;
	}
	return ret;
}

static inline int
dpaa2_flow_verify_patterns(const struct rte_flow_item pattern[],
	int sp_support)
{
	unsigned int i, j, is_found = 0;
	int ret = 0;
	const enum rte_flow_item_type *hp_supported;
	const enum rte_flow_item_type *sp_supported;
	uint64_t hp_supported_num, sp_supported_num;

	hp_supported = dpaa2_hp_supported_pattern_type;
	hp_supported_num = RTE_DIM(dpaa2_hp_supported_pattern_type);

	sp_supported = dpaa2_sp_supported_pattern_type;
	sp_supported_num = RTE_DIM(dpaa2_sp_supported_pattern_type);

	for (j = 0; pattern[j].type != RTE_FLOW_ITEM_TYPE_END; j++) {
		is_found = 0;
		for (i = 0; i < hp_supported_num; i++) {
			if (hp_supported[i] == pattern[j].type) {
				is_found = 1;
				break;
			}
		}
		if (is_found)
			continue;
		if (sp_support) {
			for (i = 0; i < sp_supported_num; i++) {
				if (sp_supported[i] == pattern[j].type) {
					is_found = 1;
					break;
				}
			}
		}
		if (!is_found) {
			DPAA2_PMD_WARN("Flow type(%d) not supported",
				pattern[j].type);
			ret = -ENOTSUP;
			break;
		}
	}

	return ret;
}

static inline int
dpaa2_flow_check_actions_support(const struct rte_flow_action actions[])
{
	unsigned int i, j, is_found = 0;

	for (j = 0; actions[j].type != RTE_FLOW_ACTION_TYPE_END; j++) {
		is_found = 0;
		for (i = 0; i < RTE_DIM(dpaa2_supported_action_type); i++) {
			if (dpaa2_supported_action_type[i] == actions[j].type) {
				is_found = 1;
				break;
			}
		}
		if (!is_found) {
			DPAA2_PMD_ERR("actions[%d].type(%d) not supported",
				j, actions[j].type);
			return -ENOTSUP;
		}
	}
	for (j = 0; actions[j].type != RTE_FLOW_ACTION_TYPE_END; j++) {
		if (actions[j].type != RTE_FLOW_ACTION_TYPE_DROP &&
			!actions[j].conf) {
			DPAA2_PMD_ERR("No config for actions[%d].type(%d)",
				j, actions[j].type);
			return -EINVAL;
		}
	}

	return 0;
}

static int
dpaa2_flow_validate(struct rte_eth_dev *dev,
	const struct rte_flow_attr *flow_attr,
	const struct rte_flow_item pattern[],
	const struct rte_flow_action actions[],
	struct rte_flow_error *error)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpni_attr dpni_attr;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;
	uint16_t token = priv->token;
	int ret = 0;

	memset(&dpni_attr, 0, sizeof(struct dpni_attr));
	ret = dpni_get_attributes(dpni, CMD_PRI_LOW, token, &dpni_attr);
	if (ret < 0) {
		DPAA2_PMD_ERR("Get dpni@%d attribute failed(%d)",
			priv->hw_id, ret);
		rte_flow_error_set(error, EPERM,
			RTE_FLOW_ERROR_TYPE_ATTR,
			flow_attr, "invalid");
		return ret;
	}

	/* Verify input attributes */
	ret = dpaa2_flow_verify_attr(&dpni_attr, flow_attr);
	if (ret < 0) {
		DPAA2_PMD_ERR("Invalid attributes are given");
		rte_flow_error_set(error, EPERM,
			RTE_FLOW_ERROR_TYPE_ATTR,
			flow_attr, "invalid");
		goto not_valid_params;
	}
	/* Verify input pattern list */
	ret = dpaa2_flow_verify_patterns(pattern, priv->sp_protocol);
	if (ret < 0) {
		DPAA2_PMD_ERR("Invalid pattern list is given");
		rte_flow_error_set(error, EPERM,
			RTE_FLOW_ERROR_TYPE_ITEM,
			pattern, "invalid");
		goto not_valid_params;
	}
	/* Verify input action list */
	ret = dpaa2_flow_check_actions_support(actions);
	if (ret < 0) {
		DPAA2_PMD_ERR("Invalid action list is given");
		rte_flow_error_set(error, EPERM,
			RTE_FLOW_ERROR_TYPE_ACTION,
			actions, "invalid");
		goto not_valid_params;
	}
not_valid_params:
	return ret;
}

static struct rte_flow *
dpaa2_flow_create(struct rte_eth_dev *dev,
	const struct rte_flow_attr *attr,
	const struct rte_flow_item pattern[],
	const struct rte_flow_action actions[],
	struct rte_flow_error *error)
{
	struct dpaa2_dev_flow *flow = NULL, *curr;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	int ret, is_rss;
	uint64_t iova;
	struct dpaa2_key_extract *key_extract;

	if (getenv("DPAA2_FLOW_CONTROL_LOG"))
		dpaa2_flow_control_log = 1;

	if (attr) {
		if (attr->group >= priv->num_rx_tc) {
			DPAA2_PMD_ERR("FS flow group(%d) >= max(%d)",
				attr->group, priv->num_rx_tc);
			return NULL;
		}
		if (attr->priority >= priv->fs_entries) {
			DPAA2_PMD_ERR("FS flow entry(%d) >= max(%d)",
				attr->priority, priv->fs_entries);
			return NULL;
		}
	}

	ret = dpaa2_flow_verify_entry(priv, attr);
	if (ret)
		return NULL;

	ret = dpaa2_flow_verify_action(priv, attr, actions);
	if (ret)
		return NULL;

	dpaa2_dump_extract_map(priv, "Start creating flow");

	flow = rte_zmalloc(NULL, sizeof(struct dpaa2_dev_flow),
			   RTE_CACHE_LINE_SIZE);
	if (!flow) {
		DPAA2_PMD_ERR("Failure to allocate memory for flow");
		goto mem_failure;
	}
	flow->priv = priv;

	flow->qos_flow = rte_zmalloc(NULL,
		sizeof(struct dpaa2_generic_flow), RTE_CACHE_LINE_SIZE);
	if (!flow->qos_flow) {
		DPAA2_PMD_ERR("Memory allocation failed");
		goto mem_failure;
	}
	flow->qos_flow->priv = priv;

	flow->fs_flow = rte_zmalloc(NULL,
		sizeof(struct dpaa2_generic_flow), RTE_CACHE_LINE_SIZE);
	if (!flow->fs_flow) {
		DPAA2_PMD_ERR("Memory allocation failed");
		goto mem_failure;
	}
	flow->fs_flow->priv = priv;

	/* Allocate DMA'ble memory to write the qos rules */
	flow->qos_flow->key_addr = rte_zmalloc(NULL,
		DPAA2_EXTRACT_ALLOC_KEY_MAX_SIZE, RTE_CACHE_LINE_SIZE);
	if (!flow->qos_flow->key_addr) {
		DPAA2_PMD_ERR("Memory allocation failed");
		goto mem_failure;
	}
	iova = DPAA2_VADDR_TO_IOVA_AND_CHECK(flow->qos_flow->key_addr,
			DPAA2_EXTRACT_ALLOC_KEY_MAX_SIZE);
	if (iova == RTE_BAD_IOVA) {
		DPAA2_PMD_ERR("%s: No IOMMU map for qos key(%p)",
			__func__, flow->qos_flow->key_addr);
		goto mem_failure;
	}
	flow->qos_flow->rule_cfg.key_iova = iova;

	flow->qos_flow->mask_addr = rte_zmalloc(NULL,
		DPAA2_EXTRACT_ALLOC_KEY_MAX_SIZE, RTE_CACHE_LINE_SIZE);
	if (!flow->qos_flow->mask_addr) {
		DPAA2_PMD_ERR("Memory allocation failed");
		goto mem_failure;
	}
	iova = DPAA2_VADDR_TO_IOVA_AND_CHECK(flow->qos_flow->mask_addr,
			DPAA2_EXTRACT_ALLOC_KEY_MAX_SIZE);
	if (iova == RTE_BAD_IOVA) {
		DPAA2_PMD_ERR("%s: No IOMMU map for qos mask(%p)",
			__func__, flow->qos_flow->mask_addr);
		goto mem_failure;
	}
	flow->qos_flow->rule_cfg.mask_iova = iova;

	/* Allocate DMA'ble memory to write the FS rules */
	flow->fs_flow->key_addr = rte_zmalloc(NULL,
		DPAA2_EXTRACT_ALLOC_KEY_MAX_SIZE, RTE_CACHE_LINE_SIZE);
	if (!flow->fs_flow->key_addr) {
		DPAA2_PMD_ERR("Memory allocation failed");
		goto mem_failure;
	}
	iova = DPAA2_VADDR_TO_IOVA_AND_CHECK(flow->fs_flow->key_addr,
			DPAA2_EXTRACT_ALLOC_KEY_MAX_SIZE);
	if (iova == RTE_BAD_IOVA) {
		DPAA2_PMD_ERR("%s: No IOMMU map for fs key(%p)",
			__func__, flow->fs_flow->key_addr);
		goto mem_failure;
	}
	flow->fs_flow->rule_cfg.key_iova = iova;

	flow->fs_flow->mask_addr = rte_zmalloc(NULL,
		DPAA2_EXTRACT_ALLOC_KEY_MAX_SIZE, RTE_CACHE_LINE_SIZE);
	if (!flow->fs_flow->mask_addr) {
		DPAA2_PMD_ERR("Memory allocation failed");
		goto mem_failure;
	}
	iova = DPAA2_VADDR_TO_IOVA_AND_CHECK(flow->fs_flow->mask_addr,
		DPAA2_EXTRACT_ALLOC_KEY_MAX_SIZE);
	if (iova == RTE_BAD_IOVA) {
		DPAA2_PMD_ERR("%s: No IOMMU map for fs mask(%p)",
			__func__, flow->fs_flow->mask_addr);
		goto mem_failure;
	}
	flow->fs_flow->rule_cfg.mask_iova = iova;

	flow->qos_flow->ip_key = NET_PROT_NONE;
	flow->fs_flow->ip_key = NET_PROT_NONE;

	priv->curr = flow;

	is_rss = dpaa2_flow_action_is_rss(actions);

	ret = dpaa2_flow_generic_extract_rule_set(flow->qos_flow,
		attr, pattern, false, DPAA2_FLOW_QOS_TYPE);
	if (ret < 0) {
		if (error && error->type > RTE_FLOW_ERROR_TYPE_ACTION) {
			rte_flow_error_set(error, EPERM,
				RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				attr, "unknown");
		}
		DPAA2_PMD_ERR("Create QoS flow failed (%d)", ret);
		goto creation_error;
	}

	ret = dpaa2_flow_add_qos_rule(priv, flow->qos_flow, attr);
	if (ret)
		goto creation_error;

	ret = dpaa2_flow_generic_extract_rule_set(flow->fs_flow,
		attr, pattern, is_rss, DPAA2_FLOW_FS_TYPE);
	if (ret < 0) {
		if (error && error->type > RTE_FLOW_ERROR_TYPE_ACTION) {
			rte_flow_error_set(error, EPERM,
				RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				attr, "unknown");
		}
		DPAA2_PMD_ERR("Create FS flow failed (%d)", ret);
		goto creation_error;
	}

	key_extract = &priv->extract.tc_key_extract[attr->group];

	flow->fs_flow->tc_id = attr->group;
	flow->fs_flow->entry_index = attr->priority;

	ret = dpaa2_flow_fs_action_update(priv, flow->fs_flow, actions,
		&key_extract->dpkg);
	if (ret)
		goto creation_error;
	ret = dpaa2_flow_add_fs_rule(priv, flow->fs_flow);
	if (ret)
		goto creation_error;

	dpaa2_dump_extract_map(priv, "Complete creating flow");

	priv->curr = NULL;

	/* New rules are inserted. */
	curr = LIST_FIRST(&priv->flows);
	if (!curr) {
		LIST_INSERT_HEAD(&priv->flows, flow, next);
	} else {
		while (LIST_NEXT(curr, next))
			curr = LIST_NEXT(curr, next);
		LIST_INSERT_AFTER(curr, flow, next);
	}

	return (struct rte_flow *)flow;

mem_failure:
	rte_flow_error_set(error, EPERM, RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
		"memory alloc");

creation_error:
	if (flow) {
		if (flow->qos_flow && flow->qos_flow->key_addr)
			rte_free(flow->qos_flow->key_addr);
		if (flow->qos_flow && flow->qos_flow->mask_addr)
			rte_free(flow->qos_flow->mask_addr);
		if (flow->fs_flow && flow->fs_flow->key_addr)
			rte_free(flow->fs_flow->key_addr);
		if (flow->fs_flow && flow->fs_flow->mask_addr)
			rte_free(flow->fs_flow->mask_addr);
		if (flow->qos_flow)
			rte_free(flow->qos_flow);
		if (flow->fs_flow)
			rte_free(flow->fs_flow);
		rte_free(flow);
	}
	priv->curr = NULL;

	return NULL;
}

static int
dpaa2_flow_rule_data_valid(struct dpaa2_dev_flow *flow,
	uint8_t key_offset, uint8_t key_size,
	enum dpaa2_flow_dist_type type)
{
	uint8_t *key, *mask, i;
	int valid = 0;
	struct dpaa2_generic_flow *_flow;

	_flow = type == DPAA2_FLOW_QOS_TYPE ?
		flow->qos_flow : flow->fs_flow;
	key = _flow->key_addr + key_offset;
	mask = _flow->mask_addr + key_offset;

	for (i = 0; i < key_size; i++) {
		if (key[i] & mask[i]) {
			valid = 1;
			break;
		}
	}

	return valid;
}

static void
dpaa2_flow_remove_invalid_rule_data(struct dpaa2_dev_priv *priv,
	enum dpaa2_flow_dist_type type, uint8_t tc_id,
	uint8_t key_offset, uint8_t key_size)
{
	struct dpaa2_dev_flow *flow, *next;
	struct dpaa2_generic_flow *_flow;

	flow = LIST_FIRST(&priv->flows);
	while (flow) {
		next = LIST_NEXT(flow, next);
		if (type == DPAA2_FLOW_QOS_TYPE) {
			_flow = flow->qos_flow;
			if (!_flow)
				goto skip_update_flow;
		} else {
			_flow = flow->fs_flow;
			if (!_flow)
				goto skip_update_flow;
			if (_flow->tc_id != tc_id)
				goto skip_update_flow;
		}

		if (key_offset < _flow->rule_size) {
			memmove(_flow->key_addr + key_offset,
				_flow->key_addr + key_offset + key_size,
				_flow->rule_size - (key_offset + key_size));
			memmove(_flow->mask_addr + key_offset,
				_flow->mask_addr + key_offset + key_size,
				_flow->rule_size - (key_offset + key_size));
				_flow->rule_size -= key_size;
		}
		if (_flow->rule_cfg.key_size > _flow->rule_size) {
			memset(_flow->key_addr + _flow->rule_size, 0,
				_flow->rule_cfg.key_size - _flow->rule_size);
			memset(_flow->mask_addr + _flow->rule_size, 0,
				_flow->rule_cfg.key_size - _flow->rule_size);
		}

skip_update_flow:
		flow = next;
	}
}

static int
dpaa2_flow_is_ip_addr_extract(const struct dpkg_extract *extract)
{
	enum dpkg_extract_type type = extract->type;
	enum net_prot prot = extract->extract.from_hdr.prot;
	uint32_t field = extract->extract.from_hdr.field;

	if (type == DPKG_EXTRACT_FROM_HDR && prot == NET_PROT_IP &&
		(field == NH_FLD_IP_SRC || field == NH_FLD_IP_DST))
		return true;

	return false;
}

static int
dpaa2_flow_ip_addr_extract_pos(uint32_t field,
	const struct dpaa2_key_profile *profile)
{
	if (field != NH_FLD_IP_SRC && field != NH_FLD_IP_DST)
		return -EINVAL;
	if (profile->ip_addr_extracts[0].field == field)
		return 0;
	else if (profile->ip_addr_extracts[1].field == field)
		return 1;
	else
		return -ENXIO;
}

static int
dpaa2_flow_key_offset_size(struct dpaa2_dev_flow *flow,
	struct dpaa2_key_extract *key_extract, uint8_t idx,
	uint8_t *offset, uint8_t *size,
	enum dpaa2_flow_dist_type type)
{
	struct dpkg_profile_cfg *dpkg = &key_extract->dpkg;
	struct dpaa2_key_profile *profile = &key_extract->key_profile;
	int pos, prev_ip_addr_pos;
	uint32_t field;
	uint8_t ip_addr_size = 0, ip_addr_offset = 0;
	struct dpaa2_generic_flow *_flow;

	_flow = type == DPAA2_FLOW_QOS_TYPE ? flow->qos_flow : flow->fs_flow;

	if (_flow->ip_key == NET_PROT_IPV4)
		ip_addr_size = NH_FLD_IPV4_ADDR_SIZE;
	else if (_flow->ip_key == NET_PROT_IPV6)
		ip_addr_size = NH_FLD_IPV6_ADDR_SIZE;

	field = dpkg->extracts[idx].extract.from_hdr.field;
	prev_ip_addr_pos = dpaa2_extract_prev_ip_addr_pos(profile);
	if (prev_ip_addr_pos >= 0) {
		ip_addr_offset =
			profile->key_offset[prev_ip_addr_pos] +
			profile->key_size[prev_ip_addr_pos];
	}

	if (dpaa2_flow_is_ip_addr_extract(&dpkg->extracts[idx])) {
		pos = dpaa2_flow_ip_addr_extract_pos(field, profile);
		if (!ip_addr_size)
			return -EINVAL;
		*offset = ip_addr_offset + ip_addr_size * pos;
		*size = ip_addr_size;
	} else {
		*offset = profile->key_offset[idx];
		*size = profile->key_size[idx];
	}

	return 0;
}

static int
dpaa2_flow_remove_invalid_extract(struct rte_eth_dev *dev,
	enum dpaa2_flow_dist_type type, uint8_t tc_id)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_dev_flow *flow, *next;
	uint8_t i, key_offset, key_size, j, remove_conut = 0;
	struct dpaa2_key_extract *key_extract;
	struct dpkg_profile_cfg *dpkg;
	struct dpaa2_key_profile *key_profile;
	int valid[DPKG_MAX_NUM_OF_EXTRACTS], update = 0, ret, ipaddr;
	enum net_prot prot;
	uint32_t field, start, end;
	uint32_t ip_src_size, ip_dst_size;
	struct dpaa2_generic_flow *_flow;

	if (type == DPAA2_FLOW_QOS_TYPE &&
		priv->num_rx_tc <= 1) {
		/** No QoS table.*/
		return 0;
	}

	if (type == DPAA2_FLOW_QOS_TYPE)
		key_extract = &priv->extract.qos_key_extract;
	else
		key_extract = &priv->extract.tc_key_extract[tc_id];

	dpkg = &key_extract->dpkg;
	key_profile = &key_extract->key_profile;
	for (i = 0; i < key_profile->num; i++) {
		valid[i] = 0;
		flow = LIST_FIRST(&priv->flows);
		while (flow) {
			next = LIST_NEXT(flow, next);
			_flow = type == DPAA2_FLOW_QOS_TYPE ?
				flow->qos_flow : flow->fs_flow;
			if (!_flow)
				goto skip_validation;

			if (type == DPAA2_FLOW_FS_TYPE &&
				_flow->tc_id != tc_id)
				goto skip_validation;

			key_offset = 0;
			key_size = 0;

			ret = dpaa2_flow_key_offset_size(flow, key_extract, i,
				&key_offset, &key_size, type);
			if (ret)
				goto skip_validation;

			if (dpaa2_flow_rule_data_valid(flow,
				key_offset, key_size, type)) {
				valid[i] = 1;
				break;
			}
skip_validation:
			flow = next;
		}
		if (!valid[i])
			remove_conut++;
	}

	if (remove_conut > 0) {
		if (type == DPAA2_FLOW_QOS_TYPE) {
			dpaa2_flow_extracts_log(priv,
				"Before removing extract(s)", MAX_TCS);
		} else {
			dpaa2_flow_extracts_log(priv,
				"Before removing extract(s)", tc_id);
		}
	} else {
		return 0;
	}

	i = key_profile->num - 1;
	while (remove_conut) {
		if (valid[i]) {
			if (i == 0) {
				DPAA2_PMD_ERR("Fatal: %d key(s) not removed!",
					remove_conut);
				return -EINVAL;
			}
			i--;
			continue;
		}
		key_size = key_profile->key_size[i];
		key_offset = key_profile->key_offset[i];

		for (j = i + 1; j < key_profile->num; j++)
			key_profile->key_offset[j] -= key_size;

		ipaddr = 0;
		if (dpkg->extracts[i].type == DPKG_EXTRACT_FROM_HDR) {
			prot = dpkg->extracts[i].extract.from_hdr.prot;
			field = dpkg->extracts[i].extract.from_hdr.field;
			ipaddr = dpaa2_flow_ip_address_extract(prot, field);
		}
		if (!ipaddr)
			update += key_size;

		if ((i + 1) < key_profile->num) {
			memmove(&key_profile->key_offset[i],
				&key_profile->key_offset[i + 1],
				key_profile->num - i - 1);
			memmove(&key_profile->key_size[i],
				&key_profile->key_size[i + 1],
				key_profile->num - i - 1);
			memmove(&key_profile->prot_field[i],
				&key_profile->prot_field[i + 1],
				(key_profile->num - i - 1) *
				sizeof(struct key_prot_field));

			memmove(&dpkg->extracts[i], &dpkg->extracts[i + 1],
				(key_profile->num - i - 1) *
				sizeof(struct dpkg_extract));
		}

		dpaa2_flow_remove_invalid_rule_data(priv, type, tc_id,
			key_offset, key_size);

		key_profile->num--;
		dpkg->num_extracts--;
		i--;
		remove_conut--;
	};

	key_profile->key_max_size -= update;
	key_profile->key_max_size -=
		(key_profile->ip_addr_extracts[0].max_size +
		key_profile->ip_addr_extracts[1].max_size);

	key_profile->l4_sp_present = 0;
	key_profile->l4_dp_present = 0;
	memset(key_profile->ip_addr_extracts, 0,
		sizeof(struct dpaa2_ip_addr_extract) * 2);

	if (key_profile->num >= 2)
		start = key_profile->num - 2;
	else if (key_profile->num >= 1)
		start = key_profile->num - 1;
	else
		goto skip_ip_addr_extract;
	end = key_profile->num;

	j = 0;
	for (i = start; i < end; i++) {
		if (dpaa2_flow_is_ip_addr_extract(&dpkg->extracts[i])) {
			key_profile->ip_addr_extracts[j].field =
				dpkg->extracts[i].extract.from_hdr.field;
			key_profile->ip_addr_extracts[j].max_size =
				sizeof(rte_be32_t);
			j++;
		}
	}

	ip_src_size = sizeof(rte_be32_t);
	ip_dst_size = sizeof(rte_be32_t);
	flow = LIST_FIRST(&priv->flows);
	while (flow) {
		next = LIST_NEXT(flow, next);
		_flow = type == DPAA2_FLOW_QOS_TYPE ?
			flow->qos_flow : flow->fs_flow;
		if (!_flow)
			goto next_flow;

		if (type == DPAA2_FLOW_FS_TYPE &&
			_flow->tc_id != tc_id)
			goto next_flow;

		if (_flow->ip_key == NET_PROT_IPV6) {
			if (_flow->ip_src == NET_PROT_IPV6)
				ip_src_size = NH_FLD_IPV6_ADDR_SIZE;
			if (_flow->ip_dst == NET_PROT_IPV6)
				ip_dst_size = NH_FLD_IPV6_ADDR_SIZE;
		}

next_flow:
		flow = next;
	}
	if (key_profile->ip_addr_extracts[0].field == NH_FLD_IP_SRC)
		key_profile->ip_addr_extracts[0].max_size = ip_src_size;
	else if (key_profile->ip_addr_extracts[0].field == NH_FLD_IP_DST)
		key_profile->ip_addr_extracts[0].max_size = ip_dst_size;

	if (key_profile->ip_addr_extracts[1].field == NH_FLD_IP_SRC)
		key_profile->ip_addr_extracts[1].max_size = ip_src_size;
	else if (key_profile->ip_addr_extracts[1].field == NH_FLD_IP_DST)
		key_profile->ip_addr_extracts[1].max_size = ip_dst_size;

	key_profile->key_max_size +=
		(key_profile->ip_addr_extracts[0].max_size +
		key_profile->ip_addr_extracts[1].max_size);

skip_ip_addr_extract:
	for (i = 0; i < dpkg->num_extracts; i++) {
		if ((dpkg->extracts[i].type == DPKG_EXTRACT_FROM_HDR &&
			dpkg->extracts[i].extract.from_hdr.prot ==
			NET_PROT_TCP &&
			dpkg->extracts[i].extract.from_hdr.field ==
			NH_FLD_TCP_PORT_SRC) ||
			(dpkg->extracts[i].type == DPKG_EXTRACT_FROM_HDR &&
			dpkg->extracts[i].extract.from_hdr.prot ==
			NET_PROT_UDP &&
			dpkg->extracts[i].extract.from_hdr.field ==
			NH_FLD_UDP_PORT_SRC) ||
			(dpkg->extracts[i].type == DPKG_EXTRACT_FROM_HDR &&
			dpkg->extracts[i].extract.from_hdr.prot ==
			NET_PROT_SCTP &&
			dpkg->extracts[i].extract.from_hdr.field ==
			NH_FLD_SCTP_PORT_SRC)) {
			key_profile->l4_sp_present = 1;
			key_profile->l4_sp_extract_idx = i;
			key_profile->l4_sp_key_offset =
				key_profile->key_offset[i];
		} else if ((dpkg->extracts[i].type == DPKG_EXTRACT_FROM_HDR &&
			dpkg->extracts[i].extract.from_hdr.prot ==
			NET_PROT_TCP &&
			dpkg->extracts[i].extract.from_hdr.field ==
			NH_FLD_TCP_PORT_DST) ||
			(dpkg->extracts[i].type == DPKG_EXTRACT_FROM_HDR &&
			dpkg->extracts[i].extract.from_hdr.prot ==
			NET_PROT_UDP &&
			dpkg->extracts[i].extract.from_hdr.field ==
			NH_FLD_UDP_PORT_DST) ||
			(dpkg->extracts[i].type == DPKG_EXTRACT_FROM_HDR &&
			dpkg->extracts[i].extract.from_hdr.prot ==
			NET_PROT_SCTP &&
			dpkg->extracts[i].extract.from_hdr.field ==
			NH_FLD_SCTP_PORT_DST)) {
			key_profile->l4_dp_present = 1;
			key_profile->l4_dp_extract_idx = i;
			key_profile->l4_dp_key_offset =
				key_profile->key_offset[i];
		}
	}

	if (type == DPAA2_FLOW_QOS_TYPE) {
		dpaa2_flow_extracts_log(priv,
			"After removing extract(s)", MAX_TCS);
	} else {
		dpaa2_flow_extracts_log(priv,
			"After removing extract(s)", tc_id);
	}

	return update;
}

static void
dpaa2_flow_remove_flow_from_list(struct dpaa2_dev_flow *flow)
{
	LIST_REMOVE(flow, next);
	if (flow->qos_flow && flow->qos_flow->key_addr)
		rte_free(flow->qos_flow->key_addr);
	if (flow->qos_flow && flow->qos_flow->mask_addr)
		rte_free(flow->qos_flow->mask_addr);
	if (flow->fs_flow && flow->fs_flow->key_addr)
		rte_free(flow->fs_flow->key_addr);
	if (flow->fs_flow && flow->fs_flow->mask_addr)
		rte_free(flow->fs_flow->mask_addr);
	if (flow->qos_flow)
		rte_free(flow->qos_flow);
	if (flow->fs_flow)
		rte_free(flow->fs_flow);
	/* Now free the flow */
	rte_free(flow);
}

static int
dpaa2_flow_remove_entry(struct rte_eth_dev *dev,
	struct dpaa2_dev_flow *flow, int *pqos_removed, int *pfs_removed)
{
	int ret = 0;
	int qos_removed = 0, fs_removed = 0;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = priv->hw;
	struct dpaa2_key_extract *extract;
	struct dpaa2_dev_flow_fs_action *fs_action;
	uint8_t tc_id;

	if (!flow->fs_flow)
		goto skip_remove_fs_flow;

	fs_action = &flow->fs_flow->flow_action.fs_action;
	tc_id = flow->fs_flow->tc_id;
	switch (fs_action->action_type) {
	case RTE_FLOW_ACTION_TYPE_QUEUE:
	case RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT:
	case RTE_FLOW_ACTION_TYPE_PORT_ID:
	case RTE_FLOW_ACTION_TYPE_DROP:
		/* Then remove entry from FS table */
		ret = dpni_remove_fs_entry(dpni, CMD_PRI_LOW, priv->token,
			flow->fs_flow->tc_id, &flow->fs_flow->rule_cfg);
		if (ret) {
			DPAA2_PMD_ERR("Remove entry from FS[%d] failed(%d)",
				flow->fs_flow->tc_id, ret);
			dpaa2_flow_fs_entry_log("Delete failed", flow->fs_flow);
		} else {
			dpaa2_flow_fs_entry_log("Delete success", flow->fs_flow);
			fs_removed = 1;
			extract = &priv->extract.tc_key_extract[tc_id];
			extract->entry_num--;
			dpaa2_flow_entry_map_set(extract->entry_map,
				flow->fs_flow->entry_index, 0);
		}
		break;
	case RTE_FLOW_ACTION_TYPE_RSS:
		/** Remove QoS entry later.*/
		break;
	default:
		DPAA2_PMD_ERR("Action(%d) not supported",
			fs_action->action_type);
		ret = -ENOTSUP;
		break;
	}

skip_remove_fs_flow:
	if (priv->num_rx_tc > 1 && flow->qos_flow) {
		/* Remove entry from QoS table first */
		ret = dpni_remove_qos_entry(dpni, CMD_PRI_LOW,
			priv->token, &flow->qos_flow->rule_cfg);
		if (ret) {
			DPAA2_PMD_ERR("Remove QoS entry failed(%d)", ret);
			dpaa2_flow_qos_entry_log("Delete failed",
				flow->qos_flow,
				flow->qos_flow->entry_index);
			/** Will not remove FS entry.*/
		} else {
			dpaa2_flow_qos_entry_log("Delete success",
				flow->qos_flow,
				flow->qos_flow->entry_index);
			qos_removed = 1;
			extract = &priv->extract.qos_key_extract;
			extract->entry_num--;
			dpaa2_flow_entry_map_set(extract->entry_map,
				flow->qos_flow->entry_index, 0);
		}
	}

	if (pqos_removed)
		*pqos_removed = qos_removed;
	if (pfs_removed)
		*pfs_removed = fs_removed;

	return ret;
}

static int
dpaa2_flow_destroy(struct rte_eth_dev *dev,
	struct rte_flow *_flow,
	struct rte_flow_error *error)
{
	int ret = 0, qos_removed = 0, fs_removed = 0, update;
	uint8_t dist_size, tc_id = 0;
	struct dpaa2_dev_flow *flow;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;

	dpaa2_dump_extract_map(priv, "Start destroying flow");

	flow = (struct dpaa2_dev_flow *)_flow;

	ret = dpaa2_flow_remove_entry(dev, flow, &qos_removed, &fs_removed);
	if (ret)
		goto error;

	if (fs_removed)
		tc_id = flow->fs_flow->tc_id;

	dpaa2_flow_remove_flow_from_list(flow);

	if (fs_removed) {
		update = dpaa2_flow_remove_invalid_extract(dev,
			DPAA2_FLOW_FS_TYPE, tc_id);
		if (update > 0) {
			dist_size = priv->nb_rx_queues / priv->num_rx_tc;
			ret = dpaa2_flow_fs_rss_table_config(priv,
				tc_id, dist_size, false);
			if (ret) {
				DPAA2_PMD_ERR("Re-configure FS table failed(%d)", ret);
				goto error;
			}
		}
	}

	if (qos_removed) {
		update = dpaa2_flow_remove_invalid_extract(dev,
			DPAA2_FLOW_QOS_TYPE, 0);
		if (update > 0) {
			ret = dpaa2_flow_qos_table_config(priv, false);
			if (ret) {
				DPAA2_PMD_ERR("Re-configure QoS table failed(%d)", ret);
				goto error;
			}
		}
	}

error:
	dpaa2_dump_extract_map(priv, "Complete destroying flow");
	if (ret) {
		ret = -ret;
		return rte_flow_error_set(error, ret,
				RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				NULL, "unknown");
	}

	return ret;
}

static int
dpaa2_flow_actions_update(struct rte_eth_dev *dev,
	struct rte_flow *_flow,
	const struct rte_flow_action actions[],
	struct rte_flow_error *error)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_dev_flow *flow;
	struct dpaa2_key_extract *tc_ext;
	uint16_t dist_size = 0, tc_id;
	int ret, is_rss = false;
	struct dpaa2_dev_flow_fs_action *fs_action;

	/* check for the valid flow */
	LIST_FOREACH(flow, &priv->flows, next) {
		if ((struct rte_flow *)flow == _flow)
			goto action_update;
	}
	DPAA2_PMD_ERR("%s: Flow(%p) is not in %s's flow list\n",
		__func__, flow, dev->data->name);

	ret = -EINVAL;
	goto quit;

action_update:
	ret = dpaa2_flow_check_actions_support(actions);
	if (ret) {
		DPAA2_PMD_ERR("%s: verify new action failed(%d)\n",
			__func__, ret);
		goto quit;
	}
	flow = (struct dpaa2_dev_flow *)_flow;
	if (!flow->fs_flow)
		goto quit;
	fs_action = &flow->fs_flow->flow_action.fs_action;
	ret = dpaa2_flow_remove_entry(dev, flow, NULL, NULL);
	if (ret) {
		DPAA2_PMD_ERR("%s: remove flow entry failed(%d)",
			__func__, ret);

		goto quit;
	}
	tc_id = flow->qos_flow->flow_action.fs_tc_id;
	tc_ext = &priv->extract.tc_key_extract[tc_id];
	if (fs_action->action_type == RTE_FLOW_ACTION_TYPE_RSS) {
		is_rss = true;
		dist_size = fs_action->rss_queues;
	}
	ret = dpaa2_flow_fs_action_update(priv, flow->fs_flow, actions,
		&tc_ext->dpkg);
	if (ret) {
		DPAA2_PMD_ERR("%s: action update failed(%d)",
			__func__, ret);

		goto quit;
	}
	if (is_rss < 0) {
		DPAA2_PMD_ERR("%s: action update rss not set",
			__func__);
		ret = -EINVAL;

		goto quit;
	}
	if (is_rss) {
		ret = dpaa2_flow_fs_rss_table_config(priv, tc_id,
			dist_size, true);
		if (ret)
			goto quit;
	}
	if (priv->num_rx_tc > 1 && flow->qos_flow) {
		ret = dpaa2_flow_add_qos_rule(priv, flow->qos_flow, NULL);
		if (ret)
			goto quit;
	}

	if (!is_rss && flow->fs_flow) {
		ret = dpaa2_flow_add_fs_rule(priv, flow->fs_flow);
		if (ret)
			goto quit;
	}

quit:
	return rte_flow_error_set(error, -ret,
			RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
			NULL, "unknown");
}

/**
 * Destroy user-configured flow rules.
 *
 * This function skips internal flows rules.
 *
 * @see rte_flow_flush()
 * @see rte_flow_ops
 */
static int
dpaa2_flow_flush(struct rte_eth_dev *dev,
		struct rte_flow_error *error)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_dev_flow *flow = LIST_FIRST(&priv->flows);
	int ret = 0, times;

	dpaa2_dump_extract_map(priv, "Start flushing flow");

	while (flow) {
		struct dpaa2_dev_flow *next = LIST_NEXT(flow, next);

		times = 10;
again:
		ret = dpaa2_flow_destroy(dev, (struct rte_flow *)flow, error);
		if (ret) {
			DPAA2_PMD_ERR("%s: Remove flow failed(%d), times=%d",
				__func__, ret, times);
		}
		if (ret == -EAGAIN) {
			if (times > 0) {
				times--;
				goto again;
			}
			dpaa2_flow_remove_flow_from_list(flow);
		}

		flow = next;
	}
	dpaa2_dump_extract_map(priv, "Complete flushing flow");

	return ret;
}

static int
dpaa2_flow_query(struct rte_eth_dev *dev,
	struct rte_flow *_flow, const struct rte_flow_action *actions,
	void *data, struct rte_flow_error *error)
{
	struct dpaa2_dev_flow *flow;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	uint16_t num = 0, num_rsp, i, tc_id = 0;
	int ret = 0, found = false;
	size_t size, iova;
	struct dpni_dump_table_rsp *rsp = NULL;

	RTE_SET_USED(actions);
	RTE_SET_USED(data);
	RTE_SET_USED(error);

	flow = LIST_FIRST(&priv->flows);
	while (flow) {
		num++;
		if (flow == (struct dpaa2_dev_flow *)_flow)
			found = true;
		flow = LIST_NEXT(flow, next);
	}
	if (!num || found == false)
		return -ENXIO;
	num = num * 2;/** Max: FS entry + QoS entry.*/
	flow = (void *)_flow;
	size = sizeof(struct dpni_dump_table_header) +
		num * sizeof(struct dpni_dump_table_entry);
	rsp = rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);
	if (!rsp)
		return -ENOMEM;
	iova = DPAA2_VADDR_TO_IOVA_AND_CHECK(rsp, size);
	if (iova == RTE_BAD_IOVA) {
		DPAA2_PMD_ERR("%s: No IOMMU map for dump table result!",
			__func__);
		ret = -EIO;
		goto quit;
	}

	if (priv->num_rx_tc <= 1)
		goto dump_fs;

	ret = dpni_dump_table(priv->hw, CMD_PRI_LOW,
		priv->token, DPNI_QOS_TABLE, 0/**Any*/,
		iova, size, &num_rsp);
	if (ret) {
		DPAA2_PMD_ERR("dump %s's QoS table failed(%d)",
			dev->data->name, ret);
		goto quit;
	}

	if (!flow->qos_flow)
		goto dump_fs;

	for (i = 0; i < num_rsp; i++) {
		if (!memcmp(rsp->entry[i].key, flow->qos_flow->key_addr,
			flow->qos_flow->rule_size) &&
			!memcmp(rsp->entry[i].mask,
			flow->qos_flow->mask_addr, flow->qos_flow->rule_size))
			break;
	}

dump_fs:
	if (!flow->fs_flow)
		goto quit;

	tc_id = flow->fs_flow->tc_id;
	ret = dpni_dump_table(priv->hw, CMD_PRI_LOW,
		priv->token, DPNI_FS_TABLE, tc_id,
		iova, size, &num_rsp);
	if (ret) {
		DPAA2_PMD_ERR("dump %s's FS%d table failed(%d)",
			dev->data->name, tc_id, ret);
		goto quit;
	}
	for (i = 0; i < num_rsp; i++) {
		if (!memcmp(rsp->entry[i].key, flow->fs_flow->key_addr,
			flow->fs_flow->rule_size) &&
			!memcmp(rsp->entry[i].mask,
			flow->fs_flow->mask_addr, flow->fs_flow->rule_size)) {
			break;
		}
	}

quit:
	if (rsp)
		rte_free(rsp);

	return ret;
}

static int
dpaa2_flow_table_dump_check(struct dpni_dump_table_rsp *rsp,
	uint16_t num_rsp, char *dump_str, int type,
	struct dpaa2_dev_flow *_flow, uint16_t size)
{
	uint16_t i, j, off = 0;
	int found, ret = 0;
	uint8_t *key, *mask;
	struct dpaa2_dev_flow *flow;

	for (i = 0; i < num_rsp; i++) {
		off += sprintf(&dump_str[off],
			"entry%d: idx(%d):action(%d)\nkey:\n",
			i, rsp->entry[i].rule_index,
			rsp->entry[i].key_action);
		for (j = 0; j < size; j++) {
			off += sprintf(&dump_str[off], "%02x ",
				rsp->entry[i].key[j]);
		}
		off += sprintf(&dump_str[off], "\nmask:\n");
		for (j = 0; j < size; j++) {
			off += sprintf(&dump_str[off], "%02x ",
				rsp->entry[i].mask[j]);
		}
		off += sprintf(&dump_str[off], "\n");
		found = false;
		flow = _flow;
		while (flow) {
			if (type == DPAA2_FLOW_QOS_TYPE) {
				key = flow->qos_flow->key_addr;
				mask = flow->qos_flow->mask_addr;
			} else {
				key = flow->fs_flow->key_addr;
				mask = flow->fs_flow->mask_addr;
			}
			if (!memcmp(rsp->entry[i].key, key, size) &&
				!memcmp(rsp->entry[i].mask, mask, size)) {
				found = true;
				break;
			}
			flow = LIST_NEXT(flow, next);
		}
		if (!found) {
			off += sprintf(&dump_str[off],
				"This entry not found in flow list\n");
			ret = -ENXIO;
		}
	}

	return ret;
}

int
rte_pmd_dpaa2_flow_table_query(uint16_t portid)
{
	struct rte_eth_dev *dev;
	struct dpaa2_dev_flow *flow;
	struct dpaa2_dev_priv *priv;
	uint16_t num = 0, num_rsp, tc_id = 0;
	int ret = 0, fs_enable[MAX_TCS];
	size_t size, iova;
	struct dpni_dump_table_rsp *rsp = NULL;
	char *dump_str = NULL;
	uint16_t fs_rule_size[MAX_TCS], qos_rule_size;
	struct dpaa2_generic_flow *_flow;

	if (!rte_pmd_dpaa2_dev_is_dpaa2(portid))
		return -EINVAL;

	dev = &rte_eth_devices[portid];
	priv = dev->data->dev_private;

	memset(fs_enable, 0, sizeof(fs_enable));
	memset(fs_rule_size, 0, sizeof(fs_rule_size));
	qos_rule_size = 0;
	flow = LIST_FIRST(&priv->flows);
	while (flow) {
		if (!flow->fs_flow)
			goto next_flow;
		_flow = flow->fs_flow;
		fs_enable[_flow->tc_id]++;
		if (fs_rule_size[_flow->tc_id] < _flow->rule_size)
			fs_rule_size[_flow->tc_id] = _flow->rule_size;
		if (qos_rule_size < _flow->rule_size)
			qos_rule_size = _flow->rule_size;
		num++;
next_flow:
		flow = LIST_NEXT(flow, next);
	}
	if (!num)
		return -ENXIO;
	size = sizeof(struct dpni_dump_table_header) +
		num * sizeof(struct dpni_dump_table_entry);
	rsp = rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);
	if (!rsp)
		return -ENOMEM;
	dump_str = rte_zmalloc(NULL, num * 1024, 0);
	if (!dump_str)
		goto quit;
	iova = DPAA2_VADDR_TO_IOVA_AND_CHECK(rsp, size);
	if (iova == RTE_BAD_IOVA) {
		DPAA2_PMD_ERR("%s: No IOMMU map for dump table result!",
			__func__);
		goto quit;
	}

	if (priv->num_rx_tc <= 1)
		goto dump_fs;

	ret = dpni_dump_table(priv->hw, CMD_PRI_LOW,
		priv->token, DPNI_QOS_TABLE, 0/**Any*/,
		iova, size, &num_rsp);
	if (ret) {
		DPAA2_PMD_ERR("dump %s's QoS table failed(%d)",
			dev->data->name, ret);
		goto quit;
	}
	DPAA2_PMD_INFO("dump %s's QoS table: type(%d):num(%d-%d):max(%d)",
		dev->data->name,
		rte_be_to_cpu_16(rsp->hdr.table_type), num_rsp,
		rte_be_to_cpu_16(rsp->hdr.table_num_entries),
		rte_be_to_cpu_16(rsp->hdr.table_max_entries));
	ret = dpaa2_flow_table_dump_check(rsp, num_rsp,
		dump_str, DPAA2_FLOW_QOS_TYPE,
		LIST_FIRST(&priv->flows), qos_rule_size);
	DPAA2_PMD_INFO("%s", dump_str);
	if (ret)
		goto quit;

dump_fs:
	if (!fs_enable[tc_id])
		goto dump_next_fs;
	ret = dpni_dump_table(priv->hw, CMD_PRI_LOW,
		priv->token, DPNI_FS_TABLE, tc_id,
		iova, size, &num_rsp);
	if (ret) {
		DPAA2_PMD_ERR("dump %s's FS%d table failed(%d)",
			dev->data->name, tc_id, ret);
		goto dump_next_fs;
	}
	DPAA2_PMD_INFO("dump %s's FS%d table: type(%d):num(%d-%d):max(%d)",
		dev->data->name, tc_id,
		rte_be_to_cpu_16(rsp->hdr.table_type), num_rsp,
		rte_be_to_cpu_16(rsp->hdr.table_num_entries),
		rte_be_to_cpu_16(rsp->hdr.table_max_entries));
	ret = dpaa2_flow_table_dump_check(rsp, num_rsp,
		dump_str, DPAA2_FLOW_FS_TYPE,
		LIST_FIRST(&priv->flows), fs_rule_size[tc_id]);
	DPAA2_PMD_INFO("%s", dump_str);
	if (ret)
		goto quit;
dump_next_fs:
	tc_id++;
	if (tc_id < MAX_TCS)
		goto dump_fs;

quit:
	if (rsp)
		rte_free(rsp);
	if (dump_str)
		rte_free(dump_str);

	return ret;
}

/**
 * Clean up all flow rules.
 *
 * Unlike dpaa2_flow_flush(), this function takes care of all remaining flow
 * rules regardless of whether they are internal or user-configured.
 *
 * @param priv
 *   Pointer to private structure.
 */
void
dpaa2_flow_clean(struct rte_eth_dev *dev)
{
	struct dpaa2_dev_flow *flow;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	int ret, times;

	dpaa2_dump_extract_map(priv, "Start cleaning flow");
	flow = LIST_FIRST(&priv->flows);
	while (flow) {
		times = 10;
again:
		ret = dpaa2_flow_destroy(dev, (struct rte_flow *)flow, NULL);
		if (ret) {
			DPAA2_PMD_ERR("%s: Remove flow failed(%d), times=%d",
				__func__, ret, times);
		}
		if (ret == -EAGAIN) {
			if (times > 0) {
				times--;
				goto again;
			}
			dpaa2_flow_remove_flow_from_list(flow);
		}
		flow = LIST_FIRST(&priv->flows);
	}
	dpaa2_dump_extract_map(priv, "Complete cleaning flow");
}

const struct rte_flow_ops dpaa2_flow_ops = {
	.create	= dpaa2_flow_create,
	.validate = dpaa2_flow_validate,
	.destroy = dpaa2_flow_destroy,
	.actions_update = dpaa2_flow_actions_update,
	.flush	= dpaa2_flow_flush,
	.query	= dpaa2_flow_query,
};

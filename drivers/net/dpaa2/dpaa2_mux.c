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

#include <bus_fslmc_driver.h>
#include <fsl_dpdmux.h>
#include <fsl_dpkg.h>
#include <fsl_dprc.h>

#include <dpaa2_ethdev.h>
#include <dpaa2_pmd_logs.h>
#include "dpaa2_parser_decode.h"

struct dpaa2_mux_flow {
	LIST_ENTRY(dpaa2_mux_flow) next;
	struct dpdmux_rule_cfg rule;
	uint8_t *key_addr;
	uint8_t *mask_addr;
	enum net_prot ip_key;
	struct dpdmux_cls_action action;
};

struct dpaa2_mux_ep {
	uint16_t mux_if_id;
	enum rte_dpaa2_dev_type ep_type;
	uint16_t ep_object_id;
	uint16_t ep_if_id;
	char ep_name[RTE_DEV_NAME_MAX_LEN];
};

struct dpaa2_dpdmux_dev {
	TAILQ_ENTRY(dpaa2_dpdmux_dev) next;
	/**< Pointer to Next device instance */
	struct fsl_mc_io dpdmux;  /** handle to DPDMUX portal object */
	uint16_t token;
	uint32_t dpdmux_id; /*HW ID for DPDMUX object */
	uint8_t num_ifs;   /* Number of interfaces in DPDMUX */
	struct dpaa2_mux_ep *mux_eps;
	struct dpaa2_key_extract key_extract;
	uint8_t *key_param;
	uint64_t key_param_iova;
	uint16_t flow_num;
	rte_spinlock_t lock;
	LIST_HEAD(, dpaa2_mux_flow) flows;
};

TAILQ_HEAD(dpdmux_dev_list, dpaa2_dpdmux_dev);
static struct dpdmux_dev_list dpdmux_dev_list =
	TAILQ_HEAD_INITIALIZER(dpdmux_dev_list); /*!< DPDMUX device list */

static bool dpaa2_mux_flow_log;

static inline void
dpaa2_mux_extracts_log(const struct dpaa2_dpdmux_dev *dpdmux_dev)
{
	if (!dpaa2_mux_flow_log)
		return;

	DPAA2_FLOW_DUMP("DPDMUX[%d] flow table: %d extracts\r\n",
		dpdmux_dev->dpdmux_id,
		dpdmux_dev->key_extract.dpkg.num_extracts);
	dpaa2_dump_dpkg(&dpdmux_dev->key_extract.dpkg);
}

static inline void
dpaa2_mux_flow_rule_log(struct dpaa2_mux_flow *flow,
	const char *prefix)
{
	int i;

	if (!dpaa2_mux_flow_log)
		return;

	DPAA2_FLOW_DUMP("DPMUX: %s flow(%p):\r\n", prefix, flow);
	DPAA2_FLOW_DUMP("key_iova:0x%lx, mask_iova:0x%lx\r\n",
		flow->rule.key_iova, flow->rule.mask_iova);
	DPAA2_FLOW_DUMP("key_size:%d, entry_index:%d\r\n",
		flow->rule.key_size, flow->rule.entry_index);
	DPAA2_FLOW_DUMP("data:\r\n");
	for (i = 0; i < flow->rule.key_size; i++)
		DPAA2_FLOW_DUMP("%02x ", flow->key_addr[i]);
	DPAA2_FLOW_DUMP("\r\nmask:\r\n");
	for (i = 0; i < flow->rule.key_size; i++)
		DPAA2_FLOW_DUMP("%02x ", flow->mask_addr[i]);
	DPAA2_FLOW_DUMP("\r\n");
}

static struct dpaa2_dpdmux_dev *
get_dpdmux_from_id(uint32_t dpdmux_id)
{
	struct dpaa2_dpdmux_dev *dpdmux_dev = NULL;

	/* Get DPDMUX dev handle from list using index */
	TAILQ_FOREACH(dpdmux_dev, &dpdmux_dev_list, next) {
		if (dpdmux_dev->dpdmux_id == dpdmux_id)
			break;
	}

	return dpdmux_dev;
}

static inline int
_dpaa2_mux_add_parser_extract(struct dpkg_extract *extract,
	enum dpaa2_parser_protocol_id protocol,
	uint8_t *key_va, uint8_t *mask_va)
{
	int ret;
	uint32_t bit_offset, byte_offset, faf_bit_in_byte;

	ret = dpaa2_protocol_psr_bit_offset(&bit_offset, protocol);
	if (ret)
		return ret;
	byte_offset = bit_offset / 8;
	extract->type = DPKG_EXTRACT_FROM_PARSE;
	extract->extract.from_parse.offset = byte_offset;
	extract->extract.from_parse.size = sizeof(uint8_t);
	faf_bit_in_byte = bit_offset % 8;
	faf_bit_in_byte = 7 - faf_bit_in_byte;
	*key_va = (1 << faf_bit_in_byte);
	*mask_va =  (1 << faf_bit_in_byte);

	return 0;
}

static int
dpaa2_mux_find_extract(struct dpaa2_key_extract *key_ext,
	struct dpkg_extract *ext)
{
	uint8_t i;
	struct dpkg_profile_cfg *dpkg = &key_ext->dpkg;
	struct dpaa2_key_profile *key_profile = &key_ext->key_profile;

	for (i = 0; i < dpkg->num_extracts; i++) {
		if (!memcmp(ext, &dpkg->extracts[i], sizeof(*ext)))
			return key_profile->key_offset[i];
	}

	return -ENODATA;
}

static inline int
dpaa2_mux_add_parser_extract(struct dpaa2_key_extract *key_ext,
	enum dpaa2_parser_protocol_id protocol,
	uint8_t *key_va, uint8_t *mask_va, int *extract_update)
{
	int ret, pos;
	struct dpkg_extract *extract;
	struct dpkg_extract local_extract;
	uint8_t local_key, local_mask;
	struct dpkg_profile_cfg *kg_cfg = &key_ext->dpkg;
	struct dpaa2_key_profile *profile = &key_ext->key_profile;

	if (kg_cfg->num_extracts >= DPKG_MAX_NUM_OF_EXTRACTS) {
		DPAA2_PMD_ERR("Too many extracts(%d)",
			kg_cfg->num_extracts);
		return -ENOTSUP;
	}
	memset(&local_extract, 0, sizeof(struct dpkg_extract));

	ret = _dpaa2_mux_add_parser_extract(&local_extract, protocol,
			&local_key, &local_mask);
	if (ret)
		return ret;

	pos = dpaa2_mux_find_extract(key_ext, &local_extract);
	if (pos < 0) {
		extract = &kg_cfg->extracts[kg_cfg->num_extracts];
		rte_memcpy(extract, &local_extract, sizeof(local_extract));
		kg_cfg->num_extracts++;

		if (profile->num > 0) {
			pos = profile->key_offset[profile->num - 1] +
				profile->key_size[profile->num - 1];
		} else {
			pos = 0;
		}
		profile->key_offset[profile->num] = pos;
		profile->key_size[profile->num] = sizeof(uint8_t);
		profile->key_max_size += sizeof(uint8_t);
		profile->num++;

		*extract_update = 1;
	}

	key_va[pos] = local_key;
	mask_va[pos] = local_mask;

	return 0;
}

static inline int
dpaa2_mux_add_hdr_extract(struct dpaa2_key_extract *key_ext,
	enum net_prot prot, uint32_t field, uint32_t field_size,
	const void *field_data, const void *field_mask,
	uint8_t *key_va, uint8_t *mask_va, int *extract_update)
{
	int pos;
	struct dpkg_extract *extract;
	struct dpkg_extract local_extract;
	struct dpkg_profile_cfg *kg_cfg = &key_ext->dpkg;
	struct dpaa2_key_profile *profile = &key_ext->key_profile;

	if (kg_cfg->num_extracts >= DPKG_MAX_NUM_OF_EXTRACTS) {
		DPAA2_PMD_ERR("Too many extracts(%d)",
			kg_cfg->num_extracts);
		return -ENOTSUP;
	}

	memset(&local_extract, 0, sizeof(struct dpkg_extract));
	local_extract.type = DPKG_EXTRACT_FROM_HDR;
	local_extract.extract.from_hdr.prot = prot;
	local_extract.extract.from_hdr.field = field;
	local_extract.extract.from_hdr.type = DPKG_FULL_FIELD;

	pos = dpaa2_mux_find_extract(key_ext, &local_extract);
	if (pos >= 0)
		goto set_rule;

	extract = &kg_cfg->extracts[kg_cfg->num_extracts];
	rte_memcpy(extract, &local_extract, sizeof(local_extract));
	kg_cfg->num_extracts++;
	if (profile->num > 0) {
		pos = profile->key_offset[profile->num - 1] +
			profile->key_size[profile->num - 1];
	} else {
		pos = 0;
	}
	profile->key_offset[profile->num] = pos;
	profile->key_size[profile->num] = field_size;
	profile->key_max_size += field_size;
	profile->num++;
	*extract_update = 1;

set_rule:

	rte_memcpy(&key_va[pos], field_data, field_size);
	if (field_mask)
		rte_memcpy(&mask_va[pos], field_mask, field_size);
	else
		memset(&mask_va[pos], 0xff, field_size);

	return 0;
}

static int
dpaa2_mux_add_ipaddr_extract(struct dpaa2_key_extract *key_ext,
	enum net_prot prot, uint32_t field, uint32_t field_size,
	const void *field_data, const void *field_mask,
	uint8_t *key_va, uint8_t *mask_va, int *extract_update)
{
	int ret, pos = 0;
	struct dpaa2_key_profile *key_profile;
	struct dpkg_profile_cfg *dpkg;
	uint8_t num, ip_addr_offset = 0;

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
		if (field_size != sizeof(rte_be32_t)) {
			DPAA2_PMD_ERR("%s: Invalid ipv4 address size(%d)",
				__func__, field_size);
			return -EINVAL;
		}
	} else {
		if (field != NH_FLD_IPV6_SRC_IP &&
			field != NH_FLD_IPV6_DST_IP) {
			DPAA2_PMD_ERR("%s: Invalid ipv6 filed(%d)",
				__func__, field);
			return -EINVAL;
		}
		if (field_size != NH_FLD_IPV6_ADDR_SIZE) {
			DPAA2_PMD_ERR("%s: Invalid ipv6 address size(%d)",
				__func__, field_size);
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

	key_profile = &key_ext->key_profile;
	dpkg = &key_ext->dpkg;
	num = key_profile->num;

	if (num >= DPKG_MAX_NUM_OF_EXTRACTS) {
		DPAA2_PMD_ERR("Number of extracts overflows");
		return -EINVAL;
	}

	pos = dpaa2_extract_prev_ip_addr_pos(key_profile);
	if (pos >= 0) {
		ip_addr_offset = key_profile->key_offset[pos] +
			key_profile->key_size[pos];
	}

	ret = dpaa2_extract_ip_addr_add(field, key_profile,
		field_size, extract_update, &pos);
	if (ret) {
		DPAA2_PMD_ERR("Add IP address extract failed(%d)", ret);
		return ret;
	}
	if (pos > 1) {
		DPAA2_PMD_ERR("Invalid IP address extract position(%d)", pos);
		return -EINVAL;
	}
	if (*extract_update) {
		key_profile->num++;
		key_profile->prot_field[num].type = DPAA2_NET_PROT_KEY;
		key_profile->prot_field[num].prot = prot;
		key_profile->prot_field[num].key_field = field;

		dpkg->extracts[num].type = DPKG_EXTRACT_FROM_HDR;
		dpkg->extracts[num].extract.from_hdr.prot = prot;
		dpkg->extracts[num].extract.from_hdr.field = field;
		dpkg->extracts[num].extract.from_hdr.type = DPKG_FULL_FIELD;
		dpkg->num_extracts++;
	}

	key_va += ip_addr_offset;
	mask_va += ip_addr_offset;

	if (pos == 0) {
		rte_memcpy(key_va, field_data, field_size);
		rte_memcpy(mask_va, field_mask, field_size);
	} else {
		rte_memcpy(key_va + field_size, field_data, field_size);
		rte_memcpy(mask_va + field_size, field_mask, field_size);
	}

	return 0;
}

static inline int
dpaa2_mux_add_non_hdr_extract(struct dpaa2_key_extract *key_ext,
	uint8_t offset, uint8_t size, enum dpkg_extract_type type,
	const void *field_data, const void *field_mask,
	uint8_t *key_va, uint8_t *mask_va, int *extract_update)
{
	int pos;
	struct dpkg_extract *extract;
	struct dpkg_extract local_extract;
	struct dpkg_profile_cfg *kg_cfg = &key_ext->dpkg;
	struct dpaa2_key_profile *profile = &key_ext->key_profile;

	if (kg_cfg->num_extracts >= DPKG_MAX_NUM_OF_EXTRACTS) {
		DPAA2_PMD_ERR("Too many extracts(%d)",
			kg_cfg->num_extracts);
		return -ENOTSUP;
	}

	memset(&local_extract, 0, sizeof(struct dpkg_extract));
	if (type == DPKG_EXTRACT_FROM_DATA) {
		local_extract.type = DPKG_EXTRACT_FROM_DATA;
		local_extract.extract.from_data.offset = offset;
		local_extract.extract.from_data.size = size;
	} else if (type == DPKG_EXTRACT_FROM_PARSE) {
		local_extract.type = DPKG_EXTRACT_FROM_PARSE;
		local_extract.extract.from_parse.offset = offset;
		local_extract.extract.from_parse.size = size;
	} else {
		DPAA2_PMD_ERR("%s: Invalid extract type(%d)",
			__func__, type);
		return -EINVAL;
	}

	pos = dpaa2_mux_find_extract(key_ext, &local_extract);
	if (pos >= 0)
		goto set_rule;

	extract = &kg_cfg->extracts[kg_cfg->num_extracts];
	rte_memcpy(extract, &local_extract, sizeof(local_extract));
	kg_cfg->num_extracts++;
	if (profile->num > 0) {
		pos = profile->key_offset[profile->num - 1] +
			profile->key_size[profile->num - 1];
	} else {
		pos = 0;
	}
	profile->key_offset[profile->num] = pos;
	profile->key_size[profile->num] = size;
	profile->num++;
	*extract_update = 1;
	profile->key_max_size += size;

set_rule:

	rte_memcpy(&key_va[pos], field_data, size);
	if (field_mask)
		rte_memcpy(&mask_va[pos], field_mask, size);
	else
		memset(&mask_va[pos], 0xff, size);

	return 0;
}

int
rte_pmd_dpaa2_mux_flow_create(uint32_t dpdmux_id,
	struct rte_flow_item pattern[],
	struct rte_flow_action actions[])
{
	struct dpaa2_dpdmux_dev *dpdmux_dev;
	struct dpaa2_key_extract *key_extract;
	struct dpkg_profile_cfg *dpkg;
	const struct rte_flow_action_vf *vf_conf = NULL;
	int ret = 0, loop = 0, extract_update = 0;
	struct dpaa2_mux_flow *flow = NULL;
	struct dpaa2_mux_flow *_flow;
	char zero_cmp[256];

	/* Find the DPDMUX from dpdmux_id in our list */
	dpdmux_dev = get_dpdmux_from_id(dpdmux_id);
	if (!dpdmux_dev) {
		DPAA2_PMD_ERR("Invalid DPDMUX ID(%d)", dpdmux_id);
		return -ENODEV;
	}

	if (actions[0].type == RTE_FLOW_ACTION_TYPE_VF) {
		vf_conf = actions[0].conf;
		if (vf_conf->id > dpdmux_dev->num_ifs ||
			dpdmux_dev->mux_eps[vf_conf->id].ep_type ==
			DPAA2_UNKNOWN) {
			DPAA2_PMD_ERR("Invalid DPDMUX%d IF ID(%d)",
				dpdmux_dev->dpdmux_id, actions[0].type);
			return -EINVAL;
		}
	} else {
		/** TODO*/
		DPAA2_PMD_ERR("MUX Action TYPE(%d) not support",
			actions[0].type);
		return -ENOTSUP;
	}

	rte_spinlock_lock(&dpdmux_dev->lock);

	flow = rte_zmalloc(NULL, sizeof(struct dpaa2_mux_flow),
			   RTE_CACHE_LINE_SIZE);
	if (!flow) {
		DPAA2_PMD_ERR("Failure to allocate memory for flow");
		goto creation_error;
	}

	key_extract = &dpdmux_dev->key_extract;
	dpkg = &key_extract->dpkg;

	flow->key_addr = rte_zmalloc(NULL, DPAA2_EXTRACT_ALLOC_KEY_MAX_SIZE,
		RTE_CACHE_LINE_SIZE);
	if (!flow->key_addr) {
		DPAA2_PMD_ERR("Unable to allocate flow rule buffer");
		ret = -ENOMEM;
		goto creation_error;
	}

	flow->rule.key_iova = DPAA2_VADDR_TO_IOVA_AND_CHECK(flow->key_addr,
		DPAA2_EXTRACT_ALLOC_KEY_MAX_SIZE);
	if (flow->rule.key_iova == RTE_BAD_IOVA) {
		DPAA2_PMD_ERR("%s: No IOMMU mapping for address(%p)",
			__func__, flow->key_addr);
		ret = -ENOBUFS;
		goto creation_error;
	}

	flow->mask_addr = rte_zmalloc(NULL, DPAA2_EXTRACT_ALLOC_KEY_MAX_SIZE,
		RTE_CACHE_LINE_SIZE);
	if (!flow->mask_addr) {
		DPAA2_PMD_ERR("Unable to allocate flow rule mask buffer");
		ret = -ENOMEM;
		goto creation_error;
	}

	flow->rule.mask_iova = DPAA2_VADDR_TO_IOVA_AND_CHECK(flow->mask_addr,
		DPAA2_EXTRACT_ALLOC_KEY_MAX_SIZE);
	if (flow->rule.mask_iova == RTE_BAD_IOVA) {
		DPAA2_PMD_ERR("%s: No IOMMU mapping for address(%p)",
			__func__, flow->mask_addr);
		ret = -ENOBUFS;
		goto creation_error;
	}

	memset(zero_cmp, 0, 256);

	while (pattern[loop].type != RTE_FLOW_ITEM_TYPE_END) {
		if (dpkg->num_extracts >= DPKG_MAX_NUM_OF_EXTRACTS) {
			DPAA2_PMD_ERR("Too many extracts(%d)",
				dpkg->num_extracts);
			ret = -ENOTSUP;
			goto creation_error;
		}
		if (pattern[loop].spec && !pattern[loop].mask) {
			DPAA2_PMD_ERR("Pattern[%d] has no mask for spec",
				loop);
			ret = -EINVAL;
			goto creation_error;
		}
		switch (pattern[loop].type) {
		case RTE_FLOW_ITEM_TYPE_IPV4:
		{
			const struct rte_flow_item_ipv4 *spec;
			const struct rte_flow_item_ipv4 *mask;

			spec = pattern[loop].spec;
			mask = pattern[loop].mask;

			if (!spec || (mask && !memcmp(mask, zero_cmp,
				sizeof(struct rte_flow_item_ipv4)))) {
				ret = dpaa2_mux_add_parser_extract(key_extract,
						DPAA2_PARSER_IPV4_ID,
						flow->key_addr, flow->mask_addr,
						&extract_update);
				if (ret)
					goto creation_error;
			}

			/** Following extraction supports both IPv4 and IPv6*/
			if (spec && mask && mask->hdr.next_proto_id) {
				ret = dpaa2_mux_add_hdr_extract(key_extract,
					NET_PROT_IP, NH_FLD_IP_PROTO,
					sizeof(uint8_t),
					&spec->hdr.next_proto_id,
					&mask->hdr.next_proto_id,
					flow->key_addr, flow->mask_addr,
					&extract_update);
				if (ret)
					goto creation_error;
			}

			if (spec && mask && mask->hdr.fragment_offset) {
				ret = dpaa2_mux_add_parser_extract(key_extract,
						DPAA2_PARSER_IP_FRAG_ID,
						flow->key_addr, flow->mask_addr,
						&extract_update);
				if (ret)
					goto creation_error;
			}

			if (spec && mask && mask->hdr.src_addr) {
				ret = dpaa2_mux_add_ipaddr_extract(key_extract,
					NET_PROT_IPV4, NH_FLD_IPV4_SRC_IP,
					sizeof(rte_be32_t),
					&spec->hdr.src_addr,
					&mask->hdr.src_addr,
					flow->key_addr, flow->mask_addr,
					&extract_update);
				if (ret)
					goto creation_error;
			}
			if (spec && mask && mask->hdr.dst_addr) {
				ret = dpaa2_mux_add_ipaddr_extract(key_extract,
					NET_PROT_IPV4, NH_FLD_IPV4_DST_IP,
					sizeof(rte_be32_t),
					&spec->hdr.dst_addr,
					&mask->hdr.dst_addr,
					flow->key_addr, flow->mask_addr,
					&extract_update);
				if (ret)
					goto creation_error;
			}

			/**TO DO*/
		}
		break;

		case RTE_FLOW_ITEM_TYPE_VLAN:
		{
			const struct rte_flow_item_vlan *spec;
			const struct rte_flow_item_vlan *mask;

			spec = pattern[loop].spec;
			mask = pattern[loop].mask;

			if (!spec || (mask && !memcmp(zero_cmp, mask,
				sizeof(struct rte_flow_item_vlan)))) {
				ret = dpaa2_mux_add_parser_extract(key_extract,
						DPAA2_PARSER_VLAN_ID,
						flow->key_addr, flow->mask_addr,
						&extract_update);
				if (ret)
					goto creation_error;
			}

			if (spec && mask && mask->tci) {
				ret = dpaa2_mux_add_hdr_extract(key_extract,
					NET_PROT_VLAN, NH_FLD_VLAN_TCI,
					sizeof(uint16_t),
					&spec->tci, &mask->tci,
					flow->key_addr, flow->mask_addr,
					&extract_update);
				if (ret)
					goto creation_error;
			}
			/**TO DO*/
		}
		break;

		case RTE_FLOW_ITEM_TYPE_ESP:
		{
			const struct rte_flow_item_esp *spec, *mask;

			spec = pattern[loop].spec;
			mask = pattern[loop].mask;
			if (!spec ||
				(mask && (!mask->hdr.spi && !mask->hdr.seq))) {
				ret = dpaa2_mux_add_parser_extract(key_extract,
						DPAA2_PARSER_IPSEC_ESP_ID,
						flow->key_addr, flow->mask_addr,
						&extract_update);
				if (ret)
					goto creation_error;
			}
			/**TO DO*/
			(void)spec;
			(void)mask;
		}
		break;

		case RTE_FLOW_ITEM_TYPE_GTP:
		{
			const struct rte_flow_item_gtp *spec, *mask;

			spec = pattern[loop].spec;
			mask = pattern[loop].mask;
			if (!spec || (mask && !memcmp(zero_cmp, mask,
				sizeof(struct rte_flow_item_gtp)))) {
				ret = dpaa2_mux_add_parser_extract(key_extract,
						DPAA2_PARSER_GTP_ID,
						flow->key_addr, flow->mask_addr,
						&extract_update);
				if (ret)
					goto creation_error;
			}
			/**TO DO*/
			(void)spec;
			(void)mask;
		}
		break;

		case RTE_FLOW_ITEM_TYPE_UDP:
		{
			const struct rte_flow_item_udp *spec;
			const struct rte_flow_item_udp *mask;

			spec = pattern[loop].spec;
			mask = pattern[loop].mask;

			/** For L4 protocol, we must specify UDP.*/
			ret = dpaa2_mux_add_parser_extract(key_extract,
					DPAA2_PARSER_UDP_ID,
					flow->key_addr, flow->mask_addr,
					&extract_update);
			if (ret)
				goto creation_error;

			if (spec && mask && mask->hdr.src_port) {
				ret = dpaa2_mux_add_hdr_extract(key_extract,
					NET_PROT_UDP, NH_FLD_UDP_PORT_SRC,
					sizeof(rte_be16_t),
					&spec->hdr.src_port,
					&mask->hdr.src_port,
					flow->key_addr, flow->mask_addr,
					&extract_update);
				if (ret)
					goto creation_error;
			}
			if (spec && mask && mask->hdr.dst_port) {
				ret = dpaa2_mux_add_hdr_extract(key_extract,
					NET_PROT_UDP, NH_FLD_UDP_PORT_DST,
					sizeof(rte_be16_t),
					&spec->hdr.dst_port,
					&mask->hdr.dst_port,
					flow->key_addr, flow->mask_addr,
					&extract_update);
				if (ret)
					goto creation_error;
			}
			/**TO DO*/
		}
		break;

		case RTE_FLOW_ITEM_TYPE_ETH:
		{
			const struct rte_flow_item_eth *spec;
			const struct rte_flow_item_eth *mask;

			spec = pattern[loop].spec;
			mask = pattern[loop].mask;

			if (!spec || (mask && !memcmp(zero_cmp, mask,
				sizeof(struct rte_flow_item_eth)))) {
				ret = dpaa2_mux_add_parser_extract(key_extract,
						DPAA2_PARSER_MAC_ID,
						flow->key_addr, flow->mask_addr,
						&extract_update);
				if (ret)
					goto creation_error;
			}

			if (spec && mask && mask->type) {
				ret = dpaa2_mux_add_hdr_extract(key_extract,
					NET_PROT_ETH, NH_FLD_ETH_TYPE,
					sizeof(rte_be16_t),
					&spec->type, &mask->type,
					flow->key_addr, flow->mask_addr,
					&extract_update);
				if (ret)
					goto creation_error;
			}
			/**TO DO*/
		}
		break;

		case RTE_FLOW_ITEM_TYPE_RAW:
		{
			const struct rte_flow_item_raw *spec;
			const struct rte_flow_item_raw *mask;

			spec = pattern[loop].spec;
			mask = pattern[loop].mask;

			ret = dpaa2_mux_add_non_hdr_extract(key_extract,
				spec->offset, spec->length,
				DPKG_EXTRACT_FROM_DATA,
				spec->pattern, mask->pattern,
				flow->key_addr, flow->mask_addr,
				&extract_update);
			if (ret)
				goto creation_error;
		}
		break;

		case RTE_FLOW_ITEM_TYPE_ECPRI:
		{
			const struct rte_flow_item_ecpri *spec, *mask;
			int extract_nb, i;
			uint64_t rule_data[DPAA2_ECPRI_MAX_EXTRACT_NB];
			uint64_t mask_data[DPAA2_ECPRI_MAX_EXTRACT_NB];
			uint8_t extract_size[DPAA2_ECPRI_MAX_EXTRACT_NB];
			uint8_t extract_off[DPAA2_ECPRI_MAX_EXTRACT_NB];
			union dpaa2_sp_fafe_parse fafe;

			spec = pattern[loop].spec;
			mask = pattern[loop].mask;

			if (!dpaa2_soft_parser_loaded()) {
				DPAA2_PMD_ERR("eCPRI mux flow: SP not loaded");
				ret = -ENOTSUP;
				goto creation_error;
			}

			if (!spec) {
				ret = dpaa2_mux_add_parser_extract(key_extract,
						DPAA2_PARSER_ECPRI_ID,
						flow->key_addr, flow->mask_addr,
						&extract_update);
				if (ret)
					goto creation_error;

				break;
			}

			extract_nb = dpaa2_parser_ecpri_extract(spec, mask,
				rule_data, mask_data, extract_size, extract_off,
				&fafe);
			if (extract_nb < 0) {
				DPAA2_PMD_ERR("MUX Extract eCPRI failed(%d)",
					extract_nb);

				ret = extract_nb;

				goto creation_error;
			}
			for (i = 0; i < extract_nb; i++) {
				ret = dpaa2_mux_add_non_hdr_extract(key_extract,
					extract_off[i], extract_size[i],
					DPKG_EXTRACT_FROM_PARSE,
					&rule_data[i], &mask_data[i],
					flow->key_addr, flow->mask_addr,
					&extract_update);
				if (ret)
					goto creation_error;
			}
		}
		break;

		default:
			DPAA2_PMD_ERR("Not supported pattern[%d] type: %d",
				loop, pattern[loop].type);
			ret = -ENOTSUP;
			goto creation_error;
		}
		loop++;
	}

	if (!extract_update)
		goto add_entry;

	_flow = LIST_FIRST(&dpdmux_dev->flows);
	while (_flow) {
		dpaa2_mux_flow_rule_log(_flow, "remove");
		ret = dpdmux_remove_custom_cls_entry(&dpdmux_dev->dpdmux,
			CMD_PRI_LOW, dpdmux_dev->token,
			&_flow->rule);
		if (ret) {
			DPAA2_PMD_ERR("Remove mux rule failed(%d)", ret);
			goto creation_error;
		}
		_flow = LIST_NEXT(_flow, next);
	}
	dpaa2_mux_extracts_log(dpdmux_dev);
	ret = dpkg_prepare_key_cfg(dpkg, dpdmux_dev->key_param);
	if (ret) {
		DPAA2_PMD_ERR("dpkg_prepare_key_cfg failed(%d)", ret);
		goto creation_error;
	}
	ret = dpdmux_set_custom_key(&dpdmux_dev->dpdmux,
			CMD_PRI_LOW, dpdmux_dev->token,
			dpdmux_dev->key_param_iova);
	if (ret) {
		DPAA2_PMD_ERR("dpdmux_set_custom_key failed(%d)",
			ret);
		goto creation_error;
	}
	_flow = LIST_FIRST(&dpdmux_dev->flows);
	while (_flow) {
		_flow->rule.key_size = key_extract->key_profile.key_max_size;
		dpaa2_mux_flow_rule_log(_flow, "update");
		ret = dpdmux_add_custom_cls_entry(&dpdmux_dev->dpdmux,
			CMD_PRI_LOW, dpdmux_dev->token,
			&_flow->rule, &_flow->action);
		if (ret) {
			DPAA2_PMD_ERR("Re-add mux rule failed(%d)", ret);
			goto creation_error;
		}
		_flow = LIST_NEXT(_flow, next);
	}

add_entry:

	flow->action.dest_if = vf_conf->id;
	/* As now our key extract parameters are set, let us configure
	 * the rule.
	 */
	flow->rule.entry_index = dpdmux_dev->flow_num;
	flow->rule.key_size = key_extract->key_profile.key_max_size;
	dpaa2_mux_flow_rule_log(flow, "new");
	ret = dpdmux_add_custom_cls_entry(&dpdmux_dev->dpdmux,
			CMD_PRI_LOW, dpdmux_dev->token,
			&flow->rule, &flow->action);
	if (ret) {
		DPAA2_PMD_ERR("MUX add classification entry failed(%d)",
			ret);
		goto creation_error;
	}
	dpdmux_dev->flow_num++;
	LIST_INSERT_HEAD(&dpdmux_dev->flows, flow, next);
	rte_spinlock_unlock(&dpdmux_dev->lock);

	return flow->rule.entry_index;

creation_error:
	rte_spinlock_unlock(&dpdmux_dev->lock);
	if (flow) {
		rte_free(flow->key_addr);
		rte_free(flow->mask_addr);
	}
	rte_free(flow);

	return ret;
}

int
rte_pmd_dpaa2_mux_flow_destroy(uint32_t dpdmux_id,
	uint16_t entry_index)
{
	struct dpaa2_dpdmux_dev *dpdmux_dev;
	int ret;
	struct dpaa2_mux_flow *flow, *next;

	dpdmux_dev = get_dpdmux_from_id(dpdmux_id);
	if (!dpdmux_dev) {
		DPAA2_PMD_ERR("Invalid DPDMUX ID(%d)", dpdmux_id);
		return -ENODEV;
	}

	rte_spinlock_lock(&dpdmux_dev->lock);

	flow = LIST_FIRST(&dpdmux_dev->flows);
	while (flow) {
		next = LIST_NEXT(flow, next);
		if (flow->rule.entry_index != entry_index) {
			flow = next;
			continue;
		}
		dpaa2_mux_flow_rule_log(flow, "remove");
		ret = dpdmux_remove_custom_cls_entry(&dpdmux_dev->dpdmux,
				CMD_PRI_LOW, dpdmux_dev->token,
				&flow->rule);
		if (ret) {
			DPAA2_PMD_ERR("Remove mux rule failed: err(%d)",
				ret);
			rte_spinlock_unlock(&dpdmux_dev->lock);
			return ret;
		}
		LIST_REMOVE(flow, next);
		rte_free(flow->key_addr);
		rte_free(flow->mask_addr);
		rte_free(flow);
		rte_spinlock_unlock(&dpdmux_dev->lock);

		return 0;
	}

	rte_spinlock_unlock(&dpdmux_dev->lock);
	DPAA2_PMD_ERR("%s: no flow index(%d) found in dpdmux%d",
		__func__, entry_index, dpdmux_id);

	return -EINVAL;
}

int
rte_pmd_dpaa2_mux_flow_l2(uint32_t dpdmux_id,
	uint8_t mac_addr[6], uint16_t vlan_id, int dest_if)
{
	struct dpaa2_dpdmux_dev *dpdmux_dev;
	struct dpdmux_l2_rule rule;
	int ret, i;

	/* Find the DPDMUX from dpdmux_id in our list */
	dpdmux_dev = get_dpdmux_from_id(dpdmux_id);
	if (!dpdmux_dev) {
		DPAA2_PMD_ERR("Invalid dpdmux_id: %d", dpdmux_id);
		return -ENODEV;
	}

	for (i = 0; i < 6; i++)
		rule.mac_addr[i] = mac_addr[i];
	rule.vlan_id = vlan_id;

	ret = dpdmux_if_add_l2_rule(&dpdmux_dev->dpdmux, CMD_PRI_LOW,
			dpdmux_dev->token, dest_if, &rule);
	if (ret) {
		DPAA2_PMD_ERR("dpdmux_if_add_l2_rule failed:err(%d)", ret);
		return ret;
	}

	return 0;
}

int
rte_pmd_dpaa2_mux_rx_frame_len(uint32_t dpdmux_id, uint16_t max_rx_frame_len)
{
	struct dpaa2_dpdmux_dev *dpdmux_dev;
	int ret;

	/* Find the DPDMUX from dpdmux_id in our list */
	dpdmux_dev = get_dpdmux_from_id(dpdmux_id);
	if (!dpdmux_dev) {
		DPAA2_PMD_ERR("Invalid dpdmux_id: %d", dpdmux_id);
		return -1;
	}

	ret = dpdmux_set_max_frame_length(&dpdmux_dev->dpdmux,
			CMD_PRI_LOW, dpdmux_dev->token, max_rx_frame_len);
	if (ret) {
		DPAA2_PMD_ERR("DPDMUX:Unable to set mtu. check config %d", ret);
		return ret;
	}

	DPAA2_PMD_INFO("dpdmux mtu set as %u",
			DPAA2_MAX_RX_PKT_LEN - RTE_ETHER_CRC_LEN);

	return ret;
}

/* dump the status of the dpaa2_mux counters on the console */
void
rte_pmd_dpaa2_mux_dump_counter(FILE *f, uint32_t dpdmux_id, int num_if)
{
	struct dpaa2_dpdmux_dev *dpdmux;
	uint64_t counter;
	int ret;
	int if_id;

	/* Find the DPDMUX from dpdmux_id in our list */
	dpdmux = get_dpdmux_from_id(dpdmux_id);
	if (!dpdmux) {
		DPAA2_PMD_ERR("Invalid dpdmux_id: %d", dpdmux_id);
		return;
	}

	for (if_id = 0; if_id < num_if; if_id++) {
		fprintf(f, "dpdmux.%d\n", if_id);

		ret = dpdmux_if_get_counter(&dpdmux->dpdmux, CMD_PRI_LOW,
			dpdmux->token, if_id, DPDMUX_CNT_ING_FRAME, &counter);
		if (!ret)
			fprintf(f, "DPDMUX_CNT_ING_FRAME %" PRIu64 "\n",
				counter);
		ret = dpdmux_if_get_counter(&dpdmux->dpdmux, CMD_PRI_LOW,
			dpdmux->token, if_id, DPDMUX_CNT_ING_BYTE, &counter);
		if (!ret)
			fprintf(f, "DPDMUX_CNT_ING_BYTE %" PRIu64 "\n",
				counter);
		ret = dpdmux_if_get_counter(&dpdmux->dpdmux, CMD_PRI_LOW,
			dpdmux->token, if_id, DPDMUX_CNT_ING_FLTR_FRAME,
			&counter);
		if (!ret)
			fprintf(f, "DPDMUX_CNT_ING_FLTR_FRAME %" PRIu64 "\n",
				counter);
		ret = dpdmux_if_get_counter(&dpdmux->dpdmux, CMD_PRI_LOW,
			dpdmux->token, if_id, DPDMUX_CNT_ING_FRAME_DISCARD,
			&counter);
		if (!ret)
			fprintf(f, "DPDMUX_CNT_ING_FRAME_DISCARD %" PRIu64 "\n",
				counter);
		ret = dpdmux_if_get_counter(&dpdmux->dpdmux, CMD_PRI_LOW,
			dpdmux->token, if_id, DPDMUX_CNT_ING_MCAST_FRAME,
			&counter);
		if (!ret)
			fprintf(f, "DPDMUX_CNT_ING_MCAST_FRAME %" PRIu64 "\n",
				counter);
		ret = dpdmux_if_get_counter(&dpdmux->dpdmux, CMD_PRI_LOW,
			dpdmux->token, if_id, DPDMUX_CNT_ING_MCAST_BYTE,
			&counter);
		if (!ret)
			fprintf(f, "DPDMUX_CNT_ING_MCAST_BYTE %" PRIu64 "\n",
				counter);
		ret = dpdmux_if_get_counter(&dpdmux->dpdmux, CMD_PRI_LOW,
			dpdmux->token, if_id, DPDMUX_CNT_ING_BCAST_FRAME,
			&counter);
		if (!ret)
			fprintf(f, "DPDMUX_CNT_ING_BCAST_FRAME %" PRIu64 "\n",
				counter);
		ret = dpdmux_if_get_counter(&dpdmux->dpdmux, CMD_PRI_LOW,
			dpdmux->token, if_id, DPDMUX_CNT_ING_BCAST_BYTES,
			&counter);
		if (!ret)
			fprintf(f, "DPDMUX_CNT_ING_BCAST_BYTES %" PRIu64 "\n",
				counter);
		ret = dpdmux_if_get_counter(&dpdmux->dpdmux, CMD_PRI_LOW,
			dpdmux->token, if_id, DPDMUX_CNT_EGR_FRAME, &counter);
		if (!ret)
			fprintf(f, "DPDMUX_CNT_EGR_FRAME %" PRIu64 "\n",
				counter);
		ret = dpdmux_if_get_counter(&dpdmux->dpdmux, CMD_PRI_LOW,
			dpdmux->token, if_id, DPDMUX_CNT_EGR_BYTE, &counter);
		if (!ret)
			fprintf(f, "DPDMUX_CNT_EGR_BYTE %" PRIu64 "\n",
				counter);
		ret = dpdmux_if_get_counter(&dpdmux->dpdmux, CMD_PRI_LOW,
			dpdmux->token, if_id, DPDMUX_CNT_EGR_FRAME_DISCARD,
			&counter);
		if (!ret)
			fprintf(f, "DPDMUX_CNT_EGR_FRAME_DISCARD %" PRIu64 "\n",
				counter);
	}
}

int
rte_pmd_dpaa2_mux_default_id(uint32_t dpdmux_id, uint16_t *id)
{
	struct dpaa2_dpdmux_dev *dpdmux_dev;
	int ret;

	/* Find the DPDMUX from dpdmux_id in our list */
	dpdmux_dev = get_dpdmux_from_id(dpdmux_id);
	if (!dpdmux_dev) {
		DPAA2_PMD_ERR("Invalid dpdmux_id: %d", dpdmux_id);
		return -ENODEV;
	}
	ret = dpdmux_if_get_default(&dpdmux_dev->dpdmux, CMD_PRI_LOW,
		dpdmux_dev->token, id);
	if (ret) {
		DPAA2_PMD_ERR("Failed(%d) to get default interface of dpdmux%d",
			ret, dpdmux_id);
	}

	return ret;
}

int
rte_pmd_dpaa2_mux_ep_name(uint32_t dpdmux_id,
	uint16_t id, const char **name)
{
	struct dpaa2_dpdmux_dev *dpdmux_dev;

	/* Find the DPDMUX from dpdmux_id in our list */
	dpdmux_dev = get_dpdmux_from_id(dpdmux_id);
	if (!dpdmux_dev) {
		DPAA2_PMD_ERR("Invalid dpdmux_id: %d", dpdmux_id);
		return -ENODEV;
	}
	if (id >= (dpdmux_dev->num_ifs + 1)) {
		DPAA2_PMD_ERR("dpdmux interface ID(%d) >= (%d + 1)",
			id, dpdmux_dev->num_ifs);
		return -EINVAL;
	}
	*name = dpdmux_dev->mux_eps[id].ep_name;

	return 0;
}

static int
dpaa2_create_dpdmux_device(int vdev_fd __rte_unused,
	struct vfio_device_info *obj_info __rte_unused,
	struct rte_dpaa2_device *obj)
{
	struct dpaa2_dpdmux_dev *dpdmux_dev;
	struct dpdmux_attr attr;
	int ret, dpdmux_id = obj->object_id, i;
	uint16_t maj_ver;
	uint16_t min_ver;
	uint8_t skip_reset_flags;
	struct dprc_endpoint endpoint1, endpoint2;
	int link_state;

	PMD_INIT_FUNC_TRACE();

	/* Allocate DPAA2 dpdmux handle */
	dpdmux_dev = rte_zmalloc(NULL,
		sizeof(struct dpaa2_dpdmux_dev), RTE_CACHE_LINE_SIZE);
	if (!dpdmux_dev) {
		DPAA2_PMD_ERR("Memory allocation failed for DPDMUX Device");
		return -ENOMEM;
	}

	if(getenv("DPAA2_MUX_FLOW_LOG"))
		dpaa2_mux_flow_log = 1;

	/* Open the dpdmux object */
	dpdmux_dev->dpdmux.regs = dpaa2_get_mcp_ptr(MC_PORTAL_INDEX);
	ret = dpdmux_open(&dpdmux_dev->dpdmux, CMD_PRI_LOW, dpdmux_id,
		&dpdmux_dev->token);
	if (ret) {
		DPAA2_PMD_ERR("Unable to open dpdmux object: err(%d)", ret);
		goto init_err;
	}

	ret = dpdmux_get_attributes(&dpdmux_dev->dpdmux, CMD_PRI_LOW,
		dpdmux_dev->token, &attr);
	if (ret) {
		DPAA2_PMD_ERR("Unable to get dpdmux attr: err(%d)", ret);
		goto init_err;
	}

	if (attr.method != DPDMUX_METHOD_C_VLAN_MAC) {
		ret = dpdmux_if_set_default(&dpdmux_dev->dpdmux, CMD_PRI_LOW,
			dpdmux_dev->token, attr.default_if);
		if (ret) {
			DPAA2_PMD_ERR("setting default interface failed in %s",
				__func__);
			goto init_err;
		}
		skip_reset_flags = DPDMUX_SKIP_MODIFY_DEFAULT_INTERFACE |
			DPDMUX_SKIP_UNICAST_RULES | DPDMUX_SKIP_MULTICAST_RULES |
			DPDMUX_SKIP_RESET_DEFAULT_INTERFACE;
	} else {
		skip_reset_flags = DPDMUX_SKIP_MODIFY_DEFAULT_INTERFACE |
					DPDMUX_SKIP_RESET_DEFAULT_INTERFACE;
	}

	ret = dpdmux_get_api_version(&dpdmux_dev->dpdmux, CMD_PRI_LOW,
			&maj_ver, &min_ver);
	if (ret) {
		DPAA2_PMD_ERR("setting version failed in %s", __func__);
		goto init_err;
	}

	/* The new dpdmux_set/get_resetable() API are available starting with
	 * DPDMUX_VER_MAJOR==6 and DPDMUX_VER_MINOR==6
	 */
	if (maj_ver >= 6 && min_ver >= 6) {
		ret = dpdmux_set_resetable(&dpdmux_dev->dpdmux, CMD_PRI_LOW,
				dpdmux_dev->token, skip_reset_flags);
		if (ret) {
			DPAA2_PMD_ERR("setting default interface failed in %s",
				__func__);
			goto init_err;
		}
	}

	if (maj_ver >= 6 && min_ver >= 9) {
		struct dpdmux_error_cfg mux_err_cfg;

		memset(&mux_err_cfg, 0, sizeof(mux_err_cfg));
		/* Note: Discarded flag(DPDMUX_ERROR_DISC) has effect only when
		         ERROR_ACTION is set to DPNI_ERROR_ACTION_SEND_TO_ERROR_QUEUE.
		*/
		mux_err_cfg.errors = DPDMUX_ALL_ERRORS;
		mux_err_cfg.error_action = DPDMUX_ERROR_ACTION_CONTINUE;

		ret = dpdmux_if_set_errors_behavior(&dpdmux_dev->dpdmux,
				CMD_PRI_LOW,
				dpdmux_dev->token, DPAA2_DPDMUX_DPMAC_IDX,
				&mux_err_cfg);
		if (ret) {
			DPAA2_PMD_ERR("dpdmux_if_set_errors_behavior %s err %d",
				__func__, ret);
			goto init_err;
		}
	}

	dpdmux_dev->dpdmux_id = dpdmux_id;
	dpdmux_dev->num_ifs = attr.num_ifs;
	/**Up link + down link.*/
	dpdmux_dev->mux_eps = rte_zmalloc(NULL,
		sizeof(struct dpaa2_mux_ep) * (attr.num_ifs + 1),
		RTE_CACHE_LINE_SIZE);
	if (!dpdmux_dev->mux_eps) {
		ret = -ENOMEM;
		goto init_err;
	}

	memset(&endpoint1, 0, sizeof(struct dprc_endpoint));
	strcpy(endpoint1.type, "dpdmux");
	endpoint1.id = dpdmux_id;
	for (i = 0; i < (attr.num_ifs + 1); i++) {
		memset(&endpoint2, 0, sizeof(struct dprc_endpoint));
		endpoint1.if_id = i;
		dpdmux_dev->mux_eps[i].mux_if_id = i;
		ret = dprc_get_connection(&obj->container->dprc,
				CMD_PRI_LOW,
				obj->container->token,
				&endpoint1, &endpoint2,
				&link_state);
		if (ret) {
			DPAA2_PMD_WARN("DPDMUX get ep of %s.%d.%d failed(%d)",
				endpoint1.type, endpoint1.id, endpoint1.if_id,
				ret);
			dpdmux_dev->mux_eps[i].ep_type = DPAA2_UNKNOWN;
			continue;
		}
		dpdmux_dev->mux_eps[i].ep_object_id = endpoint2.id;
		if (!strcmp(endpoint2.type, "dpmac")) {
			dpdmux_dev->mux_eps[i].ep_type = DPAA2_MAC;
		} else if (!strcmp(endpoint2.type, "dpni")) {
			dpdmux_dev->mux_eps[i].ep_type = DPAA2_ETH;
		} else if (!strcmp(endpoint2.type, "dpdmux")) {
			dpdmux_dev->mux_eps[i].ep_type = DPAA2_MUX;
			dpdmux_dev->mux_eps[i].ep_if_id = endpoint2.if_id;
		} else if (!strcmp(endpoint2.type, "dpsw")) {
			dpdmux_dev->mux_eps[i].ep_type = DPAA2_SW;
			dpdmux_dev->mux_eps[i].ep_if_id = endpoint2.if_id;
		} else {
			DPAA2_PMD_WARN("DPDMUX get unknown EP type(%s)",
				endpoint2.type);
			dpdmux_dev->mux_eps[i].ep_type = DPAA2_UNKNOWN;
		}
		if (dpdmux_dev->mux_eps[i].ep_type == DPAA2_MUX ||
			dpdmux_dev->mux_eps[i].ep_type == DPAA2_SW) {
			sprintf(dpdmux_dev->mux_eps[i].ep_name,
				"%s.%d.%d", endpoint2.type, endpoint2.id,
				endpoint2.if_id);
		} else {
			sprintf(dpdmux_dev->mux_eps[i].ep_name,
				"%s.%d", endpoint2.type, endpoint2.id);
		}
		RTE_LOG(INFO, PMD,
			"DPDMUX(%d)-IF%d: %s\n",
			dpdmux_id, i, dpdmux_dev->mux_eps[i].ep_name);
	}

	dpdmux_dev->key_param = rte_zmalloc(NULL,
		DIST_PARAM_IOVA_SIZE, RTE_CACHE_LINE_SIZE);
	if (!dpdmux_dev->key_param) {
		DPAA2_PMD_ERR("Failure to allocate memory for extract");
		goto init_err;
	}
	dpdmux_dev->key_param_iova =
		DPAA2_VADDR_TO_IOVA_AND_CHECK(dpdmux_dev->key_param,
			DPAA2_EXTRACT_ALLOC_KEY_MAX_SIZE);
	if (dpdmux_dev->key_param_iova == RTE_BAD_IOVA) {
		DPAA2_PMD_ERR("%s: No IOMMU mapping for address(%p)",
			__func__, dpdmux_dev->key_param);
		ret = -ENOBUFS;
		goto init_err;
	}
	rte_spinlock_init(&dpdmux_dev->lock);

	TAILQ_INSERT_TAIL(&dpdmux_dev_list, dpdmux_dev, next);

	return 0;

init_err:
	if (dpdmux_dev) {
		rte_free(dpdmux_dev->mux_eps);
		rte_free(dpdmux_dev->key_param);
	}
	rte_free(dpdmux_dev);

	return ret;
}

static void
dpaa2_close_dpdmux_device(int object_id)
{
	struct dpaa2_dpdmux_dev *dpdmux_dev;
	struct dpaa2_mux_flow *flow, *next;
	int ret;

	dpdmux_dev = get_dpdmux_from_id((uint32_t)object_id);

	flow = LIST_FIRST(&dpdmux_dev->flows);
	while (flow) {
		next = LIST_NEXT(flow, next);
		dpaa2_mux_flow_rule_log(flow, "remove");
		ret = dpdmux_remove_custom_cls_entry(&dpdmux_dev->dpdmux,
				CMD_PRI_LOW, dpdmux_dev->token,
				&flow->rule);
		if (ret)
			DPAA2_PMD_ERR("Remove mux rule failed: err(%d)", ret);
		LIST_REMOVE(flow, next);
		rte_free(flow->key_addr);
		rte_free(flow->mask_addr);
		rte_free(flow);
		flow = next;
	}

	if (dpdmux_dev) {
		dpdmux_close(&dpdmux_dev->dpdmux, CMD_PRI_LOW,
			     dpdmux_dev->token);
		TAILQ_REMOVE(&dpdmux_dev_list, dpdmux_dev, next);
		rte_free(dpdmux_dev);
	}
}

static struct rte_dpaa2_object rte_dpaa2_dpdmux_obj = {
	.dev_type = DPAA2_MUX,
	.create = dpaa2_create_dpdmux_device,
	.close = dpaa2_close_dpdmux_device,
};

RTE_PMD_REGISTER_DPAA2_OBJECT(dpdmux, rte_dpaa2_dpdmux_obj);

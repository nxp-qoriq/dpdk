/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2023-2025 NXP
 */

#ifndef _RTE_DPAA2_MUX_DEMO_H
#define _RTE_DPAA2_MUX_DEMO_H
#include <rte_pmd_dpaa2.h>

enum {
	TRAFFIC_SPLIT_NONE,
	TRAFFIC_SPLIT_ETHTYPE,
	TRAFFIC_SPLIT_IP_PROTO,
	TRAFFIC_SPLIT_UDP_DST_PORT,
	TRAFFIC_SPLIT_IP_FRAG_UDP_AND_GTP,
	TRAFFIC_SPLIT_IP_FRAG_PROTO,
	TRAFFIC_SPLIT_IP_FRAG_UDP_AND_GTP_AND_ESP,
	TRAFFIC_SPLIT_VLAN,
	TRAFFIC_SPLIT_ECPRI,
	TRAFFIC_SPLIT_MAX_NUM
};

static uint8_t s_mux_demo_proto; /**< Split traffic based on this protocol ID */
static uint16_t s_mux_demo_ethtype; /**< Split traffic based on eth type */

static uint8_t s_mux_type; /**< Split traffic based on type */
static uint32_t s_mux_val;

static uint8_t s_mux_ep_id;

enum dpaa2_mux_demo_l3 {
	DPAA2_MUX_DEMO_NO_L3,
	DPAA2_MUX_DEMO_IPv4,
	DPAA2_MUX_DEMO_IPv6
};

enum dpaa2_mux_demo_l4 {
	DPAA2_MUX_DEMO_NO_L4,
	DPAA2_MUX_DEMO_UDP,
	DPAA2_MUX_DEMO_TCP
};

struct dpaa2_mux_demo_5tups {
	int dpdmux_id;
	uint8_t ep_id;
	enum dpaa2_mux_demo_l3 l3;
	union {
		struct rte_ipv4_hdr ipv4_hdr;
		struct rte_ipv6_hdr ipv6_hdr;
	};
	union {
		struct rte_ipv4_hdr ipv4_mask;
		struct rte_ipv6_hdr ipv6_mask;
	};
	enum dpaa2_mux_demo_l4 l4;
	union {
		struct rte_udp_hdr udp_hdr;
		struct rte_tcp_hdr tcp_hdr;
	};
	union {
		struct rte_udp_hdr udp_mask;
		struct rte_tcp_hdr tcp_mask;
	};
	int flow_idx;
};

#define DPAA2_MUX_MAX_5T_FLOWS 128
struct dpaa2_mux_demo_5tups s_mux_5tups[DPAA2_MUX_MAX_5T_FLOWS];
static uint16_t s_mux_5tups_num;

#ifndef RTE_LOGTYPE_dpaa2_mux_demo
#define RTE_LOGTYPE_dpaa2_mux_demo RTE_LOGTYPE_USER1
#endif

static int
dpaa2_mux_demo_get_mux_id(void)
{
	int dpdmux_id = -ENODEV, ret, offset = 0;
	FILE *fp;
	char nm[1024];

	offset += sprintf(&nm[offset], "restool dprc show $DPRC ");
	offset += sprintf(&nm[offset], "| grep dpdmux ");
	offset += sprintf(&nm[offset], "| cut -f 1 | cut -d . -f 2");
	/* Get the dpdmux ID from environment */
	fp = popen(nm, "r");
	if (!fp) {
		RTE_LOG(ERR, dpaa2_mux_demo,
			"Error in getting dpdmux id\n");
		return -ENODEV;
	}

	ret = fscanf(fp, "%d", &dpdmux_id);
	if (ret != 1) {
		RTE_LOG(ERR, dpaa2_mux_demo,
			"Failed to get dpdmux id\n");
		dpdmux_id = -ENODEV;
	}
	pclose(fp);

	return dpdmux_id;
}

static int
parse_traffic_split_config(const char *q_arg)
{
	char s[256];
	const char *p, *p0 = q_arg;
	char *end;
	enum fieldnames {
		FLD_SPLIT_TYPE = 0,
		FLD_SPLIT_VAL,
		FLD_MUX_CONN_ID,
		_NUM_FLD
	};
	unsigned long int_fld[_NUM_FLD];
	char *str_fld[_NUM_FLD];
	int i;
	unsigned int size;
	int dpdmux_id;;
	char mux_ep_nm[64];

	p = strchr(p0, '(');
	++p;
	p0 = strchr(p, ')');
	if (!p0)
		return -EINVAL;

	size = p0 - p;
	if (size >= sizeof(s))
		return -EINVAL;

	snprintf(s, sizeof(s), "%.*s", size, p);
	if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
		return -EINVAL;
	for (i = 0; i < _NUM_FLD; i++) {
		errno = 0;
		int_fld[i] = strtoul(str_fld[i], &end, 0);
		if (errno || end == str_fld[i])
			return -EINVAL;
	}

	s_mux_type = (uint8_t)int_fld[FLD_SPLIT_TYPE];
	if (s_mux_type >= TRAFFIC_SPLIT_MAX_NUM) {
		RTE_LOG(ERR, dpaa2_mux_demo,
			"Invalid MUX split type(%d)\n", s_mux_type);
		return -EINVAL;
	}
	s_mux_val = int_fld[FLD_SPLIT_VAL];
	s_mux_ep_id = (uint8_t)int_fld[FLD_MUX_CONN_ID];

	dpdmux_id = dpaa2_mux_demo_get_mux_id();
	if (dpdmux_id < 0) {
		RTE_LOG(ERR, dpaa2_mux_demo,
			"get mux ID failed(%d)\n", dpdmux_id);
		return dpdmux_id;
	}
	sprintf(mux_ep_nm, "dpdmux.%d.%d", dpdmux_id, s_mux_ep_id);

	RTE_LOG(INFO, dpaa2_mux_demo,
		"Splitting MUX traffic on type:%d with val:%d on %s\n",
		s_mux_type, s_mux_val, mux_ep_nm);

	return 0;
}

static inline int
parse_traffic_split_info(const char *split_args)
{
	int key, dpni_id;
	char *dup_str;
	char *dpni, *proto;
	char delim = ':';

	/* the string would be in format <number>:<number> */
	dup_str = strdup(split_args);
	if (!dup_str)
		return -ENOBUFS;
	proto = dup_str;
	dpni = strchr(dup_str, delim);
	if (dpni) {
		proto[dpni - proto] = '\0';
		dpni += 1;
	} else
		goto err_ret;

	key = strtod(proto, NULL);
	if (proto[0] == '\0' || key <= 0 || key > USHRT_MAX)
		goto err_ret;

	dpni_id = strtod(dpni, NULL);
	if (dpni[0] == '\0' || dpni_id < 0 || dpni_id > INT_MAX)
		goto err_ret;

	/* if key is < 0xff - consider it tobe IP protocol
	 * else it is ether type
	 */
	if (key > 0xff)
		s_mux_demo_ethtype = key;
	else
		s_mux_demo_proto = key;
	s_mux_ep_id = dpni_id;

	RTE_LOG(INFO, dpaa2_mux_demo,
		"Split on %s(0x%x) to DPNI.%d\n",
		s_mux_demo_ethtype ?
		"ETH with ethtype" : "IP with next prot",
		s_mux_demo_ethtype ?
		s_mux_demo_ethtype : s_mux_demo_proto,
		s_mux_ep_id);

	return 0;

err_ret:
	if (dup_str)
		free(dup_str);
	return -EINVAL;
}

enum mux_5_tup_field {
	FLD_5_TUP_L3 = 0,
	FLD_5_TUP_L3_SRC,
	FLD_5_TUP_L3_DST,
	FLD_5_TUP_L4,
	FLD_5_TUP_L4_SRC,
	FLD_5_TUP_L4_DST,
	FLD_5_TUP_EP,
	FLD_5_TUP_NUM_FLD
};

enum mux_5_tup_count_flow_field {
	FLD_5_TUP_L3_SRC_BASE = 0,
	FLD_5_TUP_L3_DST_BASE,
	FLD_5_TUP_SRC_COUNT,
	FLD_5_TUP_DST_COUNT,
	FLD_5_TUP_L4_SRC_PORT,
	FLD_5_TUP_L4_DST_PORT,
	FLD_5_TUP_COUNT_FLOW_EP,
	FLD_5_TUP_COUNT_FLOW_NUM_FLD
};

static int
parse_5_tuple_count_flow_config(const char *q_arg)
{
	char s[256];
	const char *p, *p0 = q_arg;
	char *end;
	uint64_t ul_fld[FLD_5_TUP_COUNT_FLOW_NUM_FLD];
	char *str_fld[FLD_5_TUP_COUNT_FLOW_NUM_FLD];
	int flow_num = 0, dpdmux_id;
	uint32_t src_cnt, dst_cnt, src_ip_base, dst_ip_base, size, i, j;
	rte_be16_t src_port, dst_port;
	rte_be32_t src_ip, dst_ip;

	dpdmux_id = dpaa2_mux_demo_get_mux_id();
	if (dpdmux_id < 0) {
		RTE_LOG(INFO, dpaa2_mux_demo,
			"%s: No DPDMUX created.\n", __func__);
		return dpdmux_id;
	}

	p = strchr(p0, '(');
	if (!p)
		return -EINVAL;
	++p;
	p0 = strchr(p, ')');
	if (!p0)
		return -EINVAL;

	size = p0 - p;
	if (size >= sizeof(s))
		return -EINVAL;

	snprintf(s, sizeof(s), "%.*s", size, p);
	if (rte_strsplit(s, sizeof(s), str_fld,
		FLD_5_TUP_COUNT_FLOW_NUM_FLD, ',') !=
		FLD_5_TUP_COUNT_FLOW_NUM_FLD)
		return -EINVAL;
	for (i = 0; i < FLD_5_TUP_COUNT_FLOW_NUM_FLD; i++) {
		errno = 0;
		ul_fld[i] = strtoul(str_fld[i], &end, 16);
		if (errno || end == str_fld[i])
			return -EINVAL;
	}
	src_cnt = ul_fld[FLD_5_TUP_SRC_COUNT];
	dst_cnt = ul_fld[FLD_5_TUP_DST_COUNT];
	if ((src_cnt * dst_cnt) > DPAA2_MUX_MAX_5T_FLOWS ||
		!(src_cnt && dst_cnt))
		return -EINVAL;

	src_ip_base = ul_fld[FLD_5_TUP_L3_SRC_BASE];
	dst_ip_base = ul_fld[FLD_5_TUP_L3_DST_BASE];
	src_port = rte_cpu_to_be_16(ul_fld[FLD_5_TUP_L4_SRC_PORT]);
	dst_port = rte_cpu_to_be_16(ul_fld[FLD_5_TUP_L4_DST_PORT]);
	for (i = 0; i < src_cnt; i++) {
		for (j = 0; j < dst_cnt; j++) {
			src_ip = rte_cpu_to_be_32(src_ip_base + i);
			dst_ip = rte_cpu_to_be_32(dst_ip_base + j);
			s_mux_5tups[flow_num].dpdmux_id = dpdmux_id;
			s_mux_5tups[flow_num].ep_id = ul_fld[FLD_5_TUP_COUNT_FLOW_EP];
			s_mux_5tups[flow_num].l3 = DPAA2_MUX_DEMO_IPv4;
			s_mux_5tups[flow_num].l4 = DPAA2_MUX_DEMO_UDP;
			s_mux_5tups[flow_num].ipv4_hdr.src_addr = src_ip;
			s_mux_5tups[flow_num].ipv4_hdr.dst_addr = dst_ip;
			s_mux_5tups[flow_num].ipv4_mask.src_addr = 0xffffffff;
			s_mux_5tups[flow_num].ipv4_mask.dst_addr = 0xffffffff;
			s_mux_5tups[flow_num].udp_hdr.src_port = src_port;
			s_mux_5tups[flow_num].udp_hdr.dst_port = dst_port;
			s_mux_5tups[flow_num].udp_mask.src_port = 0xffff;
			s_mux_5tups[flow_num].udp_mask.dst_port = 0xffff;
			flow_num++;
		}
	}

	s_mux_5tups_num = flow_num;

	return s_mux_5tups_num;
}

static int
parse_ip_addr_inet_pton(const char *str,
	enum dpaa2_mux_demo_l3 type, uint8_t *ip_addr)
{
	int ret;
	struct in_addr ipv4;
	struct in6_addr ipv6;

	if (type == DPAA2_MUX_DEMO_IPv4) {
		ret = inet_pton(AF_INET, str, &ipv4);
		if (ret == 1) {
			rte_memcpy(ip_addr, &ipv4, sizeof(ipv4));
			return true;
		}
	} else if (type == DPAA2_MUX_DEMO_IPv6) {
		ret = inet_pton(AF_INET6, str, &ipv6);
		if (ret == 1) {
			rte_memcpy(ip_addr, &ipv6, sizeof(ipv6));
			return true;
		}
	}

	return false;
}

static int
parse_5_tuple_multi_flow_config(const char *q_arg)
{
	char s[256];
	const char *p, *p0 = q_arg;
	char *end;
	uint8_t ip_src[16], ip_dst[16], ip_zero[16];
	uint64_t ul_fld[FLD_5_TUP_NUM_FLD];
	char *str_fld[FLD_5_TUP_NUM_FLD];
	int i, flow_num = 0, dpdmux_id, ret;
	uint32_t size;

	dpdmux_id = dpaa2_mux_demo_get_mux_id();
	if (dpdmux_id < 0) {
		RTE_LOG(INFO, dpaa2_mux_demo,
			"%s: No DPDMUX created.\n", __func__);
		return dpdmux_id;
	}

	memset(ip_zero, 0, 16);

parse_next_flow:
	p = strchr(p0, '(');
	if (!p)
		return s_mux_5tups_num;
	++p;
	p0 = strchr(p, ')');
	if (!p0)
		return s_mux_5tups_num;

	if (flow_num > DPAA2_MUX_MAX_5T_FLOWS) {
		RTE_LOG(INFO, dpaa2_mux_demo,
			"%s: Too many flows\n", __func__);
		return -EINVAL;
	}

	size = p0 - p;
	if (size >= sizeof(s))
		return -EINVAL;

	snprintf(s, sizeof(s), "%.*s", size, p);
	if (rte_strsplit(s, sizeof(s), str_fld,
		FLD_5_TUP_NUM_FLD, ',') != FLD_5_TUP_NUM_FLD)
		return -EINVAL;

	memset(ip_src, 0, 16);
	memset(ip_dst, 0, 16);
	for (i = 0; i < FLD_5_TUP_NUM_FLD; i++) {
		errno = 0;
		if ((i == FLD_5_TUP_L3_SRC || i == FLD_5_TUP_L3_DST) &&
			ul_fld[FLD_5_TUP_L3] != DPAA2_MUX_DEMO_NO_L3) {
			ret = parse_ip_addr_inet_pton(str_fld[i],
				ul_fld[FLD_5_TUP_L3],
				i == FLD_5_TUP_L3_SRC ? ip_src : ip_dst);
			if (ret == false) {
				ul_fld[i] = strtoul(str_fld[i], &end, 16);
				if (errno || end == str_fld[i])
					return -EINVAL;
				if (ul_fld[FLD_5_TUP_L3] == DPAA2_MUX_DEMO_IPv4)
					ul_fld[i] = rte_cpu_to_be_32(ul_fld[i]);
				else
					ul_fld[i] = rte_cpu_to_be_64(ul_fld[i]);
				rte_memcpy(i == FLD_5_TUP_L3_SRC ?
					ip_src : ip_dst, &ul_fld[i], sizeof(uint64_t));
			}
		} else {
			ul_fld[i] = strtoul(str_fld[i], &end, 10);
			if (errno || end == str_fld[i])
				return -EINVAL;
		}
	}

	s_mux_5tups[flow_num].l3 = ul_fld[FLD_5_TUP_L3];
	if (s_mux_5tups[flow_num].l3 == DPAA2_MUX_DEMO_IPv4) {
		if (memcmp(ip_zero, ip_src, sizeof(rte_be32_t))) {
			s_mux_5tups[flow_num].ipv4_mask.src_addr =
				RTE_IPV4(0xff, 0xff, 0xff, 0xff);
		} else {
			s_mux_5tups[flow_num].ipv4_mask.src_addr =
				RTE_IPV4(0, 0, 0, 0);
		}
		if (memcmp(ip_zero, ip_dst, sizeof(rte_be32_t))) {
			s_mux_5tups[flow_num].ipv4_mask.dst_addr =
				RTE_IPV4(0xff, 0xff, 0xff, 0xff);
		} else {
			s_mux_5tups[flow_num].ipv4_mask.dst_addr =
				RTE_IPV4(0, 0, 0, 0);
		}
		rte_memcpy(&s_mux_5tups[flow_num].ipv4_hdr.src_addr,
			ip_src, sizeof(rte_be32_t));
		rte_memcpy(&s_mux_5tups[flow_num].ipv4_hdr.dst_addr,
			ip_dst, sizeof(rte_be32_t));
	} else if (s_mux_5tups[flow_num].l3 == DPAA2_MUX_DEMO_IPv6) {
		memset(s_mux_5tups[flow_num].ipv6_mask.src_addr,
			memcmp(ip_zero, ip_src, 16) ? 0xff : 0, 16);
		memset(s_mux_5tups[flow_num].ipv6_mask.dst_addr,
			memcmp(ip_zero, ip_dst, 16) ? 0xff : 0, 16);
		rte_memcpy(s_mux_5tups[flow_num].ipv6_hdr.src_addr,
			ip_src, 16);
		rte_memcpy(s_mux_5tups[flow_num].ipv6_hdr.dst_addr,
			ip_dst, 16);
	} else if (s_mux_5tups[flow_num].l3 == DPAA2_MUX_DEMO_NO_L3) {
		/** Do nothing.*/
	} else {
		RTE_LOG(INFO, dpaa2_mux_demo,
			"%s: Invalid flow%d-L3 type(%d)\n",
			__func__, flow_num, s_mux_5tups[flow_num].l3);
		return -EINVAL;
	}

	s_mux_5tups[flow_num].l4 = ul_fld[FLD_5_TUP_L4];
	if (s_mux_5tups[flow_num].l4 == DPAA2_MUX_DEMO_UDP) {
		if (ul_fld[FLD_5_TUP_L4_SRC])
			s_mux_5tups[flow_num].udp_mask.src_port = 0xffff;
		else
			s_mux_5tups[flow_num].udp_mask.src_port = 0;
		if (ul_fld[FLD_5_TUP_L4_DST])
			s_mux_5tups[flow_num].udp_mask.dst_port = 0xffff;
		else
			s_mux_5tups[flow_num].udp_mask.dst_port = 0;
		s_mux_5tups[flow_num].udp_hdr.src_port =
			rte_cpu_to_be_16(ul_fld[FLD_5_TUP_L4_SRC]);
		s_mux_5tups[flow_num].udp_hdr.dst_port =
			rte_cpu_to_be_16(ul_fld[FLD_5_TUP_L4_DST]);
	} else if (s_mux_5tups[flow_num].l4 == DPAA2_MUX_DEMO_TCP) {
		if (ul_fld[FLD_5_TUP_L4_SRC])
			s_mux_5tups[flow_num].tcp_mask.src_port = 0xffff;
		else
			s_mux_5tups[flow_num].tcp_mask.src_port = 0;
		if (ul_fld[FLD_5_TUP_L4_DST])
			s_mux_5tups[flow_num].tcp_mask.dst_port = 0xffff;
		else
			s_mux_5tups[flow_num].tcp_mask.dst_port = 0;
		s_mux_5tups[flow_num].tcp_hdr.src_port =
			rte_cpu_to_be_16(ul_fld[FLD_5_TUP_L4_SRC]);
		s_mux_5tups[flow_num].tcp_hdr.dst_port =
			rte_cpu_to_be_16(ul_fld[FLD_5_TUP_L4_DST]);
	} else if (s_mux_5tups[flow_num].l4 == DPAA2_MUX_DEMO_NO_L4) {
		/** Do nothing.*/
	} else {
		RTE_LOG(INFO, dpaa2_mux_demo,
			"%s: Invalid flow%d-L4 type(%d)\n",
			__func__, flow_num, s_mux_5tups[flow_num].l4);
		return -EINVAL;
	}
	s_mux_5tups[flow_num].dpdmux_id = dpdmux_id;
	s_mux_5tups[flow_num].ep_id = ul_fld[FLD_5_TUP_EP];
	flow_num++;
	s_mux_5tups_num = flow_num;

	goto parse_next_flow;

	return 0;
}

static int
rte_dpaa2_mux_demo_add_multi_5tup_flows(void)
{
	struct rte_flow_item pattern[3];
	struct rte_flow_action actions[2];
	struct rte_flow_action_vf vf;
	struct rte_flow_item_ipv4 ipv4_item;
	struct rte_flow_item_ipv6 ipv6_item;
	struct rte_flow_item_udp uitem;
	struct rte_flow_item_tcp titem;
	struct rte_flow_item_ipv4 ipv4_mask;
	struct rte_flow_item_ipv6 ipv6_mask;
	struct rte_flow_item_udp umask;
	struct rte_flow_item_tcp tmask;
	int dpdmux_id, flow_num = 0, ret, i, created = 0;
	__uint128_t *ipv6_src, *ipv6_dst;

create_next_flow:
	if (flow_num >= s_mux_5tups_num)
		return created;
	memset(&ipv4_item, 0, sizeof(ipv4_item));
	memset(&ipv6_item, 0, sizeof(ipv6_item));
	memset(&uitem, 0, sizeof(uitem));
	memset(&titem, 0, sizeof(titem));
	memset(&ipv4_mask, 0, sizeof(ipv4_mask));
	memset(&ipv6_mask, 0, sizeof(ipv6_mask));
	memset(&umask, 0, sizeof(umask));
	memset(&tmask, 0, sizeof(tmask));

	dpdmux_id = s_mux_5tups[flow_num].dpdmux_id;
	vf.id = s_mux_5tups[flow_num].ep_id;
	i = 0;
	if (s_mux_5tups[flow_num].l3 == DPAA2_MUX_DEMO_IPv4) {
		pattern[i].type = RTE_FLOW_ITEM_TYPE_IPV4;
		if (s_mux_5tups[flow_num].ipv4_mask.src_addr ||
			s_mux_5tups[flow_num].ipv4_mask.dst_addr) {
			rte_memcpy(&ipv4_item.hdr,
				&s_mux_5tups[flow_num].ipv4_hdr,
				sizeof(struct rte_ipv4_hdr));
			rte_memcpy(&ipv4_mask.hdr,
				&s_mux_5tups[flow_num].ipv4_mask,
				sizeof(struct rte_ipv4_hdr));
			pattern[i].spec = &ipv4_item;
			pattern[i].mask = &ipv4_mask;
		} else {
			pattern[i].spec = NULL;
			pattern[i].mask = NULL;
		}
		i++;
	} else if (s_mux_5tups[flow_num].l3 == DPAA2_MUX_DEMO_IPv6) {
		pattern[i].type = RTE_FLOW_ITEM_TYPE_IPV6;
		ipv6_src = (void *)s_mux_5tups[flow_num].ipv6_mask.src_addr;
		ipv6_dst = (void *)s_mux_5tups[flow_num].ipv6_mask.dst_addr;
		if (*ipv6_src || *ipv6_dst) {
			rte_memcpy(&ipv6_item.hdr,
				&s_mux_5tups[flow_num].ipv6_hdr,
				sizeof(struct rte_ipv6_hdr));
			rte_memcpy(&ipv6_mask.hdr,
				&s_mux_5tups[flow_num].ipv6_mask,
				sizeof(struct rte_ipv6_hdr));
			pattern[i].spec = &ipv6_item;
			pattern[i].mask = &ipv6_mask;
		} else {
			pattern[i].spec = NULL;
			pattern[i].mask = NULL;
		}
		i++;
	}

	if (s_mux_5tups[flow_num].l4 == DPAA2_MUX_DEMO_UDP) {
		pattern[i].type = RTE_FLOW_ITEM_TYPE_UDP;
		if (s_mux_5tups[flow_num].udp_mask.src_port ||
			s_mux_5tups[flow_num].udp_mask.dst_port) {
			rte_memcpy(&uitem.hdr,
				&s_mux_5tups[flow_num].udp_hdr,
				sizeof(struct rte_udp_hdr));
			rte_memcpy(&umask.hdr,
				&s_mux_5tups[flow_num].udp_mask,
				sizeof(struct rte_udp_hdr));
			pattern[i].spec = &uitem;
			pattern[i].mask = &umask;
		} else {
			pattern[i].spec = NULL;
			pattern[i].mask = NULL;
		}
		i++;
	} else if (s_mux_5tups[flow_num].l4 == DPAA2_MUX_DEMO_TCP) {
		pattern[i].type = RTE_FLOW_ITEM_TYPE_TCP;
		if (s_mux_5tups[flow_num].tcp_mask.src_port ||
			s_mux_5tups[flow_num].tcp_mask.dst_port) {
			rte_memcpy(&titem.hdr,
				&s_mux_5tups[flow_num].tcp_hdr,
				sizeof(struct rte_tcp_hdr));
			rte_memcpy(&tmask.hdr,
				&s_mux_5tups[flow_num].tcp_mask,
				sizeof(struct rte_tcp_hdr));
			pattern[i].spec = &titem;
			pattern[i].mask = &tmask;
		} else {
			pattern[i].spec = NULL;
			pattern[i].mask = NULL;
		}
		i++;
	}

	if (!i) {
		RTE_LOG(WARNING, dpaa2_mux_demo,
			"%s: Mux flow%d has no pattern\n", __func__,
			flow_num);
		s_mux_5tups[flow_num].flow_idx = -1;
		flow_num++;
		goto create_next_flow;
	}
	pattern[i].type = RTE_FLOW_ITEM_TYPE_END;

	actions[0].type = RTE_FLOW_ACTION_TYPE_VF;
	actions[0].conf = &vf;
	actions[1].type = RTE_FLOW_ACTION_TYPE_END;

	ret = rte_pmd_dpaa2_mux_flow_create(dpdmux_id, pattern,
			actions);
	if (ret < 0) {
		RTE_LOG(ERR, dpaa2_mux_demo,
			"%s: Create mux flow%d failed(%d)\n",
			__func__, flow_num, ret);
	} else {
		created++;
	}
	s_mux_5tups[flow_num].flow_idx = ret;
	flow_num++;
	goto create_next_flow;

	return 0;
}

static void
rte_dpaa2_mux_demo_del_multi_5tup_flows(void)
{
	int i, ret;

	for (i = 0; i < s_mux_5tups_num; i++) {
		if (s_mux_5tups[i].flow_idx < 0)
			continue;
		ret = rte_pmd_dpaa2_mux_flow_destroy(s_mux_5tups[i].dpdmux_id,
				s_mux_5tups[i].flow_idx);
		if (ret) {
			RTE_LOG(ERR, dpaa2_mux_demo,
				"%s: Destroy mux flow%d failed(%d)\n",
				__func__, i, ret);
		}
		s_mux_5tups[i].flow_idx = -1;
	}
	s_mux_5tups_num = 0;
}

static inline int
rte_dpaa2_mux_demo_split_flow(void)
{
	if (s_mux_type > TRAFFIC_SPLIT_NONE &&
		s_mux_type < TRAFFIC_SPLIT_MAX_NUM)
		return true;

	return false;
}

static inline int
rte_dpaa2_mux_demo_split_eth_ip(void)
{
	return (s_mux_demo_proto || s_mux_demo_ethtype);
}

/* Constraints of this function:
 * 1. Assumes that only a single rule is being created, which is matching
 *    IPv4 proto_id field or ethertype.
 * 2. Mask for this match condition is 0xFF - which would be for exact match
 *    to user-provided s_mux_demo_proto
 */
static int
rte_dpaa2_mux_demo_config_ip_eth_split(void)
{
	int ret;
	struct rte_flow_item pattern[2];
	struct rte_flow_action actions[1];
	struct rte_flow_action_vf vf;
	struct rte_flow_item_ipv4 ipv4_item;
	struct rte_flow_item_eth eitem;
	struct rte_flow_item_ipv4 ipv4_mask;
	struct rte_flow_item_eth emask;
	int dpdmux_id;

	memset(&ipv4_item, 0, sizeof(ipv4_item));
	memset(&eitem, 0, sizeof(eitem));
	memset(&ipv4_mask, 0, sizeof(ipv4_mask));
	memset(&emask, 0, sizeof(emask));

	dpdmux_id = dpaa2_mux_demo_get_mux_id();
	if (dpdmux_id < 0) {
		RTE_LOG(ERR, dpaa2_mux_demo,
			"get mux ID failed(%d)\n", dpdmux_id);
		return dpdmux_id;
	}

	vf.id = s_mux_ep_id;

	if (s_mux_demo_proto) {
		ipv4_item.hdr.next_proto_id = s_mux_demo_proto;
		ipv4_mask.hdr.next_proto_id = 0xff;
		pattern[0].type = RTE_FLOW_ITEM_TYPE_IPV4;
		pattern[0].spec = &ipv4_item;
		pattern[0].mask = &ipv4_mask;
	} else {
		eitem.type = rte_cpu_to_be_16(s_mux_demo_ethtype);
		emask.type = 0xffff;
		pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
		pattern[0].spec = &eitem;
		pattern[0].mask = &emask;
	}
	pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

	actions[0].type = RTE_FLOW_ACTION_TYPE_VF;
	actions[0].conf = &vf;

	ret = rte_pmd_dpaa2_mux_flow_create(dpdmux_id, pattern,
			actions);
	if (ret) {
		RTE_LOG(ERR, dpaa2_mux_demo,
			"%s: Create mux flow failed(%d)\n", __func__, ret);
	}

	return ret;
}

#define MAX_PATTERN_NUM 10
static int
rte_dpaa2_mux_demo_config_split_traffic(void)
{
	int ret, dpdmux_id, flow_nb = 0, start = 0;
	struct rte_flow_item pattern[MAX_PATTERN_NUM];
	struct rte_flow_action actions[1];
	struct rte_flow_action_vf vf;

	struct rte_flow_item_udp udp_item[MAX_PATTERN_NUM];
	struct rte_flow_item_ipv4 ip_item[MAX_PATTERN_NUM];
	struct rte_flow_item_eth eth_item[MAX_PATTERN_NUM];
	struct rte_flow_item_vlan vlan_item[MAX_PATTERN_NUM];
	struct rte_flow_item_ecpri ecpri_item[MAX_PATTERN_NUM];

	struct rte_flow_item_udp udp_mask[MAX_PATTERN_NUM];
	struct rte_flow_item_ipv4 ip_mask[MAX_PATTERN_NUM];
	struct rte_flow_item_eth eth_mask[MAX_PATTERN_NUM];
	struct rte_flow_item_vlan vlan_mask[MAX_PATTERN_NUM];
	struct rte_flow_item_ecpri ecpri_mask[MAX_PATTERN_NUM];

	memset(pattern, 0, sizeof(pattern));
	memset(actions, 0, sizeof(actions));
	memset(&vf, 0, sizeof(vf));
	memset(udp_item, 0, sizeof(udp_item));
	memset(ip_item, 0, sizeof(ip_item));
	memset(eth_item, 0, sizeof(eth_item));
	memset(vlan_item, 0, sizeof(vlan_item));
	memset(ecpri_item, 0, sizeof(ecpri_item));
	memset(udp_mask, 0, sizeof(udp_mask));
	memset(ip_mask, 0, sizeof(ip_mask));
	memset(eth_mask, 0, sizeof(eth_mask));
	memset(vlan_mask, 0, sizeof(vlan_mask));
	memset(ecpri_mask, 0, sizeof(ecpri_mask));

	dpdmux_id = dpaa2_mux_demo_get_mux_id();
	if (dpdmux_id < 0) {
		RTE_LOG(ERR, dpaa2_mux_demo,
			"get mux ID failed(%d)\n", dpdmux_id);
		return dpdmux_id;
	}

	vf.id = s_mux_ep_id;

	switch (s_mux_type) {
	case TRAFFIC_SPLIT_NONE:
		return 0;
	case TRAFFIC_SPLIT_ETHTYPE:
		RTE_LOG(INFO, dpaa2_mux_demo,
			"Split on ETH with Type(0x%x)\n", s_mux_val);
		eth_item[0].type =
			rte_cpu_to_be_16((uint16_t)s_mux_val);
		eth_mask[0].type = 0xffff;
		pattern[0].spec = &eth_item[0];
		pattern[0].mask = &eth_mask[0];
		pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
		pattern[1].type = RTE_FLOW_ITEM_TYPE_END;
		flow_nb++;
		break;
	case TRAFFIC_SPLIT_IP_PROTO:
		RTE_LOG(INFO, dpaa2_mux_demo,
			"Split on IP protocol(0x%x)\n", s_mux_val);
		ip_item[0].hdr.next_proto_id = s_mux_val;
		ip_mask[0].hdr.next_proto_id = 0xff;
		pattern[0].spec = &ip_item[0];
		pattern[0].mask = &ip_mask[0];
		pattern[0].type = RTE_FLOW_ITEM_TYPE_IPV4;
		pattern[1].type = RTE_FLOW_ITEM_TYPE_END;
		flow_nb++;
		break;
	case TRAFFIC_SPLIT_UDP_DST_PORT:
		RTE_LOG(INFO, dpaa2_mux_demo,
			"Split on UDP with DST port(0x%x)\n", s_mux_val);
		udp_item[0].hdr.dst_port =
			rte_cpu_to_be_16((uint16_t)s_mux_val);
		udp_mask[0].hdr.dst_port = 0xffff;
		pattern[0].spec = &udp_item[0];
		pattern[0].mask = &udp_mask[0];
		pattern[0].type = RTE_FLOW_ITEM_TYPE_UDP;
		pattern[1].type = RTE_FLOW_ITEM_TYPE_END;
		flow_nb++;
		break;
	case TRAFFIC_SPLIT_IP_FRAG_UDP_AND_GTP_AND_ESP:
	case TRAFFIC_SPLIT_IP_FRAG_UDP_AND_GTP:
		if (s_mux_type == TRAFFIC_SPLIT_IP_FRAG_UDP_AND_GTP) {
			RTE_LOG(INFO, dpaa2_mux_demo,
				"Split on IP frag/UDP or GTP\n");
		} else {
			RTE_LOG(INFO, dpaa2_mux_demo,
				"Split on IP frag/UDP or GTP or ESP\n");
		}
		ip_item[0].hdr.fragment_offset = RTE_IPV4_HDR_MF_FLAG;
		ip_mask[0].hdr.fragment_offset = RTE_IPV4_HDR_MF_FLAG;
		pattern[0].spec = &ip_item[0];
		pattern[0].mask = &ip_mask[0];
		pattern[0].type = RTE_FLOW_ITEM_TYPE_IPV4;
		pattern[1].spec = NULL;
		pattern[1].mask = NULL;
		pattern[1].type = RTE_FLOW_ITEM_TYPE_UDP;
		pattern[2].type = RTE_FLOW_ITEM_TYPE_END;
		flow_nb++;
		pattern[3].spec = NULL;
		pattern[3].mask = NULL;
		pattern[3].type = RTE_FLOW_ITEM_TYPE_GTP;
		pattern[4].type = RTE_FLOW_ITEM_TYPE_END;
		flow_nb++;
		if (s_mux_type == TRAFFIC_SPLIT_IP_FRAG_UDP_AND_GTP)
			break;
		pattern[5].spec = NULL;
		pattern[5].mask = NULL;
		pattern[5].type = RTE_FLOW_ITEM_TYPE_ESP;
		pattern[6].type = RTE_FLOW_ITEM_TYPE_END;
		flow_nb++;
		break;
	case TRAFFIC_SPLIT_IP_FRAG_PROTO:
		RTE_LOG(INFO, dpaa2_mux_demo,
			"Split on IP grag with next prot(0x%x)\n", s_mux_val);
		ip_item[0].hdr.next_proto_id = s_mux_val;
		ip_mask[0].hdr.next_proto_id = 0xff;
		pattern[0].spec = &ip_item[0];
		pattern[0].mask = &ip_mask[0];
		pattern[0].type = RTE_FLOW_ITEM_TYPE_IPV4;
		ip_item[1].hdr.fragment_offset = RTE_IPV4_HDR_MF_FLAG;
		ip_mask[1].hdr.fragment_offset = RTE_IPV4_HDR_MF_FLAG;
		pattern[1].spec = &ip_item[1];
		pattern[1].mask = &ip_mask[1];
		pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
		pattern[2].type = RTE_FLOW_ITEM_TYPE_END;
		flow_nb++;
		break;
	case TRAFFIC_SPLIT_VLAN:
		RTE_LOG(INFO, dpaa2_mux_demo,
			"Split on VLAN with vlan ID(0x%x)\n", s_mux_val);
		vlan_item[0].hdr.vlan_tci =
			rte_cpu_to_be_16((uint16_t)s_mux_val);
		vlan_mask[0].hdr.vlan_tci = RTE_BE16(0x0fff);
		pattern[0].spec = &vlan_item[0];
		pattern[0].mask = &vlan_mask[0];
		pattern[0].type = RTE_FLOW_ITEM_TYPE_VLAN;
		pattern[1].type = RTE_FLOW_ITEM_TYPE_END;
		flow_nb++;
		break;
	case TRAFFIC_SPLIT_ECPRI:
		RTE_LOG(INFO, dpaa2_mux_demo,
			"Split on IQ eCPRI with physical channel(0x%x)\n",
			s_mux_val);
		ecpri_item[0].hdr.common.type = RTE_ECPRI_MSG_TYPE_IQ_DATA;
		ecpri_item[0].hdr.type0.pc_id =
			rte_cpu_to_be_16((uint16_t)s_mux_val);
		ecpri_mask[0].hdr.common.type = 0xff;
		ecpri_mask[0].hdr.type0.pc_id = 0xffff;
		pattern[0].spec = &ecpri_item[0];
		pattern[0].mask = &ecpri_mask[0];
		pattern[0].type = RTE_FLOW_ITEM_TYPE_ECPRI;
		pattern[1].type = RTE_FLOW_ITEM_TYPE_END;
		flow_nb++;
		break;
	default:
		RTE_LOG(ERR, dpaa2_mux_demo,
			"Invalid MUX split type(%d)\n", s_mux_type);
		return -EINVAL;
	}

	actions[0].type = RTE_FLOW_ACTION_TYPE_VF;
	actions[0].conf = &vf;

	while (flow_nb) {
		ret = rte_pmd_dpaa2_mux_flow_create(dpdmux_id, &pattern[start],
				actions);
		if (ret < 0) {
			RTE_LOG(ERR, dpaa2_mux_demo,
				"%s: MUX flow create failed(%d)\n",
				__func__, ret);
			break;
		}
		flow_nb--;
		if (!flow_nb)
			break;
		while (pattern[start].type != RTE_FLOW_ITEM_TYPE_END) {
			start++;
			if (start >= (MAX_PATTERN_NUM))
				break;
		}
		start++;
		if (start >= (MAX_PATTERN_NUM)) {
			RTE_LOG(ERR, dpaa2_mux_demo,
				"MUX flow pattern index(%d) overflow\n",
				start);
			break;
		}
	}

	return ret >= 0 ? 0 : ret;
}
#endif

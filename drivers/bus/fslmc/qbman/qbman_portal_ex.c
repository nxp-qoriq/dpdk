/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 NXP
 *
 */

#include "qbman_portal.h"
#include "qbman_portal_ex.h"
#include "fsl_qbman_portal_ex.h"

struct qb_attr_code code_generic_rslt = QB_CODE(0, 8, 8);
struct qb_attr_code code_generic_verb = QB_CODE(0, 0, 7);
uint16_t qman_pres = 8534; // Todo: From RCW need to get from code
uint32_t qman_freq = 750000000; // Todo: From RCW need to get from code

/* Management command result codes (QBMAN_MC_RSLT_OK already defined) */
#define QBMAN_MC_RSLT_EXISTS   0xf3 /* authorisation 3-tuple already exists */
#define QBMAN_MC_RSLT_NOINSERT 0xf6 /* authorisation insert fail, try another */
#define QBMAN_MC_RSLT_PENDING  0xf8 /* retirement pending, will complete later */
#define QBMAN_MC_RSLT_RETRY(c) ((c) == QBMAN_MC_RSLT_EXISTS || \
				(c) == QBMAN_MC_RSLT_NOINSERT)

/* QBMan portal management command codes */
#define QBMAN_MC_BP_CONFIGURE        0x31
#define QBMAN_MC_BP_QUERY            0x32
#define QBMAN_MC_FQ_CONFIGURE        0x40
#define QBMAN_MC_FQ_QUERY            0x44
#define QBMAN_MC_FQ_QUERY_NP         0x45
#define QBMAN_MC_FQ_RETIRE           0x4A
#define QBMAN_MC_FQ_OOS              0x4B
#define QBMAN_MC_FQ_RETIRE_WITH_CTX  0x4C
#define QBMAN_MC_CGR_CONFIGURE       0x50
#define QBMAN_MC_CGR_QUERY           0x51
#define QBMAN_MC_WRED_CONFIGURE      0x53
#define QBMAN_MC_WRED_QUERY          0x54
#define QBMAN_MC_CGR_STAT_QUERY      0x55
#define QBMAN_MC_CGR_STAT_QUERY_CLR  0x56
#define QBMAN_MC_AUTH_CONFIGURE      0x61
#define QBMAN_MC_QD_CONFIGURE        0x62
#define QBMAN_MC_OPR_CONFIGURE       0x63
#define QBMAN_MC_RR_CONFIGURE        0x64
#define QBMAN_MC_LFQ_CONFIGURE       0x70
#define QBMAN_MC_LFQ_QUERY           0x71
#define QBMAN_MC_CQ_CONFIGURE        0x72
#define QBMAN_MC_CQ_QUERY            0x73
#define QBMAN_MC_DCT_CONFIGURE       0x74
#define QBMAN_MC_DCT_QUERY           0x75
#define QBMAN_MC_CSCHED_CONFIGURE    0x76
#define QBMAN_MC_CSCHED_QUERY        0x77
#define QBMAN_MC_MAPPING_CONFIGURE   0x78
#define QBMAN_MC_MAPPING_QUERY       0x79
#define QBMAN_MC_CCGR_CONFIGURE      0x7a
#define QBMAN_MC_CCGR_QUERY          0x7b
#define QBMAN_MC_CQ_PEEKPOP          0x7c
#define QBMAN_MC_STATISTICS_QUERY    0x7d

/* MAPPING_CONFIGURE verb has multiple "maptype"s */
#define QBMAN_MC_MAPPING_CHANNEL     0x0
#define QBMAN_MC_MAPPING_SUBPORTAL   0x1

/* Shaper command type */
#define QBMAN_MC_SHAPER_CHANNEL      0x2
#define QBMAN_MC_SHAPER_LNI          0x3
#define QBMAN_MC_SHAPER_CQ           0x5

/* Traffic Class Flow Control */
#define QBMAN_MC_MAPPING_TCFC        0x4

/* CQ_PEEKPOP verb has multiple "peekpop" types */
#define QBMAN_MC_PEEKPOP_PEEK        0x0
#define QBMAN_MC_PEEKPOP_POP         0x1
#define QBMAN_MC_PEEKPOP_READ        0x2

/* QD_CONFIGURE has multiple "cid" types */
#define QBMAN_MC_QD_CID_QDR          0
#define QBMAN_MC_QD_CID_QPR          2
//#ifdef MC_CLI
#define QBMAN_MC_QD_CID_Q_QDR        1
#define QBMAN_MC_QD_CID_Q_QPR        3
//#endif

/* AUTH_CONFIGURE has multiple "cid" types */
#define QBMAN_MC_AUTH_CID_CONFIG     0
#define QBMAN_MC_AUTH_CID_QUERY      1
#define QBMAN_MC_AUTH_CID_INVALID    2
#define QBMAN_MC_AUTH_CID_READ       3

/* RR_CONFIGURE has multiple "cid" types */
#define QBMAN_MC_RR_CID_CONFIG       0
#define QBMAN_MC_RR_CID_QUERY	     1
#define QBMAN_MC_RR_CID_RCR_QUERY    2
#define QBMAN_MC_RR_CID_RCR_RESET    3

/* The verb in the dq response */
#define QBMAN_RESULT_REL_MSG         0x2f

/* Some common parameter codes */
static struct qb_attr_code code_ceetm_maptype = QB_CODE(0, 28, 4);
static struct qb_attr_code code_ceetm_peekpop = QB_CODE(1, 8, 2);
static struct qb_attr_code code_ceetm_id = QB_CODE(1, 0, 8);
static struct qb_attr_code code_ceetm_cqid = QB_CODE(0, 16, 16);
static struct qb_attr_code code_ceetm_cid = QB_CODE(0, 16, 8);
static struct qb_attr_code code_ceetm_cchannelid = QB_CODE(0, 16, 5);

enum qbman_attr_usage_e {
	qbman_attr_usage_fq,
	qbman_attr_usage_bpool,
	qbman_attr_usage_cgr,
	qbman_attr_usage_ccgr,
	qbman_attr_usage_cscheduler,
	qbman_attr_usage_shaper,
	qbman_attr_usage_tcfc,
};

struct int_qbman_attr {
	uint32_t words[32];
	enum qbman_attr_usage_e usage;
};

#define attr_type_set(a, e) \
{ \
	struct qbman_attr *__attr = a; \
	enum qbman_attr_usage_e __usage = e; \
	((struct int_qbman_attr *)__attr)->usage = __usage; \
}

#define ATTR32(a) &(a)->dont_manipulate_directly[0]

	/********************/
	/* Composite values */
	/********************/

static struct qb_attr_code code_tdthresh_exp = QB_CODE(0, 0, 5);
static struct qb_attr_code code_tdthresh_mant = QB_CODE(0, 5, 8);
/* Some thresholds setting such as the FQ tail-drop threshold, CGR/CCGR
 * congestion/TD thresholds setting is an mantissa+exponent encoding used by
 * hardware to represent the those thresholds. This representation is
 * approximative in some cases, as the mantissa+exponent form cannot express all
 * integer values over the covered range. Use "_from_value" to get an encoding
 * that approximates the desired threshold value, if "rounding" is positive then
 * the generated approximation will be rounded up, if it's negative the
 * approximation rounds down, and if it's zero the closest approximation is
 * chosen (whether up or down). Use "_to_value" to convert from an encoding back
 * to an integer threshold value, either to determine what an approximation
 * generated, and/or to interpret the results from a qbman_fq_get_attr() call.
 */
static uint32_t qbman_thresh_from_value(uint32_t val, int rounding)
{
	uint32_t ret = 0, e = 0, m = val;
	if (m > 0xe0000000)
		/* Bad. Just return all F's, it's as close to "too big" we can
		 * codify. */
		return 0xffffffff;
	while (m > 0xff) {
		unsigned int oddbit = m & 1;
		m >>= 1;
		e++;
		if (oddbit && (rounding > 0))
			m++;
	}
	/* If 'rounding' is positive or negative, we're done. If it's zero, we
	 * need to measure which way to go. (m << e) will already equal the
	 * rounded down value, so determine if that's closer than rounding up.
	 * If not, we rerun with 'rounding' positive (we can't just increment
	 * 'm', because we need the above while() loop to adjust when 'm' goes
	 * from 0xff to 0x100). */
	if (!rounding && ((val - (m << e)) >= (((m + 1) << e) - val)))
		return qbman_thresh_from_value(val, 1);
	qb_attr_code_encode(&code_tdthresh_exp, &ret, e);
	qb_attr_code_encode(&code_tdthresh_mant, &ret, m);
	return ret;
}

static uint32_t qbman_thresh_to_value(uint32_t val)
{
	uint32_t m, e;
	m = qb_attr_code_decode(&code_tdthresh_mant, &val);
	e = qb_attr_code_decode(&code_tdthresh_exp, &val);
	return m << e;
}

uint32_t qbman_ceetmid_compose(uint8_t dcpid, uint8_t instanceid)
{
	BUG_ON(dcpid > 0xf);
	BUG_ON(instanceid > 0x3);
	return ((uint32_t)dcpid | ((uint32_t)instanceid << 4));
}

void qbman_ceetmid_decompose(uint32_t ceetmid, uint8_t *dcpid, uint8_t *instanceid)
{
	*dcpid = (uint8_t)ceetmid & 0xf;
	*instanceid = (uint8_t)(ceetmid >> 4) & 0x3;
}

uint32_t qbman_lfqid_compose(uint8_t dcpid, uint8_t instanceid, uint16_t lfqmtidx)
{
	BUG_ON(dcpid > 0xf);
	BUG_ON(instanceid > 0x3);
	BUG_ON(lfqmtidx > 0xfff);
	return (((uint32_t)0xf << 20) | ((uint32_t)dcpid << 16) |
		((uint32_t)instanceid << 14) | lfqmtidx);
}

void qbman_lfqid_decompose(uint32_t lfqid, uint8_t *dcpid, uint8_t *instanceid, uint16_t *lfqmtidx)
{
	BUG_ON((lfqid >> 20) != 0xf);
	*dcpid = (uint8_t)(lfqid >> 16) & 0xf;
	*instanceid = (uint8_t)(lfqid >> 14) & 0x3;
	*lfqmtidx = (uint16_t)lfqid & 0xfff;
}

uint32_t qbman_lfqid_compose_ex(uint32_t ceetmid, uint16_t lfqmt_idx)
{
	uint8_t dcpid, instanceid;
	qbman_ceetmid_decompose(ceetmid, &dcpid, &instanceid);
	return qbman_lfqid_compose(dcpid, instanceid, lfqmt_idx);
}

void qbman_lfqid_decompose_ex(uint32_t lfqid, uint32_t *ceetmid, uint16_t *lfqmtidx)
{
	uint8_t dcpid, instanceid;
	qbman_lfqid_decompose(lfqid, &dcpid, &instanceid, lfqmtidx);
	*ceetmid = qbman_ceetmid_compose(dcpid, instanceid);
}


	/**********************************/
	/* Authorisation table management */
	/**********************************/

static struct qb_attr_code code_auth_type_resource = QB_CODE(0, 24, 3);
static struct qb_attr_code code_auth_type_isDCP = QB_CODE(0, 31, 1);
static struct qb_attr_code code_auth_icid = QB_CODE(1, 0, 15);
static struct qb_attr_code code_auth_state = QB_CODE(1, 24, 1);
static struct qb_attr_code code_auth_vrid = QB_CODE(2, 0, 24);
static struct qb_attr_code code_auth_rrid = QB_CODE(3, 0, 24);
static struct qb_attr_code code_auth_addr = QB_CODE(4, 0, 16);

static int __qbman_auth_add(struct qbman_swp *s, uint16_t icid,
			    enum qbman_auth_type_e type, int isDCP,
			    uint32_t vrid, uint32_t rrid)
{
	uint32_t *p;
	uint32_t verb, rslt;

	/* Start the management command */
	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;

	qb_attr_code_encode(&code_ceetm_cid, p, QBMAN_MC_AUTH_CID_CONFIG);
	qb_attr_code_encode(&code_auth_type_resource, p, type);
	qb_attr_code_encode(&code_auth_type_isDCP, p, !!isDCP);
	qb_attr_code_encode(&code_auth_icid, p, icid);
	qb_attr_code_encode(&code_auth_vrid, p, vrid);
	qb_attr_code_encode(&code_auth_rrid, p, rrid);

	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_AUTH_CONFIGURE);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	BUG_ON(verb != QBMAN_MC_AUTH_CONFIGURE);

	if (QBMAN_MC_RSLT_RETRY(rslt))
		return -EAGAIN;
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Configure of AUTH 0x%x:0x%x:0x%x->0x%x failed, code=0x%02x\n",
		       icid, type, vrid, rrid, rslt);
		return -EIO;
	}
	return 0;
}

static int __qbman_auth_del(struct qbman_swp *s, uint16_t icid,
			    enum qbman_auth_type_e type, int isDCP, uint32_t vrid)
{
	uint32_t *p;
	uint32_t verb, rslt;

	/* Start the management command */
	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;

	qb_attr_code_encode(&code_ceetm_cid, p, QBMAN_MC_AUTH_CID_INVALID);
	qb_attr_code_encode(&code_auth_type_resource, p, type);
	qb_attr_code_encode(&code_auth_type_isDCP, p, !!isDCP);
	qb_attr_code_encode(&code_auth_icid, p, icid);
	qb_attr_code_encode(&code_auth_vrid, p, vrid);

	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_AUTH_CONFIGURE);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	BUG_ON(verb != QBMAN_MC_AUTH_CONFIGURE);

	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Deletion of AUTH 0x%x:0x%x:0x%x failed, code=0x%02x\n",
		       icid, type, vrid, rslt);
		return -EIO;
	}
	return 0;
}

static int __qbman_auth_query(struct qbman_swp *s, uint16_t icid,
			      enum qbman_auth_type_e type, int isDCP,
			      uint32_t vrid, uint32_t *rrid,
			      uint16_t *addr)
{
	uint32_t *p;
	uint32_t verb, rslt;

	/* Start the management command */
	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;

	qb_attr_code_encode(&code_ceetm_cid, p, QBMAN_MC_AUTH_CID_QUERY);
	qb_attr_code_encode(&code_auth_type_resource, p, type);
	qb_attr_code_encode(&code_auth_type_isDCP, p, !!isDCP);
	qb_attr_code_encode(&code_auth_icid, p, icid);
	qb_attr_code_encode(&code_auth_vrid, p, vrid);

	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_AUTH_CONFIGURE);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	BUG_ON(verb != QBMAN_MC_AUTH_CONFIGURE);

	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Query of AUTH 0x%x:0x%x:0x%x failed, code=0x%02x\n",
		       icid, type, vrid, rslt);
		return -EIO;
	}
	if (addr)
		*addr = (uint16_t)qb_attr_code_decode(&code_auth_addr, p);
	*rrid = qb_attr_code_decode(&code_auth_rrid, p);

	return 0;
}

static int __qbman_auth_read(struct qbman_swp *s,
			     enum qbman_auth_type_e type, uint16_t addr,
			     uint16_t *icid, int *state,
			     uint32_t *vrid, uint32_t *rrid,
			     enum qbman_auth_type_e *rtype, int isDCP)
{
	uint32_t *p;
	uint32_t verb, rslt;

	/* Start the management command */
	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;

	qb_attr_code_encode(&code_ceetm_cid, p, QBMAN_MC_AUTH_CID_READ);
	qb_attr_code_encode(&code_auth_type_resource, p, type);
	qb_attr_code_encode(&code_auth_addr, p, addr);
	qb_attr_code_encode(&code_auth_type_isDCP, p, !!isDCP);

	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_AUTH_CONFIGURE);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	BUG_ON(verb != QBMAN_MC_AUTH_CONFIGURE);
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Read AUTH in addr %d:0x%x failed, code=0x%02x\n",
			addr, type, rslt);
		return -EIO;
	}
	*state = !!qb_attr_code_decode(&code_auth_state, p);

	if (*state) {
	       *vrid = qb_attr_code_decode(&code_auth_vrid, p);
	       *rrid = qb_attr_code_decode(&code_auth_rrid, p);
	       *icid = (uint16_t)qb_attr_code_decode(&code_auth_icid, p);
	       *rtype = (enum qbman_auth_type_e)qb_attr_code_decode(
					&code_auth_type_resource, p);
	       return 0;
	     } else {
	       return -EINVAL;
	}
}

int qbman_auth_add(struct qbman_swp *s, uint16_t icid, enum qbman_auth_type_e type,
		   uint32_t vrid, uint32_t rrid, unsigned int auth_flags)
{
	int ret = 0;
	if (!auth_flags)
		auth_flags = QBMAN_AUTH_SWP | QBMAN_AUTH_DCP;

	if ((type >= qbman_auth_type_channel) && (type <= qbman_auth_type_orpid)
		&& (auth_flags & QBMAN_AUTH_DCP) ) {
		pr_err("This AUTH type is invalid for DCP\n");
		return -EIO;
	}
	if ((type == qbman_auth_type_fqid_xctl) && (auth_flags & QBMAN_AUTH_SWP)) {
			pr_err("This AUTH type is invalid for SWP\n");
			return -EIO;
	}

	/* Try first for SWP auth */
	if (auth_flags & QBMAN_AUTH_SWP)
		ret = __qbman_auth_add(s, icid, type, 0, vrid, rrid);
	if (ret)
		/* -EAGAIN means try another vrid. Anything else is an actual
		 * error. */
		return ret;
	/* Now try for DCP auth */
	if (auth_flags & QBMAN_AUTH_DCP)
		ret = __qbman_auth_add(s, icid, type, 1, vrid, rrid);
	if (ret && (auth_flags & QBMAN_AUTH_SWP))
		/* If we have to back out, undo what was done */
		__qbman_auth_del(s, icid, type, 0, vrid);
	return ret;
}

/* Use a bit array to track used VRIDs - we double the max so there is plenty of space
 * in case there is a collision
 */
#define COMPUTE_ARRAY_SIZE(x) 			(((x)*2)/(8*sizeof(uint32_t)))

/* These sizes could be tuned to the specific SoC but would require dynamic allocation at that point */
#define FQ_USED_VRID_ARRAY_SIZE			COMPUTE_ARRAY_SIZE(2048)	/* max 2048 fqs */
#define QDID_USED_VRID_ARRAY_SIZE		COMPUTE_ARRAY_SIZE(256)		/* max 256 qd */
#define BPID_USED_VRID_ARRAY_SIZE		COMPUTE_ARRAY_SIZE(64)		/* max 64 bp */
#define CHANNEL_USED_VRID_ARRAY_SIZE	COMPUTE_ARRAY_SIZE(512)		/* max number of 2WQ channels (num_WQs / 2)
																		this number should cover maximum number of 2WQ-CH that can be used */
#define CGID_USED_VRID_ARRAY_SIZE		COMPUTE_ARRAY_SIZE(4096)	/* max 4096 congestion groups */
#define ORP_USED_VRID_ARRAY_SIZE		COMPUTE_ARRAY_SIZE(256)		/* max 256 ORPs */
#define FQID_XCTL_USED_VRID_ARRAY_SIZE		COMPUTE_ARRAY_SIZE(512)		/* max 512 */
#define RPLID_FQID_USED_VRID_ARRAY_SIZE		COMPUTE_ARRAY_SIZE(256)		/* max 256 */

/* arrays to store vrid state (1-vrid is allocated, 0-vrid not allocated) */
static uint32_t fq_used_vrid[FQ_USED_VRID_ARRAY_SIZE] = {0};
static uint32_t qdid_used_vrid[QDID_USED_VRID_ARRAY_SIZE] = {0};
static uint32_t bpid_used_vrid[BPID_USED_VRID_ARRAY_SIZE] = {0};
static uint32_t channel_used_vrid[CHANNEL_USED_VRID_ARRAY_SIZE] = {0};
static uint32_t cgid_used_vrid[CGID_USED_VRID_ARRAY_SIZE] = {0};
static uint32_t orpid_used_vrid[ORP_USED_VRID_ARRAY_SIZE] = {0};
static uint32_t fqid_xctl_used_vrid[FQID_XCTL_USED_VRID_ARRAY_SIZE] = {0};
static uint32_t rplid_fqid_used_vrid[RPLID_FQID_USED_VRID_ARRAY_SIZE] = {0};

static uint32_t *used_vrid_array_list[] = {
		fq_used_vrid,
		qdid_used_vrid,
		bpid_used_vrid,
		channel_used_vrid,
		cgid_used_vrid,
		orpid_used_vrid,
		fqid_xctl_used_vrid,
		rplid_fqid_used_vrid
};

static int used_vrid_array_sizes[] = {
		FQ_USED_VRID_ARRAY_SIZE,
		QDID_USED_VRID_ARRAY_SIZE,
		BPID_USED_VRID_ARRAY_SIZE,
		CHANNEL_USED_VRID_ARRAY_SIZE,
		CGID_USED_VRID_ARRAY_SIZE,
		ORP_USED_VRID_ARRAY_SIZE,
		FQID_XCTL_USED_VRID_ARRAY_SIZE,
		RPLID_FQID_USED_VRID_ARRAY_SIZE,
};

/* Keep track of the last VRID allocated for each array
 * this acts as a start point for the search */
static uint32_t vrid_start_array[qbman_valid_type_bdi_no_auth];
static uint32_t ccgid_start = 0;	// class congestion group start


static inline int get_first_zero_bit(uint32_t data, int start_pos)
{
	int pos = start_pos;

	if ( !(~data) )
		return -1;

	data >>= start_pos;

	while ( data & 0x1 ) {
		data >>= 1;
		++pos;
	}
	return pos;
}

static void set_used_vrid(uint32_t vrid, int used, uint32_t *vrid_array)
{
	uint32_t pos;
	uint32_t bit;
	uint32_t mask;

	pos = vrid / 32;
	bit = vrid % 32;
	mask = 1 << bit;
	if( used ) {
		vrid_array[pos] = vrid_array[pos] | mask;
	} else {
		vrid_array[pos] = vrid_array[pos] & (~mask);
	}
}

static int get_first_free_vrid(uint32_t start_vrid, uint32_t *vrid, uint32_t *vrid_array, int array_size)
{
	int pos;
	int bit;
	int vrid_pos;
	int idx;

	/* Make sure start isn't larger than max which is 32 bits per array entry */
	start_vrid %= (array_size * 32);

	pos = (int)(start_vrid / 32);
	bit = (int)(start_vrid % 32);

	idx = pos;
	while (idx < array_size && vrid_array[idx]==0xffffffff) {
		++idx;
		bit = 0;
	}

	if(idx == array_size) {
		/* Wrap to the start and keep searching */
		idx = 0;
		while (idx <=pos && vrid_array[idx]==0xffffffff)
			++idx;
	}
	/* We've either reached the end of the array and everything was used
	 * or we've reached a word with a free spot */
	vrid_pos = get_first_zero_bit(vrid_array[idx], bit);

	if (vrid_pos < 0) {
		*vrid = QBMAN_INVALID_VRID;
		return -ENOMEM;
	} else {
		*vrid = (uint32_t)(idx*32 + vrid_pos);
		return 0;
	}
}

int qbman_auth_add_find(struct qbman_swp *s, uint16_t icid, enum qbman_auth_type_e type,
			uint32_t *vrid, uint32_t rrid, unsigned int auth_flags)
{
	uint32_t my_vrid;
	uint32_t first_vrid;
	int err = 0, auth_err = 0;
	int first_attempt = 1;
	uint32_t *vrid_array;
	int vrid_array_size;
	static int do_once = 0;

	if (!do_once) {
		/* Skip VRID 0 since 0 is often used to mean no resource in HW */
		do_once = 1;
		for (int i=0; i< qbman_valid_type_bdi_no_auth; i++)
			set_used_vrid(0, 1, used_vrid_array_list[i]);
	}

	vrid_array = used_vrid_array_list[type];
	vrid_array_size = used_vrid_array_sizes[type];
	my_vrid = vrid_start_array[type]++;

	if( type == qbman_auth_type_cgid ) {
		// for class congestion groups try to generate virtual IDs bigger than 256
		// for congestion groups try to generate virtual IDs smaller than 256
		// congestion group virtual ID's are used in WRIOP;
		if( rrid & ((uint32_t)1 << 23) ) {
			my_vrid = ccgid_start + MAX_CGID_VIRT_ID;
			ccgid_start++;
		}
		else {
			my_vrid = 0;
		}
	}

	first_vrid = my_vrid;
	do {
		err = get_first_free_vrid(my_vrid, &my_vrid, vrid_array, vrid_array_size);
		CHECK_COND_RETVAL(err==0, err, "No vrid available\n");
		if (first_attempt)
			first_vrid = my_vrid;

		auth_err = qbman_auth_add(s, icid, type, my_vrid, rrid, auth_flags);
		CHECK_COND_RETVAL(!(auth_err && my_vrid==first_vrid && first_attempt==0), -ENOMEM,
				"Could not authorize any vrid with this resource id: %08x\n", rrid);
		if (auth_err == -EAGAIN)
			my_vrid++;

		first_attempt = 0;
	} while (auth_err == -EAGAIN);

	CHECK_COND_RETVAL(auth_err==0, err, "qbman_auth_add() returned error\n");

	/* Sanity check that the VRID we  selected is in the range of the array */
	ASSERT_COND (my_vrid < (vrid_array_size * 32));

	set_used_vrid(my_vrid, 1, vrid_array);
	*vrid = my_vrid;
	pr_debug("Register resource auth. vid:%xh for type:%d icid:%d rid:%xh\n",
			*vrid, type, icid, rrid);
	return err;
}

int qbman_auth_delete(struct qbman_swp *s, uint16_t icid, enum qbman_auth_type_e type,
		      uint32_t vrid, unsigned int auth_flags)
{
	int ret, ret2;
	int err;
	uint32_t *vrid_array;

	ret = (auth_flags & QBMAN_AUTH_SWP) ?
		__qbman_auth_del(s, icid, type, 0, vrid) : 0;
	ret2 = (auth_flags & QBMAN_AUTH_DCP) ?
		__qbman_auth_del(s, icid, type, 1, vrid) : 0;

	err = ret ? ret : ret2;

	if( err==0 ) {
		vrid_array = used_vrid_array_list[type];
		set_used_vrid(vrid, 0, vrid_array);
	}

	return err;
}

int qbman_auth_query(struct qbman_swp *s, uint16_t icid,
		     enum qbman_auth_type_e type, uint32_t vrid,
		     uint32_t *rrid, uint16_t *addr,
		     unsigned int auth_flags)
{
	int ret = 0;

	if (!auth_flags)
		auth_flags = QBMAN_AUTH_SWP | QBMAN_AUTH_DCP;

	if ((type >= qbman_auth_type_channel) && (type <= qbman_auth_type_orpid)
		&& (auth_flags & QBMAN_AUTH_DCP)) {
		pr_err("This AUTH type is invalid for DCP\n");
		return -EIO;
	}
	if ((type == qbman_auth_type_fqid_xctl) &&
				 (auth_flags & QBMAN_AUTH_SWP)) {
			pr_err("This AUTH type is invalid for SWP\n");
			return -EIO;
	}

	/* Try first for SWP auth */
	if (auth_flags & QBMAN_AUTH_SWP)
		ret = __qbman_auth_query(s, icid, type, 0, vrid, rrid, addr);
	if (ret)
		return ret;
	/* Now try for DCP auth */
	if (auth_flags & QBMAN_AUTH_DCP)
		ret = __qbman_auth_query(s, icid, type, 1, vrid, rrid, addr);

	return ret;
}

int qbman_auth_is_valid(struct qbman_swp *s, uint16_t icid,
		     enum qbman_auth_type_e type, uint32_t vrid,
		     uint32_t rrid, unsigned int auth_flags)
{
	uint32_t qrrid;

	if (qbman_auth_query(s, icid, type, vrid, &qrrid, NULL, auth_flags)) {
		pr_err("No auth table entry was found for 0x%x:0x%x:0x%x\n",
			icid, type, vrid);
		return 0;
	}

	if (qrrid != rrid)
		return 0;
	else
		return 1;
}

int qbman_auth_read(struct qbman_swp *s,
		    enum qbman_auth_type_e type, uint16_t addr,
		    uint16_t *icid, int *state,
		    uint32_t *vrid, uint32_t *rrid,
		    enum qbman_auth_type_e *rtype,
		    unsigned int auth_flags)
{
	int ret = 0;

	if (!auth_flags)
		auth_flags = QBMAN_AUTH_SWP | QBMAN_AUTH_DCP;

	if ((type >= qbman_auth_type_channel) && (type <= qbman_auth_type_orpid)
					&& (auth_flags & QBMAN_AUTH_DCP)) {
		pr_err("This AUTH type is invalid for DCP\n");
		return -EIO;
	}
	if ((type == qbman_auth_type_fqid_xctl) &&
					(auth_flags & QBMAN_AUTH_SWP)) {
		pr_err("This AUTH type is invalid for SWP\n");
		return -EIO;
	}

	/* Try first for SWP auth */
	if (auth_flags & QBMAN_AUTH_SWP)
		ret = __qbman_auth_read(s, type, addr, icid, state, vrid, rrid,
					rtype, 0);
	if (ret)
		return ret;
	/* Now try for DCP auth */
	if (auth_flags & QBMAN_AUTH_DCP)
		ret = __qbman_auth_read(s, type, addr, icid, state, vrid, rrid,
					rtype, 1);
	return ret;
}

void qbman_auth_dump_table(struct qbman_swp *s,
			   enum qbman_auth_type_e type,
			   unsigned int auth_flags)
{
	uint16_t i, icid, bank;
	int enable, ret;
	uint32_t vrid, rrid;
	char *auth_type;
	uint16_t addr = 0, size = 0, addr1 = 0;
	enum qbman_auth_type_e rtype;

	switch (type) {
	case qbman_auth_type_fqid:
		auth_type = "FQID";
		if (auth_flags & QBMAN_AUTH_DCP) {
			addr = 0;
			size = 0x400;
			addr1 = 0x800;
		}
		break;
	case qbman_auth_type_qdid:
		auth_type = "QDID";
		if (auth_flags & QBMAN_AUTH_DCP) {
			addr = 0x400;
			size = 0x80;
			addr1 = 0xc00;
		}
		break;
	case qbman_auth_type_bpid:
		auth_type = "BPID";
		if (auth_flags & QBMAN_AUTH_DCP) {
			addr = 0;
			size = 128;
		}
		break;
	case qbman_auth_type_channel:
		auth_type = "CHANNELID";
		break;
	case qbman_auth_type_cgid:
		auth_type = "CGID";
		break;
	case qbman_auth_type_orpid:
		auth_type = "OPRID";
		addr = 0;
		size = 256;
		break;
	case qbman_auth_type_fqid_xctl:
		auth_type = "FQID for xctl";
		if ((qman_version & 0xFFFF0000) < QMAN_REV_4101) {
			addr = 0;
			size = 512;
		} else {
			addr = 0;
			size = 256;
		}
		break;
	default:
		pr_err("Unsupported type\n");
		return;
	}

	if ((type <= qbman_auth_type_cgid) && (auth_flags & QBMAN_AUTH_SWP)) {
		if ((qman_version & 0xFFFF0000) < QMAN_REV_4101) {
			addr = 0;
			size = 4096;
		} else {
			addr = 0;
			size = 2048;
		}
	}

	pr_info("Dump authorization table for %s in %s portal from addr 0x%x:\n",
				auth_type,
				(auth_flags & QBMAN_AUTH_SWP) ? "SWP" : "DCP",
				addr);
	pr_info("Addr:   ICID:   vird:     rrid:     Type:\n");
	for (i = addr; i < addr + size; i++) {
		ret = qbman_auth_read(s, type, i, &icid, &enable,
				&vrid, &rrid, &rtype, auth_flags);
		if (!ret && ((type == rtype) || ((type == qbman_auth_type_qdid) &&
				 (auth_flags & QBMAN_AUTH_DCP))))
			pr_info("0x%04x  0x%04x  0x%06x  0x%06x  %s\n",
						i, icid, vrid, rrid, auth_type);
	}
	if ((type <= qbman_auth_type_qdid) && (auth_flags & QBMAN_AUTH_DCP)) {
		for (bank = 0; bank < 3; bank++) {
			for (i = (addr1 + bank * 0x800); i < size; i++) {
				ret = qbman_auth_read(s, type, i, &icid, &enable,
						&vrid, &rrid, &rtype, auth_flags);
				if (!ret)
					pr_info("0x%04x  0x%04x  0x%06x  0x%06x  %s\n",
						i, icid, vrid, rrid, auth_type);
			}
		}
	}
}

uint32_t qbman_auth_rrid_ccgid_compose(uint8_t dcpid, uint8_t instanceid,
				       uint8_t cchannelid, uint8_t ccgid)
{
	BUG_ON(dcpid > 0xf);
	BUG_ON(instanceid > 0x3);
	return ((uint32_t)1 << 23) | ((uint32_t)dcpid << 16) |
			((uint32_t)instanceid << 14) |
			(uint16_t)((cchannelid << 4) | ccgid);
}

void qbman_auth_rrid_ccgid_decompose(uint32_t rrid, uint8_t *dcpid,
				     uint8_t *instanceid, uint8_t *cchannelid,
				     uint8_t *ccgid)
{
	*dcpid = (uint8_t)(rrid >> 16) & 0xf;
	*instanceid = (uint8_t)(rrid >> 14) & 0x3;
	*cchannelid = (uint8_t)(rrid >> 4) & 0x1f;
	*ccgid = (uint8_t)(rrid) & 0xf;
}

	/*****************/
	/* FQ management */
	/*****************/

/* Fields in qbman_attr */
static struct qb_attr_code code_fq_fqid = QB_CODE(1, 0, 24);
static struct qb_attr_code code_fq_cgrid = QB_CODE(2, 16, 16);
static struct qb_attr_code code_fq_destwq = QB_CODE(3, 0, 15);
static struct qb_attr_code code_fq_fqctrl = QB_CODE(3, 24, 8);
static struct qb_attr_code code_fq_icscred = QB_CODE(4, 0, 15);
static struct qb_attr_code code_fq_tdthresh = QB_CODE(4, 16, 13);
static struct qb_attr_code code_fq_oa_len = QB_CODE(5, 0, 12);
static struct qb_attr_code code_fq_oa_ics = QB_CODE(5, 14, 1);
static struct qb_attr_code code_fq_oa_cgr = QB_CODE(5, 15, 1);
static struct qb_attr_code code_fq_mctl_bdi = QB_CODE(5, 24, 1);
static struct qb_attr_code code_fq_mctl_ff = QB_CODE(5, 25, 1);
static struct qb_attr_code code_fq_mctl_va = QB_CODE(5, 26, 1);
static struct qb_attr_code code_fq_mctl_ps = QB_CODE(5, 27, 1);
static struct qb_attr_code code_fq_mctl_pps = QB_CODE(5, 28, 2);
static struct qb_attr_code code_fq_mctl = QB_CODE(5, 24, 8);
static struct qb_attr_code code_fq_ctx_lower32 = QB_CODE(6, 0, 32);
static struct qb_attr_code code_fq_ctx_upper32 = QB_CODE(7, 0, 32);
static struct qb_attr_code code_fq_icid = QB_CODE(8, 0, 15);
static struct qb_attr_code code_fq_pl = QB_CODE(8, 15, 1);
static struct qb_attr_code code_fq_vfqid = QB_CODE(9, 0, 24);
static struct qb_attr_code code_fq_erfqid = QB_CODE(10, 0, 24);
static struct qb_attr_code code_fq_opridsz = QB_CODE(11, 0, 16);
static struct qb_attr_code code_fq_oprid = QB_CODE(11, 0, 12);
static struct qb_attr_code code_fq_oprsz = QB_CODE(11, 12, 4);
/* Write-enable bits */
static struct qb_attr_code code_fq_we_cgrid = QB_CODE(0, 16, 1);
static struct qb_attr_code code_fq_we_destwq = QB_CODE(0, 17, 1);
static struct qb_attr_code code_fq_we_fqctrl = QB_CODE(0, 18, 1);
static struct qb_attr_code code_fq_we_icscred = QB_CODE(0, 19, 1);
static struct qb_attr_code code_fq_we_tdthresh = QB_CODE(0, 20, 1);
static struct qb_attr_code code_fq_we_oa = QB_CODE(0, 21, 1);
static struct qb_attr_code code_fq_we_mctl = QB_CODE(0, 22, 1);
static struct qb_attr_code code_fq_we_ctx = QB_CODE(0, 23, 1);
static struct qb_attr_code code_fq_we_icid = QB_CODE(0, 24, 1);
static struct qb_attr_code code_fq_we_vfqid = QB_CODE(0, 25, 1);
static struct qb_attr_code code_fq_we_erfqid = QB_CODE(0, 26, 1);
static struct qb_attr_code code_fq_we_opridsz = QB_CODE(0, 27, 1);

#define FQD32(d) &(d)->dont_manipulate_directly[0]

void qbman_fq_attr_clear(struct qbman_attr *a)
{
	memset(a, 0, sizeof(*a));
	attr_type_set(a, qbman_attr_usage_fq);
}

void qbman_fq_attr_set_fqctrl(struct qbman_attr *d, uint32_t fqctrl)
{
	uint32_t *p = ATTR32(d);
	qb_attr_code_encode(&code_fq_fqctrl, p, fqctrl);
	qb_attr_code_encode(&code_fq_we_fqctrl, p, 1);
}
void qbman_fq_attr_get_fqctrl(struct qbman_attr *d, uint32_t *fqctrl)
{
	uint32_t *p = ATTR32(d);
	*fqctrl = qb_attr_code_decode(&code_fq_fqctrl, p);
}

void qbman_fq_attr_set_cgrid(struct qbman_attr *d, uint32_t cgrid)
{
	uint32_t *p = ATTR32(d);
	qb_attr_code_encode(&code_fq_cgrid, p, cgrid);
	qb_attr_code_encode(&code_fq_we_cgrid, p, 1);
}

void qbman_fq_attr_get_cgrid(struct qbman_attr *d, uint32_t *cgrid)
{
	uint32_t *p = ATTR32(d);
	*cgrid = qb_attr_code_decode(&code_fq_cgrid, p);
}

void qbman_fq_attr_set_destwq(struct qbman_attr *d, uint32_t destwq)
{
	uint32_t *p = ATTR32(d);
	qb_attr_code_encode(&code_fq_destwq, p, destwq);
	qb_attr_code_encode(&code_fq_we_destwq, p, 1);
}

void qbman_fq_attr_get_destwq(struct qbman_attr *d, uint32_t *destwq)
{
	uint32_t *p = ATTR32(d);
	*destwq = qb_attr_code_decode(&code_fq_destwq, p);
}

void qbman_fq_attr_set_icscred(struct qbman_attr *d, uint32_t icscred)
{
	uint32_t *p = ATTR32(d);
	qb_attr_code_encode(&code_fq_icscred, p, icscred);
	qb_attr_code_encode(&code_fq_we_icscred, p, 1);
}

void qbman_fq_attr_get_icscred(struct qbman_attr *d, uint32_t *icscred)
{
	uint32_t *p = ATTR32(d);
	*icscred = qb_attr_code_decode(&code_fq_icscred, p);
}

void qbman_fq_attr_set_tdthresh(struct qbman_attr *d, uint32_t tdthresh)
{
	uint32_t *p = ATTR32(d);
	qb_attr_code_encode(&code_fq_tdthresh, p,
				 qbman_thresh_from_value(tdthresh, 0));
	qb_attr_code_encode(&code_fq_we_tdthresh, p, 1);
}

void qbman_fq_attr_get_tdthresh(struct qbman_attr *d, uint32_t *tdthresh)
{
	uint32_t *p = ATTR32(d);
	*tdthresh = qbman_thresh_to_value(qb_attr_code_decode(&code_fq_tdthresh,
					  p));
}

void qbman_fq_attr_set_oa(struct qbman_attr *d,
			  int oa_ics, int oa_cgr, int32_t oa_len)
{
	uint32_t *p = ATTR32(d);
	qb_attr_code_encode(&code_fq_oa_ics, p, !!oa_ics);
	qb_attr_code_encode(&code_fq_oa_cgr, p, !!oa_cgr);
	qb_attr_code_encode(&code_fq_oa_len, p, (uint32_t)oa_len);
	qb_attr_code_encode(&code_fq_we_oa, p, 1);
}

void qbman_fq_attr_get_oa(struct qbman_attr *d,
			  int *oa_ics, int *oa_cgr, int32_t *oa_len)
{
	uint32_t *p = ATTR32(d);
	*oa_ics = !!qb_attr_code_decode(&code_fq_oa_ics, p);
	*oa_cgr = !!qb_attr_code_decode(&code_fq_oa_cgr, p);
	*oa_len = qb_attr_code_makesigned(&code_fq_oa_len,
			qb_attr_code_decode(&code_fq_oa_len, p));
}

void qbman_fq_attr_set_mctl(struct qbman_attr *d,
			    int bdi, int ff, int va, int ps, int pps)
{
	uint32_t *p = ATTR32(d);
	uint8_t mctl;

	mctl = (uint8_t)qb_attr_code_decode(&code_fq_mctl, p) & 0xC0;
	mctl |= ((pps&0x03) << 4) | (ps << 3) | (va << 2) | (ff << 1) | bdi;
	qb_attr_code_encode(&code_fq_mctl, p, mctl);
	qb_attr_code_encode(&code_fq_we_mctl, p, 1);
}

void qbman_fq_attr_get_mctl(struct qbman_attr *d,
			    int *bdi, int *ff, int *va, int *ps, int *pps)
{
	uint32_t *p = ATTR32(d);
	*bdi= !!qb_attr_code_decode(&code_fq_mctl_bdi, p);
	*ff= !!qb_attr_code_decode(&code_fq_mctl_ff, p);
	*va= !!qb_attr_code_decode(&code_fq_mctl_va, p);
	*ps= !!qb_attr_code_decode(&code_fq_mctl_ps, p);
	*pps = (int)(qb_attr_code_decode(&code_fq_mctl_pps, p) & 0x03);
}

void qbman_fq_attr_set_pps(struct qbman_attr *d, uint8_t pps)
{
	uint32_t *p = ATTR32(d);
	uint8_t mctl;

	mctl = (uint8_t)qb_attr_code_decode(&code_fq_mctl, p) & 0xCF;
	mctl |= pps << 4;

	qb_attr_code_encode(&code_fq_mctl, p, mctl);
	qb_attr_code_encode(&code_fq_we_mctl, p, 1);
}

void qbman_fq_attr_get_pps(struct qbman_attr *d, uint8_t *pps)
{
	uint32_t *p = ATTR32(d);
	*pps= (uint8_t)qb_attr_code_decode(&code_fq_mctl_pps, p);
}

void qbman_fq_attr_set_ctx(struct qbman_attr *d, uint32_t hi, uint32_t lo)
{
	uint32_t *p = ATTR32(d);
	qb_attr_code_encode(&code_fq_ctx_upper32, p, hi);
	qb_attr_code_encode(&code_fq_ctx_lower32, p, lo);
	qb_attr_code_encode(&code_fq_we_ctx, p, 1);
}

void qbman_fq_attr_get_ctx(struct qbman_attr *d, uint32_t *hi, uint32_t *lo)
{
	uint32_t *p = ATTR32(d);
	*hi = qb_attr_code_decode(&code_fq_ctx_upper32, p);
	*lo = qb_attr_code_decode(&code_fq_ctx_lower32, p);
}

void qbman_fq_attr_set_icid(struct qbman_attr *d, uint32_t icid, int pl)
{
	uint32_t *p = ATTR32(d);
	qb_attr_code_encode(&code_fq_icid, p, icid);
	qb_attr_code_encode(&code_fq_pl, p, !!pl);
	qb_attr_code_encode(&code_fq_we_icid, p, 1);
}

void qbman_fq_attr_get_icid(struct qbman_attr *d, uint32_t *icid, int *pl)
{
	uint32_t *p = ATTR32(d);
	*icid = qb_attr_code_decode(&code_fq_icid, p);
	*pl = !!qb_attr_code_decode(&code_fq_pl, p);
}

void qbman_fq_attr_set_vfqid(struct qbman_attr *d, uint32_t vfqid)
{
	uint32_t *p = ATTR32(d);
	qb_attr_code_encode(&code_fq_vfqid, p, vfqid);
	qb_attr_code_encode(&code_fq_we_vfqid, p, 1);
}

void qbman_fq_attr_get_vfqid(struct qbman_attr *d, uint32_t *vfqid)
{
	uint32_t *p = ATTR32(d);
	*vfqid = qb_attr_code_decode(&code_fq_vfqid, p);
}

void qbman_fq_attr_set_erfqid(struct qbman_attr *d, uint32_t erfqid)
{
	uint32_t *p = ATTR32(d);
	qb_attr_code_encode(&code_fq_erfqid, p, erfqid);
	qb_attr_code_encode(&code_fq_we_erfqid, p, 1);
}

void qbman_fq_attr_get_erfqid(struct qbman_attr *d, uint32_t *erfqid)
{
	uint32_t *p = ATTR32(d);
	*erfqid = qb_attr_code_decode(&code_fq_erfqid, p);
}

void qbman_fq_attr_set_opridsz(struct qbman_attr *d, uint32_t oprid, int sz)
{
	uint32_t *p = ATTR32(d);
	qb_attr_code_encode(&code_fq_oprid, p, oprid);
	qb_attr_code_encode(&code_fq_oprsz, p, sz);
	qb_attr_code_encode(&code_fq_we_opridsz, p, 1);
}

void qbman_fq_attr_get_opridsz(struct qbman_attr *d, uint32_t *oprid, int *sz)
{
	uint32_t *p = ATTR32(d);
	*oprid = qb_attr_code_decode(&code_fq_oprid, p);
	*sz = qb_attr_code_decode(&code_fq_oprsz, p);
}

/* FQ mgmt portal interactions */

int qbman_fq_configure(struct qbman_swp *s, uint32_t fqid,
		       const struct qbman_attr *attr)
{
	uint32_t *p;
	uint32_t verb, rslt;
	const uint32_t *d = ATTR32(attr);

	if (((struct int_qbman_attr *)attr)->usage != qbman_attr_usage_fq) {
		pr_err("The qbman_attr is not for fq configure\n");
		return -EINVAL;
	}

	/* Start the management command */
	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;

	word_copy(&p[0], &d[0], 16);
	qb_attr_code_encode(&code_fq_fqid, p, fqid);

	/* Complete the management command */
	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_FQ_CONFIGURE);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	/* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	BUG_ON(verb != QBMAN_MC_FQ_CONFIGURE);

	/* Determine success or failure */
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Configure of FQID 0x%x failed, code=0x%02x\n",
		       fqid, rslt);
		return -EIO;
	}
	return 0;
}

int qbman_fq_query(struct qbman_swp *s, uint32_t fqid, struct qbman_attr *desc)
{
	uint32_t *p;
	uint32_t verb, rslt;
	uint32_t *d = ATTR32(desc);

	qbman_fq_attr_clear(desc);

	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;
	qb_attr_code_encode(&code_fq_fqid, p, fqid);
	p = qbman_swp_mc_complete(s, p, QBMAN_MC_FQ_QUERY);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	/* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	BUG_ON(verb != QBMAN_MC_FQ_QUERY);

	/* Determine success or failure */
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Query of FQID 0x%x failed, code=0x%02x\n",
		       fqid, rslt);
		return -EIO;
	}
	/* For the configure, word[0] of the command contains only the WE-mask.
	 * For the query, word[0] of the result contains only the verb/rslt
	 * fields. Skip word[0] in the latter case. */
	word_copy(&d[1], &p[1], 15);
	return 0;
}


/* Query FQ Non-Programmalbe Fields */
static struct qb_attr_code code_fq_np_state = QB_CODE(0, 16, 3);
static struct qb_attr_code code_fq_np_fe = QB_CODE(0, 19, 1);
static struct qb_attr_code code_fq_np_x = QB_CODE(0, 20, 1);
static struct qb_attr_code code_fq_np_r = QB_CODE(0, 21, 1);
static struct qb_attr_code code_fq_np_oe = QB_CODE(0, 22, 1);
static struct qb_attr_code code_fq_np_frm_cnt = QB_CODE(6, 0, 24);
static struct qb_attr_code code_fq_np_byte_cnt = QB_CODE(7, 0, 32);

int qbman_fq_query_state(struct qbman_swp *s, uint32_t fqid,
			 struct qbman_attr *state)
{
	uint32_t *p;
	uint32_t verb, rslt;
	uint32_t *d = ATTR32(state);

	qbman_fq_attr_clear(state);

	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;
	qb_attr_code_encode(&code_fq_fqid, p, fqid);
	p = qbman_swp_mc_complete(s, p, QBMAN_MC_FQ_QUERY_NP);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	/* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	BUG_ON(verb != QBMAN_MC_FQ_QUERY_NP);

	/* Determine success or failure */
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Query NP fields of FQID 0x%x failed, code=0x%02x\n",
		       fqid, rslt);
		return -EIO;
	}
	word_copy(&d[0], &p[0], 16);
	return 0;
}

uint32_t qbman_fq_state_schedstate(const struct qbman_attr *state)
{
	const uint32_t *p = ATTR32(state);
	return qb_attr_code_decode(&code_fq_np_state, p);
}

int qbman_fq_state_force_eligible(const struct qbman_attr *state)
{
	const uint32_t *p = ATTR32(state);
	return !!qb_attr_code_decode(&code_fq_np_fe, p);
}

int qbman_fq_state_xoff(const struct qbman_attr *state)
{
	const uint32_t *p = ATTR32(state);
	return !!qb_attr_code_decode(&code_fq_np_x, p);
}

int qbman_fq_state_retirement_pending(const struct qbman_attr *state)
{
	const uint32_t *p = ATTR32(state);
	return !!qb_attr_code_decode(&code_fq_np_r, p);
}

int qbman_fq_state_overflow_error(const struct qbman_attr *state)
{
	const uint32_t *p = ATTR32(state);
	return !!qb_attr_code_decode(&code_fq_np_oe, p);
}

uint32_t qbman_fq_state_frame_count(const struct qbman_attr *state)
{
	const uint32_t *p = ATTR32(state);
	return qb_attr_code_decode(&code_fq_np_frm_cnt, p);
}

uint32_t qbman_fq_state_byte_count(const struct qbman_attr *state)
{
	const uint32_t *p = ATTR32(state);
	return qb_attr_code_decode(&code_fq_np_byte_cnt, p);
}

/* Alter FQ State Commnads - Isolation Bypassed Only */
static struct qb_attr_code code_alter_fq_ro = QB_CODE(0, 24, 8);
static struct qb_attr_code code_alter_fq_tok = QB_CODE(1, 24, 8);
static struct qb_attr_code code_alter_fq_fqd_ctx_lo = QB_CODE(2, 0, 32);
static struct qb_attr_code code_alter_fq_rsp_addr_lo = QB_CODE(4, 0, 32);
/* To avoid converting the little-endian FQRN/FQRNI to host-endian
 * prior to us knowing whether there is a valid notification or not
 * (and run the risk of corrupting the incoming hardware LE write),
 * we detect in hardware endianness rather than host. This means we
 * need a different "code" depending on whether we are BE or LE in
 * software, which is where FQRN_TOK_OFFSET comes in...
 */
static struct qb_attr_code code_fqrn_tok_detect =
					QB_CODE(1, FQRN_TOK_OFFSET, 8);

#define QBMAN_RETIRE_TOK_START 0x88
#define QBMAN_RETIRE_TOK_DONE  0xff

int qbman_fq_retire_start(struct qbman_swp *s, uint32_t fqid,
			  struct qbman_result *result,
			  const uint64_t *fqd_ctx,
			  dma_addr_t result_phys)
{
	uint32_t *p;
	uint32_t verb, rslt;
	uint32_t *r = FQD32(result);

	/* Make sure 'result' is set such that we can see it change */
	qb_attr_code_encode(&code_fqrn_tok_detect, r, QBMAN_RETIRE_TOK_START);

	/* Start the management command */
	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;
	qb_attr_code_encode(&code_fq_fqid, p, fqid);
	qb_attr_code_encode(&code_alter_fq_tok, p, QBMAN_RETIRE_TOK_DONE);
	qb_attr_code_encode_64(&code_alter_fq_rsp_addr_lo, (uint64_t *)p,
				result_phys);

	/* Complete the management command */
	if (fqd_ctx) {
		qb_attr_code_encode_64(&code_alter_fq_fqd_ctx_lo, (uint64_t *)p,
						*fqd_ctx);
		p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_FQ_RETIRE_WITH_CTX);
	} else {
		p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_FQ_RETIRE);
	}
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	/* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	if (fqd_ctx)
		BUG_ON(verb != QBMAN_MC_FQ_RETIRE_WITH_CTX);
	else
		BUG_ON(verb != QBMAN_MC_FQ_RETIRE);
	/* Determine success or failure */
	if (unlikely((rslt != QBMAN_MC_RSLT_OK) &&
			(rslt != QBMAN_MC_RSLT_PENDING))) {
               pr_err("Retiring FQ 0x%x failed, code=0x%02x\n",
                     fqid, rslt);
               return -EIO;
       }
       return 0;
}

static struct qb_attr_code code_fqrn_state_empty = QB_CODE(0, 16, 1);

int qbman_fq_retire_is_finished(struct qbman_result *result)
{
	uint32_t tok;
	uint32_t *p;
	p = FQD32(result);

	tok = qb_attr_code_decode(&code_fqrn_tok_detect, p);

	if (tok == QBMAN_RETIRE_TOK_DONE) {
	/* Only now do we convert from hardware to host endianness. */
		make_le32_n(p, 16);
		return 1;
	}
	if (tok != QBMAN_RETIRE_TOK_START)
		pr_err("Illegal retire-completion state 0x%02x\n", tok);
	return 0;
}

int qbman_fq_retire_is_fq_empty(struct qbman_result *result)
{
	uint32_t *p;
	p = FQD32(result);
	return !qb_attr_code_decode(&code_fqrn_state_empty, p);
}

int qbman_fq_oos(struct qbman_swp *s, uint32_t fqid)
{
	uint32_t *p;
	uint32_t verb, rslt;

	/* Start the management command */
	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;
	qb_attr_code_encode(&code_fq_fqid, p, fqid);

	/* Complete the management command */
	p = qbman_swp_mc_complete(s, p, QBMAN_MC_FQ_OOS);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	/* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	BUG_ON(verb != QBMAN_MC_FQ_OOS);
	/* Determine success or failure */
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Taking FQ 0x%x Out of Service failed, code=0x%02x\n",
			fqid, rslt);
		return -EIO;
	}
	return 0;
}

	/**************************/
	/* Buffer pool management */
	/**************************/
/* --------------------------- */
/* BP mgmt portal interactions */
/* --------------------------- */
/* Write-enable bits */
static struct qb_attr_code code_bp_we_bdi = QB_CODE(1, 0, 1);
static struct qb_attr_code code_bp_we_swdet = QB_CODE(1, 1, 1);
static struct qb_attr_code code_bp_we_swdxt = QB_CODE(1, 2, 1);
static struct qb_attr_code code_bp_we_hwdet = QB_CODE(1, 3, 1);
static struct qb_attr_code code_bp_we_hwdxt = QB_CODE(1, 4, 1);
static struct qb_attr_code code_bp_we_swset = QB_CODE(1, 5, 1);
static struct qb_attr_code code_bp_we_swsxt = QB_CODE(1, 6, 1);
static struct qb_attr_code code_bp_we_vbpid = QB_CODE(1, 7, 1);
static struct qb_attr_code code_bp_we_icid = QB_CODE(1, 8, 1);
static struct qb_attr_code code_bp_we_bpscn_addr = QB_CODE(1, 9, 1);
static struct qb_attr_code code_bp_we_bpscn_ctx = QB_CODE(1, 10, 1);
static struct qb_attr_code code_bp_we_hw_targ = QB_CODE(1, 11, 1);
/* The common fields in both configure and query command */
static struct qb_attr_code code_bp_bpid = QB_CODE(0, 16, 16);
static struct qb_attr_code code_bp_bdi = QB_CODE(1, 16, 1);
static struct qb_attr_code code_bp_va = QB_CODE(1, 17, 1);
static struct qb_attr_code code_bp_wae = QB_CODE(1, 18, 1);
static struct qb_attr_code code_bp_swdet = QB_CODE(4, 0, 16);
static struct qb_attr_code code_bp_swdxt = QB_CODE(4, 16, 16);
static struct qb_attr_code code_bp_hwdet = QB_CODE(5, 0, 16);
static struct qb_attr_code code_bp_hwdxt = QB_CODE(5, 16, 16);
static struct qb_attr_code code_bp_swset = QB_CODE(6, 0, 16);
static struct qb_attr_code code_bp_swsxt = QB_CODE(6, 16, 16);
static struct qb_attr_code code_bp_vbpid = QB_CODE(7, 0, 14);
static struct qb_attr_code code_bp_icid = QB_CODE(7, 16, 15);
static struct qb_attr_code code_bp_pl = QB_CODE(7, 31, 1);
static struct qb_attr_code code_bp_bpscn_addr_lo = QB_CODE(8, 0, 32);
static struct qb_attr_code code_bp_bpscn_ctx_lo = QB_CODE(10, 0, 32);
static struct qb_attr_code code_bp_hw_targ = QB_CODE(12, 0, 16);
static struct qb_attr_code code_bp_dbe = QB_CODE(12, 16, 1);
/* The fields in query commands only */
static struct qb_attr_code code_bp_state = QB_CODE(1, 24, 3);
static struct qb_attr_code code_bp_fill = QB_CODE(2 , 0, 32);
static struct qb_attr_code code_bp_hdptr = QB_CODE(3, 0, 32);
static struct qb_attr_code code_bp_sdcnt = QB_CODE(13, 0, 8);
static struct qb_attr_code code_bp_hdcnt = QB_CODE(13, 8, 8);
static struct qb_attr_code code_bp_sscnt = QB_CODE(13, 16, 8);

void qbman_bp_attr_clear(struct qbman_attr *a)
{
	memset(a, 0, sizeof(*a));
	attr_type_set(a, qbman_attr_usage_bpool);
}

void qbman_bp_attr_set_bdi(struct qbman_attr *a, int bdi, int va, int wae)
{
	uint32_t *p = ATTR32(a);
	qb_attr_code_encode(&code_bp_bdi, p, !!bdi);
	qb_attr_code_encode(&code_bp_va, p, !!va);
	qb_attr_code_encode(&code_bp_wae, p, !!wae);
	qb_attr_code_encode(&code_bp_we_bdi, p, 1);
}
void qbman_bp_attr_get_bdi(struct qbman_attr *a, int *bdi, int *va, int *wae)
{
	uint32_t *p = ATTR32(a);
	*bdi = !!qb_attr_code_decode(&code_bp_bdi, p);
	*va = !!qb_attr_code_decode(&code_bp_va, p);
	*wae = !!qb_attr_code_decode(&code_bp_wae, p);
}

static uint32_t qbman_bp_thresh_from_value(uint32_t val, int roundup)
{
	uint32_t e = 0;
	uint32_t oddbit = 0;
	while (val > 0xff) {
		oddbit = val & 1;
		val >>= 1;
		e++;
		if (roundup && oddbit)
			val++;
	}
	BUG_ON(e >= 0x10);
	return val | (e << 8);
}

static uint32_t qbman_bp_thresh_to_value(uint32_t val)
{
	return (val & 0xff) << ((val & 0xf00) >> 8);
}

void qbman_bp_attr_set_swdet(struct qbman_attr *a, uint32_t swdet)
{
	uint32_t *p = ATTR32(a);
	qb_attr_code_encode(&code_bp_swdet, p,
			    qbman_bp_thresh_from_value(swdet, 0));
	qb_attr_code_encode(&code_bp_we_swdet, p, 1);
}
void qbman_bp_attr_get_swdet(struct qbman_attr *a, uint32_t *swdet)
{
	uint32_t *p = ATTR32(a);
	*swdet = qbman_bp_thresh_to_value(qb_attr_code_decode(&code_bp_swdet,
					  p));
}

void qbman_bp_attr_set_swdxt(struct qbman_attr *a, uint32_t swdxt)
{
	uint32_t *p = ATTR32(a);
	qb_attr_code_encode(&code_bp_swdxt, p,
			    qbman_bp_thresh_from_value(swdxt, 1));
	qb_attr_code_encode(&code_bp_we_swdxt, p, 1);
}
void qbman_bp_attr_get_swdxt(struct qbman_attr *a, uint32_t *swdxt)
{
	uint32_t *p = ATTR32(a);
	*swdxt = qbman_bp_thresh_to_value(qb_attr_code_decode(&code_bp_swdxt,
					  p));
}

void qbman_bp_attr_set_hwdet(struct qbman_attr *a, uint32_t hwdet)
{
	uint32_t *p = ATTR32(a);
	qb_attr_code_encode(&code_bp_hwdet, p,
			    qbman_bp_thresh_from_value(hwdet, 0));
	qb_attr_code_encode(&code_bp_we_hwdet, p, 1);
}
void qbman_bp_attr_get_hwdet(struct qbman_attr *a, uint32_t *hwdet)
{
	uint32_t *p = ATTR32(a);
	*hwdet = qbman_bp_thresh_to_value(qb_attr_code_decode(&code_bp_hwdet,
					  p));
}

void qbman_bp_attr_set_hwdxt(struct qbman_attr *a, uint32_t hwdxt)
{
	uint32_t *p = ATTR32(a);
	qb_attr_code_encode(&code_bp_hwdxt, p,
			    qbman_bp_thresh_from_value(hwdxt, 1));
	qb_attr_code_encode(&code_bp_we_hwdxt, p, 1);
}
void qbman_bp_attr_get_hwdxt(struct qbman_attr *a, uint32_t *hwdxt)
{
	uint32_t *p = ATTR32(a);
	*hwdxt = qbman_bp_thresh_to_value(qb_attr_code_decode(&code_bp_hwdxt,
					  p));
}

void qbman_bp_attr_set_swset(struct qbman_attr *a, uint32_t swset)
{
	uint32_t *p = ATTR32(a);
	qb_attr_code_encode(&code_bp_swset, p,
			    qbman_bp_thresh_from_value(swset, 0));
	qb_attr_code_encode(&code_bp_we_swset, p, 1);
}
void qbman_bp_attr_get_swset(struct qbman_attr *a, uint32_t *swset)
{
	uint32_t *p = ATTR32(a);
	*swset = qbman_bp_thresh_to_value(qb_attr_code_decode(&code_bp_swset,
					  p));
}

void qbman_bp_attr_set_swsxt(struct qbman_attr *a, uint32_t swsxt)
{
	uint32_t *p = ATTR32(a);
	qb_attr_code_encode(&code_bp_swsxt, p,
			    qbman_bp_thresh_from_value(swsxt, 1));
	qb_attr_code_encode(&code_bp_we_swsxt, p, 1);
}
void qbman_bp_attr_get_swsxt(struct qbman_attr *a, uint32_t *swsxt)
{
	uint32_t *p = ATTR32(a);
	*swsxt = qbman_bp_thresh_to_value(qb_attr_code_decode(&code_bp_swsxt,
					  p));
}

void qbman_bp_attr_set_vbpid(struct qbman_attr *a, uint32_t vbpid)
{
	uint32_t *p = ATTR32(a);
	qb_attr_code_encode(&code_bp_vbpid, p, vbpid);
	qb_attr_code_encode(&code_bp_we_vbpid, p, 1);
}
void qbman_bp_attr_get_vbpid(struct qbman_attr *a, uint32_t *vbpid)
{
	uint32_t *p = ATTR32(a);
	*vbpid = qb_attr_code_decode(&code_bp_vbpid, p);
}

void qbman_bp_attr_set_icid(struct qbman_attr *a, uint32_t icid, int pl)
{
	uint32_t *p = ATTR32(a);
	qb_attr_code_encode(&code_bp_icid, p, icid);
	qb_attr_code_encode(&code_bp_pl, p, !!pl);
	qb_attr_code_encode(&code_bp_we_icid, p, 1);
}
void qbman_bp_attr_get_icid(struct qbman_attr *a, uint32_t *icid, int *pl)
{
	uint32_t *p = ATTR32(a);
	*icid = qb_attr_code_decode(&code_bp_icid, p);
	*pl = !!qb_attr_code_decode(&code_bp_pl, p);
}

void qbman_bp_attr_set_bpscn_addr(struct qbman_attr *a, uint64_t bpscn_addr)
{
	uint32_t *p = ATTR32(a);
	BUG_ON(bpscn_addr & 0xf);
	qb_attr_code_encode_64(&code_bp_bpscn_addr_lo, (uint64_t *)p,
				bpscn_addr);
	qb_attr_code_encode(&code_bp_we_bpscn_addr, p, 1);
}
void qbman_bp_attr_get_bpscn_addr(struct qbman_attr *a, uint64_t *bpscn_addr)
{
	uint64_t *p = (uint64_t *)ATTR32(a);
	*bpscn_addr = qb_attr_code_decode_64(&code_bp_bpscn_addr_lo, p);
}

void qbman_bp_attr_set_bpscn_ctx(struct qbman_attr *a, uint64_t bpscn_ctx)
{
	uint32_t *p = ATTR32(a);
	qb_attr_code_encode_64(&code_bp_bpscn_ctx_lo, (uint64_t *)p,
				bpscn_ctx);
	qb_attr_code_encode(&code_bp_we_bpscn_ctx, p, 1);
}
void qbman_bp_attr_get_bpscn_ctx(struct qbman_attr *a, uint64_t *bpscn_ctx)
{
	uint64_t *p = (uint64_t *)ATTR32(a);
	*bpscn_ctx = qb_attr_code_decode_64(&code_bp_bpscn_ctx_lo, p);
}

void qbman_bp_attr_set_hw_targ(struct qbman_attr *a, uint32_t hw_targ)
{
	uint32_t *p = ATTR32(a);

	qb_attr_code_encode(&code_bp_hw_targ, p, hw_targ);
	qb_attr_code_encode(&code_bp_we_hw_targ, p, 1);
}
void qbman_bp_attr_get_hw_targ(struct qbman_attr *a, uint32_t *hw_targ)
{
	uint32_t *p = ATTR32(a);
	*hw_targ = qb_attr_code_decode(&code_bp_hw_targ, p);
}

void qbman_bp_attr_set_dbe(struct qbman_attr *a, int dbe)
{
	uint32_t *p = ATTR32(a);
	qb_attr_code_encode(&code_bp_dbe, p, !!dbe);
	qb_attr_code_encode(&code_bp_we_hw_targ, p, 1);
}
void qbman_bp_attr_get_dbe(struct qbman_attr *a, int *dbe)
{
	uint32_t *p = ATTR32(a);
	*dbe = !!qb_attr_code_decode(&code_bp_dbe, p);
}

int qbman_bp_configure(struct qbman_swp *s, uint32_t bpid,
			    struct qbman_attr *a)
{
	uint32_t *p;
	uint32_t verb, rslt;
	uint32_t *attr = ATTR32(a);

	if (((struct int_qbman_attr *)attr)->usage != qbman_attr_usage_bpool) {
		pr_err("The qbman_attr is not for bpool configure\n");
		return -EINVAL;
	}

	/* Start the management command */
	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;

	/* Encode the caller-provided attributes */
	word_copy(&p[1], &attr[1], 15);
	qb_attr_code_encode(&code_bp_bpid, p, bpid);

	/* Complete the management command */
	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_BP_CONFIGURE);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	/* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	BUG_ON(verb != QBMAN_MC_BP_CONFIGURE);

	/* Determine success or failure */
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Configure of BPID 0x%x failed, code=0x%02x\n", bpid,
			rslt);
		return -EIO;
	}
	return 0;
}

int qbman_bp_query(struct qbman_swp *s, uint32_t bpid,
			struct qbman_attr *a)
{
	uint32_t *p;
	uint32_t verb, rslt;
	uint32_t *attr = ATTR32(a);

	qbman_bp_attr_clear(a);

	/* Start the management command */
	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;

	/* Encode the caller-provided attributes */
	qb_attr_code_encode(&code_bp_bpid, p, bpid);

	/* Complete the management command */
	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_BP_QUERY);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	/* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	BUG_ON(verb != QBMAN_MC_BP_QUERY);

	/* Determine success or failure */
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Query of BPID 0x%x failed, code=0x%02x\n", bpid, rslt);
		return -EIO;
	}

	/* For the query, word[0] of the result contains only the
	 * verb/rslt fields, so skip word[0].
	*/
	word_copy(&attr[1], &p[1], 15);
	return 0;
}

int qbman_bp_info_has_free_bufs(struct qbman_attr *a)
{
	uint32_t *p = ATTR32(a);
	return !(int)(qb_attr_code_decode(&code_bp_state, p) & 0x1);
}

int qbman_bp_info_is_depleted(struct qbman_attr *a)
{
	uint32_t *p = ATTR32(a);
	return (int)(qb_attr_code_decode(&code_bp_state, p) & 0x2);
}

int qbman_bp_info_is_surplus(struct qbman_attr *a)
{
	uint32_t *p = ATTR32(a);
	return (int)(qb_attr_code_decode(&code_bp_state, p) & 0x4);
}

uint32_t qbman_bp_info_num_free_bufs(struct qbman_attr *a)
{
	uint32_t *p = ATTR32(a);
	return qb_attr_code_decode(&code_bp_fill, p);
}

uint32_t qbman_bp_info_hdptr(struct qbman_attr *a)
{
	uint32_t *p = ATTR32(a);
	return qb_attr_code_decode(&code_bp_hdptr, p);
}

uint32_t qbman_bp_info_sdcnt(struct qbman_attr *a)
{
	uint32_t *p = ATTR32(a);
	return qb_attr_code_decode(&code_bp_sdcnt, p);
}

uint32_t qbman_bp_info_hdcnt(struct qbman_attr *a)
{
	uint32_t *p = ATTR32(a);
	return qb_attr_code_decode(&code_bp_hdcnt, p);
}

uint32_t qbman_bp_info_sscnt(struct qbman_attr *a)
{
	uint32_t *p = ATTR32(a);
	return qb_attr_code_decode(&code_bp_sscnt, p);
}

	/******************/
	/* CGR management */
	/******************/

static struct qb_attr_code code_cgr_cgid = QB_CODE(0, 16, 16);
static struct qb_attr_code code_cgr_cscn_wq_en_enter = QB_CODE(2, 0, 1);
static struct qb_attr_code code_cgr_cscn_wq_en_exit = QB_CODE(2, 1, 1);
static struct qb_attr_code code_cgr_cscn_wq_icd = QB_CODE(2, 2, 1);
static struct qb_attr_code code_cgr_mode_ctrl = QB_CODE(3, 16, 8);
static struct qb_attr_code code_cgr_mode = QB_CODE(3, 16, 2);
static struct qb_attr_code code_cgr_rej_cnt_mode = QB_CODE(3, 18, 1);
static struct qb_attr_code code_cgr_cscn_bdi = QB_CODE(3, 19, 1);
static struct qb_attr_code code_cgr_cscn_wr_en_enter = QB_CODE(3, 24, 1);
static struct qb_attr_code code_cgr_cscn_wr_en_exit = QB_CODE(3, 25, 1);
static struct qb_attr_code code_cgr_cg_wr_ae = QB_CODE(3, 26, 1);
static struct qb_attr_code code_cgr_cscn_dcp_en = QB_CODE(3, 27, 1);
static struct qb_attr_code code_cgr_cg_wr_va = QB_CODE(3, 28, 1);
static struct qb_attr_code code_cgr_ctl2 = QB_CODE(3, 24, 8);
static struct qb_attr_code code_cgr_i_cnt_wr_en = QB_CODE(4, 0, 1);
static struct qb_attr_code code_cgr_i_cnt_wr_bnd = QB_CODE(4, 1, 5);
static struct qb_attr_code code_cgr_i_cnt_wr_pos = QB_CODE(4, 6, 1);
static struct qb_attr_code code_cgr_td_en = QB_CODE(4, 8, 1);
static struct qb_attr_code code_cgr_cs_thres = QB_CODE(4, 16, 13);
static struct qb_attr_code code_cgr_cs_thres_x = QB_CODE(5, 0, 13);
static struct qb_attr_code code_cgr_td_thres = QB_CODE(5, 16, 13);
static struct qb_attr_code code_cgr_cscn_tdcp = QB_CODE(6, 0, 16);
static struct qb_attr_code code_cgr_cscn_wqid = QB_CODE(6, 16, 16);
static struct qb_attr_code code_cgr_cscn_vcgid = QB_CODE(7, 0, 16);
static struct qb_attr_code code_cgr_cg_icid = QB_CODE(7, 16, 15);
static struct qb_attr_code code_cgr_cg_pl = QB_CODE(7, 31, 1);
static struct qb_attr_code code_cgr_cg_wr_addr_lo = QB_CODE(8, 0, 32);
static struct qb_attr_code code_cgr_cscn_ctx_lo = QB_CODE(10, 0, 32);
/* Write-enable bits */
static struct qb_attr_code code_cgr_we_mask = QB_CODE(1, 16, 16);
static struct qb_attr_code code_cgr_we_ctl1 = QB_CODE(1, 16, 1);
static struct qb_attr_code code_cgr_we_mode = QB_CODE(1, 17, 1);
static struct qb_attr_code code_cgr_we_ctl2 = QB_CODE(1, 18, 1);
static struct qb_attr_code code_cgr_we_iwc = QB_CODE(1, 19, 1);
static struct qb_attr_code code_cgr_we_tdc = QB_CODE(1, 20, 1);
static struct qb_attr_code code_cgr_we_cs_thres = QB_CODE(1, 21, 1);
static struct qb_attr_code code_cgr_we_cs_thres_x = QB_CODE(1, 22, 1);
static struct qb_attr_code code_cgr_we_td_thres = QB_CODE(1, 23, 1);
static struct qb_attr_code code_cgr_we_cscn_tdcp = QB_CODE(1, 24, 1);
static struct qb_attr_code code_cgr_we_cscn_wqid = QB_CODE(1, 25, 1);
static struct qb_attr_code code_cgr_we_cscn_vcgid = QB_CODE(1, 26, 1);
static struct qb_attr_code code_cgr_we_cg_icid = QB_CODE(1, 27, 1);
static struct qb_attr_code code_cgr_we_cg_wr_addr = QB_CODE(1, 28, 1);
static struct qb_attr_code code_cgr_we_cscn_ctx = QB_CODE(1, 29, 1);

void qbman_cgr_attr_clear(struct qbman_attr *a)
{
	memset(a, 0, sizeof(*a));
	attr_type_set(a, qbman_attr_usage_cgr);
}

#define ATTR32_1(d) (&(d)->dont_manipulate_directly[16])

void qbman_cgr_attr_set_mode(struct qbman_attr *d, uint32_t mode,
			     int rej_cnt_mode)
{
	uint32_t *p = ATTR32(d);
	uint32_t mode_ctrl;

	mode_ctrl = qb_attr_code_decode(&code_cgr_mode_ctrl, p) & 0xF8;
	mode_ctrl |= mode | (rej_cnt_mode << 2);
	qb_attr_code_encode(&code_cgr_mode_ctrl, p, mode_ctrl);
	qb_attr_code_encode(&code_cgr_we_mode, p, 1);
}
void qbman_cgr_attr_get_mode(struct qbman_attr *d, uint32_t *mode,
			     int *rej_cnt_mode)
{
	uint32_t *p = ATTR32(d);

	*mode = qb_attr_code_decode(&code_cgr_mode, p);
	*rej_cnt_mode = !!qb_attr_code_decode(&code_cgr_rej_cnt_mode, p);
}

void qbman_cgr_attr_set_icnt_in_memory(struct qbman_attr *d,
				       uint32_t icnt_wr_bnd,
				       uint64_t icnt_addr, int wae)
{
	uint32_t *p = ATTR32(d);
	uint32_t ctl2;
	unsigned int pow = ilog2(icnt_wr_bnd);

	BUG_ON(icnt_addr & 0xF);

	ctl2 = qb_attr_code_decode(&code_cgr_ctl2, p) & 0xF8;
	ctl2 |= (wae << 2);
	qb_attr_code_encode(&code_cgr_ctl2, p, ctl2);
	qb_attr_code_encode(&code_cgr_we_ctl2, p, 1);

	qb_attr_code_encode_64(&code_cgr_cg_wr_addr_lo, (uint64_t *) p,
			       icnt_addr);
	qb_attr_code_encode(&code_cgr_we_cg_wr_addr, p, 1);

	qb_attr_code_encode(&code_cgr_i_cnt_wr_en, p, 1);
	qb_attr_code_encode(&code_cgr_i_cnt_wr_bnd, p, pow);
	qb_attr_code_encode(&code_cgr_we_iwc, p, 1);
}

void qbman_cgr_attr_get_icnt_in_memory(struct qbman_attr *d,
				       uint32_t *icnt_wr_bnd,
				       uint64_t *icnt_addr, int *wae)
{
	uint32_t *p = ATTR32(d);
	*icnt_wr_bnd = qb_attr_code_decode(&code_cgr_i_cnt_wr_bnd, p);
	*icnt_addr = qb_attr_code_decode_64(&code_cgr_cg_wr_addr_lo,
					    (uint64_t *)p);
	*wae = !!qb_attr_code_decode(&code_cgr_cg_wr_ae, p);
}

void qbman_cgr_attr_get_icnt_wr_pos(struct qbman_attr *d,
				    int *icnt_wr_pos)
{
	uint32_t *p = ATTR32(d);

	if ((qman_version & 0xFFFF0000) < QMAN_REV_5000) {
		pr_warn("This bit is not support in this QMan version \n");
	}
	*icnt_wr_pos = !!qb_attr_code_decode(&code_cgr_i_cnt_wr_pos, p);
}

void qbman_cgr_attr_set_td_ctrl(struct qbman_attr *d, int td_en)
{
	uint32_t *p = ATTR32(d);
	qb_attr_code_encode(&code_cgr_td_en, p, !!td_en);
	qb_attr_code_encode(&code_cgr_we_tdc, p, 1);
}
void qbman_cgr_attr_get_td_ctrl(struct qbman_attr *d, int *td_en)
{
	uint32_t *p = ATTR32(d);
	*td_en = !!qb_attr_code_decode(&code_cgr_td_en, p);
}

void qbman_cgr_attr_set_cs_thres(struct qbman_attr *d, uint32_t cs_thres)
{
	uint32_t *p = ATTR32(d);
	qb_attr_code_encode(&code_cgr_cs_thres, p,
			    qbman_thresh_from_value(cs_thres, 0));
	qb_attr_code_encode(&code_cgr_we_cs_thres, p, 1);
}
void qbman_cgr_attr_get_cs_thres(struct qbman_attr *d, uint32_t *cs_thres)
{
	uint32_t *p = ATTR32(d);
	*cs_thres = qbman_thresh_to_value(qb_attr_code_decode(
					  &code_cgr_cs_thres, p));
}

void qbman_cgr_attr_set_cs_thres_x(struct qbman_attr *d,
				   uint32_t cs_thres_x)
{
	uint32_t *p = ATTR32(d);
	qb_attr_code_encode(&code_cgr_cs_thres_x, p,
			    qbman_thresh_from_value(cs_thres_x, 0));
	qb_attr_code_encode(&code_cgr_we_cs_thres_x, p, 1);
}
void qbman_cgr_attr_get_cs_thres_x(struct qbman_attr *d,
				   uint32_t *cs_thres_x)
{
	uint32_t *p = ATTR32(d);
	*cs_thres_x = qbman_thresh_to_value(qb_attr_code_decode(
					    &code_cgr_cs_thres_x, p));
}

void qbman_cgr_attr_set_td_thres(struct qbman_attr *d, uint32_t td_thres)
{
	uint32_t *p = ATTR32(d);
	qb_attr_code_encode(&code_cgr_td_thres, p,
			    qbman_thresh_from_value(td_thres, 0));
	qb_attr_code_encode(&code_cgr_we_td_thres, p, 1);
}
void qbman_cgr_attr_get_td_thres(struct qbman_attr *d, uint32_t *td_thres)
{
	uint32_t *p = ATTR32(d);
	*td_thres = qbman_thresh_to_value(qb_attr_code_decode(
					  &code_cgr_td_thres, p));
}

void qbman_cgr_attr_set_cscn_bdi(struct qbman_attr *d, int bdi)
{
	uint32_t *p = ATTR32(d);

	qb_attr_code_encode(&code_cgr_cscn_bdi, p, !!bdi);
}

void qbman_cgr_attr_get_cscn_bdi(struct qbman_attr *d, int *bdi)
{
	uint32_t *p = ATTR32(d);

	*bdi = !!qb_attr_code_decode(&code_cgr_cscn_bdi, p);
}

void qbman_cgr_attr_set_cscn_pl(struct qbman_attr *d, int pl)
{
	uint32_t *p = ATTR32(d);

	qb_attr_code_encode(&code_cgr_cg_pl, p, !!pl);
}

void qbman_cgr_attr_get_cscn_pl(struct qbman_attr *d, int *pl)
{
	uint32_t *p = ATTR32(d);

	*pl = !!qb_attr_code_decode(&code_cgr_cg_pl, p);
}

void qbman_cgr_attr_set_cscn_tdcp(struct qbman_attr *d, uint32_t dcp,
				  int enable)
{
	uint32_t *p = ATTR32(d);
	uint32_t cscn_tdcp;
	uint32_t ctl2;

	ctl2 = qb_attr_code_decode(&code_cgr_ctl2, p) & 0xF7;
	ctl2 |= !!enable << 3;
	qb_attr_code_encode(&code_cgr_ctl2, p, ctl2);
	qb_attr_code_encode(&code_cgr_we_ctl2, p, 1);

	cscn_tdcp = qb_attr_code_decode(&code_cgr_cscn_tdcp, p);
	cscn_tdcp |= (uint32_t)1 << dcp;
	qb_attr_code_encode(&code_cgr_cscn_tdcp, p, cscn_tdcp);
	qb_attr_code_encode(&code_cgr_we_cscn_tdcp, p, 1);
}

void qbman_cgr_attr_get_cscn_tdcp(struct qbman_attr *d, uint32_t dcp,
				  int *enable)
{
	uint32_t *p = ATTR32(d);
	uint32_t cscn_tdcp;
	int cscn_dcp_en;

	cscn_tdcp = qb_attr_code_decode(&code_cgr_cscn_tdcp, p);
	cscn_dcp_en = !!qb_attr_code_decode(&code_cgr_cscn_dcp_en, p);
	*enable = cscn_dcp_en & ((int)(cscn_tdcp >> dcp) & 1);
}

void qbman_cgr_attr_set_cscn_wq_ctrl(struct qbman_attr *d, int enter_en,
				     int exit_en, int wq_icd)
{
	uint32_t *p = ATTR32(d);
	qb_attr_code_encode(&code_cgr_cscn_wq_en_enter, p, !!enter_en);
	qb_attr_code_encode(&code_cgr_cscn_wq_en_exit, p, !!exit_en);
	qb_attr_code_encode(&code_cgr_cscn_wq_icd, p, !!wq_icd);
	qb_attr_code_encode(&code_cgr_we_ctl1, p, 1);
}
void qbman_cgr_attr_get_cscn_wq_ctrl(struct qbman_attr *d, int *enter_en,
				     int *exit_en, int *wq_icd)
{
	uint32_t *p = ATTR32(d);
	*enter_en = !!qb_attr_code_decode(&code_cgr_cscn_wq_en_enter, p);
	*exit_en = !!qb_attr_code_decode(&code_cgr_cscn_wq_en_exit, p);
	*wq_icd = !!qb_attr_code_decode(&code_cgr_cscn_wq_icd, p);
}

void qbman_cgr_attr_set_cscn_wqid(struct qbman_attr *d, uint32_t cscn_wqid)
{
	uint32_t *p = ATTR32(d);
	qb_attr_code_encode(&code_cgr_cscn_wqid, p, cscn_wqid);
	qb_attr_code_encode(&code_cgr_we_cscn_wqid, p, 1);
}
void qbman_cgr_attr_get_cscn_wqid(struct qbman_attr *d, uint32_t *cscn_wqid)
{
	uint32_t *p = ATTR32(d);
	*cscn_wqid = qb_attr_code_decode(&code_cgr_cscn_wqid, p);
}

void qbman_cgr_attr_set_cscn_vcgid(struct qbman_attr *d,
				   uint32_t cscn_vcgid, int bdi)
{
	uint32_t *p = ATTR32(d);
	uint32_t mode_ctrl;

	mode_ctrl = qb_attr_code_decode(&code_cgr_mode_ctrl, p) & 0xF7;
	mode_ctrl |= !!bdi << 3;
	qb_attr_code_encode(&code_cgr_mode_ctrl, p, mode_ctrl);
	qb_attr_code_encode(&code_cgr_we_mode, p, 1);

	qb_attr_code_encode(&code_cgr_cscn_vcgid, p, cscn_vcgid);
	qb_attr_code_encode(&code_cgr_we_cscn_vcgid, p, 1);
}
void qbman_cgr_attr_get_cscn_vcgid(struct qbman_attr *d,
				   uint32_t *cscn_vcgid, int *bdi)
{
	uint32_t *p = ATTR32(d);
	*cscn_vcgid = qb_attr_code_decode(&code_cgr_cscn_vcgid, p);
	*bdi = !!qb_attr_code_decode(&code_cgr_cscn_bdi, p);
}

void qbman_cgr_attr_set_cg_icid(struct qbman_attr *d, uint32_t icid,
				int pl, int va)
{
	uint32_t *p = ATTR32(d);
	uint32_t ctl2;

	ctl2 = qb_attr_code_decode(&code_cgr_ctl2, p) & 0xEF;
	ctl2 |= (va << 4);
	qb_attr_code_encode(&code_cgr_ctl2, p, ctl2);
	qb_attr_code_encode(&code_cgr_we_ctl2, p, 1);
	qb_attr_code_encode(&code_cgr_cg_icid, p, icid);
	qb_attr_code_encode(&code_cgr_cg_pl, p, !!pl);
	qb_attr_code_encode(&code_cgr_we_cg_icid, p, 1);
}
void qbman_cgr_attr_get_cg_icid(struct qbman_attr *d, uint32_t *icid,
				int *pl, int *va)
{
	uint32_t *p = ATTR32(d);
	*icid = qb_attr_code_decode(&code_cgr_cg_icid, p);
	*pl = !!qb_attr_code_decode(&code_cgr_cg_pl, p);
	*va = !!qb_attr_code_decode(&code_cgr_cg_wr_va, p);
}

void qbman_cgr_attr_set_cscn_in_memory(struct qbman_attr *d,
				       int enter_en, int exit_en,
				       uint64_t cscn_addr, int wae)
{
	uint32_t *p = ATTR32(d);
	uint32_t ctl2;

	BUG_ON(cscn_addr & 0xF);
	ctl2 = qb_attr_code_decode(&code_cgr_ctl2, p) & 0xF8;
	ctl2 |= enter_en | (exit_en << 1) | (wae << 2);
	qb_attr_code_encode(&code_cgr_ctl2, p, ctl2);
	qb_attr_code_encode(&code_cgr_we_ctl2, p, 1);

	qb_attr_code_encode_64(&code_cgr_cg_wr_addr_lo, (uint64_t *) p,
				cscn_addr);
	qb_attr_code_encode(&code_cgr_we_cg_wr_addr, p, 1);
}
void qbman_cgr_attr_get_cscn_in_memory(struct qbman_attr *d,
				       int *enter_en, int *exit_en,
				       uint64_t *cscn_addr, int *wae)
{
	uint32_t *p = ATTR32(d);
	*enter_en = !!qb_attr_code_decode(&code_cgr_cscn_wr_en_enter, p);
	*exit_en = !!qb_attr_code_decode(&code_cgr_cscn_wr_en_exit, p);
	*wae = !!qb_attr_code_decode(&code_cgr_cg_wr_ae, p);
	*cscn_addr = qb_attr_code_decode_64(&code_cgr_cg_wr_addr_lo,
					    (uint64_t *)p);
}

void qbman_cgr_attr_set_cscn_ctx(struct qbman_attr *d, uint64_t cscn_ctx)
{
	uint32_t *p = ATTR32(d);
	qb_attr_code_encode_64(&code_cgr_cscn_ctx_lo, (uint64_t *)p, cscn_ctx);
	qb_attr_code_encode(&code_cgr_we_cscn_ctx, p, 1);
}
void qbman_cgr_attr_get_cscn_ctx(struct qbman_attr *d, uint64_t *cscn_ctx)
{
	uint64_t *p = (uint64_t *)ATTR32(d);
	*cscn_ctx = qb_attr_code_decode_64(&code_cgr_cscn_ctx_lo, p);
}

#define WRED_EDP_WORD(n) (18 + n/4)
#define WRED_EDP_OFFSET(n) (8 * (n % 4))
#define WRED_PARM_DP_WORD(n) (n + 20)
#define WRED_WE_EDP(n) (16 + n * 2)
#define WRED_WE_PARM_DP(n) (17 + n * 2)
void qbman_cgr_attr_wred_set_edp(struct qbman_attr *d, uint32_t idx,
				 int edp)
{
	uint32_t *p = ATTR32(d);
	struct qb_attr_code code_wred_edp = QB_CODE(WRED_EDP_WORD(idx),
						WRED_EDP_OFFSET(idx), 1);
	struct qb_attr_code code_wred_we_edp = QB_CODE(17, WRED_WE_EDP(idx), 1);
	qb_attr_code_encode(&code_wred_edp, p, !!edp);
	qb_attr_code_encode(&code_wred_we_edp, p, 1);
}

void qbman_cgr_attr_wred_get_edp(struct qbman_attr *d, uint32_t idx,
				 int *edp)
{
	uint32_t *p = ATTR32(d);
	struct qb_attr_code code_wred_edp = QB_CODE(WRED_EDP_WORD(idx),
						WRED_EDP_OFFSET(idx), 8);
	*edp = (int)qb_attr_code_decode(&code_wred_edp, p);
}

/* Returns the most significant bit of the input or 0 if the input is 0 */
static uint8_t msb(uint64_t in)
{
	uint8_t i = 0;

	while (in != 0) {
		in >>= 1;
		i++;
	}
	return i;
}

uint32_t qbman_cgr_attr_wred_dp_compose(uint64_t minth, uint64_t maxth,
					uint8_t maxp)
{
	uint32_t ma, step_s;
	uint8_t mn, step_i, pn;
	uint64_t calcMaxTH, delta;

	pn = (uint8_t)((maxp * 256 / 100) >> 2) - 1;

	if (maxth < (1<<8)) {
		ma = (uint32_t) maxth;
		mn = 0;
	} else {
		mn = msb(maxth) - 8;
		ma = (uint32_t) ((maxth + (1<<mn-1)-1) / (1<<(mn-1))) - 256;
		if (ma == 256) {
			ma = 0;
			mn++;
		}
	}
	if (mn == 0)
		calcMaxTH = ma;
	else
		calcMaxTH = ((uint64_t)(ma+256) * (1<<(mn-1)));

	delta = calcMaxTH - minth;
	if (delta < (1<<8)) {
		step_i = (uint8_t) delta;
		step_s = 0;
	} else {
		step_s = (uint8_t) (msb(delta) - 8);
		step_i = (uint8_t)((delta / (1 << (step_s - 1))) - 256);
	}

	return (uint32_t)ma << 24 | (uint32_t)(mn & 0x1f) << 19 |
		(uint32_t)step_i << 11 | (uint32_t)(step_s & 0x1f) << 6 |
		(uint32_t)(pn & 0x3f);
}

void qbman_cgr_attr_wred_dp_decompose(uint32_t dp, uint64_t *minth,
				      uint64_t *maxth, uint8_t *maxp)
{
	uint8_t ma, mn, step_i, step_s, pn;

	ma = (uint8_t)(dp >> 24);
	mn = (uint8_t)(dp >> 19) & 0x1f;
	step_i = (uint8_t)(dp >> 11);
	step_s = (uint8_t)(dp >> 6) & 0x1f;
	pn = (uint8_t)dp & 0x3f;

	*maxp = (uint8_t)((((pn + 1) << 2) * 100) / 256);

	if (mn == 0)
		*maxth = ma;
	else
		*maxth = ((uint64_t)(ma+256) * (1<<(mn-1)));

	if (step_s == 0)
		*minth = *maxth - step_i;
	else
		*minth = *maxth - (256 + step_i) * (1<<(step_s - 1));
}

void qbman_cgr_attr_wred_set_parm_dp(struct qbman_attr *d, uint32_t idx,
				     uint32_t dp)
{
	uint32_t *p = ATTR32(d);
	struct qb_attr_code code_wred_parm_dp = QB_CODE(WRED_PARM_DP_WORD(idx),
						0, 32);
	struct qb_attr_code code_wred_we_parm_dp = QB_CODE(17,
						WRED_WE_PARM_DP(idx), 1);
	qb_attr_code_encode(&code_wred_parm_dp, p, dp);
	qb_attr_code_encode(&code_wred_we_parm_dp, p, 1);
}

void qbman_cgr_attr_wred_get_parm_dp(struct qbman_attr *d, uint32_t idx,
				     uint32_t *dp)
{
	uint32_t *p = ATTR32(d);
	struct qb_attr_code code_wred_parm_dp = QB_CODE(WRED_PARM_DP_WORD(idx),
						0, 8);
	*dp = qb_attr_code_decode(&code_wred_parm_dp, p);
}

int qbman_cgr_configure(struct qbman_swp *s, uint32_t cgid,
			const struct qbman_attr *attr)
{
	uint32_t *p;
	uint32_t verb, rslt;
	uint16_t we_mask;
	const uint32_t *d[2];
	int i;
	uint32_t configure_verb;

	if (((struct int_qbman_attr *)attr)->usage != qbman_attr_usage_cgr) {
		pr_err("The qbman_attr is not for cgr configure\n");
		return -EINVAL;
	}

	d[0] = ATTR32(attr);
	d[1] = ATTR32_1(attr);

	for (i = 0; i < 2; i++) {
		we_mask = (uint16_t)qb_attr_code_decode(&code_cgr_we_mask,
								 d[i]);
		if (we_mask) {
			configure_verb = i ? QBMAN_MC_WRED_CONFIGURE :
						QBMAN_MC_CGR_CONFIGURE;
			/* Start the management command */
			p = qbman_swp_mc_start(s);
			if (!p)
				return -EBUSY;

			word_copy(&p[0], &d[i][0], 16);
			qb_attr_code_encode(&code_cgr_cgid, p, cgid);

			/* Complete the management command */
			p = qbman_swp_mc_complete(s, p, p[0] | configure_verb);
			if (!p) {
				pr_err("SWP %d is not responding\n", s->desc.idx);
				return -EIO;
			}

			/* Decode the outcome */
			verb = qb_attr_code_decode(&code_generic_verb, p);
			rslt = qb_attr_code_decode(&code_generic_rslt, p);
			BUG_ON(verb != configure_verb);

			/* Determine success or failure */
			if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
				pr_err("Configure of CGID 0x%x failed, verb ="
					" 0x%02x, code=0x%02x\n",
					       cgid, verb, rslt);
				return -EIO;
			}
		}
	}
	return 0;
}

int qbman_cgr_query(struct qbman_swp *s, uint32_t cgid, struct qbman_attr *attr)
{
	uint32_t *p;
	uint32_t verb, rslt;
	uint32_t *d[2];
	int i;
	uint32_t query_verb;

	d[0] = ATTR32(attr);
	d[1] = ATTR32_1(attr);

	qbman_cgr_attr_clear(attr);

	for (i = 0; i < 2; i++) {
		p = qbman_swp_mc_start(s);
		if (!p)
			return -EBUSY;
		query_verb = i ? QBMAN_MC_WRED_QUERY : QBMAN_MC_CGR_QUERY;

		qb_attr_code_encode(&code_cgr_cgid, p, cgid);
		p = qbman_swp_mc_complete(s, p, p[0] | query_verb);
		if (!p) {
			pr_err("SWP %d is not responding\n", s->desc.idx);
			return -EIO;
		}

		/* Decode the outcome */
		verb = qb_attr_code_decode(&code_generic_verb, p);
		rslt = qb_attr_code_decode(&code_generic_rslt, p);
		BUG_ON(verb != query_verb);

		/* Determine success or failure */
		if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
			pr_err("Query of CGID 0x%x failed, verb=0x%02x "
				"code=0x%02x\n", verb, cgid, rslt);
			return -EIO;
		}
		/* For the configure, word[0] of the command contains only the
		 * verb/cgid. For the query, word[0] of the result contains
		 * only the verb/rslt fields. Skip word[0] in the latter case.
		 */
		word_copy(&d[i][1], &p[1], 15);
	}
	return 0;
}

static struct qb_attr_code code_cgr_stat_frame_cnt_lo = QB_CODE(4, 0, 32);
static struct qb_attr_code code_cgr_stat_frame_cnt_hi = QB_CODE(5, 0, 8);
static struct qb_attr_code code_cgr_stat_byte_cnt_lo = QB_CODE(6, 0, 32);
static struct qb_attr_code code_cgr_stat_byte_cnt_hi = QB_CODE(7, 0, 16);
int qbman_cgr_statistics_query(struct qbman_swp *s, uint32_t cgid, int clear,
			       uint64_t *frame_cnt, uint64_t *byte_cnt)
{
	uint32_t *p;
	uint32_t verb, rslt;
	uint32_t query_verb;
	uint32_t hi, lo;

	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;

	qb_attr_code_encode(&code_cgr_cgid, p, cgid);
	query_verb = clear ?
			QBMAN_MC_CGR_STAT_QUERY_CLR : QBMAN_MC_CGR_STAT_QUERY;
	p = qbman_swp_mc_complete(s, p, p[0] | query_verb);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	/* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	BUG_ON(verb != query_verb);

	/* Determine success or failure */
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Query statistics of CGID 0x%x failed, verb=0x%02x "
			"code=0x%02x\n", verb, cgid, rslt);
		return -EIO;
	}

	if (frame_cnt) {
		hi = qb_attr_code_decode(&code_cgr_stat_frame_cnt_hi, p);
		lo = qb_attr_code_decode(&code_cgr_stat_frame_cnt_lo, p);
		*frame_cnt = ((uint64_t)hi << 32) | (uint64_t)lo;
	}
	if (byte_cnt) {
		hi = qb_attr_code_decode(&code_cgr_stat_byte_cnt_hi, p);
		lo = qb_attr_code_decode(&code_cgr_stat_byte_cnt_lo, p);
		*byte_cnt = ((uint64_t)hi << 32) | (uint64_t)lo;
	}

	return 0;
}

int qbman_cgr_reset(struct qbman_swp *s, uint32_t cgid)
{
	uint32_t *p;
	uint32_t verb, rslt;
	uint16_t we_mask;
	int i;
	uint32_t configure_verb;

	for (i = 0; i < 2; i++) {
		configure_verb = i ? QBMAN_MC_WRED_CONFIGURE :
					QBMAN_MC_CGR_CONFIGURE;
		/* Start the management command */
		p = qbman_swp_mc_start(s);
		if (!p)
			return -EBUSY;

		qb_attr_code_encode(&code_cgr_cgid, p, cgid);
		we_mask = 0xFFFF;
		qb_attr_code_encode(&code_cgr_we_mask, p, we_mask);
		memset(&p[2], 0, sizeof(uint32_t) * 10);

		/* Complete the management command */
		p = qbman_swp_mc_complete(s, p, p[0] | configure_verb);
		if (!p) {
			pr_err("SWP %d is not responding\n", s->desc.idx);
			return -EIO;
		}

		/* Decode the outcome */
		verb = qb_attr_code_decode(&code_generic_verb, p);
		rslt = qb_attr_code_decode(&code_generic_rslt, p);
		BUG_ON(verb != configure_verb);

		/* Determine success or failure */
		if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
			pr_err("Reset of CGID 0x%x failed, verb ="
				" 0x%02x, code=0x%02x\n",
			       cgid, verb, rslt);
			return -EIO;
		}
	}

	/* Clear the statistics */
	qbman_cgr_statistics_query(s, cgid, 1, NULL, NULL);

	return 0;
}


	/********************/
	/* CEETM management */
	/********************/

/* ----------- */
/* Logical FQs */
/* ----------- */

static struct qb_attr_code code_lfq_lfqid = QB_CODE(1, 0, 24);
static struct qb_attr_code code_lfq_cqid = QB_CODE(2, 0, 16);
static struct qb_attr_code code_lfq_dctidx = QB_CODE(2, 16, 16);
static struct qb_attr_code code_lfq_fqider = QB_CODE(3, 0, 24);
static struct qb_attr_code code_lfq_ccgid = QB_CODE(3, 24, 8);

int qbman_lfq_configure(struct qbman_swp *s, uint32_t lfqid, uint16_t cqid, uint16_t dctidx,
			uint32_t fqider)
{
	uint32_t *p;
	uint32_t verb, rslt;

	/* Start the management command */
	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;

	/* Encode the caller-provided attributes */
	qb_attr_code_encode(&code_lfq_lfqid, p, lfqid);
	qb_attr_code_encode(&code_lfq_cqid, p, cqid);
	qb_attr_code_encode(&code_lfq_dctidx, p, dctidx);
	qb_attr_code_encode(&code_lfq_fqider, p, fqider);

	/* Complete the management command */
	p = qbman_swp_mc_complete(s, p, QBMAN_MC_LFQ_CONFIGURE);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	/* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	BUG_ON(verb != QBMAN_MC_LFQ_CONFIGURE);

	/* Determine success or failure */
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Configure of LFQID 0x%x failed, code=0x%02x\n",
		       lfqid, rslt);
		return -EIO;
	}
	return 0;
}

int qbman_lfq_query(struct qbman_swp *s, uint32_t lfqid, uint16_t *cqid, uint16_t *dctidx,
		    uint32_t *fqider, uint8_t *ccgid)
{
	uint32_t *p;
	uint32_t verb, rslt;

	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;
	qb_attr_code_encode(&code_lfq_lfqid, p, lfqid);
	p = qbman_swp_mc_complete(s, p, QBMAN_MC_LFQ_QUERY);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	/* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	BUG_ON(verb != QBMAN_MC_LFQ_QUERY);

	/* Determine success or failure */
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Query of LFQID 0x%x failed, code=0x%02x\n",
		       lfqid, rslt);
		return -EIO;
	}
	*cqid = (uint16_t)qb_attr_code_decode(&code_lfq_cqid, p);
	*dctidx = (uint16_t)qb_attr_code_decode(&code_lfq_dctidx, p);
	*fqider = qb_attr_code_decode(&code_lfq_fqider, p);
	*ccgid = (uint8_t)qb_attr_code_decode(&code_lfq_ccgid, p);
	return 0;
}

/* ---------------- */
/* CQ configuration */
/* ---------------- */

static struct qb_attr_code code_cq_ccgid = QB_CODE(1, 16, 4);
static struct qb_attr_code code_cq_ps = QB_CODE(1, 24, 1);
static struct qb_attr_code code_cq_pps = QB_CODE(1, 25, 2);
static struct qb_attr_code code_cq_mctl = QB_CODE(1, 24, 8);

int qbman_cq_configure(struct qbman_swp *s, uint32_t ceetmid, uint16_t cqid,
		       uint8_t ccgid, int ps, uint8_t pps)
{
	uint32_t *p;
	uint32_t verb, rslt;
	uint32_t mctl = 0;

	p = qbman_swp_mc_start(s);
	if (!p) {
		pr_err("Queue busy, could not reconfigure\n");
		return -EBUSY;
	}

	qb_attr_code_encode(&code_ceetm_id, p, ceetmid);
	qb_attr_code_encode(&code_ceetm_cqid, p, cqid);
	qb_attr_code_encode(&code_cq_ccgid, p, ccgid);

	qb_attr_code_encode(&code_cq_ps, p, !!ps);
	qb_attr_code_encode(&code_cq_pps, p, pps);
	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_CQ_CONFIGURE);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	/* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	BUG_ON(verb != QBMAN_MC_CQ_CONFIGURE);

	/* Determine success or failure */
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Configure of CQID 0x%x failed, code=0x%02x\n",
		       cqid, rslt);
		return -EIO;
	}

	return 0;
}

static struct qb_attr_code code_cq_frm_cnt = QB_CODE(3, 0, 24);
void qbman_cq_attr_get_frm_cnt(struct qbman_attr *d, uint32_t *frm_cnt)
{
	uint32_t *p = ATTR32(d);
	*frm_cnt = qb_attr_code_decode(&code_cq_frm_cnt, p);
}

int qbman_cq_query(struct qbman_swp *s, uint32_t ceetmid, uint16_t cqid,
		   uint8_t *ccgid, int *ps, struct qbman_attr *attr, uint8_t *pps)
{
	uint32_t *p;
	uint32_t verb, rslt;
	uint32_t *a = ATTR32(attr);

	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;
	qb_attr_code_encode(&code_ceetm_id, p, ceetmid);
	qb_attr_code_encode(&code_ceetm_cqid, p, cqid);
	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_CQ_QUERY);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	/* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	BUG_ON(verb != QBMAN_MC_CQ_QUERY);

	/* Determine success or failure */
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Query of CQID 0x%x failed, code=0x%02x\n",
		       cqid, rslt);
		return -EIO;
	}

	if (ccgid)
		*ccgid = (uint8_t)qb_attr_code_decode(&code_cq_ccgid, p);
	if (ps)
		*ps = !!qb_attr_code_decode(&code_cq_ps, p);
	if (pps)
		*pps = (uint8_t)(qb_attr_code_decode(&code_cq_pps, p) & 0xff);
	word_copy(&a[1], &p[1], 15);
	return 0;
}

int qbman_cq_query_pending_frame(struct qbman_swp *s, uint32_t ceetmid, uint16_t cqid,
		   uint32_t *pending_frame)
{
	uint32_t *p;
	uint32_t verb, rslt;

	*pending_frame = 0;
	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;
	qb_attr_code_encode(&code_ceetm_id, p, ceetmid);
	qb_attr_code_encode(&code_ceetm_cqid, p, cqid);
	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_CQ_QUERY);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	/* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	BUG_ON(verb != QBMAN_MC_CQ_QUERY);

	/* Determine success or failure */
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Query of CQID 0x%x failed, code=0x%02x\n",
		       cqid, rslt);
		return -EIO;
	}
	*pending_frame = qb_attr_code_decode(&code_cq_frm_cnt, p);

	return 0;
}

uint32_t qbman_cq_num_of_frames(struct qbman_attr *attr)
{
	uint32_t *p = ATTR32(attr);
	return qb_attr_code_decode(&code_cq_frm_cnt, p);
}

uint8_t qbman_cq_pps(struct qbman_attr *attr)
{
	uint32_t *p = ATTR32(attr);
	return (uint8_t)qb_attr_code_decode(&code_cq_pps, p);
}

/* ----------------- */
/* DCT configuration */
/* ----------------- */

static struct qb_attr_code code_dct_dctidx = QB_CODE(0, 16, 12);
static struct qb_attr_code code_dct_bdi = QB_CODE(1, 8, 1);
static struct qb_attr_code code_dct_va = QB_CODE(1, 9, 1);
static struct qb_attr_code code_dct_icid = QB_CODE(1, 16, 15);
static struct qb_attr_code code_dct_pl = QB_CODE(1, 31, 1);
static struct qb_attr_code code_dct_ctx_lo = QB_CODE(2, 0, 32);
static struct qb_attr_code code_dct_tp0 = QB_CODE(4, 0, 8);
static struct qb_attr_code code_dct_tp1 = QB_CODE(4, 8, 8);

int qbman_dct_configure(struct qbman_swp *s, uint32_t ceetmid, uint16_t dctidx,
			int bdi, int va, uint16_t icid, int pl,
			uint64_t ctx)
{
	uint32_t *p, *r;
	uint32_t verb, rslt;

	r = qbman_swp_mc_start(s);
	if (!r)
		return -EBUSY;
	qb_attr_code_encode(&code_ceetm_id, r, ceetmid);
	qb_attr_code_encode(&code_dct_dctidx, r, dctidx);
	r = qbman_swp_mc_complete(s, r, r[0] | QBMAN_MC_DCT_QUERY);
	if (!r) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	/* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, r);
	rslt = qb_attr_code_decode(&code_generic_rslt, r);
	BUG_ON(verb != QBMAN_MC_DCT_QUERY);
	/* Determine success or failure */
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Query of DCTIDX 0x%x failed, code=0x%02x\n",
		       dctidx, rslt);
		return -EIO;
	}

	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;

	word_copy(&p[4], &r[4], 1);
	qb_attr_code_encode(&code_ceetm_id, p, ceetmid);
	qb_attr_code_encode(&code_dct_dctidx, p, dctidx);
	qb_attr_code_encode(&code_dct_bdi, p, !!bdi);
	qb_attr_code_encode(&code_dct_va, p, !!va);
	qb_attr_code_encode(&code_dct_icid, p, icid);
	qb_attr_code_encode(&code_dct_pl, p, !!pl);
	qb_attr_code_encode_64(&code_dct_ctx_lo, (uint64_t *)p, ctx);
	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_DCT_CONFIGURE);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	/* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	BUG_ON(verb != QBMAN_MC_DCT_CONFIGURE);

	/* Determine success or failure */
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Configure of DCTIDX 0x%x failed, code=0x%02x\n",
		       dctidx, rslt);
		return -EIO;
	}
	return 0;
}

int qbman_dct_tp_configure(struct qbman_swp *s, uint32_t ceetmid,
			   uint16_t dctidx, int tp_idx,
			   uint8_t dd_code, uint32_t tp_config_flag)
{
	uint32_t *p, *r;
	uint32_t verb, rslt;
	uint8_t tp01;

	if ((qman_version & 0xFFFF0000) > QMAN_REV_4000) {
		pr_err("These fields are not support on this QMan rev!\n");
		return -EINVAL;
	}

	r = qbman_swp_mc_start(s);
	if (!r)
		return -EBUSY;
	qb_attr_code_encode(&code_ceetm_id, r, ceetmid);
	qb_attr_code_encode(&code_dct_dctidx, r, dctidx);
	r = qbman_swp_mc_complete(s, r, r[0] | QBMAN_MC_DCT_QUERY);
	if (!r) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	/* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, r);
	rslt = qb_attr_code_decode(&code_generic_rslt, r);
	BUG_ON(verb != QBMAN_MC_DCT_QUERY);
	/* Determine success or failure */
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Query of DCTIDX 0x%x failed, code=0x%02x\n",
		       dctidx, rslt);
		return -EIO;
	}

	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;
	word_copy(&p[1], &r[1], 4);
	tp01 = (parse_tp_config(tp_config_flag) << 4) | (dd_code & 0xF);
	if (tp_idx)
		qb_attr_code_encode(&code_dct_tp0, p, tp01);
	else
		qb_attr_code_encode(&code_dct_tp1, p, tp01);
	qb_attr_code_encode(&code_ceetm_id, p, ceetmid);
	qb_attr_code_encode(&code_dct_dctidx, p, dctidx);

	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_DCT_CONFIGURE);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	/* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	BUG_ON(verb != QBMAN_MC_DCT_CONFIGURE);

	/* Determine success or failure */
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Configure DCTIDX 0x%x with tp failed, code=0x%02x\n",
		       dctidx, rslt);
		return -EIO;
	}
	return 0;
}

int qbman_dct_tp_query(struct qbman_swp *s, uint32_t ceetmid, uint16_t dctidx,
		       int tp_idx, uint8_t *tp)
{
	uint32_t *p;
	uint32_t verb, rslt;

	if ((qman_version & 0xFFFF0000) > QMAN_REV_4000) {
		pr_err("These fields are not support on this QMan rev!\n");
		return -EINVAL;
	}

	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;
	qb_attr_code_encode(&code_ceetm_id, p, ceetmid);
	qb_attr_code_encode(&code_dct_dctidx, p, dctidx);
	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_DCT_QUERY);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	/* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	BUG_ON(verb != QBMAN_MC_DCT_QUERY);
	/* Determine success or failure */
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Query of DCTIDX 0x%x failed, code=0x%02x\n",
		       dctidx, rslt);
		return -EIO;
	}

	if (tp_idx)
		*tp = (uint8_t)qb_attr_code_decode(&code_dct_tp0, p);
	else
		*tp = (uint8_t)qb_attr_code_decode(&code_dct_tp1, p);
	return 0;
}

/* ----------------------------- */
/* Class scheduler configuration */
/* ----------------------------- */
static struct qb_attr_code code_cscheduler_csms = QB_CODE(0, 31, 1);
static struct qb_attr_code code_cscheduler_qcqr = QB_CODE(0, 30, 1);
static struct qb_attr_code code_cscheduler_mps = QB_CODE(1, 8, 7);
static struct qb_attr_code code_cscheduler_oal = QB_CODE(1, 16, 11);
static struct qb_attr_code code_cscheduler_cqps = QB_CODE(2, 16, 4);
static struct qb_attr_code code_cscheduler_prio_a = QB_CODE(2, 24, 3);
static struct qb_attr_code code_cscheduler_prio_b = QB_CODE(2, 27, 3);
static struct qb_attr_code code_cscheduler_group_b = QB_CODE(2, 30, 1);
static struct qb_attr_code code_cscheduler_crem_cq = QB_CODE(3, 0, 8);
static struct qb_attr_code code_cscheduler_crem_group_a = QB_CODE(3, 8, 1);
static struct qb_attr_code code_cscheduler_crem_group_b = QB_CODE(3, 9, 1);
static struct qb_attr_code code_cscheduler_erem_cq = QB_CODE(3, 16, 8);
static struct qb_attr_code code_cscheduler_erem_group_a = QB_CODE(3, 24, 1);
static struct qb_attr_code code_cscheduler_erem_group_b = QB_CODE(3, 25, 1);

void qbman_cscheduler_attr_clear(struct qbman_attr *d)
{
	memset(d, 0, sizeof(*d));
	attr_type_set(d, qbman_attr_usage_cscheduler);
}

void qbman_cscheduler_set_mps(struct qbman_attr *d, uint8_t mps)
{
	uint32_t *p = ATTR32(d);

	if ((qman_version & 0xFFFF0000) < QMAN_REV_5000) {
		pr_err("This feature is only supported on QMan5.0 and later\n");
		return;
	}
	qb_attr_code_encode(&code_cscheduler_mps, p, mps);
}
void qbman_cscheduler_get_mps(struct qbman_attr *d, uint8_t *mps)
{
	uint32_t *p = ATTR32(d);

	*mps = (uint8_t)qb_attr_code_decode(&code_cscheduler_mps, p);
}

void qbman_cscheduler_set_oal(struct qbman_attr *d, uint16_t oal)
{
	uint32_t *p = ATTR32(d);

	if ((qman_version & 0xFFFF0000) < QMAN_REV_5000) {
		pr_err("This feature is only supported on QMan5.0 and later\n");
		return;
	}
	qb_attr_code_encode(&code_cscheduler_oal, p, oal);
}
// ToDo: original code oal was a uint8_t but from BG it is 11bits. Verify
void qbman_cscheduler_get_oal(struct qbman_attr *d, uint16_t *oal)
{
	uint32_t *p = ATTR32(d);

	*oal = 0x07FF & (uint16_t)qb_attr_code_decode(&code_cscheduler_oal, p);
}

void qbman_cscheduler_set_cqps(struct qbman_attr *d, uint8_t cqps)
{
	uint32_t *p = ATTR32(d);
	qb_attr_code_encode(&code_cscheduler_cqps, p, cqps);
}
void qbman_cscheduler_get_cqps(struct qbman_attr *d, uint8_t *cqps)
{
	uint32_t *p = ATTR32(d);
	*cqps = (uint8_t)qb_attr_code_decode(&code_cscheduler_cqps, p);
}

void qbman_cscheduler_set_prio_a(struct qbman_attr *d, uint32_t prio_a)
{
	uint32_t *p = ATTR32(d);
	BUG_ON(prio_a > 7);
	qb_attr_code_encode(&code_cscheduler_prio_a, p, prio_a);
}
void qbman_cscheduler_get_prio_a(struct qbman_attr *d, uint32_t *prio_a)
{
	uint32_t *p = ATTR32(d);
	*prio_a = qb_attr_code_decode(&code_cscheduler_prio_a, p);
}

void qbman_cscheduler_set_prio_b(struct qbman_attr *d, uint32_t prio_b)
{
	uint32_t *p = ATTR32(d);
	BUG_ON(prio_b > 7);
	qb_attr_code_encode(&code_cscheduler_prio_b, p, prio_b);
}
void qbman_cscheduler_get_prio_b(struct qbman_attr *d, uint32_t *prio_b)
{
	uint32_t *p = ATTR32(d);
	*prio_b = qb_attr_code_decode(&code_cscheduler_prio_b, p);
}

void qbman_cscheduler_set_group_b(struct qbman_attr *d, int group_b)
{
	uint32_t *p = ATTR32(d);
	qb_attr_code_encode(&code_cscheduler_group_b, p, !!group_b);
}
void qbman_cscheduler_get_group_b(struct qbman_attr *d, int *group_b)
{
	uint32_t *p = ATTR32(d);
	*group_b = !!qb_attr_code_decode(&code_cscheduler_group_b, p);
}

void qbman_cscheduler_set_crem_cq(struct qbman_attr *d,
				  uint8_t cq_idx, int cre)
{
	uint32_t *p = ATTR32(d);
	uint8_t cqs;
	cqs = (uint8_t)qb_attr_code_decode(&code_cscheduler_crem_cq, p);
#ifdef ERR008742
	cqs = cqs & (uint8_t)(~(1 << (7 - cq_idx))) |
			(uint8_t)(cre << (7 - cq_idx));
#else
	cqs = cqs & (uint8_t)(~(1 << cq_idx)) | (uint8_t)(cre << cq_idx);
#endif
	qb_attr_code_encode(&code_cscheduler_crem_cq, p, cqs);
}
void qbman_cscheduler_get_crem_cq(struct qbman_attr *d,
				  uint8_t cq_idx, int *cre)
{
	uint32_t *p = ATTR32(d);
	uint8_t cqs;
	cqs = (uint8_t)qb_attr_code_decode(&code_cscheduler_crem_cq, p);
#ifdef ERR008742
	*cre = (cqs >> (7 - cq_idx)) & 1;
#else
	*cre = (cqs >> cq_idx) & 1;
#endif
}

void qbman_cscheduler_set_crem_group_a(struct qbman_attr *d,
				       int cre)
{
	uint32_t *p = ATTR32(d);
	qb_attr_code_encode(&code_cscheduler_crem_group_a, p,
			    !!cre);
}
void qbman_cscheduler_get_crem_group_a(struct qbman_attr *d,
				       int *cre)
{
	uint32_t *p = ATTR32(d);
	*cre = !!qb_attr_code_decode(&code_cscheduler_crem_group_a, p);
}

void qbman_cscheduler_set_crem_group_b(struct qbman_attr *d,
				       int cre)
{
	uint32_t *p = ATTR32(d);
	qb_attr_code_encode(&code_cscheduler_crem_group_b, p,
			    !!cre);
}
void qbman_cscheduler_get_crem_group_b(struct qbman_attr *d,
				       int *cre)
{
	uint32_t *p = ATTR32(d);
	*cre = !!qb_attr_code_decode(&code_cscheduler_crem_group_b, p);
}

void qbman_cscheduler_set_erem_cq(struct qbman_attr *d,
				  uint8_t cq_idx, int ere)
{
	uint32_t *p = ATTR32(d);
	uint8_t cqs;
	cqs = (uint8_t)qb_attr_code_decode(&code_cscheduler_erem_cq, p);
#ifdef ERR008742
	cqs = cqs & (uint8_t)(~(1 << (7 - cq_idx))) |
			(uint8_t)(ere << (7 - cq_idx));
#else
	cqs = cqs & (uint8_t)(~(1 << cq_idx)) | (uint8_t)(ere << cq_idx);
#endif
	qb_attr_code_encode(&code_cscheduler_erem_cq, p, cqs);
}
void qbman_cscheduler_get_erem_cq(struct qbman_attr *d,
				  uint8_t cq_idx, int *ere)
{
	uint32_t *p = ATTR32(d);
	uint8_t cqs;
	cqs = (uint8_t)qb_attr_code_decode(&code_cscheduler_erem_cq, p);
#ifdef ERR008742
	*ere = (cqs >> (7 - cq_idx)) & 1;
#else
	*ere = (cqs >> cq_idx) & 1;
#endif
}

void qbman_cscheduler_set_erem_group_a(struct qbman_attr *d,
				       int ere)
{
	uint32_t *p = ATTR32(d);
	qb_attr_code_encode(&code_cscheduler_erem_group_a, p,
			    !!ere);
}
void qbman_cscheduler_get_erem_group_a(struct qbman_attr *d,
				       int *ere)
{
	uint32_t *p = ATTR32(d);
	*ere = !!qb_attr_code_decode(&code_cscheduler_erem_group_a, p);
}

void qbman_cscheduler_set_erem_group_b(struct qbman_attr *d,
				       int ere)
{
	uint32_t *p = ATTR32(d);
	qb_attr_code_encode(&code_cscheduler_erem_group_b, p,
			    !!ere);
}
void qbman_cscheduler_get_erem_group_b(struct qbman_attr *d,
				       int *ere)
{
	uint32_t *p = ATTR32(d);
	*ere = !!qb_attr_code_decode(&code_cscheduler_erem_group_b, p);
}

/* Divide 'n' by 'd', rounding down if 'r' is negative, rounding up if it's
 * positive, and rounding to the closest value if it's zero. NB, this macro
 * implicitly upgrades parameters to unsigned 64-bit, so feed it with types
 * that are compatible with this. NB, these arguments should not be expressions
 * unless it is safe for them to be evaluated multiple times. Eg. do not pass
 * in "some_value++" as a parameter to the macro! */
#define ROUNDING(n, d, r) \
	(((r) < 0) ? n / d : \
	(((r) > 0) ? ((n) + (d) - 1) / (d) : \
	((n) + ((d) / 2)) / (d)))

static void reduce_fraction(uint32_t *n, uint32_t *d)
{
	uint32_t factor = 2;
	uint32_t lesser = (*n < *d) ? *n : *d;
	/* If factor exceeds the square-root of the lesser of *n and *d,
	 * then there's no point continuing. Proof: if there was a factor
	 * bigger than the square root, that would imply there exists
	 * another factor smaller than the square-root with which it
	 * multiplies to give 'lesser' - but that's a contradiction
	 * because the other factor would have already been found and
	 * divided out.
	*/
	while ((factor * factor) <= lesser) {
		/* If 'factor' is a factor of *n and *d, divide them both
		 * by 'factor' as many times as possible.
		 */
		while (!(*n % factor) && !(*d % factor)) {
			*n /= factor;
			*d /= factor;
			lesser /= factor;
		}
		if (factor == 2)
			factor = 3;
		else
			factor += 2;
	}
}

/* The WBFS code is represent as {x,y}, the effect wieght can be calculated as:
 *	effective weight = 2^x / (1 - (y/64))
 *			 = 2^(x+6) / (64 - y)
 */
static uint32_t qbman_ceetm_wbfs2weight(uint8_t weight_code)
{
	uint32_t numerator, denominator;
	numerator = ((uint32_t) 1 << ((weight_code & 7) + 6)) * 100;
	denominator = (uint32_t)64 - ((weight_code & 0xf8) >> 3);
	reduce_fraction(&numerator, &denominator);
	return numerator / denominator;
}

/* For a given x, the weight is between 2^x (inclusive) and 2^(x+1) (exclusive).
 * So find 'x' by range, and then estimate 'y' using:
 *      64 - y  = 2^(x + 6) / weight
 *              = 2^(x + 6) / (n/d)
 *              = d * 2^(x+6) / n
 *            y = 64 - (d * 2^(x+6) / n)
 */
static int qbman_ceetm_weight2wbfs(uint32_t weight, uint8_t *weight_code,
			    int rounding)
{
	unsigned int y, x = 0;
	/* search incrementing 'x' until:
	 * weight < 2^(x+1)
	 *    n/d < 2^(x+1)
	 *      n < d * 2^(x+1)
	 */
	while ((x < 8) && (weight >= (100 << (x + 1))))
		x++;
	if (x >= 8)
		return -ERANGE;
	/* because of the subtraction, use '-rounding' */
	y = (uint32_t)64 - ROUNDING(100 << (x + 6), weight, -rounding);
	if (y >= 32)
		return -ERANGE;

	*weight_code = (uint8_t)(y << 3) | (uint8_t)x;
	return 0;
}

void qbman_cscheduler_set_csms(struct qbman_attr *d, int csms)
{
	uint32_t *p = ATTR32(d);

	if ((qman_version & 0xFFFF0000) < QMAN_REV_5000) {
		pr_err("The CSMS is only supported on QMan5.0 and later\n");
		return;
	}
	qb_attr_code_encode(&code_cscheduler_csms, p, !!csms);
}
void qbman_cscheduler_get_csms(struct qbman_attr *d, int *csms)
{
	uint32_t *p = ATTR32(d);
	*csms = !!qb_attr_code_decode(&code_cscheduler_csms, p);
}

#ifdef ERR008742
#define CQ_WORD(idx) ((idx & 0x4) ? 4 : 5)
#define CQ_OFFSET(idx) ((3 - (idx & 0x3)) * 8)
#else
#define CQ_WORD(idx) ((idx >> 2) + 2)
#define CQ_OFFSET(idx) ((idx & 0x3) * 8)
#endif

#define CQ_WORD_CSMS(idx) ((idx >> 2) + 4)

/* The weight should be 100 - 24800, since we are using 100 as the
 * denominator.
 */
void qbman_cscheduler_set_cq_weight(struct qbman_attr *d, uint32_t cq_idx,
				    uint32_t weight, int csms)
{
	struct qb_attr_code code_cscheduler_w;
	uint32_t *p = ATTR32(d);
	uint8_t weight_code;

	if ((qman_version & 0xFFFF0000) < QMAN_REV_5000) {
		BUG_ON(cq_idx < 8);
		code_cscheduler_w.word = CQ_WORD(cq_idx);
	} else {
		code_cscheduler_w.word = csms ? CQ_WORD_CSMS(cq_idx) : CQ_WORD(cq_idx);;
	}
	code_cscheduler_w.lsoffset = CQ_OFFSET(cq_idx);
	code_cscheduler_w.width = 8;

	if (qbman_ceetm_weight2wbfs(weight, &weight_code, 0))
		pr_err("Cannot get the weight_code\n");

	qb_attr_code_encode(&code_cscheduler_w, p, weight_code);
}
void qbman_cscheduler_get_cq_weight(struct qbman_attr *d, uint32_t cq_idx,
				    uint32_t *weight)
{
	struct qb_attr_code code_cscheduler_w;
	uint32_t *p = ATTR32(d);
	uint8_t weight_code;

	if ((qman_version & 0xFFFF0000) < QMAN_REV_5000) {
		BUG_ON(cq_idx < 8);
		code_cscheduler_w.word = CQ_WORD(cq_idx);
	} else {
		int csms = !!qb_attr_code_decode(&code_cscheduler_csms, p);
		int qcqr = !!qb_attr_code_decode(&code_cscheduler_qcqr, p);
		if (!csms && (cq_idx < 8)) {
			pr_err("This CQ weight is not available\n");
			return;
		}
		if ((!qcqr && (cq_idx > 7)) || (qcqr && (cq_idx < 8))) {
			pr_err("This CQ index is not correct\n");
			return;
		}
		if (!qcqr)
			code_cscheduler_w.word = CQ_WORD_CSMS(cq_idx);
		else
			code_cscheduler_w.word = CQ_WORD(cq_idx);
	}
	code_cscheduler_w.lsoffset = CQ_OFFSET(cq_idx);
	code_cscheduler_w.width = 8;

	weight_code = (uint8_t)qb_attr_code_decode(&code_cscheduler_w, p);
	*weight = qbman_ceetm_wbfs2weight(weight_code);
}

int qbman_cscheduler_configure(struct qbman_swp *s, uint32_t ceetmid,
			       uint8_t cchannelid,
			       const struct qbman_attr *attr)
{
	uint32_t *p;
	uint32_t verb, rslt;
	const uint32_t *a = ATTR32(attr);

	if (((struct int_qbman_attr *)attr)->usage != qbman_attr_usage_cscheduler) {
		pr_err("The qbman_attr is not for class scheduler configure\n");
		return -EINVAL;
	}

	/* Start the management command */
	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;

	/* Encode the caller-provided attributes */
	word_copy(&p[1], &a[1], 15);
	if ((qman_version & 0xFFFF0000) >= QMAN_REV_5000) {
		/* Avoid the miss of CSMS setting */
		int csms = qb_attr_code_decode(&code_cscheduler_csms, a);
		qb_attr_code_encode(&code_cscheduler_csms, p, !!csms);
	}
	qb_attr_code_encode(&code_ceetm_id, p, ceetmid);
	qb_attr_code_encode(&code_ceetm_cchannelid, p, cchannelid);

	/* Complete the management command */
	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_CSCHED_CONFIGURE);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	/* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	BUG_ON(verb != QBMAN_MC_CSCHED_CONFIGURE);

	/* Determine success or failure */
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Configure of CEETM class scheduler 0x%x failed,"
			" code=0x%02x\n", cchannelid, rslt);
		return -EIO;
	}
	return 0;
}

int qbman_cscheduler_query(struct qbman_swp *s, uint32_t ceetmid,
			   uint8_t cchannelid, int qcqr,
			   struct qbman_attr *attr)
{
	uint32_t *p;
	uint32_t verb, rslt;
	uint32_t *a = ATTR32(attr);

	qbman_cscheduler_attr_clear(attr);

	/* Start the management command */
	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;

	/* Encode the caller-provided attributes */
	qb_attr_code_encode(&code_ceetm_id, p, ceetmid);
	qb_attr_code_encode(&code_ceetm_cchannelid, p, cchannelid);
	if ((qman_version & 0xFFFF0000) >= QMAN_REV_5000)
		qb_attr_code_encode(&code_cscheduler_qcqr, p, qcqr);

	/* Complete the management command */
	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_CSCHED_QUERY);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	/* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	BUG_ON(verb != QBMAN_MC_CSCHED_QUERY);

	/* Determine success or failure */
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Query of CEETM class scheduler 0x%x failed,"
			" code=0x%02x\n", cchannelid, rslt);
		return -EIO;
	}

	word_copy(&a[0], &p[0], 16);
	return 0;
}
/* --------------------- */
/* Channel configuration */
/* --------------------- */

static struct qb_attr_code code_cchannel_lniid = QB_CODE(1, 8, 6);
static struct qb_attr_code code_cchannel_shaped = QB_CODE(1, 15, 1);

int qbman_cchannel_configure(struct qbman_swp *s, uint32_t ceetmid, uint8_t cchannelid,
			     uint8_t lniid, int shaped)
{
	uint32_t *p;
	uint32_t verb, rslt;
	uint32_t rslt_maptype;
	uint8_t rslt_cchannelid;

	/* Start the management command */
	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;

	/* Encode the caller-provided attributes */
	qb_attr_code_encode(&code_ceetm_id, p, ceetmid);
	qb_attr_code_encode(&code_ceetm_maptype, p, QBMAN_MC_MAPPING_CHANNEL);
	qb_attr_code_encode(&code_ceetm_cchannelid, p, cchannelid);
	qb_attr_code_encode(&code_cchannel_lniid, p, lniid);
	qb_attr_code_encode(&code_cchannel_shaped, p, !!shaped);

	/* Complete the management command */
	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_MAPPING_CONFIGURE);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	/* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	rslt_maptype = qb_attr_code_decode(&code_ceetm_maptype, p);
	rslt_cchannelid = (uint8_t)qb_attr_code_decode(&code_ceetm_cchannelid,
							 p);
	BUG_ON(verb != QBMAN_MC_MAPPING_CONFIGURE);
	BUG_ON(QBMAN_MC_MAPPING_CHANNEL != rslt_maptype);
	BUG_ON(cchannelid != rslt_cchannelid);

	/* Determine success or failure */
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Configure of CEETM channel 0x%x failed, code=0x%02x\n",
		       cchannelid, rslt);
		return -EIO;
	}
	return 0;
}

//#ifdef MC_CLI
int qbman_cchannel_query(struct qbman_swp *s, uint32_t ceetmid, uint8_t cchannelid,
			     uint8_t *lniid, int *shaped)
{
	uint32_t *p;
	uint32_t verb, rslt;
	uint32_t rslt_maptype;
	uint8_t rslt_cchannelid;

	/* Start the management command */
	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;

	/* Encode the caller-provided attributes */
	qb_attr_code_encode(&code_ceetm_id, p, ceetmid);
	qb_attr_code_encode(&code_ceetm_maptype, p, QBMAN_MC_MAPPING_CHANNEL);
	qb_attr_code_encode(&code_ceetm_cchannelid, p, cchannelid);

	/* Complete the management command */
	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_MAPPING_QUERY);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	/* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	rslt_maptype = qb_attr_code_decode(&code_ceetm_maptype, p);
	rslt_cchannelid = (uint8_t)qb_attr_code_decode(&code_ceetm_cchannelid, p);
	*lniid = qb_attr_code_decode(&code_cchannel_lniid, p);
	*shaped = qb_attr_code_decode(&code_cchannel_shaped, p);
	BUG_ON(verb != QBMAN_MC_MAPPING_QUERY);
	BUG_ON(QBMAN_MC_MAPPING_CHANNEL != rslt_maptype);
	BUG_ON(cchannelid != rslt_cchannelid);

	/* Determine success or failure */
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Configure of CEETM channel 0x%x failed, code=0x%02x\n",
		       cchannelid, rslt);
		return -EIO;
	}
	return 0;
}
//#endif

/* ------------------------ */
/* Sub-portal configuration */
/* ------------------------ */

static struct qb_attr_code code_subportal_spid = QB_CODE(0, 16, 6);
static struct qb_attr_code code_subportal_lniid = QB_CODE(1, 8, 6);
static struct qb_attr_code code_subportal_txenable = QB_CODE(1, 15, 1);

int qbman_subportal_configure(struct qbman_swp *s, uint32_t ceetmid, uint8_t subportalid,
			      uint8_t lniid, int txenable)
{
	uint32_t *p;
	uint32_t verb, rslt;
	uint8_t rslt_maptype;
	uint8_t rslt_subportalid;

	/* Start the management command */
	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;

	/* Encode the caller-provided attributes */
	qb_attr_code_encode(&code_ceetm_id, p, ceetmid);
	qb_attr_code_encode(&code_ceetm_maptype, p, QBMAN_MC_MAPPING_SUBPORTAL);
	qb_attr_code_encode(&code_subportal_spid, p, subportalid);
	qb_attr_code_encode(&code_subportal_lniid, p, lniid);
	qb_attr_code_encode(&code_subportal_txenable, p, !!txenable);

	/* Complete the management command */
	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_MAPPING_CONFIGURE);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	/* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	rslt_maptype = (uint8_t)qb_attr_code_decode(&code_ceetm_maptype, p);
	rslt_subportalid = (uint8_t)qb_attr_code_decode(&code_subportal_spid, p);
	BUG_ON(verb != QBMAN_MC_MAPPING_CONFIGURE);
	BUG_ON(QBMAN_MC_MAPPING_SUBPORTAL != rslt_maptype);
	BUG_ON(subportalid != rslt_subportalid);

	/* Determine success or failure */
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Configure of subportal 0x%x failed, code=0x%02x\n",
		       subportalid, rslt);
		return -EIO;
	}
	return 0;
}

/* -------------------- */
/* Shaper configuration */
/* -------------------- */
static struct qb_attr_code code_shaper_lniid = QB_CODE(0, 16, 6);
static struct qb_attr_code code_shaper_cqid = QB_CODE(0, 16, 9);
static struct qb_attr_code code_shaper_mps = QB_CODE(1, 8, 7);
static struct qb_attr_code code_shaper_oal = QB_CODE(1, 16, 11);
static struct qb_attr_code code_shaper_cpl = QB_CODE(1, 31, 1);
static struct qb_attr_code code_shaper_crtcr = QB_CODE(2, 0, 28);
static struct qb_attr_code code_shaper_ertcr = QB_CODE(3, 0, 28);
static struct qb_attr_code code_shaper_crtbl = QB_CODE(4, 0, 18);
static struct qb_attr_code code_shaper_ertbl = QB_CODE(4, 16, 16);
static struct qb_attr_code code_shaper_ertbl_50 = QB_CODE(5, 0, 18);

void qbman_shaper_attr_clear(struct qbman_attr *d)
{
	memset(d, 0, sizeof(*d));
	attr_type_set(d, qbman_attr_usage_shaper);
}

void qbman_shaper_set_lni_mps(struct qbman_attr *d, uint32_t mps)
{
	uint32_t *p = ATTR32(d);
	qb_attr_code_encode(&code_shaper_mps, p, mps);
}
void qbman_shaper_get_lni_mps(struct qbman_attr *d, uint32_t *mps)
{
	uint32_t *p = ATTR32(d);
	*mps = qb_attr_code_decode(&code_shaper_mps, p);
}

void qbman_shaper_set_lni_oal(struct qbman_attr *d, uint32_t oal)
{
	uint32_t *p = ATTR32(d);
	qb_attr_code_encode(&code_shaper_oal, p, oal);
}
void qbman_shaper_get_lni_oal(struct qbman_attr *d, uint32_t *oal)
{
	uint32_t *p = ATTR32(d);
	*oal = qb_attr_code_decode(&code_shaper_oal, p);
}

void qbman_shaper_set_coupling(struct qbman_attr *d, int cpl)
{
	uint32_t *p = ATTR32(d);
	qb_attr_code_encode(&code_shaper_cpl, p, !!cpl);
}
void qbman_shaper_get_coupling(struct qbman_attr *d, int *cpl)
{
	uint32_t *p = ATTR32(d);
	*cpl = !!qb_attr_code_decode(&code_shaper_cpl, p);
}

static uint32_t qbman_bps2tokenrate(uint64_t bps, int rounding)
{
	uint64_t temp;

	/* For QMan4.x:
	 * token-rate = bytes-per-second * update-reference-period
	 *
	 * Where token-rate is N/8192 for a integer N, and
	 * update-reference-period is (2^22)/(PRES*QHz), where PRES
	 * is the prescalar value and QHz is the QMan clock frequency.
	 * So:
	 *
	 * token-rate = (byte-per-second*2^22)/PRES*QHZ)
	 *
	 * Converting to bits-per-second gives;
	 *
	 *      token-rate = (bps*2^19) / (PRES*QHZ)
	 *      N = (bps*2^32) / (PRES*QHz)
	 *
	 * And to avoid 64-bit overflow if 'bps' is larger than 4Gbps
	 * (yet minimise rounding error if 'bps' is small), we reorganise
	 * the formula to use two 16-bit shifts rather than 1 32-bit shift.
	 *      N = (((bps*2^16)/PRES)*2^16)/QHz
	 *
	 * For QMan 5.0:
	 * bps = (token-rate * 8 * QHz * PRES) / 2 ^ 23
	 * where token-rate is N/8192 for a integer N.
	 * So:
	 *	token-rate = (bps * 2 ^ 20) / (PRES * QHZ)
	 *	N = (bps * 2 ^ 33) / (PRES * QHZ)
	 */
	if ((qman_version & 0xFFFF0000) < QMAN_REV_5000) {
		temp = ROUNDING((bps << 16), qman_pres, rounding);
		temp = ROUNDING((temp << 16), qman_freq, rounding);
	} else {
		temp = ROUNDING((bps << 16), qman_freq, rounding);
		temp = ROUNDING((temp << 17), qman_pres, rounding);
	}
	return (uint32_t)temp;
}

static uint64_t qbman_tokenrate2bps(const uint32_t token_rate, int rounding)
{
	uint64_t temp;

	/* For QMan4.x:
	 * bytes-per-second = token-rate / update-reference-period
	 *
	 * where "token-rate" is N/8192 for an integer N, and
	 * "update-reference-period" is (2^22)/(PRES*QHz), where PRES is
	 * the prescalar value and QHz is the QMan clock frequency. So;
	 *
	 * bytes-per-second = (N/8192) / (4194304/PRES*QHz)
	 *                  = N*PRES*QHz / (4194304*8192)
	 *                  = N*PRES*QHz / (2^35)
	 *
	 * Converting to bits-per-second gives;
	 *
	 *             bps = N*PRES*QHZ / (2^32)
	 *
	 * Note, the numerator has a maximum width of 72 bits! So to
	 * avoid 64-bit overflow errors, we calculate PRES*QHZ (maximum
	 * width 48 bits) divided by 2^9 (reducing to maximum 39 bits), before
	 * multiplying by N (goes to maximum of 63 bits).
	 *
	 *             temp = PRES*QHZ / (2^16)
	 *             bps = temp*N / (2^16)
	 *
	 * For QMan5.0:
	 * 		bps = N * PRES * QHZ / (2 ^ 33)
	 * 		temp = PRES * N / (2 ^ 17)
	 *		bps = temp * QHZ / (2 ^ 16)
	 */
	if ((qman_version & 0xFFFF0000) < QMAN_REV_5000) {
		temp = ROUNDING((uint64_t)qman_freq * (uint64_t)qman_pres,
				(uint64_t)1 << 16, rounding);
		temp *= (uint64_t)token_rate;
		return ROUNDING(temp, (uint64_t)(1) << 16, rounding);
	} else {
		temp = ROUNDING((uint64_t)token_rate * (uint64_t)qman_freq,
			       (uint64_t)1 << 17, rounding);
		return ROUNDING(temp * (uint64_t)qman_pres,
			       (uint64_t)1 << 16, rounding);
	}
}

void qbman_shaper_set_commit_rate(struct qbman_attr *d, uint64_t bps)
{
	uint32_t *p = ATTR32(d);
	uint32_t crtcr;

	crtcr = qbman_bps2tokenrate(bps, -1);
	qb_attr_code_encode(&code_shaper_crtcr, p, crtcr);
}
void qbman_shaper_get_commit_rate(struct qbman_attr *d, uint64_t *bps)
{
	uint32_t *p = ATTR32(d);
	uint32_t crtcr;

	crtcr = qb_attr_code_decode(&code_shaper_crtcr, p);
	*bps = qbman_tokenrate2bps(crtcr, 1);
}

void qbman_shaper_set_excess_rate(struct qbman_attr *d, uint64_t bps)
{
	uint32_t *p = ATTR32(d);
	uint32_t ertcr;

	ertcr = qbman_bps2tokenrate(bps, -1);
	qb_attr_code_encode(&code_shaper_ertcr, p, ertcr);
}
void qbman_shaper_get_excess_rate(struct qbman_attr *d, uint64_t *bps)
{
	uint32_t *p = ATTR32(d);
	uint32_t ertcr;

	ertcr = qb_attr_code_decode(&code_shaper_ertcr, p);
	*bps = qbman_tokenrate2bps(ertcr, 1);
}

void qbman_shaper_set_crtbl(struct qbman_attr *d, uint32_t tbl)
{
	uint32_t *p = ATTR32(d);

	if ((qman_version & 0xFFFF0000) < QMAN_REV_5000) {
		/*
		 * Setting the tbl larger than the maximum allowed value may
		 * lead an incorrect shaper output rates.
		 */
//#ifdef MC_CLI
        // allow 0xFFFF for reset value
        if(tbl > 0xF7FF && tbl != 0xFFFF)
            tbl = 0xF7FF;
//#else
//		BUG_ON(tbl > 0xF7FF);
//#endif
		qb_attr_code_encode(&code_shaper_crtbl, p, tbl);
	} else {
//#ifdef MC_CLI
        // allow 0x3FFFF for reset value
        if(tbl > 0x37FFF && tbl != 0x3FFFF)
            tbl = 0x37FFF;
//#else
//		BUG_ON(tbl > 0x37FFF);
//#endif
		qb_attr_code_encode(&code_shaper_crtbl, p, tbl);
	}
}
void qbman_shaper_get_crtbl(struct qbman_attr *d, uint32_t *tbl)
{
	uint32_t *p = ATTR32(d);

	if ((qman_version & 0xFFFF0000) < QMAN_REV_5000)
		*tbl = qb_attr_code_decode(&code_shaper_crtbl, p);
	else
		*tbl = qb_attr_code_decode(&code_shaper_crtbl, p);
}

void qbman_shaper_set_ertbl(struct qbman_attr *d, uint32_t tbl)
{
	uint32_t *p = ATTR32(d);

	if ((qman_version & 0xFFFF0000) < QMAN_REV_5000) {
		/*
		 * Setting the tbl larger than the maximum allowed value
		 * may lead an incorrect shaper output rates.
		 */
		BUG_ON(tbl > 0xF7FF);
		qb_attr_code_encode(&code_shaper_ertbl, p, tbl);
	} else {
		BUG_ON(tbl > 0x37FFF);
		qb_attr_code_encode(&code_shaper_ertbl_50, p, tbl);
	}
}
void qbman_shaper_get_ertbl(struct qbman_attr *d, uint32_t *tbl)
{
	uint32_t *p = ATTR32(d);
	if ((qman_version & 0xFFFF0000) < QMAN_REV_5000)
		*tbl = qb_attr_code_decode(&code_shaper_ertbl, p);
	else
		*tbl = qb_attr_code_decode(&code_shaper_ertbl_50, p);
}

uint32_t qbman_fix_burst_size(uint32_t burst_size, uint64_t bps)
{
	uint32_t tca;
	uint32_t max_tbl;

	if( !burst_size ) {
		tca = qbman_bps2tokenrate(bps, -1);

		if( tca ) {
			if( (qman_version & 0xFFFF0000) < QMAN_REV_5000 )
				max_tbl = 0xF7FF;
			else
				max_tbl = 0x37FFF;

			tca = tca / 8192 + 1;
			burst_size = tca > max_tbl ? max_tbl : tca;
		}
	}

	return burst_size;
}

static int qbman_shaper_configure(struct qbman_swp *s, uint32_t ceetmid,
			   uint16_t id, uint8_t ct, struct qbman_attr *attr)
{
	uint32_t *p;
	uint32_t verb, rslt;
	uint32_t rslt_maptype;
	uint8_t rslt_id;
	uint32_t *d = ATTR32(attr);

	if (((struct int_qbman_attr *)attr)->usage != qbman_attr_usage_shaper) {
		pr_err("The qbman_attr is not for shaper configure\n");
		return -EINVAL;
	}

	/* Start the management command */
	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;

	word_copy(&p[1], &d[1], 15);

	/* Encode the caller-provided attributes */
	qb_attr_code_encode(&code_ceetm_id, p, ceetmid);
	switch (ct) {
	case QBMAN_MC_SHAPER_LNI:
		qb_attr_code_encode(&code_ceetm_maptype, p,
				    QBMAN_MC_SHAPER_LNI);
		qb_attr_code_encode(&code_shaper_lniid, p, id);
		break;
	case QBMAN_MC_SHAPER_CHANNEL:
		qb_attr_code_encode(&code_ceetm_maptype, p,
				    QBMAN_MC_SHAPER_CHANNEL);
		qb_attr_code_encode(&code_ceetm_cchannelid, p, id);
		break;
	case QBMAN_MC_SHAPER_CQ:
		qb_attr_code_encode(&code_ceetm_maptype, p, QBMAN_MC_SHAPER_CQ);
		qb_attr_code_encode(&code_shaper_cqid, p, id);
		break;
	default:
		pr_err("Unknown command type for shaper configure\n");
		return -EINVAL;
	}

	/* Complete the management command */
	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_MAPPING_CONFIGURE);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	/* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	rslt_maptype = qb_attr_code_decode(&code_ceetm_maptype, p);
	rslt_id = (uint16_t)qb_attr_code_decode(&code_shaper_cqid, p);
	BUG_ON(verb != QBMAN_MC_MAPPING_CONFIGURE);
	BUG_ON(rslt_maptype != ct);
	BUG_ON(rslt_id != id);

	/* Determine success or failure */
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Configure of CEETM shaper failed  code=0x%02x\n",
							 rslt);
		return -EIO;
	}
	return 0;
}

static int qbman_shaper_query(struct qbman_swp *s, uint32_t ceetmid,
		       uint32_t id, uint8_t ct, struct qbman_attr *attr)
{
	uint32_t *p;
	uint32_t verb, rslt;
	uint32_t rslt_maptype;
	uint8_t rslt_id;
	uint32_t *d = ATTR32(attr);

	qbman_shaper_attr_clear(attr);
	/* Start the management command */
	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;

	/* Encode the caller-provided attributes */
	qb_attr_code_encode(&code_ceetm_id, p, ceetmid);
	switch (ct) {
	case QBMAN_MC_SHAPER_LNI:
		qb_attr_code_encode(&code_ceetm_maptype, p,
					QBMAN_MC_SHAPER_LNI);
		qb_attr_code_encode(&code_shaper_lniid, p, id);
		break;
	case QBMAN_MC_SHAPER_CHANNEL:
		qb_attr_code_encode(&code_ceetm_maptype, p,
					QBMAN_MC_SHAPER_CHANNEL);
		qb_attr_code_encode(&code_ceetm_cchannelid, p, id);
		break;
	case QBMAN_MC_SHAPER_CQ:
		qb_attr_code_encode(&code_ceetm_maptype, p,
					QBMAN_MC_SHAPER_CQ);
		qb_attr_code_encode(&code_shaper_cqid, p, id);
		break;
	default:
		pr_err("Unknown command type for shaper query\n");
		return -EINVAL;
	}

	/* Complete the management command */
	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_MAPPING_QUERY);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	/* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	rslt_maptype = qb_attr_code_decode(&code_ceetm_maptype, p);
	rslt_id = (uint8_t)qb_attr_code_decode(&code_shaper_cqid, p);
	BUG_ON(verb != QBMAN_MC_MAPPING_QUERY);
	BUG_ON(ct != rslt_maptype);
	BUG_ON(id != rslt_id);

	/* Determine success or failure */
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Query of CEETM shaper failed, code=0x%02x\n", rslt);
		return -EIO;
	}
	word_copy(&d[1], &p[1], 15);
	return 0;
}

int qbman_lni_shaper_configure(struct qbman_swp *s, uint32_t ceetmid,
			       uint32_t lniid, struct qbman_attr *attr)
{
	return qbman_shaper_configure(s, ceetmid, lniid,
				      QBMAN_MC_SHAPER_LNI, attr);
}

int qbman_lni_shaper_query(struct qbman_swp *s, uint32_t ceetmid,
			   uint32_t lniid, struct qbman_attr *attr)
{
	return qbman_shaper_query(s, ceetmid, lniid,
				  QBMAN_MC_SHAPER_LNI, attr);
}

int qbman_lni_shaper_disable(struct qbman_swp *s, uint32_t ceetmid,
			     uint32_t lniid, uint32_t oal)
{
	uint32_t verb, rslt;
	uint32_t rslt_maptype;
	uint8_t rslt_lniid;
	struct qbman_attr attr;
	uint32_t *p = ATTR32(&attr);
	uint32_t tcr;
	uint32_t tbl;

	if ((qman_version & 0xFFFF0000) < QMAN_REV_5000) {
		tcr = 0x00FFFFFF;
		tbl = 0x0000FFFF;
	} else {
		/* QMan 5.0 and above */
		tcr = 0x0FFFFFFF;
		tbl = 0x0003FFFF;
	}

	memset(p, 0, sizeof(struct qbman_attr));
	attr_type_set(&attr, qbman_attr_usage_shaper);

	/* Start the management command */
	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;

	qb_attr_code_encode(&code_shaper_crtcr, p, tcr);
	qb_attr_code_encode(&code_shaper_ertcr, p, tcr);
	qb_attr_code_encode(&code_shaper_crtbl, p, tbl);
	if ((qman_version & 0xFFFF0000) < QMAN_REV_5000) {
		qb_attr_code_encode(&code_shaper_ertbl, p, tbl);
	} else {
		qb_attr_code_encode(&code_shaper_ertbl_50, p, tbl);
	}
	/* Encode the caller-provided attributes */
	qb_attr_code_encode(&code_ceetm_id, p, ceetmid);
	qb_attr_code_encode(&code_ceetm_maptype, p, QBMAN_MC_SHAPER_LNI);
	qb_attr_code_encode(&code_shaper_lniid, p, lniid);
	qb_attr_code_encode(&code_shaper_oal, p, oal);

	/* Complete the management command */
	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_MAPPING_CONFIGURE);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	/* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	rslt_maptype = qb_attr_code_decode(&code_ceetm_maptype, p);
	rslt_lniid = (uint8_t)qb_attr_code_decode(&code_shaper_lniid, p);
	BUG_ON(verb != QBMAN_MC_MAPPING_CONFIGURE);
	BUG_ON(QBMAN_MC_SHAPER_LNI != rslt_maptype);
	BUG_ON(lniid != rslt_lniid);

	/* Determine success or failure */
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Disable shaping for LNI 0x%x failed,"
			" code=0x%02x\n", lniid, rslt);
		return -EIO;
	}
	return 0;
}

int qbman_cchannel_shaper_configure(struct qbman_swp *s, uint32_t ceetmid,
				    uint32_t cchannelid,
				    struct qbman_attr *attr)
{
	return qbman_shaper_configure(s, ceetmid, cchannelid,
				      QBMAN_MC_SHAPER_CHANNEL, attr);
}

int qbman_cchannel_shaper_query(struct qbman_swp *s, uint32_t ceetmid,
				uint32_t cchannelid,
				struct qbman_attr *attr)
{
	return qbman_shaper_query(s, ceetmid, cchannelid,
				  QBMAN_MC_SHAPER_CHANNEL, attr);
}

int qbman_cq_shaper_configure(struct qbman_swp *s, uint32_t ceetmid,
			      uint16_t cqid,
			      struct qbman_attr *attr)
{
	if ((qman_version & 0xFFFF0000) < QMAN_REV_5000) {
		pr_err("This QMan version doesn't support CQ shaper\n");
		return -EINVAL;
	}

	return qbman_shaper_configure(s, ceetmid, cqid,
				      QBMAN_MC_SHAPER_CQ, attr);
}

int qbman_cq_shaper_query(struct qbman_swp *s, uint32_t ceetmid,
			  uint16_t cqid,
			  struct qbman_attr *attr)
{
	if ((qman_version & 0xFFFF0000) < QMAN_REV_5000) {
		pr_err("This QMan version doesn't support CQ shaper\n");
		return -EINVAL;
	}
	return qbman_shaper_query(s, ceetmid, cqid, QBMAN_MC_SHAPER_CQ, attr);
}

/* ---------------------------------------------- */
/* LNI configuration (traffic class flow control) */
/* ---------------------------------------------- */
#define LNITCFC_WORD(a) (4 + (a >> 3))
#define LNITCFC_OFFSET(a) (4 * (a & 0x7))
#define LNITCFC_WORD_MODE2(a) (4 + (a >> 1))
#define LNITCFC_OFFSET_MODE2(a) (16 * (a & 0x1))
static struct qb_attr_code code_tcfc_mode = QB_CODE(1, 24, 2);

void qbman_ceetm_tcfc_attr_clear(struct qbman_attr *a)
{
	memset(a, 0, sizeof(*a));
	attr_type_set(a, qbman_attr_usage_tcfc);
}

int qbman_ceetm_tcfc_set_lnitcfcc(struct qbman_attr *a, uint8_t mode,
				   uint8_t cq_idx, uint8_t cchannelid,
				   uint8_t tcid, int enable)
{
	uint32_t *p = ATTR32(a);
	uint8_t lnitcfcc;
	struct qb_attr_code code_lni_tcfcc;
	int renable, i, position = 0xFF;
	uint16_t lnitcfcc_mode2;

	if (mode == 0) {
		BUG_ON(cq_idx > 15);
		code_lni_tcfcc.word = (unsigned int)LNITCFC_WORD(cq_idx);
		code_lni_tcfcc.lsoffset = (unsigned int)LNITCFC_OFFSET(cq_idx);
		code_lni_tcfcc.width = 4;
		lnitcfcc = ((uint8_t)enable << 3) | tcid;
		qb_attr_code_encode(&code_tcfc_mode, p, mode);
		qb_attr_code_encode(&code_lni_tcfcc, p, lnitcfcc);
	} else if (mode == 1 || mode == 3) {
		BUG_ON(cchannelid > 31);
		code_lni_tcfcc.word =
				(unsigned int)LNITCFC_WORD(cchannelid);
		code_lni_tcfcc.lsoffset =
				(unsigned int)LNITCFC_OFFSET(cchannelid);
		code_lni_tcfcc.width = 4;
		lnitcfcc = ((uint8_t)enable << 3) | tcid;
		qb_attr_code_encode(&code_tcfc_mode, p, mode);
		qb_attr_code_encode(&code_lni_tcfcc, p, lnitcfcc);
	} else if (mode == 2) {
		if ((qman_version & 0xFFFF0000) < QMAN_REV_4100) {
			pr_err("This mode is not supported on this QBMan\n");
			return -EINVAL;
		}
		for (i = 0; i < 8; i++) {
			code_lni_tcfcc.word =
					(unsigned int)LNITCFC_WORD_MODE2(i);
			code_lni_tcfcc.lsoffset =
					(unsigned int)LNITCFC_OFFSET_MODE2(i);
			code_lni_tcfcc.width = 16;
			lnitcfcc_mode2 = (uint16_t)qb_attr_code_decode(
						&code_lni_tcfcc, p);
			renable = ((int)lnitcfcc_mode2 >> 15) & 1;
			if (renable) {
				if (((lnitcfcc_mode2 & 0xF) == cq_idx) &&
					((lnitcfcc_mode2 >> 4) & 0x1F)
					 == cchannelid) {
					if (enable) {
					/* Can't program the same CQID twice */
						return 0;
					} else {
						position = i;
						break;
					}
				}
			} else {
				position = i;
				break;
			}
		}
		if ((i == 8) && (position == 0xFF)) {
			pr_err("No spot left for this CQ\n");
			return -EINVAL;
		}
		code_lni_tcfcc.word =
				(unsigned int)LNITCFC_WORD_MODE2(position);
		code_lni_tcfcc.lsoffset =
				(unsigned int)LNITCFC_OFFSET_MODE2(position);
		code_lni_tcfcc.width = 16;
		lnitcfcc_mode2 = (uint16_t)(enable << 15) |
				 (uint16_t)(tcid << 12) |
				 (uint16_t)(cchannelid << 4) |
				 (uint16_t)cq_idx;
		qb_attr_code_encode(&code_tcfc_mode, p, mode);
		qb_attr_code_encode(&code_lni_tcfcc, p, lnitcfcc_mode2);
	} else {
		pr_err("Unsupported mode for tcfcc configure\n");
		return -EINVAL;
	}
	return 0;
}

void qbman_ceetm_tcfc_set_lnitcfcc_ex(struct qbman_attr *a, uint8_t cq_idx,
				      uint8_t tc_id, int enable)
{
	uint32_t *p = ATTR32(a);
	uint16_t lnitcfcc;
	struct qb_attr_code code_lni_tcfcc;

	code_lni_tcfcc.word = (unsigned int)(8 + (tc_id >> 1));
	code_lni_tcfcc.lsoffset = (unsigned int)((tc_id & 1) * 16 + (cq_idx));
	code_lni_tcfcc.width = 1;
	qb_attr_code_encode(&code_lni_tcfcc, p, !!enable);
}

void qbman_ceetm_tcfc_get_lnitcfcc_ex(struct qbman_attr *a, uint8_t cq_idx,
				      uint8_t tc_id, int *enable)
{
	uint32_t *p = ATTR32(a);
	uint16_t lnitcfcc;
	struct qb_attr_code code_lni_tcfcc;

	code_lni_tcfcc.word = (unsigned int)(8 + (tc_id >> 1));
	code_lni_tcfcc.lsoffset = (unsigned int)((tc_id & 1) * 16 + (cq_idx));
	code_lni_tcfcc.width = 1;
	*enable = !!qb_attr_code_decode(&code_lni_tcfcc, p);
}

int qbman_ceetm_tcfc_configure(struct qbman_swp *s, uint32_t ceetmid,
			       uint8_t lniid, struct qbman_attr *a)
{
	uint32_t *p;
	uint32_t verb, rslt;
	uint32_t rslt_maptype;
	uint8_t rslt_lniid;
	uint32_t *d = ATTR32(a);

	/* Start the management command */
	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;
	/* Encode the caller-provided attributes */
	word_copy(&p[1], &d[1], 13);
	qb_attr_code_encode(&code_ceetm_id, p, ceetmid);
	qb_attr_code_encode(&code_ceetm_maptype, p, QBMAN_MC_MAPPING_TCFC);
	qb_attr_code_encode(&code_shaper_lniid, p, lniid);

	/* Complete the management command */
	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_MAPPING_CONFIGURE);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	/* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	rslt_maptype = qb_attr_code_decode(&code_ceetm_maptype, p);
	rslt_lniid = (uint8_t)qb_attr_code_decode(&code_shaper_lniid, p);
	BUG_ON(verb != QBMAN_MC_MAPPING_CONFIGURE);
	BUG_ON(QBMAN_MC_MAPPING_TCFC != rslt_maptype);
	BUG_ON(lniid != rslt_lniid);

	/* Determine success or failure */
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("TCFC configure of CEETM LNI 0x%x failed,"
			" code=0x%02x\n", lniid, rslt);
		return -EIO;
	}

	return 0;
}

int qbman_ceetm_tcfc_get_lnitcfcc(struct qbman_attr *a,
				  uint8_t cq_idx, uint8_t cchannelid,
				  uint8_t *mode, uint8_t *tcid, int *enable)
{
	uint32_t *p = ATTR32(a);
	struct qb_attr_code code_lni_tcfcc;
	int i;
	uint8_t lnitcfcc;
	uint16_t lnitcfcc_mode2;

	*mode = (uint8_t)qb_attr_code_decode(&code_tcfc_mode, p);
	if (*mode == 0) {
		code_lni_tcfcc.word = (unsigned int)LNITCFC_WORD(cq_idx);
		code_lni_tcfcc.lsoffset =
				(unsigned int)LNITCFC_OFFSET(cq_idx);
		code_lni_tcfcc.width = 4;
		lnitcfcc = (uint8_t)qb_attr_code_decode(&code_lni_tcfcc, p);
		*enable = ((int)lnitcfcc >> 3) & 0x1;
		*tcid = (uint8_t)lnitcfcc & 0x7;
	} else if (*mode == 1 || *mode == 3) {
		code_lni_tcfcc.word =
				(unsigned int)LNITCFC_WORD(cchannelid);
		code_lni_tcfcc.lsoffset =
				(unsigned)LNITCFC_OFFSET(cchannelid);
			code_lni_tcfcc.width = 4;
		lnitcfcc = (uint8_t)qb_attr_code_decode(&code_lni_tcfcc, p);
		*enable = ((int)lnitcfcc >> 3) & 0x1;
		*tcid = (uint8_t)lnitcfcc & 0x7;
	} else if (*mode == 2) {
		for (i = 0; i < 8; i++) {
			code_lni_tcfcc.word =
					(unsigned int)LNITCFC_WORD_MODE2(i);
			code_lni_tcfcc.lsoffset =
					(unsigned int)LNITCFC_OFFSET_MODE2(i);
			code_lni_tcfcc.width = 16;
			lnitcfcc_mode2 = (uint16_t)qb_attr_code_decode(
						&code_lni_tcfcc, p);
			if (((lnitcfcc_mode2 & 0xF) == cq_idx) &&
				((lnitcfcc_mode2 >> 4) & 0x1F) == cchannelid) {
				*enable = (int)lnitcfcc_mode2 >> 15;
				*tcid = ((uint8_t)(lnitcfcc_mode2 >> 12)) & 0x7;
				return 0;
			}
		}
	} else {
		pr_err("Unsupported mode for tcfcc query\n");
		return -EINVAL;
	}
	return 0;
}

int qbman_ceetm_tcfc_query(struct qbman_swp *s, uint32_t ceetmid,
			   uint8_t lniid, struct qbman_attr *a)
{
	uint32_t *p;
	uint32_t verb, rslt;
	uint32_t rslt_maptype;
	uint8_t rslt_lniid;
	uint32_t *d = ATTR32(a);

	qbman_ceetm_tcfc_attr_clear(a);
	/* Start the management command */
	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;
	/* Encode the caller-provided attributes */
	qb_attr_code_encode(&code_ceetm_id, p, ceetmid);
	qb_attr_code_encode(&code_ceetm_maptype, p, QBMAN_MC_MAPPING_TCFC);
	qb_attr_code_encode(&code_shaper_lniid, p, lniid);

	/* Complete the management command */
	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_MAPPING_QUERY);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	/* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	rslt_maptype = qb_attr_code_decode(&code_ceetm_maptype, p);
	rslt_lniid = (uint8_t)qb_attr_code_decode(&code_shaper_lniid, p);
	BUG_ON(verb != QBMAN_MC_MAPPING_QUERY);
	BUG_ON(QBMAN_MC_MAPPING_TCFC != rslt_maptype);
	BUG_ON(lniid != rslt_lniid);

	/* Determine success or failure */
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("TCFC query of CEETM LNI 0x%x failed,"
			" code=0x%02x\n", lniid, rslt);
		return -EIO;
	}
	word_copy(&d[1], &p[1], 13);
	return 0;
}

/* ------------------ */
/* CCGR configuration */
/* ------------------ */
static struct qb_attr_code code_ccgr_ccgid = QB_CODE(0, 16, 4);
static struct qb_attr_code code_ccgr_cchannelid = QB_CODE(0, 20, 5);
static struct qb_attr_code code_ccgr_command_type = QB_CODE(0, 30, 2);
static struct qb_attr_code code_ccgr_oal = QB_CODE(2, 16, 12);
static struct qb_attr_code code_ccgr_i_cnt_hi = QB_CODE(13, 0, 8);
static struct qb_attr_code code_ccgr_i_cnt_lo = QB_CODE(12, 0, 32);
static struct qb_attr_code code_ccgr_a_cnt_hi = QB_CODE(15, 0, 8);
static struct qb_attr_code code_ccgr_a_cnt_lo = QB_CODE(14, 0, 32);

/* Write-enable bits */
static struct qb_attr_code code_ccgr_we_oal = QB_CODE(1, 30, 1);

void qbman_ccgr_attr_clear(struct qbman_attr *a)
{
	memset(a, 0, sizeof(*a));
	attr_type_set(a, qbman_attr_usage_ccgr);
}

void qbman_ccgr_attr_set_oal(struct qbman_attr *d, uint32_t oal)
{
	uint32_t *p = ATTR32(d);
	qb_attr_code_encode(&code_ccgr_oal, p, oal);
	qb_attr_code_encode(&code_ccgr_we_oal, p, 1);
}
void qbman_ccgr_attr_get_oal(struct qbman_attr *d, uint32_t *oal)
{
	uint32_t *p = ATTR32(d);
	*oal = qb_attr_code_decode(&code_ccgr_oal, p);
}

void qbman_ccgr_attr_get_i_cnt(struct qbman_attr *d, uint64_t *i_cnt)
{
	uint64_t *p = (uint64_t *)ATTR32(d);
	*i_cnt = qb_attr_code_decode_64(&code_ccgr_i_cnt_lo, p) & 0xFFFFFFFFFF;
}

void qbman_ccgr_attr_get_a_cnt(struct qbman_attr *d, uint64_t *a_cnt)
{
	uint64_t *p = (uint64_t *)ATTR32(d);
	*a_cnt = qb_attr_code_decode_64(&code_ccgr_a_cnt_lo, p) & 0xFFFFFFFFFF;
}

int qbman_ccgr_configure(struct qbman_swp *s, uint32_t ceetmid, uint8_t cchannelid,
			 uint8_t ccgid, const struct qbman_attr *attr)
{
	uint32_t *p;
	uint32_t verb, rslt;
	uint16_t we_mask;
	const uint32_t *d[2];
	unsigned int i;

	if (((struct int_qbman_attr *)attr)->usage != qbman_attr_usage_ccgr) {
		pr_err("The qbman_attr is not for ccgr configure\n");
		return -EINVAL;
	}

	d[0] = ATTR32(attr);
	d[1] = ATTR32_1(attr);

	for (i = 0; i < 2; i++) {
		we_mask = (uint16_t)qb_attr_code_decode(&code_cgr_we_mask,
								d[i]);
		if (we_mask) {
			/* Start the management command */
			p = qbman_swp_mc_start(s);
			if (!p)
				return -EBUSY;
			word_copy(&p[0], &d[i][0], 16);
			qb_attr_code_encode(&code_ccgr_ccgid, p, ccgid);
			qb_attr_code_encode(&code_ccgr_cchannelid, p,
					    cchannelid);
			qb_attr_code_encode(&code_ccgr_command_type, p, i);
			qb_attr_code_encode(&code_ceetm_id, p, ceetmid);

			/* Complete the management command */
			p = qbman_swp_mc_complete(s, p,
					 p[0] | QBMAN_MC_CCGR_CONFIGURE);
			if (!p) {
				pr_err("SWP %d is not responding\n", s->desc.idx);
				return -EIO;
			}

			/* Decode the outcome */
			verb = qb_attr_code_decode(&code_generic_verb, p);
			rslt = qb_attr_code_decode(&code_generic_rslt, p);
			BUG_ON(verb != QBMAN_MC_CCGR_CONFIGURE);

			/* Determine success or failure */
			if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
				pr_err("Configure of CCGID 0x%x in Cchannel"
					" 0x%x failed, verb ="
					" 0x%02x, code=0x%02x\n",
					ccgid, cchannelid, verb, rslt);
				return -EIO;
			}
		}
	}
	return 0;
}

int qbman_ccgr_query(struct qbman_swp *s, uint32_t ceetmid, uint8_t cchannelid,
		     uint8_t ccgid, struct qbman_attr *attr)
{
	uint32_t *p;
	uint32_t verb, rslt;
	uint32_t *d[2];
	unsigned int i;

	d[0] = ATTR32(attr);
	d[1] = ATTR32_1(attr);

	qbman_ccgr_attr_clear(attr);

	for (i = 0; i < 2; i++) {
		p = qbman_swp_mc_start(s);
		if (!p)
			return -EBUSY;

		qb_attr_code_encode(&code_ccgr_ccgid, p, ccgid);
		qb_attr_code_encode(&code_ccgr_cchannelid, p,
				    cchannelid);
		qb_attr_code_encode(&code_ccgr_command_type, p, i);
		qb_attr_code_encode(&code_ceetm_id, p, ceetmid);

		p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_CCGR_QUERY);
		if (!p) {
			pr_err("SWP %d is not responding\n", s->desc.idx);
			return -EIO;
		}

		/* Decode the outcome */
		verb = qb_attr_code_decode(&code_generic_verb, p);
		rslt = qb_attr_code_decode(&code_generic_rslt, p);
		BUG_ON(verb != QBMAN_MC_CCGR_QUERY);

		/* Determine success or failure */
		if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
			pr_err("Query of CCGID 0x%x in Cchannel 0x%x"
				" failed, verb=0x%02x code=0x%02x\n",
				ccgid, cchannelid, verb, rslt);
			return -EIO;
		}

		/* For the configure, word[0] of the command contains only the
		 * verb/cgid. For the query, word[0] of the result contains
		 * only the verb/rslt fields. Skip word[0] in the latter case.
		 */
		word_copy(&d[i][1], &p[1], 15);
	}
	return 0;
}

int qbman_ccgr_query_i_cnt(struct qbman_swp *s, uint32_t ceetmid,
		           uint8_t cchannelid, uint8_t ccgid, uint64_t *i_cnt)
{
	uint32_t *p;
	uint32_t verb, rslt;
	unsigned int i;
	
	*i_cnt = 0;

	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;

	qb_attr_code_encode(&code_ccgr_ccgid, p, ccgid);
	qb_attr_code_encode(&code_ccgr_cchannelid, p, cchannelid);
	qb_attr_code_encode(&code_ccgr_command_type, p, 0);
	qb_attr_code_encode(&code_ceetm_id, p, ceetmid);

	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_CCGR_QUERY);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	/* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	BUG_ON(verb != QBMAN_MC_CCGR_QUERY);

	/* Determine success or failure */
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Query of CCGID 0x%x in Cchannel 0x%x"
			" failed, verb=0x%02x code=0x%02x\n",
			ccgid, cchannelid, verb, rslt);
		return -EIO;
	}
	if(i_cnt)
		*i_cnt = qb_attr_code_decode_64(&code_ccgr_i_cnt_lo,
						(uint64_t *)p) & 0xFFFFFFFFFF;
	return 0;
}

int qbman_ccgr_reset(struct qbman_swp *s, uint32_t ceetmid, uint8_t cchannelid,
                     uint8_t ccgid)
{
	uint32_t *p;
	uint32_t verb, rslt;
	unsigned int i;

	for (i = 0; i < 2; i++) {
		/* Start the management command */
		p = qbman_swp_mc_start(s);
		if (!p)
			return -EBUSY;
		memset(&p[2], 0, sizeof(uint32_t) * 10);
		qb_attr_code_encode(&code_cgr_we_mask, p, 0xFFFF);
		qb_attr_code_encode(&code_ccgr_ccgid, p, ccgid);
		qb_attr_code_encode(&code_ccgr_cchannelid, p,
				    cchannelid);
		qb_attr_code_encode(&code_ccgr_command_type, p, i);
		qb_attr_code_encode(&code_ceetm_id, p, ceetmid);

		/* Complete the management command */
		p = qbman_swp_mc_complete(s, p,
				 p[0] | QBMAN_MC_CCGR_CONFIGURE);
		if (!p) {
			pr_err("SWP %d is not responding\n", s->desc.idx);
			return -EIO;
		}

		/* Decode the outcome */
		verb = qb_attr_code_decode(&code_generic_verb, p);
		rslt = qb_attr_code_decode(&code_generic_rslt, p);
		BUG_ON(verb != QBMAN_MC_CCGR_CONFIGURE);

		/* Determine success or failure */
		if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
			pr_err("Reset of CCGID 0x%x in Cchannel"
				" 0x%x failed, verb ="
				" 0x%02x, code=0x%02x\n",
				ccgid, cchannelid, verb, rslt);
			return -EIO;
		}
	}
	/* Clear the statistics */
	qbman_ceetm_statistics_query(s, ceetmid,
				(uint16_t)((cchannelid << 4) | ccgid),
				query_and_clear_reject_statistics, NULL, NULL);

	return 0;
}

/* ----------- */
/* CQ Peek/pop */
/* ----------- */

static struct qb_attr_code code_peekpop_stat_retry = QB_CODE(0, 18, 1);
static struct qb_attr_code code_peekpop_stat_empty = QB_CODE(0, 17, 1);
static struct qb_attr_code code_peekpop_stat_frame = QB_CODE(0, 16, 1);
static struct qb_attr_code code_peekpop_dctidx = QB_CODE(3, 16, 16);

int qbman_cq_pop(struct qbman_swp *s, uint32_t ceetmid, uint16_t cqid,
		 struct qbman_fd *fd, uint16_t *dctidx, int *last_frame)
{
	uint32_t *p;
	uint32_t verb, rslt;
	int stat_retry, stat_empty, stat_frame;

	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;
	qb_attr_code_encode(&code_ceetm_id, p, ceetmid);
	qb_attr_code_encode(&code_ceetm_cqid, p, cqid);
	qb_attr_code_encode(&code_ceetm_peekpop, p, QBMAN_MC_PEEKPOP_POP);
	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_CQ_PEEKPOP);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	/* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	stat_retry = (int)qb_attr_code_decode(&code_peekpop_stat_retry, p);
	stat_empty = (int)qb_attr_code_decode(&code_peekpop_stat_empty, p);
	stat_frame = (int)qb_attr_code_decode(&code_peekpop_stat_frame, p);
	BUG_ON(verb != QBMAN_MC_CQ_PEEKPOP);
	BUG_ON(!stat_frame && !stat_empty);

	/* Determine success or failure */
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Configure of CQID 0x%x failed, code=0x%02x\n",
		       cqid, rslt);
		return -EIO;
	}

	/* If "retry", nothing else is worth looking at */
	if (stat_retry)
		return -EAGAIN;

	/* If !"frame", there was nothing to pop */
	if (!stat_frame)
		return -ENAVAIL;

	/* Return frame and settings */
	if (dctidx)
		*dctidx = (uint16_t)qb_attr_code_decode(&code_peekpop_dctidx, p);
	if (last_frame)
		*last_frame = stat_empty;
	word_copy(fd, &p[8], sizeof(*fd) >> 2);
	return 0;
}

/* ---------- */
/* XSFDR read */
/* ---------- */
static struct qb_attr_code code_ceetm_xsfdr = QB_CODE(1, 16, 16);
int qbman_xsfdr_read(struct qbman_swp *s, uint32_t ceetmid, uint16_t xsfdr,
			struct qbman_fd *fd, uint16_t *dctidx)
{
	uint32_t *p;
	uint32_t verb, rslt;
	int stat_retry;

	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;
	qb_attr_code_encode(&code_ceetm_id, p, ceetmid);
	qb_attr_code_encode(&code_ceetm_xsfdr, p, xsfdr);
	qb_attr_code_encode(&code_ceetm_peekpop, p, QBMAN_MC_PEEKPOP_READ);
	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_CQ_PEEKPOP);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	/* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	stat_retry = (int)qb_attr_code_decode(&code_peekpop_stat_retry, p);
	BUG_ON(verb != QBMAN_MC_CQ_PEEKPOP);

	/* Determine success or failure */
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("XSFDR Read of XSFDR 0x%x failed, code=0x%02x\n",
			xsfdr, rslt);
		return -EIO;
	}

	/* If "retry", nothing else is worth looking at */
	if (stat_retry)
		return -EAGAIN;

	/* Return frame and settings */
	if (dctidx)
		*dctidx = (uint16_t)qb_attr_code_decode(&code_peekpop_dctidx, p);
	word_copy(fd, &p[8], sizeof(*fd) >> 2);
	return 0;
}

/* ---------- */
/* Statistics */
/* ---------- */
static struct qb_attr_code code_statistics_query_ct = QB_CODE(1, 8, 3);
static struct qb_attr_code code_statistics_frm_cnt_lo = QB_CODE(4, 0, 32);
static struct qb_attr_code code_statistics_byte_cnt_lo = QB_CODE(6, 0, 32);

int qbman_ceetm_statistics_query(struct qbman_swp *s, uint32_t ceetmid,
				uint16_t cid, enum statistics_query_ct_e ct,
				uint64_t *frm_cnt, uint64_t *byte_cnt)
{
	uint32_t *p;
	uint32_t verb, rslt;

	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;
	qb_attr_code_encode(&code_ceetm_id, p, ceetmid);
	qb_attr_code_encode(&code_ceetm_cqid, p, cid);
	qb_attr_code_encode(&code_statistics_query_ct, p, ct);
	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_STATISTICS_QUERY);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	/* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	BUG_ON(verb != QBMAN_MC_STATISTICS_QUERY);

	/* Determine success or failure */
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Query of CEETM statistics failed,"
			"verb=0x%02x code=0x%02x\n", verb, rslt);
		return -EIO;
	}
	if (frm_cnt)
		*frm_cnt = qb_attr_code_decode_64(&code_statistics_frm_cnt_lo,
						(uint64_t *)p);
	if (byte_cnt)
		*byte_cnt = qb_attr_code_decode_64(&code_statistics_byte_cnt_lo,
						(uint64_t *)p);
	return 0;
}

	/*****************/
	/* QD management */
	/*****************/

static struct qb_attr_code code_qd_qdid = QB_CODE(1, 0, 16);
static struct qb_attr_code code_qd_qprid0 = QB_CODE(4, 0, 16);

int qbman_qd_configure(struct qbman_swp *s, uint16_t qdid, const uint16_t *qprid_array)
{
	uint32_t *p;
	uint32_t verb, rslt;
	struct qb_attr_code qprid = code_qd_qprid0;
	int i = 0;

	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;
	qb_attr_code_encode(&code_ceetm_cid, p, QBMAN_MC_QD_CID_QDR);
	qb_attr_code_encode(&code_qd_qdid, p, qdid);
	qb_attr_code_for_ms(&qprid, 16, i < 16) {
		qb_attr_code_encode(&qprid, p, qprid_array[i++]);
	}

	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_QD_CONFIGURE);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	BUG_ON(verb != QBMAN_MC_QD_CONFIGURE);

	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Configure of QD 0x%x failed, code=0x%02x\n",
		       qdid, rslt);
		return -EIO;
	}
	return 0;
}

//#ifdef MC_CLI
int qbman_qd_query(struct qbman_swp *s, uint16_t qdid, uint16_t *qprid_array)
{
	uint32_t *p;
	uint32_t verb, rslt;
	struct qb_attr_code qprid = code_qd_qprid0;
	int i = 0;

	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;
	qb_attr_code_encode(&code_ceetm_cid, p, QBMAN_MC_QD_CID_Q_QDR);
	qb_attr_code_encode(&code_qd_qdid, p, qdid);

	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_QD_CONFIGURE);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	BUG_ON(verb != QBMAN_MC_QD_CONFIGURE);

	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Configure of QD 0x%x failed, code=0x%02x\n",
		       qdid, rslt);
		return -EIO;
	}
	qb_attr_code_for_ms(&qprid, 16, i < 16) {
		qprid_array[i++] = qb_attr_code_decode(&qprid, p);
	}
	return 0;
}
//#endif

	/******************/
	/* QPR management */
	/******************/

/* The QPR_DS (distribution size) values supported by hardware are of the form
 * m*(2^n), from 1 to 1024, where m is 1, 3, or 7. (NB: 5 is not included!) It's
 * easier to think of 4, 6, and 7 when numerical order is preferred, and convert
 * 6 and 4 mantissas down to 3 and 1 respectively once you're done.
 */
static uint32_t qpr_ds_m[3] = { 4, 6, 7};
#define QPR_DS(m,e) (((e) < 0) ? (m) >> -(e) : (m) << (e))
static uint32_t qpr_ds[] = {
	QPR_DS(4, -2), /* 1 */
	QPR_DS(4, -1), /* 2 */
	QPR_DS(6, -1), /* 3 */
	QPR_DS(4, 0),  /* 4 */
	QPR_DS(6, 0),  /* 6 */
	QPR_DS(7, 0),  /* 7 */
	QPR_DS(4, 1),  /* 8 */
	QPR_DS(6, 1),  /* 12 */
	QPR_DS(7, 1),  /* 14 */
	QPR_DS(4, 2),  /* 16 */
	QPR_DS(6, 2),  /* 24 */
	QPR_DS(7, 2),  /* 28 */
	QPR_DS(4, 3),  /* 32 */
	QPR_DS(6, 3),  /* 48 */
	QPR_DS(7, 3),  /* 56 */
	QPR_DS(4, 4),  /* 64 */
	QPR_DS(6, 4),  /* 96 */
	QPR_DS(7, 4), /* 112 */
	QPR_DS(4, 5), /* 128 */
	QPR_DS(6, 5), /* 192 */
	QPR_DS(7, 5), /* 224 */
	QPR_DS(4, 6), /* 256 */
	QPR_DS(6, 6), /* 384 */
	QPR_DS(7, 6), /* 448 */
	QPR_DS(4, 7), /* 512 */
	QPR_DS(6, 7), /* 768 */
	QPR_DS(7, 7), /* 896 */
	QPR_DS(4, 8), /* 1024 */
	0
};

uint32_t qbman_qpr_get_valid_num(uint32_t fqid_num, int rounding)
{
	uint32_t fnd = 0;
	if (!fqid_num)
		return 1;
	do {
		if (fnd && !qpr_ds[fnd])
			/* Gone past the end */
			return qpr_ds[fnd - 1];
		if (qpr_ds[fnd] == fqid_num)
			/* Exact match */
			return fqid_num;
		if (qpr_ds[fnd] > fqid_num) {
			/* We have upper and lower approximations, pick one */
			if (rounding > 0)
				return qpr_ds[fnd];
			if (fnd && (rounding < 0))
				return qpr_ds[fnd - 1];
			if (fnd && ((fqid_num - qpr_ds[fnd - 1]) < (qpr_ds[fnd] - fqid_num)))
				return qpr_ds[fnd - 1];
			return qpr_ds[fnd];
		}
		/* Keep looking */
		fnd++;
	} while (1);
}

static struct qb_attr_code code_qpr_qprid = QB_CODE(1, 0, 16);
static struct qb_attr_code code_qpr_fqid_base = QB_CODE(2, 0, 24);
static struct qb_attr_code code_qpr_fqid_ds = QB_CODE(2, 24, 8);
static struct qb_attr_code code_qpr_cgid_ceetm = QB_CODE(3, 23, 1);
static struct qb_attr_code code_qpr_cgid_cgid = QB_CODE(3, 0, 16);
static struct qb_attr_code code_qpr_cgid_dcpid = QB_CODE(3, 16, 4);
static struct qb_attr_code code_qpr_cgid_iid = QB_CODE(3, 14, 2);
static struct qb_attr_code code_qpr_cgid_ccgid = QB_CODE(3, 0, 14);

int qbman_qpr_configure(struct qbman_swp *s, uint16_t qprid, uint32_t fqid_base,
			uint32_t fqid_num, uint32_t cgid)
{
	uint32_t *p;
	uint32_t verb, rslt;
	uint32_t ds_idx = 0;

	/* Check that fqid_num is a valid DS field */
	while (qpr_ds[ds_idx]) {
		if (qpr_ds[ds_idx] == fqid_num)
			break;
		ds_idx++;
	}
	if (!qpr_ds[ds_idx])
		return -EINVAL;

	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;
	qb_attr_code_encode(&code_ceetm_cid, p, QBMAN_MC_QD_CID_QPR);
	qb_attr_code_encode(&code_qpr_qprid, p, qprid);
	qb_attr_code_encode(&code_qpr_fqid_base, p, fqid_base);
	qb_attr_code_encode(&code_qpr_fqid_ds, p, ds_idx);
	if ((fqid_base >> 20) != 0xf) {
		/* Regular FQID */
		qb_attr_code_encode(&code_qpr_cgid_ceetm, p, 0);
		qb_attr_code_encode(&code_qpr_cgid_cgid, p, cgid);
	} else {
		/* CEETM */
		uint8_t dcpid, instanceid;
		uint16_t foo; /* ignored */
		qbman_lfqid_decompose(fqid_base, &dcpid, &instanceid, &foo);
		qb_attr_code_encode(&code_qpr_cgid_ceetm, p, 1);
		qb_attr_code_encode(&code_qpr_cgid_dcpid, p, dcpid);
		qb_attr_code_encode(&code_qpr_cgid_iid, p, instanceid);
		qb_attr_code_encode(&code_qpr_cgid_ccgid, p, cgid);
	}

	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_QD_CONFIGURE);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	BUG_ON(verb != QBMAN_MC_QD_CONFIGURE);

	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Configure of QPR 0x%x failed, code=0x%02x\n",
		       qprid, rslt);
		return -EIO;
	}
	return 0;
}

//#ifdef MC_CLI
int qbman_qpr_query(struct qbman_swp *s, uint16_t qprid, uint32_t *fqid_base,
			uint32_t *fqid_num, uint32_t *cgid)
{
	uint32_t *p;
	uint32_t verb, rslt;

	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;
	qb_attr_code_encode(&code_ceetm_cid, p, QBMAN_MC_QD_CID_Q_QPR);
	qb_attr_code_encode(&code_qpr_qprid, p, qprid);

	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_QD_CONFIGURE);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	BUG_ON(verb != QBMAN_MC_QD_CONFIGURE);

	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Configure of QPR 0x%x failed, code=0x%02x\n",
		       qprid, rslt);
		return -EIO;
	}
	*fqid_base = qb_attr_code_decode(&code_qpr_fqid_base, p);
	*fqid_num = qb_attr_code_decode(&code_qpr_fqid_ds, p);
    *cgid = 0; // for now ignore

	return 0;
}
//#endif

	/********************************/
	/* Order restoration management */
	/********************************/
static struct qb_attr_code code_opr_cmr_cid = QB_CODE(0, 16, 8);
static struct qb_attr_code code_opr_cmr_oprid = QB_CODE(1, 0, 12);
static struct qb_attr_code code_opr_cmr_en = QB_CODE(1, 16, 1);
static struct qb_attr_code code_opr_cmr_oprc = QB_CODE(1, 24, 8);
// oprc sub code
static struct qb_attr_code code_opr_cmr_oprrws = QB_CODE(1, 24, 3);
static struct qb_attr_code code_opr_cmr_oa = QB_CODE(1,24+3, 1);
static struct qb_attr_code code_opr_cmr_olws = QB_CODE(1, 24+4, 2);
static struct qb_attr_code code_opr_cmr_oeane = QB_CODE(1, 24+6, 1);
static struct qb_attr_code code_opr_cmr_oloe = QB_CODE(1, 24+7, 1);
//
static struct qb_attr_code code_opr_cmr_voprid = QB_CODE(2, 0, 12);

int qbman_opr_configure(struct qbman_swp *s, uint16_t oprid,
            uint32_t en, uint32_t oprc, uint16_t voprid)
{
	uint32_t *p;
	uint32_t verb, rslt;
    /* Start the management command */
	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;
    /* Encode the caller-provided attributes */
    qb_attr_code_encode(&code_opr_cmr_cid, p, 0);
    qb_attr_code_encode(&code_opr_cmr_oprid, p, oprid);
    qb_attr_code_encode(&code_opr_cmr_en, p, en);
    qb_attr_code_encode(&code_opr_cmr_oprc, p, oprc);
    qb_attr_code_encode(&code_opr_cmr_voprid, p, voprid);
    /* Complete the management command */
    p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_OPR_CONFIGURE);
    if (!p) {
	    pr_err("SWP %d is not responding\n", s->desc.idx);
	    return -EIO;
    }
    /* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
    BUG_ON(verb != QBMAN_MC_OPR_CONFIGURE);
    /* Determine success or failure */
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Configure OPRID 0x%x failed, code=0x%02x\n", oprid, rslt);
		return -EIO;
	}
    return 0;
}

int qbman_opr_retire(struct qbman_swp *s, uint16_t oprid)
{
	uint32_t *p;
	uint32_t verb, rslt;
    /* Start the management command */
	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;
    /* Encode the caller-provided attributes */
    qb_attr_code_encode(&code_opr_cmr_cid, p, 2);
    qb_attr_code_encode(&code_opr_cmr_oprid, p, oprid);
    /* Complete the management command */
    p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_OPR_CONFIGURE);
    if (!p) {
	    pr_err("SWP %d is not responding\n", s->desc.idx);
	    return -EIO;
    }
    /* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
    BUG_ON(verb != QBMAN_MC_OPR_CONFIGURE);
    /* Determine success or failure */
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Retire OPRID 0x%x failed, code=0x%02x\n",
								oprid, rslt);
		return -EIO;
	}
    return 0;
}

static struct qb_attr_code code_opr_qry_rip = QB_CODE(0, 24, 1);
static struct qb_attr_code code_opr_qry_en = QB_CODE(1, 16, 1);
static struct qb_attr_code code_opr_qry_orpc = QB_CODE(1, 24, 8);
static struct qb_attr_code code_opr_qry_voprid = QB_CODE(2, 0, 12);
static struct qb_attr_code code_opr_qry_ea_hptr = QB_CODE(4, 0, 16);
static struct qb_attr_code code_opr_qry_ea_tptr = QB_CODE(5, 0, 16);
static struct qb_attr_code code_opr_qry_nesn = QB_CODE(6, 0, 14);
static struct qb_attr_code code_opr_qry_ea_hseq = QB_CODE(6, 16, 14);
static struct qb_attr_code code_opr_qry_ea_hseq_nlis = QB_CODE(6, 16+14, 1);
static struct qb_attr_code code_opr_qry_ea_tseq = QB_CODE(7, 0, 14);
static struct qb_attr_code code_opr_qry_ea_tseq_nlis = QB_CODE(7, 0+14, 1);
static struct qb_attr_code code_opr_qry_ndsn = QB_CODE(7, 16, 14);


void qbman_qpr_attr_get_rip(struct qbman_attr *d, uint32_t *rip)
{
	uint32_t *p = ATTR32(d);
	*rip = qb_attr_code_decode(&code_opr_qry_rip, p);
}
void qbman_qpr_attr_get_en(struct qbman_attr *d, uint32_t *en)
{
	uint32_t *p = ATTR32(d);
	*en = qb_attr_code_decode(&code_opr_qry_en, p);
}
void qbman_qpr_attr_get_orpc(struct qbman_attr *d, uint32_t *orpc)
{
	uint32_t *p = ATTR32(d);
	*orpc = qb_attr_code_decode(&code_opr_qry_orpc, p);
}
void qbman_qpr_attr_get_voprid(struct qbman_attr *d, uint32_t *voprid)
{
	uint32_t *p = ATTR32(d);
	*voprid = qb_attr_code_decode(&code_opr_qry_voprid, p);
}
void qbman_qpr_attr_get_nesn(struct qbman_attr *d, uint32_t *nesn)
{
	uint32_t *p = ATTR32(d);
	*nesn = qb_attr_code_decode(&code_opr_qry_nesn, p);
}
void qbman_qpr_attr_get_ea_hseq(struct qbman_attr *d, uint32_t *ea_hseq)
{
	uint32_t *p = ATTR32(d);
	*ea_hseq = qb_attr_code_decode(&code_opr_qry_ea_hseq, p);
}
void qbman_qpr_attr_get_ea_hseq_nlis(struct qbman_attr *d, uint32_t *ea_hseq_nlis)
{
	uint32_t *p = ATTR32(d);
	*ea_hseq_nlis = qb_attr_code_decode(&code_opr_qry_ea_hseq_nlis, p);
}
void qbman_qpr_attr_get_ea_tseq(struct qbman_attr *d, uint32_t *ea_tseq)
{
	uint32_t *p = ATTR32(d);
	*ea_tseq = qb_attr_code_decode(&code_opr_qry_ea_tseq, p);
}
void qbman_qpr_attr_get_ea_tseq_nlis(struct qbman_attr *d, uint32_t *ea_tseq_nlis)
{
	uint32_t *p = ATTR32(d);
	*ea_tseq_nlis = qb_attr_code_decode(&code_opr_qry_ea_tseq_nlis, p);
}
void qbman_qpr_attr_get_ndsn(struct qbman_attr *d, uint32_t *ndsn)
{
	uint32_t *p = ATTR32(d);
	*ndsn = qb_attr_code_decode(&code_opr_qry_ndsn, p);
}
void qbman_qpr_attr_get_ea_hptr(struct qbman_attr *d, uint32_t *ndsn)
{
	uint32_t *p = ATTR32(d);
	*ndsn = qb_attr_code_decode(&code_opr_qry_ea_hptr, p);
}
void qbman_qpr_attr_get_ea_tptr(struct qbman_attr *d, uint32_t *ndsn)
{
	uint32_t *p = ATTR32(d);
	*ndsn = qb_attr_code_decode(&code_opr_qry_ea_tptr, p);
}

//Decode orpc fields
static struct qb_attr_code code_opr_qry_oprrws = QB_CODE(1, 24, 3);
static struct qb_attr_code code_opr_qry_oa = QB_CODE(1, 24+3, 1);
static struct qb_attr_code code_opr_qry_olws = QB_CODE(1, 24+4, 2);
static struct qb_attr_code code_opr_qry_oeane = QB_CODE(1, 24+6, 1);
static struct qb_attr_code code_opr_qry_oloe = QB_CODE(1, 24+7, 1);

void qbman_qpr_attr_get_oprrws(struct qbman_attr *d, uint32_t *oprrws)
{
	uint32_t *p = ATTR32(d);
	*oprrws = qb_attr_code_decode(&code_opr_qry_oprrws, p);
}
void qbman_qpr_attr_get_oa(struct qbman_attr *d, uint32_t *oa)
{
	uint32_t *p = ATTR32(d);
	*oa = qb_attr_code_decode(&code_opr_qry_oa, p);
}
void qbman_qpr_attr_get_olws(struct qbman_attr *d, uint32_t *olws)
{
	uint32_t *p = ATTR32(d);
	*olws = qb_attr_code_decode(&code_opr_qry_olws, p);
}
void qbman_qpr_attr_get_oeane(struct qbman_attr *d, uint32_t *oeane)
{
	uint32_t *p = ATTR32(d);
	*oeane = qb_attr_code_decode(&code_opr_qry_oeane, p);
}
void qbman_qpr_attr_get_oloe(struct qbman_attr *d, uint32_t *oloe)
{
	uint32_t *p = ATTR32(d);
	*oloe = qb_attr_code_decode(&code_opr_qry_oloe, p);
}

int qbman_opr_query(struct qbman_swp *s, uint16_t oprid, struct qbman_attr *desc)
{
	uint32_t *p;
	uint32_t verb, rslt;
	uint32_t *d = ATTR32(desc);

	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;
    qb_attr_code_encode(&code_opr_cmr_cid, p, 3);
    qb_attr_code_encode(&code_opr_cmr_oprid, p, oprid);
    p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_OPR_CONFIGURE);
    if (!p) {
	    pr_err("SWP %d is not responding\n", s->desc.idx);
	    return -EIO;
    }

	/* Decode the outcome */
	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	BUG_ON(verb != QBMAN_MC_OPR_CONFIGURE);

	/* Determine success or failure */
	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Query of OPRID 0x%x failed, code=0x%02x\n",
		       oprid, rslt);
		return -EIO;
	}
	/* For the configure, word[0] of the command contains only the WE-mask.
	 * For the query, word[0] of the result contains only the verb/rslt
	 * fields. Skip word[0] in the latter case. */
	word_copy(&d[1], &p[1], 31);
	return 0;
}

	/*********************************/
	/* Enqueue replicator management */
	/*********************************/

static struct qb_attr_code code_rr_rrid = QB_CODE(1, 0, 16);
static struct qb_attr_code code_rr_qdid = QB_CODE(1, 16, 16);
static struct qb_attr_code code_rr_next_rrid = QB_CODE(4, 0, 16);
static struct qb_attr_code code_rr_icid = QB_CODE(4, 16, 16);
static struct qb_attr_code code_rr_return_fqid_dcpid = QB_CODE(5, 0, 24);
static struct qb_attr_code code_rr_rd = QB_CODE(5, 24, 8);

int qbman_rr_configure(struct qbman_swp *s, uint16_t rrid, uint16_t qdid,
		       uint16_t next_rrid, uint16_t icid,
		       uint32_t return_fqid_dcpid, uint8_t rd)
{
	uint32_t *p;
	uint32_t verb, rslt;

	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;
	qb_attr_code_encode(&code_ceetm_cid, p, QBMAN_MC_RR_CID_CONFIG);
	qb_attr_code_encode(&code_rr_rrid, p, rrid);
	qb_attr_code_encode(&code_rr_qdid, p, qdid);
	qb_attr_code_encode(&code_rr_next_rrid, p, next_rrid);
	qb_attr_code_encode(&code_rr_icid, p, icid);
	qb_attr_code_encode(&code_rr_return_fqid_dcpid, p, return_fqid_dcpid);
	qb_attr_code_encode(&code_rr_rd, p, rd);

	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_RR_CONFIGURE);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	BUG_ON(verb != QBMAN_MC_RR_CONFIGURE);

	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Configure of RR 0x%x failed, code=0x%02x\n",
		       rrid, rslt);
		return -EIO;
	}
	return 0;
}

int qbman_rr_query(struct qbman_swp *s, uint16_t rrid, uint16_t *qdid,
		   uint16_t *next_rrid, uint16_t *icid,
		   uint32_t *return_fqid_dcpid, uint8_t *rd)
{
	uint32_t *p;
	uint32_t verb, rslt;

	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;
	qb_attr_code_encode(&code_ceetm_cid, p, QBMAN_MC_RR_CID_QUERY);
	qb_attr_code_encode(&code_rr_rrid, p, rrid);

	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_RR_CONFIGURE);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	BUG_ON(verb != QBMAN_MC_RR_CONFIGURE);

	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Configure of RR 0x%x failed, code=0x%02x\n",
		       rrid, rslt);
		return -EIO;
	}
	*qdid = (uint16_t)qb_attr_code_decode(&code_rr_qdid, p);
	*next_rrid = (uint16_t)qb_attr_code_decode(&code_rr_next_rrid, p);
	*icid = (uint16_t)qb_attr_code_decode(&code_rr_icid, p);
	*return_fqid_dcpid = (uint32_t)qb_attr_code_decode(
					&code_rr_return_fqid_dcpid, p);
	if (rd)
		*rd = (uint8_t)qb_attr_code_decode(&code_rr_rd, p);

	return 0;
}

static struct qb_attr_code code_rcr_cnt = QB_CODE(1, 16, 16);
static struct qb_attr_code code_rcr_return_fqid_dcpid = QB_CODE(2, 0, 24);
static struct qb_attr_code code_rcr_rd = QB_CODE(2, 24, 8);
int qbman_rcr_query(struct qbman_swp *s, uint16_t tagid, uint16_t *cnt,
		   uint32_t *return_fqid_dcpid, uint8_t *rd)
{
	uint32_t *p;
	uint32_t verb, rslt;

	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;
	qb_attr_code_encode(&code_ceetm_cid, p, QBMAN_MC_RR_CID_RCR_QUERY);
	qb_attr_code_encode(&code_rr_rrid, p, tagid);

	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_RR_CONFIGURE);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	BUG_ON(verb != QBMAN_MC_RR_CONFIGURE);

	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Query of RCR 0x%x failed, code=0x%02x\n",
			tagid, rslt);
		return -EIO;
	}
	*cnt = (uint16_t)qb_attr_code_decode(&code_rcr_cnt, p);
	*return_fqid_dcpid = (uint32_t)qb_attr_code_decode(
					&code_rcr_return_fqid_dcpid, p);
	*rd = (uint8_t)qb_attr_code_decode(&code_rcr_rd, p);

	return 0;
}

void qbman_rcr_parse_dcpid(uint32_t return_dcpid, uint16_t *icid, int *bdi,
			   uint8_t *dcpid)
{
	*icid = (uint16_t)(return_dcpid & 0x7FFF);
	*bdi = (int)(return_dcpid >> 15) & 0x1;
	*dcpid = (uint8_t)(return_dcpid >> 16) & 0x4;
}

int qbman_rcr_reset(struct qbman_swp *s)
{
	uint32_t *p;
	uint32_t verb, rslt;

	p = qbman_swp_mc_start(s);
	if (!p)
		return -EBUSY;
	qb_attr_code_encode(&code_ceetm_cid, p, QBMAN_MC_RR_CID_RCR_RESET);

	p = qbman_swp_mc_complete(s, p, p[0] | QBMAN_MC_RR_CONFIGURE);
	if (!p) {
		pr_err("SWP %d is not responding\n", s->desc.idx);
		return -EIO;
	}

	verb = qb_attr_code_decode(&code_generic_verb, p);
	rslt = qb_attr_code_decode(&code_generic_rslt, p);
	BUG_ON(verb != QBMAN_MC_RR_CONFIGURE);

	if (unlikely(rslt != QBMAN_MC_RSLT_OK)) {
		pr_err("Reset RCR failed, code=0x%02x\n", rslt);
		return -EIO;
	}
	return 0;
}

/*******************/
/* Parsing REL_MSG */
/*******************/

static struct qb_attr_code code_rel_verb = QB_CODE(0, 0, 7);
static struct qb_attr_code code_rel_tok = QB_CODE(1, 24, 8);
static struct qb_attr_code code_rel_fqid = QB_CODE(2, 0, 24);
static struct qb_attr_code code_rel_frm_cnt = QB_CODE(5, 0, 24);
static struct qb_attr_code code_rel_fqd_ctx_lo = QB_CODE(6, 0, 32);
static struct qb_attr_code code_rel_verb_rm = QB_CODE(8, 0, 8);
static struct qb_attr_code code_rel_ec = QB_CODE(8, 8, 5);
static struct qb_attr_code code_rel_ec_me = QB_CODE(8, 15, 1);
static struct qb_attr_code code_rel_portal = QB_CODE(8, 16, 10);
static struct qb_attr_code code_rel_portal_type = QB_CODE(8, 31, 1);
static struct qb_attr_code code_rel_icid = QB_CODE(9, 0, 15);
static struct qb_attr_code code_rel_bdi = QB_CODE(9, 16, 1);
static struct qb_attr_code code_rel_vt = QB_CODE(9, 24, 4);
static struct qb_attr_code code_rel_vrid1 = QB_CODE(10, 0, 24);
static struct qb_attr_code code_rel_cv = QB_CODE(10, 24, 8);
static struct qb_attr_code code_rel_rrid1 = QB_CODE(11, 0, 24);
static struct qb_attr_code code_rel_cl = QB_CODE(11, 24, 2);
static struct qb_attr_code code_rel_vrid2 = QB_CODE(12, 0, 24);
static struct qb_attr_code code_rel_rrid2 = QB_CODE(13, 0, 24);

int qbman_result_is_rel_msg(const struct qbman_result *dq)
{
	const uint32_t *p = qb_cl(dq);
	uint32_t response_verb = qb_attr_code_decode(&code_rel_verb, p);
	return (response_verb == QBMAN_RESULT_REL_MSG);
}

/* These APIs assume qbman_result_is_rel_msg() is true */
uint32_t qbman_result_rel_msg_fqid(const struct qbman_result *dq)
{
	const uint32_t *p = qb_cl(dq);
	return qb_attr_code_decode(&code_rel_fqid, p);
}

uint32_t qbman_result_rel_msg_frame_count(const struct qbman_result *dq)
{
	const uint32_t *p = qb_cl(dq);
	return qb_attr_code_decode(&code_rel_frm_cnt, p);
}

uint64_t qbman_result_rel_msg_fqd_ctx(const struct qbman_result *dq)
{
	const uint64_t *p = (uint64_t *)qb_cl(dq);
	return qb_attr_code_decode_64(&code_rel_fqd_ctx_lo, p);
}

enum qbman_rerr_code_e qbman_result_rel_msg_error_code(
					const struct qbman_result *dq)
{
	const uint32_t *p = qb_cl(dq);
	return (enum qbman_rerr_code_e)qb_attr_code_decode(&code_rel_ec, p);
}

int qbman_result_rel_msg_error_code_me(const struct qbman_result *dq)
{
	const uint32_t *p = qb_cl(dq);
	return !!qb_attr_code_decode(&code_rel_ec_me, p);
}

uint16_t qbman_result_rel_msg_portal_idx(const struct qbman_result *dq)
{
	const uint32_t *p = qb_cl(dq);
	return (uint16_t)qb_attr_code_decode(&code_rel_portal, p);
}

int qbman_result_rel_msg_is_DCP(const struct qbman_result *dq)
{
	const uint32_t *p = qb_cl(dq);
	return (int)!!qb_attr_code_decode(&code_rel_portal_type, p);
}

uint16_t qbman_result_rel_msg_icid(const struct qbman_result *dq)
{
	const uint32_t *p = qb_cl(dq);
	return (uint16_t)qb_attr_code_decode(&code_rel_icid, p);
}

int qbman_result_rel_msg_bdi(const struct qbman_result *dq)
{
	const uint32_t *p = qb_cl(dq);
	return !!qb_attr_code_decode(&code_rel_bdi, p);
}

enum qbman_auth_type_e qbman_result_rel_msg_vt(const struct qbman_result *dq)
{
	const uint32_t *p = qb_cl(dq);
	return (enum qbman_auth_type_e)qb_attr_code_decode(&code_rel_vt, p);
}

uint32_t qbman_result_rel_msg_vrid1(const struct qbman_result *dq)
{
	const uint32_t *p = qb_cl(dq);
	return qb_attr_code_decode(&code_rel_vrid1, p);
}

uint32_t qbman_result_rel_msg_rrid1(const struct qbman_result *dq)
{
	const uint32_t *p = qb_cl(dq);
	return qb_attr_code_decode(&code_rel_rrid1, p);
}

uint32_t qbman_result_rel_msg_vrid2(const struct qbman_result *dq)
{
	const uint32_t *p = qb_cl(dq);
	return qb_attr_code_decode(&code_rel_vrid2, p);
}

uint32_t qbman_result_rel_msg_rrid2(const struct qbman_result *dq)
{
	const uint32_t *p = qb_cl(dq);
	return qb_attr_code_decode(&code_rel_rrid2, p);
}

uint8_t qbman_result_rel_msg_command_verb(const struct qbman_result *dq)
{
	const uint32_t *p = qb_cl(dq);
	return (uint8_t)qb_attr_code_decode(&code_rel_cv, p);
}

enum qbman_command_location_t qbman_result_rel_msg_cl(
					const struct qbman_result *dq)
{
	const uint32_t *p = qb_cl(dq);
	return (enum qbman_command_location_t)qb_attr_code_decode(&code_rel_cl,
                                                                 p);
}

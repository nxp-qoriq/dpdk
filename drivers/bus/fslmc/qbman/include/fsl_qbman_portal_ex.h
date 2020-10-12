/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 NXP
 */

#ifndef _FSL_QBMAN_PORTAL_EX_H
#define _FSL_QBMAN_PORTAL_EX_H

#include "fsl_qbman_portal.h"

/***********************************************/
/* qbman_swp - extended portal usage (MC only) */
/***********************************************/

/* Table of contents, to help find the section you're looking for;
 * - Composite values
 * - Authorisation table management
 * - Frame queue (FQ) management
 *     - FQ descriptor en/decoding
 *     - FQ state decoding
 *     - FQ mgmt portal interactions
 * - Buffer pool (BP) management
 *     - BP mgmt portal interactions
 *     - BP attributes
 *     - BP info
 * - Congestion group record (CGR) management
 * - Customer-edge egress traffic management (CEETM)
 *     - Class queue (CQ) configuration
 *       - CQ configuration
 *       - CQ query
 *     - Logical frame queue (LFQ) configuration
 *     - Dequeue context (DCT) configuration
 *     - Class scheduler configuration
 *     - Channel configuration
 *     - Sub-portal configuration
 *     - Shaper configuration
 *     - LNI configuration (traffic class flow control)
 *     - Class congestion group record (CCGR) configuration
 *     - CQ Peek/pop
 *     - XSFDR read
 *     - Statistics
 * - Queuing destination (QD) management
 * - Queuing proxy record (QPR) management
 * - Order restoration management  <-------------------------- TBD
 * - Enqueue replicator management
 */

	/********************/
	/* Composite values */
	/********************/

/* Some IDs have a composite nature, in that they need to be converted back and
 * forth between the composite form and the individual component values.
 */

/* "ceetmid" identifies an instance of CEETM logic in the silicon. Only some
 * DCPs (Direct Connect Portals) have these, and they may have more than one. So
 * "ceetmid" is a composite of "dcpid" and "instanceid". The user will
 * ultimately obtain a "ceetmid" by identifying the DCP they are dealing with,
 * and which instance within that it wishes to deal with. Nearly all CEETM
 * commands take a "ceetmid" as a leading parameter.
 */
uint32_t qbman_ceetmid_compose(uint8_t dcpid, uint8_t instanceid);
void qbman_ceetmid_decompose(uint32_t ceetmid, uint8_t *dcpid, uint8_t *instanceid);

/* The one notable exception to the last statement (that most commands use a
 * "ceetmid" parameter) is the LFQ (Logical Frame Queue) configuration. This
 * exception is due to the fact that users will not refer to LFQ resources
 * relative to this or that CEETM instance, but will refer to them absolutely
 * using a composite value that includes full identification of the CEETM
 * instance, but with an encoding that is unrelated to the "ceetmid" encoding
 * used in other commands.
 */
uint32_t qbman_lfqid_compose(uint8_t dcpid, uint8_t instanceid, uint16_t lfqmt_idx);
void qbman_lfqid_decompose(uint32_t lfqid, uint8_t *dcpid, uint8_t *instanceid, uint16_t *lfqmtidx);

/* If the caller has "ceetmid" and doesn't want to take the intermediate step of
 * decomposing it before composing a "lfqid", these variants take care of it.
 */
uint32_t qbman_lfqid_compose_ex(uint32_t ceetmid, uint16_t lfqmt_idx);
void qbman_lfqid_decompose_ex(uint32_t lfqid, uint32_t *ceetmid, uint16_t *lfqmtidx);

	/********************/
	/* Common strucutre */
	/********************/
/* A "QBMan attributer" is the attributes struct to present the specific QBMan
 * hareware features such as FQD, CGR, BP, CEETM scheduler etc. It can be used
 * to present the programmable fields in the configure commands, or the
 * attributes/states in the query commands.
 */
struct qbman_attr {
	uint32_t dont_manipulate_directly[40];
};

	/**********************************/
	/* Authorisation table management */
	/**********************************/

enum qbman_auth_type_e {
	qbman_auth_type_fqid,
	qbman_auth_type_qdid,
	qbman_auth_type_bpid,
	qbman_auth_type_channel,
	qbman_auth_type_cgid,
	qbman_auth_type_orpid,
	qbman_auth_type_fqid_xctl,
	qbman_valid_type_rplid_fqid,
	qbman_valid_type_bdi_no_auth
};
#define QBMAN_AUTH_SWP 0x1 /* Authorise for SoftWare Portal (GPP) */
#define QBMAN_AUTH_DCP 0x2 /* Authorise for Direct-Connect Portal (hardware) */
#define QBMAN_INVALID_VRID	0xffffffff /* invalid vrid */

#define MAX_CGID_VIRT_ID	256 /* maximum virtual ID that can be generated for congestion groups
									some peripherals (such as wriop) will not work properly when
									a notification message containing CGR id above 256 is received */

/* Add an authorisation table entry, mapping VRID->RRID, for the given type.
 * auth_flags==0 is equivalent to auth_flags==QBMAN_AUTH_SWP|QBMAN_AUTH_DCP. */
int qbman_auth_add(struct qbman_swp *, uint16_t icid, enum qbman_auth_type_e type,
		   uint32_t vrid, uint32_t rrid, unsigned int auth_flags);
/* Like qbman_auth_add, but finds an unused VRID */
int qbman_auth_add_find(struct qbman_swp *, uint16_t icid, enum qbman_auth_type_e type,
			uint32_t *vrid, uint32_t rrid, unsigned int auth_flags);
int qbman_auth_delete(struct qbman_swp *, uint16_t icid, enum qbman_auth_type_e type,
		      uint32_t vrid, unsigned int auth_flags);
/* Query the authorization table to see whether there is a matched entry for
 * given vrid/icid/type 3-tuple, if so, return the rrid and addr.
 */
int qbman_auth_query(struct qbman_swp *s, uint16_t icid,
		     enum qbman_auth_type_e type, uint32_t vrid,
		     uint32_t *rrid, uint16_t *addr,
		     unsigned int auth_flags);
/* Check whether the given rrid has a valid entry in the auth table with the
 * give vrid/icid/type 3 -tuple.
 */
int qbman_auth_is_valid(struct qbman_swp *s, uint16_t icid,
			enum qbman_auth_type_e type, uint32_t vrid,
			uint32_t rrid, unsigned int auth_flags);
/* Read entry in the authorization table with the given addr and type. If the
 * entry is valid(state=1), return the icid/vrid/rrid.
 */
int qbman_auth_read(struct qbman_swp *s,
		    enum qbman_auth_type_e type, uint16_t addr,
		    uint16_t *icid, int *state,
		    uint32_t *vrid, uint32_t *rrid,
		    enum qbman_auth_type_e *rtype,
		    unsigned int auth_flags);
/* Dump the authorization table with the given type and starting addr + size
 * in the table. Only the valid entry will be printed out.
 * This is for debug purpose.
 */
void qbman_auth_dump_table(struct qbman_swp *s,
			   enum qbman_auth_type_e type,
			   unsigned int auth_flags);
/* Compose/decompse the ccgid in the auth table rrid field */
uint32_t qbman_auth_rrid_ccgid_compose(uint8_t dcpid, uint8_t instanceid,
				       uint8_t cchannelid, uint8_t ccgid);
void qbman_auth_rrid_ccgid_decompose(uint32_t rrid, uint8_t *dcpid,
				     uint8_t *instanceid, uint8_t *cchannelid,
				     uint8_t *ccgid);

	/*****************/
	/* FQ management */
	/*****************/

/* Clear the contents of a fq attribute struct */
void qbman_fq_attr_clear(struct qbman_attr *);

/* Certain FQ attributes must be specified at once because the hardware updates
 * them as a group. (Any finer-grained updates require the user to
 * read-modify-write, or "query-modify-configure" to be more accurate.) As such,
 * the division of the "set" APIs capture this. */

/* Set the FQ's control mask */
#define QBMAN_FQCTRL_CGR        0x01 /* FQ is member of a CGR */
#define QBMAN_FQCTRL_TAILDROP   0x02 /* FQ is subject to tail-drop */
#define QBMAN_FQCTRL_STASH      0x04 /* data/context-stashing is enabled */
#define QBMAN_FQCTRL_SFDR       0x08 /* force high-priority SFDR allocation */
#define QBMAN_FQCTRL_HOLDACTIVE 0x10 /* on dequeue, hold active in the portal */
#define QBMAN_FQCTRL_FQDAN      0x20 /* notify and park rather than dequeue */
#define QBMAN_FQCTRL_FQDAN_IRQ  0x40 /* on FQDAN, ignore DQRI throttling */
#define QBMAN_FQCTRL_ODP        0x80 /* enable order-definition point lookup */
void qbman_fq_attr_set_fqctrl(struct qbman_attr *, uint32_t fqctrl_bits);
void qbman_fq_attr_get_fqctrl(struct qbman_attr *, uint32_t *fqctrl_bits);

/* Set the FQ's congestion group (only gets used if FQCTRL_CGR is also set) */
void qbman_fq_attr_set_cgrid(struct qbman_attr *, uint32_t cgrid);
void qbman_fq_attr_get_cgrid(struct qbman_attr *, uint32_t *cgrid);

/* Set the FQ's destination work queue (only gets used if the FQ is scheduled).
 * This implies the channel. (Beware of the WQ namespace, as affected by the
 * distinction between 8-WQ channels and 2-WQ channels.) */
void qbman_fq_attr_set_destwq(struct qbman_attr *, uint32_t destwq);
void qbman_fq_attr_get_destwq(struct qbman_attr *, uint32_t *destwq);

/* Set the FQ's intra-class scheduling credit value. */
void qbman_fq_attr_set_icscred(struct qbman_attr *, uint32_t icscred);
void qbman_fq_attr_get_icscred(struct qbman_attr *, uint32_t *icscred);

/* Set the FQ's tail-drop threshold. NB: this is a composite value, not an
 * integer tail-drop value! See qbman_fq_tdthresh_from_value(). */
void qbman_fq_attr_set_tdthresh(struct qbman_attr *, uint32_t tdthresh);
void qbman_fq_attr_get_tdthresh(struct qbman_attr *, uint32_t *tdthresh);

/* Set the FQ's overhead accounting settings. oa_ics and oa_cgr are booleans,
 * indicating whether to use OAL for intra-class scheduling and congestion group
 * accounting, respectively. 'oa_len' is from -2048 to +2047. */
void qbman_fq_attr_set_oa(struct qbman_attr *,
			  int oa_ics, int oa_cgr, int32_t oa_len);
void qbman_fq_attr_get_oa(struct qbman_attr *,
			  int *oa_ics, int *oa_cgr, int32_t *oa_len);

/* Set the FQ's memory control settings, which are all booleans. bdi bypasses
 * isolation. ff is for DCP dequeue ("FQD_CTX Format"). va specifies whether
 * addresses are virtual or (guest-)physical. ps indicates stashing of PFDRs to
 * CPC. */
void qbman_fq_attr_set_mctl(struct qbman_attr *,
			    int bdi, int ff, int va, int ps, int pps);
void qbman_fq_attr_get_mctl(struct qbman_attr *,
			    int *bdi, int *ff, int *va, int *ps, int *pps);

/* Set/Get the PPS(PFDR Pool Slection) for FQ init command */
void qbman_fq_attr_set_pps(struct qbman_attr *d, uint8_t pps);
void qbman_fq_attr_get_pps(struct qbman_attr *d, uint8_t *pps);

/* Set the FQ's 64-bit FQD_CTX. */
void qbman_fq_attr_set_ctx(struct qbman_attr *, uint32_t hi, uint32_t lo);
void qbman_fq_attr_get_ctx(struct qbman_attr *, uint32_t *hi, uint32_t *lo);

/* Set the FQ's ICID */
void qbman_fq_attr_set_icid(struct qbman_attr *, uint32_t icid, int pl);
void qbman_fq_attr_get_icid(struct qbman_attr *, uint32_t *icid, int *pl);

/* Set the FQ's virtual FQID (which shows up in dequeue results and
 * notifications on isolated portals). */
void qbman_fq_attr_set_vfqid(struct qbman_attr *, uint32_t vfqid);
void qbman_fq_attr_get_vfqid(struct qbman_attr *, uint32_t *vfqid);

/* Set the FQ's enqueue rejection FQID. */
void qbman_fq_attr_set_erfqid(struct qbman_attr *, uint32_t erfqid);
void qbman_fq_attr_get_erfqid(struct qbman_attr *, uint32_t *erfqid);

/* Set the FQ's OPRID/SIZE */
void qbman_fq_attr_set_opridsz(struct qbman_attr *d, uint32_t oprid, int sz);
void qbman_fq_attr_get_opridsz(struct qbman_attr *d, uint32_t *oprid, int *sz);

enum qbman_fq_schedstate_e {
	qbman_fq_schedstate_oos = 0,
	qbman_fq_schedstate_retired,
	qbman_fq_schedstate_tentatively_scheduled,
	qbman_fq_schedstate_truly_scheduled,
	qbman_fq_schedstate_parked,
	qbman_fq_schedstate_held_active,
};

/* Check the FQ's scheduling state */
uint32_t qbman_fq_state_schedstate(const struct qbman_attr *state);
/* Check the FQ's force eligible pending bit */
int qbman_fq_state_force_eligible(const struct qbman_attr *state);
/* Check the FQ's XON/XOFF state, 0: XON, 1: XOFF */
int qbman_fq_state_xoff(const struct qbman_attr *state);
/* Get the FQ's retirement pending bit */
int qbman_fq_state_retirement_pending(const struct qbman_attr *state);
/* Get the FQ's overflow error bit */
int qbman_fq_state_overflow_error(const struct qbman_attr *state);
/* Get the FQ's frame count */
uint32_t qbman_fq_state_frame_count(const struct qbman_attr *state);
/* Get the FQ's byte count */
uint32_t qbman_fq_state_byte_count(const struct qbman_attr *state);

/* FQ mgmt portal interactions */

int qbman_fq_configure(struct qbman_swp *, uint32_t fqid,
		       const struct qbman_attr *desc);
int qbman_fq_query(struct qbman_swp *, uint32_t fqid, struct qbman_attr *desc);
int qbman_fq_query_state(struct qbman_swp *, uint32_t fqid,
			 struct qbman_attr *state);
int qbman_fq_retire_start(struct qbman_swp *, uint32_t fqid,
			  struct qbman_result *result,
			  const uint64_t *fqd_ctx,
			  dma_addr_t result_phys);
int qbman_fq_retire_is_finished(struct qbman_result *result);
int qbman_fq_retire_is_fq_empty(struct qbman_result *result);
int qbman_fq_oos(struct qbman_swp *, uint32_t fqid);


	/**************************/
	/* Buffer pool management */
	/**************************/

enum qbman_bp_state_e {
	qbman_bp_state_avail,	/* 0: free buffers available */
				/* 1: No free buffers available */
	qbman_bp_state_depletion,	/* 0: bp is not depleted */
					/* 1: bp is depleted */
	qbman_bp_state_surplus,	/* 0: bp is not in surplus */
				/* 1: bp is in surplus */
};

/* Clear the contents of a bpool attribute struct */
void qbman_bp_attr_clear(struct qbman_attr *);

/* Set/get buffer pool's BDI field
 * @bdi: bypass DPAA resource isolation, used for BPSCN.
 * @va: virtual address.
 * @wae: write allocate enable, used only for BPSCN.
 */
void qbman_bp_attr_set_bdi(struct qbman_attr *a, int bdi, int va, int wae);
void qbman_bp_attr_get_bdi(struct qbman_attr *a, int *bdi, int *va,
			   int *wae);

/* Set/get buffer pool's SEDET field
 * @swdet: software depletion entry threshold.
 */
void qbman_bp_attr_set_swdet(struct qbman_attr *a, uint32_t swdet);
void qbman_bp_attr_get_swdet(struct qbman_attr *a, uint32_t *swdet);

/* Set/get buffer pool's SWDXT field
 * @swdxt: software depletion exit threshold.
 */
void qbman_bp_attr_set_swdxt(struct qbman_attr *a, uint32_t swdxt);
void qbman_bp_attr_get_swdxt(struct qbman_attr *a, uint32_t *swdxt);

/* Set/get buffer pool's HWDET field
 * @hwdet: hardware depletion entry threshold.
 */
void qbman_bp_attr_set_hwdet(struct qbman_attr *a, uint32_t hwdet);
void qbman_bp_attr_get_hwdet(struct qbman_attr *a, uint32_t *hwdet);

/* Set/get buffer pool's HWDXT field
 * @hwdxt: hardware depletion exit threshold.
 */
void qbman_bp_attr_set_hwdxt(struct qbman_attr *a, uint32_t hwdxt);
void qbman_bp_attr_get_hwdxt(struct qbman_attr *a, uint32_t *hwdxt);

/* Set/get buffer pool's SWSET field
 * @swset: software surplus entry threshold.
 */
void qbman_bp_attr_set_swset(struct qbman_attr *a, uint32_t swset);
void qbman_bp_attr_get_swset(struct qbman_attr *a, uint32_t *swset);

/* Set/get buffer pool's SWSXT field
 * @swsxt: software surplus exit threshold.
 */
void qbman_bp_attr_set_swsxt(struct qbman_attr *a, uint32_t swsxt);
void qbman_bp_attr_get_swsxt(struct qbman_attr *a, uint32_t *swsxt);

/* Set/get buffer pool's VBPID field
 * @vbpid: virtual buffer pool id, valid only in BPSCN to SWP and DCP
 */
void qbman_bp_attr_set_vbpid(struct qbman_attr *a, uint32_t vbpid);
void qbman_bp_attr_get_vbpid(struct qbman_attr *a, uint32_t *vbpid);

/* Set/get buffer pool's ICID field
 * @icid: the isolation context ID
 * @pl: privilege level
 */
void qbman_bp_attr_set_icid(struct qbman_attr *a, uint32_t icid, int pl);
void qbman_bp_attr_get_icid(struct qbman_attr *a, uint32_t *icid, int *pl);

/* Set/get buffer pool's BPSCN_ADDR field
 * @bpscn_addr: bp state change notification addr, must be 16 bytes aligned.
 */
void qbman_bp_attr_set_bpscn_addr(struct qbman_attr *a, uint64_t bpscn_addr);
void qbman_bp_attr_get_bpscn_addr(struct qbman_attr *a,
				  uint64_t *bpscn_addr);

/* Set/get buffer pool's BPSCN_CTX field
 * @bpscn_ctx: bp state change notification context data.
 */
void qbman_bp_attr_set_bpscn_ctx(struct qbman_attr *a, uint64_t bpscn_ctx);
void qbman_bp_attr_get_bpscn_ctx(struct qbman_attr *a, uint64_t *bpscn_ctx);

/* Set/get buffer pool's HW_TARG field
 * @hw_targ: hardware target for BPSCN to DCP portal
 */
void qbman_bp_attr_set_hw_targ(struct qbman_attr *a, uint32_t hw_targ);
void qbman_bp_attr_get_hw_targ(struct qbman_attr *a, uint32_t *hw_targ);

/* Set/get buffer pool's DBE bit
 * @dbe: enable BPSCN debug, send BPSCN to SoC debug controller for this pool.
 */
void qbman_bp_attr_set_dbe(struct qbman_attr *a, int dbe);
void qbman_bp_attr_get_dbe(struct qbman_attr *a, int *dbe);

/* Configure the buffer pool
 * @s: software portal
 * @bpid: the buffer pool id
 * @a: the buffer pool attribute object with which the bp should be configured.
 */
int qbman_bp_configure(struct qbman_swp *s, uint32_t bpid,
			    struct qbman_attr *a);

/* Query the buffer pool
 * @s: software portal
 * @bpid: the buffer pool id
 * @a: the buffer pool info in the query response.
 */
int qbman_bp_query(struct qbman_swp *s, uint32_t bpid, struct qbman_attr *a);

/* Check buffer pool state to see whether the BP has free buffers.
 * Return 1 indicates the BP has free buffers, return 0 indicates the BP
 * doesn't have free buffers.
 */
int qbman_bp_info_has_free_bufs(struct qbman_attr *a);

/* Check the buffer pool state to see whether the buffer is depleted.
 * Return 1 indicates the BP is depleted, return 0 indicates the BP is
 * not depleted.
 */
int qbman_bp_info_is_depleted(struct qbman_attr *a);

/* Check whethhet buffer pool is in suplus.
 * Return 1 indicate the BP is in surpluse, return 0 indicates the BP is
 * not in surplus.
 */
int qbman_bp_info_is_surplus(struct qbman_attr *a);

/* Return the number of free buffers in the buffer pool. */
uint32_t qbman_bp_info_num_free_bufs(struct qbman_attr *a);

/* Return the free list head pointer for the buffer pool */
uint32_t qbman_bp_info_hdptr(struct qbman_attr *a);

/* Return the software depletion threshold crossing account */
uint32_t qbman_bp_info_sdcnt(struct qbman_attr *a);

/* Return the hardware depletion threshold crossing account */
uint32_t qbman_bp_info_hdcnt(struct qbman_attr *a);

/* Return the software surplus threshold crossing account */
uint32_t qbman_bp_info_sscnt(struct qbman_attr *a);

	/******************/
	/* CGR management */
	/******************/
/* Clear the contents of a cgr attribute struct */
void qbman_cgr_attr_clear(struct qbman_attr *);

/* Set CGR mode.
 * @mode: 0-byte count, 1-frame count, 2-memory footprint.
 * @rej_cnt_mode: 0-reject counters count all bytes and frames rejected
 *		  in this CG.
 *		  1-reject counters count all bytes and frames rejected
 *		  with auto-discard.
 */
void qbman_cgr_attr_set_mode(struct qbman_attr *d, uint32_t mode,
			     int rej_cnt_mode);
void qbman_cgr_attr_get_mode(struct qbman_attr *d, uint32_t *mode,
			     int *rej_cnt_mode);
/* Set/get I_CNT write to memory.
 * @icnt_wr_bnd: Set the boundary for instataneous count write to memory,
 * should be power-of-2.
 * @icnt_addr: the memory address where the i_cnt will be written to.
 * @wae: i_cnt writes from this CG will(wae=1) or don't(wae=0) attempt
 *	   to allocate into a cache.
 */
void qbman_cgr_attr_set_icnt_in_memory(struct qbman_attr *d,
				       uint32_t icnt_wr_bnd,
				       uint64_t icnt_addr, int wae);
void qbman_cgr_attr_get_icnt_in_memory(struct qbman_attr *d,
				       uint32_t *icnt_wr_bnd,
				       uint64_t *icnt_addr, int *wae);
/* Get I_CNT write to memory position.
 * @icnt_wr_pos: the instataneous count write to memory position.
 */
void qbman_cgr_attr_get_icnt_wr_pos(struct qbman_attr *d,
				    int *icnt_wr_pos);

/* Set CGR tail drop control.
 * @td_en: enable tail drop
 */
void qbman_cgr_attr_set_td_ctrl(struct qbman_attr *d, int td_en);
void qbman_cgr_attr_get_td_ctrl(struct qbman_attr *d, int *td_en);
/* Set CGR cs_thres field
 * @cs_thres: the congestion state entrance threshold
 */
void qbman_cgr_attr_set_cs_thres(struct qbman_attr *d, uint32_t cs_thres);
void qbman_cgr_attr_get_cs_thres(struct qbman_attr *d, uint32_t *cs_thres);
/* Set CGR cs_thres_x field
 * @cs_thres: the congestion state exit threshold
 */
void qbman_cgr_attr_set_cs_thres_x(struct qbman_attr *d,
				   uint32_t cs_thres_x);
void qbman_cgr_attr_get_cs_thres_x(struct qbman_attr *d,
				   uint32_t *cs_thres_x);
/* Set CGR td_thres field
 * @td_thres: tail drop threshold
 */
void qbman_cgr_attr_set_td_thres(struct qbman_attr *d, uint32_t td_thres);
void qbman_cgr_attr_get_td_thres(struct qbman_attr *d, uint32_t *td_thres);

/* Set/Get CGR CSCN BDI bit
 * @bdi: Bypass Datapath Isolation bit
 */
void qbman_cgr_attr_set_cscn_bdi(struct qbman_attr *d, int bdi);
void qbman_cgr_attr_get_cscn_bdi(struct qbman_attr *d, int *bdi);

/* Set/Get CGR CSCN PL bit
 * @pl: Privilege Level bit
 */
void qbman_cgr_attr_set_cscn_pl(struct qbman_attr *d, int pl);
void qbman_cgr_attr_get_cscn_pl(struct qbman_attr *d, int *pl);

/* Set/get the CSCN setting for the DCP portal
 * @dcp: the DCP portal to which the CSCN is targeting.
 * @enable: enable/disable the cscn to the DCP portal.
 */
void qbman_cgr_attr_set_cscn_tdcp(struct qbman_attr *d, uint32_t dcp,
				  int enable);
void qbman_cgr_attr_get_cscn_tdcp(struct qbman_attr *d, uint32_t dcp,
				  int *enable);
/* Set CSCN wq control.
 * @dcp: the DCP portal index.
 * @enter_en: enable cscn to wq when entering congestion.
 * @exit_en: enable cscn to wq when exiting congestion.
 * @wq_icd: disable wq interrupt coalesing of DQRI interrupt for this cscn.
 */
void qbman_cgr_attr_set_cscn_wq_ctrl(struct qbman_attr *d, int enter_en,
				     int exit_en, int wq_icd);
void qbman_cgr_attr_get_cscn_wq_ctrl(struct qbman_attr *d, int *enter_en,
				     int *exit_en, int *wq_icd);
/* Set CGR cscn_wqid
 * @cscn_wqid: CSCN WQ id
 */
void qbman_cgr_attr_set_cscn_wqid(struct qbman_attr *d, uint32_t cscn_wqid);
void qbman_cgr_attr_get_cscn_wqid(struct qbman_attr *d,
				  uint32_t *cscn_wqid);
/* Set CGR vcgid
 * @cscn_vcgid: cscn virtual congestion groupd id
 * @bdi: set cscn bypass DAPP resource isolation.
 */
void qbman_cgr_attr_set_cscn_vcgid(struct qbman_attr *d,
				   uint32_t cscn_vcgid, int bdi);
void qbman_cgr_attr_get_cscn_vcgid(struct qbman_attr *d,
				   uint32_t *cscn_vcgid, int *bdi);
/* Set CGR AMQ
 * @icid: cscn isolation context id
 * @pl: contestion group write privilege level, 0 - the write will authorized
 * and translated by iommu, 1 - the iommu translateion is bypassed.
 * @va: CG write virtual address, 0 = cscn_addr is a physical address.
 *	va = 1 and pl = 0, the cscn is a virtual address.
 */
void qbman_cgr_attr_set_cg_icid(struct qbman_attr *d, uint32_t icid,
				int pl, int va);
void qbman_cgr_attr_get_cg_icid(struct qbman_attr *d, uint32_t *icid,
				int *pl, int *va);
/* Set/get CSCN in memory
 * @enter_en: enable cscn to be written to memory while entering congestion.
 * @exit_en: enable cscn to be written to memory while exiting congestion.
 * @cscn_addr: the memory address where the cscn will be written to.
 * @wae: cscn writes from this CG will(wae=1) or don't(wae=0) attempt
 *	 to allocate into a cache.
 */
void qbman_cgr_attr_set_cscn_in_memory(struct qbman_attr *d,
				       int enter_en, int exit_en,
				       uint64_t cscn_addr, int wae);
void qbman_cgr_attr_get_cscn_in_memory(struct qbman_attr *d,
				       int *enter_en, int *exit_en,
				       uint64_t *cscn_addr, int *wae);

/* Set CGR cscn_ctx
 * @cscn_ctx: the cscn context datat
 */
void qbman_cgr_attr_set_cscn_ctx(struct qbman_attr *d, uint64_t cscn_ctx);
void qbman_cgr_attr_get_cscn_ctx(struct qbman_attr *d, uint64_t *cscn_ctx);
/* Set/get WRED edp bit
 * @idx: the index of the drop priority.
 * @edp: WRED enable for Drop priorty with index given in @idx.
 */
void qbman_cgr_attr_wred_set_edp(struct qbman_attr *d, uint32_t idx,
				 int edp);
void qbman_cgr_attr_wred_get_edp(struct qbman_attr *d, uint32_t idx,
				 int *edp);
/* Compose/decompose the WRED parameters for Drop Priority.
 * @minth: minimum threshold that packets may be discarded at
 * @maxth: maximum threshold that packets may be discarded. Above this
 *		   threshold all packets are discarded. (must be less than 2^39)
 * @maxp: maximum probability that a packet will be discarded. (1-100)
 */
uint32_t qbman_cgr_attr_wred_dp_compose(uint64_t minth, uint64_t maxth,
					uint8_t maxp);
void qbman_cgr_attr_wred_dp_decompose(uint32_t dp, uint64_t *minth,
				      uint64_t *maxth, uint8_t *maxp);

/* Set/get WRED parameter drop priority
 * @idx: the index for drop priority.
 * @dp: the WRED parameters for the drop priority with index given in @idx.
 */
void qbman_cgr_attr_wred_set_parm_dp(struct qbman_attr *d, uint32_t idx,
				     uint32_t dp);
void qbman_cgr_attr_wred_get_parm_dp(struct qbman_attr *d, uint32_t idx,
				     uint32_t *dp);

/* Congiure/Query CGR
 * @cgid: the congestion group id
 * @attr: the congestion group attributes struct
 */
int qbman_cgr_configure(struct qbman_swp *s, uint32_t cgid,
			const struct qbman_attr *attr);
int qbman_cgr_query(struct qbman_swp *s, uint32_t cgid,
		    struct qbman_attr *attr);

/* Query CGR's statistics
 * @cgid: the congestion group id.
 * @clear: clear the statistics after query.
 * @frame_cnt: the frame byte returned from query command.
 * @byte_cnt: the byte count returned from the query command.
 */
int qbman_cgr_statistics_query(struct qbman_swp *s, uint32_t cgid, int clear,
				uint64_t *frame_cnt, uint64_t *byte_cnt);

/* Reset CGR - reset the CGR fields to the HW-reset values.
 * @cgid: the congestion group id.
 */
int qbman_cgr_reset(struct qbman_swp *s, uint32_t cgid);

	/********************/
	/* CEETM management */
	/********************/
/**************************/
/* QMan freqency and PRES */
/**************************/
extern uint32_t qman_freq;
extern uint16_t qman_pres;

/* ---------------- */
/* CQ configuration */
/* ---------------- */

/* ceetmid: identifies the CEETM instance with the DCP
 * cqid: "class queue ID" to be configured (within the dcpid:instanceid)
 * ccgid: "class congestion group ID"
 * ps: "PFDR stashing enable", boolean
 * pps: "PFDR Pool Selection"
 */
int qbman_cq_configure(struct qbman_swp *, uint32_t ceetmid, uint16_t cqid,
		       uint8_t ccgid, int ps, uint8_t pps);

/* Extract the number of frames in the cq from qbman_attr */
void qbman_cq_attr_get_frm_cnt(struct qbman_attr *d, uint32_t *frm_cnt);

/* query cq and save the query result in qbman_attr */
int qbman_cq_query(struct qbman_swp *, uint32_t ceetmid, uint16_t cqid,
		   uint8_t *ccgid, int *ps, struct qbman_attr *attr, uint8_t *pps);

/* query cq and extract the number of pending frames */
int qbman_cq_query_pending_frame(struct qbman_swp *s, uint32_t ceetmid,
				 uint16_t cqid,
				 uint32_t *pending_frame);

/* Get the number of frames in a Class Queue, should be called after
 * qbman_cq_query.
 */
uint32_t qbman_cq_num_of_frames(struct qbman_attr *attr);

/* Get the "PFDR Pool Selection" field in CQD */
uint8_t qbman_cq_pps(struct qbman_attr *attr);

/* ----------------- */
/* LFQ configuration */
/* ----------------- */

/* LFQID is actually a composite value, consisting of the "dcpid" to identify
 * the hardware (or "Direct Connect") portal of QBMan, the "instanceid" to
 * identify the CEETM instance within the DCP portal, and the "lfqmtidx" to
 * identify the index into the logical frame queue mapping table (LFQMT) of that
 * CEETM instance. This composite value is used because it is globally unique
 * and is needed in order to perform enqueues (which may end up occuring in any
 * of the CEETM instances of QBMan). The other CEETM IDs (class queues, dequeue
 * contexts, ...) are all expressed relative to their CEETM instance, so don't
 * have equivalents for these compose/decompose APIs.
 *
 * (The reason for this apparent inconsistency is that the LFQID value is the
 * only identifier that is used by users of isolated portals, ie. GPP. The users
 * enqueue to a LFQID, rather than a conventional FQID, and the "bundling" of
 * instance info into LFQID means that the user has a single handle, rather than
 * having to know 3 coordinates. Only the configuration software using
 * non-isolated portals (ie. MC) references to the other per-instance resource
 * types, so there's not much point putting a globally-unique wrapper ID type
 * around each of them.)
 */

/* lfqid: "logical frame queue ID" to be configured
 * cqid: "class queue ID" that this LFQID should map to
 * dctidx: "dequeue context table index", enqueues via this LFQID get this ctx
 * fqider: "error rejection FQID", rejected enqueues to this LFQID go here
 * ccgid: "class congestion group ID", has to match the CQ setting (query-only)
 */
int qbman_lfq_configure(struct qbman_swp *, uint32_t lfqid, uint16_t cqid, uint16_t dctidx,
			uint32_t fqider);

int qbman_lfq_query(struct qbman_swp *, uint32_t lfqid, uint16_t *cqid, uint16_t *dctidx,
		    uint32_t *fqider, uint8_t *ccgid);

/* ----------------- */
/* DCT configuration */
/* ----------------- */

/* dcpid: "direct connect portal (DCP) ID"
 * instanceid: identifies the CEETM instance with the DCP
 * dctidx: "dequeue context table index" to be configured (within the dcpid:instanceid)
 * bdi: "bypass DPAA isolation", boolean, for DMA by the consumer (WRIOP)
 * va: "virtual address", boolean, for DMA by the consumer
 * icid: "isolation context ID", (uint:15)
 * pl: "privilege level", boolean
 * ctx: "context", (uint:64), for use by the consumer
 * tp_idx: trace point index, tp0 or tp1.
 * dd_code: DD code in trace point
 * tp_config_flag: the tp configuration flag.
 */
int qbman_dct_configure(struct qbman_swp *, uint32_t ceetmid, uint16_t dctidx,
			int bdi, int va, uint16_t icid, int pl, uint64_t ctx);
int qbman_dct_tp_configure(struct qbman_swp *s, uint32_t ceetmid,
			   uint16_t dctidx, int tp_idx,
			   uint8_t dd_code, uint32_t tp_config_flag);
int qbman_dct_tp_query(struct qbman_swp *s, uint32_t ceetmid, uint16_t dctidx,
		       int tp_idx, uint8_t *tp);

/* ----------------------------- */
/* Class scheduler configuration */
/* ----------------------------- */
/* Clear the cscheduler attribute struct  to default/starting state. */
void qbman_cscheduler_attr_clear(struct qbman_attr *);

/* Set/get MPS
 * mps: the minimum packet size
 */
void qbman_cscheduler_set_mps(struct qbman_attr *d, uint8_t mps);
void qbman_cscheduler_get_mps(struct qbman_attr *d, uint8_t *mps);

/* Set/get OAL
 * oal: the overhead accounting length
 */
void qbman_cscheduler_set_oal(struct qbman_attr *d, uint16_t oal);
void qbman_cscheduler_get_oal(struct qbman_attr *d, uint16_t *oal);

/* Set/get the CQPS
 * @cqps: the valid value is from 0 to 8. If it is 0, all CQ0-CQ7 are priority
 * CQs. If it is set to 8, all CQ0-CQ7 will act as CQ8-CQ15(weighted CQs).
 * If it is set to 3, CQ0-CQ4 will work as CQ3-CQ7, CQ5-CQ7 will work as CQ8-
 * CQ10(Weighted CQ).
 */
void qbman_cscheduler_set_cqps(struct qbman_attr *d, uint8_t cqps);
void qbman_cscheduler_get_cqps(struct qbman_attr *d, uint8_t *cqps);

/* Set/get the priority of group A in the GPC field in the class scheduler
 * configure command for the given channel.
 * @prio_a: should be < 7.
 */
void qbman_cscheduler_set_prio_a(struct qbman_attr *d, uint32_t prio_a);
void qbman_cscheduler_get_prio_a(struct qbman_attr *d, uint32_t *prio_a);

/* Set/get the priority of group B in the GPC field in the class scheduler
 * configure command for the given channel.
 * @prio_b: should be < 7.
 */
void qbman_cscheduler_set_prio_b(struct qbman_attr *d, uint32_t prio_b);
void qbman_cscheduler_get_prio_b(struct qbman_attr *d, uint32_t *prio_b);

/* Set/get the combined group flag in the GPC of the class scheduler configure
 * command for the given channle.
 * @group_b: 1 means the groups A and B are combined into a single group of 8
 * CQs.
 */
void qbman_cscheduler_set_group_b(struct qbman_attr *d, int group_b);
void qbman_cscheduler_get_group_b(struct qbman_attr *d, int *group_b);

/* Set/get Class Queues CR eligibility
 * @cq_idx: the CQ index from 0 to 7.
 * @cre: 1 = CQ is CR eligible.
 */
void qbman_cscheduler_set_crem_cq(struct qbman_attr *d,
				  uint8_t cq_idx, int cre);
void qbman_cscheduler_get_crem_cq(struct qbman_attr *d,
				  uint8_t cq_idx, int *cre);

/* Set/get group A's CR eligibility
 * @cre: 1 = group A is CR eligible.
 */
void qbman_cscheduler_set_crem_group_a(struct qbman_attr *d,
					int cre);
void qbman_cscheduler_get_crem_group_a(struct qbman_attr *d,
					int *cre);

/* Set/get group B's CR eligibility
 * @cre: 1 = group B is CR eligible.
 */
void qbman_cscheduler_set_crem_group_b(struct qbman_attr *d,
					int cre);
void qbman_cscheduler_get_crem_group_b(struct qbman_attr *d,
					int *cre);

/* Set/get Class Queues ER eligibility
 * @cq_idx: the CQ index from 0 to 7.
 * @ere: 1 = CQ is ER eligible.
 */
void qbman_cscheduler_set_erem_cq(struct qbman_attr *d,
				  uint8_t cq_idx, int ere);
void qbman_cscheduler_get_erem_cq(struct qbman_attr *d,
				  uint8_t cq_idx, int *ere);
/* Set/get group A's ER eligibility
 * @ere: 1 = group A is ER eligible.
 */
void qbman_cscheduler_set_erem_group_a(struct qbman_attr *d,
					int ere);
void qbman_cscheduler_get_erem_group_a(struct qbman_attr *d,
					int *ere);
/* Set/get group B's ER eligibility
 * @ere: 1 = group B is ER eligible.
 */
void qbman_cscheduler_set_erem_group_b(struct qbman_attr *d,
					int ere);
void qbman_cscheduler_get_erem_group_b(struct qbman_attr *d,
					int *ere);

/* Set/get weight for CQ 8 to 15 in the given channel.
 * @cq_idx: should be 8 ~ 15 for QMan 4.1 and earlier version;
 *          0 ~ 15 for QMan 5.0 and later.
 * @weight: The weight value should be in the range of 100 ~ 24800 because we
 * use will use integers to convert the weight configuration code {y, x}.
 * Pls refer to "CEETM Weighted Scheduling among Grouped Classes"
 * Note that for QMan 5.0+,  the CSMS bit must be set to 1 by calling
 * qbman_cscheduler_set_csms() to set the weight of CQ0-7.
 * The qbman_cscheduler_query_with_cq_range() must be called to get the correct
 * weight of CQ.
 */
void qbman_cscheduler_set_cq_weight(struct qbman_attr *d, uint32_t cq_idx,
				    uint32_t weight, int csms);
void qbman_cscheduler_get_cq_weight(struct qbman_attr *d, uint32_t cq_idx,
				    uint32_t *weight);

/* Set/get the CSMS
 * @csms: the class scheduler select mode. 1 = enable 16 weighted queues
 * 					   0 = only CQ 8-15 are weight queues.
 * This is the feature of QMan 5.0 and later
 */
void qbman_cscheduler_set_csms(struct qbman_attr *d, int csms);
void qbman_cscheduler_get_csms(struct qbman_attr *d, int *csms);

/* Configure/query the class scheduler of the given channel.
 * @ceetmid: combined with dcpid and ceetm instance id.
 * @cchannelid: the given ceetm channel index.
 * @qcqr: only valid for QMan 5.0 and later version, otherwise it is ignored.
	  0 = query CQ 7 to 0; 1 = query CQ 15 to 8.
 * @attr: the attribute struct to describe the fields of configure/query
 * commands.
 */
int qbman_cscheduler_configure(struct qbman_swp *s, uint32_t ceetmid,
			       uint8_t cchannelid,
			       const struct qbman_attr *attr);
int qbman_cscheduler_query(struct qbman_swp *s, uint32_t ceetmid,
			   uint8_t cchannelid, int qcqr,
			   struct qbman_attr *attr);

/* --------------------------- */
/* CEETM Channel configuration */
/* --------------------------- */

int qbman_cchannel_configure(struct qbman_swp *, uint32_t ceetmid, uint8_t cchannelid,
			     uint8_t lniid, int shaped);

//#ifdef MC_CLI
int qbman_cchannel_query(struct qbman_swp *, uint32_t ceetmid, uint8_t cchannelid,
			     uint8_t *lniid, int *shaped);
//#endif

/* ------------------------ */
/* Sub-portal configuration */
/* ------------------------ */

int qbman_subportal_configure(struct qbman_swp *, uint32_t ceetmid, uint8_t subportalid,
			      uint8_t lniid, int txenable);

/* -------------------- */
/* Shaper configuration */
/* -------------------- */
/* Clear the shaper attribute struct to default/starting state. */
void qbman_shaper_attr_clear(struct qbman_attr *);

/* Set/get the mps field of LNI shaper.
 * @mps: Minimum packet size; 0: disable.
 */
void qbman_shaper_set_lni_mps(struct qbman_attr *d, uint32_t mps);
void qbman_shaper_get_lni_mps(struct qbman_attr *d, uint32_t *mps);
/* Set/get the OAL filed of LNI shaper.
 * @oal: Overhead accounting length.
 */
void qbman_shaper_set_lni_oal(struct qbman_attr *d, uint32_t oal);
void qbman_shaper_get_lni_oal(struct qbman_attr *d, uint32_t *oal);
/* Set/get the coupling bit of either LNI or channel shapers.
 * @cpl: 1: CR and ER are coupled; 0: CR and ER are not coupled.
 */
void qbman_shaper_set_coupling(struct qbman_attr *d, int cpl);
void qbman_shaper_get_coupling(struct qbman_attr *d, int *cpl);
/* Set/get the commit rate of either LNI or channel shaper.
 * @bps: the desired shaping rate in bit-per-second.
 */
void qbman_shaper_set_commit_rate(struct qbman_attr *d, uint64_t bps);
void qbman_shaper_get_commit_rate(struct qbman_attr *d, uint64_t *bps);
/* Set/get the excess rate of either LNI or channel shaper.
 * @bps: the desired shaping rate in bit-per-second.
 */
void qbman_shaper_set_excess_rate(struct qbman_attr *d, uint64_t bps);
void qbman_shaper_get_excess_rate(struct qbman_attr *d, uint64_t *bps);
/* Set/get the CR token bucket limit of either LNI or channel shaper.
 * @tbl: The token bucket limit, which is related to maximum burst size for
 * shaper. And it can also be used as a weight for ShFQ.
 */
void qbman_shaper_set_crtbl(struct qbman_attr *d, uint32_t tbl);
void qbman_shaper_get_crtbl(struct qbman_attr *d, uint32_t *tbl);
/* Set/get the ER token bucket limit of either LNI or channel shaper.
 * @tbl: The token bucket limit, which is related to maximum burst size for
 * shaper. And it can also be used as a weight for ShFQ.
 */
void qbman_shaper_set_ertbl(struct qbman_attr *d, uint32_t tbl);
void qbman_shaper_get_ertbl(struct qbman_attr *d, uint32_t *tbl);
/* Configure/Query the LNI shaper.
 * @ceetmid: composed with ceetm instance id and dcpid.
 * @lniid: the LNI index.
 * @attr: the ceetm descriptor with values set by the set_ functions or
 * query command.
 */
int qbman_lni_shaper_configure(struct qbman_swp *s, uint32_t ceetmid,
			       uint32_t lniid, struct qbman_attr *attr);
int qbman_lni_shaper_query(struct qbman_swp *s, uint32_t ceetmid,
			   uint32_t lniid, struct qbman_attr *attr);
/* Disable LNI shaper - by setting an infinite token credit rate,
 * thus there is no shaping limitation at LNI level.
 * @ceetmid: composed with ceetm instance id and dcpid.
 * @lniid: the LNI index.
 * @oal: Overhead accounting length.
 */
int qbman_lni_shaper_disable(struct qbman_swp *s, uint32_t ceetmid,
                               uint32_t lniid, uint32_t oal);

/* Configure/Query the CEETM channel shaper.
 * @ceetmid: composed with ceetm instance id and dcpid.
 * @cchannelid: the CEETM channel index.
 * @attr: the ceetm descriptor with values set by the set_ functions or
 * query command.
 */
int qbman_cchannel_shaper_configure(struct qbman_swp *s, uint32_t ceetmid,
				    uint32_t cchannelid,
                                    struct qbman_attr *attr);
int qbman_cchannel_shaper_query(struct qbman_swp *s, uint32_t ceetmid,
				uint32_t cchannelid,
				struct qbman_attr *attr);

/* Configure/Query the CEETM CQ shaper.
 * @ceetmid: composed with ceetm instance id and dcpid.
 * @cq: the CEETM Class Queue index.
 * @attr: the ceetm descriptor with values set by the set_ functions or
 * query command.
 */
int qbman_cq_shaper_configure(struct qbman_swp *s, uint32_t ceetmid,
			      uint16_t cqid,
			      struct qbman_attr *attr);
int qbman_cq_shaper_query(struct qbman_swp *s, uint32_t ceetmid,
			  uint16_t cqid,
			  struct qbman_attr *attr);

/* ---------------------------------------------- */
/* LNI configuration (traffic class flow control) */
/* ---------------------------------------------- */
/* Clear ceetm attr structure */
void qbman_ceetm_tcfc_attr_clear(struct qbman_attr *d);

/* Set/get LNITCFCC field for given cq_idx and/or cchannelid.
 * @mode: the TCFC is based on: 0 - CQ based, 1 - Channel based,
 * 2 - individual CQ based. 3 - channel based + per TC CQ mask.
 * @cq_idx: the CQ index within the channel, should be 0 -15.
 * @cchannelid: the cchannel index, should be 0 - 31.
 * @tcid: specify the traffic class(from 0 to 7) to which this
 *  CQ/Cchannel belongs to.
 * @enable: 1 = traffic class flow control enabled
 * 	    0 = traffic class flow control disabled
 * For set function, return 0 if the cq_idx + cchannelid has been
 * set for mode=2, return -1 if there is no spot available.
 * For get function, return 0 if the matched cq_idx and/or cchannelid
 * has been found, return -EINVAL if there is no matched cq_idx + cchannelid
 * for mode=2
 */
int qbman_ceetm_tcfc_set_lnitcfcc(struct qbman_attr *a, uint8_t mode,
				   uint8_t cq_idx, uint8_t cchannelid,
				   uint8_t tcid, int enable);
int qbman_ceetm_tcfc_get_lnitcfcc(struct qbman_attr *a,
				  uint8_t cq_idx, uint8_t cchannelid,
				  uint8_t *mode, uint8_t *tcid, int *enable);
/* Set/get the extension mode of tcfcc.
 * @cq_idx: the CQ index within the channel, should be 0 -15.
 * @tcid: specify the traffic class(from 0 to 7) index.
 * @enable: 1 = enable flow control on the CQ mapping to this TC
 *	    0 = disable flow control on the CQ mapping to this TC
 *
 * This API should be called after qbman_ceetm_tcfc_set_lnitcfcc() to set
 * mode3's addtional part, i.e the per-TC CQ mask.
 */
void qbman_ceetm_tcfc_set_lnitcfcc_ex(struct qbman_attr *a, uint8_t cq_idx,
				      uint8_t tc_id, int enable);
void qbman_ceetm_tcfc_get_lnitcfcc_ex(struct qbman_attr *a, uint8_t cq_idx,
				      uint8_t tc_id, int *enable);

/* Configure/Query the LNI traffic class flow control.
 * @s: software portal
 * @ceetmid: the DCP id + CEETM instance ID
 * @lniid: specify which LNI to be configured/queired.
 */
int qbman_ceetm_tcfc_configure(struct qbman_swp *s, uint32_t ceetmid,
			       uint8_t lniid, struct qbman_attr *a);
int qbman_ceetm_tcfc_query(struct qbman_swp *s, uint32_t ceetmid,
			   uint8_t lniid, struct qbman_attr *a);

/* ------------------ */
/* CCGR configuration */
/* ------------------ */

/* Set CCGR oal field
 * @oal: Overhead Accounting Length
 */
/* Clear the contents of a ccgr attribute struct */
void qbman_ccgr_attr_clear(struct qbman_attr *);

void qbman_ccgr_attr_set_oal(struct qbman_attr *d, uint32_t oal);
void qbman_ccgr_attr_get_oal(struct qbman_attr *d, uint32_t *oal);
void qbman_ccgr_attr_get_i_cnt(struct qbman_attr *d, uint64_t *i_cnt);
void qbman_ccgr_attr_get_a_cnt(struct qbman_attr *d, uint64_t *a_cnt);

/* Congiure/Query CCGR
 * @ceetmid: identifies the CEETM instance with the DCP
 * @cchannelid: the ceetm channel id
 * @ccgid: "class congestion group ID"
 * @attr: the congestion group attribute struct
 */
int qbman_ccgr_configure(struct qbman_swp *s, uint32_t ceetmid, uint8_t cchannelid,
			 uint8_t ccgid, const struct qbman_attr *attr);
int qbman_ccgr_query(struct qbman_swp *s, uint32_t ceetmid, uint8_t cchannelid,
		     uint8_t ccgid, struct qbman_attr *attr);

/* This is a qbman_ccgr_query but only extract the i_cnt only, to improve speed. */
int qbman_ccgr_query_i_cnt(struct qbman_swp *s, uint32_t ceetmid,
			   uint8_t cchannelid, uint8_t ccgid, uint64_t *i_cnt);

/* Reset the CCGR
 * @ceetmid: identifies the CEETM instance with the DCP
 * @cchannelid: the ceetm channel id
 * @ccgid: "class congestion group ID"
 */
int qbman_ccgr_reset(struct qbman_swp *s, uint32_t ceetmid, uint8_t cchannelid,
		     uint8_t ccgid);

/* ----------- */
/* CQ Peek/pop */
/* ----------- */

int qbman_cq_pop(struct qbman_swp *, uint32_t ceetmid, uint16_t cqid,
		 struct qbman_fd *fd, uint16_t *dctidx, int *last_frame);

/* ---------- */
/* XSFDR read */
/* ---------- */
/* XSFDR read
 * @ceetmid: DCP id + CEETM Instance id.
 * @xsfdr: XSFDR pointer to be read.
 * @fd: Frame descriptor in the sxfdr read response.
 * @dctidx: dct index that was stored with the FD.
 */
int qbman_xsfdr_read(struct qbman_swp *s, uint32_t ceetmid, uint16_t xsfdr,
		     struct qbman_fd *fd, uint16_t *dctidx);

/* ---------- */
/* Statistics */
/* ---------- */
enum statistics_query_ct_e {
	query_dq_statistics,
	query_and_clear_dq_statistics,
	write_dq_statistics,
	query_reject_statistics,
	query_and_clear_reject_statistics,
	write_reject_statistics,
};
/* Query CEETM statistics
 * @ceetmid: DCP id + CEETM Instance id.
 * @cid: cqid or ccgrid. It should be the cqid if querying the cq dequeue
 *  statistics, or ccgrid if querying the reject statistics.
 * @ct: the command type
 * @frm_cnt: the queried frame count
 * @byte_cnt: the queried byte count
 */
int qbman_ceetm_statistics_query(struct qbman_swp *s, uint32_t ceetmid,
				uint16_t cid, enum statistics_query_ct_e ct,
				uint64_t *frm_cnt, uint64_t *byte_cnt);

	/*****************/
	/* QD management */
	/*****************/

/* 'qpr_array' points to the 16 Queuing Priority Records for this QD */
int qbman_qd_configure(struct qbman_swp *, uint16_t qdid, const uint16_t *qprid_array);

#ifdef MC_CLI
int qbman_qd_query(struct qbman_swp *s, uint16_t qdid, uint16_t *qprid_array);
#endif

	/******************/
	/* QPR management */
	/******************/

/* Hardware supports various values for fqid_num, between 1 and 1024, that are
 * of the form m*(2^n), so long as m is 1, 3, or 7. The helper routine can be
 * used to converge on the nearest valid value (as passing an invalid value to
 * qbman_qpr_configure() will return failure). If the requested value is not
 * available and there are higher and lower values than the one requested, the
 * value returned will be rounded down if 'rounding' is negative, rounded up if
 * it's positive, and rounded to the closest if it is zero.
 */
uint32_t qbman_qpr_get_valid_num(uint32_t fqid_num, int rounding);

/* Configure a Queuing Priority Record. Note that the driver examines
 * 'fqid_base' to determine if it's a logical FQID (CEETM) or regular FQ, and in
 * the CEETM case, it also derives the DCP ID and CEETM instance ID from the
 * logical FQID. (They are required parameters in the hardware, but the API does
 * not let the user supply values that might contradict the FQIDs.) Similarly,
 * if it is a logical FQID, then 'cgid' is understood to be a CCGR ID, otherwise
 * it's presumed to be a regular CGR ID.
 */
int qbman_qpr_configure(struct qbman_swp *, uint16_t qprid, uint32_t fqid_base,
			uint32_t fqid_num, uint32_t cgid);

#ifdef MC_CLI
int qbman_qpr_query(struct qbman_swp *s, uint16_t qprid, uint32_t *fqid_base,
			uint32_t *fqid_num, uint32_t *cgid);
#endif

	/********************************/
	/* Order restoration management */
	/********************************/

int qbman_opr_configure(struct qbman_swp *s, uint16_t oprid,
        uint32_t en, uint32_t oprc, uint16_t voprid);
int qbman_opr_retire(struct qbman_swp *s, uint16_t oprid);
int qbman_opr_query(struct qbman_swp *s, uint16_t oprid, struct qbman_attr *desc);
void qbman_qpr_attr_get_rip(struct qbman_attr *d, uint32_t *rip);
void qbman_qpr_attr_get_en(struct qbman_attr *d, uint32_t *en);
void qbman_qpr_attr_get_orpc(struct qbman_attr *d, uint32_t *orpc);
void qbman_qpr_attr_get_voprid(struct qbman_attr *d, uint32_t *voprid);
void qbman_qpr_attr_get_ea_hptr(struct qbman_attr *d, uint32_t *hptr);
void qbman_qpr_attr_get_ea_tptr(struct qbman_attr *d, uint32_t *tptr);
void qbman_qpr_attr_get_nesn(struct qbman_attr *d, uint32_t *nesn);
void qbman_qpr_attr_get_ea_hseq(struct qbman_attr *d, uint32_t *ea_hseq);
void qbman_qpr_attr_get_ea_hseq_nlis(struct qbman_attr *d, uint32_t *ea_hseq_nlis);
void qbman_qpr_attr_get_ea_tseq(struct qbman_attr *d, uint32_t *ea_tseq);
void qbman_qpr_attr_get_ea_tseq_nlis(struct qbman_attr *d, uint32_t *ea_tseq_nlis);
void qbman_qpr_attr_get_ndsn(struct qbman_attr *d, uint32_t *ndsn);

void qbman_qpr_attr_get_oprrws(struct qbman_attr *d, uint32_t *oprrws);
void qbman_qpr_attr_get_oa(struct qbman_attr *d, uint32_t *oa);
void qbman_qpr_attr_get_olws(struct qbman_attr *d, uint32_t *olws);
void qbman_qpr_attr_get_oeane(struct qbman_attr *d, uint32_t *oeane);
void qbman_qpr_attr_get_oloe(struct qbman_attr *d, uint32_t *oloe);

	/*********************************/
	/* Enqueue replicator management */
	/*********************************/

/* Replication Lists are just sequences of "replication records" (hence "rr")
 * linked from one to the next via each record's "next_rrid" field. A list is
 * really just a reference to the first record in this linked list, and
 * continues until a record is encountered with "next_rrid"==0.
 * Once replication of a frame is complete, it is returned to the producer via
 * the "return_fqid" of the *first* replication record in the list (the value of
 * this field in all the other records is ignored).
 */
int qbman_rr_configure(struct qbman_swp *, uint16_t rrid, uint16_t qdid,
		       uint16_t next_rrid, uint16_t icid,
		       uint32_t return_fqid, uint8_t rd);
int qbman_rr_query(struct qbman_swp *s, uint16_t rrid, uint16_t *qdid,
		   uint16_t *next_rrid, uint16_t *icid,
		   uint32_t *return_fqid, uint8_t *rd);
int qbman_rcr_query(struct qbman_swp *s, uint16_t tagid, uint16_t *cnt,
		    uint32_t *return_fqid_dcpid, uint8_t *rd);
void qbman_rcr_parse_dcpid(uint32_t return_dcpid, uint16_t *icid, int *bdi,
			   uint8_t *dcpid);
int qbman_rcr_reset(struct qbman_swp *s);

	/*********************************************************/
	/* Parse for recoverable error logging message (REL_MSG) */
	/*********************************************************/
int qbman_result_is_rel_msg(const struct qbman_result *dq);
uint32_t qbman_result_rel_msg_fqid(const struct qbman_result *dq);
uint32_t qbman_result_rel_msg_frame_count(const struct qbman_result *dq);
uint64_t qbman_result_rel_msg_fqd_ctx(const struct qbman_result *dq);
enum qbman_rerr_code_e {
	qbman_rerr_ieqi,
	qbman_rerr_ieci,
	qbman_rerr_iesi,
	qbman_rerr_ieoi,
	qbman_rerr_iece,
	qbman_rerr_iere,
	qbman_rerr_idqi = 8,
	qbman_rerr_idsi,
	qbman_rerr_idfi,
	qbman_rerr_iddi,
	qbman_rerr_icvi = 16,
	qbman_rerr_ifsi,
	qbman_rerr_pebi,
	qbman_rerr_plwi,
	qbman_rerr_flwi,
	qbman_rerr_sbei,
	qbman_rerr_avi = 24,
	qbman_rerr_rpqi,
	qbman_rerr_rpli,
	qbman_rerr_plwi1 = 29,
	qbman_rerr_plwi2,
	qbman_rerr_plwi3
};
enum qbman_rerr_code_e qbman_result_rel_msg_error_code(
                                        const struct qbman_result *dq);
/* Get the "Multiple Errors" bit for AVI errors only */
int qbman_result_rel_msg_error_code_me(const struct qbman_result *dq);
/* Get portal index, Valid for IEQI, IESI, IEOI, IERE, IDQI, IDSI, IDFI,
 * IDDI, ICVI, IFSI, AVI. Not valid for AVI when VT=7 */
uint16_t qbman_result_rel_msg_portal_idx(const struct qbman_result *dq);
int qbman_result_rel_msg_is_DCP(const struct qbman_result *dq);
/* ICID is valid for IEQI, IESI, IEOI, IERE, IDQI, IDFI, IDDI, ICVI, IFSI,
 * AVI. And its the ICID of replicaiton list for (EC=AVI, VT=7) */
uint16_t qbman_result_rel_msg_icid(const struct qbman_result *dq);
/* BDI is valid for EQI, IESI, IEOI, IERE, IDQI, IDFI, IDDI, ICVI, IFSI,
 * AVI, it should always be 0 for AVI */
int qbman_result_rel_msg_bdi(const struct qbman_result *dq);
/* VT is valid for IEQI, IESI, IEOI, IERE, AVI */
enum qbman_auth_type_e qbman_result_rel_msg_vt(const struct qbman_result *dq);
/* VRID1 is valid for IEQI, IESI, IEOI, IERE, IDQI, IDFI, IFSI, AVI, RPQI,
 * RPLI */
uint32_t qbman_result_rel_msg_vrid1(const struct qbman_result *dq);
/* VRID2 is valid for IEQI, IESI, IEOI, IERE, IDQI, IDFI, IFSI, AVI, RPQI */
uint32_t qbman_result_rel_msg_rrid1(const struct qbman_result *dq);
/* VRID2 is valid for IEQI, IESI, IEOI, IERE */
uint32_t qbman_result_rel_msg_vrid2(const struct qbman_result *dq);
/* VRRID2 is valid for IEQI, IESI, IEOI, IERE, RPQI */
uint32_t qbman_result_rel_msg_rrid2(const struct qbman_result *dq);
/* CV is only valid for ICVI */
uint8_t qbman_result_rel_msg_command_verb(const struct qbman_result *dq);
enum qbman_command_location_t {
	qbman_cl_eqcr,
	qbman_cl_cr,
	qbman_cl_rcr
};
/* CL is only valid for ICVI */
enum qbman_command_location_t qbman_result_rel_msg_cl(
						const struct qbman_result *dq);

/* Fix burst_size value when this is zero.
 * If burst_size is zero the function will return the smallest CRTBL/ERTBL value that
 * supports provided rate */
uint32_t qbman_fix_burst_size(uint32_t burst_size, uint64_t bps);

#ifdef MC_CLI
int qbman_swp_cinh_write(struct qbman_swp *p, uint32_t offset, uint32_t val);
uint32_t qbman_swp_cinh_read(struct qbman_swp *p, uint32_t offset);
#endif

#endif /* !_FSL_QBMAN_PORTAL_EX_H */

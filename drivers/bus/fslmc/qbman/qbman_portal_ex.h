/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 NXP
 *
 */

#include "qbman_private.h"
#include "fsl_qbman_portal.h"

/* All QBMan command and result structures use this "valid bit" encoding */
#define QB_VALID_BIT ((uint32_t)0x80)

/* Management command result codes */
#define QBMAN_MC_RSLT_OK      0xf0

/* --------------------- */
/* portal data structure */
/* --------------------- */

// ToDo: Remove
#ifdef NOT_NEEDED
struct qbman_swp {
	struct qbman_swp_desc desc;
	/* The qbman_sys (ie. arch/OS-specific) support code can put anything it
	 * needs in here. */
	struct qbman_swp_sys sys;
	/* Management commands */
	struct {
#ifdef QBMAN_CHECKING
		enum swp_mc_check {
			swp_mc_can_start, /* call __qbman_swp_mc_start() */
			swp_mc_can_submit, /* call __qbman_swp_mc_submit() */
			swp_mc_can_poll, /* call __qbman_swp_mc_result() */
		} check;
#endif
		uint32_t valid_bit; /* 0x00 or 0x80 */
	} mc;
	/* Push dequeues */
	uint32_t sdq;
	/* Volatile dequeues */
	struct {
		/* VDQCR supports a "1 deep pipeline", meaning that if you know
		 * the last-submitted command is already executing in the
		 * hardware (as evidenced by at least 1 valid dequeue result),
		 * you can write another dequeue command to the register, the
		 * hardware will start executing it as soon as the
		 * already-executing command terminates. (This minimises latency
		 * and stalls.) With that in mind, this "busy" variable refers
		 * to whether or not a command can be submitted, not whether or
		 * not a previously-submitted command is still executing. In
		 * other words, once proof is seen that the previously-submitted
		 * command is executing, "vdq" is no longer "busy". TODO:
		 * convert this to "atomic_t" so that it is thread-safe (without
		 * locking). */
		int busy;
		uint32_t valid_bit; /* 0x00 or 0x80 */
		/* We need to determine when vdq is no longer busy. This depends
		 * on whether the "busy" (last-submitted) dequeue command is
		 * targetting DQRR or main-memory, and detected is based on the
		 * presence of the dequeue command's "token" showing up in
		 * dequeue entries in DQRR or main-memory (respectively). Debug
		 * builds will, when submitting vdq commands, verify that the
		 * dequeue result location is not already equal to the command's
		 * token value. */
		struct qbman_result *storage; /* NULL if DQRR */
		uint32_t token;
	} vdq;
	/* DQRR */
	struct {
		uint32_t next_idx;
		uint32_t valid_bit;
		uint8_t dqrr_size;
#ifdef ERR008838
                int reset_bug;
#endif /* ERR008838 */
	} dqrr;
};
#endif

/* -------------------------- */
/* portal management commands */
/* -------------------------- */

/* Different management commands all use this common base layer of code to issue
 * commands and poll for results. The first function returns a pointer to where
 * the caller should fill in their MC command (though they should ignore the
 * verb byte), the second function commits merges in the caller-supplied command
 * verb (which should not include the valid-bit) and submits the command to
 * hardware, and the third function checks for a completed response (returns
 * non-NULL if only if the response is complete). */
// ToDo: remove
#ifdef NOT_NEEDED
void *qbman_swp_mc_start(struct qbman_swp *p);
int qbman_swp_mc_submit(struct qbman_swp *p, void *cmd, uint32_t cmd_verb);
void *qbman_swp_mc_result(struct qbman_swp *p);

/* Attempt to resynchronize the MCR valid bit in case of a timeout */
void qbman_swp_sync_vb(struct qbman_swp *p);

/* Wraps up submit + poll-for-result */
static inline void *qbman_swp_mc_complete(struct qbman_swp *swp, void *cmd,
					  uint32_t cmd_verb)
{
	int loopvar = MAX_TRYS, ret;
	ret = qbman_swp_mc_submit(swp, cmd, cmd_verb);
	if (ret) {
		pr_err("Failed to submit management command to SWP %d\n",
				swp->desc.idx);
		return NULL;
	}
	do {
		if (loopvar-- < 1) {
			pr_err("SWP %d management command failed to complete\n",
					swp->desc.idx);
#ifdef QBMAN_CHECKING
			/* Allow a user to try again */ 
			swp->mc.check = swp_mc_can_submit;
#endif
			qbman_swp_sync_vb(swp);
			return NULL;
		}
		cmd = qbman_swp_mc_result(swp);
	} while (!cmd);
	return cmd;
}
#endif

/* ------------ */
/* qb_attr_code */
/* ------------ */

/* This struct locates a sub-field within a QBMan portal (CENA) cacheline which
 * is either serving as a configuration command or a query result. The
 * representation is inherently little-endian, as the indexing of the words is
 * itself little-endian in nature and layerscape is little endian for anything
 * that crosses a word boundary too (64-bit fields are the obvious examples).
 */
struct qb_attr_code {
	unsigned int word; /* which uint32_t[] array member encodes the field */
	unsigned int lsoffset; /* encoding offset from ls-bit */
	unsigned int width; /* encoding width. (bool must be 1.) */
};

/* Some pre-defined codes */
extern struct qb_attr_code code_generic_verb;
extern struct qb_attr_code code_generic_rslt;

/* Macros to define codes */
#define QB_CODE(a, b, c) { a, b, c}
#define QB_CODE_NULL \
	QB_CODE((unsigned int)-1, (unsigned int)-1, (unsigned int)-1)

/* Rotate a code "ms", meaning that it moves from less-significant bytes to
 * more-significant, from less-significant words to more-significant, etc. The
 * "ls" version does the inverse, from more-significant towards
 * less-significant.
 */
static inline void qb_attr_code_rotate_ms(struct qb_attr_code *code,
					  unsigned int bits)
{
	code->lsoffset += bits;
	while (code->lsoffset > 31) {
		code->word++;
		code->lsoffset -= 32;
	}
}
static inline void qb_attr_code_rotate_ls(struct qb_attr_code *code,
					  unsigned int bits)
{
	/* Don't be fooled, this trick should work because the types are
	 * unsigned. So the case that interests the while loop (the rotate has
	 * gone too far and the word count needs to compensate for it), is
	 * manifested when lsoffset is negative. But that equates to a really
	 * large unsigned value, starting with lots of "F"s. As such, we can
	 * continue adding 32 back to it until it wraps back round above zero,
	 * to a value of 31 or less...
	 */
	code->lsoffset -= bits;
	while (code->lsoffset > 31) {
		code->word--;
		code->lsoffset += 32;
	}
}
/* Implement a loop of code rotations until 'expr' evaluates to FALSE (0). */
#define qb_attr_code_for_ms(code, bits, expr) \
		for (; expr; qb_attr_code_rotate_ms(code, bits))
#define qb_attr_code_for_ls(code, bits, expr) \
		for (; expr; qb_attr_code_rotate_ls(code, bits))

/* decode a field from a cacheline */
static inline uint32_t qb_attr_code_decode(const struct qb_attr_code *code,
				      const uint32_t *cacheline)
{
	return d32_uint32_t(code->lsoffset, code->width, cacheline[code->word]);
}

static inline uint64_t qb_attr_code_decode_64(const struct qb_attr_code *code,
                                      const uint64_t *cacheline)
{
	uint64_t val;
	u64_from_le32_copy(&val, &cacheline[code->word / 2], 1);
	return val;
}

/* encode a field to a cacheline */
static inline void qb_attr_code_encode(const struct qb_attr_code *code,
				       uint32_t *cacheline, uint32_t val)
{
	cacheline[code->word] =
		r32_uint32_t(code->lsoffset, code->width, cacheline[code->word])
		| e32_uint32_t(code->lsoffset, code->width, val);
}

static inline void qb_attr_code_encode_64(const struct qb_attr_code *code,
                                       uint64_t *cacheline, uint64_t val)
{
	u64_to_le32_copy(&cacheline[code->word / 2], &val, 1);
}


/* Small-width signed values (two's-complement) will decode into medium-width
 * positives. (Eg. for an 8-bit signed field, which stores values from -128 to
 * +127, a setting of -7 would appear to decode to the 32-bit unsigned value
 * 249. Likewise -120 would decode as 136.) This function allows the caller to
 * "re-sign" such fields to 32-bit signed. (Eg. -7, which was 249 with an 8-bit
 * encoding, will become 0xfffffff9 if you cast the return value to uint32_t).
 */
static inline int32_t qb_attr_code_makesigned(const struct qb_attr_code *code,
					  uint32_t val)
{
	BUG_ON(val >= (1 << code->width));
	/* If the high bit was set, it was encoding a negative */
	if (val >= (uint32_t)(1 << (code->width - 1)))
		return (int32_t)0 - (int32_t)(((uint32_t)1 << code->width) -
			val);
	/* Otherwise, it was encoding a positive */
	return (int32_t)val;
}

/* ---------------------- */
/* Descriptors/cachelines */
/* ---------------------- */

/* To avoid needless dynamic allocation, the driver API often gives the caller
 * a "descriptor" type that the caller can instantiate however they like.
 * Ultimately though, it is just a cacheline of binary storage (or something
 * smaller when it is known that the descriptor doesn't need all 64 bytes) for
 * holding pre-formatted pieces of harware commands. The performance-critical
 * code can then copy these descriptors directly into hardware command
 * registers more efficiently than trying to construct/format commands
 * on-the-fly. The API user sees the descriptor as an array of 32-bit words in
 * order for the compiler to know its size, but the internal details are not
 * exposed. The following macro is used within the driver for converting *any*
 * descriptor pointer to a usable array pointer. The use of a macro (instead of
 * an inline) is necessary to work with different descriptor types and to work
 * correctly with const and non-const inputs (and similarly-qualified outputs).
 */
#define qb_cl(d) (&(d)->dont_manipulate_directly[0])

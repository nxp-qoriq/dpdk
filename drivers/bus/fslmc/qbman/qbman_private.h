/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 NXP
 *
 */

/* Perform extra checking */
/* #define QBMAN_CHECKING */

/* To maximise the amount of logic that is common between the Linux driver and
 * other targets (such as the embedded MC firmware), we pivot here between the
 * inclusion of two platform-specific headers.
 *
 * The first, qbman_sys_decl.h, includes any and all required system headers as
 * well as providing any definitions for the purposes of compatibility. The
 * second, qbman_sys.h, is where platform-specific routines go.
 *
 * The point of the split is that the platform-independent code (including this
 * header) may depend on platform-specific declarations, yet other
 * platform-specific routines may depend on platform-independent definitions.
 */

#include "compat.h"
#include "qbman_sys_decl.h"

/* When things go wrong, it is a convenient trick to insert a few FOO()
 * statements in the code to trace progress. TODO: remove this once we are
 * hacking the code less actively.
 */
#define FOO() pr_info("FOO: %s:%d\n", __FILE__, __LINE__)

#define word_copy memcpy

#define BUG_ON(_cond)

#define CHECK_COND_RETVAL(A, B, ...);
#define ASSERT_COND(_cond)

/* Convert a host-native 32bit value into little endian */
#if defined(__BIG_ENDIAN)
static inline uint32_t make_le32(uint32_t val)
{
        return (((val & 0xff) << 24) | ((val & 0xff00) << 8) |
                ((val & 0xff0000) >> 8) | ((val & 0xff000000) >> 24));
}
static inline uint32_t make_le24(uint32_t val)
{
        return (((val & 0xff) << 16) | (val & 0xff00) |
                ((val & 0xff0000) >> 16));
}
#else
#define make_le32(val) (val)
#define make_le24(val) (val)
#endif
static inline void make_le32_n(uint32_t *val, unsigned int num)
{
        while (num--) {
                *val = make_le32(*val);
                val++;
        }
}

static inline unsigned int ilog2(uint32_t x)
{
        unsigned int e = 31;
        uint32_t mask = (uint32_t)1 << e;
        do {
                if (x & mask)
                        return e;
                e--;
                mask >>= 1;
        } while (mask);
        ASSERT_COND(0);
        return (unsigned int)-1;
}
/* The platform-independent code shouldn't need endianness, except for
 * weird/fast-path cases like qbman_result_has_token(), which needs to
 * perform a passive and endianness-specific test on a read-only data structure
 * very quickly. It's an exception, and this symbol is used for that case. */
#if defined(__BIG_ENDIAN)
#define DQRR_TOK_OFFSET 0
#define FQRN_TOK_OFFSET 0
#define QBMAN_RESULT_VERB_OFFSET_IN_MEM 24
#define SCN_STATE_OFFSET_IN_MEM 8
#define SCN_RID_OFFSET_IN_MEM 8
#else
#define DQRR_TOK_OFFSET 24
#define FQRN_TOK_OFFSET 24
#define QBMAN_RESULT_VERB_OFFSET_IN_MEM 0
#define SCN_STATE_OFFSET_IN_MEM 16
#define SCN_RID_OFFSET_IN_MEM 0
#endif



/* For CCSR or portal-CINH registers that contain fields at arbitrary offsets
 * and widths, these macro-generated encode/decode/isolate/remove inlines can
 * be used.
 *
 * Eg. to "d"ecode a 14-bit field out of a register (into a "uint16_t" type),
 * where the field is located 3 bits "up" from the least-significant bit of the
 * register (ie. the field location within the 32-bit register corresponds to a
 * mask of 0x0001fff8), you would do;
 *                uint16_t field = d32_uint16_t(3, 14, reg_value);
 *
 * Or to "e"ncode a 1-bit boolean value (input type is "int", zero is FALSE,
 * non-zero is TRUE, so must convert all non-zero inputs to 1, hence the "!!"
 * operator) into a register at bit location 0x00080000 (19 bits "in" from the
 * LS bit), do;
 *                reg_value |= e32_int(19, 1, !!field);
 *
 * If you wish to read-modify-write a register, such that you leave the 14-bit
 * field as-is but have all other fields set to zero, then "i"solate the 14-bit
 * value using;
 *                reg_value = i32_uint16_t(3, 14, reg_value);
 *
 * Alternatively, you could "r"emove the 1-bit boolean field (setting it to
 * zero) but leaving all other fields as-is;
 *                reg_val = r32_int(19, 1, reg_value);
 *
 */
#define MAKE_MASK32(width) (width == 32 ? 0xffffffff : \
				 (uint32_t)((1 << width) - 1))
#define DECLARE_CODEC32(t) \
static inline uint32_t e32_##t(uint32_t lsoffset, uint32_t width, t val) \
{ \
	BUG_ON(width > (sizeof(t) * 8)); \
	return ((uint32_t)val & MAKE_MASK32(width)) << lsoffset; \
} \
static inline t d32_##t(uint32_t lsoffset, uint32_t width, uint32_t val) \
{ \
	BUG_ON(width > (sizeof(t) * 8)); \
	return (t)((val >> lsoffset) & MAKE_MASK32(width)); \
} \
static inline uint32_t i32_##t(uint32_t lsoffset, uint32_t width, \
				uint32_t val) \
{ \
	BUG_ON(width > (sizeof(t) * 8)); \
	return e32_##t(lsoffset, width, d32_##t(lsoffset, width, val)); \
} \
static inline uint32_t r32_##t(uint32_t lsoffset, uint32_t width, \
				uint32_t val) \
{ \
	BUG_ON(width > (sizeof(t) * 8)); \
	return ~(MAKE_MASK32(width) << lsoffset) & val; \
}
DECLARE_CODEC32(uint32_t)
DECLARE_CODEC32(uint16_t)
DECLARE_CODEC32(uint8_t)
DECLARE_CODEC32(int)

	/*********************/
	/* Debugging assists */
	/*********************/

// ToDo: Rwmove
#ifdef NOT_NEEDED
static inline void __hexdump(unsigned long start, unsigned long end,
			unsigned long p, size_t sz, const unsigned char *c)
{
	while (start < end) {
		unsigned int pos = 0;
		char buf[64];
		int nl = 0;
		pos += sprintf(buf + pos, "%08lx: ", start);
		do {
			if ((start < p) || (start >= (p + sz)))
				pos += sprintf(buf + pos, "..");
			else
				pos += sprintf(buf + pos, "%02x", *(c++));
			if (!(++start & 15)) {
				buf[pos++] = '\n';
				nl = 1;
			} else {
				nl = 0;
				if (!(start & 1))
					buf[pos++] = ' ';
				if (!(start & 3))
					buf[pos++] = ' ';
			}
		} while (start & 15);
		if (!nl)
			buf[pos++] = '\n';
		buf[pos] = '\0';
		pr_info("%s", buf);
	}
}
static inline void hexdump(const void *ptr, size_t sz)
{
	unsigned long p = (unsigned long)ptr;
	unsigned long start = p & ~(unsigned long)15;
	unsigned long end = (p + sz + 15) & ~(unsigned long)15;
	const unsigned char *c = ptr;
	__hexdump(start, end, p, sz, c);
}
#endif

#define QMAN_REV_4000   0x04000000
#define QMAN_REV_4100   0x04010000
#define QMAN_REV_4101   0x04010001
#define QMAN_REV_5000   0x05000000

extern uint32_t qman_version;

/* Dynamic Debug support */
/* Define the Trace point congfiguration flags */
#define TP_CONFIG_TRACE_DISABLE 0x00000001
#define TP_CONFIG_TRACE_ENABLED_TERSE_OUTPUT 0x00000002
#define TP_CONFIG_TRACE_ENABLED_VERBOSE_OUTPUT 0x00000008
#define TP_CONFIG_TRACE_ENABLED_VERBOSE_LEVEL1_OUTPUT 0x00000002
#define TP_CONFIG_TRACE_ENABLED_VERBOSE_LEVEL2_OUTPUT 0x00000004
#define TP_CONFIG_TRACE_ENABLED_VERBOSE_LEVEL3_OUTPUT 0x00000008
#define TP_CONFIG_PORTAL_HALT_DISABLED 0x00000010
#define TP_CONFIG_PORTAL_HALT_ENABLED 0x00000020



static uint8_t parse_tp_config(uint32_t tp_config_flag)
{
	uint8_t tp_config = 0;
	if (tp_config_flag & TP_CONFIG_TRACE_DISABLE)
		tp_config |= e32_uint8_t(0, 1, 0);
	if (tp_config_flag & TP_CONFIG_TRACE_ENABLED_TERSE_OUTPUT)
		tp_config |= e32_uint8_t(0, 2, 1);
	if (tp_config_flag & TP_CONFIG_TRACE_ENABLED_VERBOSE_LEVEL1_OUTPUT)
		tp_config |= e32_uint8_t(0, 2, 1);
	if (tp_config_flag & TP_CONFIG_TRACE_ENABLED_VERBOSE_OUTPUT)
		tp_config |= e32_uint8_t(0, 2, 3);
	if (tp_config_flag & TP_CONFIG_TRACE_ENABLED_VERBOSE_LEVEL3_OUTPUT)
		tp_config |= e32_uint8_t(0, 2, 3);
	if (tp_config_flag & TP_CONFIG_TRACE_ENABLED_VERBOSE_LEVEL2_OUTPUT)
		tp_config |= e32_uint8_t(0, 2, 2);
	if (tp_config_flag & TP_CONFIG_PORTAL_HALT_DISABLED)
		tp_config |= e32_uint8_t(2, 1, 0);
	if (tp_config_flag & TP_CONFIG_PORTAL_HALT_ENABLED)
		tp_config |= e32_uint8_t(2, 1, 1);
	return tp_config;
}

#include "qbman_sys.h"

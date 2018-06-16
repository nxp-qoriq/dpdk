/*-
 *   BSD LICENSE
 *
 * Copyright (C) 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2018 NXP
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef _QBMAN_SYS_DECL_H_
#define _QBMAN_SYS_DECL_H_

#include <compat.h>
#include <fsl_qbman_base.h>

/* Sanity check */
#if (__BYTE_ORDER__ != __ORDER_BIG_ENDIAN__) && \
	(__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__)
#error "Unknown endianness!"
#endif

	/****************/
	/* arch assists */
	/****************/
#if defined(RTE_ARCH_ARM64)
#define dcbz(p) { asm volatile("dc zva, %0" : : "r" (p) : "memory"); }
#define lwsync() { asm volatile("dmb st" : : : "memory"); }
#define dcbf(p) { asm volatile("dc cvac, %0" : : "r"(p) : "memory"); }
#define dccivac(p) { asm volatile("dc civac, %0" : : "r"(p) : "memory"); }
static inline void prefetch_for_load(void *p)
{
	asm volatile("prfm pldl1keep, [%0, #0]" : : "r" (p));
}

static inline void prefetch_for_store(void *p)
{
	asm volatile("prfm pstl1keep, [%0, #0]" : : "r" (p));
}
#elif defined(RTE_ARCH_ARM)
#define dcbz(p) memset(p, 0, 64)
#define lwsync() { asm volatile("dmb st" : : : "memory"); }
#define dcbf(p)	RTE_SET_USED(p)
#define dccivac(p)	RTE_SET_USED(p)
#define prefetch_for_load(p) { asm volatile ("pld [%0]" : : "r" (p)); }
#define prefetch_for_store(p) { asm volatile ("pld [%0]" : : "r" (p)); }

#else
#define dcbz(p)	RTE_SET_USED(p)
#define lwsync()
#define dcbf(p)	RTE_SET_USED(p)
#define dccivac(p)	RTE_SET_USED(p)
static inline void prefetch_for_load(void *p)
{
	RTE_SET_USED(p);
}
static inline void prefetch_for_store(void *p)
{
	RTE_SET_USED(p);
}
#endif
#endif /* _QBMAN_SYS_DECL_H_ */

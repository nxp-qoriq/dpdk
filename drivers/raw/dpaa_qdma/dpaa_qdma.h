/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 NXP
 */

#ifndef _FSL_QDMA_H_
#define _FSL_QDMA_H_

#include <dpaa_list.h>
#include <rte_atomic.h>

#define u64	uint64_t
#define u32	uint32_t
#define u16	uint16_t
#define u8	uint8_t

#ifdef DEBUG
#define debug printf
#else
#define debug
#endif
#ifndef BIT
#define BIT(nr)		(1UL << (nr))
#endif

#define CORE_NUMBER 4
#define RETRIES	5

#ifndef GENMASK
#define BITS_PER_LONG	(__SIZEOF_LONG__ * 8)
#define GENMASK(h, l) \
		(((~0UL) << (l)) & (~0UL >> (BITS_PER_LONG - 1 - (h))))
#endif

#define FSL_QDMA_DMR			0x0
#define FSL_QDMA_DSR			0x4
#define FSL_QDMA_DEIER			0xe00
#define FSL_QDMA_DEDR			0xe04
#define FSL_QDMA_DECFDW0R		0xe10
#define FSL_QDMA_DECFDW1R		0xe14
#define FSL_QDMA_DECFDW2R		0xe18
#define FSL_QDMA_DECFDW3R		0xe1c
#define FSL_QDMA_DECFQIDR		0xe30
#define FSL_QDMA_DECBR			0xe34

#define FSL_QDMA_BCQMR(x)		(0xc0 + 0x100 * (x))
#define FSL_QDMA_BCQSR(x)		(0xc4 + 0x100 * (x))
#define FSL_QDMA_BCQEDPA_SADDR(x)	(0xc8 + 0x100 * (x))
#define FSL_QDMA_BCQDPA_SADDR(x)	(0xcc + 0x100 * (x))
#define FSL_QDMA_BCQEEPA_SADDR(x)	(0xd0 + 0x100 * (x))
#define FSL_QDMA_BCQEPA_SADDR(x)	(0xd4 + 0x100 * (x))
#define FSL_QDMA_BCQIER(x)		(0xe0 + 0x100 * (x))
#define FSL_QDMA_BCQIDR(x)		(0xe4 + 0x100 * (x))

#define FSL_QDMA_SQEDPAR		0x808
#define FSL_QDMA_SQDPAR			0x80c
#define FSL_QDMA_SQEEPAR		0x810
#define FSL_QDMA_SQEPAR			0x814
#define FSL_QDMA_BSQMR			0x800
#define FSL_QDMA_BSQSR			0x804
#define FSL_QDMA_BSQICR			0x828
#define FSL_QDMA_CQMR			0xa00
#define FSL_QDMA_CQDSCR1		0xa08
#define FSL_QDMA_CQDSCR2                0xa0c
#define FSL_QDMA_CQIER			0xa10
#define FSL_QDMA_CQEDR			0xa14
#define FSL_QDMA_SQCCMR			0xa20

#define FSL_QDMA_SQICR_ICEN

#define FSL_QDMA_CQIDR_CQT		0xff000000
#define FSL_QDMA_CQIDR_SQPE		0x800000
#define FSL_QDMA_CQIDR_SQT		0x8000

#define FSL_QDMA_BCQIER_CQTIE		0x8000
#define FSL_QDMA_BCQIER_CQPEIE		0x800000
#define FSL_QDMA_BSQICR_ICEN		0x80000000
#define FSL_QDMA_BSQICR_ICST(x)		((x) << 16)
#define FSL_QDMA_CQIER_MEIE		0x80000000
#define FSL_QDMA_CQIER_TEIE		0x1
#define FSL_QDMA_SQCCMR_ENTER_WM	0x200000

#define FSL_QDMA_QUEUE_MAX		8

#define FSL_QDMA_BCQMR_EN		0x80000000
#define FSL_QDMA_BCQMR_EI		0x40000000
#define FSL_QDMA_BCQMR_CD_THLD(x)	((x) << 20)
#define FSL_QDMA_BCQMR_CQ_SIZE(x)	((x) << 16)

#define FSL_QDMA_BCQSR_QF		0x10000
#define FSL_QDMA_BCQSR_XOFF		0x1

#define FSL_QDMA_BSQMR_EN		0x80000000
#define FSL_QDMA_BSQMR_DI		0x40000000
#define FSL_QDMA_BSQMR_CQ_SIZE(x)	((x) << 16)

#define FSL_QDMA_BSQSR_QE		0x20000
#define FSL_QDMA_BSQSR_QF		0x10000

#define FSL_QDMA_DMR_DQD		0x40000000
#define FSL_QDMA_DSR_DB			0x80000000

#define FSL_QDMA_COMMAND_BUFFER_SIZE	64
#define FSL_QDMA_DESCRIPTOR_BUFFER_SIZE 32
#define FSL_QDMA_CIRCULAR_DESC_SIZE_MIN	64
#define FSL_QDMA_CIRCULAR_DESC_SIZE_MAX	16384
#define FSL_QDMA_QUEUE_NUM_MAX		8

#define FSL_QDMA_CMD_RWTTYPE		0x4
#define FSL_QDMA_CMD_LWC                0x2

#define FSL_QDMA_CMD_RWTTYPE_OFFSET	28
#define FSL_QDMA_CMD_NS_OFFSET		27
#define FSL_QDMA_CMD_DQOS_OFFSET	24
#define FSL_QDMA_CMD_WTHROTL_OFFSET	20
#define FSL_QDMA_CMD_DSEN_OFFSET	19
#define FSL_QDMA_CMD_LWC_OFFSET		16

#define QDMA_CCDF_STATUS		20
#define QDMA_CCDF_OFFSET		20
#define QDMA_CCDF_MASK			GENMASK(28, 20)
#define QDMA_CCDF_FOTMAT		BIT(29)
#define QDMA_CCDF_SER			BIT(30)

#define QDMA_SG_FIN			BIT(30)
#define QDMA_SG_EXT			BIT(31)
#define QDMA_SG_LEN_MASK		GENMASK(29, 0)

#define QDMA_BIG_ENDIAN			1
#define COMP_TIMEOUT			100000
#define COMMAND_QUEUE_OVERFLLOW		10

/* qdma engine attribute */
#define QDMA_QUEUE_SIZE 64
#define QDMA_STATUS_SIZE 64
#define QDMA_CCSR_BASE 0x8380000
#define VIRT_CHANNELS 32
#define QDMA_BLOCK_OFFSET 0x10000
#define QDMA_BLOCKS 4
#define QDMA_QUEUES 8
#define QDMA_DELAY 1000

#define __arch_getq(a)		(*(volatile u64 *)(a))
#define __arch_putq(v, a)	(*(volatile u64 *)(a) = (v))
#define __arch_getq32(a)	(*(volatile u32 *)(a))
#define __arch_putq32(v, a)	(*(volatile u32 *)(a) = (v))
#define readq32(c) \
	({ u32 __v = __arch_getq32(c); rte_io_rmb(); __v; })
#define writeq32(v, c) \
	({ u32 __v = v; __arch_putq32(__v, c); __v; })
#define ioread32(_p)		readq32(_p)
#define iowrite32(_v, _p)	writeq32(_v, _p)

#define ioread32be(_p)          be32_to_cpu(readq32(_p))
#define iowrite32be(_v, _p)	writeq32(be32_to_cpu(_v), _p)

#ifdef QDMA_BIG_ENDIAN
#define QDMA_IN(addr)		ioread32be(addr)
#define QDMA_OUT(addr, val)	iowrite32be(val, addr)
#else
#define QDMA_IN(addr)		ioread32(addr)
#define QDMA_OUT(addr, val)	iowrite32(val, addr)
#endif

#define FSL_QDMA_BLOCK_BASE_OFFSET(fsl_qdma_engine, x)			\
	(((fsl_qdma_engine)->block_offset) * (x))

typedef void (*dma_call_back)(void *params);

/* qDMA Command Descriptor Fotmats */
struct fsl_qdma_format {
	__le32 status; /* ser, status */
	__le32 cfg;	/* format, offset */
	union {
		struct {
			__le32 addr_lo;	/* low 32-bits of 40-bit address */
			u8 addr_hi;	/* high 8-bits of 40-bit address */
			u8 __reserved1[2];
			u8 cfg8b_w1; /* dd, queue */
		};
		__le64 data;
	};
};

/* qDMA Source Descriptor Format */
struct fsl_qdma_sdf {
	__le32 rev3;
	__le32 cfg; /* rev4, bit[0-11] - ssd, bit[12-23] sss */
	__le32 rev5;
	__le32 cmd;
};

/* qDMA Destination Descriptor Format */
struct fsl_qdma_ddf {
	__le32 rev1;
	__le32 cfg; /* rev2, bit[0-11] - dsd, bit[12-23] - dss */
	__le32 rev3;
	__le32 cmd;
};

enum dma_status {
	DMA_COMPLETE,
	DMA_IN_PROGRESS,
	DMA_IN_PREPAR,
	DMA_PAUSED,
	DMA_ERROR,
};

struct fsl_qdma_chan {
	struct fsl_qdma_engine	*qdma;
	struct fsl_qdma_queue	*queue;
	bool			free;
	struct list_head	list;
};

struct fsl_qdma_list {
	struct list_head	dma_list;
};

struct fsl_qdma_queue {
	struct fsl_qdma_format	*virt_head;
	struct list_head	comp_used;
	struct list_head	comp_free;
	dma_addr_t		bus_addr;
	u32                     n_cq;
	u32			id;
	u32			count;
	struct fsl_qdma_format	*cq;
	void			*block_base;
};

struct fsl_qdma_comp {
	dma_addr_t              bus_addr;
	dma_addr_t              desc_bus_addr;
	void			*virt_addr;
	void			*desc_virt_addr;
	struct fsl_qdma_chan	*qchan;
	dma_call_back		call_back_func;
	void			*params;
	struct list_head	list;
};

struct fsl_qdma_engine {
	int			desc_allocated;
	void			*ctrl_base;
	void			*status_base;
	void			*block_base;
	u32			n_chans;
	u32			n_queues;
	int			error_irq;
	struct fsl_qdma_queue	*queue;
	struct fsl_qdma_queue	**status;
	struct fsl_qdma_chan	*chans;
	u32			num_blocks;
	int			block_offset;
};

static u64 pre_addr[CORE_NUMBER];
static u64 pre_queue[CORE_NUMBER];
static rte_atomic32_t wait_task[CORE_NUMBER];

#ifndef QDMA_MEMZONE
/* Array of memzone pointers */
static const struct rte_memzone *qdma_mz_mapping[RTE_MAX_MEMZONE];
/* Counter to track current memzone allocated */
static uint16_t qdma_mz_count;
#endif

#endif /* _FSL_QDMA_H_ */

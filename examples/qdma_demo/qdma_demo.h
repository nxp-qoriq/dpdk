/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2020 NXP
 */
#ifndef __QDMA_DEMO_H__
#define __QDMA_DEMO_H__

#define QDMA_MAX_HW_QUEUES_PER_CORE	1
#define QDMA_FLE_POOL_COUNT		8192
#define QDMA_MAX_VQS			128

#define TEST_PCIE_32B_WR 0

#define TEST_PCIE_READ 1
#define TEST_PCIE_32B 1

#if TEST_PCIE_READ
#define TEST_PCIE_READ_TIMES 10000000
#else /*write times*/
#define TEST_PCIE_READ_TIMES 100000000
#endif

#define PAGE_SIZE	(sysconf(_SC_PAGESIZE))
#define PAGE_MASK	(~(PAGE_SIZE - 1))

#define ULTRA_SHORT_FMT 1
#define USE_RBP 1
#define NO_RBP 0
#define LONG_FMT 0
#define PCI_TO_PCI 1
#define MEM_TO_PCI 2
#define PCI_TO_MEM 3
#define MEM_TO_MEM 4

#define TEST_DEQUEU_CNT 6
#define TEST_PACKETS_NUM (g_packet_num)
#define TEST_M_SIZE (4096)
#define TEST_PCI_SIZE_LIMIT (8*TEST_M_SIZE)
#define TEST_PCIBUS_BASE_ADDR (0x9060044000)
#define TEST_PCICPU_BASE_ADDR (0x0 + TEST_PCIBUS_BASE_ADDR)
#define TEST_PACKET_SIZE (g_packet_size)
#define TEST_LOCAL_MEM_SIZE_PERCORE (TEST_PACKET_SIZE * TEST_PACKETS_NUM)

#define LSINIC_QDMA_MAX_HW_QUEUES_PER_CORE	2
#define LSINIC_QDMA_FLE_POOL_QUEUE_COUNT	2048
#define LSINIC_QDMA_MAX_VQS			2048

#define MAX_CORE_COUNT	16

struct qdma_test_case {
	const char *name;
	const char *help;
	int id;
};
#define TEST_CASE_NAME_SIZE 30
#define ARG_PCI_ADDR (1 << 0)
#define ARG_SIZE (1 << 1)
#define ARG_TEST_ID (1 << 2)
#define ARG_LATENCY (1 << 3)
#define ARG_PCI_SIZE (1 << 4)
#define ARG_MEMCPY (1 << 5)
#define ARG_SCATTER_GATHER (1 << 6)
#define ARG_BURST (1 << 7)

#endif

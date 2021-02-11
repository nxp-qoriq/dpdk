# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2020-2021 NXP

# meson file, for building this example as part of a main DPDK build.
#
# To build this example as a standalone application with an already-installed
# DPDK instance, use 'make'

deps += ['ip_frag']

if dpdk_conf.has('RTE_LIBRTE_DPAA_PMD')
	deps += ['pmd_dpaa']
endif

# Enable experimental API flag as l2fwd uses rte_ethdev_set_ptype API
allow_experimental_apis = true
sources = files(
	'main.c'
)

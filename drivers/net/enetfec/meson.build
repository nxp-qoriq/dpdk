# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2021 NXP

if not is_linux
	build = false
	reason = 'only supported on linux'
endif

deps += ['common_dpaax']

sources = files('enet_ethdev.c',
		'enet_rxtx.c',
		'enet_uio.c')

if cc.has_argument('-Wno-pointer-arith')
	cflags += '-Wno-pointer-arith'
endif

# Driver uses below experimental APIs
# rte_mem_virt2memseg
allow_experimental_apis = true

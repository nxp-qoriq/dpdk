# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2023-2025 NXP

if not is_linux
    build = false
    reason = 'only supported on linux'
endif

if (arch_subdir != 'aarch64' and arch_subdir != 'arm')
    build = false
    reason = 'only supported on arm'
    subdir_done()
endif

deps += ['common_dpaax']
sources = files(
	'enetqos_ethdev.c',
	'enetqos_rxtx.c',
)

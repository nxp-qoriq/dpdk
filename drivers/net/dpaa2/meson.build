# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2018-2025 NXP

if not is_linux
    build = false
    reason = 'only supported on Linux'
endif

deps += ['mempool_dpaa2']
sources = files(
        'base/dpaa2_tlu_hash.c',
        'dpaa2_tm.c',
        'dpaa2_mux.c',
        'dpaa2_ethdev.c',
        'dpaa2_flow.c',
        'dpaa2_recycle.c',
        'dpaa2_rxtx.c',
        'dpaa2_ptp.c',
        'dpaa2_meter.c',
        'mc/dprtc.c',
        'mc/dpkg.c',
        'mc/dpdmux.c',
        'mc/dpni.c',
)

includes += include_directories('base', 'mc')

headers = files('rte_pmd_dpaa2.h')

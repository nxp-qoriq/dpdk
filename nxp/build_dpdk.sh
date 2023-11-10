#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2023 NXP

RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

silent=0        # If output is dumped to screen
logoutput=output.txt

execute () {

local cmd=$1
local bld=$2

print "================================================"
print "Executing ${cmd}"
if [ ${silent} -eq 1 ]; then
	${cmd} >> $logoutput
	${bld} >> $logoutput
else
	${cmd}
	${bld}
fi
if [ $? -ne 0 ]; then
	echo -e "Error in ${RED}${cmd}${NC}"
	#exit 1
else
	echo -e "Build OK ${BLUE}${cmd}${NC}"
fi
}

rm -rf arm64-build build
execute "meson arm64-build --cross-file config/arm/arm64_dpaa_linux_gcc -Dexamples=all --buildtype=release" "ninja -C arm64-build"
rm -rf arm64-build build
execute "meson build -Dwerror=true -Dexamples=all -Dbuildtype=debug" "ninja -C build"
rm -rf arm64-build build
execute "meson arm64-build --cross-file config/arm/arm64_armv8_linux_gcc -Dexamples=all --buildtype=release" "ninja -C arm64-build"
rm -rf arm64-build build
#execute "meson arm64-build --cross-file config/arm/arm64_armv8_linux_clang_ubuntu -Dexamples=all --buildtype=release" "ninja -C arm64-build"
rm -rf arm64-build build
#execute "meson arm64-build --cross-file config/arm/arm32_armv8_linux_gcc -Dexamples=all --buildtype=release " "ninja -C arm64-build"
rm -rf arm64-build build
execute "meson arm64-build --cross-file config/arm/arm64_dpaa_linux_gcc -Dexamples=all -Dbuildtype=debug -Denable_docs=true -Dcheck_includes=true" "ninja -C arm64-build"
rm -rf arm64-build build
meson arm64-build  --buildtype=release 	-Dexamples=all 	-Dc_args="-Ofast -fPIC -ftls-model=local-dynamic -DRTE_ENABLE_ASSERT=1 -DRTE_LIBRTE_IEEE1588=1 -DRTE_FORCE_INTRINSICS=1" -Doptimization=3 --cross-file=config/arm/arm64_dpaa_linux_gcc
ninja -C arm64-build

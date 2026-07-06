# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2026 NXP

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)


set(TOOLCHAIN_PATH
    "/usr/bin/arch64-none-linux-gnu"
    CACHE PATH "Path to the cross toolchain bin directory"
)

set(CMAKE_C_COMPILER   "${TOOLCHAIN_PATH}-gcc")
set(CMAKE_CXX_COMPILER "${TOOLCHAIN_PATH}-g++")
set(CMAKE_AR           "${TOOLCHAIN_PATH}-ar")
set(CMAKE_RANLIB       "${TOOLCHAIN_PATH}-ranlib")
set(CMAKE_STRIP        "${TOOLCHAIN_PATH}-strip")

# Optional but recommended if you have a target rootfs/sysroot
#set(CMAKE_SYSROOT /opt/toolchains/aarch64-linux-gnu/sysroot)

# Tell CMake where to search for target headers/libs
#set(CMAKE_FIND_ROOT_PATH ${CMAKE_SYSROOT})

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Optional target tuning (edit for your CPU)
set(CMAKE_C_FLAGS_INIT "-O3 -fPIC")
set(CMAKE_CXX_FLAGS_INIT "-O3 -fPIC")

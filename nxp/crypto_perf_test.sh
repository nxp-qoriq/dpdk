#!/bin/bash -i
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2018-2021 NXP

#usages are:
#./crypto_perf_test.sh dpaa2_sec

#########  Tunable parameters

ops_num=100000
test_type=throughput
#test_type=latency

cores=0x3
burst=32
#burst=1,8,32

buffer_size=64,128,256,512,1024,2048
#buffer_size=64

#logs=--log-level=8
logs=--log-level=3

silent=--silent
#csv_format=--csv-friendly
#others=--out-of-place
#segment=--segment-sz 200
extra_flags=$silent $csv_format

#default for dpaa_sec
vdev_string=
dev_string=crypto_dpaa_sec

count=0
failed=0

authonly=1
cipheronly=1
cipher_auth=1
aead=1
pdcp=1

pdcp_sn=12
pdcp_domain=control

logoutput="dpdk_${dev_string}_report.txt"
#logoutput="${logoutput}_"`date +%d%m%Y_%H%M%S`".txt"

function mycmd() {
	$@ | tee ${logoutput}
	if [ $? -ne 0 ]; then
		failed=$((failed+1))
	fi
	count=$((count+1))
}

if [ -v DPDK_EXAMPLE_PATH ]; then
	echo "dpdk example app path $DPDK_EXAMPLE_PATH"
#elif [ -d "/usr/local/bin" ];then
#	export DPDK_EXAMPLE_PATH=/usr/local/bin
#	echo "dpdk example app path $DPDK_EXAMPLE_PATH"
else
	export DPDK_EXAMPLE_PATH=$(pwd)
fi

if [ ! -e $DPDK_EXAMPLE_PATH/dpdk-test-crypto-perf ]; then
	echo -e "${DPDK_EXAMPLE_PATH}/dpdk-test-crypto-perf binary not available"
	echo -e "where DPDK_EXAMPLE_PATH is ${DPDK_EXAMPLE_PATH}"
	exit 1
fi

arg=1
if [[ ${!arg} == "dpaa_sec" ]]
then
	echo -e "=============== running dpaa_sec" | tee ${logoutput}
        vdev_string=
        dev_string=crypto_dpaa_sec
	logoutput="dpdk_${dev_string}_report.txt"
elif [[ ${!arg} == "dpaa2_sec" ]]
then
	echo -e "=============== running dpaa2_sec" | tee ${logoutput}
        vdev_string=
        dev_string=crypto_dpaa2_sec
	logoutput="dpdk_${dev_string}_report.txt"

elif [[ ${!arg} == "openssl" ]]
then
	echo -e "=============== running openssl" | tee ${logoutput}
        # for openssl
        vdev_string="--vdev crypto_openssl"
        dev_string=crypto_openssl
	logoutput="dpdk_${dev_string}_report.txt"

elif [[ ${!arg} == "armv8" ]]
then
	echo -e "=============== running armv8 crypto" | tee ${logoutput}
        vdev_string="--vdev crypto_armv8"
	dev_string=crypto_armv8
	logoutput="dpdk_${dev_string}_report.txt"
	authonly=0
	cipheronly=0
	aead=0
fi

if [ $authonly -ne 0 ]; then
	#auth algos
	echo "**********auth-only: md5-hmac" | tee ${logoutput}
	cmd="$DPDK_EXAMPLE_PATH/dpdk-test-crypto-perf -c $cores $vdev_string $logs -- --devtype $dev_string \
	--optype auth-only --auth-algo md5-hmac --auth-op generate --auth-key-sz 64 \
	--digest-sz 16 --ptest $test_type --total-ops $ops_num \
	--burst-sz $burst --buffer-sz $buffer_size $extra_flags"
	mycmd ${cmd}

	echo "**********auth-only: sha1-hmac" | tee ${logoutput}
	cmd="$DPDK_EXAMPLE_PATH/dpdk-test-crypto-perf -c $cores $vdev_string  $logs -- --devtype $dev_string \
	--optype auth-only --auth-algo sha1-hmac --auth-op generate --auth-key-sz 64 \
	--digest-sz 20 --ptest $test_type --total-ops $ops_num \
	--burst-sz $burst --buffer-sz $buffer_size  $extra_flags"
	mycmd ${cmd}

        echo "**********auth-only: sha2-224" | tee ${logoutput}
        cmd="$DPDK_EXAMPLE_PATH/dpdk-test-crypto-perf -c $cores $vdev_string  $logs -- --devtype $dev_string \
        --optype auth-only --auth-algo sha2-224-hmac --auth-op generate --auth-key-sz 64 \
        --digest-sz 28 --ptest $test_type --total-ops $ops_num \
        --burst-sz $burst --buffer-sz $buffer_size  $extra_flags"
        mycmd ${cmd}

        echo "**********auth-only: sha2-256" | tee ${logoutput}
        cmd="$DPDK_EXAMPLE_PATH/dpdk-test-crypto-perf -c $cores $vdev_string  $logs -- --devtype $dev_string \
        --optype auth-only --auth-algo sha2-256-hmac --auth-op generate --auth-key-sz 64 \
        --digest-sz 32 --ptest $test_type --total-ops $ops_num \
        --burst-sz $burst --buffer-sz $buffer_size  $extra_flags"
	mycmd ${cmd}

        echo "**********auth-only: sha2-384" | tee ${logoutput}
        cmd="$DPDK_EXAMPLE_PATH/dpdk-test-crypto-perf -c $cores $vdev_string  $logs -- --devtype $dev_string \
        --optype auth-only --auth-algo sha2-384-hmac --auth-op generate --auth-key-sz 128 \
        --digest-sz 48 --ptest $test_type --total-ops $ops_num \
        --burst-sz $burst --buffer-sz $buffer_size  $extra_flags"
	mycmd ${cmd}

        echo "**********auth-only: sha2-512" | tee ${logoutput}
        cmd="$DPDK_EXAMPLE_PATH/dpdk-test-crypto-perf -c $cores $vdev_string  $logs -- --devtype $dev_string \
        --optype auth-only --auth-algo sha2-512-hmac --auth-op generate --auth-key-sz 128 \
        --digest-sz 64 --ptest $test_type --total-ops $ops_num \
        --burst-sz $burst --buffer-sz $buffer_size  $extra_flags"
	mycmd ${cmd}
fi

# cipher alogs
if [ $cipheronly -ne 0 ]; then
        echo "**********cipher-only: aes-cbc" | tee ${logoutput}
        cmd="$DPDK_EXAMPLE_PATH/dpdk-test-crypto-perf -c $cores $vdev_string $logs -- --devtype $dev_string \
        --optype cipher-only --cipher-algo aes-cbc --cipher-op encrypt --cipher-key-sz 16 \
        --cipher-iv-sz 16   --ptest $test_type --total-ops $ops_num \
        --burst-sz $burst --buffer-sz $buffer_size  $extra_flags"
	mycmd ${cmd}

        echo "**********cipher-only: aes-ctr" | tee ${logoutput}
        cmd="$DPDK_EXAMPLE_PATH/dpdk-test-crypto-perf -c $cores $vdev_string $logs -- --devtype $dev_string \
        --optype cipher-only --cipher-algo aes-ctr --cipher-op encrypt --cipher-key-sz 16 \
        --cipher-iv-sz 16  --ptest $test_type --total-ops $ops_num \
        --burst-sz $burst --buffer-sz $buffer_size  $extra_flags"
	mycmd ${cmd}

        echo "**********cipher-only: 3des-cbc" | tee ${logoutput}
        cmd="$DPDK_EXAMPLE_PATH/dpdk-test-crypto-perf -c $cores $vdev_string $logs -- --devtype $dev_string \
        --optype cipher-only --cipher-algo 3des-cbc --cipher-op encrypt --cipher-key-sz 16 \
        --cipher-iv-sz 8  --ptest $test_type --total-ops $ops_num \
        --burst-sz $burst --buffer-sz $buffer_size  $extra_flags"
	mycmd ${cmd}
fi

#cipher - auth algos
if [ $cipher_auth -ne 0 ]; then
        echo "**********cipher-auth: aes-cbc-sha1" | tee ${logoutput}
        cmd="$DPDK_EXAMPLE_PATH/dpdk-test-crypto-perf -c $cores $vdev_string  $logs -- --devtype $dev_string \
        --optype cipher-then-auth --cipher-algo aes-cbc --cipher-op encrypt --cipher-key-sz 16 \
        --cipher-iv-sz 16 --auth-algo sha1-hmac --auth-op generate --auth-key-sz 64 \
        --digest-sz 20 --ptest $test_type --total-ops $ops_num \
        --burst-sz $burst --buffer-sz $buffer_size  $extra_flags"
	mycmd ${cmd}

        echo "**********cipher-auth: aes-cbc-sha2-224" | tee ${logoutput}
        cmd="$DPDK_EXAMPLE_PATH/dpdk-test-crypto-perf -c $cores $vdev_string  $logs -- --devtype $dev_string \
        --optype cipher-then-auth --cipher-algo aes-cbc --cipher-op encrypt --cipher-key-sz 16 \
        --cipher-iv-sz 16 --auth-algo sha2-224-hmac --auth-op generate --auth-key-sz 64 \
        --digest-sz 28 --ptest $test_type --total-ops $ops_num \
        --burst-sz $burst --buffer-sz $buffer_size  $extra_flags"
	mycmd ${cmd}

        echo "**********cipher-auth: aes-cbc-sha2-256" | tee ${logoutput}
        cmd="$DPDK_EXAMPLE_PATH/dpdk-test-crypto-perf -c $cores $vdev_string  $logs -- --devtype $dev_string \
        --optype cipher-then-auth --cipher-algo aes-cbc --cipher-op encrypt --cipher-key-sz 16 \
        --cipher-iv-sz 16 --auth-algo sha2-256-hmac --auth-op generate --auth-key-sz 64 \
        --digest-sz 32 --ptest $test_type --total-ops $ops_num \
        --burst-sz $burst --buffer-sz $buffer_size  $extra_flags"
	mycmd ${cmd}

        echo "**********cipher-auth: aes-cbc-sha2-384" | tee ${logoutput}
        cmd="$DPDK_EXAMPLE_PATH/dpdk-test-crypto-perf -c $cores $vdev_string  $logs -- --devtype $dev_string \
        --optype cipher-then-auth --cipher-algo aes-cbc --cipher-op encrypt --cipher-key-sz 16 \
        --cipher-iv-sz 16 --auth-algo sha2-384-hmac --auth-op generate --auth-key-sz 128 \
        --digest-sz 48 --ptest $test_type --total-ops $ops_num \
        --burst-sz $burst --buffer-sz $buffer_size  $extra_flags"
	mycmd ${cmd}

        echo "**********cipher-auth: aes-cbc-sha2-512" | tee ${logoutput}
        cmd="$DPDK_EXAMPLE_PATH/dpdk-test-crypto-perf -c $cores $vdev_string  $logs -- --devtype $dev_string \
        --optype cipher-then-auth --cipher-algo aes-cbc --cipher-op encrypt --cipher-key-sz 16 \
        --cipher-iv-sz 16 --auth-algo sha2-512-hmac --auth-op generate --auth-key-sz 128 \
        --digest-sz 64 --ptest $test_type --total-ops $ops_num \
        --burst-sz $burst --buffer-sz $buffer_size  $extra_flags"
	mycmd ${cmd}

        echo "**********cipher-auth: aes-ctr-sha1" | tee ${logoutput}
        cmd="$DPDK_EXAMPLE_PATH/dpdk-test-crypto-perf -c $cores $vdev_string  $logs -- --devtype $dev_string \
        --optype cipher-then-auth --cipher-algo aes-ctr --cipher-op encrypt --cipher-key-sz 16 \
        --cipher-iv-sz 16 --auth-algo sha1-hmac --auth-op generate --auth-key-sz 64 \
        --digest-sz 20 --ptest $test_type --total-ops $ops_num \
        --burst-sz $burst --buffer-sz $buffer_size  $extra_flags"
	mycmd ${cmd}

        echo "**********cipher-auth: 3des-cbc-sha1" | tee ${logoutput}
        cmd="$DPDK_EXAMPLE_PATH/dpdk-test-crypto-perf -c $cores $vdev_string  $logs -- --devtype $dev_string \
        --optype cipher-then-auth --cipher-algo 3des-cbc --cipher-op encrypt --cipher-key-sz 16 \
        --cipher-iv-sz 8 --auth-algo sha1-hmac --auth-op generate --auth-key-sz 64 --digest-sz 20 \
        --ptest $test_type --total-ops $ops_num \
        --burst-sz $burst --buffer-sz $buffer_size  $extra_flags"
	mycmd ${cmd}
fi

#aead algo gcm
if [ $aead -ne 0 ]; then
        echo "**********aead: aes-gcm" | tee ${logoutput}
        cmd="$DPDK_EXAMPLE_PATH/dpdk-test-crypto-perf -c $cores $vdev_string  $logs -- --devtype $dev_string \
        --optype aead --aead-algo aes-gcm --aead-op encrypt --aead-key-sz 16 --aead-iv-sz 12 \
        --aead-aad-sz 16 --digest-sz 16  --ptest $test_type --total-ops $ops_num \
        --burst-sz $burst --buffer-sz $buffer_size  $extra_flags"
	mycmd ${cmd}
fi

pdcp_cipher=(null aes-ctr snow3g-uea2 zuc-eea3)
pdcp_auth=(null aes-cmac snow3g-uia2 zuc-eia3)

#pdcp cases
if [ $pdcp -ne 0 ]; then
	for i in 0 1
	do
		if [ $i -ne 0 ]; then
			hfn_param=--pdcp-ses-hfn-en
		else
			hfn_param=
		fi

		for j in 0 1 2 3
		do
			for k in 0 1 2 3
			do
				echo "***pdcp $hfn_param : ${pdcp_cipher[$j]}- ${pdcp_auth[$k]}" | tee ${logoutput}
				cmd="$DPDK_EXAMPLE_PATH/dpdk-test-crypto-perf -c $cores $vdev_string $logs -- --devtype $dev_string \
				--optype pdcp --cipher-algo ${pdcp_cipher[$j]} --cipher-op encrypt \
				--auth-algo ${pdcp_auth[$k]} \
				--auth-op generate  --auth-key-sz 16 \
				--ptest $test_type --total-ops $ops_num --pdcp-sn-sz $pdcp_sn \
				--pdcp-domain $pdcp_domain $hfn_param \
				--burst-sz $burst --buffer-sz $buffer_size $extra_flags"
				echo "$cmd"
				mycmd ${cmd}
			done
		done


	done
fi

#pdcp sdap cases
if [ $pdcp -ne 0 ]; then
	for i in 0 1
	do
		if [ $i -ne 0 ]; then
			hfn_param=--pdcp-ses-hfn-en
		else
			hfn_param=
		fi

		for j in 0 1 2 3
		do
			for k in 0 1 2 3
			do
				echo "***pdcp sdap $hfn_param : ${pdcp_cipher[$j]}- ${pdcp_auth[$k]}" | tee ${logoutput}
				cmd="$DPDK_EXAMPLE_PATH/dpdk-test-crypto-perf -c $cores $vdev_string $logs -- --devtype $dev_string \
				--optype pdcp --cipher-algo ${pdcp_cipher[$j]} --cipher-op encrypt \
				--auth-algo ${pdcp_auth[$k]} \
				--auth-op generate  --auth-key-sz 16 \
				--ptest $test_type --total-ops $ops_num --pdcp-sn-sz $pdcp_sn \
				--pdcp-domain $pdcp_domain $hfn_param --enable-sdap\
				--burst-sz $burst --buffer-sz $buffer_size $extra_flags"
				echo "$cmd"
				mycmd ${cmd}
			done
		done


	done
fi

echo -e "===========================================" | tee ${logoutput}
echo -e "Total testcases run $count : failed $failed" | tee ${logoutput}
echo -e "Results available at ${logoutput}" | tee ${logoutput}
echo -e "===========================================" | tee ${logoutput}

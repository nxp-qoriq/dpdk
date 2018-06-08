#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2018 NXP

# Script for DPDK cmdif Demo application
#
# This scripts takes no arguments.
# This script performs the following operations:
# 1. Create an AIOP DPRC
#    AIOP DPRC contains 4 DPBPs, 2 DPCIs
# 2. Create an AIOP Tool DPRC
#    AIOP Tool DPRC contains 1 DPAIOP and 1 DPMCP
# 3. Create an Application DPRC
#    Application DPRC contains 1 DPNI, 1 DPMCP, 1 DPBP, 3 DPIO, 3 DPCONC
#    2 DPCI
#
# DPCIs of Application DPRC and AIOP DPRC are connected
# Using this script:
# 1. Run the script to create containers mentioned above
# 2. Run AIOP Tool for loading cmdif_integ_dbg image on AIOP (AIOP Tool DPRC)
# 3. Run dpdk cmdif_demo application on Application DPRC
#
#
# Assumptions:
#  - This script assumes that enough resources are available to create the
#    three DPRCs
#  - It is assumed that no DPAIOP exists in any of the existing DPRCs
#  - 'restool' binary is expected to be installed in searchable binary path;
#    This is designed for 'restool' version compatible with MC v9.0.2

############################################################################
# Globals
############################################################################
DEBUG=0
INFO=1

ac_DPRC=
atc_DPRC=
app_DPRC=

############################################################################
# Logging Routines
############################################################################
log_debug()
{
	if [ $DEBUG -eq 1 ]
	then
		echo $@
	fi
}

log_info()
{
	if [ $INFO -eq 1 ]
	then
		echo $@
	fi
}

log_error()
{
	echo $@
	exit 1
}

############################################################################
# Helper Routines
############################################################################
sleep_fn()
{
	sleep 1
}


check_error_and_exit()
{
	if [ $1 -ne 0 ]
	then
		log_error "Failure to execute last command. Unable to continue!"
	else
		sleep_fn
	fi
}

perform_hugepage_mount()
{
	HUGE=$(grep -E '/mnt/\<hugepages\>.*hugetlbfs' /proc/mounts)
	if [[ -z $HUGE ]]
	then
		mkdir /mnt/hugepages
		mount -t hugetlbfs none /mnt/hugepages
	else
		echo
		echo
		echo "Already mounted :  " $HUGE
		echo
	fi
}

perform_vfio_mapping()
{
	# Assuming argument has DPRC to bind
	log_info "Performing vfio mapping for $1"
	if [ "$1" == "" ]
	then
		log_debug "Incorrect usage: pass DPRC to bind"
	else
		if [ -e /sys/module/vfio_iommu_type1 ];
		then
			echo 1 > /sys/module/vfio_iommu_type1/parameters/allow_unsafe_interrupts
		else
			echo "NO VFIO Support available"
			exit
		fi
		echo vfio-fsl-mc > /sys/bus/fsl-mc/devices/$1/driver_override
		if [ $? -ne 0 ]
		then
			log_debug "No such DPRC (/sys/bus/fsl-mc/devices/ \
					$1/driver_override) exists."
			return
		fi
		echo $1 > /sys/bus/fsl-mc/drivers/vfio-fsl-mc/bind
	fi
}

#
# Core command to interface with restool
# has following format:
# restool_cmd <cmd line, without 'restool'> <return variable | None> <target dprc | None>
#  - cmd line should be without restool command itself. This is to make it flexible for
#    testing purpose (replace restool without 'echo', for e.g.)
#  - return variable is a pass by reference of a global which contains return value of
#    restool execution, for example, dprc.1. This can be useful if the caller needs the
#    object created for some future command
#  - target dprc, when passed, would assign the object created to that dprc
restool_cmd()
{
	if [ $# -ne 3 ]
	then
		# Wrong usage
		log_info "Wrong usage: <$@> : Missing args"
		log_error "Should be: restool_cmd <cmd line> <return | None> <target dprc | None>"
	fi

	local _var=''
	local _object=''
	local _cmdline=$1
	local _assignRes=

	log_debug "Executing: $_cmdline"
	_var=$(restool $_cmdline)
	check_error_and_exit $?

	# Assgining to passed variable
	_object=$(echo ${_var} | head -1 | cut -d ' ' -f 1)
	if [ "$2" != "None" ]
	then
		eval "$2=$(echo ${_var} | head -1 | cut -d ' ' -f 1)"
		log_debug "Created Object: $_object"
	fi

	# Assigning if target dprc is not None
	if [ "$3" != "None" ]
	then
		# Assigining to target dprc
		_assignRes=$(restool dprc assign dprc.1 --child=${!3} --object=$_object --plugged=1)
		log_info "Assigned $_object to ${!3}"
		check_error_and_exit $?
	fi
}

############################################################################
# Helper Routines
############################################################################
create_aiop_container()
{
	log_debug "Creating AIOP Container"
	ac_DPRC=
	restool_cmd "dprc create dprc.1 --options=DPRC_CFG_OPT_TOPOLOGY_CHANGES_ALLOWED,DPRC_CFG_OPT_SPAWN_ALLOWED,DPRC_CFG_OPT_ALLOC_ALLOWED,DPRC_CFG_OPT_AIOP,DPRC_CFG_OPT_OBJ_CREATE_ALLOWED,DPRC_CFG_OPT_IRQ_CFG_ALLOWED" ac_DPRC None
	log_info "Created AIOP Container: $ac_DPRC"

	log_debug "Creating DPBP1: restool dpbp create"
	restool_cmd "dpbp create" None ac_DPRC

	log_debug "Creating DPBP2: restool dpbp create"
	restool_cmd "dpbp create" None ac_DPRC

	log_debug "Creating DPBP3: restool dpbp create"
	restool_cmd "dpbp create" None ac_DPRC

	log_debug "Creating DPBP4: restool dpbp create"
	restool_cmd "dpbp create" None ac_DPRC

	log_debug "Creating DPCI1: restool dpci create --num-priorities=2"
	ac_DPCI1=
	restool_cmd "dpci create --num-priorities=2" ac_DPCI1 ac_DPRC
	log_info "Created $ac_DPCI1"

	log_debug "Creating DPCI2: restool dpci create --num-priorities=2"
	ac_DPCI2=
	restool_cmd "dpci create --num-priorities=2" ac_DPCI2 ac_DPRC
	log_info "Created $ac_DPCI2"

	echo "AIOP Container $ac_DPRC created"
} # AIOP Container

create_aiopt_container()
{
	log_debug "Creating AIOP Tool Container"
	atc_DPRC=
	restool_cmd "dprc create dprc.1 --options=DPRC_CFG_OPT_SPAWN_ALLOWED,DPRC_CFG_OPT_ALLOC_ALLOWED,DPRC_CFG_OPT_IRQ_CFG_ALLOWED" atc_DPRC None
	log_info "Created AIOP Tool Container: $atc_DPRC"

	# Check if the AIOP Tool Container exists or not
	if [ x"$ac_DPRC" == x"" ]
	then
		log_error "AIOP Container doesn't exist"
	fi
	log_debug "Creating DPAIOP Object"
	restool_cmd "dpaiop create --aiop-container=$ac_DPRC" None atc_DPRC

	log_debug "Creating DPAIOP Object"
	restool_cmd "dpmcp create" None atc_DPRC

	# Some future hack in case dpaiop is already part of root container
	# + some argument would be taken on command line and only unplug/plug
	# + would be done.
	#log_debug "Unplugging AIOP Object if it exists"
	#restool_cmd "dprc assign dprc.1 --child=dprc.1 --object=$DPAIOP1 --plugged=0"
	#log_info "Unplugged DPAIOP"

	echo "AIOP Tool Container $atc_DPRC created"
}

create_app_container()
{
	# Some MACROs which can be toggled
	# for DPNI
	ACTUAL_MAC="00:00:00:00:00:08"
	MAX_QUEUES=8
	#/* Supported boards and options*/
        if [ -e /sys/firmware/devicetree/base/compatible ]
        then
		board_type=`grep -ao '1088\|2088\|2080\|2085\|2160' /sys/firmware/devicetree/base/compatible | head -1`
        elif [ -e /sys/firmware/devicetree/base/model ]
        then
		board_type=`grep -ao '1088\|2088\|2080\|2085\|2160' /sys/firmware/devicetree/base/model | head -1`
        fi
	if [[ $board_type == "1088" ]]
	then
		export DPNI_OPTIONS=""
	elif [[ $board_type == "2080" || $board_type == "2085" || $board_type == "2088" ]]
	then
		export DPNI_OPTIONS="DPNI_OPT_HAS_KEY_MASKING"
	else
		echo "Invalid board type $board_type"
		exit
	fi
	MAX_TCS=1
	DPCON_PRIORITIES=2
	DPIO_PRIORITIES=2
	DPCI_PRIORITIES=2

	log_debug "Creating APP container"
	app_DPRC=
	restool_cmd "dprc create dprc.1 --label=\"AppContainer\" --options=DPRC_CFG_OPT_SPAWN_ALLOWED,DPRC_CFG_OPT_ALLOC_ALLOWED" app_DPRC None
	log_info "Created AIOP Container: $app_DPRC"

	export DPRC=$app_DPRC

	log_debug "Creating DPNI"
	restool_cmd "dpni create --options=$DPNI_OPTIONS \
				--num-tcs=$MAX_TCS \
				--num-queues=$MAX_QUEUES \
				" None app_DPRC
	# TODO: Not linking it with any DPMAC - this is dummy

	log_debug "Creating DPMCP"
	restool_cmd "dpmcp create" None app_DPRC

	log_debug "Creating DPBP Objects"
	restool_cmd "dpbp create" None app_DPRC
	#restool_cmd "dpbp create" None app_DPRC
	#restool_cmd "dpbp create" None app_DPRC

	log_debug "Creating DPCON Objects"
	restool_cmd "dpcon create --num-priorities=$DPCON_PRIORITIES" None app_DPRC
	restool_cmd "dpcon create --num-priorities=$DPCON_PRIORITIES" None app_DPRC
	restool_cmd "dpcon create --num-priorities=$DPCON_PRIORITIES" None app_DPRC

	log_debug "Creating DPIO Objects"
	restool_cmd "dpio create --channel-mode=DPIO_LOCAL_CHANNEL --num-priorities=$DPIO_PRIORITIES" None app_DPRC
	restool_cmd "dpio create --channel-mode=DPIO_LOCAL_CHANNEL --num-priorities=$DPIO_PRIORITIES" None app_DPRC
	restool_cmd "dpio create --channel-mode=DPIO_LOCAL_CHANNEL --num-priorities=$DPIO_PRIORITIES" None app_DPRC

	log_debug "Creating DPCI objects to connect with AIOP Container"
	app_DPCI1=
	app_DPCI2=
	restool_cmd "dpci create --num-priorities=$DPCI_PRIORITIES" app_DPCI1 app_DPRC
	restool_cmd "dpci create --num-priorities=$DPCI_PRIORITIES" app_DPCI2 app_DPRC
}

main()
{
	log_info "Creating AIOP Container"
	create_aiop_container
	log_info "----- Contents of AIOP Container: $ac_DPRC -----"
	restool dprc show $ac_DPRC
	log_info "-----"
	echo "===================================================="

	log_info "Creating AIOP Tool Container"
	create_aiopt_container
	log_info "----- Contents of AIOP Tool Container: $atc_DPRC -----"
	restool dprc show $atc_DPRC
	log_info "-----"
	echo "===================================================="

	log_info "Creating APP Container"
	create_app_container
	log_info "----- Contents of App Container: $app_DPRC -----"
	restool dprc show $app_DPRC
	log_info "-----"
	echo "===================================================="

	#
	# Connecting AIOP Container CI and Application Container CI
	# Assuming arguments passed are dpci
	if [ "$ac_DPCI1" != "" -a "$ac_DPCI2" != "" \
		-a "$app_DPCI1" != "" -a "$app_DPCI2" != "" ]
	then
		log_info "Connecting $app_DPCI1<->$ac_DPCI1, $app_DPCI2<->$ac_DPCI2"
		log_debug "Connecting $ac_DPCI1 and $app_DPCI1"
		restool_cmd "dprc connect dprc.1 --endpoint1=$ac_DPCI1 --endpoint2=$app_DPCI1" None None
		log_debug "Connecting $ac_DPCI2 and $app_DPCI2"
		restool_cmd "dprc connect dprc.1 --endpoint1=$ac_DPCI2 --endpoint2=$app_DPCI2" None None
	fi

	log_info "Performing VFIO mapping for AIOP Tool Container ($atc_DPRC)"
	sleep_fn
	perform_vfio_mapping $atc_DPRC

	log_info "Performing VFIO mapping for APP Container ($app_DPRC)"
	sleep_fn
	perform_vfio_mapping $app_DPRC

	perform_hugepage_mount

	echo "========== Summary ================================="
	echo " AIOP Container: $ac_DPRC"
	echo " AIOP Tool Container: $atc_DPRC"
	echo " Application Container: $app_DPRC"
	echo "===================================================="
}

main

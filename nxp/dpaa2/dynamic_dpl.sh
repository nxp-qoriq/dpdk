#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2018-2021 NXP

cat > script_help << EOF


script help :----->

	Run this script as
	". ./dynamic_dpl.sh -c my.conf dpmac.1 dpmac.2 -b ab:cd:ef:gh:ij:kl dpni-dpni dpni-self..."

	Acceptable arguments are dpni-dpni, dpni-self, dpmac.x, -c and -b
    -c [optional] = Specify conf file for device count, PARENT_DPRC etc.
		    check vm_dpdk.conf as an example.
		    If specified this shall be the first argument.

	dpni-dpni = This specify that 2 DPNIs object will be created,
		    which will be connected back to back.
		    dpni.x <-------connected----->dpni.y

		    If -b option is not given then MAC addresses will be like:

		    dpni.x = 00:00:00:00:02:I
		    dpni.y = 00:00:00:00:03:I
		    where I is the index of the argument "dpni-dpni".

	dpni-self = This specify that 1 DPNI object will be created,
		    which will be connected to itself.
		    dpni.x <-------connected----->dpni.x

		    If -b option is not given then MAC address will be as:

		    dpni.x = 00:00:00:00:04:I
		    where I is the index of the argument "dpni-self".

	     dpni = This specify that 1 DPNI object will be created,
		    which will be unconnect.
		    dpni.x ------------- UNCONNECTED

		    If -b option is not given then MAC address will be as:

		    dpni.x = 00:00:00:00:05:I
		    where I is the index of the argument "dpni".

	   dpni.x = This specify that 1 DPNI (dpni.y) object will be created,
		    which will be connected to dpni.x
		    dpni.y <-------connected----->dpni.x

		    If -b option is not given then MAC address will be as:

		    dpni.y = 00:00:00:00:06:I
		    where I is the index of the argument "dpni.y".

	  dpmac.x = This specify that 1 DPNI  (dpni.y) object will be created,
		    which will be connected to dpmac.x.
		    dpmac.x <-------connected----->dpni.y

                    '-b' option for dpmac is ignored. dpni.y connected to
                    dpmac.x is assumed to take hardware assigned (firmware)
                    MAC address when the DPNI is connected to Linux Container.
                    In other cases, the application is expected to use the MC
                    API (DPDK).

	By default, this script will create 16 DPBP, 10 DPIOs, 2 DPCIs, 8 DPCON, 8 DPSEC
	device and DPNIs depend upon the arguments given during command line.

	Note: Please refer to dynamic_dpl_logs file for script logs

     Optional configuration parameters:

	Below "ENVIRONMENT VARIABLES" are exported to get user defined
	configuration"
		ENABLE_ORDERED_QUEUE = enable this for ordering queue support
						Default is disabled.
						Only 2 DPNIs can be created in this mode.
						e.g. export ENABLE_ORDERED_QUEUE=1
	/**DPNI**:-->
		MAX_QUEUES         = max number of Rx/Tx Queues on DPNI.
					Set the parameter using below command:
					'export MAX_QUEUES=<Number of Queues>'
					where "Number of Queues" is an integer
					value "e.g export MAX_QUEUES=8"

		MAX_TCS             = maximum traffic classes for Rx/Tx both.
					Set the parameter using below command:
					'export MAX_TCS=<Num of traffic class>'
					where "Number of traffic classes" is an
					integer value. "e.g export MAX_TCS=8"

		MAX_CHANNELS	    = Maximum channels a DPNI supports.
					Set the parameter using below command:
					'export MAX_CHANNELS=<Num of channels>'
					Default value is 1.

		MAX_QOS             = maximum QoS Entries.
					Set the parameter using below command:
					'export MAX_QOS=<Num of QoS entries>'
					where "Number of QoS entries" is an
					integer value. "e.g export MAX_QOS=1"
					Default is set to 1.

		MAX_CGR             = maximum CGR Entries per DPNI
					Set the parameter using below command:
					'export MAX_CGR=<Num of CGR entries>'
					where "Number of CGR entries" is an
					integer value. "e.g export MAX_CGR=16"
					Default is set same as MAX_TCS.

		DPNI_NORMAL_BUF    = Change the mode to use normal buf mode.
					The default mode is high performance buffer mode.
					However there are limitation w.r.t total outstanding packets
					in queue with that mode (i.e. ~10K)
					So, it may be desired to disable the high performance mode.

		DPNI_OPTIONS        = DPNI related options.
					Set the parameter using below command:
					'export DPNI_OPTIONS="opt-1,opt-2,..."'
					e.g export DPNI_OPTIONS="DPNI_OPT_TX_FRM_RELEASE,DPNI_OPT_HAS_KEY_MASKING"

	/**DPCON**:-->
		DPCON_COUNT	    = DPCONC objects count
					Set the parameter using below command:
					'export DPCON_COUNT=<Num of dpconc objects>'
					where "Number of dpconc objects" is an
					integer value and greater than 2.
					e.g export DPCON_COUNT=10"

		DPCON_PRIORITIES    = number of priorities 1-8.
					Set the parameter using below command:
					'export DPCON_PRIORITIES=<Num of prio>'
					where "Number of priorities" is an
					integer value.
					e.g export DPCON_PRIORITIES=8."


	/**DPSECI**:-->
		DPSECI_COUNT        = DPSECI objects count
					Set the parameter using below command:
					'export DPSECI_COUNT=<Num of dpseci objects>'
					where "Number of dpseci objects" is an
					integer value.
					e.g export DPSECI_COUNT=4"

		DPSECI_QUEUES       = number of rx/tx queues.
					Set the parameter using below command:
					'export DPSECI_QUEUES=<Num of Queues>'
					where "Number of Queues" is an integer
					value "e.g export DPSECI_QUEUES=8".
					This shall be used together with
					DPSEC_PRIORITIES

		DPSECI_PRIORITIES   = num-queues priorities.
					Set the parameter using below command:
                                        'export DPSECI_PRIORITIES="Prio-1,Prio-2,..."'
                                        e.g export DPSECI_PRIORITIES="2,2,2,2,2,2,2,2"
					This shall be used together with DPSEC_QUEUES
	/**DPIO**:-->
		DPIO_COUNT	    = DPIO objects count
					Set the parameter using below command:
					'export DPIO_COUNT=<Num of dpio objects>'
					where "Number of dpio objects" is an
					integer value.
					e.g export DPIO_COUNT=10"

		DPIO_PRIORITIES     = number of  priority from 1-8.
					Set the parameter using below command:
                                        'export DPIO_PRIORITIES=<Num of prio>'
					where "Number of priorities" is an
					integer value.
					"e.g export DPIO_PRIORITIES=8"

	/**DPMCP**:-->
		DPMCP_COUNT	    = DPMCP objects count
					Set the parameter using below command:
					'export DPMCP_COUNT=<Num of MCportal objects>'
					where "Number of dpmcp objects" is an
					integer value.
					e.g export DPMCP_COUNT=1"

	/**DPBP**:-->
		DPBP_COUNT	    = DPBP objects count
					Set the parameter using below command:
					'export DPBP_COUNT=<Num of dpbp objects>'
					where "Number of dpbp objects" is an
					integer value.
					e.g export DPBP_COUNT=4"

	/**DPCI**:-->
		DPCI_COUNT	    = DPCI objects count for software queues
					Set the parameter using below command:
					'export DPCI_COUNT=<Num of dpci objects>'
					e.g export DPCI_COUNT=12"

		DPCI_PRIORITIES     = number of  priority from 1-2.
					Set the parameter using below command:
                                        'export DPCI_PRIORITIES=<Num of prio>'
					where "Number of priorities" is an
					integer value.
					"e.g export DPCI_PRIORITIES=1"

	/**DPDMAI**:-->
		DPDMAI_COUNT	    = DPDMAI objects count for QDMA device
					Set the parameter using below command:
					'export DPDMAI_COUNT=<Num of dpdmai objects>'
					e.g export DPDMAI_COUNT=2".
					By default there are 8 dpdmai object.

	/**DPRTC**:-->
		DPRTC_COUNT	    = DPRTC objects count for PTP (timesync)
					Only single instance of DPRTC supported
					'export DPRTC_COUNT=1'
					default value is 0.

	/**DPRC**:-->
		ENABLE_PL_BIT	    = DPRC PL BIT Enabled for RBP QDMA
					INIC RBP use case need PL bit to be
					enabeld.
					'export ENABLE_PL_BIT=1'
					default value is 0.

EOF


#/* Function, to intialize the DPNI related parameters
#*/
get_dpni_parameters() {
	if [[ -z "$BOARD_TYPE" ]]
	then
		if [ -e /sys/firmware/devicetree/base/compatible ]
		then
			board_type=`grep -ao '1088\|2088\|2080\|2085\|2160' /sys/firmware/devicetree/base/compatible | head -1`
		fi
		if [ -z "$board_type" ]
		then
			echo "Unable to find the board type!"
			echo "Please enter the board type! (Accepted board type keywords: 1088/2088/2085/2080/2160)"
			read board_type
		fi
	else
		board_type=${BOARD_TYPE}
	fi

	if [ \
	     $board_type != "1088" -a $board_type != "2080" -a \
	     $board_type != "2085" -a $board_type != "2088" -a \
	     $board_type != "2160" \
	   ]
	then
		echo "  Invalid board type ${board_type} specified."
		echo -n "  Only supported values are "
		echo "  1088|2080|2085|2088|2160."
		echo "  Not continuing ahead."
		return 1;
	fi

	echo "Using board type as ${board_type}"
	if [[ -z "$MAX_QUEUES" ]]
	then
		if [[ $board_type == "2160" ]]
		then
			MAX_QUEUES=16
		else
			MAX_QUEUES=8
		fi
	fi
	if [[ -z "$MAX_TCS" ]]
	then
		if [[ $board_type == "2160" ]]
		then
			MAX_TCS=16
		else
			MAX_TCS=8
		fi
	fi
	if [[ -z "$MAX_CHANNELS" ]]
	then
		MAX_CHANNELS=1
	fi

	if [[ -z "$MAX_CGS" ]]
	then
		MAX_CGS=`expr $MAX_QUEUES + 8`
	fi
	if [[ -z "$MAX_QOS" ]]
	then
		if [[ $board_type == "1088" || $board_type == "2080" || $board_type == "2085" ]]
		then
			MAX_QOS=1
		elif [[ $board_type == "2088" || $board_type == "2160" ]]
		then
			# Setting MAX_QOS to default value on LS2088 = 64, as per restool v1.5
			MAX_QOS=64
		fi
	fi
	if [[ -z "$DPNI_OPTIONS" ]]
	then
		#enable custom cgr to configure per queue cgr based taildrop
		DPNI_OPTIONS="DPNI_OPT_SINGLE_SENDER,DPNI_OPT_CUSTOM_CG"

		if [[ $board_type != "1088" ]]
		then
			DPNI_OPTIONS="$DPNI_OPTIONS,DPNI_OPT_HAS_KEY_MASKING"
		fi
		if [[ "$ENABLE_ORDERED_QUEUE" == "1" ]]
		then
			DPNI_OPTIONS="$DPNI_OPTIONS,DPNI_OPT_HAS_OPR,DPNI_OPT_OPR_PER_TC"
		fi
		NEWDPNI_OPTIONS=1
	fi
	if [[ -z "$DPNI_NORMAL_BUF" ]]
	then
		if [[ $board_type != "1088" ]]
		then
			DPNI_OPTIONS=$DPNI_OPTIONS,0x80000000
			echo "Using High Performance Buffers"
		fi
	else
		echo "Using Normal Performance Buffers"
	fi
	if [[ -z "$MAX_DIST_KEY_SIZE" ]]
	then
		MAX_DIST_KEY_SIZE=8
	fi
	if [[ -z "$FS_ENTRIES" ]]
	then
		FS_ENTRIES=1
	fi
	if [[ -z "$DPSECI_OPTIONS" ]]
	then
		DPSECI_OPTIONS="DPSECI_OPT_HAS_CG"
		if [[ "$ENABLE_ORDERED_QUEUE" == "1" ]]
		then
			DPSECI_OPTIONS="$DPSECI_OPTIONS,DPSECI_OPT_HAS_OPR,DPSECI_OPT_OPR_SHARED"
		fi
		NEWDPSECI_OPTIONS=1
	fi
	echo >> dynamic_dpl_logs
	echo  "DPNI parameters :-->" >> dynamic_dpl_logs
	echo -e "\tMAX_QUEUES = "$MAX_QUEUES >> dynamic_dpl_logs
	echo -e "\tMAX_TCS = "$MAX_TCS >> dynamic_dpl_logs
	echo -e "\tMAX_CGS = "$MAX_CGS >> dynamic_dpl_logs
	echo -e "\tDPNI_OPTIONS = "$DPNI_OPTIONS >> dynamic_dpl_logs
	echo -e "\tDPSECI_OPTIONS = "$DPSECI_OPTIONS >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs

}

#/* Function, to intialize the DPCON related parameters
#*/
get_dpcon_parameters() {
	if [[ "$DPCON_COUNT" ]]
	then
		if [[ $DPCON_COUNT -lt 3 ]]
		then
			echo -e "\tDPCON_COUNT value should be greater than 2" >> dynamic_dpl_logs
			echo -e $RED"\tDPCON_COUNT value should be greater than 2"$NC
			return 1;
		fi

	else
		DPCON_COUNT=8
	fi
	if [[ -z "$DPCON_PRIORITIES" ]]
	then
		DPCON_PRIORITIES=2
	fi
	echo "DPCON parameters :-->" >> dynamic_dpl_logs
	echo -e "\tDPCON_PRIORITIES	= "$DPCON_PRIORITIES >> dynamic_dpl_logs
	echo -e "\tDPCON_COUNT		= "$DPCON_COUNT >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
}

#/* Function, to initialize the DPMCP related parameters
#*/
get_dpmcp_parameters() {
	if [[ -z "$DPMCP_COUNT" ]]
	then
		DPMCP_COUNT=3
	fi
	echo "DPMCP parameters :-->" >> dynamic_dpl_logs
	echo -e "\tDPMCP_COUNT = "$DPMCP_COUNT >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
}

#/* Function, to intialize the DPBP related parameters
#*/
get_dpbp_parameters() {
	if [[ -z "$DPBP_COUNT" ]]
	then
		DPBP_COUNT=16
	fi
	echo "DPBP parameters :-->" >> dynamic_dpl_logs
	echo -e "\tDPBP_COUNT = "$DPBP_COUNT >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
}

#/* Function, to intialize the DPSECI related parameters
#*/
get_dpseci_parameters() {
	if [[ -z "$DPSECI_COUNT" ]]
	then
		if [[ $board_type == "2160" ]]
		then
			DPSECI_COUNT=16
		else
			DPSECI_COUNT=8
		fi
	fi
	if [[ -z "$DPSECI_QUEUES" ]]
	then
		DPSECI_QUEUES=2
	fi
	if [[ -z "$DPSECI_PRIORITIES" ]]
	then
		DPSECI_PRIORITIES="2,2"
	fi
	echo "DPSECI parameters :-->" >> dynamic_dpl_logs
	echo -e "\tDPSECI_COUNT = "$DPSECI_COUNT >> dynamic_dpl_logs
	echo -e "\tDPSECI_QUEUES = "$DPSECI_QUEUES >> dynamic_dpl_logs
	echo -e "\tDPSECI_PRIORITIES = "$DPSECI_PRIORITIES >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
}

#/* Function, to intialize the DPIO related parameters
#*/
get_dpio_parameters() {
	if [[ -z "$DPIO_COUNT" ]]
	then
		if [[ $board_type == "2160" ]]
		then
			DPIO_COUNT=34
		else
			DPIO_COUNT=18
		fi
	fi
	if [[ -z "$DPIO_PRIORITIES" ]]
	then
		DPIO_PRIORITIES=2
	fi
	echo "DPIO parameters :-->" >> dynamic_dpl_logs
	echo -e "\tDPIO_PRIORITIES = "$DPIO_PRIORITIES >> dynamic_dpl_logs
	echo -e "\tDPIO_COUNT = "$DPIO_COUNT >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
}

#/* Function, to intialize the DPCI related parameters
#*/
get_dpci_parameters() {
	if [[ -z "$DPCI_COUNT" ]]
	then
		DPCI_COUNT=2
	fi
	if [[ -z "$DPCI_PRIORITIES" ]]
	then
		DPCI_PRIORITIES=2
	fi
	if [[ "$ENABLE_ORDERED_QUEUE" == "1" ]]
	then
			DPCI_OPTIONS="DPCI_OPT_HAS_OPR,DPCI_OPT_OPR_SHARED"
	fi
	echo "DPCI parameters :-->" >> dynamic_dpl_logs
	echo -e "\tDPCI_PRIORITIES = "$DPCI_PRIORITIES >> dynamic_dpl_logs
	echo -e "\tDPCI_COUNT = "$DPCI_COUNT >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
}

#/* Function, to intialize the DPDMAI related parameters
#*/
get_dpdmai_parameters() {
	if [[ -z "$DPDMAI_COUNT" ]]
	then
		DPDMAI_COUNT=8
	fi
	echo "DPDMAI parameters :-->" >> dynamic_dpl_logs
	echo -e "\tDPDMAI_COUNT = "$DPDMAI_COUNT >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
}

#/* Function, to initialize the DPRTC related parameters
#*/
get_dprtc_parameters() {
	if [[ -z "$DPRTC_COUNT" ]]
	then
		DPRTC_COUNT=0
	fi
	echo "DPRTC parameters :-->" >> dynamic_dpl_logs
	echo -e "\tDPRTC_COUNT = "$DPRTC_COUNT >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
}

#/* function, to create the actual MAC address from the base address
#*/
create_actual_mac() {
	last_octet=$(echo $2 | head -1 | cut -f6 -d ':')
	last_octet=$(printf "%d" 0x$last_octet)
	last_octet=$(expr $last_octet + $1)
	last_octet=$(printf "%0.2x" $last_octet)
	if [[ 0x$last_octet -gt 0xFF ]]
        then
		last_octet=$(printf "%d" 0x$last_octet)
		last_octet=`expr $last_octet - 255`
		last_octet=$(printf "%0.2x" $last_octet)
	fi
	ACTUAL_MAC=$(echo $2 | sed -e 's/..$/'$last_octet'/g')
}

obj_assign() {
	restool dprc sync
	OBJ1=$1
	if [[ "$NESTED_DPRC" == "0" ]]
	then
		TEMP=$(restool dprc assign $DPRC --object=$OBJ1 --child=$DPRC --plugged=1)
		echo $OBJ "moved to plugged state" >> dynamic_dpl_logs
	else
		TEMP=$(restool dprc assign $DPRC --object=$OBJ1 --child=$DPRC --plugged=1)
		echo "\t" $OBJ1 "assigned to " $ROOT_DPRC "->" $PARENT_DPRC "->" $DPRC >> dynamic_dpl_logs
	fi
	restool dprc sync
}

#/* script's actual starting point
#*/
rm dynamic_dpl_logs > /dev/null 2>&1
rm dynamic_results > /dev/null 2>&1
unset BASE_ADDR
ROOT_DPRC=dprc.1
PARENT_DPRC=${ROOT_DPRC}
arg=1
if [[ ${!arg} == "-c" ]]
then
	echo -e "Using configuration file $2"
	source $2
	shift
	shift
fi
printf "%-21s %-21s %-25s\n" "Interface Name" "Endpoint" "Mac Address" > dynamic_results
printf "%-21s %-21s %-25s\n" "==============" "========" "==================" >> dynamic_results
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'
if [[ $1 ]]
then
	echo "parent - $PARENT_DPRC"
	if [[ "$ROOT_DPRC" = "$PARENT_DPRC" ]]
	then
		NESTED_DPRC=0
	else
		NESTED_DPRC=1
	fi

	echo "Available DPRCs" >> dynamic_dpl_logs
	restool dprc list >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
	#/*Option to enable PL bit for INIC RBP case*/
        DPRC_OPTIONS="DPRC_CFG_OPT_SPAWN_ALLOWED,DPRC_CFG_OPT_ALLOC_ALLOWED,DPRC_CFG_OPT_OBJ_CREATE_ALLOWED"
	#/*Option to enable PL bit for INIC RBP case*/
	if [[ "$ENABLE_PL_BIT" == "1" ]]
	then
		echo "Creating DPRC with PL Bit enabled for RBP usages"
		DPRC_OPTIONS="$DPRC_OPTIONS,DPRC_CFG_OPT_PL_ALLOWED"
	fi

	#/* Creation of DPRC*/
	if [[ "$NESTED_DPRC" = "0" ]]
	then
		echo "Creating Non nested DPRC"
		export DPRC=$(restool -s dprc create $ROOT_DPRC --label="DPDK Container" --options=$DPRC_OPTIONS,DPRC_CFG_OPT_IRQ_CFG_ALLOWED)
		if [[ "$NO_BIND_DPRC" = "1" ]]
		then
			DPRC_LOC=""
			DPRC_TO_BIND=""
		else
			DPRC_LOC=/sys/bus/fsl-mc/devices/$DPRC
			DPRC_TO_BIND=$DPRC
		fi
	else
		echo "Creating nested DPRC"
		export DPRC=$(restool -s dprc create $PARENT_DPRC --label="DPDK Container" --options=$DPRC_OPTIONS)
		DPRC_LOC=/sys/bus/fsl-mc/devices/$PARENT_DPRC
		DPRC_TO_BIND=$PARENT_DPRC
	fi

	echo "NEW DPRCs"
	restool dprc list

	echo $DPRC "Created" >> dynamic_dpl_logs

	#/*Validating the arguments*/
	echo >> dynamic_dpl_logs
	echo "Validating the arguments....." >> dynamic_dpl_logs
	num=1
	max=`expr $# + 1`
	while [[ $num != $max ]]
	do
		if [[ ${!num} == "-b" ]]
		then
			num=`expr $num + 1`
			BASE_ADDR=$(echo ${!num} | egrep "^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
			if [[ $BASE_ADDR ]]
			then
				echo >> dynamic_dpl_logs
				echo -e '\t'$BASE_ADDR" will be used as MAC's base address" >> dynamic_dpl_logs
				echo -e '\t'"But, in case of dpmac<->dpni, it would be ignored" >> dynamic_dpl_logs
				num=`expr $num + 1`
			else
				echo >> dynamic_dpl_logs
				echo -e "\tInvalid MAC base address" >> dynamic_dpl_logs
				echo >> dynamic_dpl_logs
				echo
				echo -e $RED"\tInvalid MAC base address"$NC
				echo
				restool dprc destroy $DPRC >> dynamic_dpl_logs
				echo >> dynamic_dpl_logs
				[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
			fi
			continue;
		fi
		TYPE=$(echo ${!num} | head -1 | cut -f1 -d '.')
		if [[ ${!num} != "dpni-dpni" && ${!num} != "dpni-self" && $TYPE != "dpmac" && $TYPE != "dpni" ]]
		then
			echo >> dynamic_dpl_logs
			echo -e "\tInvalid Argument \""${!num}"\"" >> dynamic_dpl_logs
			echo >> dynamic_dpl_logs
			echo
			echo -e $RED"\tInvalid Argument \""${!num}"\"" $NC
			echo
			restool dprc destroy $DPRC >> dynamic_dpl_logs
			cat script_help
			rm script_help
			echo
			[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
		fi
		num=`expr $num + 1`
	done

	#/* Getting parameters*/
	get_dpni_parameters
	RET=$?
	if [[ $RET == 1 ]]
	then
		restool dprc destroy $DPRC >> dynamic_dpl_logs
		echo
		[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
	fi

	get_dpcon_parameters
	RET=$?
	if [[ $RET == 1 ]]
	then
		restool dprc destroy $DPRC >> dynamic_dpl_logs
		echo
		[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
	fi

	get_dpmcp_parameters
	get_dpbp_parameters
	get_dpseci_parameters
	get_dpio_parameters
	get_dpci_parameters
	get_dpdmai_parameters
	get_dprtc_parameters
	RET=$?
	if [[ $RET == 1 ]]
	then
		restool dprc destroy $DPRC >> dynamic_dpl_logs
		echo
		[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
	fi

	#/* Objects creation*/
	num=1
	max=`expr $# + 1`
	PRINT_ONCE=0
	while [[ $num != $max ]]
	do
		echo >> dynamic_dpl_logs
		echo >> dynamic_dpl_logs
		echo "####### Parsing argument number "$num" ("${!num}") #######" >> dynamic_dpl_logs
		echo >> dynamic_dpl_logs
		MAC_OCTET2=0
		TYPE=$(echo ${!num} | head -1 | cut -f1 -d '.')
		if [[ ${!num} == "dpni-dpni" ]]
		then
			if [[ $BASE_ADDR ]]
			then
				mac_no=`expr $# + $num`
				create_actual_mac $mac_no $BASE_ADDR
			else
				ACTUAL_MAC="00:00:00:00:02:"$num
			fi
			OBJ=$(restool -s dpni create --options=$DPNI_OPTIONS --num-tcs=$MAX_TCS --num-queues=$MAX_QUEUES --fs-entries=$FS_ENTRIES --vlan-entries=16 --qos-entries=$MAX_QOS --num-cgs=$MAX_CGS --container=$DPRC)
			restool dprc sync
			restool dpni update $OBJ --mac-addr=$ACTUAL_MAC
			echo $OBJ "created with MAC addr = "$ACTUAL_MAC >> dynamic_dpl_logs
			MAC_ADDR1=$ACTUAL_MAC
			MAC_OCTET2=3
			MAC_OCTET1=$num
		elif [[ ${!num} == "dpni-self" ]]
		then
			MAC_OCTET2=4
			MAC_OCTET1=$num;
		elif [[ ${!num} == "dpni" ]]
		then
			MAC_OCTET2=5
			MAC_OCTET1=$num;
		elif [[ $TYPE == "dpni" ]]
		then
			MAC_OCTET2=6
			MAC_OCTET1=$num;
		else
			OBJ=${!num}
			MAC_OCTET1=$(echo $OBJ | head -1 | cut -f2 -d '.');
		fi
		# All except dpmac<->dpni support custom MAC through '-b' option
		if [[ ( $BASE_ADDR ) && ( $TYPE != "dpmac" ) ]]
		then
			create_actual_mac $num $BASE_ADDR
		else
			ACTUAL_MAC="00:00:00:00:"$MAC_OCTET2":"$MAC_OCTET1
			if [[ ( $BASE_ADDR ) && ( $PRINT_ONCE -eq 0 ) ]]
			then
				echo "WARN: '-b' option for DPMAC<->DPNI case not valid. Ignored!"
				PRINT_ONCE=1
			fi
		fi
		DPNI=$(restool -s dpni create --options=$DPNI_OPTIONS --num-tcs=$MAX_TCS --num-channels=$MAX_CHANNELS --num-queues=$MAX_QUEUES --fs-entries=$FS_ENTRIES --vlan-entries=16 --qos-entries=$MAX_QOS --num-cgs=$MAX_CGS --container=$DPRC)
		restool dprc sync
		restool dpni update $DPNI --mac-addr=$ACTUAL_MAC
		echo -e '\t'$DPNI "created with MAC addr = "$ACTUAL_MAC >> dynamic_dpl_logs
		export DPNI$num=$DPNI
		MAC_ADDR2=$ACTUAL_MAC
		if [[ $TYPE == "dpmac" ]]
		then
			echo -e "\tDisconnecting the" $OBJ", if already connected" >> dynamic_dpl_logs
			TEMP=$(restool dprc disconnect $ROOT_DPRC --endpoint=$OBJ > /dev/null 2>&1)
			TEMP=$(restool dprc connect $ROOT_DPRC --endpoint1=$DPNI --endpoint2=$OBJ 2>&1)
			CHECK=$(echo $TEMP | head -1 | cut -f2 -d ' ');
			if [[ $CHECK == "error:" ]]
			then
				echo -e "\tGetting error, trying to create the "$OBJ >> dynamic_dpl_logs
				OBJ_ID=$(echo $OBJ | head -1 | cut -f2 -d '.')
				TEMP=$(restool dpmac create --mac-id=$OBJ_ID 2>&1)
				CHECK=$(echo $TEMP | head -1 | cut -f2 -d ' ');
				if [[ $CHECK == "error:" ]]
				then
					echo -e "\tERROR: unable to create "$OBJ $NC >> dynamic_dpl_logs
					echo -e "\tDestroying container "$DPRC >> dynamic_dpl_logs
					echo -e $RED"\tERROR: unable to create "$OBJ $NC
					./destroy_dynamic_dpl.sh $DPRC >> dynamic_dpl_logs
					echo
					rm script_help
					[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
				fi
				restool dprc connect $ROOT_DPRC --endpoint1=$DPNI --endpoint2=$OBJ
			fi
			MAC_ADDR1=
			echo -e '\t'$OBJ" Linked with "$DPNI >> dynamic_dpl_logs
			restool dprc sync
			TEMP=$(restool dprc assign $DPRC --object=$DPNI --child=$DPRC --plugged=1)
			echo -e '\t'$DPNI "moved to plugged state " >> dynamic_dpl_logs
		elif [[ ${!num} == "dpni" ]]
		then
			restool dprc sync
			TEMP=$(restool dprc assign $DPRC --object=$DPNI --child=$DPRC --plugged=1)
			echo -e '\t'$DPNI "moved to plugged state" >> dynamic_dpl_logs
			MAC_ADDR1=
			OBJ=
		elif [[ $TYPE == "dpni" ]]
		then
			echo " printing the dpni ="${!num} >> dynamic_dpl_logs
			TEMP=$(restool dprc connect $ROOT_DPRC --endpoint1=$DPNI --endpoint2=${!num})
			echo -e '\t'$DPNI" Linked with "${!num} >> dynamic_dpl_logs
			restool dprc sync
			TEMP=$(restool dprc assign $DPRC --object=$DPNI --child=$DPRC --plugged=1)
			echo -e '\t'$DPNI "moved to plugged state" >> dynamic_dpl_logs
			MAC_ADDR1=
			OBJ=${!num}
		elif [[ ${!num} == "dpni-self" ]]
		then
			TEMP=$(restool dprc connect $ROOT_DPRC --endpoint1=$DPNI --endpoint2=$DPNI)
			echo -e '\t'$DPNI" Linked with "$DPNI >> dynamic_dpl_logs
			restool dprc sync
			TEMP=$(restool dprc assign $DPRC --object=$DPNI --child=$DPRC --plugged=1)
			echo -e '\t'$DPNI "moved to plugged state" >> dynamic_dpl_logs
			OBJ=$DPNI
			MAC_ADDR1=$MAC_ADDR2
			unset MAC_ADDR2
		else
			TEMP=$(restool dprc connect $ROOT_DPRC --endpoint1=$DPNI --endpoint2=$OBJ)
			echo -e '\t'$OBJ" Linked with "$DPNI >> dynamic_dpl_logs
			restool dprc sync
			TEMP=$(restool dprc assign $DPRC --object=$DPNI --child=$DPRC --plugged=1)
			echo -e '\t'$DPNI "moved to plugged state" >> dynamic_dpl_logs
			restool dprc sync
			TEMP=$(restool dprc assign $DPRC --object=$OBJ --child=$DPRC --plugged=1)
			echo -e '\t'$OBJ "moved to plugged state" >> dynamic_dpl_logs
		fi
		if [[ $MAC_ADDR1 ]]
		then
			if [[ $MAC_ADDR2 ]]
			then
				printf "%-21s %-21s %-25s\n" $DPNI $OBJ $MAC_ADDR2 >> dynamic_results
			fi
			printf "%-21s %-21s %-25s\n" $OBJ $DPNI $MAC_ADDR1 >> dynamic_results
		elif [[ $OBJ ]]
		then
			if [[ $TYPE != "dpmac" ]]
			then
				printf "%-21s %-21s %-25s\n" $DPNI $OBJ $MAC_ADDR2 >> dynamic_results
			else
				# for dpmac, MAC address is assigned by application
				message="-Dynamic-"
				echo -e '\t'$DPNI"<=>"$OBJ ": MAC address dynamically assigned by application" >> dynamic_dpl_logs
				printf "%-21s %-21s %-25s\n" $DPNI $OBJ $message >> dynamic_results
			fi
		else
			printf "%-21s %-21s %-25s\n" $DPNI "UNCONNECTED" $MAC_ADDR2 >> dynamic_results
		fi
		OBJ=
		num=`expr $num + 1`
		if [[ ${!num} == "-b" ]]
		then
			num=`expr $num + 2`
			continue;
		fi
	done
	echo >> dynamic_dpl_logs
	echo "******* End of parsing ARGS *******" >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs

	restool dprc sync

	#/* DPMCP objects creation*/
	for i in $(seq 1 ${DPMCP_COUNT}); do
		DPMCP=$(restool -s dpmcp create --container=$DPRC)
		echo $DPMCP "Created" >> dynamic_dpl_logs
		obj_assign $DPMCP
	done;

	#/* DPBP objects creation*/
	for i in $(seq 1 ${DPBP_COUNT}); do
		DPBP=$(restool -s dpbp create --container=$DPRC)
		echo $DPBP "Created" >> dynamic_dpl_logs
		obj_assign $DPBP
	done;

	#/* DPCON objects creation*/
	for i in $(seq 1 ${DPCON_COUNT}); do
		DPCON=$(restool -s dpcon create --num-priorities=$DPCON_PRIORITIES --container=$DPRC)
		echo $DPCON "Created" >> dynamic_dpl_logs
		obj_assign $DPCON
	done;

	#/* DPSECI objects creation*/
	for i in $(seq 1 ${DPSECI_COUNT}); do
		DPSEC=$(restool -s dpseci create --num-queues=$DPSECI_QUEUES --priorities=$DPSECI_PRIORITIES --options=$DPSECI_OPTIONS --container=$DPRC)
		echo $DPSEC "Created" >> dynamic_dpl_logs
		obj_assign $DPSEC
	done;

	#/* DPIO objects creation*/
	for i in $(seq 1 ${DPIO_COUNT}); do
		DPIO=$(restool -s dpio create --channel-mode=DPIO_LOCAL_CHANNEL --num-priorities=$DPIO_PRIORITIES --container=$DPRC)
		echo $DPIO "Created" >> dynamic_dpl_logs
		obj_assign $DPIO
	done;

	# Create DPCI's for software queues
	unset DPCI
	for i in $(seq 1 ${DPCI_COUNT}); do
		DPCI=$(restool -s dpci create --num-priorities=$DPCI_PRIORITIES --options=$DPCI_OPTIONS --container=$DPRC)
		echo $DPCI "Created" >> dynamic_dpl_logs
		obj_assign $DPCI
	done;

	# Create DPDMAI's for qDMA
	unset DPDMAI
	for i in $(seq 1 ${DPDMAI_COUNT}); do
		DPDMAI=$(restool -s dpdmai create --num-queues=8 --priorities=1,1 --container=$DPRC)
		echo $DPDMAI "Created" >> dynamic_dpl_logs
		obj_assign $DPDMAI
	done;

	# Create DPRTC's for timesync
	unset DPRTC
	for i in $(seq 1 ${DPRTC_COUNT}); do
		DPRTC=$(restool -s dprtc create --container=$DPRC)
		echo $DPRTC "Created" >> dynamic_dpl_logs
		obj_assign $DPRTC
	done;

	dmesg -D
	# Mount HUGETLB Pages first
	HUGE=$(grep -E '/dev/\<hugepages\>.*hugetlbfs' /proc/mounts)
	if [[ -z $HUGE ]]
	then
		mkdir -p /dev/hugepages
		mount -t hugetlbfs hugetlbfs /dev/hugepages
	else
		echo >> dynamic_dpl_logs
		echo >> dynamic_dpl_logs
		echo "Already mounted :  " $HUGE >> dynamic_dpl_logs
		echo >> dynamic_dpl_logs
	fi
	echo
	if [[ -e /sys/module/vfio_iommu_type1 ]];
	then
	        echo -e "\tAllow unsafe interrupts" >> dynamic_dpl_logs
	        echo 1 > /sys/module/vfio_iommu_type1/parameters/allow_unsafe_interrupts
	else
	        echo -e " Can't Run DPAA2 without VFIO support" >> dynamic_dpl_logs
	        echo -e $RED" Can't Run DPAA2 without VFIO support"$NC
		[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
	fi
	if [[ -e $DPRC_LOC ]];
	then
		echo vfio-fsl-mc > $DPRC_LOC/driver_override
		echo -e "\tBind "$DPRC_TO_BIND" to VFIO driver" >> dynamic_dpl_logs
		echo $DPRC_TO_BIND > /sys/bus/fsl-mc/drivers/vfio-fsl-mc/bind
		echo -e "Binding to VFIO driver is done" >> dynamic_dpl_logs
	fi
	dmesg -E

	echo -e "##################### Container $GREEN $DPRC $NC is created ####################"
	echo
	echo -e "Container $DPRC have following resources :=>"
	echo
	count=$(restool dprc show $DPRC | grep -c dpmcp.*)
	echo -e " * $count DPMCP"
	count=$(restool dprc show $DPRC | grep -c dpbp.*)
	echo -e " * $count DPBP"
	count=$(restool dprc show $DPRC | grep -c dpcon.*)
	echo -e " * $count DPCON"
	count=$(restool dprc show $DPRC | grep -c dpseci.*)
	echo -e " * $count DPSECI"
	count=$(restool dprc show $DPRC | grep -c dpni.*)
	echo -e " * $count DPNI"
	count=$(restool dprc show $DPRC | grep -c dpio.*)
	echo -e " * $count DPIO"
	count=$(restool dprc show $DPRC | grep -c dpci.*)
	echo -e " * $count DPCI"
	count=$(restool dprc show $DPRC | grep -c dpdmai.*)
	echo -e " * $count DPDMAI"
	count=$(restool dprc show $DPRC | grep -c dprtc.*)
	echo -e " * $count DPRTC"
	echo
	echo
	unset count
	echo -e "######################### Configured Interfaces #########################"
	echo
	cat dynamic_results
	echo >> dynamic_dpl_logs
	echo -e "USE " $DPRC " FOR YOUR APPLICATIONS" >> dynamic_dpl_logs
	rm script_help
	echo

else
	echo >> dynamic_dpl_logs
	echo -e "\tArguments missing" >> dynamic_dpl_logs
	echo
	echo -e '\t'$RED"Arguments missing"$NC
	cat script_help
	rm script_help
fi

if [[ "$NEWDPSECI_OPTIONS" == 1 ]]
then
	unset NEWDPSECI_OPTIONS
	unset DPSECI_OPTIONS
fi

if [[ "$NEWDPNI_OPTIONS" == 1 ]]
then
	unset NEWDPNI_OPTIONS
	unset DPNI_OPTIONS
fi

#!/bin/bash
#
#
# IPsum is a threat intelligence feed based on 30+ different publicly available lists of suspicious and/or malicious IP addresses. 
# All lists are automatically retrieved and parsed on a daily (24h) basis and the final result is pushed to this repository. 
# List is made of IP addresses together with a total number of (black)list occurrence (for each). 
# Greater the number, lesser the chance of false positive detection and/or dropping in (inbound) monitored traffic. 
# Also, list is sorted from most (problematic) to least occurent IP addresses.
# As an example, to get a fresh and ready-to-deploy auto-ban list of "bad IPs" that appear on at least 3 (black)lists you can run:
# ipsum=$(curl --compressed https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt 2>/dev/null | grep -v "#" | grep -v -E "\s[1-2]$" | cut -f 1)
#
#

#global variables 
declare INBOUNDS
declare IPSUM

function log() {
	local type=$1
	local message=$2
	local showlog=$3
	local t_stamp=$(date +%c)
	local prefix
	local color
	local clear_color='\e[0m'


	# Describe message style
	case $type in
		warning)
			prefix='[ALERT]	|'
			# bold text yellow color
			color='\e[1;33m'
			;;
		err)
			prefix='[ERROR]	|'
			# bold text red color
			color='\e[1;91m'
			;;
		info)
			prefix='[INFO]	|'
			# regular text regular color
			color='\e[0m'
			;;
		*)
			log err "Can't parse priority of message in systemd-cat program. Check man systemd-cat." yes
			exit 1
	esac
	# End of describing message style

	echo ${prefix} ${message} | systemd-cat -t "NetRomGoose" -p $type 
	
	# Also check need and show the logs in terminal 
	if [ -n "${showlog}" ] ; then
		echo -e "${t_stamp} ${color}${prefix} ${message}${clear_color}"
	fi
}

function check_user() {
	if [[ "${USER}" != root ]] ; then
		log err "This program should be run by root" yes
		exit 1
	fi 
	log info "Starting network goose module" yes
}

function gather_local_connections() {
	INBOUNDS=$(ss -4p | grep -v Address | awk -F' ' '{print $6}' | awk -F: '{print $1}' | sort | uniq)
	if [[ -z "${INBOUNDS}" ]]; then
		log err "Can't gather information about connections. Looks like Network is off" yes
		exit 1
	fi
}

function get_suspisious_IPs() {
	log info "Updating malicious IP addresses" yes
	IPSUM=$(\
		curl --compressed --connect-timeout 10 https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt 2>/dev/null \
		| grep -v "#" \
		| grep -v -E "\s[1]$" \
		| cut -f 1)
	if [[ -z "${IPSUM}" ]]; then
		log err "Can't recieve list with malicious IP addresses. Check connection to https://github.com/stamparm/ipsum" yes
		exit 1
	else
		log info "Update was succesfull complete. Received $(echo ${IPSUM} | tr " " "\n" | wc -l) malicious addresses." yes
	fi	
}

check_user 
get_suspisious_IPs

#
#~~for testing purposes~~
#IPSUM+=' 80.76.42.84'
#

while true
do
	gather_local_connections

	for con in $INBOUNDS; do

		if [[ -n $(grep $con <<< $IPSUM) ]]; then
				alert_program=$(ss -4p | grep "${con}" | awk -F' ' '{print $7}' | awk -F\" '{print $2}')
	 			alert_pid=$(ss -4p | grep "${con}" | awk -F' ' '{print $7}' | awk -F\, '{print $2}')
	 			log warning "Found suspicious connection to ${con} from ${alert_program} (${alert_pid}). Trying to kill it..." yes
	 			_=$(ss -K dst ${con})
	 			log warning "Connection to ${con} from ${alert_program} (${alert_pid}) was killed" yes
		fi
	done
sleep 5
done


#!/bin/bash
######################################################################
# Get train departures.
######################################################################

set -o errexit
set -o pipefail
set -o nounset

SCHEDULE_URL="https://rozklad-pkp.pl"
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"
COOKIE_FILE=$(mktemp /tmp/trains.XXXX)
DEPENDENCIES="jq xargs curl"

print_help() {
cat << EOF
Description:
	Fetch train connections from ${SCHEDULE_URL}.
Usage:
	$0 -s START -e END
Options:
	-s START	start station
	-e END		end station
	-d DATE		date of departure(%Y.%m.%d %H:%M)
EOF
}

exit_handler() {
	rm $COOKIE_FILE
}

do_curl() {
	curl -gsSL \
		-c "${COOKIE_FILE}" -b "${COOKIE_FILE}" \
		-H "User-Agent: ${USER_AGENT}" \
		-H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
		"$@"
}

get_station_id() {
	local location=$1
	do_curl -GX GET "${SCHEDULE_URL}/station/search" \
		--data-urlencode "term=${location}" \
		--data-urlencode "short=false" \
		| jq -r ".[0].value"
}

get_connections() {
	# ID of start station
	local start=$1
	# ID of end station
	local end=$2
	local departure_date=$3

	local day="" time=""
	if [ ! -z "$departure_date" ]; then
		day="$(date -d "$departure_date" +"%d.%m.%y")"
		time="$(date -d "$departure_date" +"%H:%M")"
	else
		day="$(date +"%d.%m.%y")"
		time="$(date +"%H:%M")"
	fi
	# Get direct connections
	do_curl -GX GET "${SCHEDULE_URL}/pl/tp" \
		--data-urlencode "queryPageDisplayed=yes" \
		--data-urlencode "REQ0JourneyStopsS0A=1" \
		--data-urlencode "REQ0JourneyStopsS0G=${start}" \
		--data-urlencode "REQ0JourneyStopsS0ID=" \
		--data-urlencode "REQ0JourneyStops1.0G=" \
		--data-urlencode "REQ0JourneyStopover1=" \
		--data-urlencode "REQ0JourneyStops2.0G=" \
		--data-urlencode "REQ0JourneyStopover2=" \
		--data-urlencode "REQ0JourneyStopsZ0A=1" \
		--data-urlencode "REQ0JourneyStopsZ0G=${end}" \
		--data-urlencode "REQ0JourneyStopsZ0ID=" \
		--data-urlencode "date=${day}" \
		--data-urlencode "dateStart=${day}" \
		--data-urlencode "dateEnd=${day}" \
		--data-urlencode "REQ0JourneyDate=${day}" \
		--data-urlencode "time=${time}" \
		--data-urlencode "REQ0JourneyTime=${time}" \
		--data-urlencode "REQ0HafasSearchForw=1" \
		--data-urlencode "existBikeEverywhere=yes" \
		--data-urlencode "existHafasAttrInc=yes" \
		--data-urlencode "existHafasAttrInc=yes" \
		--data-urlencode "REQ0JourneyProduct_prod_section_0_0=1" \
		--data-urlencode "REQ0JourneyProduct_prod_section_1_0=1" \
		--data-urlencode "REQ0JourneyProduct_prod_section_2_0=1" \
		--data-urlencode "REQ0JourneyProduct_prod_section_3_0=1" \
		--data-urlencode "REQ0JourneyProduct_prod_section_0_1=1" \
		--data-urlencode "REQ0JourneyProduct_prod_section_1_1=1" \
		--data-urlencode "REQ0JourneyProduct_prod_section_2_1=1" \
		--data-urlencode "REQ0JourneyProduct_prod_section_3_1=1" \
		--data-urlencode "REQ0JourneyProduct_prod_section_0_2=1" \
		--data-urlencode "REQ0JourneyProduct_prod_section_1_2=1" \
		--data-urlencode "REQ0JourneyProduct_prod_section_2_2=1" \
		--data-urlencode "REQ0JourneyProduct_prod_section_3_2=1" \
		--data-urlencode "REQ0JourneyProduct_prod_section_0_3=1" \
		--data-urlencode "REQ0JourneyProduct_prod_section_1_3=1" \
		--data-urlencode "REQ0JourneyProduct_prod_section_2_3=1" \
		--data-urlencode "REQ0JourneyProduct_prod_section_3_3=1" \
		--data-urlencode "REQ0JourneyProduct_opt_section_0_list=1:100000" \
		--data-urlencode "existOptimizePrice=1" \
		--data-urlencode "existHafasAttrExc=yes" \
		--data-urlencode "REQ0HafasChangeTime=0:1" \
		--data-urlencode "existSkipLongChanges=0" \
		--data-urlencode "REQ0HafasAttrExc=" \
		--data-urlencode "REQ0HafasAttrExc=" \
		--data-urlencode "REQ0HafasAttrExc=" \
		--data-urlencode "REQ0HafasAttrExc=" \
		--data-urlencode "REQ0HafasAttrExc=" \
		--data-urlencode "REQ0HafasAttrExc=" \
		--data-urlencode "REQ0HafasAttrExc=" \
		--data-urlencode "REQ0HafasAttrExc=" \
		--data-urlencode "REQ0HafasAttrExc=" \
		--data-urlencode "REQ0HafasAttrExc=" \
		--data-urlencode "REQ0HafasAttrExc=" \
		--data-urlencode "REQ0HafasAttrExc=" \
		--data-urlencode "existHafasAttrInc=yes" \
		--data-urlencode "existHafasAttrExc=yes" \
		--data-urlencode "wDayExt0=Pn|Wt|Śr|Cz|Pt|So|Nd" \
		--data-urlencode "start=start" \
		--data-urlencode "existUnsharpSearch=yes" \
		--data-urlencode "came_from_form=1"
}

main() {
	which $DEPENDENCIES >/dev/null || {
		echo "Missing some dependencies: ${DEPENDENCIES}" >&2
		exit 1
	}
	trap exit_handler EXIT
	local start="" end="" date=""
	while getopts ":hd:s:e:" opt; do
		case "$opt" in
		s)
			start="$OPTARG"
			;;
		e)
			end="$OPTARG"
			;;
		d)
			date="$OPTARG"
			;;
		h)
			print_help
			exit 0
			;;
		*)
			print_help >&2
			exit 1
			;;
		esac
	done
	[ -z "$start" ] && {
		echo "Missing -s option"
		print_help
		exit 1
	}
	[ -z "$end" ] && {
		echo "Missing -e option"
		print_help
		exit 1
	}
	# Get session
	do_curl "$SCHEDULE_URL" >/dev/null
	start="$(get_station_id "${start}")"
	end="$(get_station_id "${end}")"
	local response=""
	response="$(get_connections "$start" "$end" "$date" | tidy --wrap 0 2>/dev/null)" || {
		local ret=$?
		if [ $ret -ne 0 ] && [ $ret -ne 1 ]; then
			echo "Failed to prettify response" >&2
			exit 1
		fi
	}
	echo "$response" | sed -nE \
		-e 's/<td>([0-9]{2}\.[0-9]{2}\.[0-9]{2})<br><\/td>/\1/p' \
		-e 's/.*<span class=".*">Poznań Główny<\/span><span class=".*">Puszczykowo<\/span><span class=".*"><small>.*czas przejazdu:(.*)<\/small><\/span><\/td>/\1/p' \
		-e 's/.*Szczegóły połączenia - Poznań Główny - Puszczykowo ODJAZD (.*)<\/span><\/span><\/td>/\1/p' \
		| xargs -n3 echo \
	| while read connection; do
		local departure="" span="" day=""
		departure="$(echo "$connection" | cut -d\  -f 1)"
		span="$(echo "$connection" | cut -d\  -f 2)"
		day="$(echo "$connection" | cut -d\  -f 3)"
		echo -e "Day: ${day}\tDeparture: ${departure}\tTime: ${span}"
	done
}

main "$@"

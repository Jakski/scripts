#!/bin/bash
######################################################################
# Copyright (c) 2018 Jakub Pieńkowski
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
######################################################################
# Requirements:
# - bc (bc package in Debian 9)
# - tput (ncurses-bin package in Debian 9)
######################################################################

set -o pipefail
set -o errexit
set -o nounset

NO_TURBO_PATH=/sys/devices/system/cpu/intel_pstate/no_turbo
MAX_PERF_PATH=/sys/devices/system/cpu/intel_pstate/max_perf_pct
MIN_PERF_PATH=/sys/devices/system/cpu/intel_pstate/min_perf_pct
POLICY_PATH=/sys/devices/system/cpu/cpufreq

print_help() {
cat << EOF
Synopsis:
	Control Intel P-state driver.
Usage:
	$0 [OPTION]...
Options:
	-t, --turbo	TURBO	desired state of Intel Turbo Boost
				(1 - enabled, 0 - disabled)
	--min	MIN		minimum allowed performance percent
	--max	MAX		maximum allowed performance percent
	-d, --display		display current settings
	-h, --help		display this message
Author:
	Jakub Pieńkowski
EOF
}

setup_colors() {
	if [ -t 1 ]; then
		readonly RED=$(tput setaf 1)
		readonly GREEN=$(tput setaf 2)
		readonly RESET=$(tput sgr0)
	else
		readonly GREEN="" RED="" RESET=""
	fi
}

display_state() {
	local turbo=$(cat $NO_TURBO_PATH)
	if [ "$turbo" -eq 1 ]; then
		turbo="${RED}OFF${RESET}"
	else
		turbo="${GREEN}ON${RESET}"
	fi
	echo "Intel Turbo Boost: ${turbo}"
	echo "Maximum performance: $(cat $MAX_PERF_PATH)%"
	echo "Minimum performance: $(cat $MIN_PERF_PATH)%"
	local procnum=$(($(nproc) - 1))
	for cpu in $(seq ${procnum}); do
		freq=$(cat ${POLICY_PATH}/policy${cpu}/scaling_cur_freq)
		freq=$(echo "scale=2;${freq}/1000000" | bc)
		echo "CPU ${cpu} frequency: ${freq} GHz"
	done
}

validate_percent() {
	local pct=$1
	local msg="Performance percentage must be an integer between 1-100!"
	case "$pct" in
	""|*[!0-9]*)
		echo $msg >&2
		return 1
	esac
	if [ "$pct" -gt 100 ] || [ "$pct" -lt 1 ]; then
		echo $msg >&2
		return 1
	fi
}

main() {
	local do_display=""
	local temp=$(getopt -o "hdt:" -l "min:,max:,display,turbo:,help" -n "cpuopt" -- "$@") || {
		print_help >&2
		exit 1
	}
	if [ "${temp##* }" != "--" ] || [ $# -eq 0 ]; then
		print_help >&2
		exit 1
	fi
	eval set -- "$temp"
	unset temp
	setup_colors
	while true; do
		case "$1" in
		"-h"|"--help")
			print_help
			exit 0
		;;
		"-d"|"--display")
			# Defer display to end of program, after all changes
			# have been applied.
			do_display="yes"
			shift
		;;
		"-t"|"--turbo")
			if [ "$2" -eq 1 ]; then
				echo 0 > $NO_TURBO_PATH
			elif [ "$2" -eq 0 ]; then
				echo 1 > $NO_TURBO_PATH
			else
				print_help >&2
				exit 1
			fi
			shift 2
		;;
		"--min")
			validate_percent "$2"
			echo "$2" > $MIN_PERF_PATH
			shift 2
		;;
		"--max")
			validate_percent "$2"
			echo "$2" > $MAX_PERF_PATH
			shift 2
		;;
		"--")
			shift
			break
		;;
		*)
			echo "Internal error!" >&2
			exit 1
		;;
		esac
	done
	[ ! -z "$do_display" ] && display_state
}

main "$@"

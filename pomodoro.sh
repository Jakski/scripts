#!/usr/bin/env bash

set -o errexit
set -o errtrace
set -o pipefail
set -o nounset

WORK_TIME=""
BREAK_TIME=""
ERR_MSG=""

on_error() {
	local \
		exit_code=$? \
		cmd=$BASH_COMMAND
	if [ -n "$ERR_MSG" ]; then
		echo "$ERR_MSG" >&2
	else
		echo "Failing with code ${exit_code} at ${*} in command: ${cmd}" >&2
	fi
	exit "$exit_code"
}

main_help() {
cat << EOF
Synopsis:
	Pomodoro is a technique for dividing work-time into smaller, easier to
	manage parts. Purpose of doing so, is to prevent exhaustion and encourage
	short breaks to recover after effort. This script is meant to be run in
	background and inform user to start/stop break.
Options:
	-h|--help               Display this message.
	--work-time WTIME       Length of work session in minutes.
	--break-time BTIME      Length of break in minutes.
EOF
}

main_parse_args() {
	while [ "$#" != 0 ]; do
		case "$1" in
		--work-time)
			shift
			if [[ ! $1 =~ [0-9]+ ]]; then
				ERR_MSG="--work-time must be a non-negative integer number"
			fi
			WORK_TIME=$(("$1" * 60))
			shift
		;;
		--break-time)
			shift
			if [[ ! $1 =~ [0-9]+ ]]; then
				ERR_MSG="--break-time must be a non-negative integer number"
			fi
			BREAK_TIME=$(("$1" * 60))
			shift
		;;
		-h|--help)
			shift
			main_help
			exit 0
		;;
		*)
			shift
			main_help
			exit 1
		;;
		esac
	done
	[ -z "$WORK_TIME" ] && {
		ERR_MSG="Work time needs to be set."
		return 1
	}
	[ -z "$BREAK_TIME" ] && {
		ERR_MSG="Break time needs to be set."
		return 1
	}
	return 0
}

wait_for() {
	local name=$1 time=$2 current=0
	while [ "$current" != "$time" ]; do
		local \
			elapsed_minutes elapsed_seconds \
			session_minutes session_seconds
		elapsed_minutes=$(("$current" / 60))
		elapsed_seconds=$(("$current" % 60))
		session_minutes=$(("$time" / 60))
		session_seconds=$(("$time" % 60))
		tput clear
		echo -n "${name}: ${elapsed_minutes}m ${elapsed_seconds}s / "
		echo "${session_minutes}m ${session_seconds}s"
		sleep 1
		current=$(("$current" + 1))
	done
}

display_message() {
	local msg=$1
	notify-send "$msg"
	tmux display-message "$msg"
}

main() {
	trap 'on_error ${BASH_SOURCE[0]}:${LINENO}' ERR
	main_parse_args "$@"
	while true; do
		display_message "Work time begins"
		wait_for "Work time" "$WORK_TIME"
		display_message "Break time begins"
		wait_for "Break time" "$BREAK_TIME"
	done
}

main "$@"

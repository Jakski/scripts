#!/usr/bin/env bash
#shellcheck disable=SC2128
# SC2128: Expanding an array without an index only gives the first element.

set -euo pipefail -o errtrace
shopt -s inherit_errexit nullglob lastpipe

TEST_CONTAINER=""
#shellcheck disable=SC2034
SCRIPT_FILE=$(readlink -f "$0")
declare -a TEST_SUITES=()

on_error() {
	declare \
		cmd=$BASH_COMMAND \
		exit_code=$?
	if [ "$exit_code" != 0 ]; then
		echo "Failing with exit code ${exit_code} at ${*} in command: ${cmd}" >&2
	fi
	exit "$exit_code"
}

on_exit() {
	if [ -n "$TEST_CONTAINER" ]; then
		docker rm -f "$TEST_CONTAINER" > /dev/null || :
	fi
}

###
# Parse options as key-value pairs and output shell compatible declare statements.
get_options() {
	declare \
		keys \
		key \
		name \
		value \
		is_opt_found
	declare -a opts 
	read -r -a keys <<< "$1"
	shift
	opts=("$@")
	for key in "${keys[@]}"; do
		is_opt_found=0
		set -- "${opts[@]}"
		while [ "$#" != 0 ]; do
			name=$1
			value=$2
			shift 2
			if [ "$name" = "$key" ]; then
				is_opt_found=1
				break
			fi
		done
		if [ "$is_opt_found" = 0 ]; then
			value=""
		fi
		key=${key//-/_}
		key=$(printf "%q" "OPT_${key^^}")
		value=$(printf "%q" "$value")
		echo "declare ${key}=${value}"
	done
}

###
# Skip task in check mode.
check_do() {
	declare comment=$1
	shift
	if [ -n "$comment" ]; then
		echo "$comment"
	fi
	if [ "${CHECK_MODE:-0}" = 0 ]; then
		"$@"
	fi
}

###
# Ensure, that line exists in file. Add it to the end, if missing.
#
# Requirements:
#  - get_options
#  - module_file_content
module_line_in_file() {
	eval "$(get_options "path line state pattern" "$@")"
	: \
		"${OPT_STATE:=1}" \
		"${OPT_PATH:?}"
	if [ -z "$OPT_LINE" ] && [ -z "$OPT_PATTERN" ]; then
		echo "line or pattern must be provided" >&2
		return 1
	fi
	declare \
		src_line \
		merged_content
	declare -a \
		output_content=() \
		content=()
	if [ ! -f "$OPT_PATH" ] && [ "${CHECK_MODE:-0}" = 1 ]; then
		return 0
	fi
	mapfile -t content < "$OPT_PATH"
	for src_line in "${content[@]}"; do
		if
			{ [ -n "$OPT_LINE" ] && [ "$src_line" = "$OPT_LINE" ]; } \
			|| { [ -n "$OPT_PATTERN" ] && [[ $src_line =~ $OPT_PATTERN ]]; }
		then
			if [ "$OPT_STATE" = 1 ]; then
				return 0
			else
				continue
			fi
		fi
		output_content+=("$src_line")
	done
	if [ "$OPT_STATE" = 1 ]; then
		output_content+=("$OPT_LINE")
	fi
	merged_content=$(printf "%s\n" "${output_content[@]}")
	module_file_content \
		path "$OPT_PATH" \
		content "$merged_content"$'\n'
}

TEST_SUITES+=(test_line_in_file)
test_line_in_file() {
	echo -n "${FUNCNAME[0]} "
	declare image
	for image in debian alpine; do
		launch_container "$image"
		exec_container > /dev/null <<- "EOF"
			echo "line 1" > /test.txt
			echo "line 2" >> /test.txt
			echo "line 3" >> /test.txt
			module_line_in_file \
				path /test.txt \
				line "line 1"
			module_line_in_file \
				path /test.txt \
				line "another line 4"
			[ "$(wc -l < /test.txt)" = 4 ]
			module_line_in_file \
				path /test.txt \
				line "line 3" \
				state 0
			[ "$(wc -l < /test.txt)" = 3 ]
			module_line_in_file \
				path /test.txt \
				pattern "^line" \
				state 0
			[ "$(wc -l < /test.txt)" = 1 ]
		EOF
		remove_container
	done
	echo "ok"
}

###
# Ensure, that file has mode, group or owner.
#
# Requirements:
# - get_options
# - check_do
module_file_permissions() {
	eval "$(get_options "mode owner group path" "$@")"
	: "${OPT_PATH:?}"
	declare -a details
	if [ ! -e "$OPT_PATH" ] && [ "${CHECK_MODE:-0}" = 1 ]; then
		return 0
	fi
	mapfile -t details <<< "$(stat -c "%u"$'\n'"%g"$'\n'"%a" "$OPT_PATH")"
	if [ -n "$OPT_OWNER" ]; then
		if [[ ! "$OPT_OWNER" =~ ^[[:digit:]]+$ ]]; then
			OPT_OWNER=$(id -u "$OPT_OWNER")
		fi
		if [ "${details[0]}" != "$OPT_OWNER" ]; then
			check_do "Set ${OPT_PATH} owner to ${OPT_OWNER}" \
				chown "$OPT_OWNER" "$OPT_PATH"
		fi
	fi
	if [ -n "$OPT_GROUP" ]; then
		if [[ ! "$OPT_GROUP" =~ ^[[:digit:]]+$ ]]; then
			OPT_GROUP=$(id -g "$OPT_GROUP")
		fi
		if [ "${details[1]}" != "$OPT_GROUP" ]; then
			check_do "Set ${OPT_PATH} group to ${OPT_OWNER}" \
				chgrp "$OPT_GROUP" "$OPT_PATH"
		fi
	fi
	if [ -n "$OPT_MODE" ] && [ "$OPT_MODE" != "${details[2]}" ]; then
		check_do "Set ${OPT_PATH} mode to ${OPT_MODE}" \
			chmod "$OPT_MODE" "$OPT_PATH"
	fi
}

TEST_SUITES+=(test_file_permissions)
test_file_permissions() {
	echo -n "${FUNCNAME[0]} "
	declare image
	for image in debian alpine; do
		launch_container "$image"
		exec_container > /dev/null <<- "EOF"
			touch /test.txt
			chown 1 /test.txt
			chmod 777 /test.txt
			module_file_permissions \
				path /test.txt \
				mode 222 \
				owner 2 \
				group 2
			[ "$(stat -c "%u %g %a" /test.txt)" = "2 2 222" ]
		EOF
		remove_container
	done
	echo "ok"
}

###
# Ensure, that file has content.
#
# Requirements:
# - get_options
# - check_do
module_file_content() {
	eval "$(get_options "path content" "$@")"
	: \
		"${OPT_PATH:?}" \
		"${OPT_CONTENT:?}"
	declare \
		delta="" \
		old_umask
	if [ ! -f "$OPT_PATH" ]; then
		old_umask=$(umask)
		umask 0077
		check_do "Create file ${OPT_PATH}" \
			touch "$OPT_PATH"
		umask "$old_umask"
		if [ "${CHECK_MODE:-0}" != 0 ]; then
			return 0
		fi
	fi
	delta=$(diff <(echo -n "$OPT_CONTENT") "$OPT_PATH") || {
		if [ "$?" != 1 ]; then
			return $?
		fi
	}
	if [ -n "$delta" ]; then
		echo "File ${OPT_PATH} changed:"$'\n'"$delta"
		if [ "${CHECK_MODE:-0}" = 0 ]; then
			echo -n "$OPT_CONTENT" > "$OPT_PATH"
		fi
	fi
}

TEST_SUITES+=(test_file_content)
test_file_content() {
	echo -n "${FUNCNAME[0]} "
	declare image
	for image in debian alpine; do
		launch_container "$image"
		exec_container > /dev/null <<- "EOF"
			module_file_content \
				path /test.txt \
				content "test"
			[ "$(stat -c "%a" /test.txt)" = "600" ]
			[ "$(cat /test.txt)" = "test" ]
			content="test1"$'\n'"test"$'\n'"test2"
			module_file_content \
				path /test.txt \
				content "$content"
			[ "$(cat /test.txt)" = "$content" ]
		EOF
		remove_container
	done
	echo "ok"
}

###
# Ensure, that APT package is installed.
#
# Requirements:
# - get_options
module_apt_packages() {
	eval "$(get_options "names state" "$@")"
	: \
		"${OPT_NAMES:?}" \
		"${OPT_STATE:=1}"
	declare -a \
		pending=() \
		packages=() \
		present=() \
		options=()
	declare \
		old_debian_frontend=${DEBIAN_FRONTEND:-} \
		is_installed \
		package \
		present_package \
		action
	export DEBIAN_FRONTEND=noninteractive
	dpkg-query -f '${db:Status-Abbrev} ${Package} ${Version}\n' -W | mapfile -t present
	read -r -a packages <<< "$OPT_NAMES"
	for package in "${packages[@]}"; do
		is_installed=0
		for present_package in "${present[@]}"; do
			if [[ ${present_package} =~ ^.i[[:space:]]+${package}[[:space:]] ]]; then
				is_installed=1
				break
			fi
		done
		if [ "$OPT_STATE" != "$is_installed" ]; then
			pending+=("$package")
		fi
	done
	if [ "${CHECK_MODE:-0}" = 0 ]; then
		options+=("-y")
	else
		options+=("-qq" "--simulate" "-o" "APT::Get::Show-User-Simulation-Note=no")
	fi
	if [ "$OPT_STATE" = 1 ]; then
		action="install"
	else
		action="remove"
	fi
	if [ "${#pending[@]}" != 0 ]; then
		apt-get "$action" "${options[@]}" "${pending[@]}"
	fi
	if [ -z "$old_debian_frontend" ]; then
		unset DEBIAN_FRONTEND
	else
		export DEBIAN_FRONTEND=$old_debian_frontend
	fi
}

TEST_SUITES+=(test_apt_packages)
test_apt_packages() {
	echo -n "${FUNCNAME[0]} "
	launch_container "debian"
	exec_container > /dev/null <<- "EOF"
		dpkg-query -s eatmydata &>/dev/null && exit 1 || :
		module_apt_packages \
			names "eatmydata bash"
		dpkg-query -s eatmydata &>/dev/null
		module_apt_packages \
			names "eatmydata" \
			state 0
		dpkg-query -s eatmydata &>/dev/null && exit 1 || :
	EOF
	remove_container
	echo "ok"
}

###
# Ensure, that APT repository exists.
#
# Requirements:
# - get_options
# - check_do
# - module_file_content
# - module_file_permissions
module_apt_repository() {
	eval "$(get_options "\
		name \
		url \
		suites \
		components \
		architectures \
		keyring_url \
		keyring_armored \
		types \
		update \
	" "$@")"
	: \
		"${OPT_NAME:?}" \
		"${OPT_URL:?}" \
		"${OPT_SUITES:?}" \
		"${OPT_COMPONENTS:?}" \
		"${OPT_KEYRING_URL:?}"
	declare \
		delta="" \
		repository_file \
		keyring_file \
		content
	repository_file="/etc/apt/sources.list.d/${OPT_NAME}.sources"
	keyring_file="/usr/share/keyrings/${OPT_NAME}-archive-keyring.gpg"
	if [ -z "$OPT_ARCHITECTURES" ]; then
		OPT_ARCHITECTURES=$(dpkg --print-architecture)
	fi
	mapfile -d "" content <<- EOF
		Types: ${OPT_TYPES:-"deb"}
		URIs: ${OPT_URL}
		Suites: ${OPT_SUITES}
		Architectures: ${OPT_ARCHITECTURES}
		Components: ${OPT_COMPONENTS}
		Signed-By: ${keyring_file}
	EOF
	delta=$(module_file_content path "$repository_file" content "$content")
	module_file_permissions \
		path "$repository_file" \
		mode "644"
	if [ -n "$delta" ]; then
		echo "$delta"
	fi
	if [ ! -e "$keyring_file" ]; then
		if [ "${CHECK_MODE:-0}" = 1 ]; then
			echo "Create keyring ${keyring_file}"
		elif [ "${OPT_KEYRING_ARMORED:-0}" = 1 ]; then
			wget -q -O - "$OPT_KEYRING_URL" | gpg --dearmor > "$keyring_file"
		else
			wget -q -O  "$keyring_file" "$OPT_KEYRING_URL"
		fi
	fi
	if [ "${OPT_UPDATE:-1}" = 1 ] && [ -n "$delta" ]; then
		check_do "Update APT repositories" \
			apt-get update
	fi
}

TEST_SUITES+=(test_apt_repository)
test_apt_repository() {
	echo -n "${FUNCNAME[0]} "
	launch_container "debian"
	exec_container > /dev/null <<- "EOF"
		source /etc/os-release
		module_apt_repository \
			name nodesource \
			url "https://deb.nodesource.com/node_18.x" \
			keyring_url "https://deb.nodesource.com/gpgkey/nodesource.gpg.key" \
			keyring_armored 1 \
			suites "$VERSION_CODENAME" \
			components main
		# TODO: Ensure, that package from a new repository can be installed.
		[ -e /etc/apt/sources.list.d/nodesource.sources ]
		[ -e /usr/share/keyrings/nodesource-archive-keyring.gpg ]
	EOF
	remove_container
	echo "ok"
}

###
# Mark APT packages as held.
#
# Requirements:
# - get_options
# - check_do
module_apt_hold() {
	eval "$(get_options "names state" "$@")"
	: \
		"${OPT_NAMES:?}" \
		"${OPT_STATE:=1}"
	declare -a \
		pending=() \
		present=() \
		packages=()
	declare \
		package \
		is_held \
		present_package \
		action
	dpkg-query -f '${db:Status-Abbrev} ${Package} ${Version}\n' -W | mapfile -t present
	read -r -a packages <<< "$OPT_NAMES"
	for package in "${packages[@]}"; do
		is_held=0
		for present_package in "${present[@]}"; do
			if [[ ${present_package} =~ ^h.[[:space:]]+${package}[[:space:]] ]]; then
				is_held=1
				break
			fi
		done
		if [ "$OPT_STATE" != "$is_held" ]; then
			pending+=("$package")
		fi
	done
	if [ "$OPT_STATE" = 1 ]; then
		action="hold"
	else
		action="unhold"
	fi
	if [ "${#pending[@]}" != 0 ]; then
		check_do "${action^} APT packages: ${pending[*]}" \
			apt-mark  "$action" "${pending[@]}"
	fi
}

TEST_SUITES+=(test_apt_hold)
test_apt_hold() {
	echo -n "${FUNCNAME[0]} "
	launch_container "debian"
	exec_container > /dev/null <<- "EOF"
		package="bash"
		status=$(apt-mark showhold "$package")
		[ -z "$status" ]
		module_apt_hold \
			names "$package"
		status=$(apt-mark showhold "$package")
		[ "$status" = "$package" ]
		module_apt_hold \
			names "$package" \
			state 0
		status=$(apt-mark showhold "$package")
		[ -z "$status" ]
	EOF
	remove_container
	echo "ok"
}

###
# Setup NodeJS.
#
# Requirements:
# - get_options
# - module_apt_repository
# - module_apt_packages
module_nodejs() {
	eval "$(get_options "version" "$@")"
	: "${OPT_VERSION:?}"
	declare codename
	{
		#shellcheck disable=SC1091
		source /etc/os-release
		echo "$VERSION_CODENAME"
	} | read -r codename
	module_apt_repository \
		name nodesource \
		url "https://deb.nodesource.com/node_${OPT_VERSION}.x" \
		keyring_url "https://deb.nodesource.com/gpgkey/nodesource.gpg.key" \
		keyring_armored 1 \
		suites "$codename" \
		components main
	module_apt_packages names nodejs
}

###
# Setup Yarn.
#
# Requirements:
# - module_apt_repository
# - module_apt_packages
module_yarn() {
	module_apt_repository \
		name yarn \
		url "https://dl.yarnpkg.com/debian/" \
		keyring_url "https://dl.yarnpkg.com/debian/pubkey.gpg" \
		keyring_armored 1 \
		suites stable \
		components main
	module_apt_packages names yarn
}

###
# Ensure, that systemd service is in defined state.
#
# Requirements:
# - get_options
module_systemd_service() {
	eval "$(get_options "name active enabled" "$@")"
	: "${OPT_NAME:?}"
	declare \
		enabled \
		enable_cmd \
		activated \
		active_cmd
	if [ -n "$OPT_ENABLED" ]; then
		enabled=1
		systemctl is-enabled "$OPT_NAME" &> /dev/null || enabled=0
		if [ "$OPT_ENABLED" = 1 ]; then
			enable_cmd="enable"
		else
			enable_cmd="disable"
		fi
		if [ "$enabled" != "$OPT_ENABLED" ]; then
			check_do "${enable_cmd^} ${OPT_NAME}" \
				systemctl "$enable_cmd" "$OPT_NAME"
		fi
	fi
	if [ -n "$OPT_ACTIVE" ]; then
		activated=1
		systemctl is-active "$OPT_NAME" &> /dev/null || activated=0
		if [ "$OPT_ACTIVE" = 1 ]; then
			active_cmd="start"
		else
			active_cmd="stop"
		fi
		if [ "$activated" != "$OPT_ACTIVE" ]; then
			check_do "${active_cmd^} ${OPT_NAME}" \
				systemctl "$active_cmd" "$OPT_NAME"
		fi
	fi
}

TEST_SUITES+=(test_systemd_service)
test_systemd_service() {
	echo -n "${FUNCNAME[0]} "
	launch_container "debian"
	exec_container > /dev/null <<- "EOF"
		declare -a INVOCATIONS=()
		systemctl() {
			INVOCATIONS+=("$*")
			case "$1" in
			is-active)
				return "$ACTIVATED_RETURN"
			;;
			is-enabled)
				return "$ENABLED_RETURN"
			;;
			esac
		}
		ACTIVATED_RETURN=0
		ENABLED_RETURN=0
		module_systemd_service \
			name "test" \
			active 1
		[ "${INVOCATIONS[0]}" = "is-active test" ]
		[ "${#INVOCATIONS[@]}" = 1 ]
		INVOCATIONS=()
		ACTIVATED_RETURN=0
		ENABLED_RETURN=1
		module_systemd_service \
			name "test" \
			active 0 \
			enabled 1
		[ "${INVOCATIONS[0]}" = "is-enabled test" ]
		[ "${INVOCATIONS[1]}" = "enable test" ]
		[ "${INVOCATIONS[2]}" = "is-active test" ]
		[ "${INVOCATIONS[3]}" = "stop test" ]
		[ "${#INVOCATIONS[@]}" = 4 ]
	EOF
	remove_container
	echo "ok"
}

###
# Record command for later invocation.
add_handler() {
	declare \
		cmd="" \
		arg \
		handler
	if [ -z "${HANDLERS:-}" ]; then
		declare -g -a HANDLERS=()
	fi
	for arg in "$@"; do
		cmd="${cmd} $(printf "%q" "$arg")"
	done
	cmd=${cmd# }
	for handler in "${HANDLERS[@]}"; do
		if [ "$handler" = "$cmd" ]; then
			return 0
		fi
	done
	HANDLERS+=("$cmd")
}

###
# Run recorder tasks.
flush_handlers() {
	declare handler
	for handler in "${HANDLERS[@]}"; do
		eval "$handler"
	done
	HANDLERS=()
}

TEST_SUITES+=(test_handlers)
test_handlers() {
	echo -n "${FUNCNAME[0]} "
	launch_container "debian"
	exec_container > /dev/null <<- "EOF"
		add_handler touch /test1.txt
		add_handler touch /test2.txt
		flush_handlers
		[ -e /test1.txt ]
		[ -e /test2.txt ]
		rm /test1.txt /test2.txt
		add_handler touch /test3.txt
		flush_handlers
		[ -e /test3.txt ]
		rm /test3.txt
	EOF
	remove_container
	echo "ok"
}

launch_container() {
	declare image="modules:${1}"
	TEST_CONTAINER="modules-test-${RANDOM}"
	docker run \
		--detach \
		--name "$TEST_CONTAINER" \
		"$image" \
		> /dev/null
}

remove_container() {
	docker rm -f "$TEST_CONTAINER" > /dev/null
	TEST_CONTAINER=""
}

#shellcheck disable=SC2120
exec_container() {
	cat "$SCRIPT_FILE" - | docker exec \
		--interactive \
		"$TEST_CONTAINER" \
		/bin/bash -c "TEST_MODULES=1; source /dev/stdin"
}

build_images() {
	declare -a dockerfile
mapfile -d "" -t dockerfile <<EOF
FROM debian:stable

ENV PATH=/usr/local/bin:/usr/local/sbin:/bin:/sbin:/usr/bin:/usr/sbin
ENV SVDIR=/etc/service

RUN apt-get update && apt-get install -y \
	apt-utils \
	wget \
	gpg \
	bash \
	openssh-server \
	openssh-client \
	jq \
	findutils \
	sudo \
	curl  \
	nano \
	rsync \
	ncurses-bin \
	runit

ENTRYPOINT ["/usr/bin/runsvdir", "-P", "/etc/service"]
EOF
	if ! docker image inspect "modules:debian" &> /dev/null; then
		docker build -t "modules:debian" -f - . <<< "$dockerfile"
		echo
	fi
mapfile -d "" -t dockerfile <<EOF
FROM alpine:latest

ENV PATH=/usr/local/bin:/usr/local/sbin:/bin:/sbin:/usr/bin:/usr/sbin
ENV SVDIR=/etc/service

RUN apk add \
	bash \
	openssh-server \
	openssh-client \
	jq \
	findutils \
	sudo \
	curl  \
	nano \
	rsync \
	ncurses \
	runit \
	&& mkdir -p /etc/service/sshd \
	&& echo "#!/bin/sh" > /etc/service/sshd/run \
	&& echo "exec 2>&1" >> /etc/service/sshd/run \
	&& echo "exec /usr/sbin/sshd -D -e" >> /etc/service/sshd/run \
	&& chmod +x /etc/service/sshd/run

ENTRYPOINT ["/sbin/runsvdir", "-P", "/etc/service"]
EOF
	if ! docker image inspect "modules:alpine" &> /dev/null; then
		docker build -t "modules:alpine" -f - . <<< "$dockerfile"
		echo
	fi
}

main() {
	trap 'on_error "${BASH_SOURCE[0]}:${LINENO}"' ERR
	trap on_exit EXIT
	declare \
		test_suite \
		selected_suite
	if [ "${TEST_MODULES:-0}" = 1 ]; then
		return 0
	fi
	build_images
	shellcheck "$SCRIPT_FILE"
	for test_suite in "${TEST_SUITES[@]}"; do
		if [ "$#" = 0 ]; then
			"$test_suite"
			continue
		fi
		for selected_suite in "$@"; do
			if [ "$selected_suite" = "$test_suite" ]; then
				"$test_suite"
				continue
			fi
		done
	done
}

main "$@"

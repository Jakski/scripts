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

module_line_in_file() {
	eval "$(get_options "path line" "$@")"
	declare \
		content \
		src_line
	if [ ! -f "$OPT_PATH" ] && [ "${CHECK_MODE:-0}" = 1 ]; then
		return 0
	fi
	mapfile -t content < "$OPT_PATH"
	for src_line in "${content[@]}"; do
		if [ "$src_line" = "$OPT_LINE" ]; then
			return 0
		fi
	done
	echo "Add line to ${OPT_PATH}:"$'\n'"  ${OPT_LINE}"
	if [ "${CHECK_MODE:-0}" = 0 ]; then
		echo "$OPT_LINE" >> "$OPT_PATH"
	fi
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
				line "line 4"
			[ "$(wc -l < /test.txt)" = 4 ]
		EOF
		remove_container
	done
	echo "ok"
}

module_file_permissions() {
	eval "$(get_options "mode owner group path" "$@")"
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

module_file_content() {
	eval "$(get_options "path content" "$@")"
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

module_apt_packages() {
	eval "$(get_options "names" "$@")"
	declare -a \
		pending=() \
		packages=() \
		present=() \
		options=()
	declare \
		old_debian_frontend=${DEBIAN_FRONTEND:-} \
		is_installed \
		package \
		present_package
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
		if [ "$is_installed" = 0 ]; then
			pending+=("$package")
		fi
	done
	if [ "${CHECK_MODE:-0}" = 0 ]; then
		options+=("-y")
	else
		options+=("-qq" "--simulate" "-o" "APT::Get::Show-User-Simulation-Note=no")
	fi
	if [ "${#pending[@]}" != 0 ]; then
		apt-get install "${options[@]}" "${pending[@]}"
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
			names "eatmydata perl"
		dpkg-query -s eatmydata &>/dev/null
	EOF
	remove_container
	echo "ok"
}

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
		check_do "" apt-get update
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

module_apt_hold() {
	eval "$(get_options "names" "$@")"
	declare -a \
		pending=() \
		present=() \
		packages=()
	declare \
		package \
		is_held \
		present_package
	dpkg-query -f '${db:Status-Abbrev} ${Package} ${Version}\n' -W | mapfile -t present
	read -r -a packages <<< "$OPT_NAMES"
	for package in "${packages[@]}"; do
		is_held=0
		for present_package in "${present[@]}"; do
			if [[ ${present_package} =~ ^h.[[:space:]]+${package}[[:space:]] ]]; then
				is_installed=1
				break
			fi
			if [ "$is_held" = 0 ]; then
				pending+=("$package")
			fi
		done
	done
	if [ "${#pending[@]}" != 0 ]; then
		check_do "Hold APT packages: ${pending[*]}" \
			apt-mark hold "${pending[@]}"
	fi
}

TEST_SUITES+=(test_apt_hold)
test_apt_hold() {
	echo -n "${FUNCNAME[0]} "
	launch_container "debian"
	exec_container > /dev/null <<- "EOF"
		status=$(apt-mark showhold perl)
		[ -z "$status" ]
		module_apt_hold \
			names "perl"
		status=$(apt-mark showhold perl)
		[ "$status" = "perl" ]
	EOF
	remove_container
	echo "ok"
}

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
	declare test_suite
	if [ "${TEST_MODULES:-0}" = 1 ]; then
		return 0
	fi
	build_images
	shellcheck "$SCRIPT_FILE"
	for test_suite in "${TEST_SUITES[@]}"; do
		"$test_suite"
	done
}

main "$@"

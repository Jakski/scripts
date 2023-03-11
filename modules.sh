#!/usr/bin/env bash
###############################################################################
# Reusable Bash functions.
# Some variables have special meaning:
#   - REQUIREMENTS - Associative array with function dependencies.
#   - HANDLERS - Array with queued operations.
#   - HANDLED_ERROR - Set, if error has been already handled in some trap.
###############################################################################

set -eEuo pipefail
shopt -s inherit_errexit nullglob lastpipe

TEST_CONTAINER=""
#shellcheck disable=SC2035
SCRIPT_FILE=$(readlink -f "$0")
declare -a TEST_SUITES=()
declare -A REQUIREMENTS=()

on_exit() {
	declare \
		cmd=$BASH_COMMAND \
		exit_code=$? \
		i=0 \
		line=""
	declare -a \
		all_functions=() \
		parts
	if [ "$exit_code" != 0 ] && [ "${HANDLED_ERROR:-}" != 1 ]; then
		echo "Process ${BASHPID} exited with code ${exit_code} in command: ${cmd}" 1>&2
		while true; do
			line=$(caller "$i") || break
			echo "  ${line}" 1>&2
			i=$((i + 1))
		done
		HANDLED_ERROR=1
		HANDLED_ERROR=1
	fi
	declare -F | mapfile -t all_functions
	for i in "${all_functions[@]}"; do
		if [[ $i =~ declare[[:space:]]-f[[:space:]]on_exit_[^[:space:]]+$ ]]; then
			read -r -a parts <<< "$i"
			"${parts[2]}"
		fi
	done
	exit "$exit_code"
}

on_error() {
	declare \
		cmd=$BASH_COMMAND \
		exit_code=$? \
		i=0 \
		line=""
	echo "Process ${BASHPID} exited with code ${exit_code} in command: ${cmd}" 1>&2
	while true; do
		line=$(caller "$i") || break
		echo "  ${line}" 1>&2
		i=$((i + 1))
	done
	HANDLED_ERROR=1
	HANDLED_ERROR=1
	exit "$exit_code"
}

on_exit_remove_container() {
	if [ -n "${TEST_CONTAINER:-}" ]; then
		docker rm -f "$TEST_CONTAINER" > /dev/null || :
	fi
}

###
# Export command as a standalone script with error handling.
REQUIREMENTS["export_command"]="export_functions"
export_command() {
	declare -a \
		functions=(
			on_exit
			on_error
			add_handler
			flush_handlers
			get_options
			check_do
		) \
		args=() \
		output
	declare \
		in_args=0 \
		arg1
	mapfile -d "" output <<EOF
#!/usr/bin/env bash
set -eEuo pipefail
shopt -s inherit_errexit nullglob lastpipe
if [ ! -v REQUIREMENTS ]; then
	declare -A REQUIREMENTS=()
fi
EOF
	echo -n "$output"
	while [ "$#" != 0 ]; do
		arg1=$1
		shift
		if [ "$in_args" = 1 ]; then
			args+=("$arg1")
		else
			case "$arg1" in
			-v|--with-variable)
				declare -p "$1"
				shift
				;;
			-f|--with-function)
				functions+=("$1")
				shift
				;;
			*)
				if [ "$arg1" = "--" ]; then
					in_args=1
				else
					args+=("$arg1")
				fi
				;;
			esac
		fi
	done
	if [[ ${args[0]:-} =~ ^[a-zA-Z] ]] && declare -f "${args[0]}" >/dev/null; then
		functions+=("${args[0]}")
	fi
	export_functions "${functions[@]}"
	echo "trap on_error ERR"
	echo "trap on_exit EXIT"
	echo "declare CHECK_MODE=${CHECK_MODE:-0}"
	printf "%q " "${args[@]}"
}

TEST_SUITES+=("test_export_command")
test_export_command() {
	echo -n "${FUNCNAME[0]} "
	declare image
	for image in debian alpine rockylinux; do
		launch_container "$image"
		exec_container > /dev/null <<- "EOF"
			REQUIREMENTS["fn1"]="fn2"
			fn1() {
				echo "$*"
				fn2
				fn3
			}
			fn2() {
				echo "$VAR"
			}
			fn3() {
				echo "fn3"
			}
			declare VAR=qwerty
			declare -a lines
			export_command -v VAR -f fn3 fn1 qwe rty \
				| source /dev/stdin \
				| mapfile -t lines
			[ "${lines[0]}" = "qwe rty" ]
			[ "${lines[1]}" = "qwerty" ]
			[ "${lines[2]}" = "fn3" ]
		EOF
		remove_container
	done
	echo "ok"
}

###
# Pipe script into shell started as a different user.
REQUIREMENTS["become"]="export_command"
become() {
	declare user=$1
	shift
	export_command "$@" | sudo -u "$user" /bin/bash -
}


TEST_SUITES+=("test_become")
test_become() {
	echo -n "${FUNCNAME[0]} "
	declare image
	for image in debian alpine rockylinux; do
		launch_container "$image"
		exec_container > /dev/null <<- "EOF"
			mkdir /test
			chown daemon:daemon /test
			become daemon module_file_content \
				path /test/test.txt \
				content "hello world"$'\n'
			[ "$(stat -c "%U %G" /test/test.txt)" = "daemon daemon" ]
			rm -rf /test
		EOF
		remove_container
	done
	echo "ok"
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
		key=${key//-/_}
		key=$(printf "%q" "OPT_${key^^}")
		if [ "$is_opt_found" = 0 ]; then
			echo "declare ${key}"
		else
			value=$(printf "%q" "$value")
			echo "declare ${key}=${value}"
		fi
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
# Ensure, that symlink exists and points to destination.
REQUIREMENTS["module_symlink"]="get_options check_do"
module_symlink() {
	eval "$(get_options "src dest" "$@")"
	declare src=""
	if [ -L "$OPT_DEST" ]; then
		src=$(readlink "$OPT_DEST")
	elif [ -e "$OPT_DEST" ]; then
		echo "Destination exists and is not a symbolic link" >&2
		return 1
	fi
	if [ "$src" != "$OPT_SRC" ]; then
		check_do "Create symbolic link from ${OPT_DEST} to ${OPT_SRC}" \
			ln -Tsf "$OPT_SRC" "$OPT_DEST"
	fi
}

TEST_SUITES+=(test_symlink)
test_symlink() {
	echo -n "${FUNCNAME[0]} "
	declare image
	for image in debian alpine rockylinux; do
		launch_container "$image"
		exec_container > /dev/null <<- "EOF"
			module_symlink \
				src /test1.txt \
				dest /test.txt
			src=$(readlink -f /test.txt)
			[ "$src" = "/test1.txt" ]
			ln -Tsf /test2.txt /test.txt
			module_symlink \
				src /test1.txt \
				dest /test.txt
			[ "$src" = "/test1.txt" ]
			rm -f /test.txt
			touch /test.txt
			failed=0
			module_symlink \
				src /test1.txt \
				dest /test.txt \
				2>/dev/null \
				|| { failed=1; }
			[ "$failed" = 1 ]
		EOF
		remove_container
	done
	echo "ok"
}

###
# Ensure, that line exists in file. Add it to the end, if missing.
REQUIREMENTS["module_line_in_file"]="get_options module_file_content"
module_line_in_file() {
	eval "$(get_options "path line state pattern" "$@")"
	[ -v OPT_STATE ] || OPT_STATE=1
	if [ ! -v OPT_LINE ] && [ ! -v OPT_PATTERN ]; then
		echo "line or pattern must be provided" >&2
		return 1
	fi
	declare \
		src_line \
		merged_content \
		is_found
	declare -a \
		output_content=() \
		content=()
	if [ ! -f "$OPT_PATH" ] && [ "${CHECK_MODE:-0}" = 1 ]; then
		return 0
	fi
	mapfile -t content < "$OPT_PATH"
	is_found=0
	for src_line in "${content[@]}"; do
		if
			{ [ -v OPT_LINE ] && [ "$src_line" = "$OPT_LINE" ]; } \
			|| { [ -v OPT_PATTERN ] && [[ $src_line =~ $OPT_PATTERN ]]; }
		then
			if [ "$OPT_STATE" = 1 ]; then
				is_found=1
				output_content+=("$OPT_LINE")
			fi
			continue
		fi
		output_content+=("$src_line")
	done
	if [ "$OPT_STATE" = 1 ] && [ "$is_found" = 0 ]; then
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
	for image in debian alpine rockylinux; do
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
			echo "line 5" >> /test.txt
			module_line_in_file \
				path /test.txt \
				line "another line 6" \
				pattern "^another"
			mapfile -t content < /test.txt
			[ "${content[0]}" = "another line 6" ]
			[ "${content[1]}" = "line 5" ]
			[ "${#content[@]}" = 2 ]
		EOF
		remove_container
	done
	echo "ok"
}

###
# Ensure, that file has mode, group or owner.
REQUIREMENTS["module_file_permissions"]="get_options check_do"
module_file_permissions() {
	eval "$(get_options "mode owner group path" "$@")"
	declare -a details
	if [ ! -e "$OPT_PATH" ] && [ "${CHECK_MODE:-0}" = 1 ]; then
		return 0
	fi
	mapfile -t details <<< "$(stat -c "%u"$'\n'"%g"$'\n'"%a" "$OPT_PATH")"
	if [ -v OPT_OWNER ]; then
		if [[ ! "$OPT_OWNER" =~ ^[[:digit:]]+$ ]]; then
			OPT_OWNER=$(id -u "$OPT_OWNER")
		fi
		if [ "${details[0]}" != "$OPT_OWNER" ]; then
			check_do "Set ${OPT_PATH} owner to ${OPT_OWNER}" \
				chown "$OPT_OWNER" "$OPT_PATH"
		fi
	fi
	if [ -v OPT_GROUP ]; then
		if [[ ! "$OPT_GROUP" =~ ^[[:digit:]]+$ ]]; then
			OPT_GROUP=$(id -g "$OPT_GROUP")
		fi
		if [ "${details[1]}" != "$OPT_GROUP" ]; then
			check_do "Set ${OPT_PATH} group to ${OPT_GROUP}" \
				chgrp "$OPT_GROUP" "$OPT_PATH"
		fi
	fi
	if [ -v OPT_MODE ] && [ "$OPT_MODE" != "${details[2]}" ]; then
		check_do "Set ${OPT_PATH} mode to ${OPT_MODE}" \
			chmod "$OPT_MODE" "$OPT_PATH"
	fi
}

TEST_SUITES+=(test_file_permissions)
test_file_permissions() {
	echo -n "${FUNCNAME[0]} "
	declare image
	for image in debian alpine rockylinux; do
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
REQUIREMENTS["module_file_content"]="get_options check_do"
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
	for image in debian alpine rockylinux; do
		launch_container "$image"
		exec_container > /dev/null <<- "EOF"
			rm -f /test.txt
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
			module_file_content \
				path /test.txt \
				content ""
			[ "$(cat /test.txt)" = "" ]
		EOF
		remove_container
	done
	echo "ok"
}

###
# Ensure, that APT package is installed.
REQUIREMENTS["module_apt_packages"]="get_options"
module_apt_packages() {
	eval "$(get_options "names state" "$@")"
	[ -v OPT_STATE ] || OPT_STATE=1
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
REQUIREMENTS["module_apt_repository"]="get_options check_do module_file_content module_file_permissions"
module_apt_repository() {
	eval "$(get_options "\
		name \
		url \
		suites \
		components \
		architectures \
		keyring_url \
		keyring_prefix \
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
	if [ -v OPT_KEYRING_PREFIX ]; then
		keyring_file="/usr/share/keyrings/${OPT_KEYRING_PREFIX}-archive-keyring.gpg"
	else
		keyring_file="/usr/share/keyrings/${OPT_NAME}-archive-keyring.gpg"
	fi
	if [ ! -v OPT_ARCHITECTURES ]; then
		OPT_ARCHITECTURES=$(dpkg --print-architecture)
	fi
	content="Types: ${OPT_TYPES:-"deb"}"
	content="$content"$'\n'"URIs: ${OPT_URL}"
	content="$content"$'\n'"Suites: ${OPT_SUITES}"
	content="$content"$'\n'"Architectures: ${OPT_ARCHITECTURES}"
	if [ -v OPT_COMPONENTS ]; then
		content="$content"$'\n'"Components: ${OPT_COMPONENTS}"
	fi
	content="$content"$'\n'"Signed-By: ${keyring_file}"
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
REQUIREMENTS["module_apt_hold"]="get_options check_do"
module_apt_hold() {
	eval "$(get_options "names state" "$@")"
	[ -v OPT_STATE ] || OPT_STATE=1
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
# Ensure user's state.
REQUIREMENTS["module_user"]="get_options check_do"
module_user() {
	eval "$(get_options "name uid gid comment create_home home shell force remove move_home state" "$@")"
	[ -v OPT_CREATE_HOME ] || OPT_CREATE_HOME=1
	[ -v OPT_FORCE ] || OPT_FORCE=0
	[ -v OPT_REMOVE ] || OPT_REMOVE=0
	[ -v OPT_MOVE_HOME ] || OPT_MOVE_HOME=0
	[ -v OPT_STATE ] || OPT_STATE=1
	declare \
		name \
		uid \
		gid \
		comment \
		home \
		shell \
		i
	declare -a \
		opts=() \
		common_opts=()
	[ ! -v OPT_UID ] || common_opts+=("--uid" "$OPT_UID")
	[ ! -v OPT_GID ] || common_opts+=("--gid" "$OPT_GID")
	[ ! -v OPT_COMMENT ] || common_opts+=("--comment" "$OPT_COMMENT")
	# Use short flag to avoid useradd and usermod discrepancy.
	[ ! -v OPT_HOME ] || common_opts+=("-d" "$OPT_HOME")
	[ ! -v OPT_SHELL ] || common_opts+=("--shell" "$OPT_SHELL")
	i=$(getent passwd "$OPT_NAME") || i=""
	if [ -z "$i" ]; then
		if [ "$OPT_STATE" = 0 ]; then
			return 0
		else
			[ "$OPT_CREATE_HOME" != 1 ] || opts+=("--create-home")
			check_do "Create user ${OPT_NAME}" \
				useradd "${opts[@]}" "${common_opts[@]}" "$OPT_NAME"
		fi
	else
		if [ "$OPT_STATE" = 0 ]; then
			[ "$OPT_FORCE" != 1 ] || opts+=("--force")
			[ "$OPT_REMOVE" != 1 ] || opts+=("--remove")
			check_do "Remove user ${OPT_NAME}" \
				userdel "${opts[@]}" "$OPT_NAME"
		else
			IFS=":" read -r name i uid gid comment home shell <<< "$i"
			if
				[ "$uid" != "${OPT_UID:-"$uid"}" ] \
				|| [ "$gid" != "${OPT_GID:-"$gid"}" ] \
				|| [ "$comment" != "${OPT_COMMENT:-"$comment"}" ] \
				|| [ "$home" != "${OPT_HOME:-"$home"}" ] \
				|| [ "$shell" != "${OPT_SHELL:-"$shell"}" ]
			then
				check_do "Modify user ${OPT_NAME}" \
					usermod "${common_opts[@]}" "$OPT_NAME"
			fi
		fi
	fi
}

TEST_SUITES+=(test_user)
test_user() {
	echo -n "${FUNCNAME[0]} "
	for image in debian rockylinux; do
		launch_container "$image"
		exec_container > /dev/null <<- "EOF"
			module_user \
				name test1 \
				uid 1005 \
				home /srv/test1 \
				comment "Test user" \
				shell /bin/bash
			entry=$(grep ^test1 /etc/passwd)
			IFS=":" read -r -a fields <<< "$entry"
			[ "${fields[0]}" = "test1" ]
			[ "${fields[2]}" = "1005" ]
			[ "${fields[4]}" = "Test user" ]
			[ "${fields[5]}" = "/srv/test1" ]
			[ -d "/srv/test1" ]
			[ "${fields[6]}" = "/bin/bash" ]
			module_user \
				name test1 \
				shell /bin/sh
			entry=$(grep ^test1 /etc/passwd)
			IFS=":" read -r -a fields <<< "$entry"
			[ "${fields[6]}" = "/bin/sh" ]
			module_user \
				name test1 \
				state 0
			failed=0
			id test1 &>/dev/null || failed=1
			[ "$failed" = 1 ]
		EOF
		remove_container
	done
	echo "ok"
}

###
# Setup NodeJS.
REQUIREMENTS["module_nodejs"]="get_options module_apt_repository module_apt_packages"
module_nodejs() {
	eval "$(get_options "version" "$@")"
	[ -v OPT_VERSION ] || OPT_VERSION=18
	declare codename
	{
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
# Setup Varnish
REQUIREMENTS["module_varnish"]="get_options module_apt_repository module_apt_packages"
module_varnish() {
	eval "$(get_options "version" "$@")"
	[ -v OPT_VERSION ] || OPT_VERSION="60lts"
	: "${OPT_VERSION:="60lts"}"
	declare codename
	{
		source /etc/os-release
		echo "$VERSION_CODENAME"
	} | read -r codename
	module_apt_repository \
		name varnish \
		url "https://packagecloud.io/varnishcache/varnish${OPT_VERSION}/debian" \
		keyring_url "https://packagecloud.io/varnishcache/varnish${OPT_VERSION}/gpgkey" \
		keyring_armored 1 \
		suites "$codename" \
		components "main"
	module_apt_packages names varnish
}

###
# Setup Netdata
REQUIREMENTS["module_netdata"]="get_options module_apt_repository module_apt_packages"
module_netdata() {
	eval "$(get_options "release" "$@")"
	[ -v OPT_RELEASE ] || OPT_RELEASE="stable"
	declare codename
	{
		source /etc/os-release
		echo "$VERSION_CODENAME"
	} | read -r codename
	module_apt_repository \
		name netdata \
		url "http://repo.netdata.cloud/repos/${OPT_RELEASE}/debian/" \
		keyring_url "https://repo.netdata.cloud/netdatabot.gpg.key" \
		keyring_armored 1 \
		suites "${codename}/"
	module_apt_packages \
		names netdata
}

###
# Setup PostgreSQL repository without installing anything.
REQUIREMENTS["module_postgresql"]="get_options module_apt_repository"
module_postgresql() {
	declare codename
	{
		source /etc/os-release
		echo "$VERSION_CODENAME"
	} | read -r codename
	module_apt_repository \
		name postgresql \
		url "http://apt.postgresql.org/pub/repos/apt" \
		keyring_url "https://www.postgresql.org/media/keys/ACCC4CF8.asc" \
		keyring_armored 1 \
		suites "${codename}-pgdg" \
		components main
}

###
# Setup Elasticsearch.
REQUIREMENTS["module_elasticsearch"]="get_options module_apt_repository module_apt_packages"
module_elasticsearch() {
	eval "$(get_options "version" "$@")"
	[ -v OPT_VERSION ] || OPT_VERSION=8
	module_apt_repository \
		name elasticsearch \
		url "https://artifacts.elastic.co/packages/${OPT_VERSION}.x/apt" \
		keyring_url "https://artifacts.elastic.co/GPG-KEY-elasticsearch" \
		keyring_armored 1 \
		suites "stable" \
		components "main"
	module_apt_packages names elasticsearch
}

###
# Setup MySQL.
REQUIREMENTS["module_mysql"]="get_options module_apt_repository module_apt_packages"
module_mysql() {
	eval "$(get_options "version" "$@")"
	[ -v OPT_VERSION ] || OPT_VERSION="8.0"
	declare \
		keyring_url="https://pgp.mit.edu/pks/lookup?op=get&search=0x467B942D3A79BD29&exact=on&options=mr" \
		codename
	{
		source /etc/os-release
		echo "$VERSION_CODENAME"
	} | read -r codename
	module_apt_repository \
		name "mysql-${OPT_VERSION}" \
		url "http://repo.mysql.com/apt/debian/" \
		keyring_url "$keyring_url" \
		keyring_prefix "mysql" \
		keyring_armored 1 \
		suites "$codename" \
		components "mysql-${OPT_VERSION}"
	module_apt_repository \
		name "mysql-tools" \
		url "http://repo.mysql.com/apt/debian/" \
		keyring_url "$keyring_url" \
		keyring_prefix "mysql" \
		keyring_armored 1 \
		suites "$codename" \
		components "mysql-tools"
	module_apt_packages names mysql-community-server
}

###
# Setup PHP from Sury.
REQUIREMENTS["module_php_sury"]="get_options module_apt_repository module_apt_packages"
module_php_sury() {
	eval "$(get_options "version extensions" "$@")"
	[ -v OPT_VERSION ] || OPT_VERSION="8.1"
	declare \
		i \
		codename
	declare -a \
		packages=() \
		extensions=()
	if [ -z "$OPT_EXTENSIONS" ]; then
		extensions=(
			bcmath
			bz2
			cgi
			cli
			curl
			dba
			fpm
			gd
			igbinary
			imap
			intl
			json
			mbstring
			mcrypt
			mysql
			opcache
			phpdbg
			readline
			redis
			soap
			sqlite3
			xml
			xmlrpc
			xsl
			zip
		)
	else
		read -r -a extensions <<< "$OPT_EXTENSIONS"
	fi
	for i in "${extensions[@]}"; do
		packages+=("php${OPT_VERSION}-${i}")
	done
	{
		source /etc/os-release
		echo "$VERSION_CODENAME"
	} | read -r codename
	module_apt_repository \
		name sury \
		url https://packages.sury.org/php/ \
		keyring_url https://packages.sury.org/php/apt.gpg \
		suites "$codename" \
		components main
	module_apt_packages \
		names "${packages[*]}"
}

###
# Setup Yarn.
REQUIREMENTS["module_yarn"]="module_apt_repository module_apt_packages"
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
# Ensure directory state.
REQUIREMENTS["module_directory"]="get_options"
module_directory() {
	eval "$(get_options "path state recursive" "$@")"
	[ -v OPT_STATE ] || OPT_STATE=1
	[ -v OPT_RECURSIVE ] || OPT_RECURSIVE=0
	declare -a cmd
	if [ "$OPT_STATE" = 0 ]; then
		if [ "$OPT_RECURSIVE" = 1 ]; then
			cmd=("rm" "-r")
		else
			cmd=("rmdir")
		fi
		if [ -e "$OPT_PATH" ]; then
			check_do "Remove directory ${OPT_PATH}" \
				"${cmd[@]}" "$OPT_PATH"
		fi
	elif [ -e "$OPT_PATH" ]; then
		if [ ! -d "$OPT_PATH" ] && [ "${CHECK_MODE:-0}" = 0 ]; then
			echo "Path ${OPT_PATH} exists and is not a directory" >&2
			return 1
		fi
	else
		cmd=("mkdir")
		if [ "$OPT_RECURSIVE" = 1 ]; then
			cmd+=("-p")
		fi
		check_do "Create directory ${OPT_PATH}" \
			"${cmd[@]}" "$OPT_PATH"
	fi
}

TEST_SUITES+=(test_directory)
test_directory() {
	echo -n "${FUNCNAME[0]} "
	declare image
	for image in debian alpine rockylinux; do
		launch_container "$image"
		exec_container > /dev/null <<- "EOF"
			module_directory \
				path /test
			[ -d /test ]
			module_directory \
				path /test/l1/l2 \
				recursive 1
			[ -d /test/l1/l2 ]
			CHECK_MODE=1 module_directory \
				path /etc/hosts
			module_directory \
				path /test/l1/l2 \
				state 0
			[ ! -d /test/l1/l2 ]
			module_directory \
				path /test \
				state 0 \
				recursive 1
			[ ! -d /test ]
			rm -rf /test
		EOF
		remove_container
	done
	echo "ok"
}

###
# Ensure, that systemd service is in defined state.
REQUIREMENTS["module_systemd_service"]="get_options"
module_systemd_service() {
	eval "$(get_options "name active enabled" "$@")"
	declare \
		enabled \
		enable_cmd \
		activated \
		active_cmd
	if [ -v OPT_ENABLED ]; then
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
	if [ -v OPT_ACTIVE ]; then
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
	for handler in "${HANDLERS[@]:-}"; do
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
	for handler in "${HANDLERS[@]:-}"; do
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

###
# Manage file.
REQUIREMENTS["module_file"]="
get_options
check_do
module_file_content
module_file_permissions
module_directory
module_symlink
"
module_file() {
	eval "$(get_options "path src content recursive mode owner group state" "$@")"
	declare -a permission_options=()
	case "$OPT_STATE" in
	directory)
		module_directory \
			path "$OPT_PATH"
		;;
	file)
		if [ -v OPT_CONTENT ]; then
			module_file_content \
				path "$OPT_PATH" \
				content "$OPT_CONTENT"
		elif [ ! -e "$OPT_PATH" ]; then
			check_do "Create file ${OPT_PATH}" \
				install -m 700 /dev/null "$OPT_PATH"
		fi
		;;
	symlink)
		module_symlink \
			src "$OPT_SRC" \
			dest "$OPT_PATH"
		;;
	absent)
		if [ -L "$OPT_PATH" ]; then
			check_do "Remove symlink ${OPT_PATH}" \
				rm "$OPT_PATH"
		elif [ -f "$OPT_PATH" ]; then
			check_do "Remove file ${OPT_PATH}" \
				rm "$OPT_PATH"
		elif [ -d "$OPT_PATH" ]; then
			module_directory \
				path "$OPT_PATH" \
				recursive "${OPT_RECURSIVE:-0}" \
				state 0
		fi
		;;
	*)
		echo "Unknown file state: ${OPT_STATE}" >&2
		return 1
		;;
	esac
	if [ -v OPT_MODE ]; then
		permission_options+=(mode "$OPT_MODE")
	fi
	if [ -v OPT_OWNER ]; then
		permission_options+=(owner "$OPT_OWNER")
	fi
	if [ -v OPT_GROUP ]; then
		permission_options+=(group "$OPT_GROUP")
	fi
	if [ "${#permission_options[@]}" != 0 ]; then
		module_file_permissions \
			path "$OPT_PATH" \
			"${permission_options[@]}"
	fi
}

TEST_SUITES+=(test_file)
test_file() {
	echo -n "${FUNCNAME[0]} "
	declare image
	for image in debian alpine rockylinux; do
		launch_container "$image"
		exec_container > /dev/null <<- "EOF"
			rm -rf /test.txt /test
			module_file \
				path /test.txt \
				state "file"
			[ "$(cat /test.txt)" = "" ]
			module_file \
				path /test.txt \
				content "qwe" \
				mode 777 \
				owner 2 \
				group 2 \
				state "file"
			module_file \
				path /test.txt \
				state "file"
			[ "$(stat -c "%u %g %F %a" /test.txt)" = "2 2 regular file 777" ]
			[ "$(cat /test.txt)" = "qwe" ]
			module_file \
				path /test.txt \
				state "absent"
			[ ! -e /test.txt ]
			module_file \
				path /test \
				mode 777 \
				owner 2 \
				group 2 \
				state directory
			[ "$(stat -c "%u %g %F %a" /test)" = "2 2 directory 777" ]
			module_file \
				path /test \
				state absent
			[ ! -d /test ]
			module_file \
				path /test.txt \
				src /etc/hosts \
				state symlink
			[ -L /test.txt ]
			[ "$(realpath /test.txt)" = /etc/hosts ]
			module_file \
				path /test.txt \
				state absent
			[ ! -L /test.txt ]
		EOF
		remove_container
	done
	echo "ok"
}

###
# Verify checksum in pipe. All input data is buffered in memory.
verify_checksum() {
	declare \
		algorithm=$1 \
		sum=$2 \
		input_sum \
		input
	input=$(base64 -w 0)
	input_sum=$(echo "$input" | base64 -d | "${algorithm}sum" | cut -d " " -f 1)
	if [ "$sum" != "$input_sum" ]; then
		echo "Input checksum mismatch: ${input_sum}" >&2
		return 1
	fi
	echo "$input" | base64 -d
}

TEST_SUITES+=(test_verify_checksum)
test_verify_checksum() {
	echo -n "${FUNCNAME[0]} "
	declare image
	for image in debian alpine rockylinux; do
		launch_container "$image"
		exec_container > /dev/null <<- "EOF"
			payload="test"
			checksum=$(echo "$payload" | sha256sum | cut -d " " -f 1)
			echo "$payload" | verify_checksum sha256 "$checksum" > /dev/null
			failed=0
			echo "${payload}extra" | verify_checksum sha256 "$checksum" &> /dev/null \
				|| { failed=1; }
			[ "$failed" = 1 ]
		EOF
		remove_container
	done
	echo "ok"
}

file_to_function() {
	declare \
		arg1 \
		filename \
		name \
		password \
		content
	while [ "$#" != 0 ]; do
		arg1=$1
		shift
		case "$arg1" in
		-f|--file)
			filename=$1
			shift
			;;
		-n|--name)
			name=$1
			shift
			;;
		-p|--password)
			password=$1
			shift
			;;
		*)
			echo "Wrong option: ${arg1}" >&2
			return 1
			;;
		esac
	done
	if [ ! -v filename ]; then
		echo "Filename must be provided" >&2
		return 1
	fi
	if [ ! -v name ]; then
		name=$(basename "$filename")
		name=${name//-/_}
		name=${name//./_}
		name=${name//\(/_}
		name=${name//)/_}
		name="render_${name}"
	fi
	if [ ! -v password ]; then
		content=$(base64 -w 0 "$filename")
	else
		content=$(
			gpg \
				--batch \
				--quiet \
				--decrypt \
				--passphrase-file <(echo "$password") \
				<"$filename" \
				| base64 -w 0
		)
	fi
	eval "${name}() { base64 -d <<<${content}; }"
}

TEST_SUITES+=("test_file_to_function")
test_file_to_function() {
	echo -n "${FUNCNAME[0]} "
	declare image
	for image in debian alpine rockylinux; do
		launch_container "$image"
		exec_container > /dev/null <<- "EOF"
			declare checksum1 checksum2

			checksum1=$(md5sum /etc/hosts | cut -d " " -f 1)
			file_to_function -f /etc/hosts
			checksum2=$(render_hosts | md5sum | cut -d " " -f 1)
			[ "$checksum1" = "$checksum2" ]

			checksum1=$(md5sum /bin/sh | cut -d " " -f 1)
			file_to_function -n render_binary -f /bin/sh
			checksum2=$(render_binary | md5sum | cut -d " " -f 1)
			[ "$checksum1" = "$checksum2" ]

			checksum1=$(md5sum /etc/resolv.conf | cut -d " " -f 1)
			rm -f /etc/resolv.conf.gpg
			gpg \
				--batch \
				--quiet \
				--symmetric \
				--passphrase-file <(echo qwerty) \
				</etc/resolv.conf \
				>/etc/resolv.conf.gpg
			file_to_function -p qwerty -f /etc/resolv.conf.gpg
			checksum2=$(render_resolv_conf_gpg | md5sum | cut -d " " -f 1)
			[ "$checksum1" = "$checksum2" ]
		EOF
		remove_container
	done
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

RUN apt-get update && apt-get install -y \
	apt-utils \
	wget \
	gpg \
	gpg-agent \
	bash \
	openssh-server \
	openssh-client \
	jq \
	findutils \
	sudo \
	curl  \
	nano \
	rsync \
	diffutils \
	ncurses-bin \

ENTRYPOINT ["/bin/sleep", "infinity"]
EOF
	if ! docker image inspect "modules:debian" &> /dev/null; then
		docker build -t "modules:debian" -f - . <<< "$dockerfile"
		echo
	fi
mapfile -d "" -t dockerfile <<EOF
FROM alpine:latest

ENV PATH=/usr/local/bin:/usr/local/sbin:/bin:/sbin:/usr/bin:/usr/sbin

RUN apk add \
	bash \
	gpg \
	gpg-agent \
	openssh-server \
	openssh-client \
	jq \
	findutils \
	sudo \
	curl  \
	nano \
	rsync \
	ncurses

ENTRYPOINT ["/bin/sleep", "infinity"]
EOF
	if ! docker image inspect "modules:alpine" &> /dev/null; then
		docker build -t "modules:alpine" -f - . <<< "$dockerfile"
		echo
	fi
mapfile -d "" -t dockerfile << EOF
FROM rockylinux:9

ENV PATH=/usr/local/bin:/usr/local/sbin:/bin:/sbin:/usr/bin:/usr/sbin

RUN dnf install -y --allowerasing \
	bash \
	gpg \
	openssh-server \
	openssh-clients \
	jq \
	findutils \
	sudo \
	curl \
	nano \
	rsync \
	ncurses \
	diffutils

ENTRYPOINT ["/bin/sleep", "infinity"]
EOF
	if ! docker image inspect "modules:rockylinux" &> /dev/null; then
		docker build -t "modules:rockylinux" -f - . <<< "$dockerfile"
		echo
	fi
}

run_tests() {
	declare \
		test_suite \
		selected_suite
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

export_functions() {
	declare -a functions=("$@")
	declare -A exported=()
	declare \
		fn \
		requires
	while [ "${#functions[@]}" != 0 ]; do
		fn=${functions[0]}
		requires=${REQUIREMENTS["$fn"]:-}
		requires=${requires//$'\n'/ }
		if [ ! -v "exported[${fn}]" ]; then
			exported["$fn"]="$requires"
		fi
		for fn in $requires; do
			functions+=("$fn")
		done
		unset "functions[0]"
		functions=("${functions[@]}")
	done
	for fn in "${!exported[@]}"; do
		requires=${exported["$fn"]}
		requires=${requires## }
		requires=${requires%% }
		echo "REQUIREMENTS[\"${fn}\"]=\"${requires}\""
		declare -pf "$fn"
		echo
	done
}

main() {
	trap on_exit EXIT
	trap on_error ERR
	declare arg1
	declare -a \
		functions \
		args
	if [ "${TEST_MODULES:-0}" = 1 ]; then
		return 0
	fi
	arg1=${1:-}
	shift
	case "$arg1" in
	test)
		build_images
		shellcheck "$SCRIPT_FILE"
		run_tests "$@"
	;;
	export)
		if command -v shfmt >/dev/null; then
			export_command "$@" | shfmt
		else
			export_command "$@"
		fi
	;;
	*)
		echo "Unknown command: ${arg1}" >&2
		return 1
	;;
	esac
}

main "$@"

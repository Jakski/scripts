#!/usr/bin/env bash
# TODO: Finish this script. It works OK with single feed featuring RSS 1.0,
# but:
# - Won't work with RSS 2.0
# - Won't sort articles by date
# - Doesn't include page links in HTML

set -euo pipefail -o errtrace
shopt -s inherit_errexit nullglob lastpipe

on_error() {
	declare \
		exit_code=$? \
		cmd=$BASH_COMMAND
	echo "Failing with code ${exit_code} at ${*} in command: ${cmd}" >&2
	exit "$exit_code"
}

check_dependencies() {
	declare -a dependencies=(
		jq
		curl
		xmlstarlet
		sed
		tac
	)
	declare dependency
	for dependency in "${dependencies[@]}"; do
		if ! command -v "$dependency" >/dev/null; then
			echo "Missing dependency: ${dependency}" >&2
			return 1
		fi
	done
}

print_help() {
	# TODO
	echo "Help message stub"
}

parse_arguments() {
	while [ "$#" -ne 0 ]; do
		declare argument=$1
		shift
		case "$argument" in
		-c|--config)
			ARG_CONFIG_FILE=$1
			shift
		;;
		-d|--dest)
			ARG_DEST_DIR=$1
			shift
		;;
		-t|--timeout)
			ARG_TIMEOUT=$1
			shift
		;;
		-p|--page)
			ARG_PAGE_SIZE=$1
			shift
		;;
		-h|--help)
			print_help
			return 0
		;;
		*)
			print_help >&2
			return 1
		;;
		esac
	done
	: "${ARG_CONFIG_FILE:="${HOME}/.config/feed.cfg"}"
	: "${ARG_TIMEOUT:=5}"
	: "${ARG_DEST_DIR:?"Destination directory must be set"}"
	: "${ARG_PAGE_SIZE:=50}"
}

html_escape() {
	echo "$1" | sed \
		-e 's/&/\&amp;/g' \
		-e 's/</\&lt;/g' \
		-e 's/>/\&gt;/g' \
		-e 's/"/\&quot;/g' \
		-e 's/'"'"'/\&#39;/g'
}

update_feed() {
	declare cfg_url=$1 cfg_timeout=$2 cfg_description=$3
	if [ -z "$cfg_url" ]; then
		return 0
	fi
	declare feed_xml
	# Get rid of default namespaces. Otherwise xmlstarlet will require to pass
	# them explicitly. 
	# Limit feed size to 2 MiB, since we buffor everything in memory.
	feed_xml=$(curl -m "$cfg_timeout" -fsSL "$cfg_url" \
		| head -c 2M \
		| xmlstarlet pyx \
		| grep -v "^Axmlns " \
		| xmlstarlet p2x
	)
	declare articles_count article_index
	articles_count=$(echo "$feed_xml" | xmlstarlet sel -t -v "count(//item)")
	for article_index in $(seq "$articles_count" -1 1); do
		declare link title description publish_date
		link=$(xmlstarlet sel -t -v "(//item)[${article_index}]/link" <<< "$feed_xml" | tr "\n" " ")
		if grep -qxF "link ${link}" "${ARG_DEST_DIR}/articles.db"; then
			continue
		fi
		title=$(xmlstarlet sel -t -v "(//item)[${article_index}]/title" <<< "$feed_xml" | tr "\n" " ")
		description=$(xmlstarlet sel -t -v "(//item)[${article_index}]/description" <<< "$feed_xml" | tr "\n" " ")
		publish_date=$(xmlstarlet sel -t -v "(//item)[${article_index}]/dc:date" <<< "$feed_xml" | tr "\n" " ")
		cat >> "${ARG_DEST_DIR}/articles.db" <<-EOF

			link ${link}
			title ${title}
			date ${publish_date}
			description ${description}
		EOF
	done
}

update_feeds() {
	declare \
		key="" \
		value="" \
		line="" \
		cfg_url="" \
		cfg_timeout="" \
		cfg_description="" \
		line_num=0
	while read -r line; do
		((line_num+=1))
		if [ "$line" = "" ] || [[ "$line" =~ ^# ]]; then
			continue
		fi
		# shellcheck disable=SC2116
		{
			IFS=$'\n' read -d "" -r key value || true
		} <<< "$(echo "${line/ /$'\n'}")"
		if [ -z "$value" ]; then
			echo "${ARG_CONFIG_FILE}:${line_num}: value can't be empty" >&2
			return 1
		fi
		case "$key" in
		url)
			update_feed "$cfg_url" "$cfg_timeout" "$cfg_description"
			cfg_url=$value
			cfg_timeout=$ARG_TIMEOUT
			cfg_description=0
		;;
		timeout)
			cfg_timeout=$value
		;;
		description)
			cfg_description=$value
		;;
		*)
			echo "Wrong key \"${key}\" in line ${line_num}" >&2
			return 1
		;;
		esac
	done < "$ARG_CONFIG_FILE"
	update_feed "$cfg_url" "$cfg_timeout" "$cfg_description"
}

render_css() {
cat << "EOF"
	<style>
		html, body, div, span, applet, object, iframe,
		h1, h2, h3, h4, h5, h6, p, blockquote, pre,
		a, abbr, acronym, address, big, cite, code,
		del, dfn, em, img, ins, kbd, q, s, samp,
		small, strike, strong, sub, sup, tt, var,
		b, u, i, center,
		dl, dt, dd, ol, ul, li,
		fieldset, form, label, legend,
		table, caption, tbody, tfoot, thead, tr, th, td,
		article, aside, canvas, details, embed,
		figure, figcaption, footer, header, hgroup,
		menu, nav, output, ruby, section, summary,
		time, mark, audio, video {
			margin: 0;
			padding: 0;
			border: 0;
			font-size: 100%;
			font: inherit;
			vertical-align: baseline;
		}
		/* HTML5 display-role reset for older browsers */
		article, aside, details, figcaption, figure,
		footer, header, hgroup, menu, nav, section {
			display: block;
		}
		body {
			line-height: 1.5;
			min-height: 99vh;
			margin-bottom: 1vh;
			margin-left: 2vw;
			margin-right: 2vw;
		}
		@media (min-width: 768px) {
			body {
				max-width: 60rem;
				margin-left: auto;
				margin-right: auto;
			}
		}
		ol, ul {
			padding: 0.5rem;
			margin-left: 0.5rem;
		}
		blockquote, q {
			quotes: none;
		}
		blockquote:before, blockquote:after,
		q:before, q:after {
			content: '';
			content: none;
		}
		table {
			border-collapse: collapse;
			border-spacing: 0;
		}
		pre {
			overflow: auto;
			font-family: monospace;
			background-color: #E0E0E0;
			padding: 0.5rem;
			margin: 0.5rem;
		}
		code {
			font-family: monospace;
			font-size: 1rem;
		}
		a {
			text-decoration: none;
			color: #6e7583;
		}
		a:focus, a:hover, a:active {
			color: black;
		}
		strong {
			font-family: monospace;
			font-weight: bold;
			font-size: 1rem;
		}
		em {
			font-family: monospace;
			font-style: italic;
			font-size: 1rem;
		}
		h1, h2, h3, h4 {
			line-height: 1.25;
			padding-top: 0.5rem;
			padding-bottom: 0.5rem;
		}
		h1 { font-size: 2.5rem; }
		h2 { font-size: 2rem; }
		h3 { font-size: 1.5rem; }
		h4 { font-size: 1rem; }
		blockquote {
			border-left: solid black 0.25rem;
			border-right: solid black 0.25rem;
			border-top: solid black 1px;
			border-bottom: solid black 1px;
			margin: 0.5rem;
			padding-top: 0.5rem;
			padding-bottom: 0.5rem;
			padding-right: 0.5rem;
			padding-left: 1.5rem;
		}
		header {
			padding-bottom: 1rem;
		}
		#post-title {
			text-decoration: underline;
		}
		#post-date {
			font-size: 1rem;
			font-family: monospace;
			font-style: italic;
		}
		#posts-list-item {
			padding-top: 0.5rem;
			padding-bottom: 0.5rem;
		}
		#title {
			font-size: 3rem;
			border-bottom: solid black 1px;
		}
		p {
			padding-top: 0.5rem;
			padding-bottom: 0.5rem;
		}
	</style>
EOF
}

render_page_start() {
	declare page_number=$1
cat << EOF
<!DOCTYPE html>
<html>
<head>
	<title>News feed - page ${page_number}</title>
	<link href="/style.css" rel="stylesheet">
	<meta charset="UTF-8" />
	<meta name="viewport" content="width=device-width, initial-scale=1.0" />
$(render_css)
</head>
<body>
	<h1 id="title">
		<a href="/">
			News feed - page ${page_number}
		</a>
	</h1>
	<ul id="posts-list">
EOF
}

render_article_body() {
	declare link=$1 title=$2 date=$3 description=$4
cat << EOF
		<li class="posts-list-item">
			<a href="$(html_escape "$link")">
				$(html_escape "$title")
			</a>
			<time datetime="$(html_escape "$date")">
				[$(html_escape "$date")]
			</time>
		</li>
EOF
}

render_page_end() {
cat << EOF
	</ul>
</body>
</html>
EOF
}

render_article() {
	declare \
		article_number=$1 \
		link=$2 \
		title=$3 \
		date=$4 \
		description=$5 \
		page_number \
		article_position \
		output_file
	((page_number = article_number / ARG_PAGE_SIZE + 1))
	((article_position = article_number % (ARG_PAGE_SIZE + 1)))
	if [ "$page_number" = 1 ]; then
		output_file="${ARG_DEST_DIR}/index.html"
	else
		output_file="${ARG_DEST_DIR}/page-${page_number}.html"
	fi
	if [ "$article_position" = 1 ]; then
		render_page_start "$page_number" >> "$output_file"
	fi
	render_article_body "$link" "$title" "$date" "$description" >> "$output_file"
	if [ "$article_position" = "$ARG_PAGE_SIZE" ]; then
		render_page_end >> "$output_file"
	else
		# Otherwise we need to add ending to page which isn't full. We don't know
		# how many articles there will be, so this needs to be delayed until EOF.
		echo "$output_file"
	fi
}

render_html() {
	declare article_number=0 line_number=0 incomplete_file=""
	tac "${ARG_DEST_DIR}/articles.db" \
	| while true; do
		declare next_article=0 link="" date="" description="" title="" line
		while read -r line; do
			((line_number+=1))
			declare position="${ARG_DEST_DIR}/articles.db:${line_number}"
			if [ -z "$line" ]; then
				next_article=1
				: "${link:?"Missing link in ${position}"}"
				: "${description:?"Missing description in ${position}"}"
				: "${title:?"Missing title in ${position}"}"
				: "${date:?"Missing date in ${position}"}"
				((article_number+=1))
				incomplete_file=$(render_article "$article_number" "$link" "$title" "$date" "$description")
				break
			fi
			# shellcheck disable=SC2116
			{
				IFS=$'\n' read -d "" -r key value || true
			} <<< "$(echo "${line/ /$'\n'}")"
			if [ -z "$value" ]; then
				echo "${position}: value can't be empty" >&2
				return 1
			fi
			case "$key" in
			link)
				link=$value
			;;
			description)
				description=$value
			;;
			title)
				title=$value
			;;
			date)
				date=$value
			;;
			*)
				echo "${position}: wrong database entry \"${key}\"" >&2
				return 1
			;;
			esac
		done
		if [ "$next_article" = 0 ]; then
			if [ -n "$incomplete_file" ]; then
				render_page_end >> "$incomplete_file"
			fi
			break
		fi
	done
}

main() {
	trap 'on_error ${BASH_SOURCE[0]}:${LINENO}' ERR
	check_dependencies
	parse_arguments "$@"
	mkdir -p "$ARG_DEST_DIR"
	touch "${ARG_DEST_DIR}/articles.db"
	update_feeds
	render_html
}

main "$@"

#!/usr/bin/env bash
#
# procinfo - get process details instantly!
# A portable process inspector for Linux and macOS.
#
# https://github.com/pranshuparmar/witr/issues/32
#

readonly VERSION="2025.12.31"
readonly PROGNAME="${0##*/}"

# Colors
C_RESET='' C_BOLD='' C_DIM=''
C_RED='' C_GREEN='' C_YELLOW='' C_BLUE='' C_MAGENTA='' C_CYAN='' C_WHITE=''

# Cached process data
PROC_USER="" PROC_COMM="" PROC_RSS="" PROC_ETIME="" PROC_PPID="" PROC_LSTART="" PROC_ARGS=""
# Cached lsof output
LSOF_OUTPUT=""
FULL_DESC=false

setup_colors() {
    if [[ -n "${TERM:-}" && "${TERM}" != "dumb" && "${NO_COLOR:-}" != "1" ]]; then
        C_RESET=$'\033[0m'
        C_BOLD=$'\033[1m'
        C_DIM=$'\033[90m'
        C_RED=$'\033[31m'
        C_GREEN=$'\033[32m'
        C_YELLOW=$'\033[33m'
        C_BLUE=$'\033[34m'
        C_MAGENTA=$'\033[35m'
        C_CYAN=$'\033[36m'
        C_WHITE=$'\033[37m'
    fi
}

die() { printf '%s\n' "${C_RED}error:${C_RESET} $1" >&2; exit 1; }

usage() {
    printf '%s\n' "${C_CYAN}${C_BOLD}${PROGNAME}${C_RESET} - process information"
    printf '\n'
    printf '%s\n' "${C_YELLOW}USAGE${C_RESET}"
    printf '%s\n' "    ${PROGNAME} --port <port>"
    printf '%s\n' "    ${PROGNAME} --pid <pid>"
    printf '%s\n' "    ${PROGNAME} <name>"
    printf '\n'
    printf '%s\n' "${C_YELLOW}OPTIONS${C_RESET}"
    printf '%s\n' "    ${C_GREEN}-p${C_RESET}, ${C_GREEN}--port${C_RESET} <port>    Find process listening on port"
    printf '%s\n' "    ${C_GREEN}-P${C_RESET}, ${C_GREEN}--pid${C_RESET} <pid>      Explain specific PID"
    printf '%s\n' "    ${C_GREEN}-s${C_RESET}, ${C_GREEN}--short${C_RESET}          One-line output"
    printf '%s\n' "    ${C_GREEN}-j${C_RESET}, ${C_GREEN}--json${C_RESET}           JSON output (requires jq)"
    printf '%s\n' "        ${C_GREEN}--no-color${C_RESET}       Disable colored output"
    printf '%s\n' "    ${C_GREEN}-d${C_RESET}, ${C_GREEN}--description${C_RESET}     Wait for process description (slow on macOS)"
    printf '%s\n' "    ${C_GREEN}-h${C_RESET}, ${C_GREEN}--help${C_RESET}           Show this help"
    printf '%s\n' "    ${C_GREEN}-v${C_RESET}, ${C_GREEN}--version${C_RESET}        Show version"
    printf '\n'
    printf '%s\n' "${C_YELLOW}EXAMPLES${C_RESET}"
    printf '%s\n' "    ${PROGNAME} --port ${C_MAGENTA}3306${C_RESET}"
    printf '%s\n' "    ${PROGNAME} --pid ${C_MAGENTA}1234${C_RESET}"
    printf '%s\n' "    ${PROGNAME} ${C_CYAN}nginx${C_RESET}"
    exit 0
}

cache_proc_info() {
    local pid=$1
    # comm can have dots/special chars - get separately to avoid column alignment issues
    PROC_COMM=$(ps -p "$pid" -o comm= 2>/dev/null | sed 's/^[[:space:]]*//')
    [[ -z "$PROC_COMM" ]] && return 1
    PROC_COMM="${PROC_COMM##*/}"
    # These are simple fields (no spaces, predictable widths)
    read -r PROC_USER PROC_RSS PROC_ETIME PROC_PPID <<< "$(ps -p "$pid" -o user=,rss=,etime=,ppid= 2>/dev/null)"
    # lstart has spaces - separate call
    PROC_LSTART=$(ps -p "$pid" -o lstart= 2>/dev/null | sed 's/^[[:space:]]*//')
    # args can have arbitrary content - separate call
    PROC_ARGS=$(ps -p "$pid" -o args= 2>/dev/null | sed 's/^[[:space:]]*//')
    return 0
}

# Cache lsof output once
cache_lsof() {
    local pid=$1
    LSOF_OUTPUT=$(lsof -Pn -p "$pid" 2>/dev/null)
}

get_pid_by_port() {
    local result
    result=$(lsof -i :"$1" -t 2>/dev/null | head -1)
    echo "${result:-}"
}

get_pid_by_name() {
    local name=$1
    local pids count

    pids=$(pgrep -xi "$name" 2>/dev/null)
    [[ -z "$pids" ]] && pids=$(pgrep -i "$name" 2>/dev/null)

    # Count lines properly
    if [[ -z "$pids" ]]; then
        count=0
    else
        count=$(echo "$pids" | wc -l | tr -d ' ')
    fi

    if [[ $count -gt 1 ]]; then
        printf '%s\n' "${C_YELLOW}Note:${C_RESET} $count processes match '$name', showing first." >&2
        echo "$pids" | while read -r p; do
            local cmd=$(ps -p "$p" -o args= 2>/dev/null | cut -c1-60)
            printf '  %s--%s %s(pid %s)%s %s\n' "${C_DIM}" "${C_RESET}" "${C_CYAN}" "$p" "${C_RESET}" "$cmd" >&2
        done
        printf '%s\n' "Use ${C_CYAN}--pid <pid>${C_RESET} for specific process." >&2
        echo "" >&2
    fi

    echo "$pids" | head -1
}

build_chain() {
    local pid=$1
    local chain="${C_GREEN}${C_BOLD}${PROC_COMM}${C_RESET} ${C_DIM}(pid $pid)${C_RESET}"
    local ppid pcomm first=true

    while [[ $pid -gt 1 ]]; do
        if $first; then
            ppid=$PROC_PPID
            first=false
        else
            ppid=$(ps -p "$pid" -o ppid= 2>/dev/null | tr -d ' ')
        fi
        [[ -z "$ppid" ]] && break

        pcomm=$(ps -p "$ppid" -o comm= 2>/dev/null)
        [[ -z "$pcomm" ]] && break
        pcomm="${pcomm##*/}"

        chain="${C_BLUE}$pcomm${C_RESET} ${C_DIM}(pid $ppid)${C_RESET} ${C_MAGENTA}→${C_RESET} $chain"
        [[ "$ppid" -le 1 ]] && break
        pid=$ppid
    done
    echo "$chain"
}

get_listen_ports() {
    echo "$LSOF_OUTPUT" | awk '/LISTEN/{print $9}' | sort -u
}

get_docker_info() {
    local pid=$1 target=$2
    local container_id container_name image

    # Linux: docker-proxy has container info in its args
    if [[ "$PROC_COMM" == "docker-proxy" ]]; then
        local container_ip container_port

        # Parse args - POSIX compatible (no grep -P)
        container_ip=$(echo "$PROC_ARGS" | sed -n 's/.*-container-ip \([0-9.]*\).*/\1/p')
        container_port=$(echo "$PROC_ARGS" | sed -n 's/.*-container-port \([0-9]*\).*/\1/p')

        # Find container by IP on bridge network
        container_id=$(docker network inspect bridge -f '{{range .Containers}}{{if eq .IPv4Address "'"$container_ip"'/16"}}{{.Name}}{{end}}{{end}}' 2>/dev/null)

        # Fallback: find by port mapping
        if [[ -z "$container_id" ]]; then
            container_id=$(docker ps --filter "publish=$container_port" -q 2>/dev/null | head -1)
        fi

        [[ -z "$container_id" ]] && return

        container_name=$(docker inspect -f '{{.Name}}' "$container_id" 2>/dev/null | tr -d '/')
        image=$(docker inspect -f '{{.Config.Image}}' "$container_id" 2>/dev/null)

        echo "container:$container_id"
        echo "name:$container_name"
        echo "image:$image"
        echo "ip:$container_ip"
        echo "port:$container_port"
        return
    fi

    # macOS: Docker Desktop uses com.docker.backend, vpnkit, etc.
    command -v docker &>/dev/null || return

    case "$PROC_COMM" in
        com.docker*|vpnkit*|Docker*) ;;
        *) return ;;
    esac

    # Extract port from target if queried by port (e.g., "port 5432")
    local query_port
    if [[ "$target" == "port "* ]]; then
        query_port="${target#port }"
    else
        # Fallback: try first listening port
        query_port=$(get_listen_ports | sed -n 's/.*:\([0-9]*\)$/\1/p' | head -1)
    fi
    [[ -z "$query_port" ]] && return

    # Find container publishing this port
    container_id=$(docker ps --filter "publish=$query_port" -q 2>/dev/null | head -1)
    [[ -z "$container_id" ]] && return

    container_name=$(docker inspect -f '{{.Name}}' "$container_id" 2>/dev/null | tr -d '/')
    image=$(docker inspect -f '{{.Config.Image}}' "$container_id" 2>/dev/null)

    echo "container:$container_id"
    echo "name:$container_name"
    echo "image:$image"
}

get_file_handles() {
    local pid=$1 count limit pct
    count=$(lsof -p "$pid" 2>/dev/null | wc -l | tr -d ' ')
    if [[ -f "/proc/$pid/limits" ]]; then
        limit=$(awk '/Max open files/{print $4}' "/proc/$pid/limits" 2>/dev/null)
    else
        limit=$(ulimit -n 2>/dev/null)
    fi

    [[ ! "$limit" =~ ^[0-9]+$ ]] && return

    pct=$((count * 100 / limit))

    if [[ $pct -ge 75 ]]; then
        echo "$count of $limit ($pct%) ⚠ high"
    elif [[ $pct -ge 50 ]]; then
        echo "$count of $limit ($pct%) ⚠ elevated"
    elif $VERBOSE; then
        echo "$count of $limit ($pct%)"
    fi
}

get_locks() {
    echo "$LSOF_OUTPUT" | awk '$4~/[0-9]+[a-z]*[wW]/ || /\.lock|\.lck|\.pid|lockfile/{print $9}' | \
        grep -v '^$' | sort -u | head -5
}

get_working_dir() {
    local pid=$1 result
    if [[ -d "/proc/$pid/cwd" ]]; then
        result=$(readlink -f "/proc/$pid/cwd" 2>/dev/null)
    else
        result=$(lsof -p "$pid" 2>/dev/null | awk '$4=="cwd" && $5!="unknown"{print $9; exit}')
    fi

    # Skip if permission denied or empty
    [[ "$result" == *"Permission denied"* || "$result" == *"/proc/"* || -z "$result" ]] && return
    echo "$result"
}

get_source() {
    local pid=$1
    local ppid=$PROC_PPID
    local pcomm

    pcomm=$(ps -p "$ppid" -o comm= 2>/dev/null)
    pcomm="${pcomm##*/}"

    # command name starts with a dash, most likely a login shell
    [[ "$pcomm" == -* ]] && { echo "interactive $pcomm shell (login)"; return; }

    case "$pcomm" in
        systemd)
            local service path is_user="" proc_user=$PROC_USER

            if [[ $EUID -eq 0 ]]; then
                service=$(runuser -u "$proc_user" -- systemctl --user whoami "$pid" 2>/dev/null | grep -v "does not belong")
            else
                service=$(systemctl --user whoami "$pid" 2>/dev/null | grep -v "does not belong")
            fi
            [[ -n "$service" ]] && is_user="--user"

            [[ -z "$service" ]] && service=$(systemctl whoami "$pid" 2>/dev/null | grep -v "does not belong" | grep -v "user@")

            if [[ -n "$service" ]]; then
                if [[ -n "$is_user" && $EUID -eq 0 ]]; then
                    path=$(runuser -u "$proc_user" -- systemctl --user show -p FragmentPath --value "$service" 2>/dev/null)
                else
                    path=$(systemctl $is_user show -p FragmentPath --value "$service" 2>/dev/null)
                fi
                if [[ -n "$path" ]]; then
                    echo "$service ($path)"
                else
                    echo "$service"
                fi
            else
                echo "systemd service"
            fi
            ;;
        launchd)           echo "launchd" ;;
        docker*|containerd*|podman) echo "container runtime" ;;
        pm2)               echo "pm2" ;;
        supervisord)       echo "supervisor" ;;
        cron|crond)        echo "cron" ;;
        sshd)              echo "ssh session" ;;
        tmux*|screen)      echo "terminal multiplexer" ;;
        bash|zsh|fish|sh|dash) echo "interactive $pcomm shell" ;;
        init)              echo "init system" ;;
        *)                 echo "${pcomm:-unknown}" ;;
    esac
}

get_combined_rss() {
    local pid=$1
    local total=0 count=0 child_rss

    # Self
    total=$PROC_RSS
    count=1

    # Get all descendants - collect PIDs first
    local children
    children=$(pgrep -P "$pid" 2>/dev/null)

    if [[ -n "$children" ]]; then
        # Recursively collect all descendant PIDs
        local all_descendants=""
        local to_check="$children"

        while [[ -n "$to_check" ]]; do
            all_descendants+=" $to_check"
            local next_level=""
            for c in $to_check; do
                local grandchildren
                grandchildren=$(pgrep -P "$c" 2>/dev/null)
                [[ -n "$grandchildren" ]] && next_level+=" $grandchildren"
            done
            to_check="$next_level"
        done

        # Single ps call for all descendants' RSS
        if [[ -n "$all_descendants" ]]; then
            local pids_csv
            pids_csv=$(echo $all_descendants | tr ' ' ',' | sed 's/^,//')
            while read -r child_rss; do
                [[ -n "$child_rss" && "$child_rss" =~ ^[0-9]+$ ]] && total=$((total + child_rss)) && ((count++))
            done < <(ps -p "$pids_csv" -o rss= 2>/dev/null)
        fi
    fi

    if [[ $count -gt 1 ]]; then
        echo "$((total / 1024)) MB ($count processes)"
    fi
}

get_git_info() {
    local pid=$1
    local dir=""
    local exe
    exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null)

    if [[ -n "$exe" && -f "$exe" ]]; then
        case "$exe" in
            /usr/*|/bin/*|/sbin/*)
                # System binary - check for script in args
                local script
                script=$(echo "$PROC_ARGS" | grep -oE '/[^ ]+\.(py|js|rb|pl|sh)' | head -1)
                if [[ -n "$script" && -f "$script" ]]; then
                    dir=$(dirname "$script")
                else
                    # System binary, no script - git info not relevant
                    echo "not found"
                    return
                fi
                ;;
            *)
                dir=$(dirname "$exe")
                ;;
        esac
    fi

    [[ -z "$dir" || "$dir" == "unknown" ]] && return

    while [[ "$dir" != "/" && -n "$dir" ]]; do
        if [[ -d "$dir/.git" ]]; then
            local repo branch remote
            repo=$(basename "$dir")
            branch=$(sed 's|ref: refs/heads/||' "$dir/.git/HEAD" 2>/dev/null)
            remote=$(awk '/\[remote "origin"\]/{found=1} found && /url = /{print $3; exit}' "$dir/.git/config" 2>/dev/null)
            if [[ -n "$remote" ]]; then
                echo "$repo ($branch) - $remote"
            else
                echo "$repo ($branch)"
            fi
            return
        fi
        dir=$(dirname "$dir")
    done
}

collect_warnings() {
    local pid=$1 user=$2 rss=$3 listen=$4

    echo "$listen" | grep -qE '0\.0\.0\.0|\*:|::' 2>/dev/null && \
        echo "Process is listening on a public interface"

    [[ "$user" == "root" ]] && \
        echo "Process is running as root"

    [[ "$rss" -gt 1048576 ]] 2>/dev/null && \
        echo "Process is using high memory (>1GB RSS)"
}

print_short() {
    build_chain "$1"
}

print_json() {
    command -v jq &>/dev/null || die "--json requires jq"

    local pid=$1 target=$2
    local listen cwd source

    listen=$(get_listen_ports)
    cwd=$(get_working_dir "$pid")
    source=$(get_source "$pid")

    jq -n \
        --arg target "$target" \
        --arg comm "$PROC_COMM" \
        --arg pid "$pid" \
        --arg user "$PROC_USER" \
        --arg command "$PROC_ARGS" \
        --arg started "$PROC_ETIME" \
        --arg rss_mb "$((PROC_RSS / 1024))" \
        --arg chain "$(build_chain "$pid")" \
        --arg cwd "$cwd" \
        --arg source "$source" \
        --arg file_handles "$(get_file_handles "$pid")" \
        --argjson listening "$(echo "$listen" | jq -R . | jq -s .)" \
        --argjson locks "$(get_locks | jq -R . | jq -s .)" \
        --argjson warnings "$(collect_warnings "$PROC_USER" "$PROC_RSS" "$listen" | jq -R . | jq -s .)" \
        '{
            target: $target,
            process: { name: $comm, pid: ($pid|tonumber), user: $user },
            command: $command,
            started: $started,
            rss_mb: ($rss_mb|tonumber),
            chain: $chain,
            working_dir: $cwd,
            source: $source,
            file_handles: $file_handles,
            listening: $listening,
            locks: $locks,
            warnings: $warnings
        }'
}

get_whatis() {
    local comm=$1
    local desc

    if $FULL_DESC; then
        whatis "$comm" 2>/dev/null | sed -n '1s/.*- //p'
    elif [[ ${BASH_VERSINFO[0]} -ge 4 ]]; then
        # Bash 4+ supports fractional timeout - fast, no fork
        read -t 0.5 desc < <(whatis "$comm" 2>/dev/null | sed -n '1s/.*- //p') && echo "$desc"
    elif command -v timeout &>/dev/null; then
        # Fallback for bash 3.x with coreutils
        timeout 0.5 whatis "$comm" 2>/dev/null | sed -n '1s/.*- //p'
    fi
}


print_full() {
    local pid=$1 target=$2
    local cwd source git_info file_handles listen locks warnings combined_rss desc docker_info

    desc=$(get_whatis "$PROC_COMM")
    combined_rss=$(get_combined_rss "$pid")
    cwd=$(get_working_dir "$pid")
    source=$(get_source "$pid")
    git_info=$(get_git_info "$pid")
    file_handles=$(get_file_handles "$pid")
    listen=$(get_listen_ports)
    locks=$(get_locks)
    warnings=$(collect_warnings "$PROC_USER" "$PROC_RSS" "$listen")
    docker_info=$(get_docker_info "$pid" "$target")

    printf '%s\n' "${C_CYAN}Target${C_RESET}      : ${C_WHITE}$target${C_RESET}"
    printf '\n'
    printf '%s\n' "${C_CYAN}Process${C_RESET}     : ${C_GREEN}${C_BOLD}${PROC_COMM}${C_RESET} ${C_DIM}(pid $pid)${C_RESET}"
    [[ -n "$desc" ]] && \
    printf '%s\n' "${C_CYAN}Description${C_RESET} : ${C_DIM}$desc${C_RESET}"
    printf '%s\n' "${C_CYAN}User${C_RESET}        : ${C_MAGENTA}${PROC_USER}${C_RESET}"
    printf '%s\n' "${C_CYAN}Command${C_RESET}     : ${C_DIM}${PROC_ARGS}${C_RESET}"
    printf '%s\n' "${C_CYAN}Started at${C_RESET}  : ${C_YELLOW}${PROC_LSTART}${C_RESET}"
    printf '%s\n' "${C_CYAN}Running for${C_RESET} : ${C_YELLOW}$(format_etime "$PROC_ETIME")${C_RESET}"
    printf '%s\n' "${C_CYAN}RSS Memory${C_RESET}  : ${C_YELLOW}$((PROC_RSS / 1024)) MB${C_RESET}"
    [[ -n "$combined_rss" ]] && \
    printf '%s\n' "${C_CYAN}Combined RSS${C_RESET}: ${C_YELLOW}$combined_rss${C_RESET}"
    printf '\n'
    printf '%s\n' "${C_CYAN}Process tree${C_RESET}:"
    printf '%s\n' "  $(build_chain "$pid")"
    printf '\n'
    printf '%s\n' "${C_CYAN}Source${C_RESET}      : ${C_BLUE}$source${C_RESET}"
    [[ -n "$git_info" ]] && printf '%s\n' "${C_CYAN}git info${C_RESET}    : ${C_BLUE}$git_info${C_RESET}"
    [[ -n "$cwd" ]] && printf '%s\n' "${C_CYAN}Working Dir${C_RESET} : ${C_BLUE}$cwd${C_RESET}"

    if [[ -n "$listen" ]]; then
        printf '%s\n' "${C_CYAN}Listening${C_RESET}   : ${C_GREEN}$(echo "$listen" | head -1)${C_RESET}"
        echo "$listen" | tail -n +2 | while IFS= read -r port; do
            printf '%s\n' "              ${C_GREEN}$port${C_RESET}"
        done
    fi

    [[ -n "$file_handles" ]] && printf '%s\n' "${C_CYAN}File Handles${C_RESET}: ${C_YELLOW}$file_handles${C_RESET}"

    if [[ -n "$locks" ]]; then
        printf '%s\n' "${C_CYAN}Locks${C_RESET}       : ${C_MAGENTA}$(echo "$locks" | head -1)${C_RESET}"
        echo "$locks" | tail -n +2 | while IFS= read -r lock; do
            printf '%s\n' "              ${C_MAGENTA}$lock${C_RESET}"
        done
    fi

    if [[ -n "$docker_info" ]]; then
        printf '\n'
        printf '%s\n' "${C_CYAN}Docker info${C_RESET} :"

        local cid cname cimage cip cport
        cid=$(echo "$docker_info" | grep '^container:' | cut -d: -f2)
        cname=$(echo "$docker_info" | grep '^name:' | cut -d: -f2)
        cimage=$(echo "$docker_info" | grep '^image:' | cut -d: -f2)
        cip=$(echo "$docker_info" | grep '^ip:' | cut -d: -f2)
        cport=$(echo "$docker_info" | grep '^port:' | cut -d: -f2)

        printf '%s\n' "  Container : ${C_GREEN}$cname${C_RESET} ($cid)"
        printf '%s\n' "  Image     : ${C_BLUE}$cimage${C_RESET}"
        [[ -n "$cip" && -n "$cport" ]] && \
        printf '%s\n' "  Internal  : ${C_YELLOW}$cip:$cport${C_RESET}"
        printf '\n'
        printf '%s\n' "${C_DIM}Docker cheatsheet:${C_RESET}"
        printf '%s\n' "  ${C_DIM}docker logs $cname${C_RESET}"
        printf '%s\n' "  ${C_DIM}docker exec -it $cname sh${C_RESET}"
        printf '%s\n' "  ${C_DIM}docker top $cname${C_RESET}"
        printf '%s\n' "  ${C_DIM}docker ps # List all containers${C_RESET}"
    fi

    if [[ -n "$warnings" ]]; then
        printf '\n'
        printf '%s\n' "${C_YELLOW}Extra info${C_RESET}  :"
        echo "$warnings" | while IFS= read -r warn; do
            printf '%s\n' "  ${C_GREEN}-${C_RESET} ${C_GREEN}$warn${C_RESET}"
        done
    fi

    if [[ $EUID -ne 0 && ( -z "$cwd" || -z "$listen" || "$file_handles" == "0"* ) ]]; then
        printf '\n'
        printf '%s\n' "${C_DIM}Note: Some info may be hidden due to permissions. Try sudo for full details.${C_RESET}"
    fi
}

format_etime() {
    local etime=$1
    local days=0 hours=0 mins=0 secs=0
    local weeks=0 remaining_days=0
    local result=""

    # Parse etime formats: MM:SS, HH:MM:SS, D-HH:MM:SS
    if [[ "$etime" == *-* ]]; then
        # Has days: D-HH:MM:SS
        days="${etime%%-*}"
        local time="${etime#*-}"
        IFS=: read -r hours mins secs <<< "$time"
    elif [[ "$etime" =~ ^[0-9]+:[0-9]+:[0-9]+$ ]]; then
        # HH:MM:SS
        IFS=: read -r hours mins secs <<< "$etime"
    else
        # MM:SS
        IFS=: read -r mins secs <<< "$etime"
    fi

    # Remove leading zeros
    days=$((10#$days))
    hours=$((10#${hours:-0}))
    mins=$((10#${mins:-0}))
    secs=$((10#${secs:-0}))

    # Convert days to weeks + days
    weeks=$((days / 7))
    remaining_days=$((days % 7))

    # Build human readable string
    if [[ $weeks -gt 0 ]]; then
        result="${weeks} week"
        [[ $weeks -gt 1 ]] && result+="s"
    fi

    if [[ $remaining_days -gt 0 ]]; then
        [[ -n "$result" ]] && result+=", "
        result+="${remaining_days} day"
        [[ $remaining_days -gt 1 ]] && result+="s"
    fi

    if [[ $hours -gt 0 ]]; then
        [[ -n "$result" ]] && result+=", "
        result+="${hours} hour"
        [[ $hours -gt 1 ]] && result+="s"
    fi

    if [[ $mins -gt 0 ]]; then
        [[ -n "$result" ]] && result+=", "
        result+="${mins} minute"
        [[ $mins -gt 1 ]] && result+="s"
    fi

    [[ -n "$result" ]] && result+=", "
    result+="${secs} second"
    [[ $secs -gt 1 ]] && result+="s"

    [[ -z "$result" ]] && result="just now"

    echo "$result"
}

main() {
    local port="" pid="" name="" short=false json=false target=""

    [[ $# -eq 0 ]] && { setup_colors; usage; }

    while [[ $# -gt 0 ]]; do
        case $1 in
            -p|--port)    port="${2:-}"; shift 2 || die "--port requires an argument" ;;
            -P|--pid)     pid="${2:-}"; shift 2 || die "--pid requires an argument" ;;
            -s|--short)   short=true; shift ;;
            -j|--json)    json=true; shift ;;
            --no-color)   NO_COLOR=1; shift ;;
            -d|--description) FULL_DESC=true; shift ;;
            -h|--help)    setup_colors; usage ;;
            -v|--version) echo "$PROGNAME $VERSION"; exit 0 ;;
            -*)           setup_colors; die "unknown option: $1" ;;
            *)            name="$1"; shift ;;
        esac
    done

    setup_colors

    for cmd in lsof ps pgrep; do
        command -v "$cmd" &>/dev/null || die "missing dependency: $cmd"
    done

    if [[ -n "$port" ]]; then
        pid=$(get_pid_by_port "$port")
        target="port $port"
        if [[ -z "$pid" ]]; then
            if [[ $EUID -ne 0 ]]; then
                die "nothing listening on port $port (try sudo?)"
            else
                die "nothing listening on port $port"
            fi
        fi
    elif [[ -n "$name" ]]; then
        pid=$(get_pid_by_name "$name")
        target="$name"
        if [[ -z "$pid" ]]; then
            if [[ $EUID -ne 0 ]]; then
                die "no process found: '$name' (try sudo?)"
            else
                die "no process found: '$name'"
            fi
        fi
    elif [[ -z "$pid" ]]; then
        die "must specify --port, --pid, or process name"
    else
        target="pid $pid"
    fi

    # Cache everything upfront
    cache_proc_info "$pid" || die "process $pid does not exist"
    cache_lsof "$pid"

    if $json; then
        print_json "$pid" "$target"
    elif $short; then
        print_short "$pid"
    else
        print_full "$pid" "$target"
    fi
}

main "$@"

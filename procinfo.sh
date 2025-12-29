#!/usr/bin/env bash
#
# procinfo - get process details instantly!
# A portable process inspector for Linux and macOS.
#
# https://github.com/pranshuparmar/witr/issues/32
#

readonly VERSION="1.0.0"
readonly PROGNAME="${0##*/}"

# Colors
C_RESET='' C_BOLD='' C_DIM=''
C_RED='' C_GREEN='' C_YELLOW='' C_BLUE='' C_MAGENTA='' C_CYAN='' C_WHITE=''

setup_colors() {
    if [[ -n "${TERM:-}" && "${TERM}" != "dumb" && "${NO_COLOR:-}" != "1" ]]; then
        C_RESET=$'\033[0m'
        C_BOLD=$'\033[1m'
        C_DIM=$'\033[2m'
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
    printf '%s\n' "${C_CYAN}${C_BOLD}${PROGNAME}${C_RESET} - why is this running?"
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
    printf '%s\n' "    ${C_GREEN}-h${C_RESET}, ${C_GREEN}--help${C_RESET}           Show this help"
    printf '%s\n' "    ${C_GREEN}-v${C_RESET}, ${C_GREEN}--version${C_RESET}        Show version"
    printf '\n'
    printf '%s\n' "${C_YELLOW}EXAMPLES${C_RESET}"
    printf '%s\n' "    ${PROGNAME} --port ${C_MAGENTA}3306${C_RESET}"
    printf '%s\n' "    ${PROGNAME} --pid ${C_MAGENTA}1234${C_RESET}"
    printf '%s\n' "    ${PROGNAME} ${C_CYAN}nginx${C_RESET}"
    exit 0
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

    count=$(echo "$pids" | grep -c . || echo 0)

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

get_field() {
    ps -p "$1" -o "$2=" 2>/dev/null | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

build_chain() {
    local pid=$1 chain ppid pcomm
    local comm
    comm=$(basename "$(get_field "$pid" comm)")
    chain="${C_GREEN}${C_BOLD}$comm${C_RESET} ${C_DIM}(pid $pid)${C_RESET}"

    while [[ $pid -gt 1 ]]; do
        ppid=$(get_field "$pid" ppid)
        [[ -z "$ppid" ]] && break
        pcomm=$(basename "$(get_field "$ppid" comm)")
        chain="${C_BLUE}$pcomm${C_RESET} ${C_DIM}(pid $ppid)${C_RESET} ${C_MAGENTA}→${C_RESET} $chain"
        [[ "$ppid" -le 1 ]] && break
        pid=$ppid
    done
    echo "$chain"
}

get_listen_ports() {
    lsof -i -P -n -a -p "$1" 2>/dev/null | awk '/LISTEN/{print $9}' | sort -u
}

get_open_files() {
    local pid=$1 count limit
    count=$(lsof -p "$pid" 2>/dev/null | wc -l | tr -d ' ')

    if [[ -f "/proc/$pid/limits" ]]; then
        limit=$(awk '/Max open files/{print $4}' "/proc/$pid/limits" 2>/dev/null)
    else
        limit=$(ulimit -n 2>/dev/null)
    fi

    if [[ -n "$limit" && "$limit" != "unlimited" && "$limit" -gt 0 ]] 2>/dev/null; then
        echo "$count of $limit ($((count * 100 / limit))%)"
    else
        echo "$count"
    fi
}

get_locks() {
    lsof -p "$1" 2>/dev/null | awk '$4~/[0-9]+[a-z]*[wW]/ || /\.lock|\.lck|\.pid|lockfile/{print $9}' | \
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
    local ppid pcomm
    ppid=$(get_field "$1" ppid)
    pcomm=$(basename "$(get_field "$ppid" comm)" 2>/dev/null)

    case "$pcomm" in
        systemd)           echo "systemd service" ;;
        launchd)           echo "launchd" ;;
        docker*|containerd*|podman) echo "container runtime" ;;
        pm2)               echo "pm2" ;;
        supervisord)       echo "supervisor" ;;
        cron|crond)        echo "cron" ;;
        sshd)              echo "ssh session" ;;
        tmux*|screen)      echo "terminal multiplexer" ;;
        bash|zsh|fish|sh|dash) echo "interactive shell" ;;
        init)              echo "init system" ;;
        *)                 echo "${pcomm:-unknown}" ;;
    esac
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
    local user comm rss etime args cwd source listen

    user=$(get_field "$pid" user)
    comm=$(basename "$(get_field "$pid" comm)")
    rss=$(get_field "$pid" rss)
    etime=$(get_field "$pid" etime)
    args=$(get_field "$pid" args)
    cwd=$(get_working_dir "$pid")
    source=$(get_source "$pid")
    listen=$(get_listen_ports "$pid")

    jq -n \
        --arg target "$target" \
        --arg comm "$comm" \
        --arg pid "$pid" \
        --arg user "$user" \
        --arg command "$args" \
        --arg started "$etime" \
        --arg rss_mb "$((rss / 1024))" \
        --arg chain "$(build_chain "$pid")" \
        --arg cwd "$cwd" \
        --arg source "$source" \
        --arg open_files "$(get_open_files "$pid")" \
        --argjson listening "$(echo "$listen" | jq -R . | jq -s .)" \
        --argjson locks "$(get_locks "$pid" | jq -R . | jq -s .)" \
        --argjson warnings "$(collect_warnings "$pid" "$user" "$rss" "$listen" | jq -R . | jq -s .)" \
        '{
            target: $target,
            process: { name: $comm, pid: ($pid|tonumber), user: $user },
            command: $command,
            started: $started,
            rss_mb: ($rss_mb|tonumber),
            chain: $chain,
            working_dir: $cwd,
            source: $source,
            open_files: $open_files,
            listening: $listening,
            locks: $locks,
            warnings: $warnings
        }'
}

print_full() {
    local pid=$1 target=$2
    local user comm rss etime args cwd source open_files listen locks warnings

    user=$(get_field "$pid" user)
    comm=$(basename "$(get_field "$pid" comm)")
    rss=$(get_field "$pid" rss)
    etime=$(get_field "$pid" etime)
    args=$(get_field "$pid" args)
    cwd=$(get_working_dir "$pid")
    source=$(get_source "$pid")
    open_files=$(get_open_files "$pid")
    listen=$(get_listen_ports "$pid")
    locks=$(get_locks "$pid")
    warnings=$(collect_warnings "$pid" "$user" "$rss" "$listen")

    printf '%s\n' "${C_CYAN}Target${C_RESET}      : ${C_WHITE}$target${C_RESET}"
    printf '\n'
    printf '%s\n' "${C_CYAN}Process${C_RESET}     : ${C_GREEN}${C_BOLD}$comm${C_RESET} ${C_DIM}(pid $pid)${C_RESET}"
    printf '%s\n' "${C_CYAN}User${C_RESET}        : ${C_MAGENTA}$user${C_RESET}"
    printf '%s\n' "${C_CYAN}Command${C_RESET}     : ${C_DIM}$args${C_RESET}"
    printf '%s\n' "${C_CYAN}Started at${C_RESET}  : ${C_YELLOW}$(get_start_time "$pid")${C_RESET}"
    printf '%s\n' "${C_CYAN}Running for${C_RESET} : ${C_YELLOW}$(format_etime "$etime")${C_RESET}"
    printf '%s\n' "${C_CYAN}RSS${C_RESET}         : ${C_YELLOW}$((rss / 1024)) MB${C_RESET}"
    printf '\n'
    printf '%s\n' "${C_CYAN}Why It Exists${C_RESET} :"
    printf '%s\n' "  $(build_chain "$pid")"
    printf '\n'
    printf '%s\n' "${C_CYAN}Source${C_RESET}      : ${C_BLUE}$source${C_RESET}"
    [[ -n "$cwd" ]] && printf '%s\n' "${C_CYAN}Working Dir${C_RESET} : ${C_BLUE}$cwd${C_RESET}"

    if [[ -n "$listen" ]]; then
        printf '%s\n' "${C_CYAN}Listening${C_RESET}   : ${C_GREEN}$(echo "$listen" | head -1)${C_RESET}"
        echo "$listen" | tail -n +2 | while IFS= read -r port; do
            printf '%s\n' "              ${C_GREEN}$port${C_RESET}"
        done
    fi

    printf '%s\n' "${C_CYAN}Open Files${C_RESET}  : ${C_YELLOW}$open_files${C_RESET}"

    if [[ -n "$locks" ]]; then
        printf '%s\n' "${C_CYAN}Locks${C_RESET}       : ${C_MAGENTA}$(echo "$locks" | head -1)${C_RESET}"
        echo "$locks" | tail -n +2 | while IFS= read -r lock; do
            printf '%s\n' "              ${C_MAGENTA}$lock${C_RESET}"
        done
    fi

    if [[ -n "$warnings" ]]; then
        printf '\n'
        printf '%s\n' "${C_YELLOW}Extra info${C_RESET}    :"
        echo "$warnings" | while IFS= read -r warn; do
            printf '%s\n' "  ${C_GREEN}-${C_RESET} ${C_GREEN}$warn${C_RESET}"
        done
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

get_start_time() {
    local pid=$1
    ps -p "$pid" -o lstart= 2>/dev/null | sed 's/^[[:space:]]*//'
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

    ps -p "$pid" &>/dev/null || die "process $pid does not exist"

    if $json; then
        print_json "$pid" "$target"
    elif $short; then
        print_short "$pid"
    else
        print_full "$pid" "$target"
    fi
}

main "$@"

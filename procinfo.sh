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
VERBOSE=false
SHOW_ENV=false

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
    printf '%s\n' "    ${PROGNAME} --all-ports"
    printf '\n'
    printf '%s\n' "${C_YELLOW}OPTIONS${C_RESET}"
    printf '%s\n' "    ${C_GREEN}-p${C_RESET}, ${C_GREEN}--port${C_RESET} <port>    Find process listening on port"
    printf '%s\n' "    ${C_GREEN}-P${C_RESET}, ${C_GREEN}--pid${C_RESET} <pid>      Inspect specific PID"
    printf '%s\n' "    ${C_GREEN}-a${C_RESET}, ${C_GREEN}--all-ports${C_RESET}      List all process PIDs of all active ports"
    printf '%s\n' "    ${C_GREEN}-s${C_RESET}, ${C_GREEN}--short${C_RESET}          One-line output"
    printf '%s\n' "    ${C_GREEN}-j${C_RESET}, ${C_GREEN}--json${C_RESET}           JSON output (requires jq)"
    printf '%s\n' "        ${C_GREEN}--no-color${C_RESET}       Disable colored output"
    printf '%s\n' "    ${C_GREEN}-d${C_RESET}, ${C_GREEN}--description${C_RESET}     Include descriptions (slow on macOS)"
    printf '%s\n' "    ${C_GREEN}-e${C_RESET}, ${C_GREEN}--env${C_RESET}            Show environment variables"
    printf '%s\n' "    ${C_GREEN}-V${C_RESET}, ${C_GREEN}--verbose${C_RESET}         Full width output (no truncation)"
    printf '%s\n' "    ${C_GREEN}-h${C_RESET}, ${C_GREEN}--help${C_RESET}           Show this help"
    printf '%s\n' "    ${C_GREEN}-v${C_RESET}, ${C_GREEN}--version${C_RESET}        Show version"
    printf '\n'
    printf '%s\n' "${C_YELLOW}EXAMPLES${C_RESET}"
    printf '%s\n' "    ${PROGNAME} --port ${C_MAGENTA}3306${C_RESET}"
    printf '%s\n' "    ${PROGNAME} --pid ${C_MAGENTA}1234${C_RESET}"
    printf '%s\n' "    ${PROGNAME} ${C_CYAN}nginx${C_RESET}"
    printf '%s\n' "    ${PROGNAME} --all-ports"
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

get_locked_files() {
    echo "$LSOF_OUTPUT" | awk '
        /\.lock|\.lck|\.pid|lockfile/ {print $9; next}
        $4 ~ /^[0-9]+[a-z]*[RW]/      {print $9}
    ' | grep -v '^$' | sort -u | head -5
}

get_open_files() {
    echo "$LSOF_OUTPUT" | awk '
        $4 == "cwd" || $4 == "rtd" || $4 == "txt" || $4 == "mem" || $4 == "DEL" { next }
        $4 !~ /^[3-9][0-9]*[rwuRW]?$/ && $4 !~ /^[0-9]{2,}[rwuRW]?$/ { next }
        $5 != "REG" { next }
        $9 ~ /^\/dev\// || $9 ~ /^\/proc\// || $9 ~ /^\/sys\// { next }
        $9 ~ /\.so($|\.)/ || $9 ~ /\/lib\/|\/lib64\// { next }
        $9 ~ /\.lock$|\.lck$|\.pid$|lockfile/ { next }
        $9 ~ /gconv-modules|ld\.so\.cache|\.cache\// { next }
        $9 != "" { print $9 }
    ' | sort -u | head -5
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

get_ssh_info() {
    local pid=$1
    local env_file="/proc/$pid/environ"

    [[ -r "$env_file" ]] || return

    local ssh_conn=""
    local ssh_user=""

    while IFS= read -r -d '' var; do
        case "$var" in
            SSH_CONNECTION=*)
                ssh_conn="${var#*=}"
                ;;
            SSH_CLIENT=*)
                [[ -z "$ssh_conn" ]] && ssh_conn="${var#*=}"
                ;;
            USER=*)
                ssh_user="${var#*=}"
                ;;
        esac
    done < "$env_file"

    # No ssh info found
    [[ -z "$ssh_conn" ]] && return

    local client_ip="${ssh_conn%% *}"
    if [[ -n "$ssh_user" ]]; then
        echo "${ssh_user}@${client_ip}"
    else
        echo "$client_ip"
    fi
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
        ssh|sshd|sshd-session)
                echo "ssh session" ;;
        tmux*|screen)      echo "terminal multiplexer" ;;
        bash|zsh|fish|sh|dash) echo "interactive $pcomm shell" ;;
        init)              echo "init system" ;;
        *)                 echo "${pcomm:-unknown}" ;;
    esac
}

get_combined_rss() {
    local pid=$1
    local result

    # Single ps call: get all processes with pid, ppid, rss
    # Let awk traverse the tree and sum RSS
    result=$(ps -A -o pid=,ppid=,rss= 2>/dev/null | awk -v root="$pid" '
        {
            # Build parent->children map and store RSS
            p = $1+0; pp = $2+0; rss = $3+0
            children[pp] = children[pp] " " p
            mem[p] = rss
        }
        END {
            # BFS from root to find all descendants
            total = mem[root]+0
            count = (total > 0 ? 1 : 0)
            queue = children[root]
            
            while (queue != "") {
                # Pop first PID from queue
                n = split(queue, arr, " ")
                if (n == 0) break
                
                current = ""
                for (i = 1; i <= n; i++) {
                    if (arr[i] == "") continue
                    p = arr[i]+0
                    if (p > 0 && !visited[p]) {
                        visited[p] = 1
                        total += mem[p]
                        count++
                        current = current " " children[p]
                    }
                }
                queue = current
            }
            
            if (count > 1) {
                printf "%d MB (%d processes)\n", int(total/1024), count
            }
        }
    ')
    
    echo "$result"
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

get_env() {
    local pid=$1

    $SHOW_ENV || $VERBOSE || return

    # Linux: read from /proc
    if [[ -r "/proc/$pid/environ" ]]; then
        tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null
        return
    fi

    # macOS: use ps -E (limited, may require elevated perms)
    local output
    output=$(ps -p "$pid" -E -ww -o command= 2>/dev/null)
    [[ -z "$output" ]] && return

    echo "$output" | tr ' ' '\n' | awk -F= '
        /^[A-Za-z_][A-Za-z0-9_]*=/ { print }
    '
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
    local listen cwd source desc combined_rss git_info docker_info

    desc=$(get_whatis "$PROC_COMM")
    combined_rss=$(get_combined_rss "$pid")
    git_info=$(get_git_info "$pid")
    listen=$(get_listen_ports)
    cwd=$(get_working_dir "$pid")
    source=$(get_source "$pid")
    docker_info=$(get_docker_info "$pid" "$target")

    # Build docker object if present
    local docker_json="null"
    if [[ -n "$docker_info" ]]; then
        local cid cname cimage cip cport
        cid=$(echo "$docker_info" | grep '^container:' | cut -d: -f2)
        cname=$(echo "$docker_info" | grep '^name:' | cut -d: -f2)
        cimage=$(echo "$docker_info" | grep '^image:' | cut -d: -f2)
        cip=$(echo "$docker_info" | grep '^ip:' | cut -d: -f2)
        cport=$(echo "$docker_info" | grep '^port:' | cut -d: -f2)

        if [[ -n "$cip" && -n "$cport" ]]; then
            docker_json=$(jq -n \
                --arg id "$cid" \
                --arg name "$cname" \
                --arg image "$cimage" \
                --arg ip "$cip" \
                --arg port "$cport" \
                '{id: $id, name: $name, image: $image, internal_ip: $ip, internal_port: ($port|tonumber)}')
        else
            docker_json=$(jq -n \
                --arg id "$cid" \
                --arg name "$cname" \
                --arg image "$cimage" \
                '{id: $id, name: $name, image: $image}')
        fi
    fi

    jq -n \
        --arg target "$target" \
        --arg comm "$PROC_COMM" \
        --arg pid "$pid" \
        --arg user "$PROC_USER" \
        --arg command "$PROC_ARGS" \
        --arg started_at "$PROC_LSTART" \
        --arg running_for "$(format_etime "$PROC_ETIME")" \
        --arg rss_mb "$((PROC_RSS / 1024))" \
        --arg combined_rss "$combined_rss" \
        --arg desc "$desc" \
        --arg chain "$(build_chain "$pid")" \
        --arg cwd "$cwd" \
        --arg source "$source" \
        --arg git_info "$git_info" \
        --arg file_handles "$(get_file_handles "$pid")" \
        --argjson listening "$(echo "$listen" | jq -R . | jq -s .)" \
        --argjson open_files "$(get_open_files | jq -R . | jq -s .)" \
        --argjson locked_files "$(get_locked_files | jq -R . | jq -s .)" \
        --argjson warnings "$(collect_warnings "$PROC_USER" "$PROC_RSS" "$listen" | jq -R . | jq -s .)" \
        --argjson docker "$docker_json" \
        --argjson environment "$(get_env "$pid" | jq -R . | jq -s .)" \
        '{
            target: $target,
            process: { name: $comm, pid: ($pid|tonumber), user: $user, description: $desc },
            command: $command,
            started_at: $started_at,
            running_for: $running_for,
            rss_mb: ($rss_mb|tonumber),
            combined_rss: $combined_rss,
            chain: $chain,
            working_dir: $cwd,
            source: $source,
            git_info: $git_info,
            open_files: $open_files,
            locked_files: $locked_files,
            listening: $listening,
            locks: $locks,
            docker: $docker,
            environment: $environment,
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
    local cwd source git_info ssh_info open_files locked_files listen warnings combined_rss desc docker_info

    desc=$(get_whatis "$PROC_COMM")
    combined_rss=$(get_combined_rss "$pid")
    cwd=$(get_working_dir "$pid")
    source=$(get_source "$pid")
    ssh_info=$(get_ssh_info "$pid")
    git_info=$(get_git_info "$pid")
    open_files=$(get_open_files)
    locked_files=$(get_locked_files)
    listen=$(get_listen_ports)
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
    [[ -n "$ssh_info" ]] && printf '%s\n' "${C_CYAN}ssh info${C_RESET}    : ${C_BLUE}$ssh_info${C_RESET}"
    [[ -n "$git_info" ]] && printf '%s\n' "${C_CYAN}git info${C_RESET}    : ${C_BLUE}$git_info${C_RESET}"
    [[ -n "$cwd" ]] && printf '%s\n' "${C_CYAN}Working Dir${C_RESET} : ${C_BLUE}$cwd${C_RESET}"

    if [[ -n "$listen" ]]; then
        printf '%s\n' "${C_CYAN}Listening${C_RESET}   : ${C_GREEN}$(echo "$listen" | head -1)${C_RESET}"
        echo "$listen" | tail -n +2 | while IFS= read -r port; do
            printf '%s\n' "              ${C_GREEN}$port${C_RESET}"
        done
    fi

    if [[ -n "$open_files" ]]; then
        printf '%s\n' "${C_CYAN}Open files${C_RESET}  : ${C_GREEN}$(echo "$open_files" | head -1)${C_RESET}"
        echo "$open_files" | tail -n +2 | while IFS= read -r file; do
            printf '%s\n' "              ${C_GREEN}$file${C_RESET}"
            done
    fi

    if [[ -n "$locked_files" ]]; then
        printf '%s\n' "${C_CYAN}Locks${C_RESET}       : ${C_MAGENTA}$(echo "$locked_files" | head -1)${C_RESET}"
        echo "$locked_files" | tail -n +2 | while IFS= read -r lock; do
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
        printf '%s\n' "  ${C_DIM}docker ps //see all containers${C_RESET}"
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

    if $SHOW_ENV; then
        local env_vars
        env_vars=$(get_env "$pid")
        if [[ -n "$env_vars" ]]; then
            printf '\n'
            printf '%s\n' "${C_CYAN}Environment${C_RESET} :"
            echo "$env_vars" | while IFS= read -r var; do
                printf '%s\n' "  ${C_DIM}$var${C_RESET}"
            done
        fi
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

print_all_ports() {
    local term_width is_macos=false show_desc=true
    local col_pid=8 col_port=8 col_cmd col_desc=0 col_cwd col_uptime=15

    [[ "$(uname)" == "Darwin" ]] && is_macos=true
    $is_macos && ! $FULL_DESC && show_desc=false

    term_width=${COLUMNS:-}
    [[ -z "$term_width" ]] && term_width=$( (stty size </dev/tty | awk '{print $2}') 2>/dev/null )
    [[ -z "$term_width" || "$term_width" == "0" ]] && term_width=$(tput cols 2>/dev/null)
    [[ -z "$term_width" || "$term_width" == "0" ]] && term_width=120

    # Calculate flexible column widths
    local fixed=$((col_pid + col_port + col_uptime + 4))
    local flex=$((term_width - fixed))

    if $VERBOSE; then
        # No truncation - just split space evenly
        col_cmd=$((flex * 50 / 100))
        col_cwd=$((flex - col_cmd))
    elif $show_desc; then
        col_cmd=$((flex * 30 / 100))
        col_desc=$((flex * 25 / 100))
        col_cwd=$((flex - col_cmd - col_desc))
    else
        # Default: COMMAND 40%, CWD 60%
        col_cmd=$((flex * 40 / 100))
        col_cwd=$((flex - col_cmd))
    fi

    # Minimum widths
    [[ $col_cmd -lt 30 ]] && col_cmd=30
    [[ $col_cwd -lt 30 ]] && col_cwd=30

    # Step 1: Get port:pid pairs
    local ports_data pids
    ports_data=$(lsof -i -P -n 2>/dev/null | awk '/LISTEN/{
        for (i=1; i<=NF; i++) {
            if ($i ~ /:\*$|:[0-9]+$/) {
                split($i, a, ":")
                port = a[length(a)]
                if (port ~ /^[0-9]+$/ && !seen[port]++) print port, $2
                break
            }
        }
    }' | sort -n)

    [[ -z "$ports_data" ]] && return

    # Step 2: Extract unique PIDs
    pids=$(echo "$ports_data" | awk '{p[$2]} END {for(i in p) printf "%s,",i}')
    pids=${pids%,}

    # Header
    if $show_desc; then
        printf "${C_BOLD}%-${col_pid}s %-${col_port}s %-${col_cmd}s %-${col_desc}s %-${col_cwd}s %s${C_RESET}\n" \
            "PID" "PORT" "COMMAND" "DESCRIPTION" "CWD" "UPTIME"
    else
        printf "${C_BOLD}%-${col_pid}s %-${col_port}s %-${col_cmd}s %-${col_cwd}s %s${C_RESET}\n" \
            "PID" "PORT" "COMMAND" "CWD" "UPTIME"
    fi
    printf '%*s\n' "$term_width" '' | sed 's/ /─/g'

    # Step 3: Get CWD - use /proc on Linux (faster), lsof on macOS
    local cwd_data=""
    if [[ -d /proc ]]; then
        for p in ${pids//,/ }; do
            local d=$(readlink -f "/proc/$p/cwd" 2>/dev/null)
            [[ -n "$d" ]] && cwd_data+="$p $d"$'\n'
        done
    else
        cwd_data=$(lsof -p "$pids" 2>/dev/null | awk '$4=="cwd" && $9!="" {print $2, $9}')
    fi

    # Step 4: Get ps data
    local ps_data
    ps_data=$(ps -ww -p "$pids" -o pid=,etime=,command= 2>/dev/null)

    # Step 5: Get descriptions if requested (slow - calls whatis for each unique command)
    local desc_data=""
    if $show_desc; then
        local cmds
        cmds=$(echo "$ps_data" | awk '{print $3}' | sort -u)
        while IFS= read -r cmd; do
            [[ -z "$cmd" ]] && continue
            local basename=${cmd##*/}
            local desc
            desc=$(whatis "$basename" 2>/dev/null | head -1 | sed 's/.*- //' | cut -c1-60)
            [[ -n "$desc" ]] && desc_data+="$basename $desc"$'\n'
        done <<< "$cmds"
    fi

    # Step 6: Join and print via pipe
    {
        echo "---PS---"
        echo "$ps_data"
        echo "---CWD---"
        echo "$cwd_data"
        echo "---DESC---"
        echo "$desc_data"
        echo "---PORTS---"
        echo "$ports_data"
    } | awk -v col_pid="$col_pid" -v col_port="$col_port" -v col_cmd="$col_cmd" \
        -v col_cwd="$col_cwd" -v col_desc="$col_desc" -v show_desc="$show_desc" \
        -v verbose="$VERBOSE" \
        -v c_green="$C_GREEN" -v c_dim="$C_DIM" -v c_blue="$C_BLUE" \
        -v c_yellow="$C_YELLOW" -v c_reset="$C_RESET" '
    function smart_truncate(str, maxlen,    sp, exe, args, exe_max, args_max, s, e) {
        if (length(str) <= maxlen) return str
        sp = index(str, " ")
        if (sp == 0) {
            s = int((maxlen - 3) * 0.4)
            e = maxlen - 3 - s
            return substr(str, 1, s) "..." substr(str, length(str) - e + 1)
        }
        exe = substr(str, 1, sp - 1)
        args = substr(str, sp + 1)
        exe_max = int((maxlen - 4) * 0.45)
        args_max = maxlen - exe_max - 4
        if (length(exe) > exe_max) {
            s = int((exe_max - 3) * 0.35)
            e = exe_max - 3 - s
            exe = substr(exe, 1, s) "..." substr(exe, length(exe) - e + 1)
        }
        if (length(args) > args_max) {
            args = "..." substr(args, length(args) - args_max + 4)
        }
        return exe " " args
    }
    /^---PS---$/ { mode="ps"; next }
    /^---CWD---$/ { mode="cwd"; next }
    /^---DESC---$/ { mode="desc"; next }
    /^---PORTS---$/ { mode="ports"; next }
    mode=="ps" && /^[[:space:]]*[0-9]/ {
        pid = $1; etime[pid] = $2
        cmd = ""; for (i = 3; i <= NF; i++) cmd = cmd (cmd ? " " : "") $i
        fullcmd[pid] = cmd
        exe = $3; n = split(exe, parts, "/"); cmdbase[pid] = parts[n]
        next
    }
    mode=="cwd" && NF>=2 { cwd[$1]=$2; next }
    mode=="desc" && NF>=2 { bn=$1; $1=""; sub(/^ */, ""); desc[bn]=$0; next }
    mode=="ports" {
        port = $1; pid = $2
        if (!(pid in fullcmd)) next
        c = fullcmd[pid]; e = etime[pid]
        cw = (pid in cwd) ? cwd[pid] : "-"
        ds = (cmdbase[pid] in desc) ? desc[cmdbase[pid]] : ""
        if (verbose != "true") {
            c = smart_truncate(c, col_cmd)
            if (length(cw) > col_cwd) cw = "..." substr(cw, length(cw)-col_cwd+4)
            if (length(ds) > col_desc) ds = substr(ds, 1, col_desc-3) "..."
        }
        if (show_desc == "true") {
            printf "%-" col_pid "s %-" col_port "s %s%-" col_cmd "s%s %s%-" col_desc "s%s %s%-" col_cwd "s%s %s%s%s\n", \
                pid, port, c_green, c, c_reset, c_dim, ds, c_reset, c_blue, cw, c_reset, c_yellow, e, c_reset
        } else {
            printf "%-" col_pid "s %-" col_port "s %s%-" col_cmd "s%s %s%-" col_cwd "s%s %s%s%s\n", \
                pid, port, c_green, c, c_reset, c_blue, cw, c_reset, c_yellow, e, c_reset
        }
    }'
}

main() {
    local port="" pid="" name="" short=false json=false all_ports=false target=""

    [[ $# -eq 0 ]] && { setup_colors; usage; }

    while [[ $# -gt 0 ]]; do
        case $1 in
            -p|--port)    port="${2:-}"; shift 2 || die "--port requires an argument" ;;
            -P|--pid)     pid="${2:-}"; shift 2 || die "--pid requires an argument" ;;
            -a|--all-ports) all_ports=true; shift ;;
            -s|--short)   short=true; shift ;;
            -j|--json)    json=true; shift ;;
            --no-color)   NO_COLOR=1; shift ;;
            -d|--description) FULL_DESC=true; shift ;;
            -e|--env) SHOW_ENV=true; shift ;;
            -V|--verbose) VERBOSE=true; shift ;;
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

    if $all_ports; then
        print_all_ports
        exit 0
    fi

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

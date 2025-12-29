#!/usr/bin/env sh
#
# procinfo_minimal.sh - pure /proc process inspector
#

die() { printf 'error: %s\n' "$1" >&2; exit 1; }

hex2dec() { printf '%d' "0x$1"; }

hex2ip() {
    printf '%d.%d.%d.%d' \
        "0x$(echo "$1" | cut -c7-8)" \
        "0x$(echo "$1" | cut -c5-6)" \
        "0x$(echo "$1" | cut -c3-4)" \
        "0x$(echo "$1" | cut -c1-2)"
}

get_all_info() {
    pid=$1

    # comm
    read -r comm < "/proc/$pid/comm" 2>/dev/null

    # cmdline
    cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)

    # cwd
    cwd=$(readlink "/proc/$pid/cwd" 2>/dev/null)

    # uid + rss from status
    uid="" rss=""
    while read -r key val rest; do
        case "$key" in
            Uid:) uid=$val ;;
            VmRSS:) rss=$val; break ;;
        esac
    done < "/proc/$pid/status" 2>/dev/null

    # resolve user without awk
    user=""
    if [ "$uid" = "0" ]; then
        user="root"
    else
        while IFS=: read -r name x u rest; do
            [ "$u" = "$uid" ] && user=$name && break
        done < /etc/passwd
    fi
    [ -z "$user" ] && user=$uid

    # open files count - no ls/wc
    open=0
    for f in "/proc/$pid/fd"/*; do
        [ -e "$f" ] && open=$((open + 1))
    done

    # chain - build without subshells
    chain="$comm ($pid)"
    cpid=$pid
    while [ "$cpid" -gt 1 ] 2>/dev/null; do
        read -r statline < "/proc/$cpid/stat" 2>/dev/null || break
        # Extract ppid - field 4 after (comm)
        rest="${statline#*) }"
        set -- $rest
        ppid=$2
        [ -z "$ppid" ] || [ "$ppid" -le 1 ] 2>/dev/null && break
        read -r pcomm < "/proc/$ppid/comm" 2>/dev/null || break
        chain="$pcomm ($ppid) -> $chain"
        cpid=$ppid
    done

    # listening ports
    listen=""
    inodes=""
    for fd in "/proc/$pid/fd"/*; do
        link=$(readlink "$fd" 2>/dev/null) || continue
        case "$link" in
            socket:*)
                inode="${link#socket:[}"
                inodes="$inodes ${inode%]}"
                ;;
        esac
    done

    if [ -n "$inodes" ]; then
        for f in /proc/net/tcp /proc/net/tcp6; do
            [ -f "$f" ] || continue
            while read -r sl local_addr rem_addr st tx_rx tr_tm retr luid timeout inode rest; do
                [ "$st" != "0A" ] && continue
                case "$inodes" in
                    *" $inode"*|"$inode "*)
                        port_hex="${local_addr##*:}"
                        port=$(printf '%d' "0x$port_hex")
                        ip_hex="${local_addr%:*}"
                        if [ ${#ip_hex} -eq 8 ]; then
                            ip=$(hex2ip "$ip_hex")
                            listen="${listen}${ip}:${port}\n"
                        else
                            listen="${listen}[::]:${port}\n"
                        fi
                        ;;
                esac
            done < "$f"
        done
    fi
}

find_pid_by_port() {
    port=$1
    hex_port=$(printf '%04X' "$port")

    inode=""
    for f in /proc/net/tcp /proc/net/tcp6; do
        [ -f "$f" ] || continue
        while read -r sl local_addr rem_addr st rest; do
            [ "$st" != "0A" ] && continue
            addr_port="${local_addr##*:}"
            if [ "$addr_port" = "$hex_port" ]; then
                set -- $rest
                inode=$6
                break 2
            fi
        done < "$f"
    done

    [ -z "$inode" ] && return 1

    # Single find instead of nested loops
    match=$(find /proc/[0-9]*/fd -lname "socket:\[$inode\]" 2>/dev/null | head -1)
    [ -z "$match" ] && return 1

    echo "$match" | cut -d/ -f3
}

find_pid_by_name() {
    name=$1

    match=$(grep -l -i "^${name}$" /proc/[0-9]*/comm 2>/dev/null | head -1)
    if [ -n "$match" ]; then
        echo "${match#/proc/}" | cut -d/ -f1
        return 0
    fi

    match=$(grep -l -i "^${name}" /proc/[0-9]*/comm 2>/dev/null | head -1)
    if [ -n "$match" ]; then
        echo "${match#/proc/}" | cut -d/ -f1
        return 0
    fi

    name_lower=$(echo "$name" | tr 'A-Z' 'a-z')
    for pid_dir in /proc/[0-9]*; do
        pid="${pid_dir#/proc/}"
        [ -f "/proc/$pid/cmdline" ] || continue
        cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | tr 'A-Z' 'a-z')
        case "$cmdline" in
            *procinfo*) continue ;;
            *"$name_lower"*) echo "$pid"; return 0 ;;
        esac
    done

    return 1
}

# Main
[ $# -eq 0 ] && { echo "Usage: $0 [--port PORT | --pid PID | NAME]"; exit 1; }

pid="" target=""

case "$1" in
    --port)
        [ -z "$2" ] && die "--port requires argument"
        target="port $2"
        pid=$(find_pid_by_port "$2") || die "nothing listening on port $2"
        ;;
    --pid)
        [ -z "$2" ] && die "--pid requires argument"
        target="pid $2"
        pid=$2
        [ -d "/proc/$pid" ] || die "process $pid not found"
        ;;
    -*)
        echo "Usage: $0 [--port PORT | --pid PID | NAME]"; exit 1
        ;;
    *)
        target="$1"
        pid=$(find_pid_by_name "$1") || die "no process found: $1"
        ;;
esac

get_all_info "$pid"

printf 'Target      : %s\n\n' "$target"
printf 'Process     : %s (pid %s)\n' "$comm" "$pid"
printf 'User        : %s\n' "$user"
printf 'Command     : %s\n' "$cmdline"
[ -n "$rss" ] && printf 'RSS Memory  : %s MB\n' "$((rss / 1024))"
printf '\n'
printf 'Process tree:\n'
printf '  %s\n' "$chain"
printf '\n'
[ -n "$cwd" ] && printf 'Working Dir : %s\n' "$cwd"
[ -n "$listen" ] && printf 'Listening   : %b' "$listen"
[ "$open" -gt 0 ] && printf 'Open Files  : %s\n' "$open"

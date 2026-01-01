# procinfo

A portable process inspector for Linux and macOS. Get details about any running process instantly!

<img width="695" height="582" alt="procinfo_docker" src="https://github.com/user-attachments/assets/2f43fb5a-40f3-4a5f-a3f4-15b0d30b03c3" />

Also see procinfo_minimal.sh - pure sh implementation of procinfo.

## Installation
```bash
curl -fsSL https://raw.githubusercontent.com/wenekar/procinfo/main/procinfo.sh -o procinfo
chmod +x procinfo
sudo mv procinfo /usr/local/bin/
```

Or just copy the script. It's a bash script with no dependencies beyond standard Unix tools (`ps`, `lsof`, `pgrep`). Or better yet, copy parts of it, combine them, make one script that satisfies your specific needs!

## Features

- **Cross-platform** - Works on Linux and macOS (no Windows?)
- **Zero dependencies** - Except for bash and standard Unix tools, and maybe an operating system.
- **Process tree** - See all parents of a given process. (shocking!)
- **Environment inspection** - See ENV variables for a given process (-V or --env)
- **Systemd integration** - If a process belongs to a .service, shows the path to that .service file.
- **SSH integration** - Instantly see the user@IP of the ssh-session that started the process.
- **git integration** - Does the process belong to a git repo? See the branch, and remote URL directly in the output.
- **Docker aware** - Detects containers, composes, container-id, image name, port bindings... May add more info later.
- **Network info** - Shows all listening ports for a process.
- **Port list** - Pretty ss -tunlp output for everyone!
- **Lock detection** - Shows lock files and open files of the process.
- **Multiple formats** - Human-readable, short one-liner, or JSON
- **Case-insensitive** - `procinfo nginx` matches `Nginx`, `NGINX`, etc.

## Requirements

procinfo:
- A UNIX-like system
- bash
- ps
- lsof
- pgrep

Optional dependencies:
- docker
- git
- systemctl
- whatis (included with man)
- jq (json output support)

procinfo_minimal:
- sh

## Usage
```bash
# Interactive TUI mode (requires fzf)
procinfo --tui

# By process name
procinfo nginx

# By port
procinfo --port 3306

# By PID
procinfo --pid 1234

# One-line output
procinfo --short nginx

# JSON output (requires jq)
procinfo --json nginx
```

## Example Output
```
Target      : godot

Process     : godot.linuxbsd. (pid 234167)
User        : wenekar
Command     : ./bin/godot.linuxbsd.editor.x86_64 --verbose
Started at  : Wed Dec 31 19:12:10 2025
Running for : 1 minute, 6 seconds
RSS Memory  : 330 MB

Process tree:
  systemd (pid 1) → systemd (pid 1141) → konsole (pid 1725) → fish (pid 233851) → godot.linuxbsd. (pid 234167)

Source      : interactive fish shell
git info    : godot (fix-libdecor-ssd-fallback) - git@github.com:wenekar/godot.git
Working Dir : /mnt/Sandisk480/GitHub/godot
Open files  : /memfd:kwin-xkb-keymap-shared
              /memfd:wayland-cursor
```

### Docker Container
When inspecting a port bound to a Docker container:
```
Target      : port 6379

Process     : docker-proxy (pid 31782)
User        : root
Command     : /usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 6379 -container-ip 172.18.0.2 -container-port 6379 -use-listen-fd
Started at  : Wed Dec 31 01:45:01 2025
Running for : 17 hours, 28 minutes, 39 seconds
RSS Memory  : 6 MB

Process tree:
  systemd (pid 1) → dockerd (pid 25817) → docker-proxy (pid 31782)

Source      : container runtime
git info    : not found
Working Dir : /
Listening   : *:6379

Docker info :
  Container : redis (463ab2f88502)
  Image     : redis
  Compose   : backend_test (/home/wenekar/backend_test/docker-compose.yml)
  Internal  : 172.18.0.2:6379

Docker cheatsheet:
  docker logs redis
  docker exec -it redis sh
  docker top redis
  docker ps //see all containers
```

## Options

| Option | Description |
|--------|-------------|
| `-p, --port <port>` | Find process listening on port |
| `-P, --pid <pid>` | Inspect specific PID |
| `-a, --all-ports` | List all listening ports |
| `-t, --tui` | Interactive TUI mode (requires fzf) |
| `-s, --short` | One-line output (just the process chain) |
| `-j, --json` | JSON output (requires jq) |
| `-d, --description` | Wait for process description (slow on macOS) |
| `--no-color` | Disable colored output |
| `-h, --help` | Show help |
| `-v, --version` | Show version |

## Why?

I saw an ad on TikTok about a project called witr, [link to said TikTok video](https://vt.tiktok.com/ZS5LXha1T).
Then I thought to myself, who is the target user? Who is that binary for? Isn't this just a bash wrapper of `ps -p`?

Thus came procinfo, turns out, _I_ am that target user. Also see [issue 32](https://github.com/pranshuparmar/witr/issues/32).

## License

MIT

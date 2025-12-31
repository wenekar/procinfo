# procinfo

A portable process inspector for Linux and macOS. Get details about any running process instantly!

<img width="1293" height="524" alt="procinfo example" src="https://github.com/user-attachments/assets/5e912e8c-c87a-44ab-aa09-b43fc139a708" />

Also see procinfo_minimal.sh - pure sh implementation of procinfo.

## Installation
```bash
curl -fsSL https://raw.githubusercontent.com/wenekar/procinfo/main/procinfo.sh -o procinfo
chmod +x procinfo
sudo mv procinfo /usr/local/bin/
```

Or just copy the script. It's a bash script with no dependencies beyond standard Unix tools (`ps`, `lsof`, `pgrep`). Or better yet, copy parts of it, combine them, make one script that satisfies your specific needs!

## Usage
```bash
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
Target      : port 5432

Process     : postgres (pid 1234)
User        : postgres
Command     : /usr/lib/postgresql/15/bin/postgres -D /var/lib/postgresql/15/main
Started at  : Wed Dec 25 10:30:00 2025
Running for : 4 days, 6 hours, 23 minutes
RSS         : 128 MB

Process tree:
  systemd (pid 1) → postgres (pid 1234)

Source      : systemd service
Working Dir : /var/lib/postgresql/15/main
Listening   : 127.0.0.1:5432
              *:5432
File Handles: 45 of 1024 (4%)
Locks       : /var/lib/postgresql/15/main/postmaster.pid

Extra info  :
  - Process is listening on a public interface
```

### Docker Container
When inspecting a port bound to a Docker container:
```
Target      : port 6379

Process     : docker-proxy (pid 5678)
...

Docker info :
  Container : my-redis (abc123def456)
  Image     : redis:alpine
  Internal  : 172.17.0.2:6379

Docker cheatsheet:
  docker logs my-redis
  docker exec -it my-redis sh
  docker top my-redis
  docker ps //see all containers
```

## Features

- **Cross-platform** - Works on Linux and macOS
- **Zero dependencies** - Just bash and standard Unix tools
- **Process ancestry** - Shows the full chain of how a process came to exist (including systemd.service files if found)
- **Source detection** - Identifies systemd, launchd, Docker, pm2, cron, SSH, etc.
- **Docker awareness** - Detects containers behind port bindings, shows image and helpful commands
- **Network info** - Shows all listening ports for a process
- **Lock detection** - Shows lock files held by the process
- **Multiple formats** - Human-readable, short one-liner, or JSON
- **Case-insensitive** - `procinfo nginx` matches `Nginx`, `NGINX`, etc.

## Options

| Option | Description |
|--------|-------------|
| `-p, --port <port>` | Find process listening on port |
| `-P, --pid <pid>` | Inspect specific PID |
| `-s, --short` | One-line output (just the process chain) |
| `-j, --json` | JSON output (requires jq) |
| `-d, --description` | Wait for process description (slow on macOS) |
| `--no-color` | Disable colored output |
| `-h, --help` | Show help |
| `-v, --version` | Show version |

## Why?

I saw an ad on TikTok of this [link to said TikTok video](https://vt.tiktok.com/ZS5LXha1T) written in Go with 4k+ GitHub stars.
Then I thought to myself, who is the target user? Who is that binary for? Isn't this just a bash wrapper of `ps -p`?

Thus came procinfo, also see [issue 32](https://github.com/pranshuparmar/witr/issues/32).

## License

MIT

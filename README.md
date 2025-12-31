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
Target      : port 8000

Process     : com.docker.backend (pid 2398)
User        : wenekar
Command     : /Applications/Docker.app/Contents/MacOS/com.docker.backend services
Started at  : Thu Dec 25 09:53:50 2025
Running for : 6 days, 7 hours, 22 minutes, 44 seconds
RSS Memory  : 112 MB
Combined RSS: 141 MB (2 processes)

Process tree:
  launchd (pid 1) → com.docker.backend (pid 2396) → com.docker.backend (pid 2398)

Source      : com.docker.backend
Working Dir : /Users/wenekar/Library/Containers/com.docker.docker/Data
Listening   : *:15672
              *:27017
              *:5432
              *:5672
              *:6379
              *:8000
Open files  : /Users/wenekar/.docker/.token_seed
              /Users/wenekar/.docker/config.json
              /Users/wenekar/.docker/contexts/meta/fe9c6bd7a66301f49ca9b6a70b217107cd1284598bfc254700c989b916da791e/meta.json
              /Users/wenekar/.docker/daemon.json
              /Users/wenekar/Documents/GitLab/backend/.env.docker
Locks       : /Users/wenekar/.docker/.token_seed.lock
              /Users/wenekar/.docker/mutagen/daemon/daemon.lock
              /Users/wenekar/Library/Containers/com.docker.docker/backend.lock

Docker info :
  Container : backend-django-backend-1 (78b6e1cdc4ae)
  Image     : backend-django-backend
  Compose   : backend (/Users/wenekar/Documents/GitLab/backend/docker-compose.yml)

Docker cheatsheet:
  docker logs backend-django-backend-1
  docker exec -it backend-django-backend-1 sh
  docker top backend-django-backend-1
  docker ps //see all containers
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

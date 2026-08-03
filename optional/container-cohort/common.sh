#!/usr/bin/env bash

cc_script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cc_repo_root=$(CDPATH= cd -- "$cc_script_dir/../.." && pwd)
cc_compose_file="$cc_script_dir/docker-compose.dev.yml"
cc_env_file="$cc_script_dir/dev.env"

cc_is_wsl() {
  [[ -n "${WSL_DISTRO_NAME:-}" ]] || grep -qi microsoft /proc/version 2>/dev/null
}

cc_print_docker_help() {
  local probe_output="${1:-}"

  if cc_is_wsl; then
    cat >&2 <<EOF
Docker is installed but not usable from this WSL shell.

If you are using Docker Desktop with WSL 2:
1. Start Docker Desktop on Windows.
2. Open Docker Desktop -> Settings -> Resources -> WSL Integration.
3. Enable integration for this distro${WSL_DISTRO_NAME:+ (${WSL_DISTRO_NAME})}.
4. Open a new WSL terminal and rerun one of these:
   ./optional/container-cohort/up.sh
   cd optional/container-cohort && ./up.sh

If you prefer not to use Docker Desktop, install Docker Engine and the Compose plugin directly inside this distro instead.

Docker probe output:
${probe_output}
EOF
    return
  fi

  cat >&2 <<EOF
Docker is installed but not responding in this shell.

Make sure the Docker daemon is running, then retry:
  ./optional/container-cohort/up.sh

Docker probe output:
${probe_output}
EOF
}

cc_require_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    cat >&2 <<'EOF'
Docker CLI is not installed or not on PATH.

Install Docker (or Docker Desktop with WSL integration) before running the container cohort helpers.
EOF
    exit 127
  fi

  local probe_output
  if ! probe_output=$(docker info 2>&1); then
    cc_print_docker_help "$probe_output"
    exit 1
  fi
}

cc_run_compose() {
  local subcommand="${1:?missing compose subcommand}"
  shift || true

  cc_require_docker

  cd "$cc_repo_root"

  if [[ -f "$cc_env_file" ]]; then
    docker compose --env-file "$cc_env_file" -f "$cc_compose_file" "$subcommand" "$@"
  else
    docker compose -f "$cc_compose_file" "$subcommand" "$@"
  fi
}

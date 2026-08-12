#!/usr/bin/env bash
# Start the nested Docker daemon, then run whatever the caller asked for.
set -euo pipefail

echo "==> starting nested dockerd"
dockerd >/tmp/dockerd.log 2>&1 &

for _ in $(seq 1 60); do
  if docker info >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
if ! docker info >/dev/null 2>&1; then
  echo "nested dockerd never came up:" >&2
  tail -40 /tmp/dockerd.log >&2
  exit 1
fi
echo "==> dockerd ready ($(docker version --format '{{.Server.Version}}'))"

cd /repo

# Never touch the host's .venv through the bind mount — it holds macOS binaries.
export UV_PROJECT_ENVIRONMENT=/tmp/lxvenv
export UV_CACHE_DIR=/tmp/uvcache
export UV_PYTHON_INSTALL_DIR=/tmp/uvpython
# Match CI exactly. Left unpinned, uv picks the newest interpreter satisfying
# requires-python (3.14 at the time of writing) — the suite passes there too,
# but a harness that quietly tests a different Python than CI is not a
# reproduction of CI.
export UV_PYTHON=3.12
# BuildKit wants a writable ~/.docker/buildx and buys nothing here.
export DOCKER_BUILDKIT=0

echo "==> uv sync"
uv sync --frozen 2>&1 | tail -2

echo "==> ${*:-pytest packages -q}"
exec uv run "${@:-pytest}"

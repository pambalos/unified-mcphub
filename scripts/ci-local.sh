#!/usr/bin/env bash
# Run the CI suite the way CI runs it: Linux, with a real Docker daemon.
#
#   scripts/ci-local.sh                    # integration suite, minus Langfuse
#   scripts/ci-local.sh pytest packages -q # anything else
#
# This exists because "it passes on my machine" has been wrong twice on this
# repo in ways only Linux or only a container would have shown: `crewai` cannot
# install on an Intel Mac at all, and the whole integration suite had never run
# on the platform it deploys to.
#
# Note the images are pulled *inside* the nested daemon, so the first run does
# not share the host's image cache and takes a few minutes. The Langfuse matrix
# is excluded by default for that reason — pass it explicitly if you want it.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="unified-ci-local:latest"

DEFAULT_ARGS=(
  pytest packages -m integration -q -p no:cacheprovider
  --ignore=packages/unified-enforce/tests/integration/test_otlp_backends.py
)

echo "==> building $IMAGE"
DOCKER_BUILDKIT=0 docker build -q -t "$IMAGE" "$REPO/scripts/ci-local" >/dev/null

echo "==> running (privileged; nested dockerd)"
exec docker run --rm --privileged \
  -v "$REPO:/repo" \
  -e PYTEST_ADDOPTS="${PYTEST_ADDOPTS:-}" \
  "$IMAGE" "${@:-${DEFAULT_ARGS[@]}}"

# Reproduce the Linux CI environment locally, Docker and all.
#
# Why a nested daemon rather than mounting the host's socket: the integration
# suite starts containers *and* talks to them from the test process. With a
# mounted socket those containers are siblings on the host, so the engine
# running inside the test container is not reachable at `host.docker.internal`
# and bind-mount paths resolve against the host filesystem rather than ours.
# Docker-in-Docker gives one self-consistent Linux environment — exactly what a
# CI runner has, where the tests run on the host beside its daemon.
#
# Why Debian rather than the official `docker:dind` (Alpine): musl. Two of our
# dependencies publish no musllinux wheel — `onnxruntime` (via crewai) and
# `google-re2` (via cel-python, so the *engine itself* will not install) — and
# building them from source in a throwaway container is a poor trade. CI runs
# `ubuntu-latest`, so glibc is also the more faithful reproduction.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl gnupg iptables uidmap procps \
 && install -m 0755 -d /etc/apt/keyrings \
 && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
 && chmod a+r /etc/apt/keyrings/docker.asc \
 && echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable" \
      > /etc/apt/sources.list.d/docker.list \
 && apt-get update && apt-get install -y --no-install-recommends \
      docker-ce docker-ce-cli containerd.io docker-buildx-plugin \
 && rm -rf /var/lib/apt/lists/*

# Terraform, so test_terraform_modules.py validates rather than skips. A skip
# here would read as coverage this environment does not actually have.
RUN curl -fsSL https://apt.releases.hashicorp.com/gpg -o /etc/apt/keyrings/hashicorp.asc \
 && chmod a+r /etc/apt/keyrings/hashicorp.asc \
 && echo "deb [signed-by=/etc/apt/keyrings/hashicorp.asc] https://apt.releases.hashicorp.com bookworm main" \
      > /etc/apt/sources.list.d/hashicorp.list \
 && apt-get update && apt-get install -y --no-install-recommends terraform \
 && rm -rf /var/lib/apt/lists/*

# uv brings its own CPython, so the distro's Python is irrelevant here.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

# An anonymous volume: overlay2 refuses to stack on the container's own overlay
# filesystem, and the alternative (--storage-driver=vfs) copies whole images on
# every layer, which turns an Envoy pull into minutes.
VOLUME /var/lib/docker

COPY entrypoint.sh /usr/local/bin/ci-entrypoint
RUN chmod +x /usr/local/bin/ci-entrypoint

ENTRYPOINT ["/usr/local/bin/ci-entrypoint"]

# Security

## Reporting a vulnerability

Email **security@unified-ai.app** with enough detail to reproduce. If you would
rather not send details in plain email, say so and we will arrange an encrypted
channel first.

- **Acknowledgement within 2 working days.** If you have not heard back in that
  window, assume the mail did not arrive and try again.
- **An assessment within 10 working days**, including whether we agree it is a
  vulnerability and what we intend to do.
- **Coordinated disclosure.** We will agree a date with you. We would rather
  publish a fix and a full description than a quiet patch, and we will credit
  you unless you ask us not to.
- **No legal action** for good-faith research: testing against your own
  deployment, reporting privately, and not accessing anyone else's data.

Please do **not** open a public issue for a vulnerability.

## What counts

In scope: anything that lets an action past enforcement, forges or replays an
identity across the boundaries in the [threat model](docs/threat-model.md),
tampers with evidence undetected, or crosses a tenant boundary in the control
plane.

Out of scope, and stated so you do not waste your time: findings that require
already holding a private key the design assumes is secret; denial of service by
volume against a self-hosted deployment; and the deliberate limits documented in
the threat model — those are known, written down, and we would rather hear that
the *documentation* is wrong than that the limit exists.

## Supported versions

Pre-1.0. The latest minor release receives security fixes; older ones do not.
That changes at 1.0, and this file will say so when it does.

| version | supported |
|---|---|
| latest minor | yes |
| anything older | no |

## What this project is, in one paragraph

An enforcement plane for AI agents: a policy engine that decides whether an
agent's tool call is permitted, a tamper-evident audit chain of what it
attempted, and a control plane that distributes signed policy and lets a human
stop an agent. The security posture is written up in full in
[docs/threat-model.md](docs/threat-model.md), including the things it does not
defend against.

## The boundary worth reading before you deploy

**The hub ships unsandboxed.** MCP servers run as ordinary child processes with
the privileges of the user that started them, and a malicious or compromised
server is therefore a compromise of that account. Container and process
sandboxing is tracked in the *M0.5 · Security Hardening* milestone and is not
done. If you are running untrusted MCP servers today, run the hub in a container
or as a dedicated low-privilege user — do not rely on the enforcement plane to
contain a server that has already been given a shell.

Enforcement governs what an agent may *ask a server to do*. It is not a sandbox
for the server itself, and conflating the two is the most likely way to be
surprised by this project.

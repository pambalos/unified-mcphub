# Deployment security: what `locked` protects, and what only the OS can

`deployment.policy_protection: locked` exists to stop an agent granting itself
authority by editing the policy that constrains it. This is what each control
actually buys, in the order they stop things — and where the line is.

## The controls, and their limits

**Reload-gating.** In `locked`, `reload_mode` defaults to `approval`: a change
to a policy file is logged and not applied. This is the robust one, because it
does not care *how* the file was written — a shell redirection, a Python
`open()`, a text editor, all the same. `locked` + `reload_mode: hot` is refused
at config load, because it cancels exactly this.

The deployment profile itself is fixed at boot and is not re-read on reload, in
either direction. Otherwise the one control protecting policy from tampering
could be switched off by editing the file it protects. Changing `locked`/`open`
takes a restart.

**Constitutional denies.** A precedence tier above every workspace rule, which
no workspace rule can waive. In `locked` it denies filesystem writes into the
hub config directory. Matched with `path_under`, so `..`, `~`, and symlinks all
resolve before the comparison, and a sibling directory sharing a name prefix is
not swept up.

**One canonicalisation, shared.** The component that decides and the component
that opens the file both import `unified_paths.canonical`. They previously
disagreed — the engine resolved symlinks, the filesystem server did not — which
is enough for an authorisation to examine one file while the write lands on
another. The hub also canonicalises a server's declared `path_args` *before*
deciding and forwards the canonical form, so the path the policy authorised is
the path the server receives.

**Fail closed on indeterminate.** A path that does not reduce to one location —
a relative path with no known base, a value the filesystem will not parse — is
treated as matching a deny rule and as not matching an allow rule. The uncertain
case never resolves in the permissive direction.

## Where the line is

All of the above decide on a path *string*, before the write. The kernel
resolves the path again, at the write. Between those two moments the filesystem
can change: a symlink that pointed somewhere harmless when the policy read it
can point into the config directory by the time the server opens it. This is a
time-of-check/time-of-use gap and it is not closable by better matching. Nor
does a path check see a shell redirection, which carries no path argument at all.

**So the policy layer is defence in depth. The boundary is filesystem
permissions.**

## Running `locked` properly

Give the MCP server processes an account that cannot write the policy directory.
Either is sufficient:

```sh
# Separate account: the hub owns its config, the servers cannot write it.
chown -R hub:hub  ~/.unified-ai/mcphub
chmod -R o-w      ~/.unified-ai/mcphub
# ...and run the server subprocesses as a different, non-hub user.
```

```yaml
# Or, in a container: mount the policy directory read-only for the servers.
volumes:
  - ./mcphub:/home/app/.unified-ai/mcphub:ro
```

With this in place, none of the path-matching subtleties above are load-bearing:
symlink races, `..` traversal, relative-path bases, hardlinks, and shell
redirection all fail at the kernel, regardless of what the policy layer
concluded.

The hub logs a warning at startup when `policy_protection: locked` is set and
the policy directory is still writable by the account it runs as. It is advisory
rather than fatal: a hub that refuses to boot protects nothing.

A deployment that wants the OS boundary treated as a hard precondition sets
`deployment.require_protected_config_dir: true`. In `locked`, that turns the
warning into a boot refusal (`PolicyDirWritableError`) when the policy directory
is writable by the account the servers run as — for an operator who would rather
fail to start than serve with the real boundary missing. Off by default, for the
reason above.

## Still open

- `manual`/`approval` reload currently log the pending change; wiring an
  explicit reload signal and an approval-queue application is follow-up work.
- Self-broadening *content* analysis — an agent that may propose policy but not
  grant itself allow — belongs with the Layer-2 policy-diff detector.

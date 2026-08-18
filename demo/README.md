# The three-minute demo (UAI-187)

One deterministic terminal run showing the full enforcement loop: deny with
the latency on screen, the signed hash-chain record, tampering caught by
offline `verify`, a candidate policy measured by offline `replay`, and a
DEFER handed to a human. Terminal-first, no slideware, every number measured
on the machine running it.

```sh
uv run python demo/three_minutes.py
```

Scratch state lives in `demo/.run/` and is wiped on each start. Nothing else
is touched; no network, no services.

## Recording

```sh
brew install asciinema
asciinema rec -c "uv run python demo/three_minutes.py" demo.cast
# or screen-capture a terminal at ~100 columns and voice over it
```

The script prints instantly; pause on each act while narrating, or wrap the
run in `less -R` output paging if you want manual pacing.

## Voiceover beats (~3 minutes)

**Act 1 — the deny (45s).** "This is a finance agent with real authority and
real limits. Reading the ledger is its job — allowed. Reading the vault is
not — denied, with the reason in the record. A forty-eight-thousand-dollar
wire is over the hard cap, so it's refused *before execution* — that's the
whole point: not a flag in a dashboard afterwards, a refusal beforehand. The
latency is on screen — sub-millisecond hot path, measured in-process on this
laptop, and we say exactly that on our site."

**Act 2 — the record (45s).** "Every decision is a link in a hash chain, and
every link is signed with Ed25519. Offline `verify` walks the chain — no
server, no vendor, an auditor can run it on a laptop. Now watch what happens
when someone edits one digit of one amount in the log: verify names the
exact file and line that broke. Tamper-evident isn't a slogan, it's a
property you can test in front of your compliance team."

**Act 3 — the replay (45s).** "Someone proposes raising the cap to sixty
thousand. Before that ships, we replay the recorded history against the
candidate policy — offline. It reports exactly which past verdicts change:
the forty-eight-thousand-dollar wire that was refused would now go to a
human instead. You know what a policy change does *before* rollout, not
after the money moves."

**Act 4 — the defer (30s).** "In between the hard cap and the routine, a
human decides. Seventy-five hundred dollars defers — it waits in the
approvals console, and the human's resolution lands as its own signed entry,
joined to the action by digest. Allow, deny, or defer to a human —
deterministically, before execution."

**Close (15s).** "Self-hosted, air-gap capable, MIT engine in the coming
weeks — design partners get repo access today. Everything you just saw is
measured, with its boundary stated."

## Honesty notes

- The per-call figures include the signed audit write; the p50/p99 loop is
  the pure decision path. Both are in-process on local hardware — never quote
  them as end-to-end gateway latency (that's being measured with design
  partners; see `docs/threat-model.md`).
- The tamper check `assert`s that verification actually fails — if the
  enforcement library ever regressed there, the demo crashes rather than
  narrating a property that no longer holds.

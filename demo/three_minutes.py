"""The three-minute demo (UAI-187): deny, prove, replay, defer.

One deterministic run of the enforcement loop against a real policy, printing
what a design partner needs to see: a forbidden action refused before
execution with the latency on screen, the signed hash-chain entry it left
behind, tampering caught by offline `verify`, a candidate policy measured by
offline `replay`, and a mid-sized action deferred to a human.

Run it from the repo root:

    uv run python demo/three_minutes.py

Everything happens in-process against a scratch audit directory under
demo/.run/ (wiped on each start). No network, no services, no cleanup to
forget. Latency figures are measured on the machine running the demo and are
labeled for what they are — in-process, this hardware.
"""

from __future__ import annotations

import json
import shutil
import statistics
import time
from pathlib import Path

from unified_enforce import (
    Action,
    ActionContext,
    AuditChain,
    Enforcer,
    PolicyEngine,
    Principal,
    Signer,
    replay,
)

HERE = Path(__file__).parent
RUN_DIR = HERE / ".run"
AUDIT_DIR = RUN_DIR / "audit"

# --- terminal dressing -------------------------------------------------------

RESET, BOLD, DIM = "\x1b[0m", "\x1b[1m", "\x1b[2m"
RED, GREEN, YELLOW, CYAN = "\x1b[31m", "\x1b[32m", "\x1b[33m", "\x1b[36m"
VERDICT_COLOR = {"allow": GREEN, "deny": RED, "defer": YELLOW}


def header(title: str) -> None:
    print()
    print(f"{BOLD}{CYAN}── {title} {'─' * max(0, 68 - len(title))}{RESET}")
    print()


def show(decision, action, elapsed_ms: float) -> None:
    color = VERDICT_COLOR[decision.verdict.value]
    verdict = f"{color}{BOLD}{decision.verdict.value.upper():6s}{RESET}"
    amount = action.params.get("amount")
    what = f"{action.tool}  {action.verb}" + (f"  ${amount:,}" if amount else "")
    print(f"  {verdict}  {what}")
    print(f"          rule: {decision.rule_id or 'default-deny (non-configurable)'}")
    if decision.reason:
        print(f"          reason: {DIM}{decision.reason}{RESET}")
    print(f"          decided before execution in {BOLD}{elapsed_ms:.2f} ms{RESET}")
    print()


def attempt(enforcer: Enforcer, tool: str, verb: str, **params):
    action = Action.build(
        principal=Principal(id="agent:finops-1", kind="agent"),
        tool=tool,
        verb=verb,
        resource="acct:operating",
        params=params,
        context=ActionContext(origin="sdk", workspace="demo"),
    )
    t0 = time.perf_counter()
    decision = enforcer.enforce(action)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    show(decision, action, elapsed_ms)
    return action, decision


def main() -> None:
    shutil.rmtree(RUN_DIR, ignore_errors=True)
    AUDIT_DIR.mkdir(parents=True)

    engine = PolicyEngine.from_yaml((HERE / "policy.yaml").read_text())
    signer = Signer.generate("demo-key-2026")
    chain = AuditChain(AUDIT_DIR, signer=signer)
    chain.start()
    enforcer = Enforcer(engine, chain=chain)

    print(f"{BOLD}unified-enforce — the enforcement plane for AI agents{RESET}")
    print(f"{DIM}policy: demo/policy.yaml · audit: demo/.run/audit · signing: Ed25519{RESET}")

    # ── Act 1: the deny ─────────────────────────────────────────────────────
    header("1 · An agent tries three things")
    attempt(enforcer, "mcp://ledger/transactions", "read", account="operating")
    attempt(enforcer, "mcp://vault/get_secret", "read", key="prod/db-password")
    attempt(enforcer, "sdk://payments/wire_transfer", "create", amount=48_000, to="acct:9931")

    # The honest in-process figure: the pure decision path, measured hot.
    samples = []
    probe = Action.build(
        principal=Principal(id="agent:finops-1", kind="agent"),
        tool="sdk://payments/wire_transfer",
        verb="create",
        resource="acct:operating",
        params={"amount": 48_000, "to": "acct:9931"},
    )
    for _ in range(2_000):
        t0 = time.perf_counter()
        engine.decide(probe, None)
        samples.append((time.perf_counter() - t0) * 1000)
    quantiles = statistics.quantiles(samples, n=100)
    print(
        f"  {DIM}decision path, 2,000 hot calls on this machine (in-process): "
        f"p50 {quantiles[49]:.2f} ms · p99 {quantiles[98]:.2f} ms{RESET}"
    )

    # ── Act 2: the record, and what happens to a tampered one ───────────────
    header("2 · Every decision is a signed link in a hash chain")
    chain.stop()
    day_file = next(iter(sorted(AUDIT_DIR.glob("*.jsonl"))))
    last = json.loads(day_file.read_text().splitlines()[-1])
    for key in ("seq", "kind", "prev_hash", "hash", "sig", "key_id"):
        value = str(last.get(key, ""))
        shown = value if len(value) <= 48 else value[:45] + "..."
        print(f"  {key:9s} {DIM}{shown}{RESET}")
    payload = last.get("payload", {})
    print(f"  {'verdict':9s} {payload.get('verdict')}  ({payload.get('rule_id')})")
    print(f"  {'digest':9s} {DIM}{payload.get('action_digest', '')[:45]}...{RESET}")

    result = AuditChain.verify(AUDIT_DIR, public_key=signer.public_bytes())
    print(
        f"\n  offline verify: {GREEN}{BOLD}OK{RESET} — {result.entries} entries, "
        f"chain intact, every signature checks"
    )

    original = day_file.read_bytes()
    edited = original.replace(b"48000", b"18000", 1)
    assert edited != original, "tamper edit found nothing to change — demo bug"
    day_file.write_bytes(edited)
    tampered = AuditChain.verify(AUDIT_DIR, public_key=signer.public_bytes())
    assert not tampered.ok, "tampering went undetected — that would be a real bug"
    print("  edit one digit of one amount and run it again:")
    print(f"  offline verify: {RED}{BOLD}TAMPERED{RESET} — {tampered.error}")
    day_file.write_bytes(original)

    # ── Act 3: replay a candidate policy against recorded history ───────────
    header("3 · A proposed policy change, measured before it ships")
    candidate = PolicyEngine.from_yaml((HERE / "candidate-policy.yaml").read_text())
    report = replay(AUDIT_DIR, candidate)
    print("  candidate: raise the hard cap $25,000 → $60,000 (demo/candidate-policy.yaml)")
    print(f"  replayed {report.replayed} of {report.total} recorded decisions offline:\n")
    for d in report.divergences:
        print(
            f"  seq {d.seq}: {d.tool}  "
            f"{VERDICT_COLOR[d.recorded_verdict]}{d.recorded_verdict.upper()}{RESET}"
            f" → {VERDICT_COLOR[d.replayed_verdict]}{d.replayed_verdict.upper()}{RESET}"
            f"  {DIM}({d.recorded_rule} → {d.replayed_rule}){RESET}"
        )
    if report.divergences:
        print(
            f"\n  {DIM}the $48,000 wire that was refused would now go to a human instead —"
            f"\n  known before rollout, not discovered after the money moves{RESET}"
        )

    # ── Act 4: the defer ────────────────────────────────────────────────────
    header("4 · Between the lines, a human decides")
    chain2 = AuditChain(AUDIT_DIR, signer=signer)
    chain2.start()
    enforcer2 = Enforcer(engine, chain=chain2)
    attempt(enforcer2, "sdk://payments/wire_transfer", "create", amount=7_500, to="acct:2204")
    chain2.stop()
    print(
        f"  {DIM}a DEFER waits in the approvals console; the human's resolution lands"
        f"\n  as its own signed entry, joined to this action by digest{RESET}"
    )

    print()
    print(
        f"{DIM}Latency measured in-process on this machine. End-to-end behind Envoy"
        f"\nis being measured with design partners — see docs/threat-model.md for"
        f"\nexact guarantees and their boundaries.{RESET}"
    )


if __name__ == "__main__":
    main()

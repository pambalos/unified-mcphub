#!/usr/bin/env bash
# Prove the shipped NetworkPolicy pair on a real cluster, not by reading it.
#
# The manifest was structurally validated from the day it shipped; that proves
# the YAML parses, and nothing else. Whether it *enforces* depends entirely on
# the cluster's CNI — on kindnet or any CNI that ignores NetworkPolicy, the
# file is decoration. So this script measures, with the same shape as the AWS
# harness: a CONTROL pod with no labels proves the network works, and the
# difference between it and the enforced pods is the assertion.
#
#   ./verify-kubernetes-networkpolicy.sh [kubectl-context]
#
# Creates namespaces `agents` and `unified-verify-upstream`, applies the
# SHIPPED kubernetes-networkpolicy.yaml verbatim, probes, and deletes both
# namespaces on exit. Needs: kubectl pointed at a cluster whose CNI enforces
# NetworkPolicy (Calico, Cilium; k3s' default; NOT kind's default kindnet).
set -uo pipefail

cd "$(dirname "$0")"
CTX="${1:-$(kubectl config current-context)}"
K="kubectl --context=$CTX"
EXTERNAL="1.1.1.1"   # any internet IP; the control pod proves it is reachable

fail=0
say() { echo "$*"; }
check() { # check <desc> <expect:pass|fail> <pod> <cmd...>
  local desc="$1" expect="$2" pod="$3"; shift 3
  if $K -n agents exec "$pod" -- "$@" >/dev/null 2>&1; then got=pass; else got=fail; fi
  if [ "$got" = "$expect" ]; then
    say "PASS: $desc"
  else
    say "FAIL: $desc (expected $expect, got $got)"
    fail=1
  fi
}

cleanup() {
  $K delete ns agents unified-verify-upstream --ignore-not-found --wait=false >/dev/null 2>&1
}
trap cleanup EXIT

say "=== cluster: $CTX ==="
$K get nodes -o wide | sed 's/^/  /'

# --- stand up ---------------------------------------------------------------
$K create ns agents >/dev/null
$K create ns unified-verify-upstream >/dev/null
$K label ns unified-verify-upstream unified.ai/upstream=true >/dev/null

# The upstream the sidecar allowlist points at: a TCP listener on 443.
$K -n unified-verify-upstream run upstream --image=busybox:1.36 --restart=Never \
  --port=443 -- sh -c 'while true; do echo ok | nc -l -p 443; done' >/dev/null
$K -n unified-verify-upstream expose pod upstream --port=443 >/dev/null

# The three probes. Identical image, identical namespace; only labels differ,
# so labels are the only thing any observed difference can be attributed to.
probe() { # probe <name> <labels...>
  local name="$1"; shift
  $K -n agents run "$name" --image=busybox:1.36 --restart=Never "$@" \
    -- sleep 3600 >/dev/null
}
probe control
probe agent --labels=unified.ai/enforced=true
probe sidecar --labels=unified.ai/role=sidecar

$K -n unified-verify-upstream wait --for=condition=Ready pod/upstream --timeout=120s >/dev/null
$K -n agents wait --for=condition=Ready pod --all --timeout=120s >/dev/null

# Apply the SHIPPED manifest, verbatim — the thing under test.
$K apply -f kubernetes-networkpolicy.yaml >/dev/null
sleep 5  # let the CNI program the dataplane

UPSTREAM="upstream.unified-verify-upstream.svc.cluster.local"

# --- the control: the network works -----------------------------------------
check "control reaches the internet ($EXTERNAL:443)"  pass control nc -z -w 5 "$EXTERNAL" 443
check "control reaches the upstream service"          pass control nc -z -w 5 "$UPSTREAM" 443

# --- the enforced agent: DNS and nothing else -------------------------------
check "agent resolves names (DNS allowed)"            pass agent nslookup kubernetes.default.svc.cluster.local
check "agent CANNOT reach the internet"               fail agent nc -z -w 5 "$EXTERNAL" 443
check "agent CANNOT reach even the allowlisted upstream" fail agent nc -z -w 5 "$UPSTREAM" 443

# --- the sidecar: the allowlist, and only the allowlist ---------------------
check "sidecar reaches the allowlisted upstream on 443" pass sidecar nc -z -w 5 "$UPSTREAM" 443
check "sidecar CANNOT reach the internet"             fail sidecar nc -z -w 5 "$EXTERNAL" 443

if [ "$fail" -eq 0 ]; then
  say "=== PASS: the shipped NetworkPolicy pair enforces on this cluster ==="
else
  say "=== FAIL: see above — is the CNI actually enforcing NetworkPolicy? ==="
fi
exit "$fail"

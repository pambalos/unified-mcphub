#!/usr/bin/env bash
# Read the probes' verdicts, and sweep. UAI-161.
#
# The control instance is not optional. "The air-gapped instance reached
# nothing" is worthless on its own — a broken subnet produces the same output.
# The assertion is the *difference* between two instances in one subnet whose
# only distinction is the security group under test.
set -euo pipefail

cd "$(dirname "$0")"

airgap="$(terraform output -raw airgap_probe_id)"
control="$(terraform output -raw control_probe_id)"

probe_output() {
  aws ec2 get-console-output --instance-id "$1" --output text --query Output 2>/dev/null \
    | grep "UAI161" || true
}

echo "waiting for both probes to report..."
for _ in $(seq 1 40); do
  if [ -n "$(probe_output "$control" | grep 'probe-done' || true)" ] &&
     [ -n "$(probe_output "$airgap"  | grep 'probe-done' || true)" ]; then
    break
  fi
  sleep 15
done

control_out="$(probe_output "$control")"
airgap_out="$(probe_output "$airgap")"

echo "=== control (default security group) ==="; echo "$control_out"
echo "=== under test (self-hosted security groups) ==="; echo "$airgap_out"

fail=0

# The control must reach the internet, or nothing below means anything.
if ! grep -q "egress-REACHED" <<<"$control_out"; then
  echo "FAIL: the control could not reach the internet either. The air-gap"
  echo "      result is meaningless — fix the network before reading it."
  fail=1
fi

if grep -q "egress-REACHED" <<<"$airgap_out"; then
  echo "FAIL: the air-gapped instance reached the internet."
  fail=1
elif grep -q "egress-blocked" <<<"$airgap_out"; then
  echo "PASS: egress blocked by the security group, with the internet one hop away."
fi

# Recorded rather than asserted. Link-local is not governed by security-group
# egress rules, so this is a limit of the mode rather than a regression — see
# the README. It is printed every run so it cannot quietly become normal.
if grep -q "imds-reached" <<<"$airgap_out"; then
  echo "NOTE: IMDS was reachable. Security groups do not govern link-local, so"
  echo "      'nothing leaves the perimeter' does not cover 169.254.169.254."
fi

exit "$fail"

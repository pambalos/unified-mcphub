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

# Asserted since the 2026-08-14 finding. Link-local is not governed by
# security-group egress rules, so the probe carries its own IMDS hardening
# (tokens required, hop limit 1) and this checks it held: v1 dead on the probe,
# alive on the control (proving the check can see it), and the host token path
# intact (cloud-init fetched this probe through it — a fix that kills it kills
# the boot contract).
# The liveness baseline is the token path, not tokenless v1: AL2023 AMIs
# default to tokens-required, so v1 is refused on the *control* too (measured
# 2026-08-17 — the 08-14 "imds-reached" was a 401 answering, not credentials
# moving). A control that can mint a token proves IMDS is alive and the
# refusals below are enforcement rather than a broken endpoint.
if ! grep -q "imdsv2-host-token-ok" <<<"$control_out"; then
  echo "FAIL: the control could not mint an IMDSv2 token. IMDS itself is not"
  echo "      answering here, so the refusals below prove nothing."
  fail=1
fi

if grep -q "imdsv1-reached" <<<"$airgap_out"; then
  echo "FAIL: tokenless IMDSv1 answered on the hardened instance."
  fail=1
elif grep -q "imdsv1-blocked" <<<"$airgap_out"; then
  echo "PASS: tokenless IMDSv1 refused on the hardened instance."
fi

if grep -q "imdsv2-host-token-failed" <<<"$airgap_out"; then
  echo "NOTE: the host could not mint an IMDSv2 token, yet this output arrived,"
  echo "      so user_data was delivered. Something is odd — look before trusting."
fi

# The hop limit cannot be measured from a bare host (it constrains the response
# crossing a routed hop, and the probe has no container runtime), so observe the
# applied configuration from outside the instance instead of trusting the plan.
mo_tokens=$(aws ec2 describe-instances --instance-ids "$airgap" \
  --query 'Reservations[0].Instances[0].MetadataOptions.HttpTokens' --output text)
mo_hops=$(aws ec2 describe-instances --instance-ids "$airgap" \
  --query 'Reservations[0].Instances[0].MetadataOptions.HttpPutResponseHopLimit' --output text)
if [ "$mo_tokens" = "required" ] && [ "$mo_hops" = "1" ]; then
  echo "PASS: applied MetadataOptions are HttpTokens=required, HopLimit=1."
else
  echo "FAIL: applied MetadataOptions are HttpTokens=$mo_tokens, HopLimit=$mo_hops"
  echo "      — the IMDS hardening did not reach the instance."
  fail=1
fi

# The visible delta on AL2023, printed every run: the AMI default hop limit is
# 2 (one routed hop — a container — still reaches IMDS), and tokens-required
# is the AMI's choice rather than ours. The hardened instance pins both, so a
# different AMI cannot silently take them away.
ctl_hops=$(aws ec2 describe-instances --instance-ids "$control" \
  --query 'Reservations[0].Instances[0].MetadataOptions.HttpPutResponseHopLimit' --output text)
echo "note: control (AMI defaults) hop limit is $ctl_hops; the hardened instance pins 1."

exit "$fail"

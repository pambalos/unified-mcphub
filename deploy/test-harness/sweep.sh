#!/usr/bin/env bash
# Nothing this harness created may survive it. UAI-161.
#
# The teardown assertion, and deliberately independent of Terraform state: a
# run that died before writing state would leave resources that `destroy` no
# longer knows about, which is precisely the case worth catching.
set -euo pipefail

tag="Name=tag:unified-ai.purpose,Values=deployment-mode-test"
left=0

live="$(aws ec2 describe-instances --filters "$tag" \
  --query 'Reservations[].Instances[?State.Name!=`terminated`].InstanceId' --output text)"
vpcs="$(aws ec2 describe-vpcs --filters "$tag" --query 'Vpcs[].VpcId' --output text)"
sgs="$(aws ec2 describe-security-groups --filters "$tag" --query 'SecurityGroups[].GroupId' --output text)"

for kind in "instances:$live" "vpcs:$vpcs" "security groups:$sgs"; do
  name="${kind%%:*}"; value="${kind#*:}"
  if [ -n "$value" ]; then echo "STILL RUNNING — $name: $value"; left=1; fi
done

[ "$left" -eq 0 ] && echo "PASS: nothing tagged for this harness survives."
exit "$left"

#!/usr/bin/env bash
# Temporary credentials for the deployment-mode test role. UAI-161.
#
# Assumed rather than stored: an access key for a test harness is a long-lived
# credential sitting on a laptop, and this account's admin user is the only
# thing that can mint these. One hour, then it stops working on its own.
#
#   eval "$(deploy/test-harness/assume.sh)"
set -euo pipefail

ROLE="arn:aws:iam::836688625766:role/unified-deployment-mode-test"
creds="$(aws sts assume-role --role-arn "$ROLE" \
  --role-session-name "uai161-$(date +%s)" --duration-seconds 3600 \
  --query Credentials --output json)"

python3 - "$creds" <<'PY'
import json, sys
c = json.loads(sys.argv[1])
print(f"export AWS_ACCESS_KEY_ID={c['AccessKeyId']}")
print(f"export AWS_SECRET_ACCESS_KEY={c['SecretAccessKey']}")
print(f"export AWS_SESSION_TOKEN={c['SessionToken']}")
print("export AWS_DEFAULT_REGION=us-east-1")
PY

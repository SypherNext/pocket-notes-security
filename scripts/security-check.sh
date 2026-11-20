#!/usr/bin/env bash
# Run the three automated security checks on one copy of the app, the way CI does:
# the security regression tests, Semgrep with the custom rules, and npm audit.
# Usage (from pocket-notes-security): bash scripts/security-check.sh vulnerable|fixed
# Expects Semgrep at ../.venv (see lesson 1); set SEMGREP to use another path.
app=${1:?usage: security-check.sh vulnerable|fixed}
cd "$(dirname "$0")/../$app" || exit 2
SEMGREP=${SEMGREP:-../../.venv/Scripts/semgrep}            # Windows venv layout
[ -x "$SEMGREP" ] || [ -x "$SEMGREP.exe" ] || SEMGREP=../../.venv/bin/semgrep   # macOS and Linux
export PYTHONUTF8=1
status=0
check() { # name, command
  if bash -c "$2" > /dev/null 2>&1; then echo "PASS  $1"; else echo "FAIL  $1"; status=1; fi
}
check "security tests (node --test)" "node --test"
check "static analysis (semgrep --error)" "$SEMGREP scan --config ../semgrep/pocket-notes.yaml --metrics=off --error --quiet src/"
check "dependencies (npm audit --omit=dev --audit-level=high)" "npm audit --omit=dev --audit-level=high"
exit $status

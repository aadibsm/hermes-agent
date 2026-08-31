#!/bin/bash
# Run the profile-local Codex window-touch rotation.
#
# This job is intentionally unprivileged and isolated to itsupportbot's own
# auth.json. Do not add sudo here: a service-owned script must never become a
# root execution path, and profile credential stores must remain isolated.
set -euo pipefail

exec /home/hermes/.hermes/hermes-agent/venv/bin/python3 \
  /home/hermes/.hermes/profiles/itsupportbot/scripts/codex-account-rotation.py "$@"

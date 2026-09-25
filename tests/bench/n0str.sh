#!/bin/sh
# Keep the measured PID on Bun, not a package-script supervisor.
set -eu
cd /opt/n0str
exec bun --no-env-file /opt/n0str/index.ts "$@"

#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/../.."

echo "[deploy-mock] running mock deployment"

# Build and run the mock daemon
go run scripts/deploy/ota-daemon-mock.go

echo "[deploy-mock] done"

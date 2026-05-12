#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/../.."

VAR="out/var.img"
STAGE="out/var-staging"
SIZE="${1:-512M}"

echo "[var-build] creating persistent /var ext4 image (${SIZE})"

rm -rf "${STAGE}" "${VAR}"
mkdir -p "${STAGE}"/{home,etc-upper,etc-work,lib,cache,log,spool,tmp,run}
chmod 1777 "${STAGE}/tmp"
mkdir -p "${STAGE}/home/sinty"
chmod 0777 "${STAGE}/home/sinty"
: > "${STAGE}/.atom-var"

mke2fs -q -t ext4 -L atom-var -d "${STAGE}" "${VAR}" "${SIZE}"

echo "[var-build] done: ${VAR}"
ls -lh "${VAR}"

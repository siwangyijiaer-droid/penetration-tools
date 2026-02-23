#!/usr/bin/env bash
set -Eeuo pipefail

# =========================================================
# Master pipeline
# subdomain → ip → web
# =========================================================

# -------------------------
# Usage
# -------------------------
if [[ ${1:-} == "" || ${1:-} == "--help" ]]; then
  echo "Usage: $0 <target> [subdomain] [web] [ip]"
  echo
  echo "Examples:"
  echo "  $0 govt.nz                 # run all"
  echo "  $0 govt.nz subdomain web   # skip ip"
  echo "  $0 govt.nz ip              # only ip stage"
  exit 1
fi

TARGET="$1"
shift || true

# -------------------------
# Stage switches
# -------------------------
RUN_SUBDOMAIN=0
RUN_WEB=0
RUN_IP=0

if [[ $# -eq 0 ]]; then
  RUN_SUBDOMAIN=1
  RUN_WEB=1
  RUN_IP=1
else
  for s in "$@"; do
    case "$s" in
      subdomain) RUN_SUBDOMAIN=1 ;;
      web)       RUN_WEB=1 ;;
      ip)        RUN_IP=1 ;;
      *)
        echo "[FATAL] Unknown stage: $s"
        exit 1
        ;;
    esac
  done
fi

# -------------------------
# Paths
# -------------------------
ROOT="/home/vboxuser/Desktop/penetration-tools"

SUBDOMAIN_SH="${ROOT}/run_find_subdomain.sh"
WEB_SH="${ROOT}/run_find_website.sh"
IP_SH="${ROOT}/run_ip.sh"

LOG_DIR="${ROOT}/log"
mkdir -p "${LOG_DIR}"

LOG_FILE="${LOG_DIR}/master_${TARGET}_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "${LOG_FILE}") 2>&1

log() { echo "[$(date +'%F %T')] $*"; }

require_exec() {
  [[ -x "$1" ]] || { log "[FATAL] Missing or not executable: $1"; exit 1; }
}

require_exec "${SUBDOMAIN_SH}"
require_exec "${WEB_SH}"
require_exec "${IP_SH}"

log "[*] Target : ${TARGET}"
log "[*] Stages : subdomain=${RUN_SUBDOMAIN}, web=${RUN_WEB}, ip=${RUN_IP}"
log "[*] Log    : ${LOG_FILE}"

# =========================================================
# Stage 1: Subdomain
# =========================================================
if [[ "${RUN_SUBDOMAIN}" -eq 1 ]]; then
  log "[1/3] subdomain start"
  "${SUBDOMAIN_SH}" "${TARGET}"
  log "[1/3] subdomain done"
else
  log "[1/3] subdomain skipped"
fi

# =========================================================
# Stage 2: IP
# =========================================================
if [[ "${RUN_IP}" -eq 1 ]]; then
  log "[2/3] ip start"
  "${IP_SH}" "${TARGET}"
  log "[2/3] ip done"
else
  log "[2/3] ip skipped"
fi

# =========================================================
# Stage 3: Web
# =========================================================
if [[ "${RUN_WEB}" -eq 1 ]]; then
  log "[3/3] web start"
  "${WEB_SH}" "${TARGET}"
  log "[3/3] web done"
else
  log "[3/3] web skipped"
fi



log "[DONE] all selected stages finished"


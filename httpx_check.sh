#!/usr/bin/env bash
set -Eeuo pipefail

# =========================================================
# run_httpx_rank_from_file.sh
# 1) 输入一个 URL 文件（每行一个 URL）
# 2) 直接 httpx 探测
# 3) asset_rank.py 打分
# =========================================================

# -------------------------
# Usage
# -------------------------
if [[ ${1:-} == "" || ${1:-} == "--help" ]]; then
  echo "Usage: $0 <url_file>"
  echo "Example: $0 /path/to/urls.txt"
  exit 1
fi

URL_FILE="$1"

if [[ ! -f "${URL_FILE}" ]]; then
  echo "[FATAL] URL file not found: ${URL_FILE}"
  exit 1
fi

# -------------------------
# Global Paths
# -------------------------
ROOT="${ROOT:-/home/vboxuser/Desktop/penetration-tools}"
REPORT_ROOT="${ROOT}/report"
LOG_DIR="${ROOT}/log"
BASE_DIR="${BASE_DIR:-${ROOT}/tools/tool_find_web}"

HTTPX_BIN="${HTTPX_BIN:-${BASE_DIR}/httpx}"

VENV_DIR="${VENV_DIR:-/home/vboxuser/venv}"
PYTHON="${PYTHON:-${VENV_DIR}/bin/python}"
ASSET_RANK_PY="${ASSET_RANK_PY:-${BASE_DIR}/asset_rank.py}"

# -------------------------
# Output dirs
# -------------------------
SAFE_NAME="$(basename "${URL_FILE}" | tr '/:' '__' | tr -cd 'A-Za-z0-9._-')"
OUT_DIR="${REPORT_ROOT}/${SAFE_NAME}"
LOG_FILE="${LOG_DIR}/httpx_rank_${SAFE_NAME}_$(date +%Y%m%d_%H%M%S).log"

mkdir -p "${OUT_DIR}" "${LOG_DIR}"

exec > >(tee -a "${LOG_FILE}") 2>&1
log() { echo "[$(date +'%F %T')] $*"; }
trap 'log "[ERROR] Script failed at line $LINENO"' ERR

# -------------------------
# Random headers（保持你原逻辑）
# -------------------------
pick_ua() {
  local uas=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0"
  )
  echo "${uas[$((RANDOM % ${#uas[@]}))]}"
}

RAND_UA="${RAND_UA:-$(pick_ua)}"
RAND_REF="${RAND_REF:-https://www.google.com/}"

CUSTOM_HEADERS=(
  -H "User-Agent: ${RAND_UA}"
  -H "Referer: ${RAND_REF}"
)

HTTPX_JSONL="${OUT_DIR}/httpx.jsonl"

log "[*] Input file : ${URL_FILE}"
log "[*] Output dir : ${OUT_DIR}"
log "[*] httpx out  : ${HTTPX_JSONL}"

# -------------------------
# Step 1: httpx probe (NO clean / NO dedup)
# -------------------------
log "[1/2] httpx probing (raw input, no filtering)"

"${HTTPX_BIN}" \
  -l "${URL_FILE}" \
  "${CUSTOM_HEADERS[@]}" \
  -silent \
  -sc -title -td -server -ip -cdn -cname -ct -cl -location -hash md5 \
  -fr -maxr 3 \
  -timeout 10 -retries 2 \
  -t 15 -rl 20 \
  -j -o "${HTTPX_JSONL}" || true

if [[ ! -s "${HTTPX_JSONL}" ]]; then
  log "[FATAL] httpx output is empty"
  exit 1
fi

log "[*] httpx done: $(wc -l < "${HTTPX_JSONL}") lines"

# -------------------------
# Step 2: asset ranking
# -------------------------
log "[2/2] asset_rank.py scoring"

"${PYTHON}" "${ASSET_RANK_PY}" \
  -i "${HTTPX_JSONL}" \
  -o "${OUT_DIR}"

log "[DONE]"
log "  - httpx jsonl      : ${HTTPX_JSONL}"
log "  - asset_rank csv  : ${OUT_DIR}/asset_rank.csv"
log "  - asset_rank json : ${OUT_DIR}/asset_rank.jsonl"

#!/usr/bin/env bash
set -Eeuo pipefail

# =========================================================
# run_find_urls.sh
# 1) 给一个URL，使用 gau / waybackurls / katana 收集相关URL
# 2) 对收集到的URL用 httpx 探测识别，输出 httpx.jsonl
# 3) 调用 asset_rank.py 对 httpx.jsonl 做打分，输出 asset_rank.csv/jsonl
# =========================================================

# -------------------------
# Usage
# -------------------------
if [[ ${1:-} == "" || ${1:-} == "--help" ]]; then
  echo "Usage: $0 <url>"
  echo "Example: $0 https://example.com/"
  echo
  echo "Optional env vars:"
  echo "  ROOT=...              (default: /home/vboxuser/Desktop/penetration-tools)"
  echo "  BASE_DIR=...          (default: \$ROOT/tools/tool_find_web)"
  echo "  OUT_DIR=...           (default: \$ROOT/report/<safe_host>)"
  echo "  VENV_DIR=...          (default: /home/vboxuser/venv)"
  echo "  ASSET_RANK_PY=...     (default: /mnt/data/asset_rank.py)"
  exit 1
fi

INPUT_URL="$1"

# -------------------------
# Global Paths (参考 run_find_website.sh)
# -------------------------
ROOT="${ROOT:-/home/vboxuser/Desktop/penetration-tools}"
REPORT_ROOT="${ROOT}/report"
LOG_DIR="${ROOT}/log"

BASE_DIR="${BASE_DIR:-${ROOT}/tools/tool_find_web}"

# tools (可按你机器实际位置改)
HTTPX_BIN="${HTTPX_BIN:-${BASE_DIR}/httpx}"
GAU_BIN="${GAU_BIN:-${BASE_DIR}/gau}"
WAYBACKURLS_BIN="${WAYBACKURLS_BIN:-${BASE_DIR}/waybackurls}"
KATANA_BIN="${KATANA_BIN:-${BASE_DIR}/katana}"

# python venv
VENV_DIR="${VENV_DIR:-/home/vboxuser/venv}"
PYTHON="${PYTHON:-${VENV_DIR}/bin/python}"

# asset_rank.py：默认使用你这次上传的路径（你也可以改成 ${BASE_DIR}/asset_rank.py）
ASSET_RANK_PY="${ASSET_RANK_PY:-${BASE_DIR}/asset_rank.py}"

# -------------------------
# Derive host & safe output dir
# -------------------------
# 提取 host（兼容 http/https）
HOST="$(echo "${INPUT_URL}" | awk -F/ '{print $3}' | tr -d '\r')"
if [[ -z "${HOST}" ]]; then
  echo "[FATAL] Cannot parse host from URL: ${INPUT_URL}"
  exit 1
fi

SAFE_HOST="$(echo "${HOST}" | tr '/:' '__' | tr -cd 'A-Za-z0-9._-')"
OUT_DIR="${OUT_DIR:-${REPORT_ROOT}/${SAFE_HOST}}"
LOG_FILE="${LOG_DIR}/find_urls_${SAFE_HOST}_$(date +%Y%m%d_%H%M%S).log"

mkdir -p "${OUT_DIR}" "${LOG_DIR}"

exec > >(tee -a "${LOG_FILE}") 2>&1
log() { echo "[$(date +'%F %T')] $*"; }
on_error() { log "[ERROR] Script failed at line $1"; }
trap 'on_error $LINENO' ERR

# -------------------------
# Random headers (沿用 run_find_website.sh 逻辑)
# -------------------------
rand_ip() {
  local a b c d
  while :; do
    a=$(( (RANDOM % 223) + 1 ))
    b=$(( RANDOM % 256 ))
    c=$(( RANDOM % 256 ))
    d=$(( RANDOM % 256 ))
    [[ "$a" -eq 10 || "$a" -eq 127 || "$a" -eq 0 ]] && continue
    [[ "$a" -eq 169 && "$b" -eq 254 ]] && continue
    [[ "$a" -eq 172 && "$b" -ge 16 && "$b" -le 31 ]] && continue
    [[ "$a" -eq 192 && "$b" -eq 168 ]] && continue
    [[ "$a" -ge 224 ]] && continue
    echo "${a}.${b}.${c}.${d}"
    return 0
  done
}

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
RAND_XFF="${RAND_XFF:-$(rand_ip)}"

CUSTOM_HEADERS=(
  -H "User-Agent: ${RAND_UA}"
  -H "Referer: ${RAND_REF}"
  -H "X-Forwarded-For: ${RAND_XFF}"
)

# -------------------------
# Preflight
# -------------------------
require_exec() { [[ -x "$1" ]] || { log "[FATAL] Missing or not executable: $1"; exit 1; }; }
require_file() { [[ -f "$1" ]] || { log "[FATAL] Missing file: $1"; exit 1; }; }
require_cmd()  { command -v "$1" >/dev/null 2>&1 || { log "[FATAL] Missing command in PATH: $1"; exit 1; }; }

log "[*] Input URL  : ${INPUT_URL}"
log "[*] Host       : ${HOST}"
log "[*] Output dir : ${OUT_DIR}"
log "[*] Log file   : ${LOG_FILE}"
log "[*] UA         : ${RAND_UA}"
log "[*] Ref        : ${RAND_REF}"
log "[*] XFF        : ${RAND_XFF}"

require_exec "${HTTPX_BIN}"
require_exec "${PYTHON}"
require_file "${ASSET_RANK_PY}"
require_cmd awk
require_cmd sort
require_cmd uniq
require_cmd sed
require_cmd grep
require_cmd wc

# gau/waybackurls/katana 不是必需都存在：不存在就跳过
if [[ -z "${GAU_BIN}" ]]; then log "[WARN] gau not found in PATH, will skip gau"; fi
if [[ -z "${WAYBACKURLS_BIN}" ]]; then log "[WARN] waybackurls not found in PATH, will skip waybackurls"; fi
if [[ -z "${KATANA_BIN}" ]]; then log "[WARN] katana not found in PATH, will skip katana"; fi

# -------------------------
# Output files
# -------------------------
RAW_GAU="${OUT_DIR}/urls.gau.txt"
RAW_WAYBACK="${OUT_DIR}/urls.waybackurls.txt"
RAW_KATANA="${OUT_DIR}/urls.katana.txt"
URLS_ALL_RAW="${OUT_DIR}/urls.all.raw.txt"
URLS_ALL="${OUT_DIR}/urls.all.txt"

HTTPX_JSONL="${OUT_DIR}/httpx.jsonl"

# -------------------------
# Step 1: Collect URLs
# -------------------------
log "[1/3] Collect URLs via gau / waybackurls / katana"

: > "${RAW_GAU}"
: > "${RAW_WAYBACK}"
: > "${RAW_KATANA}"

# gau：通常给 domain/host
if [[ -n "${GAU_BIN}" ]]; then
  log "[*] gau ${HOST}"
  # -subs 尝试把子域也带上（按你需求可以去掉）
  "${GAU_BIN}" --subs "${HOST}" 2>/dev/null | tr -d '\r' >> "${RAW_GAU}" || true
  log "[*] wrote: ${RAW_GAU} ($(wc -l < "${RAW_GAU}" | tr -d ' '))"
fi

# waybackurls：通常 stdin 输入域名
if [[ -n "${WAYBACKURLS_BIN}" ]]; then
  log "[*] waybackurls ${HOST}"
  echo "${HOST}" | "${WAYBACKURLS_BIN}" 2>/dev/null | tr -d '\r' >> "${RAW_WAYBACK}" || true
  log "[*] wrote: ${RAW_WAYBACK} ($(wc -l < "${RAW_WAYBACK}" | tr -d ' '))"
fi

# katana：从输入 URL 开始爬
if [[ -n "${KATANA_BIN}" ]]; then
  log "[*] katana crawl ${INPUT_URL}"
  # 这里用 -u 单URL，-jc 输出 jsonl 太重；我们直接输出URL文本（-silent）
  # 深度/并发你可以按需调
  "${KATANA_BIN}" -u "${INPUT_URL}" -silent -d 3 -c 10 -p 10 2>/dev/null \
    | tr -d '\r' >> "${RAW_KATANA}" || true
  log "[*] wrote: ${RAW_KATANA} ($(wc -l < "${RAW_KATANA}" | tr -d ' '))"
fi

# 合并 + 简单清洗 + 去重
cat "${RAW_GAU}" "${RAW_WAYBACK}" "${RAW_KATANA}" 2>/dev/null \
  | sed 's/[[:space:]]\+$//' \
  | grep -E '^https?://' \
  | sort -u > "${URLS_ALL_RAW}" || true

# 你如果只想保留“与输入 host 强相关”的 URL，可用下面一行进一步过滤（默认不过滤）
grep -F "://${HOST}" "${URLS_ALL_RAW}" > "${URLS_ALL}" || true

cp -a "${URLS_ALL_RAW}" "${URLS_ALL}" || true

log "[*] wrote: ${URLS_ALL} ($(wc -l < "${URLS_ALL}" | tr -d ' '))"
if [[ ! -s "${URLS_ALL}" ]]; then
  log "[FATAL] No URLs collected. Check tool install or target availability."
  exit 1
fi



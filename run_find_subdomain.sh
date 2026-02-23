#!/usr/bin/env bash
set -Eeuo pipefail

# =========================
# Usage
# =========================
if [[ ${1:-} == "" || ${1:-} == "--help" ]]; then
  echo "Usage: $0 <target.com>"
  exit 1
fi

TARGET="$1"

# =========================
# Global Paths
# =========================
ROOT="/home/vboxuser/Desktop/penetration-tools"
REPORT_ROOT="${ROOT}/report"
LOG_DIR="${ROOT}/log"

BASE_DIR="${ROOT}/tools/tool_find_subdomain"
TOOLS_DIRS="${BASE_DIR}/other_tools"
TMP_ROOT="${BASE_DIR}/tmp"


# =========================
# Wordlists / Resolvers
# =========================
WORDLIST="${TOOLS_DIRS}/dict/domain_20000"
RESOLVERS="${TOOLS_DIRS}/dict/resolvers.txt"

# trusted resolvers（自动兼容无后缀 / .txt）
if [[ -f "${TOOLS_DIRS}/dict/trusted_resolvers.txt" ]]; then
  TRUSTED_R="${TOOLS_DIRS}/dict/trusted_resolvers.txt"
else
  TRUSTED_R="${TOOLS_DIRS}/dict/trusted_resolvers"
fi

# =========================
# Binaries
# =========================
SUBFINDER="${BASE_DIR}/subfinder"
SHUFFLEDNS="${BASE_DIR}/shuffledns"
ALTERX="${BASE_DIR}/alterx"
HTTPX_BIN="${BASE_DIR}/httpx"
DNSVALIDATOR_CMD="dnsvalidator"
DNSVALIDATOR_ALL="${TOOLS_DIRS}/dnsvalidator/all_dns.txt"

# 🔴 massdns：你给定的路径（明确到可执行文件）
MASSDNS_BIN="${TOOLS_DIRS}/massdns/bin/massdns"

# =========================
# Output Layout
# =========================
SAFE_TARGET="$(echo "$TARGET" | tr '/:' '__' | tr -cd 'A-Za-z0-9._-')"
OUT_DIR="${REPORT_ROOT}/${SAFE_TARGET}"
mkdir -p "${OUT_DIR}" "${LOG_DIR}" "${TMP_ROOT}"

TS="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="${LOG_DIR}/${SAFE_TARGET}_${TS}.log"

TMP_DIR="$(mktemp -d "${TMP_ROOT}/${SAFE_TARGET}_${TS}_XXXX")"

INPUT_LIST="${OUT_DIR}/alive_subs.txt"
# httpx JSON Lines 输出（-j），推荐后缀 .jsonl
JSONL_OUT="${OUT_DIR}/httpx.jsonl"


exec > >(tee -a "${LOG_FILE}") 2>&1

log() { echo "[$(date +'%F %T')] $*"; }

on_error() {
  log "[ERROR] Script failed at line $1"
}
trap 'on_error $LINENO' ERR

cleanup() {
  [[ -d "${TMP_DIR}" ]] && rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

# =========================
# Preflight checks
# =========================
require_file() {
  [[ -f "$1" ]] || { log "[FATAL] Missing file: $1"; exit 1; }
}
require_bin() {
  [[ -x "$1" ]] || { log "[FATAL] Missing or not executable: $1"; exit 1; }
}

log "[*] Target: ${TARGET}"
log "[*] Output: ${OUT_DIR}"
log "[*] Log: ${LOG_FILE}"
log "[*] Tmp: ${TMP_DIR}"

require_file "${WORDLIST}"
require_file "${DNSVALIDATOR_ALL}"
require_file "${TRUSTED_R}"

require_bin "${SUBFINDER}"
require_bin "${SHUFFLEDNS}"
require_bin "${ALTERX}"
require_bin "${HTTPX_BIN}"

# dnsvalidator
#if ! command -v "${DNSVALIDATOR_CMD}" >/dev/null 2>&1; then
#  log "[FATAL] dnsvalidator not found in PATH"
#  exit 1
#fi


# massdns
require_bin "${MASSDNS_BIN}"
log "[*] massdns: ${MASSDNS_BIN}"

# =========================
# 1) Build resolvers list
# =========================
# 目的：准备 shuffledns/massdns 使用的 resolvers 列表
# 策略：
# - 若已有 resolvers.txt 且行数足够（>=50），直接复用（节省时间）
# - 否则用 dnsvalidator 生成
# - 最终必须保证 resolvers 文件存在且非空（-s），否则直接退出
log "[1/6] resolvers"

if [[ -f "${RESOLVERS}" ]] && [[ "$(wc -l < "${RESOLVERS}")" -ge 50 ]]; then
  log "[*] Reuse resolvers (${RESOLVERS})"
else
  log "[*] Generate resolvers via dnsvalidator"
  dnsvalidator -tL "${DNSVALIDATOR_ALL}" -threads 3000 -o "${RESOLVERS}"
fi

# 生成/复用之后统一校验：存在且非空
require_file "${RESOLVERS}"
if [[ ! -s "${RESOLVERS}" ]]; then
  log "[FATAL] resolvers empty after build: ${RESOLVERS}"
  exit 1
fi



# =========================
# 2) Passive: subfinder
# =========================
log "[2/6] subfinder"
"${SUBFINDER}" -d "${TARGET}" -all -silent -o "${TMP_DIR}/subfinder-domains.txt"

# =========================
# 3) Active: shuffledns bruteforce
# =========================
log "[3/6] shuffledns bruteforce"
"${SHUFFLEDNS}" -d "${TARGET}" \
  -w "${WORDLIST}" \
  -r "${RESOLVERS}" \
  -mode bruteforce \
  -t 300 -retries 3 \
  -massdns "${MASSDNS_BIN}" \
  -o "${TMP_DIR}/shuffledns-domains.txt"

log "[3.5/6] merge extra domains (web.txt) before alterx"

EXTRA_WEB="${ROOT}/web.txt"
MERGED_BASE="${TMP_DIR}/base_domains_merged.txt"

# 合并 subfinder + shuffledns
cat "${TMP_DIR}/subfinder-domains.txt" "${TMP_DIR}/shuffledns-domains.txt" \
  | sed 's/^\xEF\xBB\xBF//' | tr -d '\r' \
  | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
  | grep -vE '^\s*$|^\s*#' \
  | sort -u \
  > "${MERGED_BASE}"

# 如果 web.txt 存在：清洗后合并，并只保留属于 TARGET 的域名（推荐）
if [[ -s "${EXTRA_WEB}" ]]; then
  log "[*] Detected web.txt, merge into base domains: ${EXTRA_WEB}"

  cat "${EXTRA_WEB}" \
    | sed 's/^\xEF\xBB\xBF//' \
    | tr -d '\r' \
    | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
    | sed -E 's#^https?://##I; s#/.*$##; s/:([0-9]+)$//' \
    | grep -vE '^\s*$|^\s*#' \
    | grep -iE "(^|\\.)${TARGET}$" \
    >> "${MERGED_BASE}"

  sort -u "${MERGED_BASE}" -o "${MERGED_BASE}"
else
  log "[*] web.txt not found or empty, skip"
fi

# Step 4) alterx permutations（输入换成 MERGED_BASE）
log "[4/6] alterx"
cat "${MERGED_BASE}" \
  | "${ALTERX}" -silent \
  > "${TMP_DIR}/alterx-domains.txt"

log "[4.1/6] filter alterx domains by Twilio scope patterns"

ALTERX_FILTERED="${TMP_DIR}/alterx-domains.filtered.txt"
MERGED_BASE_FILTERED="${TMP_DIR}/base_domains_merged.filtered.txt"

grep -iE '(^[A-Za-z0-9-]+\.sip\.[A-Za-z0-9-]+\.twilio\.com$|^static[A-Za-z0-9-]*\.twilio\.com$)' \
  "${TMP_DIR}/alterx-domains.txt" \
  | sort -u \
  > "${ALTERX_FILTERED}"

grep -iE '(^[A-Za-z0-9-]+\.sip\.[A-Za-z0-9-]+\.twilio\.com$|^static[A-Za-z0-9-]*\.twilio\.com$)' \
  "${TMP_DIR}/base_domains_merged.txt" \
  | sort -u \
  > "${MERGED_BASE_FILTERED}"


# 用过滤后的结果覆盖原文件（后续流程不需要改）
mv "${ALTERX_FILTERED}" "${TMP_DIR}/alterx-domains.txt"
mv "${MERGED_BASE_FILTERED}" "${TMP_DIR}/base_domains_merged.txt"

log "[*] alterx domains filtered: $(wc -l < "${TMP_DIR}/alterx-domains.txt") kept"
log "[*] MERGED BASE filtered: $(wc -l < "${TMP_DIR}/base_domains_merged.txt") kept"


# =========================
# 5) Resolve truth
# =========================
log "[5/6] shuffledns resolve"
cat "${MERGED_BASE}" \
    "${TMP_DIR}/alterx-domains.txt" \
  | sort -u \
  | "${SHUFFLEDNS}" -r "${RESOLVERS}" -tr "${TRUSTED_R}" -mode resolve -silent \
    -massdns "${MASSDNS_BIN}" \
  > "${INPUT_LIST}"


# =========================
# 6): httpx (skip if exists)
# =========================
log "[6/6] httpx"
if [[ -s "${JSONL_OUT}" ]]; then
  log "[*] Skip httpx (exists & non-empty): ${JSONL_OUT}"
else
  "${HTTPX_BIN}" \
    -l "${INPUT_LIST}" \
    -silent \
    -sc -title -td -server -ip -cdn -cname -ct -cl -location -hash md5 \
    -p 80,443,8080,8443,8000,8888 \
    -fr -maxr 3 \
    -timeout 10 -retries 2 \
    -t 20 -rl 30 \
    -j -o "${JSONL_OUT}"

  require_file "${JSONL_OUT}"
  log "[*] httpx done: ${JSONL_OUT}"
fi


# =========================
# Save results
# =========================
cp -f "${TMP_DIR}/subfinder-domains.txt"  "${OUT_DIR}/" || true
cp -f "${TMP_DIR}/shuffledns-domains.txt" "${OUT_DIR}/" || true
cp -f "${TMP_DIR}/alterx-domains.txt"     "${OUT_DIR}/" || true

log "[DONE] Results saved to ${OUT_DIR}"
log "[DONE] alive_subs.txt ready"

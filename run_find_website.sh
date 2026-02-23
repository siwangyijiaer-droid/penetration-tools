#!/usr/bin/env bash
set -Eeuo pipefail

# =========================================================
# Step0 Pre-Segmentation
# - optional merge naabu -> httpx.with_naabu.jsonl
# - export CSV snapshot(s)
# Stops BEFORE segmentation.
# =========================================================

# -------------------------
# Usage
# -------------------------
if [[ ${1:-} == "" || ${1:-} == "--help" ]]; then
  echo "Usage: $0 <target-domain>"
  echo "Example: $0 govt.nz"
  exit 1
fi

TARGET="$1"

# -------------------------
# Global Paths
# -------------------------
ROOT="/home/vboxuser/Desktop/penetration-tools"
REPORT_ROOT="${ROOT}/report"
LOG_DIR="${ROOT}/log"

SAFE_TARGET="$(echo "$TARGET" | tr '/:' '__' | tr -cd 'A-Za-z0-9._-')"
OUT_DIR="${REPORT_ROOT}/${SAFE_TARGET}"
LOG_FILE="${LOG_DIR}/httpx_${SAFE_TARGET}_$(date +%Y%m%d_%H%M%S).log"

BASE_DIR="${ROOT}/tools/tool_find_web"
HTTPX_BIN="${BASE_DIR}/httpx"

JSONL_OUT="${OUT_DIR}/httpx.jsonl"                # input: existing httpx output (if any)
JSONL_STEP0_OUT="${OUT_DIR}/httpx.with_naabu.jsonl" # output: step0 merged

HOST_FX_DIR="${OUT_DIR}/host_fx"
NAABU_IP_PORT="${HOST_FX_DIR}/naabu_ip_port.txt"
NAABU_HTTPX_LIST="${HOST_FX_DIR}/naabu_httpx.txt"
NAABU_JSONL_TMP="${OUT_DIR}/httpx.naabu.tmp.jsonl"

HTTPX_KEY_DEDUP_PY="${ROOT}/tools/tool_find_web/httpx_key_dedup.py"
ASSET_RANK_PY="${ROOT}/tools/tool_find_web/asset_rank.py"


VENV_DIR="/home/vboxuser/venv"
PYTHON="${VENV_DIR}/bin/python"

mkdir -p "${OUT_DIR}" "${LOG_DIR}" "${HOST_FX_DIR}"

exec > >(tee -a "${LOG_FILE}") 2>&1
log() { echo "[$(date +'%F %T')] $*"; }

on_error() { log "[ERROR] Script failed at line $1"; }
trap 'on_error $LINENO' ERR

require_file() { [[ -f "$1" ]] || { log "[FATAL] Missing file: $1"; exit 1; }; }
require_exec() { [[ -x "$1" ]] || { log "[FATAL] Missing or not executable: $1"; exit 1; }; }
require_cmd()  { command -v "$1" >/dev/null 2>&1 || { log "[FATAL] Missing command in PATH: $1"; exit 1; }; }

log "[*] Target     : ${TARGET}"
log "[*] Output dir : ${OUT_DIR}"
log "[*] Log file   : ${LOG_FILE}"

# -------------------------
# Random headers (built-in)
# -------------------------
rand_ip() {
  # Generate a public-looking XFF. (WAF may ignore it; keep it only as a mild entropy source.)
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

log "[*] UA  : ${RAND_UA}"
log "[*] Ref : ${RAND_REF}"
log "[*] XFF : ${RAND_XFF}"

# -------------------------
# Preflight
# -------------------------
require_exec "${HTTPX_BIN}"
require_exec "${PYTHON}"
require_cmd jq
require_cmd awk
require_cmd wc
require_file "${HTTPX_KEY_DEDUP_PY}"
require_file "${ASSET_RANK_PY}"

# Need either existing httpx.jsonl or naabu_ip_port.txt to proceed.
if [[ ! -s "${JSONL_OUT}" && ! -s "${NAABU_IP_PORT}" ]]; then
  log "[FATAL] Missing ${JSONL_OUT}. Provide httpx.jsonl OR provide ${NAABU_IP_PORT} for step0." 
  exit 1
fi

# -------------------------
# Helper: JSONL -> CSV snapshot
# -------------------------
jsonl_to_csv() {
  local in_jsonl="$1"
  local out_csv="$2"

  if [[ ! -s "${in_jsonl}" ]]; then
    : > "${out_csv}"
    log "[WARN] csv created empty (input missing/empty): ${out_csv}"
    return 0
  fi

  {
    echo 'url,host,port,status_code,title,webserver,host_ip,cdn,cdn_type,cdn_name,content_type,tech,cname,location,body_md5,failed'
    jq -r '[
      (.url // ""),
      (.host // ""),
      ((.port // "")|tostring),
      ((.status_code // "")|tostring),
      (.title // ""),
      (.webserver // .server // ""),
      ((.host_ip // "")|tostring),
      ((.cdn // false)|tostring),
      (.cdn_type // ""),
      (.cdn_name // ""),
      (.content_type // ""),
      ((.tech // [])  | (if type=="array" then join(";") else tostring end)),
      ((.cname // []) | (if type=="array" then join(";") else tostring end)),
      (.location // ""),
      ((.hash.body_md5 // "")|tostring),
      ((.failed // false)|tostring)
    ] | @csv' "${in_jsonl}"
  } > "${out_csv}"

  log "[*] wrote: ${out_csv} ($(wc -l < "${out_csv}" | tr -d ' '))"
}

# -------------------------
# Step 0: httpx from naabu (ip:port -> http/https) + merge
# -------------------------
if [[ -s "${JSONL_STEP0_OUT}" ]]; then
  log "[0/1] SKIP step0 merge (output exists): ${JSONL_STEP0_OUT} ($(wc -l < "${JSONL_STEP0_OUT}" | tr -d ' '))"
else
  if [[ -s "${NAABU_IP_PORT}" ]]; then
    log "[0/1] httpx from naabu: ${NAABU_IP_PORT}"

    : > "${NAABU_HTTPX_LIST}"
    while IFS= read -r line; do
      [[ -z "${line}" ]] && continue
      # trim CRLF + surrounding whitespace
      line="$(echo "${line}" | tr -d '\r' | awk '{$1=$1;print}')"
      [[ -z "${line}" ]] && continue
      echo "http://${line}"  >> "${NAABU_HTTPX_LIST}"
      echo "https://${line}" >> "${NAABU_HTTPX_LIST}"
    done < "${NAABU_IP_PORT}"

    log "[*] wrote: ${NAABU_HTTPX_LIST} ($(wc -l < "${NAABU_HTTPX_LIST}" | tr -d ' '))"

    "${HTTPX_BIN}" \
      -l "${NAABU_HTTPX_LIST}" \
      "${CUSTOM_HEADERS[@]}" \
      -silent \
      -sc -title -td -server -ip -cdn -cname -ct -cl -location -hash md5 \
      -fr -maxr 3 \
      -timeout 10 -retries 2 \
      -t 20 -rl 30 \
      -j -o "${NAABU_JSONL_TMP}" || true

    log "[*] wrote: ${NAABU_JSONL_TMP} ($(wc -l < "${NAABU_JSONL_TMP}" 2>/dev/null | tr -d ' '))"

    if [[ -s "${NAABU_JSONL_TMP}" ]]; then
      if [[ -s "${JSONL_OUT}" ]]; then
        "${PYTHON}" "${HTTPX_KEY_DEDUP_PY}" \
          "${JSONL_OUT}" \
          "${NAABU_JSONL_TMP}" \
          "${JSONL_STEP0_OUT}" || true
      else
        cp -a "${NAABU_JSONL_TMP}" "${JSONL_STEP0_OUT}"
      fi
      log "[*] wrote step0 output => ${JSONL_STEP0_OUT} ($(wc -l < "${JSONL_STEP0_OUT}" 2>/dev/null | tr -d ' '))"
    else
      # naabu ran but produced nothing; fallback to JSONL_OUT (if exists)
      if [[ -s "${JSONL_OUT}" ]]; then
        cp -a "${JSONL_OUT}" "${JSONL_STEP0_OUT}"
        log "[*] no naabu output, copy JSONL_OUT => ${JSONL_STEP0_OUT}"
      else
        : > "${JSONL_STEP0_OUT}"
        log "[WARN] no JSONL_OUT and no naabu output, created empty ${JSONL_STEP0_OUT}"
      fi
    fi
  else
    log "[0/1] skip httpx from naabu (missing or empty): ${NAABU_IP_PORT}"
    # no naabu input; step0 output is just JSONL_OUT snapshot
    if [[ -s "${JSONL_OUT}" ]]; then
      cp -a "${JSONL_OUT}" "${JSONL_STEP0_OUT}"
      log "[*] no naabu, copy JSONL_OUT => ${JSONL_STEP0_OUT} ($(wc -l < "${JSONL_STEP0_OUT}" | tr -d ' '))"
    else
      : > "${JSONL_STEP0_OUT}"
      log "[WARN] JSONL_OUT empty, created empty ${JSONL_STEP0_OUT}"
    fi
  fi
fi

# -------------------------
# CSV snapshot(s)
# -------------------------
STEP0_CSV_OUT="${OUT_DIR}/httpx.with_naabu.csv"

# 1) helpful: step0 merged -> csv (this is what step1+ should use)
jsonl_to_csv "${JSONL_STEP0_OUT}" "${STEP0_CSV_OUT}"

log "[DONE] Pre-segmentation finished."
log "[DONE] Step0 JSONL => ${JSONL_STEP0_OUT}"
log "[DONE] CSV (step0 merged) => ${STEP0_CSV_OUT}"

# -------------------------
# Step 0b: Asset ranking
# -------------------------
log "[*] Step 0b: asset ranking"

"${PYTHON}" "${ASSET_RANK_PY}" \
  -i "${JSONL_STEP0_OUT}" \
  -n "${NAABU_IP_PORT}" \
  -o "${OUT_DIR}" || true

log "[DONE] Asset ranking => ${OUT_DIR}/asset_rank.{jsonl,csv}"



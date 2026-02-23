#!/usr/bin/env bash
set -Eeuo pipefail

# =========================================================
# Host exposure & vuln discovery pipeline (IP-centric)
# - Step0: run select_cdn.py to generate cdn_fx outputs
# - Seed IPs: report/<key>/cdn_fx/no_cdn_realip.jsonl (host_ip)
# - mapcidr: aggregate -> (optional) expand
# - ASN filter: ip2asn-combined.tsv + deny keywords (cloud/cdn/edge)
# - Scan: naabu -> nmap -sV
# =========================================================

# -------------------------
# Usage
# -------------------------
if [[ ${1:-} == "" || ${1:-} == "--help" ]]; then
  echo "Usage: $0 <project_key>"
  echo "Example: $0 govt.nz"
  exit 1
fi

KEY="$1"

# -------------------------
# Global Paths
# -------------------------
ROOT="/home/vboxuser/Desktop/penetration-tools"
REPORT_ROOT="${ROOT}/report"
LOG_DIR="${ROOT}/log"

# Tool base
ASSET_SEG_DIR="${ROOT}/tools/tool_Asset_Segmentation"
CDN_IP_DIR="${ASSET_SEG_DIR}/cdn_ip"
IP2ASN_TSV="${CDN_IP_DIR}/ip2asn-combined.tsv"

# select_cdn.py (fixed path as requested)
SELECT_CDN="${ASSET_SEG_DIR}/select_cdn.py"
EXPAND_CIDR="${ASSET_SEG_DIR}/expand_cidr.py"
ASN_FILTER="${ASSET_SEG_DIR}/asn_filter.py"
GROUP_NAABU="${ASSET_SEG_DIR}/group_naabu_ports.py"
NMAP_INDEX="${ASSET_SEG_DIR}/nmap_service_index.py"
VULN_PREFILTER="${ASSET_SEG_DIR}/vuln_prefilter.py"

# Python venv (fixed)
VENV_DIR="/home/vboxuser/venv"
PYTHON="${VENV_DIR}/bin/python"

SAFE_KEY="$(echo "$KEY" | tr '/:' '__' | tr -cd 'A-Za-z0-9._-')"
OUT_DIR="${REPORT_ROOT}/${SAFE_KEY}"
CDN_FX_DIR="${OUT_DIR}/cdn_fx"
HOST_FX_DIR="${OUT_DIR}/host_fx"

HTTPX_JSONL="${OUT_DIR}/httpx.jsonl"
INPUT_JSONL="${CDN_FX_DIR}/no_cdn_realip.jsonl"

mkdir -p "${OUT_DIR}" "${HOST_FX_DIR}" "${LOG_DIR}"

TS="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="${LOG_DIR}/${SAFE_KEY}_hostfx_${TS}.log"

TMP_ROOT="${HOST_FX_DIR}/tmp"
mkdir -p "${TMP_ROOT}"
TMP_DIR="$(mktemp -d "${TMP_ROOT}/${SAFE_KEY}_${TS}_XXXX")"

exec > >(tee -a "${LOG_FILE}") 2>&1

log() { echo "[$(date +'%F %T')] $*"; }

rel() {
  command -v realpath >/dev/null 2>&1 && realpath --relative-to="${OUT_DIR}" "$1" 2>/dev/null && return 0
  echo "$1"
}

statf() {
  local f="$1"
  if [[ -s "$f" ]]; then
    local lines bytes
    lines=$(wc -l < "$f" 2>/dev/null || echo "?")
    bytes=$(wc -c < "$f" 2>/dev/null || echo "?")
    printf "  %-22s | %8s lines | %10s bytes | %s\n" "$(basename "$f")" "$lines" "$bytes" "$(rel "$f")"
  else
    printf "  %-22s | %8s | %10s | %s\n" "$(basename "$f")" "EMPTY" "-" "$(rel "$f")"
  fi
}

wc_safe() {
  local f="$1"
  [[ -s "$f" ]] && wc -l < "$f" 2>/dev/null || echo 0
}


on_error() { log "[ERROR] Script failed at line $1"; }
trap 'on_error $LINENO' ERR

cleanup() { [[ -d "${TMP_DIR}" ]] && rm -rf "${TMP_DIR}"; }
trap cleanup EXIT

# -------------------------
# Binaries (prefer PATH; allow local overrides)
# -------------------------

MAPCIDR_BIN="${MAPCIDR_BIN:-${ASSET_SEG_DIR}/mapcidr}"
NAABU_BIN="${NAABU_BIN:-${ASSET_SEG_DIR}/naabu}"
NMAP_BIN="${NMAP_BIN:-nmap}"
NUCLEI_BIN="${NUCLEI_BIN:-${ASSET_SEG_DIR}/nuclei}"

# -------------------------
# Scan Params (override via env)
# -------------------------
NAABU_RATE="${NAABU_RATE:-500}"
NUCLEI_TEMPLATES="${NUCLEI_TEMPLATES:-/home/vboxuser/Desktop/penetration-tools/tools/tool_Asset_Segmentation/nuclei-templates}"


# Your long port list (override via env PORTS if needed)
PORTS="${PORTS:-21,22,23,25,53,80,81,88,110,111,123,135,137,138,139,143,161,389,443,4443,445,465,502,512,513,514,587,593,631,873,888,102,1025,1080,1158,1194,1234,13306,1433,1521,1522,1525,16379,1911,19200,2049,2082,2083,2181,2375,2376,2379,2380,2480,2525,26379,27017,27018,27019,28017,3000,3001,30080,3306,33060,33306,3389,3390,3690,4000,44818,47808,4840,4848,5000,5001,5002,50030,50070,5020,5432,5433,54321,5500,5601,5900,5901,5984,6000,6379,6666,7000,7001,7002,7003,7004,7005,7006,7007,7547,7777,8000,8001,8008,8010,8020,8030,8042,8069,8080,8081,8088,8090,8091,8161,8200,8222,8280,8300,8443,8500,8600,8800,8880,8888,9000,9001,9042,9060,9080,9090,9200,9201,9202,9300,9393,9443,9999,10000,10001,10443,10502,12345,15600,15672,18080,49152,49153,49154,49155,49156,49157,49158,49159,49160,10250,10255}"

NMAP_INTENSITY="${NMAP_INTENSITY:-5}"
NMAP_EXTRA="${NMAP_EXTRA:-}"   # e.g. "-sC"

# -------------------------
# Outputs
# -------------------------
SEED_IPS="${HOST_FX_DIR}/no_cdn_ips.txt"

GREY_JSONL="${CDN_FX_DIR}/maybe_frontend_grey.jsonl"
GREY_IPS="${HOST_FX_DIR}/grey_ips.txt"

# naabu 实际输入（最终 IP 列表：expanded+asn_allowed + grey）
NAABU_INPUT_IPS="${HOST_FX_DIR}/naabu_input_ips.txt"

CIDR_AGG="${HOST_FX_DIR}/mapcidr_cidr.txt"
EXPANDED_IPS="${HOST_FX_DIR}/mapcidr_expanded_ips.txt"

ASN_ALLOWED="${HOST_FX_DIR}/asn_allowed_ips.txt"
ASN_BLOCKED="${HOST_FX_DIR}/asn_blocked_ips.txt"
ASN_DETAIL_JSONL="${HOST_FX_DIR}/asn_lookup_detail.jsonl"

NAABU_OUT="${HOST_FX_DIR}/naabu_ip_port.txt"

NMAP_DIR="${HOST_FX_DIR}/nmap"
NMAP_SUMMARY_TSV="${HOST_FX_DIR}/nmap_summary.tsv"
mkdir -p "${NMAP_DIR}"

# -------------------------
# Helpers
# -------------------------
require_file() { [[ -f "$1" ]] || { log "[FATAL] Missing file: $1"; exit 1; }; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || { log "[FATAL] Missing command in PATH: $1"; exit 1; }; }
require_exec() { [[ -x "$1" ]] || { log "[FATAL] Missing or not executable: $1"; exit 1; }; }

log "[*] Key: ${KEY}"
log "[*] Report Dir: ${OUT_DIR}"
log "[*] Tool base: ${ASSET_SEG_DIR}"
log "[*] select_cdn.py: ${SELECT_CDN}"
log "[*] Python: ${PYTHON}"
log "[*] Log: ${LOG_FILE}"
log "[*] Tmp: ${TMP_DIR}"

# Preflight
#require_file "${IP2ASN_TSV}"
require_exec "${MAPCIDR_BIN}"
require_exec "${NAABU_BIN}"
require_cmd "${NMAP_BIN}"
require_cmd jq
require_exec "${PYTHON}"
require_file "${SELECT_CDN}"
require_file "${EXPAND_CIDR}"
require_file "${ASN_FILTER}"
require_file "${GROUP_NAABU}"
require_file "${NMAP_INDEX}"
require_file "${VULN_PREFILTER}"
#require_exec "${NUCLEI_BIN}"
#require_file "${NUCLEI_TEMPLATES}/README.md"


#NUCLEI_RATE="${NUCLEI_RATE:-50}"
#NUCLEI_TIMEOUT="${NUCLEI_TIMEOUT:-7}"
#NUCLEI_RETRIES="${NUCLEI_RETRIES:-1}"




# =========================================================
# 0) select_cdn.py (generate cdn_fx/no_cdn_realip.jsonl)
# =========================================================
log "[0/6] select_cdn (generate cdn_fx)"

require_file "${HTTPX_JSONL}"

if [[ -s "${INPUT_JSONL}" ]]; then
  log "[*] Skip select_cdn (exists & non-empty): ${INPUT_JSONL}"
else
  log "[*] Run: ${PYTHON} ${SELECT_CDN} ${SAFE_KEY}"
  "${PYTHON}" "${SELECT_CDN}" "${SAFE_KEY}"
  require_file "${INPUT_JSONL}"
fi

# Always report counts and enforce strict empty condition here
no_cdn_cnt=$(wc -l < "${INPUT_JSONL}" 2>/dev/null || echo 0)
grey_cnt=0
[[ -f "${GREY_JSONL}" ]] && grey_cnt=$(wc -l < "${GREY_JSONL}" 2>/dev/null || echo 0)

log "[*] select_cdn outputs: no_cdn_realip=${no_cdn_cnt}, maybe_frontend_grey=${grey_cnt}"

if [[ "${no_cdn_cnt}" -eq 0 && "${grey_cnt}" -eq 0 ]]; then
  log "[!] No usable IPs from select_cdn (CDN-only target). Skip Host-FX pipeline."
  log "[!] Suggest continuing with domain/URL-centric workflow (httpx / nuclei / js / paths)."
  exit 0
fi



# =========================================================
# 1) Extract host_ip from JSONL -> SEED_IPS
# =========================================================
log "[1/6] Extract seed IPs from no_cdn_realip.jsonl"

if [[ -s "${SEED_IPS}" ]]; then
  log "[*] Skip seed extraction (exists & non-empty): ${SEED_IPS}"
else
  # Extract host_ip (fallback to ip), filter empty/null, unique + sort
  # -r: raw output (no quotes)
  # // empty: fallback
  # select(. != "" and . != "null"): drop empties
 # Always create output file first (avoid pipefail when grep finds no matches)
 : > "${SEED_IPS}"

 # NOTE: With `set -o pipefail`, `grep` returns exit code 1 when no lines match.
 # That is NOT an error for us (it just means zero seed IPs). So we neutralize it.
 jq -r '(._split.real_ips[]? // .host_ip // .ip // empty) | select(. != "" and . != "null")' \
   "${INPUT_JSONL}" 2>/dev/null || true \
   | { grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' || true; } \
   | sort -u \
   > "${SEED_IPS}"

  require_file "${SEED_IPS}"
  if [[ ! -s "${SEED_IPS}" ]]; then
    log "[!] Seed IP list is empty: ${SEED_IPS} (will rely on grey IPs if any)"
  fi
fi

log "[*] Seed IPs: $(wc -l < "${SEED_IPS}")"

# =========================================================
# 1b) Extract grey IPs (NO mapcidr/expand, NO asn_filter)
# =========================================================
log "[1b/6] Extract grey IPv4 IPs from maybe_frontend_grey.jsonl"

if [[ -s "${GREY_IPS}" ]]; then
  log "[*] Skip grey extraction (exists & non-empty): ${GREY_IPS}"
else
  if [[ -s "${GREY_JSONL}" ]]; then
    jq -r '(._split.real_ips[]? // .host_ip // .ip // empty) | select(. != "" and . != "null")' \
      "${GREY_JSONL}" \
      | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' \
      | sort -u \
      > "${GREY_IPS}" || true
  else
    : > "${GREY_IPS}" || true
  fi
fi

log "[*] Grey IPs: $(wc -l < "${GREY_IPS}" 2>/dev/null || echo 0)"
if [[ ! -s "${SEED_IPS}" && ! -s "${GREY_IPS}" ]]; then
  log "[FATAL] No usable IPs after extraction (seed & grey both empty)"
  exit 1
fi
# =========================================================
# 2/3/4) mapcidr + expand + asn_filter (ONLY if seed exists)
# =========================================================
if [[ -s "${SEED_IPS}" ]]; then
  # =========================================================
  # 2) mapcidr aggregate -> CIDR list
  # =========================================================
  log "[2/6] mapcidr aggregate (IPs -> CIDRs)"

  if [[ -s "${CIDR_AGG}" ]]; then
    log "[*] Skip mapcidr aggregate (exists & non-empty): ${CIDR_AGG}"
  else
    "${MAPCIDR_BIN}" -cl "${SEED_IPS}" -aggregate -silent -o "${CIDR_AGG}"
    require_file "${CIDR_AGG}"
    if [[ ! -s "${CIDR_AGG}" ]]; then
      log "[FATAL] CIDR output empty: ${CIDR_AGG}"
      exit 1
    fi
  fi
  log "[*] Aggregated CIDRs: $(wc -l < "${CIDR_AGG}")"

  # =========================================================
  # 3) Expand CIDRs -> IP list
  # =========================================================
  log "[3/6] Expand CIDRs -> IPs"

  if [[ -s "${EXPANDED_IPS}" ]]; then
    log "[*] Skip expand (exists & non-empty): ${EXPANDED_IPS}"
  else
    "${PYTHON}" "${EXPAND_CIDR}" "${CIDR_AGG}" "${EXPANDED_IPS}"
    require_file "${EXPANDED_IPS}"
    if [[ ! -s "${EXPANDED_IPS}" ]]; then
      log "[FATAL] Expanded IP list is empty: ${EXPANDED_IPS}"
      exit 1
    fi
  fi
  log "[*] Expanded IPs: $(wc -l < "${EXPANDED_IPS}")"

  # =========================================================
  # 4) ASN lookup + deny (cloud/cdn/edge) -> allowed IPs
  # =========================================================
  log "[4/6] ASN filter using ip2asn-combined.tsv"

  DENY_KW_FILE="${CDN_IP_DIR}/asn_deny_keywords.txt"

  if [[ -s "${ASN_ALLOWED}" && -s "${ASN_DETAIL_JSONL}" ]]; then
    log "[*] Skip ASN filter (exists): ${ASN_ALLOWED}"
  else
    "${PYTHON}" "${ASN_FILTER}" \
      "${IP2ASN_TSV}" "${EXPANDED_IPS}" \
      "${ASN_ALLOWED}" "${ASN_BLOCKED}" "${ASN_DETAIL_JSONL}" \
      "${DENY_KW_FILE}"
    require_file "${ASN_ALLOWED}"
    require_file "${ASN_DETAIL_JSONL}"
  fi
else
  log "[!] No seed IPs -> skip mapcidr/expand/asn_filter (grey-only mode)"
  : > "${CIDR_AGG}" || true
  : > "${EXPANDED_IPS}" || true
  : > "${ASN_ALLOWED}" || true
  : > "${ASN_BLOCKED}" || true
  : > "${ASN_DETAIL_JSONL}" || true
fi

# =========================================================
# Build final naabu input IP list (asn_allowed + grey)
# =========================================================
log "[*] Build naabu input IP list"

# Merge ASN_ALLOWED (may be empty) + GREY_IPS
cat "${ASN_ALLOWED}" "${GREY_IPS}" 2>/dev/null \
  | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' \
  | sort -u \
  > "${NAABU_INPUT_IPS}" || true

require_file "${NAABU_INPUT_IPS}"

if [[ ! -s "${NAABU_INPUT_IPS}" ]]; then
  log "[FATAL] naabu input IP list is empty: ${NAABU_INPUT_IPS}"
  exit 1
fi

log "[*] naabu input IPs: $(wc -l < "${NAABU_INPUT_IPS}")"
# =========================================================
# [Extra] Merge bc.csv Ip column into NAABU_INPUT_IPS (if exists)
# =========================================================
BC_CSV="${ROOT}/bc.csv"

if [[ -f "${BC_CSV}" ]]; then
  log "[*] Detected bc.csv, merging first-column IPs into naabu input IPs"

  ORIG_CNT=$(wc -l < "${NAABU_INPUT_IPS}")
  TMP_BC_IPS="${TMP_DIR}/bc_ips.txt"

  # 取第一列作为 IP（跳过表头，处理 BOM / CRLF / 空格）
  tail -n +2 "${BC_CSV}" \
    | cut -d',' -f1 \
    | sed 's/^\xEF\xBB\xBF//' \
    | tr -d '\r' \
    | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
    | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' \
    | sort -u > "${TMP_BC_IPS}"

  BC_CNT=$(wc -l < "${TMP_BC_IPS}")

  # 合并 + 去重
  cat "${NAABU_INPUT_IPS}" "${TMP_BC_IPS}" \
    | sort -u > "${NAABU_INPUT_IPS}.merged"

  MERGED_CNT=$(wc -l < "${NAABU_INPUT_IPS}.merged")
  mv "${NAABU_INPUT_IPS}.merged" "${NAABU_INPUT_IPS}"

  DEDUP_CNT=$(( ORIG_CNT + BC_CNT - MERGED_CNT ))
  ADDED_CNT=$(( MERGED_CNT - ORIG_CNT ))

  log "[*] bc.csv merge stats:"
  log "    - original naabu IPs : ${ORIG_CNT}"
  log "    - bc.csv IPs         : ${BC_CNT}"
  log "    - deduplicated       : ${DEDUP_CNT}"
  log "    - added              : ${ADDED_CNT}"
  log "    - final naabu IPs    : ${MERGED_CNT}"
else
  log "[*] bc.csv not found, skip merge"
fi


# =========================================================
# 5) naabu port scan (allowed IPs)
# =========================================================
log "[5/6] naabu scan"

if [[ -s "${NAABU_OUT}" ]]; then
  log "[*] Skip naabu (exists & non-empty): ${NAABU_OUT}"
else
  "${NAABU_BIN}" -l "${NAABU_INPUT_IPS}" \
    -rate "${NAABU_RATE}" \
    -p "${PORTS}" \
	-retries 3 \
    -timeout 2000 \
    -silent -o "${NAABU_OUT}"

  require_file "${NAABU_OUT}"
  if [[ ! -s "${NAABU_OUT}" ]]; then
    log "[FATAL] naabu output empty: ${NAABU_OUT}"
    exit 1
  fi
fi

log "[*] naabu hits: $(wc -l < "${NAABU_OUT}")"

# =========================================================
# 6) nmap service version scan (group ports per IP)
# =========================================================
log "[6/6] nmap -sV (grouped by IP)"

if [[ -s "${NMAP_SUMMARY_TSV}" ]]; then
  log "[*] Skip nmap (summary exists): ${NMAP_SUMMARY_TSV}"
else
  : > "${NMAP_SUMMARY_TSV}"
  echo -e "ip\tports\tnmap_output" >> "${NMAP_SUMMARY_TSV}"

  # 6.1 group naabu output -> ip_ports.tsv
  "${PYTHON}" "${GROUP_NAABU}" "${NAABU_OUT}" "${TMP_DIR}/ip_ports.tsv"

  # 6.2 run nmap per IP (single run per host)
  while IFS=$'\t' read -r ip ports; do
    [[ -z "${ip}" || -z "${ports}" ]] && continue
    out_file="${NMAP_DIR}/${ip}.nmap.txt"


    if [[ -s "${out_file}" ]]; then
      log "[*] Skip nmap for ${ip} (exists): ${out_file}"
    else
      log "[*] nmap ${ip} ports=${ports}"
      "${NMAP_BIN}" -p "${ports}" -sV -Pn \
        --version-intensity "${NMAP_INTENSITY}" ${NMAP_EXTRA} \
        --reason --stats-every 30s \
        -oN "${out_file}" "${ip}" 2>>"${LOG_FILE}" || true
    fi

    echo -e "${ip}\t${ports}\t${out_file}" >> "${NMAP_SUMMARY_TSV}"
  done < "${TMP_DIR}/ip_ports.tsv"
fi


# =========================================================
# 7/8/9) Build service index from nmap -> targeted NSE + nuclei
# =========================================================
log "[7/9] Build service index (from nmap outputs)"

NUCLEI_DIR="${HOST_FX_DIR}/nuclei"
mkdir -p "${NUCLEI_DIR}"

INDEX_DIR="${HOST_FX_DIR}/service_index"
mkdir -p "${INDEX_DIR}"

if [[ -s "${INDEX_DIR}/targets_ipports_all.txt" ]]; then
  log "[*] Skip service index (exists): ${INDEX_DIR}/targets_ipports_all.txt"
else
  "${PYTHON}" "${NMAP_INDEX}" "${NMAP_SUMMARY_TSV}" "${INDEX_DIR}"
fi

# ---------
# Fallback targets (anti-miss): if parsed targets are empty or suspiciously small, fallback to naabu hits.
# This does NOT add any network traffic; it only prevents missing downstream nuclei coverage when nmap parsing fails.
# Control via:
#   TARGETS_MIN_RATIO (default 0.6): if targets_all < naabu_hits * ratio => fallback
TARGETS_MIN_RATIO="${TARGETS_MIN_RATIO:-0.6}"

NAABU_HITS_CNT="$(wc_safe "${NAABU_OUT}")"
TARGETS_ALL_CNT="$(wc_safe "${INDEX_DIR}/targets_ipports_all.txt")"

if [[ "${NAABU_HITS_CNT}" -gt 0 ]]; then
  # compute need_fallback = (targets_all == 0) OR (targets_all < naabu_hits * ratio)
  need_fallback=0
  if [[ "${TARGETS_ALL_CNT}" -eq 0 ]]; then
    need_fallback=1
  else
    # awk float compare
    need_fallback="$(awk -v t="${TARGETS_ALL_CNT}" -v n="${NAABU_HITS_CNT}" -v r="${TARGETS_MIN_RATIO}" 'BEGIN{print (t < n*r) ? 1 : 0}')"
  fi

  if [[ "${need_fallback}" -eq 1 ]]; then
    log "[!] targets_ipports_all seems incomplete (targets=${TARGETS_ALL_CNT}, naabu=${NAABU_HITS_CNT}, ratio=${TARGETS_MIN_RATIO}) -> fallback to naabu hits"
    # naabu output is already ip:port; just normalize/sort/unique
    sort -u "${NAABU_OUT}" > "${INDEX_DIR}/targets_ipports_all.txt" || true
    TARGETS_ALL_CNT="$(wc_safe "${INDEX_DIR}/targets_ipports_all.txt")"
    log "[*] Fallback targets_ipports_all.txt lines=${TARGETS_ALL_CNT}"
  fi
fi

# ---------
# Optional: targeted NSE verification (low-noise)
# ---------
log "[7b/9] Optional NSE verify (service-based)"

# Notes:
# - Minimal-noise principle: ONLY touch ip:port that were already identified by nmap service index.
# - Avoid fixed ports (e.g., 22 / 443) to prevent extra probes and to cover non-standard ports.
# - Write per-host outputs to avoid overwrite and to allow resume.

VERIFY_DIR="${NMAP_DIR}/verify"
mkdir -p "${VERIFY_DIR}"

# --- SSH (use actual ports from targets_ipports_ssh.txt) ---
if [[ -s "${INDEX_DIR}/targets_ipports_ssh.txt" ]]; then
  # Build ip<TAB>portlist
  awk -F: 'NF>=2 {p[$1]=p[$1] ? p[$1]","$2 : $2} END {for (ip in p) print ip"\t"p[ip]}' \
    "${INDEX_DIR}/targets_ipports_ssh.txt" \
    | sort -t$'\t' -k1,1 > "${TMP_DIR}/ssh_ip_ports.tsv" || true

  while IFS=$'\t' read -r ip ports; do
    [[ -z "${ip}" || -z "${ports}" ]] && continue
    out="${VERIFY_DIR}/ssh2-enum-algos_${ip}.txt"
    [[ -s "${out}" ]] && continue
    log "[*] NSE ssh2-enum-algos ${ip} ports=${ports}"
    "${NMAP_BIN}" -p "${ports}" --script ssh2-enum-algos -oN "${out}" "${ip}" 2>/dev/null || true
  done < "${TMP_DIR}/ssh_ip_ports.tsv"
fi

# --- HTTPS/TLS (use actual ports from targets_ipports_https.txt) ---
if [[ -s "${INDEX_DIR}/targets_ipports_https.txt" ]]; then
  awk -F: 'NF>=2 {p[$1]=p[$1] ? p[$1]","$2 : $2} END {for (ip in p) print ip"\t"p[ip]}' \
    "${INDEX_DIR}/targets_ipports_https.txt" \
    | sort -t$'\t' -k1,1 > "${TMP_DIR}/https_ip_ports.tsv" || true

  while IFS=$'\t' read -r ip ports; do
    [[ -z "${ip}" || -z "${ports}" ]] && continue
    out="${VERIFY_DIR}/ssl-enum-ciphers_${ip}.txt"
    [[ -s "${out}" ]] && continue
    log "[*] NSE ssl-enum-ciphers ${ip} ports=${ports}"
    "${NMAP_BIN}" -p "${ports}" --script ssl-enum-ciphers -oN "${out}" "${ip}" 2>/dev/null || true
  done < "${TMP_DIR}/https_ip_ports.tsv"
fi

# --- SMB (keep 445 by default; smb on non-445 is rare, but can be extended similarly if needed) ---
if [[ -s "${INDEX_DIR}/targets_ipports_smb.txt" ]]; then
  cut -d: -f1 "${INDEX_DIR}/targets_ipports_smb.txt" | sort -u > "${TMP_DIR}/smb_ips.txt"
  "${NMAP_BIN}" -iL "${TMP_DIR}/smb_ips.txt" -p 445 --script smb2-security-mode,smb-os-discovery -oN "${VERIFY_DIR}/verify_smb.txt" 2>/dev/null || true
fi

: <<'DISABLE_NUCLEI_PREFILTER'
# =========================================================
# 7c) Signals -> hypotheses (vuln prefilter)
#    - Extract protocol + anomaly signals from Nmap/NSE outputs
#    - Generate hypothesis tags/targets to make nuclei *validate* not *guess*
# =========================================================
log "[7c/9] Build signals & hypotheses (vuln_prefilter)"

HYP_DIR="${HOST_FX_DIR}/hypothesis"
mkdir -p "${HYP_DIR}"

SIGNALS_JSONL="${HYP_DIR}/signals.jsonl"
HYP_JSONL="${HYP_DIR}/hypotheses.jsonl"
HYP_TAGS="${HYP_DIR}/hypothesis_tags.txt"
HYP_TARGETS="${HYP_DIR}/hypothesis_targets_ipports.txt"

if [[ -s "${HYP_JSONL}" && -s "${HYP_TAGS}" ]]; then
  log "[*] Skip vuln_prefilter (exists): ${HYP_JSONL}"
else
  # Default ON: enable low-noise HTTP host-sensitivity probing + minimal protocol probes
  HTTP_PROBE="${HTTP_PROBE:-1}"
  PROTO_PROBE="${PROTO_PROBE:-1}"
  PROBE_TIMEOUT="${PROBE_TIMEOUT:-6}"
  log "[*] Run: ${PYTHON} ${VULN_PREFILTER} --nmap-summary ${NMAP_SUMMARY_TSV} --index-dir ${INDEX_DIR} --verify-dir ${VERIFY_DIR} --out-dir ${HYP_DIR} --http-probe ${HTTP_PROBE} --proto-probe ${PROTO_PROBE} --timeout ${PROBE_TIMEOUT}"
  "${PYTHON}" "${VULN_PREFILTER}" \
    --nmap-summary "${NMAP_SUMMARY_TSV}" \
    --index-dir "${INDEX_DIR}" \
    --verify-dir "${VERIFY_DIR}" \
    --out-dir "${HYP_DIR}" \
    --http-probe "${HTTP_PROBE}" \
    --proto-probe "${PROTO_PROBE}" \
    --timeout "${PROBE_TIMEOUT}" \
    >>"${LOG_FILE}" 2>&1 || true
fi

DISABLE_NUCLEI_PREFILTER
: <<'DISABLE_NUCLEI_STEP8'
# =========================================================
# 8) nuclei targeted (misconfig/exposures/default-logins) by tags
# =========================================================
log "[8/9] nuclei targeted (misconfig/exposures/default-logins)"

NUCLEI8_OUT="${NUCLEI_DIR}/08_targeted_misconfig_exposure.jsonl"
if [[ -s "${NUCLEI8_OUT}" ]]; then
  log "[*] Skip nuclei step8 (exists): ${NUCLEI8_OUT}"
else
  TAG_SOURCE="${HYP_TAGS}"
  [[ -s "${TAG_SOURCE}" ]] || TAG_SOURCE="${INDEX_DIR}/nuclei_tags.txt"
  TAGS="$(paste -sd, "${TAG_SOURCE}" 2>/dev/null || true)"
  NUCLEI_TAG_ARGS=()
  if [[ -n "${TAGS}" ]]; then NUCLEI_TAG_ARGS=(-tags "${TAGS}"); fi
  # 用全 ip:port 作为 targets，但用 tags 限定模板范围（精准）
  if [[ -s "${INDEX_DIR}/targets_ipports_all.txt" ]]; then
    TARGET_LIST="${HYP_TARGETS}"
    [[ -s "${TARGET_LIST}" ]] || TARGET_LIST="${INDEX_DIR}/targets_ipports_all.txt"

    "${NUCLEI_BIN}" \
      -l "${TARGET_LIST}" \
      "${NUCLEI_TAG_ARGS[@]}" \
      -t exposures/ -t misconfiguration/ -t default-logins/ -t network/ \
      -severity medium,high,critical \
      -rate-limit "${NUCLEI_RATE}" -timeout "${NUCLEI_TIMEOUT}" -retries "${NUCLEI_RETRIES}" \
      -jsonl -o "${NUCLEI8_OUT}" \
      >>"${LOG_FILE}" 2>&1 || true
  else
    log "[*] No ip:port targets for nuclei step8"
  fi  
fi
DISABLE_NUCLEI_STEP8
: <<'DISABLE_NUCLEI_STEP9'
# =========================================================
# 9) nuclei targeted CVE (high/critical) by tags
# =========================================================
log "[9/9] nuclei targeted CVE (high/critical)"

NUCLEI9_OUT="${NUCLEI_DIR}/09_targeted_cves.jsonl"
if [[ -s "${NUCLEI9_OUT}" ]]; then
  log "[*] Skip nuclei step9 (exists): ${NUCLEI9_OUT}"
else
  TAG_SOURCE="${HYP_TAGS}"
  [[ -s "${TAG_SOURCE}" ]] || TAG_SOURCE="${INDEX_DIR}/nuclei_tags.txt"
  TAGS="$(paste -sd, "${TAG_SOURCE}" 2>/dev/null || true)"
  NUCLEI_TAG_ARGS=()
  if [[ -n "${TAGS}" ]]; then NUCLEI_TAG_ARGS=(-tags "${TAGS}"); fi
  if [[ -s "${INDEX_DIR}/targets_ipports_all.txt" ]]; then
    TARGET_LIST="${HYP_TARGETS}"
    [[ -s "${TARGET_LIST}" ]] || TARGET_LIST="${INDEX_DIR}/targets_ipports_all.txt"

    "${NUCLEI_BIN}" \
      -l "${TARGET_LIST}" \
      "${NUCLEI_TAG_ARGS[@]}" \
      -t cves/ -t network/cves/ \
      -severity high,critical \
      -rate-limit "${NUCLEI_RATE}" -timeout "${NUCLEI_TIMEOUT}" -retries "${NUCLEI_RETRIES}" \
      -jsonl -o "${NUCLEI9_OUT}" \
      >>"${LOG_FILE}" 2>&1 || true
  else
    log "[*] No ip:port targets for nuclei step9"
  fi

fi
DISABLE_NUCLEI_STEP9

log "[DONE] Host FX results saved to: ${HOST_FX_DIR}"
log "[DONE] Outputs summary:"
statf "${SEED_IPS}"
statf "${GREY_IPS}"
statf "${CIDR_AGG}"
statf "${EXPANDED_IPS}"
statf "${ASN_ALLOWED}"
statf "${ASN_BLOCKED}"
statf "${NAABU_OUT}"
statf "${NMAP_SUMMARY_TSV}"
statf "${INDEX_DIR}/targets_ipports_all.txt"
#statf "${INDEX_DIR}/nuclei_tags.txt"
#statf "${NUCLEI8_OUT}"
#statf "${NUCLEI9_OUT}"


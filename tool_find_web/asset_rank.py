#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Asset ranking for httpx.with_naabu.jsonl
- Input : httpx.with_naabu.jsonl
- Input : host_fx/naabu_ip_port.txt (optional)
- Output: asset_rank.jsonl / asset_rank.csv (sorted by risk_score desc)
"""

import json
import csv
import re
import argparse
from pathlib import Path


# -------------------------
# Regex patterns
# -------------------------
RE_ADMIN = re.compile(r'(^|/)(admin|manage|manager|console|dashboard|portal)(/|$)', re.I)
RE_LOGIN = re.compile(r'(^|/)(login|signin|sign-in|sso|oauth|auth|idp)(/|$)', re.I)
RE_API = re.compile(r'(^|/)(api)(/|$)|(^api\.)|/graphql(/|$)|/rpc(/|$)|/rest(/|$)|/v\d+(/|$)', re.I)
RE_DOCS = re.compile(r'swagger|openapi|api-docs|swagger-ui|v2/api-docs|v3/api-docs|actuator|metrics|prometheus|graphiql', re.I)
RE_NONPROD = re.compile(
    r'(^|\.)(dev|uat|test|preprod|staging|stage|stg|qa|sit|pit|int|integration|sandbox|demo|beta|preview|perf|load|training)(\.|$)'
    r'|/dev/|/uat/|/test/|/staging/|/sandbox/|/beta/|/preview/|/debug/|/internal/',
    re.I
)
RE_ERRORLIKE = re.compile(r'error|exception|stack|trace|debug|not\s*found|forbidden|unauthorized', re.I)

HI_DEVOPS = re.compile(r'Jenkins|GitLab|Harbor|Nexus|Sonatype|Artifactory|Grafana|Kibana|Prometheus|Zabbix|Sentry|SonarQube|Confluence|Jira', re.I)
HI_JAVA = re.compile(r'Java|Spring|Tomcat|Jetty|JBoss|WildFly|Struts', re.I)
HI_IIS = re.compile(r'Microsoft-IIS|ASP\.NET|IIS', re.I)


# -------------------------
# Helpers
# -------------------------
def to_str(x):
    if x is None:
        return ""
    return str(x)


def join_list(x):
    if isinstance(x, list):
        return ";".join(map(str, x))
    return to_str(x)


def load_naabu(p: Path):
    s = set()
    if p and p.exists():
        for line in p.read_text(errors="ignore").splitlines():
            if ":" in line:
                ip, port = line.rsplit(":", 1)
                s.add((ip.strip(), port.strip()))
    return s


def score_asset(o: dict, naabu_set: set):
    score = 0
    tags = []

    url = to_str(o.get("url"))
    title = to_str(o.get("title"))
    host = to_str(o.get("host"))
    host_ip = to_str(o.get("host_ip") or o.get("ip"))
    port = to_str(o.get("port"))
    tech = join_list(o.get("tech"))
    server = to_str(o.get("webserver") or o.get("server"))
    content_type = to_str(o.get("content_type"))

    # status
    try:
        status = int(o.get("status_code"))
    except Exception:
        status = None

    cdn = o.get("cdn", False) is True

    # A) Network
    if host_ip and port and (host_ip, port) in naabu_set:
        score += 30
        tags.append("NAABU_PORT")

    if not cdn:
        score += 20
        tags.append("NON_CDN")

    if port and port not in ("80", "443"):
        score += 10
        tags.append("NON_STD_PORT")

    # B) HTTP status
    if status == 200:
        score += 15
        tags.append("HTTP_200")
    elif status in (401, 403):
        score += 12
        tags.append("AUTH_REQUIRED")
    elif status and 500 <= status < 600:
        score += 15
        tags.append("HTTP_5XX")
    elif status and 300 <= status < 400:
        score += 5
        tags.append("REDIRECT")

    # C) Semantics
    if RE_ADMIN.search(url) or RE_ADMIN.search(title):
        score += 20
        tags.append("ADMIN")

    if RE_LOGIN.search(url) or RE_LOGIN.search(title):
        score += 15
        tags.append("LOGIN")

    if RE_API.search(url) or host.startswith("api.") or "json" in content_type.lower():
        score += 15
        tags.append("API")

    if RE_DOCS.search(url) or RE_DOCS.search(title):
        score += 25
        tags.append("API_DOCS")

    if RE_NONPROD.search(url) or RE_NONPROD.search(host):
        score += 20
        tags.append("NONPROD")

    # D) Tech stack
    if HI_DEVOPS.search(tech) or HI_DEVOPS.search(server):
        score += 25
        tags.append("DEVOPS")

    if HI_JAVA.search(tech) or HI_JAVA.search(server):
        score += 15
        tags.append("JAVA_STACK")

    if HI_IIS.search(tech) or HI_IIS.search(server):
        score += 12
        tags.append("IIS_DOTNET")

    # E) Anomaly
    if status == 200 and RE_ERRORLIKE.search(title):
        score += 20
        tags.append("ERRORLIKE_200")

    score = min(score, 100)
    return score, tags


# -------------------------
# Main
# -------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--input", required=True, help="httpx.with_naabu.jsonl")
    ap.add_argument("-n", "--naabu", help="naabu_ip_port.txt")
    ap.add_argument("-o", "--outdir", required=True, help="output directory")
    args = ap.parse_args()

    in_jsonl = Path(args.input)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    naabu_set = load_naabu(Path(args.naabu)) if args.naabu else set()

    rows = []
    for line in in_jsonl.read_text(errors="ignore").splitlines():
        try:
            o = json.loads(line)
        except Exception:
            continue
        score, tags = score_asset(o, naabu_set)
        o["risk_score"] = score
        o["risk_tags"] = tags
        o["risk_reason"] = ",".join(tags[:8])
        rows.append(o)

    rows.sort(key=lambda x: x.get("risk_score", 0), reverse=True)

    # JSONL
    with (outdir / "asset_rank.jsonl").open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    # CSV
    with (outdir / "asset_rank.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "risk_score", "risk_reason", "url", "host", "port", "status_code",
                "title", "webserver", "host_ip", "cdn", "cdn_type", "content_type"
            ],
        )
        w.writeheader()
        for r in rows:
            w.writerow({
                "risk_score": r.get("risk_score"),
                "risk_reason": r.get("risk_reason"),
                "url": r.get("url"),
                "host": r.get("host"),
                "port": r.get("port"),
                "status_code": r.get("status_code"),
                "title": r.get("title"),
                "webserver": r.get("webserver") or r.get("server"),
                "host_ip": r.get("host_ip") or r.get("ip"),
                "cdn": r.get("cdn"),
                "cdn_type": r.get("cdn_type"),
                "content_type": r.get("content_type"),
            })


if __name__ == "__main__":
    main()


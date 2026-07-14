"""
ScanBs — Backend API
Real TCP port scanner + service banner grabbing + tech detection + CVE + headers
+ SQLite scan history + MITRE ATT&CK mapping + ASM modules

Install:
    pip install -r requirements.txt

Run:
    uvicorn main:app --reload --port 5000
"""

import asyncio
import socket
import ssl
import re
import json
import uuid
import sqlite3
import httpx
import base64
from pathlib import Path
from datetime import datetime
from typing import Optional, cast
from fastapi import FastAPI, BackgroundTasks, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="ScanBs API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── In-memory scan store ──────────────────────────────────────────
scans: dict = {}

# ═══════════════════════════════════════════════════════════════════
#  SQLITE HISTORY
# ═══════════════════════════════════════════════════════════════════

import logging
logger = logging.getLogger("scanbs")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")

import os
DB_PATH = os.environ.get("DB_PATH", "scanbs_history.db")

# ═══════════════════════════════════════════════════════════════════
#  OLLAMA — LLM LOCAL MITIGATION ENGINE
# ═══════════════════════════════════════════════════════════════════

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://host.docker.internal:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:7b")

MITIGATION_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "cve_id":        {"type": "string"},
        "cause":         {"type": "string"},
        "impact":        {"type": "string"},
        "immediate_fix": {"type": "string"},
        "long_term":     {"type": "string"},
        "sources_used":  {"type": "array", "items": {"type": "string"}},
        "confidence":    {"type": "string", "enum": ["high", "medium", "low"]},
    },
    "required": ["cve_id", "cause", "impact", "immediate_fix", "long_term", "confidence"],
}


async def generate_mitigation(cve_id: str, product: str, description: str,
                               cvss: float, severity: str,
                               version: str = "", refs: Optional[list] = None) -> Optional[dict]:
    """
    Call Ollama local LLM to generate a STRUCTURED, GROUNDED mitigation
    recommendation for a detected CVE.

    Anti-hallucination measures:
      - temperature=0 (deterministic, no "creative" filling-in of gaps)
      - the model only receives facts we already verified (NVD description + real refs)
      - explicit instruction to say "unknown" instead of inventing version/patch numbers
      - forced JSON schema output (format="json") instead of free text
      - the model is told to only cite URLs from the provided reference list
    Returns None if Ollama is unavailable or the response fails validation
    (never returns a partially-hallucinated blob).
    """
    refs = refs or []
    refs_block = "\n".join(f"- {u}" for u in refs[:6]) or "(aucune référence officielle disponible)"

    prompt = f"""Tu es un assistant technique qui aide à corriger une vulnérabilité connue.
Tu dois utiliser EXCLUSIVEMENT les informations fournies ci-dessous. N'invente RIEN.

DONNÉES VÉRIFIÉES (seule source de vérité) :
CVE: {cve_id}
Produit détecté: {product}
Version détectée: {version or "non précisée"}
Sévérité: {severity} (CVSS: {cvss})
Description officielle (NVD): {description}
Références officielles disponibles :
{refs_block}

RÈGLES STRICTES :
1. N'invente jamais un numéro de version corrigée, une date, ou une commande que tu ne peux pas déduire directement de la description ci-dessus. Si tu ne sais pas, écris "Consulter la référence officielle ci-dessus" au lieu de deviner.
2. Ne cite dans "sources_used" QUE des URLs présentes dans la liste de références ci-dessus, jamais une URL inventée.
3. Le champ "cve_id" de ta réponse DOIT être exactement "{cve_id}", ne mentionne aucun autre CVE.
4. Réponds UNIQUEMENT avec un objet JSON valide respectant strictement ce schéma, rien d'autre (pas de texte avant/après) :
{{
  "cve_id": "{cve_id}",
  "cause": "1 phrase : pourquoi la vulnérabilité existe",
  "impact": "1 phrase : ce qu'un attaquant peut faire",
  "immediate_fix": "étapes concrètes de correction basées uniquement sur les données fournies",
  "long_term": "bonne pratique générale pour éviter ce type de faille",
  "sources_used": ["url1", "url2"],
  "confidence": "high | medium | low — 'low' si la description ne donne pas assez de détails techniques précis"
}}"""

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            r = await client.post(
                f"{OLLAMA_HOST}/api/generate",
                json={
                    "model": OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                    "options": {
                        "temperature": 0,
                        "top_p": 0.9,
                        "num_predict": 400,
                    }
                }
            )
            if r.status_code != 200:
                logger.warning(f"[ollama] HTTP {r.status_code} for {cve_id}")
                return None

            raw = r.json().get("response", "").strip()
            return validate_mitigation(raw, cve_id, refs)

    except Exception as e:
        logger.warning(f"[ollama] Unavailable: {e}")
        return None


def validate_mitigation(raw_json: str, expected_cve_id: str, allowed_refs: list) -> Optional[dict]:
    """
    Post-generation guard rail. Rejects the mitigation entirely (returns None)
    rather than showing the user a half-hallucinated result if:
      - the JSON doesn't parse or is missing required fields
      - the model answered about a different CVE than the one asked
      - the model cited a source URL that wasn't in the allowed reference list
    """
    try:
        data = json.loads(raw_json)
    except Exception:
        logger.warning(f"[ollama] Non-JSON response for {expected_cve_id}, discarded")
        return None

    for field in MITIGATION_JSON_SCHEMA["required"]:
        if field not in data or not str(data[field]).strip():
            logger.warning(f"[ollama] Missing field '{field}' for {expected_cve_id}, discarded")
            return None

    if data["cve_id"].strip().upper() != expected_cve_id.strip().upper():
        logger.warning(
            f"[ollama] CVE mismatch: asked {expected_cve_id}, model answered {data['cve_id']} — discarded"
        )
        return None

    # Strip any cited source that isn't in the list we actually gave the model
    allowed_set = set(allowed_refs)
    sources = data.get("sources_used") or []
    clean_sources = [u for u in sources if u in allowed_set]
    if len(clean_sources) != len(sources):
        logger.warning(f"[ollama] Dropped {len(sources)-len(clean_sources)} unverified source(s) for {expected_cve_id}")
    data["sources_used"] = clean_sources

    if data.get("confidence") not in ("high", "medium", "low"):
        data["confidence"] = "low"

    data["ai_generated"] = True  # always flag in the UI, even after validation
    data["model"] = OLLAMA_MODEL
    data["generated_at"] = datetime.utcnow().isoformat()
    data["execution"] = f"Local via Ollama ({OLLAMA_HOST})"
    data["review_status"] = "human_review_required"
    return data


async def enrich_cves_with_mitigations(cves: list) -> list:
    """
    Generate mitigations for the top CVEs (max 8 to avoid long waits).
    Only processes HIGH and CRITICAL CVEs, or CISA KEV ones.
    Uses a SQLite cache keyed on (cve_id, product, exact detected version)
    so the same version of the same product is never re-sent to the LLM.
    """
    priority_cves = [
        c for c in cves
        if c.get("in_cisa_kev") or (c.get("cvss") or 0) >= 7
    ][:8]

    to_generate = []
    mitigation_map = {}

    for c in priority_cves:
        key = mitigation_cache_key(c["id"], c.get("product", ""), c.get("version", "") or "")
        cached = db_get_mitigation(key)
        if cached:
            mitigation_map[c["id"]] = cached
        else:
            to_generate.append((c, key))

    if to_generate:
        tasks = [
            generate_mitigation(
                c["id"],
                c.get("product", ""),
                c.get("description", ""),
                c.get("cvss") or 0,
                c.get("severity", "N/A"),
                c.get("version", "") or "",
                c.get("refs", [])
            )
            for c, _key in to_generate
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for (c, key), result in zip(to_generate, results):
            if isinstance(result, dict):
                mitigation_map[c["id"]] = result
                db_save_mitigation(key, c["id"], c.get("product", ""), result, OLLAMA_MODEL)
            # if None or exception: no mitigation shown, no hallucinated fallback text

    for c in cves:
        c["mitigation"] = mitigation_map.get(c["id"])  # dict or None — never a guessed string

    return cves

def db_init():
    """Create history table if it doesn't exist."""
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id          TEXT PRIMARY KEY,
            domain      TEXT NOT NULL,
            scanned_at  TEXT NOT NULL,
            risk_score  INTEGER,
            risk_label  TEXT,
            open_ports  INTEGER,
            tech_count  INTEGER,
            cve_count   INTEGER,
            header_issues INTEGER,
            result_json TEXT
        )
    """)
    con.commit()
    con.close()

def db_init_mitigation_cache():
    """Create the mitigation cache table (keyed by cve_id + product version)."""
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS mitigation_cache (
            cache_key    TEXT PRIMARY KEY,
            cve_id       TEXT NOT NULL,
            product      TEXT,
            payload_json TEXT NOT NULL,
            model        TEXT,
            created_at   TEXT NOT NULL
        )
    """)
    con.commit()
    con.close()

db_init()
db_init_mitigation_cache()

def db_save(scan_id: str, data: dict):
    """Persist a completed scan to SQLite."""
    try:
        risk = data.get("risk", {})
        ports_open = len([p for p in data.get("ports", []) if p.get("state") == "open"])
        con = sqlite3.connect(DB_PATH)
        con.execute("""
            INSERT OR REPLACE INTO scans
            (id, domain, scanned_at, risk_score, risk_label,
             open_ports, tech_count, cve_count, header_issues, result_json)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (
            scan_id,
            data.get("domain", ""),
            data.get("finished_at", datetime.utcnow().isoformat()),
            risk.get("score"),
            risk.get("label"),
            ports_open,
            len(data.get("technologies", [])),
            len(data.get("cves", [])),
            sum(1 for h in data.get("headers", {}).get("checks", []) if h.get("status") != "pass"),
            json.dumps(data)
        ))
        con.commit()
        con.close()
    except Exception as e:
        print(f"[DB] Save error: {e}")

def db_list() -> list:
    """Return all scans from history (summary only, no full JSON)."""
    try:
        con = sqlite3.connect(DB_PATH)
        rows = con.execute("""
            SELECT id, domain, scanned_at, risk_score, risk_label,
                   open_ports, tech_count, cve_count, header_issues
            FROM scans ORDER BY scanned_at DESC LIMIT 50
        """).fetchall()
        con.close()
        return [
            {
                "id": r[0], "domain": r[1], "scanned_at": r[2],
                "risk_score": r[3], "risk_label": r[4],
                "open_ports": r[5], "tech_count": r[6],
                "cve_count": r[7], "header_issues": r[8]
            }
            for r in rows
        ]
    except Exception as e:
        print(f"[DB] List error: {e}")
        return []

def db_get(scan_id: str) -> Optional[dict]:
    """Return full scan result from history."""
    try:
        con = sqlite3.connect(DB_PATH)
        row = con.execute(
            "SELECT result_json FROM scans WHERE id=?", (scan_id,)
        ).fetchone()
        con.close()
        return json.loads(row[0]) if row else None
    except Exception as e:
        print(f"[DB] Get error: {e}")
        return None

def db_delete(scan_id: str):
    """Delete a scan from history."""
    try:
        con = sqlite3.connect(DB_PATH)
        con.execute("DELETE FROM scans WHERE id=?", (scan_id,))
        con.commit()
        con.close()
    except Exception as e:
        print(f"[DB] Delete error: {e}")


def mitigation_cache_key(cve_id: str, product: str, version: str) -> str:
    """Cache key includes the exact detected version — never reuse a mitigation across versions."""
    return f"{cve_id}::{product or ''}::{version or ''}".lower()


def db_get_mitigation(cache_key: str) -> Optional[dict]:
    try:
        con = sqlite3.connect(DB_PATH)
        row = con.execute(
            "SELECT payload_json FROM mitigation_cache WHERE cache_key=?", (cache_key,)
        ).fetchone()
        con.close()
        return json.loads(row[0]) if row else None
    except Exception as e:
        print(f"[DB] Mitigation cache get error: {e}")
        return None


def db_save_mitigation(cache_key: str, cve_id: str, product: str, payload: dict, model: str):
    try:
        con = sqlite3.connect(DB_PATH)
        con.execute("""
            INSERT OR REPLACE INTO mitigation_cache
            (cache_key, cve_id, product, payload_json, model, created_at)
            VALUES (?,?,?,?,?,?)
        """, (
            cache_key, cve_id, product, json.dumps(payload), model,
            datetime.utcnow().isoformat()
        ))
        con.commit()
        con.close()
    except Exception as e:
        print(f"[DB] Mitigation cache save error: {e}")

# ═══════════════════════════════════════════════════════════════════
#  OWASP TOP 10 MAPPING
# ═══════════════════════════════════════════════════════════════════

OWASP_TOP10 = {
    "A01": {
        "name": "Broken Access Control",
        "desc": "Restrictions on authenticated users not properly enforced.",
        "cwe": ["CWE-22","CWE-284","CWE-285","CWE-639","CWE-732","CWE-918"]
    },
    "A02": {
        "name": "Cryptographic Failures",
        "desc": "Failures related to cryptography exposing sensitive data.",
        "cwe": ["CWE-261","CWE-296","CWE-310","CWE-319","CWE-321","CWE-326","CWE-327","CWE-328","CWE-330"]
    },
    "A03": {
        "name": "Injection",
        "desc": "User-supplied data not validated — SQL, NoSQL, OS, LDAP injection.",
        "cwe": ["CWE-20","CWE-74","CWE-75","CWE-77","CWE-78","CWE-79","CWE-88","CWE-89","CWE-90","CWE-91","CWE-93","CWE-94","CWE-95","CWE-96","CWE-97","CWE-98","CWE-99","CWE-116"]
    },
    "A04": {
        "name": "Insecure Design",
        "desc": "Missing or ineffective security controls by design.",
        "cwe": ["CWE-73","CWE-183","CWE-209","CWE-213","CWE-235","CWE-256","CWE-257","CWE-266","CWE-269","CWE-280","CWE-311","CWE-312","CWE-313","CWE-316","CWE-419","CWE-430","CWE-434","CWE-444","CWE-451","CWE-522","CWE-525","CWE-539","CWE-579","CWE-598","CWE-602","CWE-620","CWE-640","CWE-646","CWE-650","CWE-653","CWE-656","CWE-657","CWE-799"]
    },
    "A05": {
        "name": "Security Misconfiguration",
        "desc": "Missing security hardening, open cloud storage, unnecessary features enabled.",
        "cwe": ["CWE-2","CWE-11","CWE-13","CWE-15","CWE-16","CWE-260","CWE-315","CWE-520","CWE-526","CWE-537","CWE-541","CWE-547","CWE-611","CWE-614","CWE-756","CWE-776","CWE-942"]
    },
    "A06": {
        "name": "Vulnerable and Outdated Components",
        "desc": "Components with known vulnerabilities used without updates.",
        "cwe": ["CWE-1035","CWE-1104"]
    },
    "A07": {
        "name": "Identification and Authentication Failures",
        "desc": "Weak authentication allowing account takeover.",
        "cwe": ["CWE-255","CWE-259","CWE-287","CWE-288","CWE-290","CWE-294","CWE-295","CWE-297","CWE-300","CWE-302","CWE-304","CWE-306","CWE-307","CWE-346","CWE-384","CWE-521","CWE-613","CWE-620","CWE-640","CWE-798","CWE-940","CWE-1216"]
    },
    "A08": {
        "name": "Software and Data Integrity Failures",
        "desc": "Code and infrastructure without integrity verification.",
        "cwe": ["CWE-345","CWE-353","CWE-426","CWE-494","CWE-502","CWE-565","CWE-784","CWE-829","CWE-830","CWE-913"]
    },
    "A09": {
        "name": "Security Logging and Monitoring Failures",
        "desc": "Insufficient logging, monitoring and response to breaches.",
        "cwe": ["CWE-117","CWE-223","CWE-532","CWE-778"]
    },
    "A10": {
        "name": "Server-Side Request Forgery",
        "desc": "Server fetches a remote resource without validating user-supplied URL.",
        "cwe": ["CWE-918"]
    },
}

def compute_owasp(cves: list, header_checks: list, ports: list) -> list:
    """
    Map scan findings to OWASP Top 10 categories.
    Returns list of affected categories with evidence.
    """
    results = []

    # Collect all CWEs from CVEs
    all_cwes = set()
    for c in cves:
        for cwe in c.get("cwes", []):
            all_cwes.add(cwe)

    for code, info in OWASP_TOP10.items():
        affected = False
        evidence = []
        severity = "info"

        # ── Match CVEs by CWE
        matched_cwes = [cw for cw in info["cwe"] if cw in all_cwes]
        if matched_cwes:
            affected = True
            matched_cves = [
                c["id"] for c in cves
                if any(cw in c.get("cwes", []) for cw in matched_cwes)
            ]
            evidence.append(f"CVEs matching this category: {', '.join(matched_cves[:3])}")
            # Severity based on CVEs
            worst = max((c.get("cvss") or 0) for c in cves
                        if any(cw in c.get("cwes", []) for cw in matched_cwes))
            severity = "critical" if worst >= 9 else "high" if worst >= 7 else "medium"

        # ── A05: Security Misconfiguration — missing security headers
        if code == "A05":
            failed = [h["name"] for h in header_checks if h["status"] == "fail" and h.get("critical")]
            if failed:
                affected = True
                evidence.append(f"Missing critical headers: {', '.join(failed[:3])}")
                severity = "high" if len(failed) >= 3 else "medium"

        # ── A06: Vulnerable Components — any CVE = affected
        if code == "A06" and cves:
            affected = True
            severity = "critical" if any((c.get("cvss") or 0) >= 9 for c in cves) else "high"
            evidence.append(f"{len(cves)} known CVEs detected in identified components")

        # ── A02: Cryptographic Failures — missing HSTS
        if code == "A02":
            hsts = next((h for h in header_checks if "strict-transport" in h["name"].lower()), None)
            if hsts and hsts["status"] == "fail":
                affected = True
                evidence.append("Strict-Transport-Security header missing — HTTP not enforced")
                severity = "medium"

        # ── A07: Auth Failures — risky ports open (RDP, FTP, Telnet)
        if code == "A07":
            risky_open = [p for p in ports if p.get("risky") and p.get("state") == "open"
                          and p.get("port") in (21, 23, 3389)]
            if risky_open:
                affected = True
                evidence.append(f"Risky auth services exposed: {', '.join(str(p['port'])+'/'+p['service'] for p in risky_open)}")
                severity = "high"

        if affected:
            results.append({
                "code":     code,
                "name":     info["name"],
                "desc":     info["desc"],
                "severity": severity,
                "evidence": evidence
            })

    return results

class ScanRequest(BaseModel):
    domain: str
    nmap_xml: Optional[str] = None  # Optional nmap XML content


@app.post("/api/parse-nmap")
async def parse_nmap_upload(request: Request):
    """
    Accept raw nmap XML and return parsed open ports immediately.
    Frontend POSTs the XML file content here.
    """
    body = await request.body()
    xml_content = body.decode("utf-8", errors="ignore")
    try:
        ports = parse_nmap_xml(xml_content)
        ip = get_ip_from_nmap_xml(xml_content)
        return {
            "ip": ip,
            "ports": ports,
            "open_count": len(ports),
            "tcp_count": len([p for p in ports if p["proto"] == "TCP"]),
            "udp_count": len([p for p in ports if p["proto"] == "UDP"]),
        }
    except ValueError as e:
        raise HTTPException(400, str(e))

# ═══════════════════════════════════════════════════════════════════
#  PHASE 1 — NMAP XML PARSER (nmap run locally, output parsed here)
# ═══════════════════════════════════════════════════════════════════

import xml.etree.ElementTree as ET

RISKY_PORTS = {21, 23, 445, 3306, 3389, 5432, 6379, 27017, 2375, 9200, 5601, 2376, 4243}

# Top UDP ports worth scanning
UDP_PORTS = "53,67,68,69,123,137,138,161,162,500,514,520,1194,1900,4500,5353"


def parse_nmap_xml(xml_content: str) -> list:
    """
    Parse nmap XML output and return only OPEN ports.
    Works with output from:
      nmap -sS -sU -sV -sC -oX output.xml target
    """
    ports = []
    try:
        root = ET.fromstring(xml_content)
        for host in root.findall("host"):
            for port_el in host.findall(".//port"):
                state_el = port_el.find("state")
                if state_el is None:
                    continue

                state = state_el.get("state", "")
                if state not in ("open", "open|filtered"):
                    continue

                portid   = int(port_el.get("portid", 0))
                protocol = port_el.get("protocol", "tcp").upper()

                svc = port_el.find("service")
                svc_name    = svc.get("name", "unknown")    if svc is not None else "unknown"
                svc_product = svc.get("product", "")        if svc is not None else ""
                svc_version = svc.get("version", "")        if svc is not None else ""
                svc_extra   = svc.get("extrainfo", "")      if svc is not None else ""
                svc_tunnel  = svc.get("tunnel", "")         if svc is not None else ""

                banner_parts = [p for p in [svc_product, svc_version, svc_extra] if p]
                banner = " ".join(banner_parts) or svc_name

                # Collect NSE script outputs
                scripts = {}
                for script_el in port_el.findall("script"):
                    sid = script_el.get("id", "")
                    out = script_el.get("output", "").strip()
                    if sid and out:
                        scripts[sid] = out[:300]

                # Use script output for richer banner
                for key in ["banner", "http-title", "ssh-hostkey",
                            "ftp-anon", "smtp-commands"]:
                    if key in scripts:
                        banner = scripts[key].split("\n")[0].strip()[:120]
                        break

                is_ssl = svc_tunnel == "ssl" or portid in (443, 8443, 465, 993, 995)

                ports.append({
                    "port":    portid,
                    "proto":   protocol,
                    "service": svc_name,
                    "state":   "open",
                    "banner":  banner[:120] if banner else f"{svc_name} service",
                    "version": svc_version or None,
                    "product": svc_product,
                    "ssl":     is_ssl,
                    "scripts": scripts,
                    "risky":   portid in RISKY_PORTS,
                })

    except ET.ParseError as e:
        raise ValueError(f"Invalid nmap XML: {e}")

    return sorted(ports, key=lambda p: (p["proto"], p["port"]))


def get_ip_from_nmap_xml(xml_content: str) -> str:
    """Extract the target IP from nmap XML."""
    try:
        root = ET.fromstring(xml_content)
        for host in root.findall("host"):
            addr = host.find("address[@addrtype='ipv4']")
            if addr is not None:
                return addr.get("addr", "")
    except Exception:
        pass
    return ""


def extract_version_from_banner(banner: str, service: str) -> Optional[str]:
    """Fallback version extraction from banner string."""
    patterns = [
        r"Apache/([\d.]+)",
        r"nginx/([\d.]+)",
        r"OpenSSH_([\d.]+)",
        r"PHP/([\d.]+)",
        r"MySQL[\s/]+([\d.]+)",
        r"Microsoft-IIS/([\d.]+)",
        r"([\d]+\.[\d]+\.[\d]+)",
    ]
    for pat in patterns:
        m = re.search(pat, banner, re.I)
        if m:
            return m.group(1)
    return None


# ═══════════════════════════════════════════════════════════════════
#  PHASE 2 — TECH DETECTION (HTTP headers + HTML fingerprinting)
# ═══════════════════════════════════════════════════════════════════

TECH_FINGERPRINTS = [
    # (regex_on_combined_headers+html, name, category, emoji, cpe_vendor:product)
    (r"apache/([\d.]+)",           "Apache HTTP Server", "Web Server",  "🌐", "apache:http_server"),
    (r"nginx/([\d.]+)",            "Nginx",              "Web Server",  "⚡", "nginx:nginx"),
    (r"php/([\d.]+)",              "PHP",                "Language",    "🐘", "php:php"),
    (r"microsoft-iis/([\d.]+)",    "Microsoft IIS",      "Web Server",  "🪟", "microsoft:iis"),
    (r"wp-content|wp-json",        "WordPress",          "CMS",         "📝", "wordpress:wordpress"),
    (r"drupal",                    "Drupal",             "CMS",         "💧", "drupal:drupal"),
    (r"joomla",                    "Joomla",             "CMS",         "🔧", "joomla:joomla"),
    (r"django",                    "Django",             "Framework",   "🎸", "djangoproject:django"),
    (r"express",                   "Express.js",         "Framework",   "🚂", "expressjs:express"),
    (r"laravel",                   "Laravel",            "Framework",   "🔴", "laravel:laravel"),
    (r"cloudflare",                "Cloudflare",         "CDN/WAF",     "☁️", None),
    (r"varnish",                   "Varnish",            "Cache",       "🗄️", "varnish-cache:varnish"),
    (r"openssl/([\d.]+)",          "OpenSSL",            "TLS",         "🔐", "openssl:openssl"),
    (r"tomcat/([\d.]+)",           "Apache Tomcat",      "App Server",  "🐱", "apache:tomcat"),
    (r"node\.js",                  "Node.js",            "Runtime",     "💚", "nodejs:node.js"),
    (r"ruby",                      "Ruby",               "Language",    "💎", "ruby-lang:ruby"),
    (r"python/([\d.]+)",           "Python",             "Language",    "🐍", "python:python"),
    (r"jquery[/\s]+([\d.]+)",      "jQuery",             "JS Library",  "🔷", None),
    (r"bootstrap",                 "Bootstrap",          "CSS Framework","🎨", None),
    (r"react",                     "React",              "JS Framework","⚛️", None),
    (r"vue\.js",                   "Vue.js",             "JS Framework","💚", None),
    (r"next\.js|__next",           "Next.js",            "JS Framework","▲",  None),
    (r"x-generator.*wordpress",    "WordPress",          "CMS",         "📝", "wordpress:wordpress"),
    (r"powered by.*php",           "PHP",                "Language",    "🐘", "php:php"),
    (r"servlet/([\d.]+)",          "Java Servlet",       "App Server",  "☕", None),
    (r"spring",                    "Spring Framework",   "Framework",   "🌿", "pivotal_software:spring_framework"),
    (r"elastic",                   "Elasticsearch",      "Search",      "🔍", "elastic:elasticsearch"),
    (r"redis",                     "Redis",              "Cache/DB",    "🔴", "redis:redis"),
    (r"mysql",                     "MySQL",              "Database",    "🐬", "oracle:mysql"),
    (r"postgresql|pgsql",          "PostgreSQL",         "Database",    "🐘", "postgresql:postgresql"),
    (r"mongodb",                   "MongoDB",            "Database",    "🍃", "mongodb:mongodb"),
]


async def detect_tech(domain: str) -> dict:
    """Fetch HTTP/HTTPS response and fingerprint technologies."""
    raw_headers = {}
    body = ""
    final_url = ""

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=12.0,
        verify=False,
        headers={"User-Agent": "Mozilla/5.0 (compatible; ReconShield/1.0)"}
    ) as client:
        for scheme in ["https", "http"]:
            try:
                r = await client.get(f"{scheme}://{domain}")
                raw_headers = dict(r.headers)
                body = r.text[:80000]
                final_url = str(r.url)
                break
            except Exception:
                continue

    # Normalize headers to lowercase
    norm_headers = {k.lower(): v for k, v in raw_headers.items()}
    combined = (json.dumps(norm_headers) + body).lower()

    techs = []
    seen = set()

    for pattern, name, category, emoji, cpe in TECH_FINGERPRINTS:
        m = re.search(pattern, combined, re.I)
        if m and name not in seen:
            seen.add(name)
            # Try to extract version from match group
            version = None
            try:
                if m.lastindex and m.lastindex >= 1:
                    version = m.group(1)
            except Exception:
                pass

            # Also look in headers directly for known keys
            if not version:
                for hk in ("server", "x-powered-by", "x-generator"):
                    hv = norm_headers.get(hk, "")
                    vm = re.search(pattern, hv, re.I)
                    if vm:
                        try:
                            version = vm.group(1)
                        except Exception:
                            pass
                        break

            techs.append({
                "name": name,
                "category": category,
                "emoji": emoji,
                "version": version or "detected",
                "cpe": cpe,
            })

    # Leaking headers
    leaking = {k: v for k, v in norm_headers.items()
               if k in ("server", "x-powered-by", "x-aspnet-version",
                        "x-aspnetmvc-version", "x-runtime", "x-drupal-cache")}

    return {
        "techs": techs,
        "raw_headers": norm_headers,
        "leaking_headers": leaking,
        "final_url": final_url,
    }


# ═══════════════════════════════════════════════════════════════════
#  PHASE 3 — CVE LOOKUP (NVD + EPSS + CISA KEV)
# ═══════════════════════════════════════════════════════════════════

async def fetch_cisa_kev() -> set:
    try:
        async with httpx.AsyncClient(timeout=10.0) as c:
            r = await c.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            )
            return {v["cveID"] for v in r.json().get("vulnerabilities", [])}
    except Exception:
        return set()


async def fetch_epss(cve_ids: list) -> dict:
    if not cve_ids:
        return {}
    try:
        ids = ",".join(cve_ids)
        async with httpx.AsyncClient(timeout=10.0) as c:
            r = await c.get(f"https://api.first.org/data/1.0/epss?cve={ids}")
            return {
                e["cve"]: round(float(e["epss"]) * 100, 2)
                for e in r.json().get("data", [])
            }
    except Exception:
        return {}


async def nvd_query(client: httpx.AsyncClient, url: str) -> list:
    try:
        await asyncio.sleep(0.8)  # NVD rate limit
        r = await client.get(url, timeout=15.0,
                             headers={"User-Agent": "ReconShield/1.0"})
        return r.json().get("vulnerabilities", [])
    except Exception:
        return []


async def fetch_trickest_poc(cve_id: str) -> list:
    """
    Fetch the trickest/cve markdown file for a CVE via GitHub API
    and extract the exact PoC links listed inside it.

    The markdown file looks like:
      ### [CVE-ID](url_to_poc_repo)
      - [repo_name](direct_github_link)
      ...

    We decode the base64 content, parse all markdown links,
    and return only those pointing to real PoC repos (github.com,
    exploit-db, packetstorm, etc.) — excluding trickest itself.
    """
    try:
        year = cve_id.split("-")[1]
        api_url = f"https://api.github.com/repos/trickest/cve/contents/{year}/{cve_id}.md"

        async with httpx.AsyncClient(
            timeout=10.0,
            headers={
                "User-Agent": "ScanBs/1.0",
                "Accept": "application/json",
            }
        ) as client:
            r = await client.get(api_url)

            if r.status_code == 404:
                return []  # No PoC for this CVE in trickest

            if r.status_code != 200:
                return []

            data = r.json()
            import base64 as _b64
            raw_md = _b64.b64decode(
                data.get("content", "").replace("\n", "")
            ).decode("utf-8", errors="ignore")

            links = []
            seen_urls = set()

            # Extract all markdown links: [label](url)
            for m in re.finditer(r'\[([^\]]+)\]\((https?://[^)]+)\)', raw_md):
                label = m.group(1).strip()
                url   = m.group(2).strip()

                # Skip trickest links and duplicate URLs
                if "trickest" in url.lower():
                    continue
                if url in seen_urls:
                    continue
                seen_urls.add(url)

                # Only keep real PoC/exploit sources
                if re.search(
                    r'github\.com|exploit-db\.com|packetstormsecurity|'
                    r'vulhub|rapid7|metasploit|exploit\.ph|0day|nuclei',
                    url, re.I
                ):
                    links.append({
                        "source": "trickest/cve",
                        "url": url,
                        "label": label[:60],
                        "trickest": True,
                        "verified": True
                    })

            return links

    except Exception:
        return []


async def build_poc_links(cve_id: str, refs: list) -> list:
    """
    Return only the direct trickest/cve link for this CVE.
    Format: https://github.com/trickest/cve/blob/main/YEAR/CVE-ID.md
    Only shown if the file actually exists in the trickest repo.
    """
    try:
        year = cve_id.split("-")[1]
        api_url = f"https://api.github.com/repos/trickest/cve/contents/{year}/{cve_id}.md"

        async with httpx.AsyncClient(
            timeout=8.0,
            headers={"User-Agent": "ScanBs/1.0", "Accept": "application/json"}
        ) as client:
            r = await client.get(api_url)
            if r.status_code == 200:
                return [{
                    "source": "trickest/cve",
                    "url": f"https://github.com/trickest/cve/blob/main/{year}/{cve_id}.md",
                    "label": f"{cve_id}.md",
                    "trickest": True,
                    "verified": True
                }]
            return []
    except Exception:
        return []


def _safe_cve_year(cve_id: str) -> int:
    try:
        return int(cve_id.split("-")[1])
    except Exception:
        return 0


def _version_tuple(v: str) -> tuple:
    nums = re.findall(r"\d+", str(v or ""))[:4]
    return tuple(int(x) for x in nums) if nums else tuple()


def _version_between(version: str, start: str = "", end: str = "", start_incl: bool = True, end_incl: bool = True) -> bool:
    """Best-effort NVD range check. If parsing fails, stay conservative."""
    vt = _version_tuple(version)
    if not vt:
        return False
    if start:
        st = _version_tuple(start)
        if st and ((vt < st) or (vt == st and not start_incl)):
            return False
    if end:
        et = _version_tuple(end)
        if et and ((vt > et) or (vt == et and not end_incl)):
            return False
    return True


def _iter_cpe_matches(obj):
    """Recursively walk NVD configurations and yield cpeMatch entries."""
    if isinstance(obj, dict):
        if "cpeMatch" in obj and isinstance(obj["cpeMatch"], list):
            for m in obj["cpeMatch"]:
                yield m
        for v in obj.values():
            yield from _iter_cpe_matches(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from _iter_cpe_matches(item)


def _matches_detected_version(vuln: dict, cpe_base: str, version: str) -> bool:
    """
    Reduce false positives by checking whether NVD CPE criteria/ranges mention
    the detected product and include the detected version.
    """
    if not version or version == "detected":
        return False

    cpe_marker = f":{cpe_base}:"  # vendor:product
    for match in _iter_cpe_matches(vuln.get("cve", {}).get("configurations", [])):
        criteria = match.get("criteria", "") or match.get("cpe23Uri", "")
        if cpe_marker not in criteria:
            continue
        if match.get("vulnerable") is False:
            continue

        # Exact CPE version appears in the CPE criteria.
        if f":{version}:" in criteria:
            return True

        # Wildcard CPE with explicit affected version range.
        if any(k in match for k in (
            "versionStartIncluding", "versionStartExcluding",
            "versionEndIncluding", "versionEndExcluding"
        )):
            return _version_between(
                version,
                start=match.get("versionStartIncluding") or match.get("versionStartExcluding") or "",
                end=match.get("versionEndIncluding") or match.get("versionEndExcluding") or "",
                start_incl="versionStartIncluding" in match,
                end_incl="versionEndIncluding" in match,
            )
    return False


def parse_cve(vuln: dict, product: str, *, min_year: int = 2024,
              method: str = "unknown", confidence: str = "medium",
              detected_version: str = "") -> Optional[dict]:
    """
    Parse one NVD CVE and keep only recent CVEs by CVE-ID year.
    The scanner now prioritizes recent CVEs to reduce old false positives.
    """
    c = vuln.get("cve", {})
    desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    if not desc:
        return None

    cve_id = c.get("id", "")
    cve_year = _safe_cve_year(cve_id)
    if cve_year and cve_year < min_year:
        return None

    m = c.get("metrics", {})
    best = (
        (m.get("cvssMetricV40") or [{}])[0].get("cvssData") or
        (m.get("cvssMetricV31") or [{}])[0].get("cvssData") or
        (m.get("cvssMetricV30") or [{}])[0].get("cvssData") or
        (m.get("cvssMetricV2")  or [{}])[0].get("cvssData") or {}
    )
    cvss = best.get("baseScore")
    sev  = best.get("baseSeverity", "")
    if not sev and cvss:
        sev = "CRITICAL" if cvss >= 9 else "HIGH" if cvss >= 7 else "MEDIUM" if cvss >= 4 else "LOW"

    refs = [r.get("url", "") for r in c.get("references", [])[:8] if r.get("url")]
    poc_refs = [u for u in refs if re.search(r"exploit-db|github|poc|metasploit|packetstorm", u, re.I)]

    cwes = list({
        d.get("value", "") for w in c.get("weaknesses", [])
        for d in w.get("description", [])
        if d.get("lang") == "en" and d.get("value", "").startswith("CWE-")
    })[:3]

    return {
        "id": cve_id,
        "product": product,
        "description": desc[:300] + ("…" if len(desc) > 300 else ""),
        "cvss": cvss,
        "severity": sev.upper() if sev else "N/A",
        "vector": best.get("vectorString", ""),
        "published": c.get("published", "")[:10],
        "last_modified": c.get("lastModified", "")[:10],
        "cwes": cwes,
        "refs": refs,
        "poc_refs": poc_refs[:2],
        "poc_links": [],
        "in_cisa_kev": False,
        "epss": None,
        "lookup_method": method,
        "confidence": confidence,
        "detected_version": detected_version,
        "recent": True,
    }


def _recent_nvd_urls(base_params: dict, start_year: int = 2024, results_per_page: int = 20) -> list:
    """
    NVD date filters are queried in chunks to avoid large ranges.
    Uses pubStartDate/pubEndDate so results focus on recent CVEs.
    """
    from urllib.parse import urlencode
    from datetime import timedelta

    urls = []
    now = datetime.utcnow()
    start = datetime(start_year, 1, 1)
    # 110 days keeps us safely below NVD's common 120-day date-window limit.
    step = timedelta(days=110)
    while start < now:
        end = min(start + step, now)
        params = dict(base_params)
        params.update({
            "pubStartDate": start.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT23:59:59.999"),
            "resultsPerPage": str(results_per_page),
        })
        urls.append("https://services.nvd.nist.gov/rest/json/cves/2.0?" + urlencode(params))
        start = end + timedelta(days=1)
    return urls


async def _collect_recent_nvd(client: httpx.AsyncClient, params: dict, start_year: int, limit: int = 12) -> list:
    vulns = []
    for url in _recent_nvd_urls(params, start_year=start_year, results_per_page=min(limit, 20)):
        batch = await nvd_query(client, url)
        if batch:
            vulns.extend(batch)
        if len(vulns) >= limit:
            break
    return vulns[:limit]


def _keyword_for_tech(name: str, version: str = "") -> str:
    # Human-readable keywords work better for NVD keywordSearch than internal CPE names.
    aliases = {
        "Apache HTTP Server": "Apache HTTP Server",
        "Nginx": "nginx",
        "PHP": "PHP",
        "Microsoft IIS": "Microsoft IIS",
        "WordPress": "WordPress",
        "Drupal": "Drupal",
        "Joomla": "Joomla",
        "Django": "Django",
        "Laravel": "Laravel",
        "Apache Tomcat": "Apache Tomcat",
        "OpenSSL": "OpenSSL",
        "Node.js": "Node.js",
        "Spring Framework": "Spring Framework",
        "Redis": "Redis",
        "MySQL": "MySQL",
        "PostgreSQL": "PostgreSQL",
        "MongoDB": "MongoDB",
        "Elasticsearch": "Elasticsearch",
    }
    base = aliases.get(name, name)
    return f"{base} {version}".strip() if version and version != "detected" else base


async def lookup_cves(techs: list, port_results: list) -> list:
    """
    Recent-CVE engine, designed to reduce false positives:
      1) CPE exact + detected version + recent publication window.
      2) Keyword + detected version + recent publication window.
      3) Keyword-only recent search only as LOW confidence and only if high/critical or KEV.
      4) EPSS + CISA KEV enrichment for prioritization.
    """
    RECENT_START_YEAR = max(2024, datetime.utcnow().year - 2)
    cisa_kev = await fetch_cisa_kev()
    all_cves = []
    seen_ids = set()

    extra_techs = []
    for p in port_results:
        if p.get("state") == "open" and p.get("banner"):
            b = p["banner"].lower()
            for pattern, name, cat, emoji, cpe in TECH_FINGERPRINTS:
                if cpe and re.search(pattern, b, re.I):
                    version = extract_version_from_banner(p["banner"], name)
                    if not any(t.get("name") == name for t in techs + extra_techs):
                        extra_techs.append({
                            "name": name, "category": cat, "emoji": emoji,
                            "version": version or "detected", "cpe": cpe
                        })

    all_techs = techs + extra_techs

    async with httpx.AsyncClient(verify=False) as client:
        for tech in all_techs:
            name = tech.get("name", "")
            cpe_base = tech.get("cpe")
            version = tech.get("version") or "detected"
            has_version = bool(version and version != "detected")

            candidate_vulns = []

            # 1) Exact CPE + exact version, recent only.
            if cpe_base and has_version:
                cpe_name = f"cpe:2.3:a:{cpe_base}:{version}:*:*:*:*:*:*:*"
                vulns = await _collect_recent_nvd(
                    client, {"cpeName": cpe_name}, RECENT_START_YEAR, limit=10
                )
                for v in vulns:
                    candidate_vulns.append((v, "exact_cpe_version", "high"))

            # 2) Keyword + product + version, recent only.
            if has_version:
                kw = _keyword_for_tech(name, version)
                vulns = await _collect_recent_nvd(
                    client, {"keywordSearch": kw}, RECENT_START_YEAR, limit=10
                )
                for v in vulns:
                    candidate_vulns.append((v, "keyword_product_version", "medium"))

            # 3) Keyword only, recent only, low confidence.
            # Keep this small and strict to avoid returning unrelated old/noisy CVEs.
            kw = _keyword_for_tech(name, "")
            vulns = await _collect_recent_nvd(
                client, {"keywordSearch": kw}, RECENT_START_YEAR, limit=6
            )
            for v in vulns:
                candidate_vulns.append((v, "keyword_recent_product", "low"))

            for vuln, method, confidence in candidate_vulns:
                parsed = parse_cve(
                    vuln, name,
                    min_year=RECENT_START_YEAR,
                    method=method,
                    confidence=confidence,
                    detected_version=version if has_version else ""
                )
                if not parsed or parsed["id"] in seen_ids:
                    continue

                # If exact CPE/keyword-version was used, raise confidence only when NVD configurations
                # confirm the detected version. If not confirmed, keep it but mark lower confidence.
                if method in ("exact_cpe_version", "keyword_product_version") and cpe_base and has_version:
                    if _matches_detected_version(vuln, cpe_base, version):
                        parsed["confidence"] = "high"
                        parsed["version_confirmed"] = True
                    else:
                        parsed["confidence"] = "medium" if method == "exact_cpe_version" else "low"
                        parsed["version_confirmed"] = False
                else:
                    parsed["version_confirmed"] = False

                parsed["in_cisa_kev"] = parsed["id"] in cisa_kev

                # Strict rule for keyword-only results: keep only important recent CVEs.
                if method == "keyword_recent_product":
                    if not parsed["in_cisa_kev"] and (parsed.get("cvss") or 0) < 7:
                        continue

                seen_ids.add(parsed["id"])
                all_cves.append(parsed)

    epss_map = await fetch_epss([c["id"] for c in all_cves])
    for c in all_cves:
        c["epss"] = epss_map.get(c["id"])

    poc_tasks = [build_poc_links(c["id"], c.get("refs", [])) for c in all_cves]
    poc_results = await asyncio.gather(*poc_tasks, return_exceptions=True)
    for c, poc in zip(all_cves, poc_results):
        c["poc_links"] = poc if isinstance(poc, list) else []

    all_cves.sort(key=lambda x: (
        not x.get("in_cisa_kev", False),
        {"high": 0, "medium": 1, "low": 2}.get(x.get("confidence", "low"), 2),
        -(x.get("cvss") or 0),
        -(x.get("epss") or 0),
        x.get("published", "")
    ))

    return all_cves


# ═══════════════════════════════════════════════════════════════════
#  PHASE 4 — SECURITY HEADER ANALYSIS
# ═══════════════════════════════════════════════════════════════════

SECURITY_HEADERS = [
    {
        "name": "Content-Security-Policy",
        "key": "content-security-policy",
        "critical": True,
        "desc": "Prevents XSS by restricting allowed resource sources.",
        "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
    },
    {
        "name": "Strict-Transport-Security",
        "key": "strict-transport-security",
        "critical": True,
        "desc": "Forces HTTPS connections, prevents SSL stripping.",
        "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
    },
    {
        "name": "X-Frame-Options",
        "key": "x-frame-options",
        "critical": True,
        "desc": "Prevents clickjacking via iframe embedding.",
        "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
    },
    {
        "name": "X-Content-Type-Options",
        "key": "x-content-type-options",
        "critical": False,
        "desc": "Prevents MIME-type sniffing attacks.",
        "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
    },
    {
        "name": "Referrer-Policy",
        "key": "referrer-policy",
        "critical": False,
        "desc": "Controls how much referrer info is sent.",
        "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
    },
    {
        "name": "Permissions-Policy",
        "key": "permissions-policy",
        "critical": False,
        "desc": "Restricts browser APIs (camera, mic, geolocation).",
        "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"
    },
    {
        "name": "Cross-Origin-Opener-Policy",
        "key": "cross-origin-opener-policy",
        "critical": False,
        "desc": "Isolates browsing context, prevents XS-Leaks.",
        "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy"
    },
    {
        "name": "Cross-Origin-Resource-Policy",
        "key": "cross-origin-resource-policy",
        "critical": False,
        "desc": "Prevents cross-origin reads of this resource.",
        "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy"
    },
    {
        "name": "Cross-Origin-Embedder-Policy",
        "key": "cross-origin-embedder-policy",
        "critical": False,
        "desc": "Prevents loading cross-origin resources without permission.",
        "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy"
    },
]


async def analyze_headers(domain: str) -> dict:
    raw = {}

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=10.0,
        verify=False,
        headers={"User-Agent": "Mozilla/5.0 (compatible; ReconShield/1.0)"}
    ) as client:
        for scheme in ["https", "http"]:
            try:
                r = await client.get(f"{scheme}://{domain}")
                raw = {k.lower(): v for k, v in r.headers.items()}
                break
            except Exception:
                continue

    checks = []
    for h in SECURITY_HEADERS:
        val = raw.get(h["key"])
        status = "pass"
        note = ""

        if not val:
            status = "fail" if h["critical"] else "warn"
        else:
            # Quality checks
            if h["key"] == "strict-transport-security":
                ma = re.search(r"max-age=(\d+)", val, re.I)
                age = int(ma.group(1)) if ma else 0
                if age < 31536000:
                    status = "warn"
                    note = f"max-age={age} is below recommended 31536000 (1 year)"
            elif h["key"] == "content-security-policy":
                issues = []
                if "'unsafe-inline'" in val: issues.append("'unsafe-inline'")
                if "'unsafe-eval'"   in val: issues.append("'unsafe-eval'")
                if "default-src *"  in val: issues.append("wildcard default-src")
                if issues:
                    status = "warn"
                    note = f"Weak CSP: contains {', '.join(issues)}"
            elif h["key"] == "x-frame-options":
                if val.upper() not in ("DENY", "SAMEORIGIN"):
                    status = "warn"
                    note = f"Unexpected value: {val} (expected DENY or SAMEORIGIN)"

        checks.append({**h, "value": val, "status": status, "note": note})

    leaking = {k: v for k, v in raw.items()
               if k in ("server", "x-powered-by", "x-aspnet-version",
                        "x-aspnetmvc-version", "x-runtime")}

    return {"checks": checks, "raw": raw, "leaking": leaking}



# ═══════════════════════════════════════════════════════════════════
#  SUBDOMAIN DISCOVERY
# ═══════════════════════════════════════════════════════════════════

COMMON_SUBDOMAINS = [
    "www", "api", "dev", "test", "staging", "admin", "portal", "app", "apps",
    "mail", "webmail", "smtp", "vpn", "remote", "sso", "auth", "login", "cdn",
    "assets", "static", "blog", "shop", "docs", "help", "support", "status",
    "git", "gitlab", "jenkins", "grafana", "prometheus", "kibana", "elastic"
]

async def resolve_host(hostname: str) -> Optional[str]:
    loop = asyncio.get_event_loop()
    try:
        return await loop.run_in_executor(None, socket.gethostbyname, hostname)
    except Exception:
        return None

async def discover_subdomains(domain: str, limit: int = 60) -> dict:
    """Discover subdomains from Certificate Transparency and DNS brute-force fallback."""
    found = {}

    # Certificate Transparency logs via crt.sh
    try:
        async with httpx.AsyncClient(timeout=18.0, verify=False) as client:
            r = await client.get(f"https://crt.sh/?q=%25.{domain}&output=json")
            if r.status_code == 200:
                for row in r.json()[:500]:
                    names = row.get("name_value", "").split("\n")
                    for name in names:
                        name = name.strip().lower().lstrip("*.")
                        if name.endswith("." + domain) and len(found) < limit:
                            found.setdefault(name, {"source": "crt.sh", "ip": None})
    except Exception as e:
        logger.info(f"[subdomains] crt.sh skipped: {e}")

    # DNS discovery for common names, useful if crt.sh is blocked/rate-limited
    candidates = [f"{sub}.{domain}" for sub in COMMON_SUBDOMAINS]
    tasks = [resolve_host(c) for c in candidates]
    answers = await asyncio.gather(*tasks, return_exceptions=True)
    for host, ip in zip(candidates, answers):
        if isinstance(ip, str):
            found.setdefault(host, {"source": "dns", "ip": ip})
            found[host]["ip"] = found[host].get("ip") or ip

    # Resolve CT results, capped for speed
    unresolved = [h for h, v in found.items() if not v.get("ip")][:25]
    ips = await asyncio.gather(*[resolve_host(h) for h in unresolved], return_exceptions=True)
    for h, ip in zip(unresolved, ips):
        if isinstance(ip, str):
            found[h]["ip"] = ip

    results = [
        {"host": host, "ip": data.get("ip"), "source": data.get("source", "unknown")}
        for host, data in sorted(found.items())
    ][:limit]

    return {"items": results, "count": len(results)}


# ═══════════════════════════════════════════════════════════════════
#  SENSITIVE FILES / ENDPOINT DISCOVERY
# ═══════════════════════════════════════════════════════════════════

SENSITIVE_PATHS = [
    {"path": "/.env", "risk": "critical", "desc": "Environment file may expose secrets, tokens or database credentials."},
    {"path": "/.git/config", "risk": "critical", "desc": "Exposed Git metadata can leak source code repository information."},
    {"path": "/.git/HEAD", "risk": "high", "desc": "Exposed Git directory indicator."},
    {"path": "/phpinfo.php", "risk": "high", "desc": "phpinfo page leaks PHP configuration and server details."},
    {"path": "/server-status", "risk": "high", "desc": "Apache status page may expose live server internals."},
    {"path": "/actuator", "risk": "high", "desc": "Spring Boot actuator endpoint may expose operational data."},
    {"path": "/actuator/env", "risk": "critical", "desc": "Spring environment endpoint may expose secrets."},
    {"path": "/swagger", "risk": "medium", "desc": "Swagger UI may expose API structure."},
    {"path": "/swagger-ui.html", "risk": "medium", "desc": "Swagger UI may expose API structure."},
    {"path": "/api-docs", "risk": "medium", "desc": "API documentation endpoint."},
    {"path": "/v3/api-docs", "risk": "medium", "desc": "OpenAPI documentation endpoint."},
    {"path": "/admin", "risk": "medium", "desc": "Public administration path."},
    {"path": "/login", "risk": "low", "desc": "Login page exposed."},
    {"path": "/robots.txt", "risk": "info", "desc": "Robots file may reveal hidden paths."},
    {"path": "/sitemap.xml", "risk": "info", "desc": "Sitemap can help enumerate application URLs."},
    {"path": "/backup.zip", "risk": "critical", "desc": "Backup archive may expose source code or data."},
    {"path": "/backup.tar.gz", "risk": "critical", "desc": "Backup archive may expose source code or data."},
    {"path": "/db.sql", "risk": "critical", "desc": "Database dump may expose sensitive data."},
]

async def check_sensitive_files(domain: str) -> dict:
    findings = []
    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=8.0,
        verify=False,
        headers={"User-Agent": "Mozilla/5.0 (compatible; ScanBs/1.0)"}
    ) as client:
        for scheme in ["https", "http"]:
            # Stop at first scheme that responds at all
            scheme_worked = False
            tasks = []
            for item in SENSITIVE_PATHS:
                url = f"{scheme}://{domain}{item['path']}"
                tasks.append(client.get(url))
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            for item, resp in zip(SENSITIVE_PATHS, responses):
                if isinstance(resp, BaseException):
                    continue
                resp = cast(httpx.Response, resp)
                scheme_worked = True
                status = resp.status_code
                body_sample = resp.text[:500].lower() if resp.text else ""
                content_type = resp.headers.get("content-type", "")
                length = int(resp.headers.get("content-length", "0") or 0) or len(resp.content or b"")
                interesting = status in (200, 206, 301, 302, 401, 403)
                # Avoid false positives from generic SPA 200 pages
                if status == 200 and item["path"] not in ("/admin", "/login", "/robots.txt", "/sitemap.xml"):
                    generic_html = "text/html" in content_type and not any(x in body_sample for x in ["password", "secret", "token", "git", "swagger", "openapi", "php version", "spring"])
                    if generic_html and length < 4000:
                        interesting = False
                if interesting:
                    risk = item["risk"]
                    if status in (401, 403) and risk in ("critical", "high"):
                        risk = "medium"
                    findings.append({
                        "url": str(resp.url),
                        "path": item["path"],
                        "status": status,
                        "risk": risk,
                        "content_type": content_type,
                        "length": length,
                        "description": item["desc"],
                    })
            if scheme_worked:
                break
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda x: (order.get(x["risk"], 9), x["path"]))
    return {"items": findings, "count": len(findings)}


# ═══════════════════════════════════════════════════════════════════
#  SCREENSHOT CAPTURE
# ═══════════════════════════════════════════════════════════════════

async def capture_screenshots(domain: str, scan_id: str, sensitive: dict) -> dict:
    """Capture homepage and selected exposed pages. Gracefully skips if Playwright/Chromium is unavailable."""
    shots = []
    try:
        from playwright.async_api import async_playwright
    except Exception as e:
        return {"items": [], "status": "skipped", "message": f"Playwright not installed: {e}"}

    base_dir = Path(DB_PATH).parent / "screenshots" / scan_id
    base_dir.mkdir(parents=True, exist_ok=True)

    urls = [f"https://{domain}", f"http://{domain}"]
    for f in (sensitive or {}).get("items", [])[:4]:
        if f.get("status") in (200, 401, 403):
            urls.append(f["url"])

    seen = set()
    urls = [u for u in urls if not (u in seen or seen.add(u))][:6]

    try:
        async with async_playwright() as p:
            launch_args = {"headless": True, "args": ["--no-sandbox", "--disable-dev-shm-usage"]}
            chromium_path = os.environ.get("CHROMIUM_PATH", "/usr/bin/chromium")
            if Path(chromium_path).exists():
                launch_args["executable_path"] = chromium_path
            browser = await p.chromium.launch(**launch_args)
            page = await browser.new_page(viewport={"width": 1366, "height": 768})
            for idx, url in enumerate(urls, 1):
                try:
                    await page.goto(url, wait_until="networkidle", timeout=15000)
                    title = await page.title()
                    file_path = base_dir / f"shot_{idx}.png"
                    await page.screenshot(path=str(file_path), full_page=False)
                    shots.append({
                        "url": url,
                        "title": title,
                        "path": str(file_path),
                        "filename": file_path.name,
                        "status": "captured"
                    })
                except Exception as e:
                    shots.append({"url": url, "status": "error", "error": str(e)[:120]})
            await browser.close()
        return {"items": shots, "status": "done", "message": f"{len([s for s in shots if s.get('status')=='captured'])} screenshots captured"}
    except Exception as e:
        return {"items": shots, "status": "error", "message": str(e)[:200]}


# ═══════════════════════════════════════════════════════════════════
#  MITRE ATT&CK MAPPING + ATTACK SURFACE MAP
# ═══════════════════════════════════════════════════════════════════

MITRE_TECHNIQUES = {
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1133": {"name": "External Remote Services", "tactic": "Initial Access"},
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery"},
    "T1210": {"name": "Exploitation of Remote Services", "tactic": "Lateral Movement"},
    "T1552": {"name": "Unsecured Credentials", "tactic": "Credential Access"},
    "T1087": {"name": "Account Discovery", "tactic": "Discovery"},
}

def compute_mitre(ports: list, cves: list, sensitive: dict, subdomains: dict) -> list:
    mapped = {}

    def add(tid: str, evidence: str, severity: str = "medium"):
        info = MITRE_TECHNIQUES[tid]
        if tid not in mapped:
            mapped[tid] = {"id": tid, "name": info["name"], "tactic": info["tactic"], "severity": severity, "evidence": []}
        mapped[tid]["evidence"].append(evidence)
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        if sev_order.get(severity, 0) > sev_order.get(mapped[tid]["severity"], 0):
            mapped[tid]["severity"] = severity

    if ports:
        add("T1046", f"{len([p for p in ports if p.get('state') == 'open'])} open services discovered", "low")

    for p in ports:
        if p.get("state") != "open":
            continue
        port = p.get("port")
        svc = p.get("service", "unknown")
        if port in (22, 3389, 5900, 21, 23):
            add("T1133", f"External remote/auth service exposed: {port}/{svc}", "high")
        if port in (445, 3306, 5432, 6379, 27017, 9200, 2375, 2376):
            add("T1210", f"Remote service exposed and potentially exploitable: {port}/{svc}", "high")

    for c in cves:
        sev = "critical" if c.get("in_cisa_kev") or (c.get("cvss") or 0) >= 9 else "high" if (c.get("cvss") or 0) >= 7 else "medium"
        add("T1190", f"{c.get('id')} on {c.get('product')} CVSS {c.get('cvss') or 'N/A'}", sev)

    for f in (sensitive or {}).get("items", []):
        path = f.get("path", "")
        risk = f.get("risk", "medium")
        if any(x in path for x in [".env", ".git", "db.sql", "backup"]):
            add("T1552", f"Sensitive exposure found: {path} returned HTTP {f.get('status')}", risk)
        elif path in ("/admin", "/login"):
            add("T1087", f"Public authentication/admin surface discovered: {path}", "low")
        else:
            add("T1190", f"Exposed web endpoint: {path} returned HTTP {f.get('status')}", risk)

    if (subdomains or {}).get("items"):
        add("T1046", f"{len(subdomains.get('items', []))} subdomains discovered in external attack surface", "low")

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(mapped.values(), key=lambda x: (order.get(x["severity"], 9), x["id"]))


def build_attack_surface(domain: str, ip: Optional[str], ports: list, techs: list, cves: list, subdomains: dict, sensitive: dict, mitre: list) -> dict:
    nodes = [{"id": domain, "label": domain, "type": "root", "risk": "info"}]
    edges = []
    if ip:
        nodes.append({"id": ip, "label": ip, "type": "ip", "risk": "info"})
        edges.append({"from": domain, "to": ip, "label": "resolves_to"})

    for p in ports[:40]:
        if p.get("state") == "open":
            pid = f"port:{p.get('port')}/{p.get('proto')}"
            nodes.append({"id": pid, "label": f"{p.get('port')}/{p.get('proto')} {p.get('service')}", "type": "port", "risk": "high" if p.get("risky") else "low"})
            edges.append({"from": ip or domain, "to": pid, "label": "exposes"})

    for s in (subdomains or {}).get("items", [])[:30]:
        sid = s["host"]
        nodes.append({"id": sid, "label": sid, "type": "subdomain", "risk": "low"})
        edges.append({"from": domain, "to": sid, "label": "subdomain"})

    for t in techs[:25]:
        tid = f"tech:{t.get('name')}"
        nodes.append({"id": tid, "label": f"{t.get('name')} {t.get('version') if t.get('version')!='detected' else ''}".strip(), "type": "technology", "risk": "medium" if t.get("cpe") else "info"})
        edges.append({"from": domain, "to": tid, "label": "runs"})

    for f in (sensitive or {}).get("items", [])[:20]:
        fid = f"file:{f.get('path')}"
        nodes.append({"id": fid, "label": f.get("path"), "type": "exposure", "risk": f.get("risk", "medium")})
        edges.append({"from": domain, "to": fid, "label": "exposes"})

    return {
        "summary": {
            "subdomains": len((subdomains or {}).get("items", [])),
            "open_ports": len([p for p in ports if p.get("state") == "open"]),
            "technologies": len(techs),
            "cves": len(cves),
            "sensitive_findings": len((sensitive or {}).get("items", [])),
            "mitre_techniques": len(mitre),
        },
        "nodes": nodes,
        "edges": edges,
    }


# ═══════════════════════════════════════════════════════════════════
#  PDF REPORT
# ═══════════════════════════════════════════════════════════════════

def generate_pdf_report(scan_id: str, data: dict) -> Optional[str]:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
        from reportlab.lib import colors
    except Exception as e:
        logger.warning(f"[pdf] reportlab unavailable: {e}")
        return None

    report_dir = Path(DB_PATH).parent / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    file_path = report_dir / f"scanbs_report_{scan_id}.pdf"
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(file_path), pagesize=A4, rightMargin=1.4*cm, leftMargin=1.4*cm, topMargin=1.2*cm, bottomMargin=1.2*cm)
    story = []

    def add_title(text):
        story.append(Paragraph(text, styles["Heading2"])); story.append(Spacer(1, 0.2*cm))
    def add_p(text):
        story.append(Paragraph(str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"), styles["BodyText"])); story.append(Spacer(1, 0.15*cm))

    story.append(Paragraph("ScanBs Web Security Report", styles["Title"]))
    add_p(f"Target: {data.get('domain')} | IP: {data.get('ip') or 'N/A'} | Finished: {data.get('finished_at')}")
    risk = data.get("risk", {})
    add_p(f"Overall Risk: {risk.get('score', 'N/A')}/100 — {risk.get('label', 'N/A')}")

    surface = data.get("attack_surface", {}).get("summary", {})
    add_title("Executive Summary")
    rows = [["Metric", "Value"]] + [[k.replace("_", " ").title(), str(v)] for k, v in surface.items()]
    table = Table(rows, hAlign="LEFT", colWidths=[8*cm, 6*cm])
    table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1f2937")), ("TEXTCOLOR", (0,0), (-1,0), colors.white), ("GRID", (0,0), (-1,-1), 0.25, colors.grey)]))
    story.append(table); story.append(Spacer(1, 0.4*cm))

    add_title("Open Ports")
    ports = [[str(p.get("port")), p.get("proto", ""), p.get("service", ""), "Risky" if p.get("risky") else "Normal"] for p in data.get("ports", [])[:25]]
    story.append(Table([["Port", "Proto", "Service", "Risk"]] + (ports or [["-", "-", "No open ports", "-"]]), hAlign="LEFT")); story.append(Spacer(1, 0.35*cm))

    add_title("Sensitive Files / Endpoints")
    sens = data.get("sensitive_files", {}).get("items", [])
    story.append(Table([["Path", "HTTP", "Risk"]] + [[f.get("path"), str(f.get("status")), f.get("risk")] for f in sens[:20]] or [["-", "-", "None"]], hAlign="LEFT")); story.append(Spacer(1, 0.35*cm))

    add_title("Critical CVEs")
    critical = [c for c in data.get("cves", []) if c.get("in_cisa_kev") or (c.get("cvss") or 0) >= 7][:15]
    if critical:
        for c in critical:
            add_p(f"{c.get('id')} — {c.get('product')} — CVSS {c.get('cvss') or 'N/A'} — {c.get('severity')}")
    else:
        add_p("No high or critical CVEs found from detected technologies.")

    add_title("MITRE ATT&CK Mapping")
    for m in data.get("mitre", [])[:15]:
        add_p(f"{m.get('id')} — {m.get('name')} ({m.get('tactic')}) — {m.get('severity')}: {'; '.join(m.get('evidence', [])[:2])}")

    add_title("Screenshots")
    for shot in data.get("screenshots", {}).get("items", [])[:4]:
        if shot.get("status") == "captured" and shot.get("path") and Path(shot["path"]).exists():
            add_p(shot.get("url"))
            try:
                story.append(Image(shot["path"], width=15*cm, height=8.4*cm)); story.append(Spacer(1, 0.25*cm))
            except Exception:
                pass

    doc.build(story)
    return str(file_path)

# ═══════════════════════════════════════════════════════════════════
#  RISK SCORE
# ═══════════════════════════════════════════════════════════════════

def compute_risk(ports: list, cves: list, header_checks: list, sensitive_files: Optional[dict] = None, subdomains: Optional[dict] = None) -> dict:
    """
    Professional weighted risk engine.

    Goal: avoid unrealistic 100/100 scores caused by simply adding every CVE
    and every missing header. Each category has a cap, and CVE confidence is
    used to reduce false positives.

    Categories:
      - Vulnerability Intelligence: max 45
      - Network Exposure:          max 25
      - Sensitive Exposures:       max 35
      - Header Hardening:          max 15
      - Attack Surface Size:       max 8
    """
    findings: list[str] = []
    recommendations: list[str] = []
    breakdown = {
        "vulnerabilities": 0,
        "network_exposure": 0,
        "sensitive_exposure": 0,
        "headers": 0,
        "attack_surface": 0,
    }

    # ── 1) Vulnerability intelligence, capped ─────────────────────────────
    # Only recent CVEs are already returned by the CVE engine. Here we weight
    # them by exploitability and confidence instead of counting all equally.
    cve_points = 0.0
    kev_count = 0
    critical_count = 0
    low_conf_ignored = 0

    confidence_weight = {"high": 1.0, "medium": 0.65, "low": 0.35}

    for c in cves:
        cvss = c.get("cvss") or 0
        epss = c.get("epss") or 0
        conf = str(c.get("confidence", "low")).lower()
        weight = confidence_weight.get(conf, 0.35)

        # CVSS base contribution.
        if cvss >= 9:
            pts = 12
            critical_count += 1
        elif cvss >= 7:
            pts = 8
        elif cvss >= 4:
            pts = 4
        else:
            pts = 1.5

        # Exploitability enrichments.
        if c.get("in_cisa_kev"):
            pts += 18
            kev_count += 1
        if epss >= 90:
            pts += 8
        elif epss >= 50:
            pts += 4

        # Reduce keyword-only / uncertain matches.
        pts *= weight

        # Very low confidence, non-critical results should not dominate risk.
        if conf == "low" and not c.get("in_cisa_kev") and cvss < 9:
            low_conf_ignored += 1
            pts = min(pts, 2)

        cve_points += pts

    breakdown["vulnerabilities"] = min(round(cve_points), 45)

    if kev_count:
        findings.append(f"{kev_count} CVE(s) are listed in CISA KEV, meaning exploitation is confirmed in the wild")
        recommendations.append("Prioritize remediation of CISA KEV vulnerabilities before all other CVEs.")
    if critical_count:
        findings.append(f"{critical_count} recent critical CVE(s) detected on identified technologies")
        recommendations.append("Upgrade affected components to vendor-supported fixed versions.")
    if low_conf_ignored:
        findings.append(f"{low_conf_ignored} low-confidence CVE match(es) were down-weighted to reduce false positives")

    # ── 2) Network exposure, capped ───────────────────────────────────────
    network_points = 0
    risky_ports = {21, 23, 445, 3306, 3389, 5432, 6379, 27017, 2375, 2376, 4243, 9200, 5601}
    auth_remote_ports = {22, 3389, 5900}
    open_ports = [p for p in ports if p.get("state") == "open"]

    for p in open_ports:
        port = int(p.get("port") or 0)
        service = str(p.get("service", "unknown"))
        if port in risky_ports:
            pts = 10 if port in (6379, 27017, 2375, 2376, 4243, 9200, 5601) else 7
            network_points += pts
            findings.append(f"Sensitive service exposed: {port}/{service}")
            recommendations.append(f"Restrict access to {port}/{service} using firewall rules, VPN or IP allowlisting.")
        elif port in auth_remote_ports:
            network_points += 5
            findings.append(f"Remote administration/authentication service exposed: {port}/{service}")
            recommendations.append(f"Harden {port}/{service}: disable password login where possible, enforce MFA/VPN and monitor brute-force attempts.")

    # Many open ports increase exposure but should not alone make risk critical.
    if len(open_ports) >= 20:
        network_points += 8
    elif len(open_ports) >= 10:
        network_points += 5
    elif len(open_ports) >= 5:
        network_points += 2

    breakdown["network_exposure"] = min(network_points, 25)

    # ── 3) Sensitive files / exposed paths, capped ────────────────────────
    exposure_points = 0
    for f in (sensitive_files or {}).get("items", []):
        risk = str(f.get("risk", "medium")).lower()
        path = f.get("path", "")
        if risk == "critical":
            exposure_points += 25
            findings.append(f"Critical sensitive exposure: {path}")
            recommendations.append(f"Immediately remove or protect {path}; verify that no credentials or source code were exposed.")
        elif risk == "high":
            exposure_points += 15
            findings.append(f"High-risk exposed endpoint: {path}")
            recommendations.append(f"Restrict or remove public access to {path}.")
        elif risk == "medium":
            exposure_points += 6
        elif risk == "low":
            exposure_points += 2

    breakdown["sensitive_exposure"] = min(exposure_points, 35)

    # ── 4) Security headers, capped ───────────────────────────────────────
    # Missing headers are important hardening issues, but should not by
    # themselves force a Critical rating.
    header_points = 0
    missing_critical = []
    for h in header_checks:
        status = h.get("status")
        name = h.get("name", "")
        critical = bool(h.get("critical"))
        if status == "fail":
            header_points += 3 if critical else 1
            if critical:
                missing_critical.append(name)
        elif status == "warn":
            header_points += 1

    breakdown["headers"] = min(header_points, 15)
    if missing_critical:
        findings.append(f"Missing important security headers: {', '.join(missing_critical[:4])}")
        recommendations.append("Add a hardened HTTP security header baseline: CSP, HSTS, X-Frame-Options, X-Content-Type-Options and Referrer-Policy.")

    # ── 5) Attack surface size, capped ────────────────────────────────────
    sub_count = len((subdomains or {}).get("items", []))
    surface_points = 0
    if sub_count >= 50:
        surface_points = 8
        findings.append(f"Large external attack surface: {sub_count} subdomains discovered")
        recommendations.append("Review discovered subdomains and decommission unused or forgotten assets.")
    elif sub_count >= 20:
        surface_points = 5
    elif sub_count >= 5:
        surface_points = 2

    breakdown["attack_surface"] = surface_points

    raw_score = sum(breakdown.values())
    score = min(int(round(raw_score)), 100)

    if score >= 81:
        label = "Critical"
    elif score >= 61:
        label = "High"
    elif score >= 41:
        label = "Medium"
    elif score >= 21:
        label = "Low"
    else:
        label = "Informational"

    # Keep recommendations clean and unique.
    seen_rec = set()
    unique_recs = []
    for r in recommendations:
        if r not in seen_rec:
            seen_rec.add(r)
            unique_recs.append(r)

    return {
        "score": score,
        "label": label,
        "findings": findings[:10],
        "recommendations": unique_recs[:10],
        "breakdown": breakdown,
        "model": "weighted_capped_v2",
        "thresholds": {
            "informational": "0-20",
            "low": "21-40",
            "medium": "41-60",
            "high": "61-80",
            "critical": "81-100",
        },
    }


# ═══════════════════════════════════════════════════════════════════
#  SCAN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════

async def run_nmap(ip: str) -> list:
    """Run nmap TCP + UDP scan and return parsed open ports."""
    import subprocess

    all_ports = []
    loop = asyncio.get_event_loop()

    # TCP scan — top 1000 ports + version + NSE scripts
    tcp_cmd = [
        "nmap", "-sS", "-sV", "--version-intensity", "5",
        "--script", "banner,http-title,ssh-hostkey,ftp-anon,smtp-commands",
        "-T4", "--open", "-oX", "-",
        "--host-timeout", "120s", ip
    ]
    try:
        tcp = await loop.run_in_executor(
            None, lambda: subprocess.run(tcp_cmd, capture_output=True, text=True, timeout=150)
        )
        if tcp.stdout:
            tcp_ports = parse_nmap_xml(tcp.stdout)
            all_ports.extend(tcp_ports)
            logger.info(f"[nmap TCP] Found {len(tcp_ports)} open TCP ports on {ip}")
        else:
            logger.warning(f"[nmap TCP] No output for {ip}")
    except Exception as e:
        logger.error(f"[nmap TCP] Error: {e}")

    # UDP scan — common ports only
    udp_cmd = [
        "nmap", "-sU", "-sV", "--version-intensity", "3",
        "-p", "53,67,68,69,123,137,138,161,162,500,514,1194,1900,4500,5353",
        "--open", "-oX", "-", "-T4", "--host-timeout", "60s", ip
    ]
    try:
        udp = await loop.run_in_executor(
            None, lambda: subprocess.run(udp_cmd, capture_output=True, text=True, timeout=90)
        )
        if udp.stdout:
            udp_ports = parse_nmap_xml(udp.stdout)
            all_ports.extend(udp_ports)
            logger.info(f"[nmap UDP] Found {len(udp_ports)} open UDP ports on {ip}")
        else:
            logger.warning(f"[nmap UDP] No output for {ip}")
    except Exception as e:
        logger.error(f"[nmap UDP] Error: {e}")

    return all_ports


async def run_scan(scan_id: str, domain: str, nmap_xml: Optional[str] = None):
    scans[scan_id]["status"] = "running"
    result = {
        "scan_id": scan_id,
        "domain": domain,
        "started_at": datetime.utcnow().isoformat(),
        "phases": {
            "ports":       {"status": "pending", "message": ""},
            "tech":        {"status": "pending", "message": ""},
            "cves":        {"status": "pending", "message": ""},
            "mitigations": {"status": "pending", "message": ""},
            "headers":     {"status": "pending", "message": ""},
            "subdomains":  {"status": "pending", "message": ""},
            "sensitive":   {"status": "pending", "message": ""},
            "screenshots": {"status": "pending", "message": ""},
            "report":      {"status": "pending", "message": ""},
        },
        "ip": None,
        "ports": [],
        "technologies": [],
        "raw_headers": {},
        "leaking_headers": {},
        "cves": [],
        "headers": {},
        "subdomains": {"items": [], "count": 0},
        "sensitive_files": {"items": [], "count": 0},
        "screenshots": {"items": [], "status": "pending", "message": ""},
        "mitre": [],
        "attack_surface": {},
        "pdf_report": None,
        "risk": {},
        "finished_at": None,
        "error": None,
    }
    scans[scan_id]["data"] = result

    try:
        # ── Phase 1: nmap TCP + UDP scan ──────────────────────────
        result["phases"]["ports"] = {
            "status": "running",
            "message": f"nmap scanning {domain} (TCP + UDP)..."
        }
        scans[scan_id]["data"] = result
        logger.info(f"[scan] Starting nmap on {domain} (scan_id={scan_id})")

        try:
            ip = socket.gethostbyname(domain)
            result["ip"] = ip

            # Use provided XML or run nmap automatically
            if nmap_xml:
                ports = parse_nmap_xml(nmap_xml)
            else:
                ports = await run_nmap(ip)

            result["ports"] = ports
            tcp_count = len([p for p in ports if p["proto"] == "TCP"])
            udp_count = len([p for p in ports if p["proto"] == "UDP"])
            result["phases"]["ports"] = {
                "status":  "done",
                "message": f"{len(ports)} open ports ({tcp_count} TCP, {udp_count} UDP)"
            }
        except Exception as e:
            result["phases"]["ports"] = {"status": "error", "message": str(e)}

        scans[scan_id]["data"] = result

        # ── Phase 2: Tech detection ───────────────────────────────
        result["phases"]["tech"] = {"status": "running", "message": "Fingerprinting technologies…"}
        scans[scan_id]["data"] = result

        tech_data = await detect_tech(domain)
        result["technologies"] = tech_data["techs"]
        result["raw_headers"]  = tech_data["raw_headers"]
        result["leaking_headers"] = tech_data["leaking_headers"]

        result["phases"]["tech"] = {
            "status": "done",
            "message": f"{len(result['technologies'])} technologies detected"
        }
        scans[scan_id]["data"] = result

        # ── Phase 3: CVE lookup ───────────────────────────────────
        result["phases"]["cves"] = {"status": "running", "message": "Querying NVD + EPSS + CISA KEV…"}
        scans[scan_id]["data"] = result

        result["cves"] = await lookup_cves(result["technologies"], result["ports"])

        crit = sum(1 for c in result["cves"] if c.get("in_cisa_kev") or (c.get("cvss") or 0) >= 9)
        result["phases"]["cves"] = {
            "status": "done",
            "message": f"{len(result['cves'])} CVEs found ({crit} critical)"
        }
        scans[scan_id]["data"] = result

        # ── Phase 3b: LLM Mitigations (Ollama local) ─────────────
        result["phases"]["mitigations"] = {
            "status": "running",
            "message": "Generating mitigations with local LLM (Qwen2.5)…"
        }
        scans[scan_id]["data"] = result

        result["cves"] = await enrich_cves_with_mitigations(result["cves"])

        mitig_count = sum(1 for c in result["cves"] if c.get("mitigation"))
        result["phases"]["mitigations"] = {
            "status": "done",
            "message": f"{mitig_count} mitigations generated"
        }
        scans[scan_id]["data"] = result

        # ── Phase 4: Header analysis ──────────────────────────────
        result["phases"]["headers"] = {"status": "running", "message": "Auditing security headers…"}
        scans[scan_id]["data"] = result

        result["headers"] = await analyze_headers(domain)

        issues = sum(1 for h in result["headers"]["checks"] if h["status"] != "pass")
        result["phases"]["headers"] = {
            "status": "done",
            "message": f"{issues} header issues"
        }
        scans[scan_id]["data"] = result

        # ── Phase 5: Subdomain discovery ──────────────────────────
        result["phases"]["subdomains"] = {"status": "running", "message": "Discovering subdomains…"}
        scans[scan_id]["data"] = result
        result["subdomains"] = await discover_subdomains(domain)
        result["phases"]["subdomains"] = {"status": "done", "message": f"{result['subdomains']['count']} subdomains found"}
        scans[scan_id]["data"] = result

        # ── Phase 6: Sensitive files discovery ────────────────────
        result["phases"]["sensitive"] = {"status": "running", "message": "Checking sensitive files and exposed endpoints…"}
        scans[scan_id]["data"] = result
        result["sensitive_files"] = await check_sensitive_files(domain)
        result["phases"]["sensitive"] = {"status": "done", "message": f"{result['sensitive_files']['count']} exposed paths found"}
        scans[scan_id]["data"] = result

        # ── Phase 7: MITRE + Attack Surface Map ───────────────────
        result["mitre"] = compute_mitre(result["ports"], result["cves"], result["sensitive_files"], result["subdomains"])
        result["attack_surface"] = build_attack_surface(domain, result.get("ip"), result["ports"], result["technologies"], result["cves"], result["subdomains"], result["sensitive_files"], result["mitre"])

        # ── Risk score ────────────────────────────────────────────
        result["risk"] = compute_risk(
            result["ports"],
            result["cves"],
            result["headers"]["checks"],
            result["sensitive_files"],
            result["subdomains"]
        )

        # ── Phase 8: Screenshot capture ───────────────────────────
        result["phases"]["screenshots"] = {"status": "running", "message": "Capturing screenshots…"}
        scans[scan_id]["data"] = result
        result["screenshots"] = await capture_screenshots(domain, scan_id, result["sensitive_files"])
        result["phases"]["screenshots"] = {"status": result["screenshots"].get("status", "done"), "message": result["screenshots"].get("message", "Screenshots processed")}
        scans[scan_id]["data"] = result

        # ── Phase 9: PDF report ───────────────────────────────────
        result["phases"]["report"] = {"status": "running", "message": "Generating PDF report…"}
        result["pdf_report"] = generate_pdf_report(scan_id, result)
        result["phases"]["report"] = {"status": "done" if result["pdf_report"] else "skipped", "message": "PDF report generated" if result["pdf_report"] else "PDF report skipped; reportlab unavailable"}

        result["finished_at"] = datetime.utcnow().isoformat()
        scans[scan_id] = {"status": "done", "data": result}

        # ── Save to SQLite history ────────────────────────────────
        db_save(scan_id, result)

    except Exception as e:
        result["error"] = str(e)
        result["finished_at"] = datetime.utcnow().isoformat()
        scans[scan_id] = {"status": "error", "data": result}


# ═══════════════════════════════════════════════════════════════════
#  API ROUTES
# ═══════════════════════════════════════════════════════════════════

@app.post("/api/scan")
async def start_scan(req: ScanRequest, bg: BackgroundTasks):
    domain = (req.domain.strip()
              .lower()
              .removeprefix("https://")
              .removeprefix("http://")
              .split("/")[0])

    if not re.match(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$", domain):
        raise HTTPException(400, f"Invalid domain: {domain}")

    scan_id = str(uuid.uuid4())
    scans[scan_id] = {"status": "queued", "data": None}
    bg.add_task(run_scan, scan_id, domain)

    return {"scan_id": scan_id, "domain": domain, "status": "queued"}


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(404, "Scan not found")
    return scans[scan_id]


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/api/history")
async def get_history():
    """Return list of all past scans from SQLite."""
    return {"scans": db_list()}


@app.get("/api/history/{scan_id}")
async def get_history_scan(scan_id: str):
    """Return full result of a past scan from SQLite."""
    data = db_get(scan_id)
    if not data:
        raise HTTPException(404, "Scan not found in history")
    return {"status": "done", "data": data}


@app.delete("/api/history/{scan_id}")
async def delete_history_scan(scan_id: str):
    """Delete a scan from history."""
    db_delete(scan_id)
    return {"deleted": scan_id}

@app.get("/api/report/{scan_id}")
async def download_report(scan_id: str):
    data = scans.get(scan_id, {}).get("data") or db_get(scan_id)
    if not data:
        raise HTTPException(404, "Scan not found")
    path = data.get("pdf_report") or generate_pdf_report(scan_id, data)
    if not path or not Path(path).exists():
        raise HTTPException(404, "PDF report not available")
    return FileResponse(path, media_type="application/pdf", filename=f"scanbs_report_{data.get('domain','target')}.pdf")


@app.get("/")
async def root():
    return {
        "name": "ScanBs API",
        "docs": "/docs",
        "endpoints": [
            "POST /api/scan         — start a scan",
            "GET  /api/scan/{id}    — poll results",
            "GET  /api/history      — scan history",
            "GET  /api/history/{id} — full past scan",
            "GET  /api/report/{id}  — download PDF report",
            "DELETE /api/history/{id} — delete from history",
            "GET  /api/health       — health check"
        ]
    }
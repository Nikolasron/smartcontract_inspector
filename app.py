
import os
import re
import json
import hmac
from datetime import datetime, timezone

import requests
from flask import Flask, jsonify, render_template, request
from upstash_redis import Redis

app = Flask(__name__)

# Configuration
TRONSCAN_URL = "https://apilist.tronscanapi.com"
TRONSCAN_API_KEY = os.getenv("TRONSCAN_API_KEY", "")
CRON_SECRET = os.getenv("CRON_SECRET", "")

BATCH_SIZE = 5
MAX_TRONSCAN_INDEX = 10000
MAX_SAVED_REPORTS = 500

REDIS_URL = os.getenv("UPSTASH_REDIS_REST_URL")
REDIS_TOKEN = os.getenv("UPSTASH_REDIS_REST_TOKEN")

redis = None
if REDIS_URL and REDIS_TOKEN:
    redis = Redis(url=REDIS_URL, token=REDIS_TOKEN)

session = requests.Session()
session.headers.update({
    "Accept": "application/json",
    "User-Agent": "TRON-Contract-Intelligence/1.0"
})

if TRONSCAN_API_KEY:
    session.headers["TRON-PRO-API-KEY"] = TRONSCAN_API_KEY


# Database helpers
def database_ready():
    return redis is not None


def save_value(key, value):
    redis.set(key, json.dumps(value))


def read_value(key, default=None):
    value = redis.get(key)

    if value is None:
        return default

    if isinstance(value, (dict, list)):
        return value

    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default


def save_report(report):
    address = report["address"]
    save_value("tron:report:" + address, report)

    addresses = read_value("tron:report_addresses", [])

    if address in addresses:
        addresses.remove(address)

    addresses.insert(0, address)
    save_value(
        "tron:report_addresses",
        addresses[:MAX_SAVED_REPORTS]
    )


def get_saved_reports():
    addresses = read_value("tron:report_addresses", [])
    reports = []

    for address in addresses:
        report = read_value("tron:report:" + address)
        if report:
            reports.append(report)

    return reports


# Discover verified contracts
def fetch_verified_contracts(start=0, limit=BATCH_SIZE):
    if not TRONSCAN_API_KEY:
        raise RuntimeError("TRONSCAN_API_KEY is not configured.")

    start = max(0, min(int(start), MAX_TRONSCAN_INDEX - 1))
    limit = max(1, min(int(limit), 10))

    response = session.get(
        TRONSCAN_URL + "/api/contracts",
        params={
            "start": start,
            "limit": limit,
            "sort": "-timestamp",
            "verified-only": "true",
            "open-source-only": "true"
        },
        timeout=15
    )

    response.raise_for_status()
    payload = response.json()

    contracts = payload.get("data", [])

    if not isinstance(contracts, list):
        raise RuntimeError("Unexpected TRONSCAN response.")

    return contracts, payload


# Extract actual Solidity source only
def extract_source(value, depth=0):
    if depth > 8:
        return None

    source_keys = {
        "sourcecode",
        "source_code",
        "contract_source",
        "source",
        "soliditysource",
        "solidity_source"
    }

    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in source_keys:
                result = extract_source(item, depth + 1)
                if result:
                    return result

        for item in value.values():
            result = extract_source(item, depth + 1)
            if result:
                return result

    elif isinstance(value, list):
        for item in value:
            result = extract_source(item, depth + 1)
            if result:
                return result

    elif isinstance(value, str):
        text = value.strip()

        if (
            "pragma solidity" in text
            or "contract " in text
            or "interface " in text
            or "library " in text
        ):
            return text

    return None


def fetch_contract_source(address):
    endpoints = [
        "/api/contract",
        "/api/contracts/code"
    ]

    for endpoint in endpoints:
        try:
            response = session.get(
                TRONSCAN_URL + endpoint,
                params={"contract": address},
                timeout=15
            )

            response.raise_for_status()
            payload = response.json()

            source = extract_source(payload)

            if source:
                return source

        except (requests.RequestException, ValueError):
            continue

    return None


# Solidity security checks
def analyze_solidity(source):
    findings = []

    checks = [
        (
            "REENTRANCY_REVIEW",
            r"\.call\s*\{[^}]*value\s*:",
            "External value call detected. Review reentrancy protection.",
            "HIGH"
        ),
        (
            "DELEGATECALL",
            r"\.delegatecall\s*\(",
            "delegatecall detected. Review target control and storage compatibility.",
            "HIGH"
        ),
        (
            "TX_ORIGIN",
            r"\btx\.origin\b",
            "tx.origin detected. Review authorization logic.",
            "MEDIUM"
        ),
        (
            "SELFDESTRUCT",
            r"\bselfdestruct\s*\(",
            "Self-destruct operation detected. Review access restrictions.",
            "HIGH"
        ),
        (
            "LOW_LEVEL_CALL",
            r"\.call\s*\(",
            "Low-level call detected. Review return-value handling.",
            "MEDIUM"
        ),
        (
            "ASSEMBLY",
            r"\bassembly\b",
            "Inline assembly detected. Manual review is recommended.",
            "MEDIUM"
        ),
        (
            "UNCHECKED_BLOCK",
            r"\bunchecked\s*\{",
            "Unchecked arithmetic block detected. Review overflow risks.",
            "MEDIUM"
        )
    ]

    for code, pattern, message, severity in checks:
        if re.search(pattern, source, re.IGNORECASE):
            findings.append({
                "code": code,
                "severity": severity,
                "message": message
            })

    sensitive_functions = re.findall(
        r"function\s+([A-Za-z0-9_]+)\s*\([^)]*\)[^{;]*",
        source,
        re.IGNORECASE
    )

    for function_name in sensitive_functions:
        if re.search(
            r"(withdraw|transfer|mint|burn|pause|owner|admin|upgrade|rescue)",
            function_name,
            re.IGNORECASE
        ):
            declaration = re.search(
                r"function\s+" + re.escape(function_name) +
                r"\s*\([^)]*\)[^{;]*",
                source,
                re.IGNORECASE
            )

            if declaration:
                signature = declaration.group(0)

                if not re.search(
                    r"\b(onlyOwner|onlyRole|onlyAdmin|private|internal)\b",
                    signature,
                    re.IGNORECASE
                ):
                    findings.append({
                        "code": "ACCESS_CONTROL_REVIEW",
                        "severity": "MEDIUM",
                        "message": (
                            "Sensitive function '" + function_name +
                            "' has no obvious access modifier. "
                            "Review its authorization logic."
                        )
                    })

    if re.search(r"pragma\s+solidity\s+\^?0\.[0-7]\.", source):
        findings.append({
            "code": "OLD_SOLIDITY_VERSION",
            "severity": "LOW",
            "message": "Older Solidity compiler version detected."
        })

    return findings


def determine_risk(findings):
    if not findings:
        return "NO_FLAGS_FOUND"

    severities = [item["severity"] for item in findings]

    if "HIGH" in severities:
        return "HIGH"

    if "MEDIUM" in severities:
        return "MEDIUM"

    return "LOW"


# Scan one contract
def scan_contract(contract):
    address = (
        contract.get("address")
        or contract.get("contractAddress")
        or contract.get("contract_address")
    )

    if not address:
        return None

    source = fetch_contract_source(address)

    report = {
        "address": address,
        "name": contract.get("name") or contract.get("contractName") or "Unknown",
        "verified": True,
        "source_available": bool(source),
        "status": "ANALYZED" if source else "SOURCE_UNAVAILABLE",
        "risk": "UNASSESSED",
        "findings": [],
        "source_code": source or None,
        "explorer_url": "https://tronscan.org/#/contract/" + address,
        "scanned_at": datetime.now(timezone.utc).isoformat()
    }

    if source:
        report["findings"] = analyze_solidity(source)
        report["risk"] = determine_risk(report["findings"])

    save_report(report)
    return report


# Scan a small batch
def scan_batch(start, limit=BATCH_SIZE):
    contracts, metadata = fetch_verified_contracts(start, limit)
    reports = []

    for contract in contracts:
        try:
            report = scan_contract(contract)

            if report:
                reports.append(report)

        except Exception as error:
            address = (
                contract.get("address")
                or contract.get("contractAddress")
                or "unknown"
            )

            reports.append({
                "address": address,
                "status": "SCAN_ERROR",
                "risk": "UNASSESSED",
                "error": str(error),
                "scanned_at": datetime.now(timezone.utc).isoformat()
            })

    next_start = start + len(contracts)

    if next_start >= MAX_TRONSCAN_INDEX or not contracts:
        next_start = 0

    return {
        "reports": reports,
        "start": start,
        "next_start": next_start,
        "contracts_returned": len(contracts),
        "total_available": metadata.get("total", 0)
    }


# Dashboard
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/status")
def api_status():
    if not database_ready():
        return jsonify({
            "ok": False,
            "error": "Database is not configured."
        }), 503

    reports = get_saved_reports()

    return jsonify({
        "ok": True,
        "saved_reports": len(reports),
        "cursor": read_value("tron:cursor", 0),
        "last_cron_run": read_value("tron:last_cron_run"),
        "database": "connected"
    })


@app.route("/api/reports")
def api_reports():
    if not database_ready():
        return jsonify({"error": "Database is not configured."}), 503

    reports = get_saved_reports()

    return jsonify({
        "ok": True,
        "count": len(reports),
        "reports": reports
    })


@app.route("/api/report/<address>")
def api_report(address):
    if not database_ready():
        return jsonify({"error": "Database is not configured."}), 503

    report = read_value("tron:report:" + address)

    if not report:
        return jsonify({"error": "Report not found."}), 404

    return jsonify(report)


# Protected scheduled scanner
@app.route("/api/cron", methods=["GET", "POST"])
def cron_scan():
    if not CRON_SECRET:
        return jsonify({
            "ok": False,
            "error": "CRON_SECRET is not configured."
        }), 503

    auth_header = request.headers.get("Authorization", "")
    expected = "Bearer " + CRON_SECRET

    if not hmac.compare_digest(auth_header, expected):
        return jsonify({"error": "Unauthorized"}), 401

    if not database_ready():
        return jsonify({
            "ok": False,
            "error": "Upstash database is not configured."
        }), 503

    try:
        cursor = int(read_value("tron:cursor", 0))
        result = scan_batch(cursor, BATCH_SIZE)

        save_value("tron:cursor", result["next_start"])
        save_value(
            "tron:last_cron_run",
            datetime.now(timezone.utc).isoformat()
        )

        return jsonify({
            "ok": True,
            "message": "Scheduled scan completed.",
            "start": result["start"],
            "next_start": result["next_start"],
            "scanned": len(result["reports"]),
            "reports": result["reports"]
        })

    except Exception as error:
        return jsonify({
            "ok": False,
            "error": str(error)
        }), 500


# Optional manual batch endpoint
@app.route("/api/scan")
def api_scan():
    if not database_ready():
        return jsonify({"error": "Database is not configured."}), 503

    try:
        start = int(request.args.get("start", 0))
        limit = int(request.args.get("limit", BATCH_SIZE))

        if start < 0 or start >= MAX_TRONSCAN_INDEX:
            return jsonify({"error": "Invalid start position."}), 400

        if limit < 1 or limit > 10:
            return jsonify({"error": "Limit must be between 1 and 10."}), 400

        result = scan_batch(start, limit)

        return jsonify({
            "ok": True,
            **result
        })

    except Exception as error:
        return jsonify({
            "ok": False,
            "error": str(error)
        }), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

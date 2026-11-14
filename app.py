
import os
import re
import time
import requests

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

TRONSCAN_URL = "https://apilist.tronscanapi.com"
API_KEY = os.getenv("TRONSCAN_API_KEY", "")

SESSION = requests.Session()
SESSION.headers.update({
    "Accept": "application/json",
    "User-Agent": "TRON-Contract-Intelligence/1.0"
})

if API_KEY:
    SESSION.headers["TRON-PRO-API-KEY"] = API_KEY

MAX_LIMIT = 10
MAX_START = 9990
REQUEST_TIMEOUT = 15


def tronscan_get(path, params):
    response = SESSION.get(
        TRONSCAN_URL + path,
        params=params,
        timeout=REQUEST_TIMEOUT
    )
    response.raise_for_status()
    return response.json()


def fetch_verified_contracts(start=0, limit=10):
    start = max(0, min(int(start), MAX_START))
    limit = max(1, min(int(limit), MAX_LIMIT))

    data = tronscan_get(
        "/api/contracts",
        {
            "start": start,
            "limit": limit,
            "sort": "-timestamp",
            "verified-only": "true",
            "open-source-only": "true"
        }
    )

    contracts = data.get("data", [])

    # Only fully verified contracts are accepted.
    contracts = [
        item for item in contracts
        if item.get("verify_status") == 2
        and item.get("address")
    ]

    return {
        "contracts": contracts,
        "total": data.get("rangeTotal", data.get("total", 0)),
        "next_start": start + limit
    }


def find_source_fields(obj, depth=0):
    """Find source-code fields in returned API objects."""

    if depth > 5:
        return None

    if isinstance(obj, dict):
        for key in (
            "sourceCode",
            "source_code",
            "source",
            "contractCode",
            "contract_code"
        ):
            value = obj.get(key)

            if isinstance(value, str) and (
                "pragma solidity" in value
                or "contract " in value
                or "interface " in value
                or "library " in value
            ):
                return value

        for value in obj.values():
            result = find_source_fields(value, depth + 1)
            if result:
                return result

    elif isinstance(obj, list):
        for value in obj:
            result = find_source_fields(value, depth + 1)
            if result:
                return result

    return None


def fetch_contract_source(address):
    """
    Try documented TRONSCAN contract detail/code endpoints.
    Do not treat bytecode or ABI as Solidity source.
    """

    endpoints = [
        ("/api/contract", {"contract": address}),
        ("/api/contracts/code", {"contract": address})
    ]

    for path, params in endpoints:
        try:
            result = tronscan_get(path, params)
            source = find_source_fields(result)

            if source:
                return source

        except requests.RequestException:
            continue

    return None


def add_finding(findings, severity, title, description):
    findings.append({
        "severity": severity,
        "title": title,
        "description": description
    })


def analyze_solidity(source):
    findings = []

    # Reentrancy-related patterns
    if re.search(r'\.call\s*\{[^}]*value\s*:', source):
        add_finding(
            findings,
            "HIGH",
            "External value call",
            "Review whether state changes occur before this external "
            "call and whether reentrancy protection is required."
        )

    # Delegatecall
    if re.search(r'\.delegatecall\s*\(', source):
        add_finding(
            findings,
            "HIGH",
            "Delegatecall detected",
            "Review target validation, storage layout and access controls."
        )

    # tx.origin
    if re.search(r'\btx\.origin\b', source):
        add_finding(
            findings,
            "MEDIUM",
            "tx.origin usage",
            "Review whether tx.origin is used for authorization."
        )

    # Selfdestruct
    if re.search(r'\bselfdestruct\s*\(', source):
        add_finding(
            findings,
            "HIGH",
            "Selfdestruct detected",
            "Review authorization and intended contract lifecycle."
        )

    # Dangerous low-level calls
    if re.search(r'\.call\s*\(', source):
        add_finding(
            findings,
            "MEDIUM",
            "Low-level call detected",
            "Check return-value handling and destination validation."
        )

    # Assembly
    if re.search(r'\bassembly\b', source):
        add_finding(
            findings,
            "INFO",
            "Inline assembly detected",
            "Manual review of memory and storage operations is advised."
        )

    # Unchecked blocks
    if re.search(r'\bunchecked\s*\{', source):
        add_finding(
            findings,
            "MEDIUM",
            "Unchecked arithmetic",
            "Review arithmetic operations for overflow and underflow."
        )

    # Sensitive functions without obvious modifiers
    sensitive = [
        "withdraw",
        "mint",
        "pause",
        "setOwner",
        "setAdmin",
        "upgradeTo"
    ]

    for function in sensitive:
        pattern = (
            r'function\s+' + re.escape(function) +
            r'\s*\([^)]*\)[^{;]*\{'
        )

        for match in re.finditer(pattern, source):
            header = match.group(0)

            if not re.search(
                r'onlyOwner|onlyRole|onlyAdmin|'
                r'hasRole|require\s*\(\s*msg\.sender',
                header
            ):
                add_finding(
                    findings,
                    "MEDIUM",
                    "Review access control: " + function,
                    "No recognized access-control pattern was found "
                    "in the function declaration."
                )

    # Older compiler versions
    if re.search(r'pragma\s+solidity\s+0\.[0-7]\.', source):
        add_finding(
            findings,
            "LOW",
            "Older Solidity compiler",
            "Review compiler compatibility and known compiler bugs."
        )

    return findings


def get_risk(findings):
    severities = {item["severity"] for item in findings}

    if "HIGH" in severities:
        return "HIGH"

    if "MEDIUM" in severities:
        return "MEDIUM"

    if "LOW" in severities:
        return "LOW"

    return "INFO"


def scan_contract(contract):
    address = contract["address"]

    report = {
        "address": address,
        "name": contract.get("name", "Unknown"),
        "verified": True,
        "source_available": False,
        "status": "SOURCE_UNAVAILABLE",
        "risk": "UNASSESSED",
        "findings": [],
        "explorer": (
            "https://tronscan.org/#/contract/" + address
        )
    }

    source = fetch_contract_source(address)

    if not source:
        return report

    report["source_available"] = True
    report["status"] = "SCANNED"

    findings = analyze_solidity(source)

    report["findings"] = findings
    report["risk"] = get_risk(findings)
    report["finding_count"] = len(findings)

    return report


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/scan")
def scan_batch():
    try:
        start = int(request.args.get("start", 0))
        limit = int(request.args.get("limit", 5))

        if start < 0 or start > MAX_START:
            return jsonify({"error": "Invalid pagination offset."}), 400

        if limit < 1 or limit > MAX_LIMIT:
            return jsonify({
                "error": "Batch size must be between 1 and 10."
            }), 400

        batch = fetch_verified_contracts(start, limit)

        reports = []

        for contract in batch["contracts"]:
            reports.append(scan_contract(contract))
            time.sleep(0.15)

        return jsonify({
            "network": "TRON Mainnet",
            "total_verified": batch["total"],
            "start": start,
            "next_start": batch["next_start"],
            "processed": len(reports),
            "reports": reports
        })

    except requests.HTTPError as error:
        status = (
            error.response.status_code
            if error.response is not None else 502
        )

        return jsonify({
            "error": "TRONSCAN API request failed.",
            "upstream_status": status
        }), 502

    except requests.RequestException:
        return jsonify({
            "error": "Unable to connect to TRONSCAN."
        }), 502

    except (ValueError, TypeError):
        return jsonify({
            "error": "Invalid request parameters."
        }), 400


@app.errorhandler(500)
def server_error(error):
    return jsonify({"error": "Internal server error."}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

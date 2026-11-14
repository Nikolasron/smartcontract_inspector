
import re
import requests

API = "https://apilist.tronscanapi.com/api"

session = requests.Session()

session.headers.update({
    "User-Agent": "TRON-GUARD-Security-Scanner/2.0",
    "Accept": "application/json"
})

TIMEOUT = 25


def headers(api_key=""):
    result = {}

    if api_key:
        result["TRON-PRO-API-KEY"] = api_key

    return result


def valid_tron_address(address):
    return bool(
        re.fullmatch(
            r"T[1-9A-HJ-NP-Za-km-z]{33}",
            address or ""
        )
    )


def extract_source(obj):
    """
    Extract Solidity source only from explicit source fields.
    Never treat ABI or bytecode as Solidity source.
    """

    if not isinstance(obj, dict):
        return ""

    possible_fields = [
        "sourceCode",
        "source_code",
        "contractSource",
        "contract_source",
        "solidityCode",
        "solidity_code",
        "code"
    ]

    for field in possible_fields:
        value = obj.get(field)

        if isinstance(value, str) and value.strip():
            if "pragma solidity" in value or "contract " in value:
                return value

        if isinstance(value, dict):
            nested = extract_source(value)

            if nested:
                return nested

    for value in obj.values():
        if isinstance(value, dict):
            nested = extract_source(value)

            if nested:
                return nested

    return ""


def fetch_contract_source(address, api_key=""):
    if not valid_tron_address(address):
        raise ValueError("Invalid TRON contract address.")

    response = session.get(
        API + "/contract",
        params={
            "contract": address
        },
        headers=headers(api_key),
        timeout=TIMEOUT
    )

    response.raise_for_status()

    payload = response.json()

    obj = payload.get("data", payload)

    if isinstance(obj, list):
        obj = obj[0] if obj else {}

    if not isinstance(obj, dict):
        obj = {}

    source = extract_source(obj)

    metadata = {
        "address": address,
        "name": obj.get("name", "Unknown"),
        "verified": obj.get("verify_status") == 2,
        "explorer_url": (
            "https://tronscan.org/#/contract/"
            + address
        )
    }

    if not metadata["verified"]:
        raise ValueError(
            "TRONSCAN does not report this contract as verified."
        )

    if not source:
        raise ValueError(
            "Solidity source was not returned by the contract-detail API. "
            "ABI and bytecode are not accepted as source."
        )

    return source, metadata


def analyze_source(source):
    if not isinstance(source, str) or not source.strip():
        raise ValueError("Solidity source is empty.")

    findings = []

    checks = [
        (
            "REENTRANCY-01",
            "High",
            "External call detected",
            "Review whether state changes occur before external calls.",
            r"\.(call|send|transfer)\s*(?:\{[^}]*\})?\s*\("
        ),
        (
            "REENTRANCY-02",
            "Medium",
            "Callback function detected",
            "Review callback functions for re-entry risks.",
            r"\b(onERC721Received|onERC1155Received|tokensReceived|fallback|receive)\s*\("
        ),
        (
            "CALL-01",
            "High",
            "Low-level external call detected",
            "Check destination validation and return-value handling.",
            r"\.(call|delegatecall|staticcall)\s*(?:\{[^}]*\})?\s*\("
        ),
        (
            "CALL-02",
            "Medium",
            "Delegatecall detected",
            "Review implementation authorization and storage compatibility.",
            r"\.delegatecall\s*(?:\{[^}]*\})?\s*\("
        ),
        (
            "ACCESS-01",
            "High",
            "Sensitive function detected",
            "Review owner or role authorization.",
            r"function\s+\w*(?:withdraw|sweep|rescue|mint|pause|upgrade|setOwner|setAdmin)\w*\s*\([^)]*\)[^{;]*\b(public|external)\b"
        ),
        (
            "ACCESS-02",
            "Info",
            "Access-control indicator detected",
            "Review ownership initialization and role management.",
            r"\b(onlyOwner|AccessControl|grantRole|revokeRole|transferOwnership)\b"
        ),
        (
            "FUNDS-01",
            "Info",
            "Token transfer function detected",
            "Review transfer authorization and recipient validation.",
            r"\b(transferFrom|safeTransferFrom|safeTransfer|transfer)\s*\("
        ),
        (
            "UPGRADE-01",
            "Medium",
            "Upgradeable contract indicator detected",
            "Review upgrade authorization and initialization.",
            r"\b(upgradeTo|_authorizeUpgrade|proxyAdmin)\b"
        ),
        (
            "ORIGIN-01",
            "High",
            "tx.origin usage detected",
            "Review whether tx.origin is used for authorization.",
            r"\btx\.origin\b"
        ),
        (
            "DESTRUCTION-01",
            "High",
            "Self-destruct operation detected",
            "Review destruction behavior and authorization.",
            r"\bselfdestruct\s*\("
        ),
        (
            "ASSEMBLY-01",
            "Medium",
            "Inline assembly detected",
            "Manually inspect low-level memory and storage operations.",
            r"\bassembly\b"
        )
    ]

    for rule, severity, title, detail, pattern in checks:
        matches = list(
            re.finditer(pattern, source, re.I | re.M)
        )

        if not matches:
            continue

        evidence = []

        for match in matches[:5]:
            line = source.count(
                "\n", 0, match.start()
            ) + 1

            snippet = source[
                max(0, match.start() - 60):
                min(len(source), match.end() + 100)
            ].replace("\n", " ")

            evidence.append({
                "line": line,
                "snippet": snippet[:200]
            })

        findings.append({
            "rule": rule,
            "severity": severity,
            "title": title,
            "detail": detail,
            "evidence": evidence
        })

    weights = {
        "Critical": 10,
        "High": 6,
        "Medium": 3,
        "Low": 1,
        "Info": 0
    }

    score = min(
        100,
        sum(
            weights.get(item["severity"], 0)
            for item in findings
        )
    )

    counts = {
        level: sum(
            1 for item in findings
            if item["severity"] == level
        )
        for level in weights
    }

    if counts["Critical"] or counts["High"] >= 2:
        verdict = "HIGH PRIORITY REVIEW"
    elif counts["High"] or counts["Medium"]:
        verdict = "CAUTION - MANUAL REVIEW"
    else:
        verdict = "NO HEURISTIC ALERTS - NOT PROOF OF SAFETY"

    return {
        "verdict": verdict,
        "risk_score": score,
        "counts": counts,
        "finding_count": len(findings),
        "findings": findings,
        "method": "Heuristic static analysis",
        "disclaimer": (
            "This is a preliminary automated review, not a formal audit. "
            "Patterns can produce false positives and miss vulnerabilities. "
            "No detection percentage or security guarantee is implied."
        )
    }

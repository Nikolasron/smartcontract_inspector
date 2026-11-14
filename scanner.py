
import re
import requests

API = "https://apilist.tronscanapi.com/api"

session = requests.Session()
session.headers.update({
    "User-Agent": "TRON-GUARD-Security-Scanner/1.0"
})


def headers(api_key=""):
    return {
        "TRON-PRO-API-KEY": api_key
    } if api_key else {}


def valid_tron_address(address):
    return bool(re.fullmatch(
        r"T[1-9A-HJ-NP-Za-km-z]{33}",
        address or ""
    ))


def fetch_contract_source(address, api_key=""):
    response = session.get(
        API + "/contract",
        params={"contract": address},
        headers=headers(api_key),
        timeout=25
    )
    response.raise_for_status()

    data = response.json()
    obj = data.get("data", data)

    if isinstance(obj, list):
        obj = obj[0] if obj else {}

    source = (
        obj.get("code")
        or obj.get("sourceCode")
        or obj.get("contractCode")
        or ""
    )

    if isinstance(source, dict):
        source = source.get("source", "")

    if not source:
        raise ValueError(
            "Verified Solidity source unavailable."
        )

    return source, {
        "address": address,
        "name": obj.get("name", "Unknown"),
        "verified": obj.get("verify_status") == 2,
        "tronscan_url":
            f"https://tronscan.org/#/contract/{address}"
    }


def discover_contracts(api_key="", limit=30):
    response = session.get(
        API + "/contracts",
        params={
            "start": 0,
            "limit": min(limit, 50),
            "sort": "-timestamp"
        },
        headers=headers(api_key),
        timeout=25
    )

    response.raise_for_status()
    rows = response.json().get("data", [])

    results = []

    for item in rows:
        address = item.get("address", "")

        if not valid_tron_address(address):
            continue

        results.append({
            "address": address,
            "name": item.get("name", "Unknown"),
            "verified": item.get("verify_status") == 2,
            "tronscan_url":
                f"https://tronscan.org/#/contract/{address}"
        })

    return results


def analyze_source(source):
    findings = []

    def check(rule, severity, title, detail, pattern):
        matches = list(re.finditer(
            pattern, source, re.I | re.M
        ))

        if matches:
            findings.append({
                "rule": rule,
                "severity": severity,
                "title": title,
                "detail": detail,
                "evidence": [
                    {
                        "line": source.count(
                            "\n", 0, m.start()
                        ) + 1,
                        "snippet": source[
                            max(0, m.start()-60):
                            min(len(source), m.end()+100)
                        ].replace("\n", " ")[:200]
                    }
                    for m in matches[:5]
                ]
            })

    check(
        "REENTRANCY-01",
        "High",
        "External call detected",
        "Review whether external calls happen before state updates. Check reentrancy protection and checks-effects-interactions.",
        r"\.(call|send|transfer)\s*(?:\{[^}]*\})?\s*\("
    )

    check(
        "REENTRANCY-02",
        "Medium",
        "Callback function detected",
        "Review callback functions for possible re-entry and state inconsistencies.",
        r"\b(onERC721Received|onERC1155Received|tokensReceived|fallback|receive)\s*\("
    )

    check(
        "CALL-01",
        "High",
        "Low-level external call",
        "Verify the destination is trusted and the call result is checked.",
        r"\.(call|delegatecall|staticcall)\s*(?:\{[^}]*\})?\s*\("
    )

    check(
        "CALL-02",
        "Medium",
        "Delegatecall detected",
        "Review implementation authorization and storage compatibility.",
        r"\.delegatecall\s*(?:\{[^}]*\})?\s*\("
    )

    check(
        "ACCESS-01",
        "High",
        "Sensitive function detected",
        "Check whether this function has proper owner or role authorization.",
        r"function\s+\w*(?:withdraw|sweep|rescue|mint|pause|upgrade|setOwner|setAdmin)\w*\s*\([^)]*\)\s*(?:public|external)"
    )

    check(
        "ACCESS-02",
        "Medium",
        "Access-control mechanisms detected",
        "Review ownership initialization and role management.",
        r"\b(onlyOwner|AccessControl|grantRole|revokeRole|transferOwnership)\b"
    )

    check(
        "FUNDS-01",
        "Medium",
        "Token transfer function detected",
        "Review authorization, recipient validation and transfer limits.",
        r"\b(transferFrom|safeTransferFrom|safeTransfer|transfer)\s*\("
    )

    check(
        "UPGRADE-01",
        "Medium",
        "Upgradeable contract indicator",
        "Review upgrade authorization and implementation initialization.",
        r"\b(upgradeTo|_authorizeUpgrade|proxyAdmin)\b"
    )

    weights = {
        "Critical": 10,
        "High": 6,
        "Medium": 3,
        "Low": 1,
        "Info": 0
    }

    score = min(100, sum(
        weights.get(f["severity"], 0)
        for f in findings
    ))

    counts = {
        level: sum(
            1 for f in findings
            if f["severity"] == level
        )
        for level in weights
    }

    if counts["High"] >= 2:
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
            "This scanner is not a formal audit. "
            "False positives and missed vulnerabilities "
            "are possible. No 90% detection rate is guaranteed."
        )
    }

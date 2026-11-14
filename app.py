
import os
import json
import hmac
import requests

from datetime import datetime, timezone
from flask import Flask, render_template, request, jsonify
from upstash_redis import Redis

from scanner import (
    analyze_source,
    fetch_contract_source,
    valid_tron_address
)


ROOT = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(ROOT, "templates")
)

app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

TRONSCAN_API = "https://apilist.tronscanapi.com/api"

API_KEY = os.getenv("TRONSCAN_API_KEY", "")
CRON_SECRET = os.getenv("CRON_SECRET", "")

BATCH_SIZE = 5
MAX_TRONSCAN_INDEX = 10000
MAX_SAVED_REPORTS = 500

REDIS_URL = os.getenv("UPSTASH_REDIS_REST_URL", "")
REDIS_TOKEN = os.getenv("UPSTASH_REDIS_REST_TOKEN", "")

redis = None

if REDIS_URL and REDIS_TOKEN:
    redis = Redis(
        url=REDIS_URL,
        token=REDIS_TOKEN
    )


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def redis_get(key, default=None):
    if redis is None:
        return default

    value = redis.get(key)

    if value is None:
        return default

    if isinstance(value, bytes):
        value = value.decode("utf-8")

    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value

    return value


def redis_set(key, value):
    if redis is None:
        raise RuntimeError("Upstash Redis is not configured.")

    redis.set(key, json.dumps(value))


def get_reports():
    reports = redis_get("tron_guard:reports", [])

    return reports if isinstance(reports, list) else []


def save_report(report):
    reports = get_reports()

    address = report.get("address")

    reports = [
        item for item in reports
        if item.get("address") != address
    ]

    reports.insert(0, report)

    redis_set(
        "tron_guard:reports",
        reports[:MAX_SAVED_REPORTS]
    )


def get_state():
    return redis_get(
        "tron_guard:state",
        {
            "cursor": 0,
            "last_cron_run": None,
            "last_error": None,
            "last_batch_count": 0,
            "total_processed": 0
        }
    )


def save_state(state):
    redis_set("tron_guard:state", state)


def fetch_verified_contracts(start, limit):
    response = requests.get(
        TRONSCAN_API + "/contracts",
        params={
            "start": start,
            "limit": min(limit, 50),
            "sort": "-timestamp",
            "verified-only": "true",
            "open-source-only": "true"
        },
        headers={
            "TRON-PRO-API-KEY": API_KEY
        } if API_KEY else {},
        timeout=25
    )

    response.raise_for_status()

    payload = response.json()

    rows = payload.get("data", [])

    if not isinstance(rows, list):
        raise ValueError("Unexpected TRONSCAN contract-list response.")

    return rows


def normalize_report(contract, source, metadata):
    result = analyze_source(source)

    findings = []

    for finding in result.get("findings", []):
        findings.append({
            "severity": finding.get("severity", "Unknown"),
            "code": finding.get("rule", "REVIEW"),
            "message": finding.get("detail", "Manual review required."),
            "title": finding.get("title", "Potential issue"),
            "evidence": finding.get("evidence", [])
        })

    counts = result.get("counts", {})

    high_count = counts.get("High", 0)
    critical_count = counts.get("Critical", 0)
    medium_count = counts.get("Medium", 0)

    if critical_count or high_count:
        risk = "HIGH"
    elif medium_count:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "address": contract["address"],
        "name": metadata.get("name") or contract.get("name") or "Unknown",
        "risk": risk,
        "status": "ANALYZED",
        "source_available": True,
        "risk_score": result.get("risk_score", 0),
        "verdict": result.get("verdict"),
        "findings": findings,
        "finding_count": len(findings),
        "explorer_url": (
            "https://tronscan.org/#/contract/"
            + contract["address"]
        ),
        "scanned_at": utc_now(),
        "method": result.get("method"),
        "disclaimer": result.get("disclaimer")
    }


def make_unassessed_report(contract, reason):
    return {
        "address": contract["address"],
        "name": contract.get("name", "Unknown"),
        "risk": "UNASSESSED",
        "status": "SOURCE_UNAVAILABLE",
        "source_available": False,
        "risk_score": None,
        "finding_count": 0,
        "findings": [],
        "message": reason,
        "explorer_url": (
            "https://tronscan.org/#/contract/"
            + contract["address"]
        ),
        "scanned_at": utc_now()
    }


def scan_one(item):
    address = item.get("address", "")

    if not valid_tron_address(address):
        return None

    contract = {
        "address": address,
        "name": item.get("name", "Unknown")
    }

    try:
        source, metadata = fetch_contract_source(
            address,
            API_KEY
        )

        if not source:
            return make_unassessed_report(
                contract,
                "Verified Solidity source was not returned."
            )

        return normalize_report(
            contract,
            source,
            metadata or {}
        )

    except requests.RequestException as error:
        return make_unassessed_report(
            contract,
            "Source retrieval request failed: " + str(error)[:200]
        )

    except Exception as error:
        return make_unassessed_report(
            contract,
            "Source could not be analyzed: " + str(error)[:200]
        )


def run_scan_batch():
    if redis is None:
        raise RuntimeError("Upstash Redis is not configured.")

    state = get_state()

    cursor = int(state.get("cursor", 0))

    if cursor >= MAX_TRONSCAN_INDEX:
        cursor = 0

    rows = fetch_verified_contracts(
        cursor,
        BATCH_SIZE
    )

    if not rows:
        state["cursor"] = 0
        state["last_cron_run"] = utc_now()
        state["last_batch_count"] = 0
        state["last_error"] = None
        save_state(state)

        return {
            "processed": 0,
            "message": "No contracts returned. Discovery cursor reset."
        }

    processed = 0

    for item in rows:
        address = item.get("address", "")

        if not valid_tron_address(address):
            continue

        report = scan_one(item)

        if report:
            save_report(report)
            processed += 1

    state["cursor"] = cursor + len(rows)

    if state["cursor"] >= MAX_TRONSCAN_INDEX:
        state["cursor"] = 0

    state["last_cron_run"] = utc_now()
    state["last_batch_count"] = processed
    state["total_processed"] = (
        int(state.get("total_processed", 0))
        + processed
    )
    state["last_error"] = None

    save_state(state)

    return {
        "processed": processed,
        "next_cursor": state["cursor"],
        "message": "Scanning batch completed."
    }


@app.get("/")
def home():
    return render_template("index.html")


@app.get("/health")
def health():
    return jsonify({
        "status": "ok",
        "redis_configured": redis is not None,
        "tronscan_key_configured": bool(API_KEY)
    })


@app.get("/api/status")
def status():
    state = get_state()

    return jsonify({
        "status": "running",
        "redis_configured": redis is not None,
        "last_cron_run": state.get("last_cron_run"),
        "last_error": state.get("last_error"),
        "last_batch_count": state.get("last_batch_count", 0),
        "total_processed": state.get("total_processed", 0),
        "next_cursor": state.get("cursor", 0)
    })


@app.get("/api/reports")
def reports():
    saved = get_reports()

    return jsonify({
        "count": len(saved),
        "reports": saved
    })


@app.get("/api/report/<address>")
def individual_report(address):
    if not valid_tron_address(address):
        return jsonify({"error": "Invalid TRON address"}), 400

    for item in get_reports():
        if item.get("address") == address:
            return jsonify(item)

    return jsonify({"error": "Report not found"}), 404


@app.post("/api/cron")
def cron():
    if not CRON_SECRET:
        return jsonify({
            "error": "CRON_SECRET is not configured."
        }), 503

    supplied = request.headers.get(
        "Authorization",
        ""
    )

    expected = "Bearer " + CRON_SECRET

    if not hmac.compare_digest(supplied, expected):
        return jsonify({"error": "Unauthorized"}), 401

    try:
        result = run_scan_batch()
        return jsonify({
            "success": True,
            **result
        })

    except Exception as error:
        state = get_state()
        state["last_error"] = str(error)[:500]
        state["last_cron_run"] = utc_now()

        try:
            save_state(state)
        except Exception:
            pass

        return jsonify({
            "success": False,
            "error": str(error)
        }), 502


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", "5000"))
    )

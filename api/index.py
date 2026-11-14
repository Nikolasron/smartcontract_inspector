
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from flask import Flask, render_template, request, jsonify
from scanner import (
    analyze_source,
    fetch_contract_source,
    discover_contracts,
    valid_tron_address
)

app = Flask(__name__, template_folder=os.path.join(ROOT, "templates"))
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

API_KEY = os.getenv("TRONSCAN_API_KEY", "")


@app.get("/")
def home():
    return render_template("index.html")


@app.post("/api/scan")
def scan():
    data = request.get_json(silent=True) or request.form

    address = (data.get("address") or "").strip()
    source = (data.get("source") or "").strip()

    if address and not valid_tron_address(address):
        return jsonify({"error": "Invalid TRON address"}), 400

    metadata = {}

    if not source and address:
        try:
            source, metadata = fetch_contract_source(
                address, API_KEY
            )
        except Exception as error:
            return jsonify({
                "error": str(error),
                "hint": "Try pasting verified Solidity source manually."
            }), 502

    if not source:
        return jsonify({
            "error": "Provide a contract address or Solidity source."
        }), 400

    report = analyze_source(source)
    report["contract"] = metadata or {
        "address": address or "Source-only scan",
        "name": "Pasted source"
    }

    return jsonify(report)


@app.get("/api/discover")
def discover():
    try:
        contracts = discover_contracts(API_KEY, limit=30)

        return jsonify({
            "count": len(contracts),
            "contracts": contracts
        })

    except Exception as error:
        return jsonify({
            "error": str(error),
            "contracts": []
        }), 502


@app.get("/health")
def health():
    return jsonify({"status": "ok"})

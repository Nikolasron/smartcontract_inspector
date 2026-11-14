
from flask import Flask, render_template, request, jsonify
import re

app = Flask(__name__)

MAX_CODE_SIZE = 500_000


def analyze_contract(code):
    findings = []

    def add_finding(severity, title, description):
        findings.append({
            "severity": severity,
            "title": title,
            "description": description
        })

    # 1. Reentrancy patterns
    if re.search(r'\.call\s*\{[^}]*value\s*:', code):
        if re.search(
            r'\.call\s*\{[^}]*value\s*:[\s\S]*?\n[\s\S]{0,500}'
            r'(balances|balanceOf|withdraw)',
            code
        ):
            add_finding(
                "HIGH",
                "Possible Reentrancy",
                "An external value-transfer call may occur before "
                "related state updates. Review checks-effects-interactions."
            )

    # 2. Unprotected self-destruct
    if re.search(r'\bselfdestruct\s*\(', code):
        if not re.search(
            r'onlyOwner|onlyRole|hasRole|msg\.sender\s*==',
            code
        ):
            add_finding(
                "HIGH",
                "Potentially Unprotected Selfdestruct",
                "The contract uses selfdestruct but no obvious "
                "access-control pattern was detected."
            )

    # 3. Missing access-control patterns
    sensitive_functions = [
        "withdraw",
        "mint",
        "pause",
        "upgradeTo",
        "setOwner",
        "setAdmin"
    ]

    for function in sensitive_functions:
        pattern = (
            r'function\s+' + re.escape(function) +
            r'\s*\([^)]*\)[^{;]*\{'
        )

        matches = list(re.finditer(pattern, code))

        for match in matches:
            header = match.group(0)

            if not re.search(
                r'onlyOwner|onlyRole|onlyAdmin|'
                r'hasRole|require\s*\(\s*msg\.sender',
                header
            ):
                add_finding(
                    "MEDIUM",
                    "Review Access Control: " + function,
                    "The function does not show a recognized "
                    "access-control modifier in its declaration. "
                    "Inspect its full implementation."
                )

    # 4. Dangerous delegatecall
    if re.search(r'\.delegatecall\s*\(', code):
        add_finding(
            "HIGH",
            "Delegatecall Detected",
            "delegatecall executes code in the caller's storage context. "
            "Review target validation and authorization."
        )

    # 5. Unchecked low-level calls
    if re.search(r'\.call\s*\(', code):
        if not re.search(
            r'(success|ok)\s*(,|=)',
            code
        ):
            add_finding(
                "MEDIUM",
                "Review Low-Level Call Result",
                "A low-level call exists. Verify that its success "
                "return value is checked."
            )

    # 6. tx.origin authentication
    if re.search(r'tx\.origin', code):
        add_finding(
            "MEDIUM",
            "tx.origin Usage",
            "tx.origin is present. Avoid using it as the primary "
            "authorization mechanism."
        )

    # 7. Solidity version
    if re.search(r'pragma\s+solidity\s+0\.[0-7]\.', code):
        add_finding(
            "MEDIUM",
            "Older Solidity Version",
            "An older Solidity compiler version is specified. "
            "Review known compiler bugs and upgrade compatibility."
        )

    # 8. Floating pragma
    if re.search(r'pragma\s+solidity\s+\^', code):
        add_finding(
            "LOW",
            "Floating Compiler Version",
            "A floating compiler pragma is used. Pin a tested "
            "compiler version for reproducible builds."
        )

    # 9. Block timestamp dependency
    if re.search(r'block\.timestamp', code):
        add_finding(
            "LOW",
            "Block Timestamp Dependency",
            "The contract uses block.timestamp. Avoid relying on "
            "precise timestamps for sensitive randomness or timing."
        )

    # 10. Unchecked arithmetic in older Solidity
    if re.search(r'pragma\s+solidity\s+0\.[0-7]\.', code):
        if re.search(r'\bunchecked\s*\{', code):
            add_finding(
                "MEDIUM",
                "Unchecked Arithmetic",
                "An unchecked arithmetic block was detected. "
                "Review possible integer underflow and overflow."
            )

    # 11. Assembly usage
    if re.search(r'\bassembly\b', code):
        add_finding(
            "INFO",
            "Inline Assembly Detected",
            "Review assembly blocks manually for memory, storage "
            "and call-safety issues."
        )

    # 12. Arbitrary external call targets
    if re.search(r'\.call\s*\(', code):
        if re.search(r'address\s*\([^)]*\)\s*\.call', code):
            add_finding(
                "HIGH",
                "Dynamic External Call Target",
                "A dynamically selected address may be used as a "
                "low-level call target. Verify target restrictions."
            )

    # Remove duplicate findings
    unique_findings = []
    seen = set()

    for finding in findings:
        key = (finding["title"], finding["description"])

        if key not in seen:
            seen.add(key)
            unique_findings.append(finding)

    severity_counts = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }

    for finding in unique_findings:
        severity_counts[finding["severity"]] += 1

    return {
        "summary": (
            f"Analysis completed. "
            f"{len(unique_findings)} potential findings detected. "
            f"High: {severity_counts['HIGH']}, "
            f"Medium: {severity_counts['MEDIUM']}, "
            f"Low: {severity_counts['LOW']}, "
            f"Info: {severity_counts['INFO']}."
        ),
        "findings": unique_findings
    }


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON request."}), 400

    code = data.get("contract", "")

    if not isinstance(code, str):
        return jsonify({"error": "Contract code must be text."}), 400

    code = code.strip()

    if not code:
        return jsonify({"error": "Contract code is empty."}), 400

    if len(code) > MAX_CODE_SIZE:
        return jsonify({"error": "Contract code is too large."}), 413

    result = analyze_contract(code)

    return jsonify(result)


@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error."}), 500


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )

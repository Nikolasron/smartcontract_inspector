
const totalContracts = document.getElementById("totalContracts");
const processed = document.getElementById("processed");
const highRisk = document.getElementById("highRisk");
const mediumRisk = document.getElementById("mediumRisk");

const systemStatus = document.getElementById("systemStatus");
const progressBar = document.getElementById("progressBar");
const progressText = document.getElementById("progressText");
const scanActivity = document.getElementById("scanActivity");

const contractResults = document.getElementById("contractResults");
const report = document.getElementById("report");
const searchInput = document.getElementById("searchInput");

let contracts = [];

function setText(element, value) {
    if (element) {
        element.textContent = value;
    }
}

function createCell(value) {
    const cell = document.createElement("td");
    cell.textContent = value || "Unknown";
    return cell;
}

function showReport(item) {
    if (!report) return;

    report.replaceChildren();

    const title = document.createElement("h3");
    title.textContent = item.name || "Unknown contract";

    const address = document.createElement("p");
    address.textContent = "Address: " + (item.address || "Unknown");

    const risk = document.createElement("p");
    risk.textContent = "Risk classification: " + (item.risk || "UNASSESSED");

    const status = document.createElement("p");
    status.textContent = "Scan status: " + (item.status || "Unknown");

    const source = document.createElement("p");
    source.textContent = item.source_available
        ? "Verified Solidity source was retrieved and analyzed."
        : "Source code unavailable. Security analysis was not completed.";

    report.append(title, address, risk, status, source);

    const findingsTitle = document.createElement("h4");
    findingsTitle.textContent = "Security findings";
    report.appendChild(findingsTitle);

    if (!item.findings || item.findings.length === 0) {
        const message = document.createElement("p");

        message.textContent = item.source_available
            ? "No suspicious patterns were detected by the current scanner. This does not prove the contract is secure."
            : "No findings available because source code could not be retrieved.";

        report.appendChild(message);
    } else {
        const list = document.createElement("ul");

        item.findings.forEach(finding => {
            const li = document.createElement("li");

            li.textContent =
                `[${finding.severity || "UNKNOWN"}] ` +
                (finding.code || "Finding") +
                ": " +
                (finding.message || "Review required.");

            list.appendChild(li);
        });

        report.appendChild(list);
    }

    if (item.explorer_url) {
        const link = document.createElement("a");

        link.href = item.explorer_url;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        link.textContent = "View contract on TRONSCAN";

        report.appendChild(link);
    }
}

function renderContracts() {
    if (!contractResults) return;

    const query = searchInput
        ? searchInput.value.toLowerCase().trim()
        : "";

    contractResults.replaceChildren();

    const filtered = contracts.filter(item =>
        (item.name || "").toLowerCase().includes(query) ||
        (item.address || "").toLowerCase().includes(query)
    );

    if (filtered.length === 0) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 5;
        cell.textContent = "No saved contracts found.";

        row.appendChild(cell);
        contractResults.appendChild(row);
        return;
    }

    filtered.forEach(item => {
        const row = document.createElement("tr");

        row.appendChild(createCell(item.name));
        row.appendChild(createCell(item.address));
        row.appendChild(createCell(item.risk));
        row.appendChild(createCell(item.status));

        const reportCell = document.createElement("td");
        const button = document.createElement("button");

        button.textContent = "View report";
        button.addEventListener("click", () => showReport(item));

        reportCell.appendChild(button);
        row.appendChild(reportCell);

        contractResults.appendChild(row);
    });
}

function updateStats() {
    setText(processed, contracts.length);

    setText(
        highRisk,
        contracts.filter(item => item.risk === "HIGH").length
    );

    setText(
        mediumRisk,
        contracts.filter(item => item.risk === "MEDIUM").length
    );

    // This dashboard displays saved reports, not the total
    // number of contracts available on TRONSCAN.
    setText(totalContracts, "Saved reports");

    if (progressBar) {
        progressBar.style.width = "0%";
    }

    setText(
        progressText,
        `${contracts.length} saved reports loaded`
    );
}

async function loadDashboard() {
    try {
        setText(systemStatus, "Connecting to saved reports...");
        setText(scanActivity, "Loading stored contract reports...");

        const statusResponse = await fetch("/api/status", {
            headers: { "Accept": "application/json" },
            cache: "no-store"
        });

        if (!statusResponse.ok) {
            throw new Error(
                `Status request failed: HTTP ${statusResponse.status}`
            );
        }

        const statusData = await statusResponse.json();

        const reportsResponse = await fetch("/api/reports", {
            headers: { "Accept": "application/json" },
            cache: "no-store"
        });

        if (!reportsResponse.ok) {
            throw new Error(
                `Reports request failed: HTTP ${reportsResponse.status}`
            );
        }

        const reportsData = await reportsResponse.json();

        contracts = Array.isArray(reportsData.reports)
            ? reportsData.reports
            : [];

        updateStats();
        renderContracts();

        setText(systemStatus, "Connected — displaying saved reports");

        const lastRun = statusData.last_cron_run
            ? new Date(statusData.last_cron_run).toLocaleString()
            : "No scheduled scan recorded yet";

        setText(
            scanActivity,
            `Last scheduled scan: ${lastRun}. Dashboard refreshes automatically.`
        );

    } catch (error) {
        setText(systemStatus, "Dashboard connection error");
        setText(scanActivity, error.message);
    }
}

if (searchInput) {
    searchInput.addEventListener("input", renderContracts);
}

// Load saved results when the page opens.
// This dashboard does not call TRONSCAN or start scans.
loadDashboard();

// Refresh saved results every 30 seconds.
setInterval(loadDashboard, 30000);

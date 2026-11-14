
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
let nextStart = 0;
let total = 0;
let scanning = false;
let finished = false;

const BATCH_SIZE = 5;
const MAX_START = 9990;

function updateStats() {
    processed.textContent = contracts.length;

    highRisk.textContent = contracts.filter(
        item => item.risk === "HIGH"
    ).length;

    mediumRisk.textContent = contracts.filter(
        item => item.risk === "MEDIUM"
    ).length;

    totalContracts.textContent = Number(total).toLocaleString();

    const percentage = total > 0
        ? Math.min(100, (nextStart / total) * 100)
        : 0;

    progressBar.style.width = percentage + "%";

    progressText.textContent =
        `${contracts.length} processed | ${percentage.toFixed(1)}% indexed progress`;
}

function createCell(value) {
    const cell = document.createElement("td");
    cell.textContent = value || "Unknown";
    return cell;
}

function showReport(item) {
    report.replaceChildren();

    const title = document.createElement("h3");
    title.textContent = item.name || "Unknown contract";

    const address = document.createElement("p");
    address.textContent = "Address: " + item.address;

    const risk = document.createElement("p");
    risk.textContent = "Risk classification: " + item.risk;

    const status = document.createElement("p");
    status.textContent = "Scan status: " + item.status;

    const source = document.createElement("p");
    source.textContent = item.source_available
        ? "Verified Solidity source analyzed."
        : "Source code unavailable; security analysis not completed.";

    report.append(title, address, risk, status, source);

    const findingsTitle = document.createElement("h4");
    findingsTitle.textContent = "Security findings";
    report.appendChild(findingsTitle);

    if (!item.findings || item.findings.length === 0) {
        const message = document.createElement("p");

        message.textContent = item.source_available
            ? "No suspicious patterns detected by the current scanner. This is not proof of security."
            : "No findings available because source code could not be retrieved.";

        report.appendChild(message);
    } else {
        const list = document.createElement("ul");

        item.findings.forEach(finding => {
            const li = document.createElement("li");

            li.textContent =
                `[${finding.severity}] ${finding.title}: ${finding.description}`;

            list.appendChild(li);
        });

        report.appendChild(list);
    }

    const link = document.createElement("a");
    link.href = item.explorer;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.textContent = "View contract on TRONSCAN";

    report.appendChild(link);
}

function renderContracts() {
    const query = searchInput.value.toLowerCase().trim();

    contractResults.replaceChildren();

    const filtered = contracts.filter(item =>
        (item.name || "").toLowerCase().includes(query) ||
        (item.address || "").toLowerCase().includes(query)
    );

    if (filtered.length === 0) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 5;
        cell.textContent = "No matching contracts found.";

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

async function fetchBatch() {
    const response = await fetch(
        `/api/scan?start=${nextStart}&limit=${BATCH_SIZE}`,
        {
            method: "GET",
            headers: {
                "Accept": "application/json"
            }
        }
    );

    const data = await response.json();

    if (!response.ok) {
        throw new Error(data.error || "TRONSCAN request failed.");
    }

    return data;
}

function wait(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function startAutomaticDiscovery() {
    if (scanning || finished) return;

    scanning = true;
    systemStatus.textContent = "Automatic scanner running";

    try {
        while (nextStart <= MAX_START) {
            scanActivity.textContent =
                `Discovering verified contracts from index ${nextStart}...`;

            const data = await fetchBatch();

            total = Number(data.total_verified || 0);

            if (!Array.isArray(data.reports) || data.reports.length === 0) {
                finished = true;
                break;
            }

            contracts.push(...data.reports);

            nextStart = Number(data.next_start);

            updateStats();
            renderContracts();

            scanActivity.textContent =
                `Analyzed ${contracts.length} contracts. Fetching next batch...`;

            if (nextStart > MAX_START || nextStart >= total) {
                finished = true;
                break;
            }

            await wait(1000);
        }

        systemStatus.textContent = finished
            ? "Current discovery range completed"
            : "Scanner stopped";

        scanActivity.textContent = finished
            ? "Discovery of the available indexed range is complete."
            : "Discovery paused.";

    } catch (error) {
        systemStatus.textContent = "Scanner connection error";
        scanActivity.textContent = error.message;

    } finally {
        scanning = false;
    }
}

searchInput.addEventListener("input", renderContracts);

// Automatically start when the dashboard loads.
document.addEventListener("DOMContentLoaded", () => {
    startAutomaticDiscovery();
});

// Also support scripts loaded after DOMContentLoaded.
if (document.readyState !== "loading") {
    startAutomaticDiscovery();
}

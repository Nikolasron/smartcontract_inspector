
const scanForm = document.getElementById("scanForm");
const contractInput = document.getElementById("contract");
const scanButton = document.getElementById("scanButton");
const loading = document.getElementById("loading");
const results = document.getElementById("results");

scanForm.addEventListener("submit", async function (event) {
    event.preventDefault();

    const contract = contractInput.value.trim();

    if (!contract) {
        results.textContent = "Please paste Solidity contract code first.";
        return;
    }

    scanButton.disabled = true;
    scanButton.textContent = "Scanning...";
    loading.hidden = false;
    results.textContent = "Analyzing contract security...";

    try {
        const response = await fetch("/scan", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                contract: contract
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Scan failed.");
        }

        displayResults(data);

    } catch (error) {
        results.textContent = "Error: " + error.message;
    } finally {
        scanButton.disabled = false;
        scanButton.textContent = "Scan Contract";
        loading.hidden = true;
    }
});

function displayResults(data) {
    results.replaceChildren();

    const heading = document.createElement("h3");
    heading.textContent = "Scan Summary";
    results.appendChild(heading);

    const summary = document.createElement("p");
    summary.textContent = data.summary || "Analysis completed.";
    results.appendChild(summary);

    const findings = data.findings || [];

    if (findings.length === 0) {
        const message = document.createElement("p");
        message.textContent = "No suspicious patterns detected.";
        results.appendChild(message);
        return;
    }

    const list = document.createElement("ul");

    findings.forEach(function (finding) {
        const item = document.createElement("li");

        item.textContent =
            `[${finding.severity || "INFO"}] ` +
            `${finding.title || "Finding"}: ` +
            `${finding.description || ""}`;

        list.appendChild(item);
    });

    results.appendChild(list);
}

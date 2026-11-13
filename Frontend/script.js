const uploadForm = document.getElementById("uploadForm");
const emailFile = document.getElementById("emailFile");
const analyzeButton = document.getElementById("analyzeButton");
const statusMessage = document.getElementById("statusMessage");
const resultsContainer = document.getElementById("resultsContainer");

function displayResults(result) {
    const risk = result.risk_assessment;

    resultsContainer.replaceChildren();

    const riskCard = document.createElement("div");
    riskCard.className = `risk-card risk-${risk.risk_level.toLowerCase()}`;

    const riskTitle = document.createElement("h3");
    riskTitle.textContent = `Risk Level: ${risk.risk_level}`;

    const riskScore = document.createElement("p");
    riskScore.textContent = `Risk Score: ${risk.score} / ${risk.max_score}`;

    riskCard.append(riskTitle, riskScore);
    resultsContainer.appendChild(riskCard);

    const emailInfo = document.createElement("div");
    emailInfo.className = "email-info";

    const emailDetails = [
        ["From", result.from],
        ["To", result.to],
        ["Subject", result.subject],
        ["Date", result.date]
    ];

    emailDetails.forEach(([label, value]) => {
        const paragraph = document.createElement("p");
        paragraph.textContent = `${label}: ${value || "Not available"}`;
        emailInfo.appendChild(paragraph);
    });

    resultsContainer.appendChild(emailInfo);

    const indicatorsTitle = document.createElement("h3");
    indicatorsTitle.textContent = "Suspicious Indicators";

    const indicatorsList = document.createElement("ul");

    const explanations = result.risk_assessment.explanations;

    if (explanations.length > 0) {
        explanations.forEach(indicator => {
            const item = document.createElement("li");
            item.textContent = indicator;
            indicatorsList.appendChild(item);
        });
    } else {
        const item = document.createElement("li");
        item.textContent = "No suspicious indicators detected.";
        indicatorsList.appendChild(item);
        }

        resultsContainer.append(indicatorsTitle, indicatorsList);

    const urlsTitle = document.createElement("h3");
    urlsTitle.textContent = "URL Analysis";

    const urlsList = document.createElement("ul");

    result.analyzed_urls.forEach(url => {
    const item = document.createElement("li");

    const urlText = document.createElement("p");
    urlText.textContent = `URL: ${url.url}`;

    const domainText = document.createElement("p");
    domainText.textContent = `Domain: ${url.domain || "Unknown"}`;

    const statusText = document.createElement("p");
    statusText.textContent = `HTTPS: ${url.uses_https ? "Yes" : "No"}`;

    item.append(urlText, domainText, statusText);

    url.suspicious_indicators.forEach(indicator => {
        const warning = document.createElement("p");
        warning.textContent = `Warning: ${indicator}`;
        item.appendChild(warning);
    });

    urlsList.appendChild(item);
});

    resultsContainer.append(urlsTitle, urlsList);


    const attachmentsTitle = document.createElement("h3");
    attachmentsTitle.textContent = "Attachment Analysis";

    const attachmentsList = document.createElement("ul");

    if (result.analyzed_attachments.length > 0) {
        result.analyzed_attachments.forEach(attachment => {
            const item = document.createElement("li");

            const filename = document.createElement("p");
            filename.textContent = `Filename: ${attachment.filename}`;

            const fileType = document.createElement("p");
            fileType.textContent = `File Type: ${attachment.extension}`;

            const fileSize = document.createElement("p");
            fileSize.textContent = `Size: ${attachment.size} bytes`;

            const hash = document.createElement("p");
            hash.textContent = `SHA-256: ${attachment.sha256}`;

            item.append(filename, fileType, fileSize, hash);

            if (attachment.virustotal) {
                const vt = attachment.virustotal;

                const vtResult = document.createElement("p");

                if (vt.status === "success") {
                    vtResult.textContent =
                        `VirusTotal: ${vt.stats.malicious} malicious, ` +
                        `${vt.stats.suspicious} suspicious, ` +
                        `${vt.stats.undetected} undetected`;
                } else {
                    vtResult.textContent = `VirusTotal Status: ${vt.status}`;
                }

                item.appendChild(vtResult);
            }

            attachmentsList.appendChild(item);
        });
    } else {
        const item = document.createElement("li");
        item.textContent = "No attachments found.";
        attachmentsList.appendChild(item);
    }

    resultsContainer.append(attachmentsTitle, attachmentsList);


    const authTitle = document.createElement("h3");
    authTitle.textContent = "Email Authentication";

    const authList = document.createElement("ul");

    const authentication = result.authentication || {};

    ["spf", "dkim", "dmarc"].forEach(method => {
        const item = document.createElement("li");

        const status = authentication[method] || "Not available";

        item.textContent = `${method.toUpperCase()}: ${status.toUpperCase()}`;

        authList.appendChild(item);
    });

    resultsContainer.append(authTitle, authList);

}

uploadForm.addEventListener("submit", async function (event) {
    event.preventDefault();

    const file = emailFile.files[0];

    if (!file) {
        statusMessage.textContent = "Please select an email file.";
        return;
    }

    if (!file.name.toLowerCase().endsWith(".eml")) {
        statusMessage.textContent = "Only .eml files are allowed.";
        return;
    }

    statusMessage.textContent = "Analyzing email...";
    analyzeButton.disabled = true;

    const formData = new FormData();
    formData.append("file", file);

    try {
        const response = await fetch("http://127.0.0.1:8000/analyze", {
            method: "POST",
            body: formData
        });

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.detail || "Analysis failed.");
        }

        statusMessage.textContent = "Analysis completed successfully.";
        displayResults(result);
    } catch (error) {
    statusMessage.textContent =
        error.message === "Failed to fetch"
            ? "Cannot connect to the server. Please check whether the API is running."
            : error.message;

    resultsContainer.replaceChildren();
    } finally {
        analyzeButton.disabled = false;
    }
});
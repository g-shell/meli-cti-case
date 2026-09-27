"use strict";

const byId = (id) => document.getElementById(id);

function setStatus(message, kind = "") {
    const element = byId("request-status");
    element.textContent = message;
    element.className = `status ${kind}`.trim();
}

function formatDate(value) {
    if (!value) {
        return "—";
    }

    const parsed = new Date(value);

    if (Number.isNaN(parsed.getTime())) {
        return String(value);
    }

    return parsed.toLocaleString("pt-BR");
}

async function requestJson(url, options = {}) {
    const response = await fetch(url, options);
    let payload = null;

    try {
        payload = await response.json();
    } catch (_error) {
        payload = null;
    }

    if (!response.ok) {
        const detail = payload && payload.detail
            ? JSON.stringify(payload.detail)
            : `${response.status} ${response.statusText}`;
        throw new Error(detail);
    }

    return payload;
}

function makeElement(tag, text, className = "") {
    const element = document.createElement(tag);

    if (text !== undefined && text !== null) {
        element.textContent = String(text);
    }

    if (className) {
        element.className = className;
    }

    return element;
}

function makeTable(headers, rows) {
    const table = document.createElement("table");
    const head = document.createElement("thead");
    const headRow = document.createElement("tr");

    headers.forEach((header) => {
        headRow.appendChild(makeElement("th", header));
    });

    head.appendChild(headRow);
    table.appendChild(head);

    const body = document.createElement("tbody");

    rows.forEach((row) => {
        const tableRow = document.createElement("tr");

        row.forEach((value, index) => {
            const cell = makeElement(
                "td",
                value === null || value === undefined || value === ""
                    ? "—"
                    : value,
                index === 1 ? "mono" : "",
            );
            tableRow.appendChild(cell);
        });

        body.appendChild(tableRow);
    });

    table.appendChild(body);
    return table;
}

function addAction(container, label, href) {
    const link = makeElement("a", label);
    link.href = href;
    link.target = "_blank";
    link.rel = "noreferrer";
    container.appendChild(link);
}

function renderResult(result) {
    const panel = byId("result-panel");
    const summary = byId("result-summary");
    const details = byId("result-details");
    const actions = byId("result-actions");

    panel.classList.remove("hidden");
    summary.replaceChildren();
    details.replaceChildren();
    actions.replaceChildren();

    const analysis = result.analysis || {};
    const execution = result.analysis_execution || {};
    const usage = execution.usage || {};
    const families = Array.isArray(analysis.family_candidates)
        ? analysis.family_candidates
        : [];

    const values = [
        ["Status", result.status || "—"],
        ["Veredito", analysis.verdict || "unknown"],
        ["Confiança", analysis.confidence || "low"],
        ["Família", families[0] ? families[0].family : "não atribuída"],
        ["Motor", execution.engine || "deterministic"],
        ["Modelo", execution.model || "—"],
        ["Tokens", usage.total_tokens || 0],
        ["Observáveis", Array.isArray(result.observables) ? result.observables.length : 0],
    ];

    values.forEach(([label, value]) => {
        const card = makeElement("article", null, "result-card metric");
        card.appendChild(makeElement("span", label));
        card.appendChild(makeElement("strong", value));
        summary.appendChild(card);
    });

    addAction(actions, "Relatório HTML", `/api/v1/scans/${result.scan_id}/report/html`);
    addAction(actions, "Relatório JSON", `/api/v1/scans/${result.scan_id}/report`);
    addAction(actions, "Exportar CSV", `/api/v1/scans/${result.scan_id}/export.csv`);
    addAction(actions, "Resultado bruto", `/api/v1/scans/${result.scan_id}`);

    if (analysis.executive_summary) {
        const section = makeElement("section", null, "result-details-section");
        section.appendChild(makeElement("h3", "Resumo executivo"));
        section.appendChild(makeElement("p", analysis.executive_summary));
        details.appendChild(section);
    }

    const providerRows = (result.providers || []).map((provider) => [
        provider.provider,
        provider.status,
        formatDate(provider.fetched_at),
        provider.error || "—",
    ]);

    if (providerRows.length) {
        const section = makeElement("section", null, "result-details-section");
        section.appendChild(makeElement("h3", "Provedores"));
        section.appendChild(
            makeTable(["Provedor", "Status", "Coleta", "Erro"], providerRows),
        );
        details.appendChild(section);
    }

    const sourceErrors = Array.isArray(result.source_errors)
        ? result.source_errors
        : [];

    if (sourceErrors.length) {
        const section = makeElement("section", null, "result-details-section");
        section.appendChild(makeElement("h3", "Limitações da execução"));
        const list = document.createElement("ul");
        sourceErrors.forEach((error) => list.appendChild(makeElement("li", error)));
        section.appendChild(list);
        details.appendChild(section);
    }
}

async function loadStats() {
    try {
        const stats = await requestJson("/api/v1/stats");
        byId("metric-scans").textContent = stats.total_scans;
        byId("metric-hashes").textContent = stats.unique_hashes;
        byId("metric-malicious").textContent = stats.verdict_counts.malicious || 0;
        byId("metric-partial").textContent = stats.status_counts.partial || 0;
    } catch (_error) {
        byId("metric-scans").textContent = "!";
    }
}

async function loadHistory() {
    const container = byId("history");
    container.replaceChildren(makeElement("p", "Carregando histórico...", "muted"));

    try {
        const scans = await requestJson("/api/v1/scans?limit=50");

        if (!scans.length) {
            container.replaceChildren(
                makeElement("p", "Nenhum scan persistido.", "muted"),
            );
            return;
        }

        const table = makeTable(
            ["Data", "Hash", "Status", "Veredito", "Confiança"],
            scans.map((scan) => [
                formatDate(scan.created_at),
                scan.requested_hash,
                scan.status,
                scan.analysis ? scan.analysis.verdict : "unknown",
                scan.analysis ? scan.analysis.confidence : "low",
            ]),
        );

        const rows = table.querySelectorAll("tbody tr");
        rows.forEach((row, index) => {
            row.style.cursor = "pointer";
            row.tabIndex = 0;
            const open = () => renderResult(scans[index]);
            row.addEventListener("click", open);
            row.addEventListener("keydown", (event) => {
                if (event.key === "Enter" || event.key === " ") {
                    open();
                }
            });
        });

        container.replaceChildren(table);
    } catch (error) {
        container.replaceChildren(
            makeElement("p", `Falha ao carregar: ${error.message}`, "status error"),
        );
    }
}

byId("triage-form").addEventListener("submit", async (event) => {
    event.preventDefault();

    const providers = Array.from(
        document.querySelectorAll('input[name="provider"]:checked'),
    ).map((input) => input.value);

    if (!providers.length) {
        setStatus("Selecione ao menos um provedor.", "error");
        return;
    }

    const submitButton = byId("submit-button");
    submitButton.disabled = true;
    setStatus("Coletando e analisando o artefato...");

    const payload = {
        hash: byId("artifact-hash").value.trim(),
        providers,
        use_genai: byId("use-genai").checked,
        force_refresh: byId("force-refresh").checked,
    };

    try {
        const result = await requestJson("/api/v1/triage", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify(payload),
        });
        renderResult(result);
        setStatus(`Triagem concluída: ${result.scan_id}`, "success");
        await Promise.all([loadHistory(), loadStats()]);
    } catch (error) {
        setStatus(`Falha na triagem: ${error.message}`, "error");
    } finally {
        submitButton.disabled = false;
    }
});

byId("observable-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const container = byId("observable-results");
    const value = byId("observable-value").value.trim();
    const type = byId("observable-type").value;
    const query = new URLSearchParams({value, limit: "100"});

    if (type) {
        query.set("type", type);
    }

    container.replaceChildren(makeElement("p", "Buscando...", "muted"));

    try {
        const matches = await requestJson(`/api/v1/observables/search?${query}`);

        if (!matches.length) {
            container.replaceChildren(
                makeElement("p", "Nenhuma ocorrência encontrada.", "muted"),
            );
            return;
        }

        container.replaceChildren(
            makeTable(
                ["Data", "Valor", "Tipo", "Fonte", "Scan"],
                matches.map((match) => [
                    formatDate(match.created_at),
                    match.observable.value,
                    match.observable.type,
                    match.observable.source,
                    match.scan_id,
                ]),
            ),
        );
    } catch (error) {
        container.replaceChildren(
            makeElement("p", `Falha na busca: ${error.message}`, "status error"),
        );
    }
});

byId("refresh-history").addEventListener("click", loadHistory);

Promise.all([loadHistory(), loadStats()]);

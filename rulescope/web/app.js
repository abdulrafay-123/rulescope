(() => {
  const $ = (id) => document.getElementById(id);
  let catalog = [];

  async function getJson(url) {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`${url} failed`);
    return res.json();
  }

  async function getText(url) {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`${url} failed`);
    return res.text();
  }

  function profile() {
    try {
      return JSON.parse($("profile-input").value || "{}");
    } catch (err) {
      throw new Error("Asset profile JSON is invalid");
    }
  }

  function setStatus(msg) {
    $("status").textContent = msg;
  }

  function renderSummary(summary) {
    const nodes = $("summary-stats").querySelectorAll("strong");
    nodes[0].textContent = summary.total_rules;
    nodes[1].textContent = summary.with_cve;
    nodes[2].textContent = summary.high_severity;
    nodes[3].textContent = (summary.by_relevance?.noise || 0) + (summary.outdated || 0);
  }

  function filteredRules() {
    const q = ($("filter-q").value || "").toLowerCase();
    const sev = $("filter-severity").value;
    const rel = $("filter-relevance").value;
    return catalog.filter((r) => {
      if (sev && r.severity !== sev) return false;
      if (rel && r.relevance_label !== rel) return false;
      if (!q) return true;
      const blob = `${r.sid} ${r.msg} ${(r.cves || []).join(" ")} ${(r.platforms || []).join(" ")}`.toLowerCase();
      return blob.includes(q);
    });
  }

  function renderTable() {
    const rows = filteredRules();
    const tbody = $("rules-tbody");
    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="7" class="empty">No rules match the current filters.</td></tr>`;
      return;
    }
    tbody.innerHTML = rows
      .map((r) => {
        const age = r.age_days == null ? "—" : `${r.age_days}d`;
        const cves = (r.cves || [])
          .map((c) => `<a class="mono" href="https://nvd.nist.gov/vuln/detail/${c}" target="_blank" rel="noreferrer">${c}</a>`)
          .join(" ") || "—";
        const outdated = r.outdated ? `<div class="outdated">outdated?</div>` : "";
        return `<tr>
          <td class="mono">${r.sid}</td>
          <td><div class="msg">${escapeHtml(r.msg)}</div>${outdated}</td>
          <td><span class="pill sev-${r.severity}">${r.severity}</span></td>
          <td><span class="pill rel-${r.relevance_label}">${r.relevance_label} ${r.relevance_score}</span></td>
          <td>${(r.platforms || []).join(", ") || "—"}</td>
          <td>${cves}</td>
          <td class="mono">${age}</td>
        </tr>`;
      })
      .join("");
  }

  function escapeHtml(s) {
    return String(s)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;");
  }

  async function analyze() {
    setStatus("Analyzing…");
    const res = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rules_text: $("rules-input").value, profile: profile() }),
    });
    if (!res.ok) throw new Error(await res.text());
    const data = await res.json();
    catalog = data.rules || [];
    renderSummary(data.summary);
    renderTable();
    setStatus(`Analyzed ${catalog.length} rules.`);
  }

  async function exportConf(kind) {
    setStatus(`Exporting ${kind}.conf…`);
    const res = await fetch(`/api/export/${kind}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rules_text: $("rules-input").value, profile: profile() }),
    });
    if (!res.ok) throw new Error(await res.text());
    const text = await res.text();
    const blob = new Blob([text], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `${kind}.conf`;
    a.click();
    URL.revokeObjectURL(a.href);
    setStatus(`Downloaded ${kind}.conf`);
  }

  async function correlateEve() {
    setStatus("Correlating EVE alerts…");
    const res = await fetch("/api/eve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        eve_text: $("eve-input").value,
        rules_text: $("rules-input").value,
        profile: profile(),
      }),
    });
    if (!res.ok) throw new Error(await res.text());
    const data = await res.json();
    const root = $("eve-results");
    if (!data.alerts?.length) {
      root.innerHTML = `<p class="empty">No alerts found.</p>`;
      setStatus("No alerts.");
      return;
    }
    root.innerHTML = data.alerts
      .map((a) => {
        const rel = a.rule
          ? `${a.rule.relevance_label} ${a.rule.relevance_score}`
          : "unmapped";
        const why = a.rule?.relevance_reasons?.slice(0, 3).join("; ") || "no local rule match";
        return `<div class="eve-item">
          <strong>${escapeHtml(a.signature || "alert")}</strong>
          <div class="eve-meta">${escapeHtml(a.timestamp || "")} · sid=${a.signature_id ?? "?"} · ${escapeHtml(a.src_ip || "?")} → ${escapeHtml(a.dest_ip || "?")} · relevance ${escapeHtml(rel)}</div>
          <div class="eve-meta">${escapeHtml(why)}</div>
        </div>`;
      })
      .join("");
    setStatus(`Correlated ${data.alerts.length} alerts.`);
  }

  function bind() {
    $("load-sample-rules").onclick = async () => {
      $("rules-input").value = await getText("/api/sample/rules");
      setStatus("Loaded demo rules.");
    };
    $("load-sample-profile").onclick = async () => {
      $("profile-input").value = JSON.stringify(await getJson("/api/sample/profile"), null, 2);
      setStatus("Loaded homelab profile.");
    };
    $("load-sample-eve").onclick = async () => {
      $("eve-input").value = await getText("/api/sample/eve");
      setStatus("Loaded sample EVE alerts.");
    };
    $("analyze-btn").onclick = () => analyze().catch((e) => setStatus(e.message));
    $("export-disable-btn").onclick = () => exportConf("disable").catch((e) => setStatus(e.message));
    $("export-enable-btn").onclick = () => exportConf("enable").catch((e) => setStatus(e.message));
    $("eve-btn").onclick = () => correlateEve().catch((e) => setStatus(e.message));
    ["filter-q", "filter-severity", "filter-relevance"].forEach((id) => {
      $(id).addEventListener("input", renderTable);
      $(id).addEventListener("change", renderTable);
    });
  }

  async function boot() {
    bind();
    $("profile-input").value = JSON.stringify(await getJson("/api/sample/profile"), null, 2);
    $("rules-input").value = await getText("/api/sample/rules");
    $("eve-input").value = await getText("/api/sample/eve");
    await analyze();
  }

  boot().catch((e) => setStatus(e.message));
})();

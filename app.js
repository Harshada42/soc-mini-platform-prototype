// SOC Mini Platform - Step 2
// Views: Logs, Alerts, Rules
// Generates Alerts in-memory from logs.json + rules.json (no backend)

const els = {
    // Sidebar / header
    navItems: Array.from(document.querySelectorAll(".nav-item[data-view]")),
    pageTitle: document.getElementById("pageTitle"),
    pageSubtitle: document.getElementById("pageSubtitle"),
    statusText: document.getElementById("statusText"),
    reloadBtn: document.getElementById("reloadBtn"),
    exportBtn: document.getElementById("exportBtn"),
  
    // Views
    viewLogs: document.getElementById("view-logs"),
    viewAlerts: document.getElementById("view-alerts"),
    viewRules: document.getElementById("view-rules"),
  
    // Logs controls/table
    resultMeta: document.getElementById("resultMeta"),
    tbody: document.getElementById("logsTbody"),
    searchInput: document.getElementById("searchInput"),
    severitySelect: document.getElementById("severitySelect"),
    sourceSelect: document.getElementById("sourceSelect"),
    pageSizeSelect: document.getElementById("pageSizeSelect"),
    prevBtn: document.getElementById("prevBtn"),
    nextBtn: document.getElementById("nextBtn"),
    pageInfo: document.getElementById("pageInfo"),
  
    // Alerts view
    alertsMeta: document.getElementById("alertsMeta"),
    alertsList: document.getElementById("alertsList"),
    alertSearchInput: document.getElementById("alertSearchInput"),
    alertSeveritySelect: document.getElementById("alertSeveritySelect"),
    alertStatusSelect: document.getElementById("alertStatusSelect"),
    regenerateAlertsBtn: document.getElementById("regenerateAlertsBtn"),
  
    // Rules view
    rulesMeta: document.getElementById("rulesMeta"),
    rulesList: document.getElementById("rulesList"),
    addRuleBtn: document.getElementById("addRuleBtn"),
    copyRulesJsonBtn: document.getElementById("copyRulesJsonBtn"),
  
    // Details Modal
    modalOverlay: document.getElementById("modalOverlay"),
    closeModalBtn: document.getElementById("closeModalBtn"),
    modalTitle: document.getElementById("modalTitle"),
    modalSubtitle: document.getElementById("modalSubtitle"),
    modalKv: document.getElementById("modalKv"),
    modalJson: document.getElementById("modalJson"),
    copyJsonBtn: document.getElementById("copyJsonBtn"),
  
    // Add Rule Modal
    ruleOverlay: document.getElementById("ruleOverlay"),
    closeRuleBtn: document.getElementById("closeRuleBtn"),
    saveRuleBtn: document.getElementById("saveRuleBtn"),
    rName: document.getElementById("rName"),
    rType: document.getElementById("rType"),
    rSeverity: document.getElementById("rSeverity"),
    rSource: document.getElementById("rSource"),
    rEventType: document.getElementById("rEventType"),
    rMitre: document.getElementById("rMitre"),
    rContains: document.getElementById("rContains"),
    rThreshold: document.getElementById("rThreshold"),
    rWindow: document.getElementById("rWindow"),
    rGroupBy: document.getElementById("rGroupBy"),
    rField: document.getElementById("rField"),
    rMinLen: document.getElementById("rMinLen")
  };
  
  const state = {
    view: "logs",
  
    logs: [],
    rules: [],
    alerts: [],
  
    // Logs filters
    logSearch: "",
    logSeverity: "ALL",
    logSource: "ALL",
    logPage: 1,
    logPageSize: Number(els.pageSizeSelect.value),
  
    // Alerts filters
    alertSearch: "",
    alertSeverity: "ALL",
    alertStatus: "ALL"
  };
  
  document.addEventListener("DOMContentLoaded", init);
  
  function init() {
    wireEvents();
    loadAll();
    setView("logs");
  }
  
  function wireEvents() {
    // Sidebar nav
    els.navItems.forEach(btn => {
      btn.addEventListener("click", () => {
        if (btn.disabled) return;
        setView(btn.dataset.view);
      });
    });
  
    // Reload
    els.reloadBtn.addEventListener("click", loadAll);
  
    // Export
    els.exportBtn.addEventListener("click", exportCurrentViewCSV);
  
    // Logs filters
    els.searchInput.addEventListener("input", e => {
      state.logSearch = e.target.value;
      state.logPage = 1;
      renderLogs();
    });
    els.severitySelect.addEventListener("change", e => {
      state.logSeverity = e.target.value;
      state.logPage = 1;
      renderLogs();
    });
    els.sourceSelect.addEventListener("change", e => {
      state.logSource = e.target.value;
      state.logPage = 1;
      renderLogs();
    });
    els.pageSizeSelect.addEventListener("change", e => {
      state.logPageSize = Number(e.target.value);
      state.logPage = 1;
      renderLogs();
    });
  
    els.prevBtn.addEventListener("click", () => {
      state.logPage = Math.max(1, state.logPage - 1);
      renderLogs();
    });
    els.nextBtn.addEventListener("click", () => {
      state.logPage = Math.min(getLogTotalPages(), state.logPage + 1);
      renderLogs();
    });
  
    // Alerts filters
    els.alertSearchInput.addEventListener("input", e => {
      state.alertSearch = e.target.value;
      renderAlerts();
    });
    els.alertSeveritySelect.addEventListener("change", e => {
      state.alertSeverity = e.target.value;
      renderAlerts();
    });
    els.alertStatusSelect.addEventListener("change", e => {
      state.alertStatus = e.target.value;
      renderAlerts();
    });
    els.regenerateAlertsBtn.addEventListener("click", () => {
      state.alerts = generateAlerts(state.logs, state.rules);
      setStatus(`Generated ${state.alerts.length} alerts`);
      renderAlerts();
    });
  
    // Rules view
    els.addRuleBtn.addEventListener("click", () => openRuleModal());
    els.copyRulesJsonBtn.addEventListener("click", async () => {
      await copyText(JSON.stringify(state.rules, null, 2));
      els.copyRulesJsonBtn.textContent = "Copied!";
      setTimeout(() => (els.copyRulesJsonBtn.textContent = "Copy Rules JSON"), 900);
    });
  
    // Details modal
    els.closeModalBtn.addEventListener("click", closeModal);
    els.modalOverlay.addEventListener("click", (e) => {
      if (e.target === els.modalOverlay) closeModal();
    });
    els.copyJsonBtn.addEventListener("click", async () => {
      await copyText(els.modalJson.textContent);
      els.copyJsonBtn.textContent = "Copied!";
      setTimeout(() => (els.copyJsonBtn.textContent = "Copy"), 900);
    });
  
    // Rule modal
    els.closeRuleBtn.addEventListener("click", closeRuleModal);
    els.ruleOverlay.addEventListener("click", (e) => {
      if (e.target === els.ruleOverlay) closeRuleModal();
    });
    els.saveRuleBtn.addEventListener("click", saveRuleFromUI);
  }
  
  async function loadAll() {
    setStatus("Loading logs.json + rules.json…");
    try {
      const [logsRes, rulesRes] = await Promise.all([
        fetch("data/logs.json", { cache: "no-store" }),
        fetch("data/rules.json", { cache: "no-store" })
      ]);
  
      if (!logsRes.ok) throw new Error(`logs.json HTTP ${logsRes.status}`);
      if (!rulesRes.ok) throw new Error(`rules.json HTTP ${rulesRes.status}`);
  
      const logs = await logsRes.json();
      const rules = await rulesRes.json();
  
      state.logs = Array.isArray(logs) ? logs.map(normalizeLog).filter(Boolean) : [];
      state.rules = Array.isArray(rules) ? rules.map(normalizeRule).filter(Boolean) : [];
  
      populateSourceFilter();
  
      state.alerts = generateAlerts(state.logs, state.rules);
  
      setStatus(`Loaded ${state.logs.length} logs • ${state.rules.length} rules • ${state.alerts.length} alerts`);
  
      renderLogs();
      renderRules();
      renderAlerts();
    } catch (err) {
      console.error(err);
      setStatus("Load failed. Run via Live Server / http server (not file://).");
    }
  }
  
  function setView(view) {
    state.view = view;
  
    // Sidebar active state
    els.navItems.forEach(b => b.classList.toggle("active", b.dataset.view === view));
  
    // Show/hide views
    show(els.viewLogs, view === "logs");
    show(els.viewAlerts, view === "alerts");
    show(els.viewRules, view === "rules");
  
    // Header texts
    if (view === "logs") {
      els.pageTitle.textContent = "Logs";
      els.pageSubtitle.textContent = "Search, filter, and inspect events";
    } else if (view === "alerts") {
      els.pageTitle.textContent = "Alerts";
      els.pageSubtitle.textContent = "Generated from rules (synthetic detections)";
    } else if (view === "rules") {
      els.pageTitle.textContent = "Rules";
      els.pageSubtitle.textContent = "Enable/disable rules and generate alerts";
    }
  
    // Export button label
    els.exportBtn.textContent = "Export CSV";
  }
  
  function show(el, on) {
    el.classList.toggle("hidden", !on);
  }
  
  /* ---------------------------
     LOGS RENDER
  ---------------------------- */
  
  function renderLogs() {
    const filtered = filterLogs(state.logs);
  
    const total = filtered.length;
    const totalPages = Math.max(1, Math.ceil(total / state.logPageSize));
    state.logPage = Math.min(state.logPage, totalPages);
  
    const start = (state.logPage - 1) * state.logPageSize;
    const end = start + state.logPageSize;
    const pageRows = filtered.slice(start, end);
  
    els.tbody.innerHTML = "";
  
    if (total === 0) {
      els.tbody.innerHTML = `
        <tr>
          <td colspan="9" style="color:#a6b3c2; padding:18px;">
            No logs found. Add data to <span class="mono">data/logs.json</span> and click Reload.
          </td>
        </tr>`;
      els.resultMeta.textContent = "0 results";
      els.pageInfo.textContent = "Page 1 / 1";
      els.prevBtn.disabled = true;
      els.nextBtn.disabled = true;
      return;
    }
  
    for (const log of pageRows) {
      const tr = document.createElement("tr");
      tr.addEventListener("click", () => openDetailsModal("log", log));
      tr.innerHTML = `
        <td class="mono">${escapeHtml(formatTime(log.timestamp))}</td>
        <td>${escapeHtml(log.source)}</td>
        <td class="mono">${escapeHtml(log.event_type)}</td>
        <td>${escapeHtml(log.user || "-")}</td>
        <td class="mono">${escapeHtml(log.host || "-")}</td>
        <td class="mono">${escapeHtml(log.src_ip || "-")}</td>
        <td class="mono">${escapeHtml(log.dst_ip || "-")}</td>
        <td>${renderSeverityBadge(log.severity)}</td>
        <td><span class="truncate">${escapeHtml(log.message)}</span></td>
      `;
      els.tbody.appendChild(tr);
    }
  
    const showingStart = start + 1;
    const showingEnd = Math.min(end, total);
    els.resultMeta.textContent = `${total} results • showing ${showingStart}-${showingEnd}`;
  
    els.pageInfo.textContent = `Page ${state.logPage} / ${totalPages}`;
    els.prevBtn.disabled = state.logPage <= 1;
    els.nextBtn.disabled = state.logPage >= totalPages;
  }
  
  function filterLogs(logs) {
    const q = norm(state.logSearch);
    const sev = state.logSeverity;
    const src = state.logSource;
  
    let out = logs.slice();
  
    if (sev !== "ALL") out = out.filter(l => norm(l.severity) === norm(sev));
    if (src !== "ALL") out = out.filter(l => l.source === src);
  
    if (q) {
      out = out.filter(l => {
        const hay = norm([
          l.id, l.timestamp, l.source, l.event_type, l.user, l.host,
          l.src_ip, l.dst_ip, l.severity, l.message
        ].join(" "));
        return hay.includes(q);
      });
    }
  
    out.sort((a, b) => (Date.parse(b.timestamp) || 0) - (Date.parse(a.timestamp) || 0));
    return out;
  }
  
  function getLogTotalPages() {
    return Math.max(1, Math.ceil(filterLogs(state.logs).length / state.logPageSize));
  }
  
  function populateSourceFilter() {
    const sources = Array.from(new Set(state.logs.map(l => l.source).filter(Boolean))).sort();
    const current = els.sourceSelect.value;
    els.sourceSelect.innerHTML = `<option value="ALL">All</option>`;
    for (const s of sources) {
      const opt = document.createElement("option");
      opt.value = s;
      opt.textContent = s;
      els.sourceSelect.appendChild(opt);
    }
    els.sourceSelect.value = sources.includes(current) ? current : "ALL";
  }
  
  /* ---------------------------
     RULES RENDER + TOGGLE
  ---------------------------- */
  
  function renderRules() {
    els.rulesList.innerHTML = "";
  
    els.rulesMeta.textContent = `${state.rules.length} rules`;
  
    for (const r of state.rules) {
      const card = document.createElement("div");
      card.className = "card";
      card.innerHTML = `
        <div class="card-top">
          <div>
            <div class="card-title">${escapeHtml(r.name)}</div>
            <p class="card-sub">
              <span class="mono">${escapeHtml(r.rule_id)}</span> •
              type: <span class="mono">${escapeHtml(r.type)}</span> •
              source: <span class="mono">${escapeHtml(r.match?.source || "-")}</span> •
              event: <span class="mono">${escapeHtml(r.match?.event_type || "-")}</span>
            </p>
            <div class="chips">
              <span class="chip">${escapeHtml(r.severity)}</span>
              ${(r.mitre || []).map(t => `<span class="chip mitre">${escapeHtml(t)}</span>`).join("")}
            </div>
          </div>
          <div class="card-right">
            <div class="switch ${r.enabled ? "on" : ""}" title="Toggle rule"></div>
          </div>
        </div>
      `;
  
      // Toggle click
      const sw = card.querySelector(".switch");
      sw.addEventListener("click", (e) => {
        e.stopPropagation();
        r.enabled = !r.enabled;
        sw.classList.toggle("on", r.enabled);
  
        state.alerts = generateAlerts(state.logs, state.rules);
        setStatus(`Rules updated • alerts: ${state.alerts.length}`);
        renderAlerts();
      });
  
      // Card click opens details
      card.addEventListener("click", () => openDetailsModal("rule", r));
  
      els.rulesList.appendChild(card);
    }
  }
  
  /* ---------------------------
     ALERTS RENDER
  ---------------------------- */
  
  function renderAlerts() {
    const filtered = filterAlerts(state.alerts);
  
    els.alertsMeta.textContent = `${filtered.length} alerts`;
  
    els.alertsList.innerHTML = "";
  
    if (filtered.length === 0) {
      els.alertsList.innerHTML = `
        <div class="card" style="cursor:default;">
          <div class="card-title">No alerts</div>
          <p class="card-sub">Enable rules or add more synthetic logs.</p>
        </div>
      `;
      return;
    }
  
    for (const a of filtered) {
      const card = document.createElement("div");
      card.className = "card";
      card.innerHTML = `
        <div class="card-top">
          <div>
            <div class="card-title">${escapeHtml(a.title)}</div>
            <p class="card-sub">
              <span class="mono">${escapeHtml(formatTime(a.timestamp))}</span> •
              status: <span class="mono">${escapeHtml(a.status)}</span> •
              rule: <span class="mono">${escapeHtml(a.rule_id)}</span>
            </p>
            <div class="chips">
              <span class="chip">${renderSeverityText(a.severity)}</span>
              ${(a.mitre_tags || []).map(t => `<span class="chip mitre">${escapeHtml(t)}</span>`).join("")}
              ${a.entities?.src_ip ? `<span class="chip mono">src:${escapeHtml(a.entities.src_ip)}</span>` : ""}
              ${a.entities?.user ? `<span class="chip mono">user:${escapeHtml(a.entities.user)}</span>` : ""}
            </div>
          </div>
          <div class="card-right">
            ${renderSeverityBadge(a.severity)}
          </div>
        </div>
      `;
  
      card.addEventListener("click", () => openDetailsModal("alert", a));
      els.alertsList.appendChild(card);
    }
  }
  
  function filterAlerts(alerts) {
    const q = norm(state.alertSearch);
    const sev = state.alertSeverity;
    const st = state.alertStatus;
  
    let out = alerts.slice();
  
    if (sev !== "ALL") out = out.filter(a => norm(a.severity) === norm(sev));
    if (st !== "ALL") out = out.filter(a => norm(a.status) === norm(st));
  
    if (q) {
      out = out.filter(a => {
        const hay = norm([
          a.alert_id, a.title, a.rule_id, a.severity, a.status,
          a.entities?.src_ip, a.entities?.dst_ip, a.entities?.user, a.entities?.host,
          ...(a.mitre_tags || [])
        ].join(" "));
        return hay.includes(q);
      });
    }
  
    out.sort((a, b) => (Date.parse(b.timestamp) || 0) - (Date.parse(a.timestamp) || 0));
    return out;
  }
  
  /* ---------------------------
     DETECTION ENGINE (Rules -> Alerts)
  ---------------------------- */
  
  function generateAlerts(logs, rules) {
    const enabled = rules.filter(r => r.enabled);
  
    const alerts = [];
    let alertCounter = 5000;
  
    const logsSorted = logs.slice().sort((a, b) => (Date.parse(a.timestamp) || 0) - (Date.parse(b.timestamp) || 0));
  
    for (const rule of enabled) {
      if (rule.type === "simple_contains") {
        const matches = logsSorted.filter(l => logMatchesRule(l, rule));
        for (const l of matches) {
          alerts.push(makeAlert({
            alert_id: `ALERT-${++alertCounter}`,
            rule,
            timestamp: l.timestamp,
            title: `${rule.name} (${l.source})`,
            related_log_ids: [l.id],
            entities: pickEntities(l)
          }));
        }
      }
  
      if (rule.type === "field_length") {
        const matches = logsSorted.filter(l => fieldLengthMatch(l, rule));
        for (const l of matches) {
          alerts.push(makeAlert({
            alert_id: `ALERT-${++alertCounter}`,
            rule,
            timestamp: l.timestamp,
            title: `${rule.name} (${l.source})`,
            related_log_ids: [l.id],
            entities: pickEntities(l)
          }));
        }
      }
  
      if (rule.type === "threshold_count") {
        const base = logsSorted.filter(l => logMatchesRule(l, rule));
        const groupBy = rule.group_by || "src_ip";
        const winMs = (Number(rule.window_minutes) || 2) * 60 * 1000;
        const threshold = Number(rule.threshold) || 5;
  
        // Group logs by key
        const groups = new Map();
        for (const l of base) {
          const key = (l[groupBy] || "").toString().trim() || "(empty)";
          if (!groups.has(key)) groups.set(key, []);
          groups.get(key).push(l);
        }
  
        // Sliding window per group
        for (const [key, arr] of groups.entries()) {
          const times = arr.map(l => Date.parse(l.timestamp) || 0);
          let i = 0;
  
          // Avoid duplicate alerts: once triggered, skip until window moves beyond trigger start
          let lastTriggerAt = -Infinity;
  
          for (let j = 0; j < arr.length; j++) {
            while (times[j] - times[i] > winMs) i++;
  
            const count = j - i + 1;
            if (count >= threshold) {
              const triggerAt = times[j];
              if (triggerAt - lastTriggerAt < winMs) continue;
  
              lastTriggerAt = triggerAt;
  
              const windowLogs = arr.slice(i, j + 1);
              const relatedIds = windowLogs.map(x => x.id);
  
              const title = `${rule.name} • ${groupBy}:${key}`;
              alerts.push(makeAlert({
                alert_id: `ALERT-${++alertCounter}`,
                rule,
                timestamp: arr[j].timestamp,
                title,
                related_log_ids: relatedIds,
                entities: {
                  ...pickEntities(arr[j]),
                  [groupBy]: key
                }
              }));
            }
          }
        }
      }
    }
  
    // De-duplicate very similar alerts (optional safety)
    return dedupeAlerts(alerts);
  }
  
  function makeAlert({ alert_id, rule, timestamp, title, related_log_ids, entities }) {
    return {
      alert_id,
      rule_id: rule.rule_id,
      timestamp,
      title,
      severity: rule.severity,
      status: "new",
      mitre_tags: rule.mitre || [],
      entities: entities || {},
      related_log_ids: related_log_ids || []
    };
  }
  
  function logMatchesRule(log, rule) {
    const m = rule.match || {};
    if (m.source && log.source !== m.source) return false;
    if (m.event_type && log.event_type !== m.event_type) return false;
  
    const contains = Array.isArray(m.contains) ? m.contains : [];
    if (contains.length > 0) {
      const msg = norm(log.message);
      for (const c of contains) {
        if (!msg.includes(norm(c))) return false;
      }
    }
    return true;
  }
  
  function fieldLengthMatch(log, rule) {
    const m = rule.match || {};
    if (m.source && log.source !== m.source) return false;
    if (m.event_type && log.event_type !== m.event_type) return false;
  
    const field = m.field || "message";
    const minLen = Number(m.min_length) || 80;
    const val = String(log[field] || "");
    return val.length >= minLen;
  }
  
  function dedupeAlerts(alerts) {
    const seen = new Set();
    const out = [];
    for (const a of alerts) {
      const key = `${a.rule_id}|${a.timestamp}|${a.title}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(a);
    }
    return out;
  }
  
  function pickEntities(log) {
    return {
      src_ip: log.src_ip || "",
      dst_ip: log.dst_ip || "",
      user: log.user || "",
      host: log.host || "",
      source: log.source || "",
      event_type: log.event_type || ""
    };
  }
  
  /* ---------------------------
     MODALS
  ---------------------------- */
  
  function openDetailsModal(kind, obj) {
    if (kind === "log") {
      els.modalTitle.textContent = `Log ${obj.id || ""}`.trim() || "Log Details";
      els.modalSubtitle.textContent = `${formatTime(obj.timestamp)} • ${obj.source} • ${obj.event_type}`.trim();
  
      setKv([
        ["Severity", obj.severity],
        ["User", obj.user || "-"],
        ["Host", obj.host || "-"],
        ["Source IP", obj.src_ip || "-"],
        ["Destination IP", obj.dst_ip || "-"],
        ["Timestamp (UTC)", obj.timestamp || "-"]
      ], obj);
    }
  
    if (kind === "alert") {
      els.modalTitle.textContent = `Alert ${obj.alert_id}`;
      els.modalSubtitle.textContent = `${formatTime(obj.timestamp)} • ${obj.severity} • ${obj.status}`;
  
      setKv([
        ["Title", obj.title],
        ["Rule ID", obj.rule_id],
        ["Severity", obj.severity],
        ["Status", obj.status],
        ["MITRE", (obj.mitre_tags || []).join(", ") || "-"],
        ["Related Logs", (obj.related_log_ids || []).length]
      ], obj);
    }
  
    if (kind === "rule") {
      els.modalTitle.textContent = `Rule ${obj.rule_id}`;
      els.modalSubtitle.textContent = `${obj.type} • ${obj.severity} • ${obj.enabled ? "enabled" : "disabled"}`;
  
      setKv([
        ["Name", obj.name],
        ["Type", obj.type],
        ["Severity", obj.severity],
        ["Enabled", String(obj.enabled)],
        ["Source", obj.match?.source || "-"],
        ["Event Type", obj.match?.event_type || "-"],
        ["MITRE", (obj.mitre || []).join(", ") || "-"]
      ], obj);
    }
  
    els.modalOverlay.classList.remove("hidden");
  }
  
  function setKv(pairs, rawObj) {
    els.modalKv.innerHTML = pairs.map(([k, v]) => `
      <div class="kv-row">
        <div class="kv-key">${escapeHtml(k)}</div>
        <div class="kv-val mono">${escapeHtml(String(v ?? "-"))}</div>
      </div>
    `).join("");
    els.modalJson.textContent = JSON.stringify(rawObj, null, 2);
  }
  
  function closeModal() {
    els.modalOverlay.classList.add("hidden");
  }
  
  function openRuleModal() {
    // quick defaults
    els.rName.value = "";
    els.rType.value = "simple_contains";
    els.rSeverity.value = "High";
    els.rSource.value = "";
    els.rEventType.value = "";
    els.rMitre.value = "";
    els.rContains.value = "";
    els.rThreshold.value = 5;
    els.rWindow.value = 2;
    els.rGroupBy.value = "src_ip";
    els.rField.value = "message";
    els.rMinLen.value = 80;
  
    els.ruleOverlay.classList.remove("hidden");
  }
  
  function closeRuleModal() {
    els.ruleOverlay.classList.add("hidden");
  }
  
  function saveRuleFromUI() {
    const name = els.rName.value.trim();
    if (!name) return alert("Rule name is required.");
  
    const type = els.rType.value;
    const severity = els.rSeverity.value;
    const source = els.rSource.value.trim();
    const eventType = els.rEventType.value.trim();
  
    const mitre = splitCsv(els.rMitre.value);
    const contains = splitCsv(els.rContains.value);
  
    const rule = {
      rule_id: `RULE-${String(state.rules.length + 1).padStart(2, "0")}`,
      name,
      type,
      enabled: true,
      severity,
      mitre,
      match: { source, event_type: eventType }
    };
  
    if (type === "simple_contains" || type === "threshold_count") {
      rule.match.contains = contains;
    }
  
    if (type === "threshold_count") {
      rule.group_by = els.rGroupBy.value;
      rule.threshold = Number(els.rThreshold.value) || 5;
      rule.window_minutes = Number(els.rWindow.value) || 2;
    }
  
    if (type === "field_length") {
      rule.match.field = els.rField.value;
      rule.match.min_length = Number(els.rMinLen.value) || 80;
    }
  
    state.rules.push(normalizeRule(rule));
    closeRuleModal();
  
    state.alerts = generateAlerts(state.logs, state.rules);
  
    renderRules();
    renderAlerts();
    setStatus(`Added rule • ${state.rules.length} rules • ${state.alerts.length} alerts`);
  }
  
  /* ---------------------------
     EXPORT
  ---------------------------- */
  
  function exportCurrentViewCSV() {
    if (state.view === "logs") return exportCSV(state.logs, "soc_logs");
    if (state.view === "alerts") return exportCSV(state.alerts, "soc_alerts");
    if (state.view === "rules") return exportCSV(state.rules, "soc_rules");
    alert("Nothing to export in this view yet.");
  }
  
  function exportCSV(rows, name) {
    if (!Array.isArray(rows) || rows.length === 0) {
      return alert("Nothing to export.");
    }
  
    const cols = Object.keys(flatten(rows[0]));
    const header = cols.join(",");
  
    const lines = rows.map(r => {
      const flat = flatten(r);
      return cols.map(c => csvCell(flat[c])).join(",");
    });
  
    const csv = [header, ...lines].join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
  
    const a = document.createElement("a");
    a.href = url;
    a.download = `${name}_${new Date().toISOString().slice(0,10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }
  
  function flatten(obj, prefix = "", out = {}) {
    for (const [k, v] of Object.entries(obj || {})) {
      const key = prefix ? `${prefix}.${k}` : k;
      if (v && typeof v === "object" && !Array.isArray(v)) {
        flatten(v, key, out);
      } else {
        out[key] = Array.isArray(v) ? v.join("|") : v;
      }
    }
    return out;
  }
  
  /* ---------------------------
     HELPERS
  ---------------------------- */
  
  function normalizeLog(item) {
    if (!item) return null;
    const safe = {
      id: String(item.id ?? ""),
      timestamp: String(item.timestamp ?? ""),
      source: String(item.source ?? ""),
      event_type: String(item.event_type ?? ""),
      user: String(item.user ?? ""),
      host: String(item.host ?? ""),
      src_ip: String(item.src_ip ?? ""),
      dst_ip: String(item.dst_ip ?? ""),
      severity: String(item.severity ?? ""),
      message: String(item.message ?? "")
    };
    const hasAny = Object.values(safe).some(v => v.trim() !== "");
    return hasAny ? safe : null;
  }
  
  function normalizeRule(r) {
    if (!r) return null;
    return {
      rule_id: String(r.rule_id ?? ""),
      name: String(r.name ?? ""),
      type: String(r.type ?? "simple_contains"),
      enabled: Boolean(r.enabled),
      severity: String(r.severity ?? "Low"),
      mitre: Array.isArray(r.mitre) ? r.mitre.map(String) : [],
      match: r.match || {},
      group_by: r.group_by,
      threshold: r.threshold,
      window_minutes: r.window_minutes
    };
  }
  
  function setStatus(text) { els.statusText.textContent = text; }
  
  function norm(s) { return String(s ?? "").toLowerCase().trim(); }
  
  function formatTime(iso) {
    if (!iso) return "-";
    const t = Date.parse(iso);
    if (!t) return iso;
    return new Date(t).toISOString().replace("T", " ").replace("Z", "");
  }
  
  function escapeHtml(str) {
    return String(str ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }
  
  function renderSeverityBadge(severity) {
    const s = norm(severity || "Low");
    let cls = "low";
    if (s === "medium") cls = "medium";
    if (s === "high") cls = "high";
    if (s === "critical") cls = "critical";
    const label = severity || "Low";
    return `<span class="badge ${cls}"><i></i>${escapeHtml(label)}</span>`;
  }
  function renderSeverityText(severity) {
    return String(severity || "Low");
  }
  
  function csvCell(val) {
    const s = String(val ?? "");
    const escaped = s.replaceAll('"', '""');
    return `"${escaped}"`;
  }
  
  function splitCsv(s) {
    return String(s || "")
      .split(",")
      .map(x => x.trim())
      .filter(Boolean);
  }
  
  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      alert("Copy failed. Browser may block clipboard.");
    }
  }
  
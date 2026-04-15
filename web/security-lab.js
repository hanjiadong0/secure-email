const LAB_STORAGE_KEY = `secure-email:security-lab:${window.location.origin}`;

const state = {
  session: null,
  evidence: null,
  busy: false,
};

const ui = {};

document.addEventListener("DOMContentLoaded", () => {
  void initialize();
});

async function initialize() {
  cacheUi();
  bindUi();
  restoreSession();
  syncAccess();
  renderEvidence();
  await loadHealth();
  await loadEvidence({ silent: true });
}

function cacheUi() {
  ui.labDomain = document.getElementById("labDomain");
  ui.labOperator = document.getElementById("labOperator");
  ui.labAccess = document.getElementById("labAccess");
  ui.labLoginForm = document.getElementById("labLoginForm");
  ui.labEmail = document.getElementById("labEmail");
  ui.labPassword = document.getElementById("labPassword");
  ui.labLogoutButton = document.getElementById("labLogoutButton");
  ui.labRunButton = document.getElementById("labRunButton");
  ui.labRefreshButton = document.getElementById("labRefreshButton");
  ui.labAccessHint = document.getElementById("labAccessHint");
  ui.overviewSummary = document.getElementById("overviewSummary");
  ui.overviewCards = document.getElementById("overviewCards");
  ui.threatModel = document.getElementById("threatModel");
  ui.methodologyList = document.getElementById("methodologyList");
  ui.attackerChart = document.getElementById("attackerChart");
  ui.matrixChart = document.getElementById("matrixChart");
  ui.scenarioCards = document.getElementById("scenarioCards");
  ui.recommendationList = document.getElementById("recommendationList");
  ui.toastRegion = document.getElementById("labToastRegion");
}

function bindUi() {
  ui.labLoginForm?.addEventListener("submit", (event) => {
    event.preventDefault();
    void handleLogin();
  });
  ui.labLogoutButton?.addEventListener("click", handleLogout);
  ui.labRunButton?.addEventListener("click", () => {
    void runSimulation();
  });
  ui.labRefreshButton?.addEventListener("click", () => {
    void loadEvidence();
  });
}

function restoreSession() {
  try {
    const raw = window.sessionStorage.getItem(LAB_STORAGE_KEY);
    state.session = raw ? JSON.parse(raw) : null;
  } catch {
    state.session = null;
  }
}

function persistSession() {
  if (!state.session) {
    window.sessionStorage.removeItem(LAB_STORAGE_KEY);
    return;
  }
  window.sessionStorage.setItem(LAB_STORAGE_KEY, JSON.stringify(state.session));
}

function syncAccess() {
  ui.labOperator.textContent = state.session?.email || "Guest";
  ui.labAccess.textContent = state.session ? "Run enabled" : "Read-only";
  ui.labRunButton.disabled = !state.session || state.busy;
  ui.labLogoutButton.disabled = !state.session;
  ui.labRefreshButton.disabled = state.busy;
  ui.labAccessHint.textContent = state.session
    ? "You are signed in for the security lab only. Running the drill creates fresh evidence without opening the mailbox page."
    : "Sign in to rerun the drill. Reading the latest evidence stays available without mailbox access.";
}

async function loadHealth() {
  try {
    const data = await fetchJson("/health");
    ui.labDomain.textContent = `${data.domain} Security Lab`;
  } catch (error) {
    ui.labDomain.textContent = "Security Lab offline";
    showToast(normalizeError(error), true);
  }
}

async function handleLogin() {
  const email = ui.labEmail.value.trim();
  const password = ui.labPassword.value;
  if (!email || !password) {
    showToast("Enter both email and password.", true);
    return;
  }
  await guard(async () => {
    const data = await fetchJson("/v1/auth/login", {
      method: "POST",
      body: { email, password },
    });
    state.session = {
      email,
      session_id: data.session_id,
      session_token: data.session_token,
      session_key: data.session_key,
      seq_no: 0,
    };
    persistSession();
    ui.labLoginForm.reset();
    syncAccess();
    showToast(`Security lab access granted for ${email}.`);
  });
}

function handleLogout() {
  state.session = null;
  persistSession();
  syncAccess();
  showToast("Security lab session cleared.");
}

async function loadEvidence(options = {}) {
  try {
    state.evidence = await fetchJson("/v1/security/evidence");
    renderEvidence();
    return state.evidence;
  } catch (error) {
    if (!options.silent) {
      showToast(normalizeError(error), true);
    }
    return null;
  }
}

async function runSimulation() {
  if (!state.session) {
    showToast("Sign in before running a fresh security drill.", true);
    return;
  }
  await guard(async () => {
    state.evidence = await signedPost("/v1/security/simulate", { scenario: "full" });
    renderEvidence();
    showToast("Threat drill finished. The evidence below is now fresh.");
  });
}

function renderEvidence() {
  const report = state.evidence;
  if (!report || report.status === "unavailable") {
    ui.overviewSummary.textContent = "No simulation evidence exists yet. Sign in and run the drill to generate a full report.";
    ui.overviewCards.innerHTML = emptyCard("No overview yet", "Run the independent threat drill to populate this section.");
    ui.threatModel.innerHTML = emptyCard("Threat model unavailable", "The lab will publish assets, attacker profiles, and boundaries here.");
    ui.methodologyList.innerHTML = emptyCard("No methodology yet", "The drill methodology will appear after a run.");
    ui.scenarioCards.innerHTML = emptyCard("No scenario explanations yet", "Each threat scenario will be explained in detail here.");
    ui.recommendationList.innerHTML = emptyCard("No recommendations yet", "Hardening priorities are generated from the latest drill.");
    setChart(ui.attackerChart, null);
    setChart(ui.matrixChart, null);
    return;
  }
  if (report.status !== "ok") {
    ui.overviewSummary.textContent = "Security evidence exists but is currently unreadable. Regenerate the drill to rebuild the report.";
    return;
  }

  renderOverview(report);
  renderThreatModel(report.threat_model || {});
  renderMethodology(report.methodology || []);
  renderScenarios(report.scenarios || []);
  renderRecommendations(report.recommendations || []);
  setChart(ui.attackerChart, report.images?.attacker_vs_defender?.url || null);
  setChart(ui.matrixChart, report.images?.scenario_matrix?.url || null);
}

function renderOverview(report) {
  const metrics = report.metrics || {};
  const overview = report.overview || {};
  const posture = String(overview.posture || "mixed");
  const postureText = {
    strong: "Controls held across the current drill set.",
    mixed: "Several controls worked, but the drill still exposes non-zero attacker progress.",
    weak: "Attacker progress remained too high in the current drill results.",
  }[posture] || "Security posture summary unavailable.";
  ui.overviewSummary.textContent = `${overview.summary || ""} ${postureText}`.trim();
  ui.overviewCards.innerHTML = [
    metricCard("Defender Success Rate", `${metrics.defender_success_rate_percent ?? 0}%`, "Combined blocked and detected pressure across all simulated attempts."),
    metricCard("Total Attempts", String(metrics.total_attempts ?? 0), "All attacker actions executed in the latest drill run."),
    metricCard("Strongest Control Area", overview.strongest_control_area || "Not available", "Scenario where defender controls showed the clearest effect."),
    metricCard("Highest Residual Risk", overview.highest_residual_risk || "Not available", "Scenario that still leaves the most attacker room to maneuver."),
  ].join("");
}

function renderThreatModel(model) {
  const cards = [
    modelCard("Protected Assets", model.assets || []),
    modelCard("Trust Boundaries", model.trust_boundaries || []),
    modelCard("Attacker Profiles", model.attacker_profiles || []),
  ];
  if ((model.priority_attackers || []).length) {
    cards.push(modelCard("Priority Attackers", model.priority_attackers || []));
  }
  if ((model.llm_risks || []).length) {
    cards.push(modelCard("LLM Risks", model.llm_risks || []));
  }
  if ((model.attacker_layers || []).length) {
    cards.push(modelCard("Attacker Layers", model.attacker_layers || []));
  }
  ui.threatModel.innerHTML = cards.join("");
}

function renderMethodology(items) {
  ui.methodologyList.innerHTML = items.length
    ? items.map((item) => `<div>${escapeHtml(item)}</div>`).join("")
    : emptyCard("Methodology unavailable", "No methodology was stored in the current report.");
}

function renderScenarios(items) {
  if (!items.length) {
    ui.scenarioCards.innerHTML = emptyCard("No scenarios recorded", "Run a fresh simulation to generate scenario explanations.");
    return;
  }
  ui.scenarioCards.innerHTML = items.map((item) => scenarioCard(item)).join("");
}

function renderRecommendations(items) {
  ui.recommendationList.innerHTML = items.length
    ? items.map((item) => `<div>${escapeHtml(item)}</div>`).join("")
    : emptyCard("No recommendations recorded", "The report did not include hardening suggestions.");
}

function metricCard(label, value, note) {
  return `
    <article class="metric-card">
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(value)}</strong>
      <div>${escapeHtml(note)}</div>
    </article>
  `;
}

function modelCard(title, items) {
  return `
    <article class="model-card">
      <strong>${escapeHtml(title)}</strong>
      <ul>
        ${items.map((item) => `<li>${escapeHtml(item)}</li>`).join("") || "<li>Not available</li>"}
      </ul>
    </article>
  `;
}

function scenarioCard(item) {
  const resultClass = scenarioResultClass(item.result_label);
  return `
    <article class="scenario-card">
      <div class="scenario-top">
        <div>
          <h3>${escapeHtml(item.scenario)}</h3>
          <div class="scenario-meta">
            <span>${escapeHtml(item.category || "General")}</span>
            <span>${escapeHtml(item.severity || "medium")} severity</span>
            <span class="mono">${escapeHtml(item.scenario_id || "")}</span>
          </div>
        </div>
        <div class="result-badge ${resultClass}">${escapeHtml(item.result_label || "Observed")}</div>
      </div>
      <div class="scenario-story">
        <strong>Attacker goal</strong>
        <p>${escapeHtml(item.attacker_goal || "No attacker goal recorded.")}</p>
      </div>
      <div class="scenario-columns">
        <section class="scenario-block">
          <strong>Attacker Persona</strong>
          <ul>
            <li>Name: ${escapeHtml(item.attacker_name || "Not recorded")}</li>
            <li>Class: ${escapeHtml(item.attacker_class || "Not recorded")}</li>
            <li>Script: ${escapeHtml(item.attacker_script || "Not recorded")}</li>
            <li>Boundary: ${escapeHtml(item.trust_boundary || "Not recorded")}</li>
          </ul>
        </section>
        <section class="scenario-block">
          <strong>Security Scope</strong>
          <ul>${(item.security_objectives || []).map((step) => `<li>${escapeHtml(step)}</li>`).join("") || "<li>Not recorded</li>"}</ul>
          <strong>Entry Points</strong>
          <ul>${(item.entry_points || []).map((step) => `<li>${escapeHtml(step)}</li>`).join("") || "<li>Not recorded</li>"}</ul>
        </section>
      </div>
      <div class="scenario-columns">
        <section class="scenario-block">
          <strong>Attack Path</strong>
          <ul>${(item.attack_path || []).map((step) => `<li>${escapeHtml(step)}</li>`).join("")}</ul>
        </section>
        <section class="scenario-block">
          <strong>Defender Controls</strong>
          <ul>${(item.defender_controls || []).map((step) => `<li>${escapeHtml(step)}</li>`).join("")}</ul>
        </section>
      </div>
      <div class="scenario-columns">
        <section class="scenario-block">
          <strong>Observed Evidence</strong>
          <ul>${(item.evidence || []).map((step) => `<li>${escapeHtml(step)}</li>`).join("")}</ul>
        </section>
        <section class="scenario-block">
          <strong>Numerical Outcome</strong>
          <ul>
            <li>Attempts: ${escapeHtml(String(item.attempts ?? 0))}</li>
            <li>Blocked: ${escapeHtml(String(item.blocked ?? 0))}</li>
            <li>Detected: ${escapeHtml(String(item.detected ?? 0))}</li>
            <li>Attacker Success: ${escapeHtml(String(item.attacker_success ?? 0))}</li>
          </ul>
        </section>
      </div>
      <div class="scenario-story">
        <strong>Why this result matters</strong>
        <p>${escapeHtml(item.explanation || item.outcome || "No explanation recorded.")}</p>
      </div>
      <div class="scenario-story">
        <strong>Residual risk</strong>
        <p>${escapeHtml(item.residual_risk || "No residual-risk narrative recorded.")}</p>
      </div>
    </article>
  `;
}

function scenarioResultClass(label) {
  const value = String(label || "").toLowerCase();
  if (value.includes("held")) {
    return "held";
  }
  if (value.includes("partial")) {
    return "partial";
  }
  return "risk";
}

function setChart(node, url) {
  if (!node) {
    return;
  }
  if (!url) {
    node.removeAttribute("src");
    node.style.display = "none";
    return;
  }
  node.src = `${url}${url.includes("?") ? "&" : "?"}t=${Date.now()}`;
  node.style.display = "block";
}

async function guard(action) {
  if (state.busy) {
    showToast("Please wait for the current lab action to finish.", true);
    return null;
  }
  state.busy = true;
  syncAccess();
  try {
    return await action();
  } catch (error) {
    showToast(normalizeError(error), true);
    return null;
  } finally {
    state.busy = false;
    syncAccess();
  }
}

async function signedPost(path, body) {
  const headers = await buildSignedHeaders(path, body);
  return fetchJson(path, {
    method: "POST",
    body,
    headers: {
      Authorization: `Bearer ${state.session.session_token}`,
      ...headers,
    },
  });
}

async function buildSignedHeaders(path, body) {
  const nextSeq = Number(state.session.seq_no || 0) + 1;
  const requestId = randomId();
  const nonce = randomId();
  const timestamp = Math.floor(Date.now() / 1000);
  const canonical = canonicalJson({
    method: "POST",
    path,
    request_id: requestId,
    session_id: state.session.session_id,
    seq_no: nextSeq,
    timestamp,
    nonce,
    body,
  });
  const bodyMac = await hmacHex(state.session.session_key, canonical);
  state.session.seq_no = nextSeq;
  persistSession();
  return {
    "X-Request-Id": requestId,
    "X-Session-Id": state.session.session_id,
    "X-Seq-No": String(nextSeq),
    "X-Timestamp": String(timestamp),
    "X-Nonce": nonce,
    "X-Body-Mac": bodyMac,
  };
}

async function fetchJson(path, options = {}) {
  const response = await fetch(path, {
    method: options.method || "GET",
    headers: {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(options.headers || {}),
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  if (!response.ok) {
    throw await parseError(response);
  }
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    return response.json();
  }
  return response.text();
}

async function parseError(response) {
  try {
    const data = await response.json();
    return new Error(data.detail || JSON.stringify(data));
  } catch {
    return new Error(`${response.status} ${response.statusText}`);
  }
}

async function hmacHex(secret, message) {
  const enc = new TextEncoder();
  const key = await window.crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await window.crypto.subtle.sign("HMAC", key, enc.encode(message));
  return Array.from(new Uint8Array(signature))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function canonicalJson(value) {
  return stableStringify(value).replace(/[\u007f-\uffff]/g, (char) => {
    return `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`;
  });
}

function stableStringify(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }
  const entries = Object.keys(value)
    .sort()
    .map((key) => `${stableStringify(key)}:${stableStringify(value[key])}`);
  return `{${entries.join(",")}}`;
}

function randomId() {
  if (window.crypto?.randomUUID) {
    return window.crypto.randomUUID();
  }
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function emptyCard(title, body) {
  return `
    <article class="metric-card">
      <span>${escapeHtml(title)}</span>
      <div>${escapeHtml(body)}</div>
    </article>
  `;
}

function normalizeError(error) {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function showToast(message, isError = false) {
  const node = document.createElement("div");
  node.className = `toast${isError ? " error" : ""}`;
  node.textContent = message;
  ui.toastRegion.appendChild(node);
  window.setTimeout(() => {
    node.remove();
  }, 4200);
}

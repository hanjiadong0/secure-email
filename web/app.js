const STORAGE_KEY = `secure-email:web:${window.location.origin}`;

const state = {
  domain: "",
  session: null,
  refreshPromise: null,
  securityEvidence: null,
  activeMailbox: "inbox",
  mailboxes: {
    inbox: [],
    sent: [],
    drafts: [],
    search: [],
  },
  todos: [],
  calendarEvents: [],
  searchContacts: [],
  selectedMessageId: null,
  composeAttachments: [],
  preview: null,
};

const ui = {};
const actionLocks = new Set();
const actionCooldowns = new Map();
const CLIENT_ACTION_COOLDOWN_MS = 900;

document.addEventListener("DOMContentLoaded", () => {
  void initialize();
});

async function initialize() {
  cacheUi();
  bindUi();
  restoreSession();
  syncSessionCard();
  syncComposeMode();
  renderSecurityEvidence();
  renderAttachments();
  renderMailboxTabs();
  renderMailboxList();
  renderDetail();
  await loadHealth();
  if (state.session) {
    await refreshAll();
  }
}

function cacheUi() {
  ui.domainBadge = document.getElementById("domainBadge");
  ui.serviceStatus = document.getElementById("serviceStatus");
  ui.sessionUser = document.getElementById("sessionUser");
  ui.sessionSeq = document.getElementById("sessionSeq");
  ui.logoutButton = document.getElementById("logoutButton");
  ui.registerForm = document.getElementById("registerForm");
  ui.loginForm = document.getElementById("loginForm");
  ui.registerEmail = document.getElementById("registerEmail");
  ui.registerPassword = document.getElementById("registerPassword");
  ui.registerConfirmPassword = document.getElementById("registerConfirmPassword");
  ui.loginEmail = document.getElementById("loginEmail");
  ui.loginPassword = document.getElementById("loginPassword");
  ui.composeForm = document.getElementById("composeForm");
  ui.composeTo = document.getElementById("composeTo");
  ui.composeCc = document.getElementById("composeCc");
  ui.composeSubject = document.getElementById("composeSubject");
  ui.composeBody = document.getElementById("composeBody");
  ui.composeE2E = document.getElementById("composeE2E");
  ui.composeE2EHint = document.getElementById("composeE2EHint");
  ui.attachmentFile = document.getElementById("attachmentFile");
  ui.uploadAttachmentButton = document.getElementById("uploadAttachmentButton");
  ui.saveDraftButton = document.getElementById("saveDraftButton");
  ui.clearComposeButton = document.getElementById("clearComposeButton");
  ui.attachmentList = document.getElementById("attachmentList");
  ui.searchForm = document.getElementById("searchForm");
  ui.searchQuery = document.getElementById("searchQuery");
  ui.clearSearchButton = document.getElementById("clearSearchButton");
  ui.refreshButton = document.getElementById("refreshButton");
  ui.searchContacts = document.getElementById("searchContacts");
  ui.groupCreateForm = document.getElementById("groupCreateForm");
  ui.groupSendForm = document.getElementById("groupSendForm");
  ui.groupName = document.getElementById("groupName");
  ui.groupMembers = document.getElementById("groupMembers");
  ui.groupSendName = document.getElementById("groupSendName");
  ui.groupSendSubject = document.getElementById("groupSendSubject");
  ui.groupSendBody = document.getElementById("groupSendBody");
  ui.runSecuritySimulationButton = document.getElementById("runSecuritySimulationButton");
  ui.refreshSecurityEvidenceButton = document.getElementById("refreshSecurityEvidenceButton");
  ui.securitySummary = document.getElementById("securitySummary");
  ui.securityAttackerDefenderImage = document.getElementById("securityAttackerDefenderImage");
  ui.securityScenarioMatrixImage = document.getElementById("securityScenarioMatrixImage");
  ui.mailboxTabs = document.getElementById("mailboxTabs");
  ui.mailboxList = document.getElementById("mailboxList");
  ui.detailView = document.getElementById("detailView");
  ui.toastRegion = document.getElementById("toastRegion");
}

function bindUi() {
  ui.logoutButton.addEventListener("click", handleLogout);
  ui.registerForm.addEventListener("submit", (event) => {
    event.preventDefault();
    void handleRegister();
  });
  ui.loginForm.addEventListener("submit", (event) => {
    event.preventDefault();
    void handleLogin();
  });
  ui.composeForm.addEventListener("submit", (event) => {
    event.preventDefault();
    void handleSendMail();
  });
  ui.composeE2E.addEventListener("change", syncComposeMode);
  ui.uploadAttachmentButton.addEventListener("click", () => {
    void handleUploadAttachment();
  });
  ui.saveDraftButton.addEventListener("click", () => {
    void handleSaveDraft();
  });
  ui.clearComposeButton.addEventListener("click", clearCompose);
  ui.searchForm.addEventListener("submit", (event) => {
    event.preventDefault();
    void handleSearch();
  });
  ui.clearSearchButton.addEventListener("click", clearSearch);
  ui.refreshButton.addEventListener("click", () => {
    void refreshAll();
  });
  ui.groupCreateForm.addEventListener("submit", (event) => {
    event.preventDefault();
    void handleGroupCreate();
  });
  ui.groupSendForm.addEventListener("submit", (event) => {
    event.preventDefault();
    void handleGroupSend();
  });
  ui.runSecuritySimulationButton?.addEventListener("click", () => {
    void handleRunSecuritySimulation();
  });
  ui.refreshSecurityEvidenceButton?.addEventListener("click", () => {
    void refreshSecurityEvidence();
  });
  ui.mailboxTabs.addEventListener("click", (event) => {
    const button = event.target.closest("[data-mailbox]");
    if (!button) {
      return;
    }
    state.activeMailbox = button.dataset.mailbox;
    renderMailboxTabs();
    renderMailboxList();
  });
  ui.mailboxList.addEventListener("click", (event) => {
    const card = event.target.closest("[data-message-id]");
    if (!card) {
      return;
    }
    state.selectedMessageId = card.dataset.messageId;
    state.preview = null;
    renderMailboxList();
    renderDetail();
  });
  ui.detailView.addEventListener("click", (event) => {
    const actionNode = event.target.closest("[data-detail-action]");
    if (!actionNode) {
      return;
    }
    void handleDetailAction(actionNode);
  });
}

async function loadHealth() {
  try {
    const data = await fetchJson("/health");
    state.domain = data.domain;
    ui.domainBadge.textContent = data.domain;
    ui.serviceStatus.textContent = data.status === "ok" ? "Ready" : data.status.toUpperCase();
  } catch (error) {
    ui.serviceStatus.textContent = "Offline";
    showToast(normalizeError(error), true);
  }
}

function restoreSession() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      return;
    }
    state.session = JSON.parse(raw);
  } catch {
    state.session = null;
  }
}

function persistSession() {
  if (!state.session) {
    localStorage.removeItem(STORAGE_KEY);
    return;
  }
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state.session));
}

function syncSessionCard() {
  ui.sessionUser.textContent = state.session ? state.session.email : "Guest";
  if (ui.sessionSeq) {
    ui.sessionSeq.textContent = state.session ? String(state.session.seq_no) : "0";
  }
  ui.logoutButton.disabled = !state.session;
  if (ui.runSecuritySimulationButton) {
    ui.runSecuritySimulationButton.disabled = !state.session;
  }
  if (ui.refreshSecurityEvidenceButton) {
    ui.refreshSecurityEvidenceButton.disabled = !state.session;
  }
}

function syncComposeMode() {
  const e2eEnabled = Boolean(ui.composeE2E?.checked);
  if (ui.attachmentFile) {
    ui.attachmentFile.disabled = e2eEnabled;
  }
  if (ui.uploadAttachmentButton) {
    ui.uploadAttachmentButton.disabled = e2eEnabled;
  }
  if (ui.composeE2EHint) {
    ui.composeE2EHint.textContent = e2eEnabled
      ? "End-to-end encryption is on. Your browser will encrypt the subject and message locally. Attachments are off in this mode for now."
      : "You can add attachments while standard sending is active.";
  }
}

async function ensureE2EIdentityPublished() {
  if (!state.session) {
    return null;
  }
  if (!state.session.e2e_public_key || !state.session.e2e_private_jwk) {
    const identity = await generateBrowserE2EIdentity();
    state.session.e2e_public_key = identity.publicKey;
    state.session.e2e_private_jwk = identity.privateJwk;
    persistSession();
  }
  if (state.session.e2e_published_public_key !== state.session.e2e_public_key) {
    await signedPost("/v1/keys/publish", {
      algorithm: "ECDH-P256-HKDF-SHA256-AESGCM",
      curve: "P-256",
      public_key: state.session.e2e_public_key,
    });
    state.session.e2e_published_public_key = state.session.e2e_public_key;
    persistSession();
  }
  return {
    publicKey: state.session.e2e_public_key,
    privateJwk: state.session.e2e_private_jwk,
  };
}

async function generateBrowserE2EIdentity() {
  const pair = await window.crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
  const publicRaw = await window.crypto.subtle.exportKey("raw", pair.publicKey);
  const privateJwk = await window.crypto.subtle.exportKey("jwk", pair.privateKey);
  return {
    publicKey: bytesToBase64Url(new Uint8Array(publicRaw)),
    privateJwk,
  };
}

async function hydrateMailbox(messages) {
  return Promise.all((messages || []).map((message) => hydrateMessage(message)));
}

async function hydrateMessage(message) {
  if (!message?.e2e_encrypted || !state.session?.e2e_private_jwk) {
    return message;
  }
  try {
    const decrypted = await decryptEnvelopeForSession(message.e2e_envelope);
    if (decrypted) {
      message.subject = decrypted.subject;
      message.body_text = decrypted.body_text;
      message.security_flags = {
        ...(message.security_flags || {}),
        e2e_decrypted_local: true,
      };
    }
  } catch (error) {
    message.security_flags = {
      ...(message.security_flags || {}),
      e2e_decrypt_error: normalizeError(error),
    };
  }
  return message;
}

async function handleRegister() {
  const email = ui.registerEmail.value.trim();
  const password = ui.registerPassword.value;
  const confirmPassword = ui.registerConfirmPassword.value;
  if (!email || !password || !confirmPassword) {
    showToast("Please enter your email, password, and password confirmation.", true);
    return;
  }
  if (password !== confirmPassword) {
    showToast("The password confirmation does not match.", true);
    return;
  }
  await runClientGuard("register", async () => {
    const result = await fetchJson("/v1/auth/register", {
      method: "POST",
      body: { email, password, confirm_password: confirmPassword },
    });
    ui.loginEmail.value = email;
    ui.registerForm.reset();
    showToast(`Account created for ${result.email}. You can sign in now.`);
  });
}

async function handleLogin() {
  const email = ui.loginEmail.value.trim();
  const password = ui.loginPassword.value;
  if (!email || !password) {
    showToast("Please enter both email and password.", true);
    return;
  }
  await runClientGuard("login", async () => {
    const preservedIdentity =
      state.session?.email === email
        ? {
            e2e_public_key: state.session.e2e_public_key,
            e2e_private_jwk: state.session.e2e_private_jwk,
            e2e_published_public_key: state.session.e2e_published_public_key,
          }
        : {};
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
      ...preservedIdentity,
    };
    persistSession();
    await ensureE2EIdentityPublished();
    syncSessionCard();
    ui.loginForm.reset();
    state.activeMailbox = "inbox";
    await refreshAll();
    showToast(`Signed in as ${email}.`);
  });
}

function handleLogout() {
  state.session = null;
  state.refreshPromise = null;
  state.securityEvidence = null;
  state.mailboxes = { inbox: [], sent: [], drafts: [], search: [] };
  state.todos = [];
  state.calendarEvents = [];
  state.searchContacts = [];
  state.selectedMessageId = null;
  state.composeAttachments = [];
  revokePreview();
  persistSession();
  syncSessionCard();
  renderAttachments();
  renderMailboxTabs();
  renderMailboxList();
  renderDetail();
  renderSecurityEvidence();
  showToast("Signed out.");
}

async function refreshAll() {
  if (!requireSession()) {
    return;
  }
  if (state.refreshPromise) {
    return state.refreshPromise;
  }
  state.refreshPromise = (async () => {
    try {
      await ensureE2EIdentityPublished();
      const dashboard = await authGet("/v1/mail/dashboard");
      state.mailboxes.inbox = await hydrateMailbox(dashboard.inbox || []);
      state.mailboxes.sent = await hydrateMailbox(dashboard.sent || []);
      state.mailboxes.drafts = await hydrateMailbox(dashboard.drafts || []);
      state.todos = dashboard.todos || [];
      state.calendarEvents = dashboard.calendar_events || [];
      if (!lookupSelectedMessage() && state.mailboxes.inbox.length) {
        state.selectedMessageId = state.mailboxes.inbox[0].message_id;
      }
      renderMailboxTabs();
      renderMailboxList();
      renderDetail();
      await refreshSecurityEvidence({ silent: true });
      syncSessionCard();
    } catch (error) {
      showToast(normalizeError(error), true);
    } finally {
      state.refreshPromise = null;
    }
  })();
  return state.refreshPromise;
}

async function handleRunSecuritySimulation() {
  if (!requireSession()) {
    return;
  }
  await runClientGuard("security_simulation", async () => {
    const report = await signedPost("/v1/security/simulate", { scenario: "full" });
    state.securityEvidence = report;
    renderSecurityEvidence();
    showToast("Security simulation completed and evidence was refreshed.");
  });
}

async function refreshSecurityEvidence(options = {}) {
  if (!state.session) {
    state.securityEvidence = null;
    renderSecurityEvidence();
    return null;
  }
  try {
    const report = await authGet("/v1/security/evidence");
    state.securityEvidence = report;
    renderSecurityEvidence();
    return report;
  } catch (error) {
    if (!options.silent) {
      showToast(normalizeError(error), true);
    }
    return null;
  }
}

function renderSecurityEvidence() {
  if (!ui.securitySummary) {
    return;
  }
  const report = state.securityEvidence;
  if (!report || report.status === "unavailable") {
    ui.securitySummary.textContent = "No security evidence generated yet. Run the simulation after signing in.";
    setSecurityEvidenceImage(ui.securityAttackerDefenderImage, null);
    setSecurityEvidenceImage(ui.securityScenarioMatrixImage, null);
    return;
  }
  if (report.status !== "ok") {
    ui.securitySummary.textContent = "Security evidence is currently unavailable. Please run the simulation again.";
    setSecurityEvidenceImage(ui.securityAttackerDefenderImage, null);
    setSecurityEvidenceImage(ui.securityScenarioMatrixImage, null);
    return;
  }
  const metrics = report.metrics || {};
  const defenderRate = metrics.defender_success_rate_percent ?? 0;
  const totalAttempts = metrics.total_attempts ?? 0;
  const blocked = metrics.blocked ?? 0;
  const detected = metrics.detected ?? 0;
  const attackerSuccess = metrics.attacker_success ?? 0;
  ui.securitySummary.textContent =
    `Generated ${formatTime(report.generated_at || "")}. ` +
    `Defender success ${defenderRate}% across ${totalAttempts} attacks ` +
    `(blocked ${blocked}, detected ${detected}, attacker success ${attackerSuccess}).`;
  setSecurityEvidenceImage(
    ui.securityAttackerDefenderImage,
    report.images?.attacker_vs_defender?.url || null
  );
  setSecurityEvidenceImage(
    ui.securityScenarioMatrixImage,
    report.images?.scenario_matrix?.url || null
  );
}

function setSecurityEvidenceImage(node, url) {
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

async function handleUploadAttachment() {
  if (!requireSession()) {
    return;
  }
  if (ui.composeE2E.checked) {
    showToast("Encrypted message mode is text-only right now, so attachment uploads are unavailable.", true);
    return;
  }
  const file = ui.attachmentFile.files?.[0];
  if (!file) {
    showToast("Choose a file first.", true);
    return;
  }
  const contentBase64 = await fileToBase64(file);
  const body = { filename: file.name, content_base64: contentBase64 };
  await runClientGuard("upload", async () => {
    const attachment = await signedPost("/v1/attachments/upload", body);
    state.composeAttachments.push(attachment);
    renderAttachments();
    ui.attachmentFile.value = "";
    showToast(`Added ${attachment.filename} to the message.`);
  });
}

async function handleSendMail() {
  if (!requireSession()) {
    return;
  }
  if (ui.composeE2E.checked && state.composeAttachments.length) {
    showToast("Encrypted sending is text-only for now. Remove attachments before sending.", true);
    return;
  }
  const body = await buildComposeBody();
  await runClientGuard("send_mail", async () => {
    const result = await signedPost("/v1/mail/send", body);
    clearCompose();
    await refreshAll();
    state.activeMailbox = "sent";
    state.selectedMessageId = result.message_id;
    renderMailboxTabs();
    renderMailboxList();
    renderDetail();
    showToast("Your message is on its way.");
  });
}

async function handleSaveDraft() {
  if (!requireSession()) {
    return;
  }
  if (ui.composeE2E.checked) {
    showToast("Encrypted drafts are not available in the browser yet.", true);
    return;
  }
  const body = {
    message_id: null,
    to: csv(ui.composeTo.value),
    cc: csv(ui.composeCc.value),
    subject: ui.composeSubject.value.trim(),
    body_text: ui.composeBody.value.trim(),
    attachment_ids: state.composeAttachments.map((attachment) => attachment.id),
    send_now: false,
  };
  await runClientGuard("save_draft", async () => {
    const result = await signedPost("/v1/mail/draft", body);
    await refreshAll();
    state.activeMailbox = "drafts";
    state.selectedMessageId = result.message_id;
    renderMailboxTabs();
    renderMailboxList();
    renderDetail();
    showToast("Draft saved.");
  });
}

function clearCompose() {
  ui.composeForm.reset();
  state.composeAttachments = [];
  syncComposeMode();
  renderAttachments();
}

async function handleSearch() {
  if (!requireSession()) {
    return;
  }
  const query = ui.searchQuery.value.trim();
  if (!query) {
    showToast("Enter something to search for first.", true);
    return;
  }
  try {
    const result = await authGet("/v1/mail/search", { q: query });
    state.mailboxes.search = await hydrateMailbox(result.messages);
    state.searchContacts = result.contacts;
    state.activeMailbox = "search";
    renderSearchContacts();
    renderMailboxTabs();
    renderMailboxList();
    showToast(`Found ${result.messages.length} matching messages.`);
  } catch (error) {
    showToast(normalizeError(error), true);
  }
}

function clearSearch() {
  ui.searchQuery.value = "";
  state.mailboxes.search = [];
  state.searchContacts = [];
  renderSearchContacts();
  if (state.activeMailbox === "search") {
    state.activeMailbox = "inbox";
  }
  renderMailboxTabs();
  renderMailboxList();
}

async function handleGroupCreate() {
  if (!requireSession()) {
    return;
  }
  const name = ui.groupName.value.trim();
  const members = csv(ui.groupMembers.value);
  if (!name) {
    showToast("Please enter a name for the list.", true);
    return;
  }
  await runClientGuard("group_create", async () => {
    await signedPost("/v1/groups/create", { name, members });
    ui.groupCreateForm.reset();
    showToast(`Saved the list ${name}.`);
  });
}

async function handleGroupSend() {
  if (!requireSession()) {
    return;
  }
  const body = {
    group_name: ui.groupSendName.value.trim(),
    subject: ui.groupSendSubject.value.trim(),
    body_text: ui.groupSendBody.value.trim(),
    attachment_ids: state.composeAttachments.map((attachment) => attachment.id),
  };
  if (!body.group_name || !body.subject || !body.body_text) {
    showToast("Sending to a list needs the list name, subject, and message body.", true);
    return;
  }
  await runClientGuard("group_send", async () => {
    await signedPost("/v1/mail/send_group", body);
    ui.groupSendForm.reset();
    await refreshAll();
    showToast(`Sent the message to ${body.group_name}.`);
  });
}

async function handleDetailAction(node) {
  if (!requireSession()) {
    return;
  }
  const message = lookupSelectedMessage();
  if (!message) {
    return;
  }
  const action = node.dataset.detailAction;
  try {
    if (action === "mark-read") {
      await runClientGuard("mark_read", async () => {
        await signedPost(`/v1/mail/mark_read/${message.message_id}`, { message_id: message.message_id });
        await refreshAll();
        showToast("Marked as read.");
      });
      return;
    }
    if (action === "recall") {
      await runClientGuard("recall", async () => {
        await signedPost("/v1/mail/recall", { message_id: message.message_id });
        await refreshAll();
        showToast("Recall request processed.");
      });
      return;
    }
    if (action === "quick-reply") {
      const replyText = node.dataset.replyText || "Received, thank you.";
      await runClientGuard("quick_reply", async () => {
        await signedPost("/v1/mail/send", {
          to: [message.from_email],
          cc: [],
          subject: `Re: ${message.subject}`,
          body_text: replyText,
          attachment_ids: [],
          thread_id: message.thread_id,
        });
        await refreshAll();
        showToast("Reply sent.");
      });
      return;
    }
    if (action === "execute-token") {
      const token = node.dataset.token;
      await runClientGuard("execute_action", async () => {
        const result = await signedPost("/v1/actions/execute", { token });
        await refreshAll();
        const status = String(result?.status || "");
        if (status === "todo_added") {
          showToast("Follow-up added.");
          return;
        }
        if (status === "calendar_event_added") {
          showToast("Calendar event added.");
          return;
        }
        if (status === "phishing_reported") {
          showToast("Message reported and flagged for review.");
          return;
        }
        if (status === "acknowledged") {
          showToast("Message marked as read.");
          return;
        }
        showToast("Action completed.");
      });
      return;
    }
    if (action === "load-draft") {
      fillComposeFromMessage(message);
      showToast("Draft opened in the message form.");
      return;
    }
    if (action === "preview-attachment") {
      const attachmentId = node.dataset.attachmentId;
      const filename = node.dataset.filename;
      await previewAttachment(attachmentId, filename);
      return;
    }
    if (action === "transform-attachment") {
      const attachmentId = node.dataset.attachmentId;
      const mode = node.dataset.mode;
      await transformAttachmentToComposer(attachmentId, mode);
    }
  } catch (error) {
    showToast(normalizeError(error), true);
  }
}

function fillComposeFromMessage(message) {
  ui.composeTo.value = message.to.join(", ");
  ui.composeCc.value = message.cc.join(", ");
  ui.composeSubject.value = message.subject;
  ui.composeBody.value = message.body_text;
  ui.composeE2E.checked = Boolean(message.e2e_encrypted);
  state.composeAttachments = [...message.attachments];
  syncComposeMode();
  renderAttachments();
}

async function buildComposeBody() {
  const to = csv(ui.composeTo.value);
  const cc = csv(ui.composeCc.value);
  const subject = ui.composeSubject.value.trim();
  const bodyText = ui.composeBody.value.trim();
  if (ui.composeE2E.checked) {
    const envelope = await buildE2EEnvelope(to, cc, subject, bodyText);
    return {
      to,
      cc,
      subject: "[End-to-end encrypted message]",
      body_text: "",
      attachment_ids: [],
      thread_id: null,
      e2e_envelope: envelope,
    };
  }
  return {
    to,
    cc,
    subject,
    body_text: bodyText,
    attachment_ids: state.composeAttachments.map((attachment) => attachment.id),
    thread_id: null,
  };
}

async function buildE2EEnvelope(to, cc, subject, bodyText) {
  if (!window.crypto?.subtle) {
    throw new Error("This browser does not support the Web Crypto APIs needed for E2E encryption.");
  }
  const identity = await ensureE2EIdentityPublished();
  const recipients = [...new Set([...to, ...cc])];
  const resolved = await signedPost("/v1/keys/resolve", { emails: recipients });
  if (resolved.missing?.length) {
    throw new Error(`Missing E2E public keys for: ${resolved.missing.join(", ")}`);
  }
  const recipientMap = Object.fromEntries((resolved.keys || []).map((item) => [item.email, item.public_key]));
  recipientMap[state.session.email] = identity.publicKey;

  const ephemeral = await window.crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
  const ephemeralPublicRaw = new Uint8Array(await window.crypto.subtle.exportKey("raw", ephemeral.publicKey));
  const contentKeyBytes = randomBytes(32);
  const payloadNonce = randomBytes(12);
  const contentKey = await window.crypto.subtle.importKey(
    "raw",
    contentKeyBytes,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
  const payloadPlaintext = encoder().encode(
    JSON.stringify({ subject, body_text: bodyText })
  );
  const payloadCiphertext = new Uint8Array(
    await window.crypto.subtle.encrypt({ name: "AES-GCM", iv: payloadNonce }, contentKey, payloadPlaintext)
  );
  const recipientKeys = {};
  for (const [email, publicKeyB64] of Object.entries(recipientMap)) {
    const recipientPublic = await importRecipientPublicKey(publicKeyB64);
    const sharedBits = await window.crypto.subtle.deriveBits(
      { name: "ECDH", public: recipientPublic },
      ephemeral.privateKey,
      256
    );
    const salt = randomBytes(16);
    const wrapKey = await deriveWrapKey(sharedBits, salt);
    const wrapNonce = randomBytes(12);
    const wrappedKey = new Uint8Array(
      await window.crypto.subtle.encrypt({ name: "AES-GCM", iv: wrapNonce }, wrapKey, contentKeyBytes)
    );
    recipientKeys[email] = {
      salt_b64: bytesToBase64Url(salt),
      nonce_b64: bytesToBase64Url(wrapNonce),
      wrapped_key_b64: bytesToBase64Url(wrappedKey),
    };
  }
  return {
    version: "ecc-p256-aesgcm-v1",
    algorithm: "ECDH-P256-HKDF-SHA256-AESGCM",
    curve: "P-256",
    ephemeral_public_key: bytesToBase64Url(ephemeralPublicRaw),
    payload_nonce_b64: bytesToBase64Url(payloadNonce),
    payload_ciphertext_b64: bytesToBase64Url(payloadCiphertext),
    recipient_keys: recipientKeys,
  };
}

async function decryptEnvelopeForSession(envelope) {
  if (!envelope || !state.session?.e2e_private_jwk) {
    return null;
  }
  const recipientEntry = envelope.recipient_keys?.[state.session.email];
  if (!recipientEntry) {
    throw new Error("No wrapped key for the active user.");
  }
  const privateKey = await window.crypto.subtle.importKey(
    "jwk",
    state.session.e2e_private_jwk,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"]
  );
  const ephemeralPublic = await importRecipientPublicKey(envelope.ephemeral_public_key);
  const sharedBits = await window.crypto.subtle.deriveBits(
    { name: "ECDH", public: ephemeralPublic },
    privateKey,
    256
  );
  const wrapKey = await deriveWrapKey(sharedBits, base64UrlToBytes(recipientEntry.salt_b64));
  const contentKeyBytes = new Uint8Array(
    await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64UrlToBytes(recipientEntry.nonce_b64) },
      wrapKey,
      base64UrlToBytes(recipientEntry.wrapped_key_b64)
    )
  );
  const contentKey = await window.crypto.subtle.importKey(
    "raw",
    contentKeyBytes,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );
  const plaintext = new Uint8Array(
    await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64UrlToBytes(envelope.payload_nonce_b64) },
      contentKey,
      base64UrlToBytes(envelope.payload_ciphertext_b64)
    )
  );
  return JSON.parse(decoder().decode(plaintext));
}

function renderAttachments() {
  if (!state.composeAttachments.length) {
    ui.attachmentList.innerHTML = '<div class="text-list">No attachments added to this message yet.</div>';
    return;
  }
  ui.attachmentList.innerHTML = state.composeAttachments
    .map((attachment) => {
      const transformModes = Array.isArray(attachment?.analysis?.transform_modes)
        ? attachment.analysis.transform_modes
        : [];
      const transformButtons =
        isImageAttachment(attachment) && transformModes.length
          ? transformModes
              .filter((mode) => ["anime", "photo_boost", "thumbnail"].includes(mode))
              .map((mode) => {
                const label = {
                  anime: "Stylized Copy",
                  photo_boost: "Enhance Photo",
                  thumbnail: "Small Preview",
                }[mode] || mode;
                return `
                  <button type="button" class="ghost-button" data-transform-compose-attachment="${escapeHtml(attachment.id)}" data-mode="${escapeHtml(mode)}">
                    ${escapeHtml(label)}
                  </button>
                `;
              })
              .join("")
          : "";
      return `
        <div class="attachment-chip-card">
          <div class="chip">
            <span>${escapeHtml(attachment.filename)}</span>
            <button type="button" data-remove-attachment="${escapeHtml(attachment.id)}" aria-label="Remove attachment">x</button>
          </div>
          <div class="text-list">${escapeHtml(composeAttachmentSummary(attachment))}</div>
          ${transformButtons ? `<div class="inline-actions">${transformButtons}</div>` : ""}
        </div>
      `
    })
    .join("");
  ui.attachmentList.querySelectorAll("[data-remove-attachment]").forEach((button) => {
    button.addEventListener("click", () => {
      const attachmentId = button.dataset.removeAttachment;
      state.composeAttachments = state.composeAttachments.filter((item) => item.id !== attachmentId);
      renderAttachments();
    });
  });
  ui.attachmentList.querySelectorAll("[data-transform-compose-attachment]").forEach((button) => {
    button.addEventListener("click", () => {
      const attachmentId = button.dataset.transformComposeAttachment;
      const mode = button.dataset.mode;
      void transformAttachmentToComposer(attachmentId, mode);
    });
  });
}

function composeAttachmentSummary(attachment) {
  const analysis = attachment.analysis || {};
  const contentType = attachment.content_type || "application/octet-stream";
  if (!isImageAttachment(attachment)) {
    return `${contentType} | file stored`;
  }
  const dimensions = analysis.dimensions
    ? `${analysis.dimensions.width}x${analysis.dimensions.height}`
    : "dimensions unavailable";
  const verdict = analysis.suspicious ? "needs review" : "ready";
  return `${dimensions} | ${verdict}`;
}

function renderAttachmentAnalysisCard(attachment, includeTransformActions = false) {
  const analysis = attachment.analysis || {};
  const imageAttachment = isImageAttachment(attachment);
  const labels = Array.isArray(analysis.labels) ? analysis.labels : [];
  const reasons = Array.isArray(analysis.reasons) ? analysis.reasons : [];
  const dimensions = analysis.dimensions
    ? `${analysis.dimensions.width}x${analysis.dimensions.height}`
    : "unknown size";
  const summary = analysis.summary || `${attachment.content_type} attachment`;
  const riskLabel = imageAttachment
    ? (analysis.suspicious
        ? "Attachment review suggests checking this image before trusting it."
        : "Attachment review did not find a strong warning sign.")
    : "Non-image attachment. Image AI checks were skipped.";
  const reasonText = reasons.length
    ? reasons.map((reason) => humanizeSecurityReason(reason)).join(", ")
    : "";
  const transformModes = Array.isArray(analysis.transform_modes) ? analysis.transform_modes : [];
  const transformActions =
    includeTransformActions && imageAttachment
      ? transformModes
          .filter((mode) => ["anime", "photo_boost", "thumbnail"].includes(mode))
          .map((mode) => {
            const label = {
              anime: "Stylized Copy",
              photo_boost: "Enhance Photo",
              thumbnail: "Small Preview",
            }[mode] || mode;
            return `
              <button type="button" class="ghost-button" data-detail-action="transform-attachment" data-attachment-id="${escapeHtml(attachment.id)}" data-mode="${escapeHtml(mode)}">
                ${escapeHtml(label)}
              </button>
            `;
          })
          .join("")
      : "";
  const previewAction =
    imageAttachment && analysis.preview_ready !== false
      ? `
        <button type="button" class="ghost-button" data-detail-action="preview-attachment" data-attachment-id="${escapeHtml(attachment.id)}" data-filename="${escapeHtml(attachment.filename)}">
          Open Preview
        </button>
      `
      : "";
  return `
    <div class="attachment-card">
      <strong>${escapeHtml(attachment.filename)}</strong>
      <div class="text-list">${escapeHtml(summary)}</div>
      <div class="text-list">${escapeHtml(imageAttachment ? dimensions : attachment.content_type || "application/octet-stream")}</div>
      <div class="text-list">${escapeHtml(riskLabel)}</div>
      <div class="mail-tags">
        ${(labels.length ? labels : [imageAttachment ? "image" : "file"]).map((label) => `<span>${escapeHtml(label)}</span>`).join("")}
      </div>
      ${
        reasonText
          ? `<div class="text-list">Review notes: ${escapeHtml(reasonText)}</div>`
          : ""
      }
      ${(previewAction || transformActions) ? `<div class="detail-actions">${previewAction}${transformActions}</div>` : ""}
    </div>
  `;
}

function isImageAttachment(attachment) {
  return String(attachment?.content_type || "").toLowerCase().startsWith("image/");
}

function renderSearchContacts() {
  if (!state.searchContacts.length) {
    ui.searchContacts.innerHTML = "";
    return;
  }
  ui.searchContacts.innerHTML = `
    <strong>Matching Contacts</strong>
    <ul>
      ${state.searchContacts
        .map((contact) => `<li>${escapeHtml(contact.email)}</li>`)
        .join("")}
    </ul>
  `;
}

function renderMailboxTabs() {
  ui.mailboxTabs.querySelectorAll("[data-mailbox]").forEach((button) => {
    button.classList.toggle("active", button.dataset.mailbox === state.activeMailbox);
  });
}

function renderMailboxList() {
  if (!state.session) {
    ui.mailboxList.innerHTML = `
      <div class="empty-state">
        <strong>Sign in to open your mailbox</strong>
        <p>Your messages stay protected until you sign in.</p>
      </div>
    `;
    return;
  }
  if (state.activeMailbox === "todos") {
    ui.mailboxList.innerHTML = state.todos.length
      ? state.todos
          .map(
            (todo) => `
              <article class="mail-card">
                <strong>${escapeHtml(todo.title)}</strong>
                <div class="mail-snippet">Added ${escapeHtml(formatTime(todo.created_at))}</div>
              </article>
            `
          )
          .join("")
      : `
        <div class="empty-state">
          <strong>No follow-ups yet</strong>
          <p>Helpful message actions can add reminders here.</p>
        </div>
      `;
    return;
  }
  if (state.activeMailbox === "calendar") {
    ui.mailboxList.innerHTML = state.calendarEvents.length
      ? state.calendarEvents
          .map(
            (event) => `
              <article class="mail-card">
                <strong>${escapeHtml(event.title)}</strong>
                <div class="mail-snippet">Starts ${escapeHtml(formatTime(event.starts_at))} (${escapeHtml(String(event.duration_minutes))} min)</div>
              </article>
            `
          )
          .join("")
      : `
        <div class="empty-state">
          <strong>No calendar items yet</strong>
          <p>Use "Add To Calendar" from an inbox message to create one-click schedule items.</p>
        </div>
      `;
    return;
  }
  const messages = currentMailboxMessages();
  if (!messages.length) {
    const mailboxName = {
      inbox: "inbox",
      sent: "sent mail",
      drafts: "drafts",
      calendar: "calendar",
      search: "search results",
      todos: "follow-ups",
    }[state.activeMailbox] || state.activeMailbox;
    ui.mailboxList.innerHTML = `
      <div class="empty-state">
        <strong>No messages in ${escapeHtml(mailboxName)}</strong>
        <p>Try refreshing the mailbox or sending a message from another account.</p>
      </div>
    `;
    return;
  }
  ui.mailboxList.innerHTML = messages
    .map((message) => {
      const tags = friendlyMessageTags(message);
      return `
        <article class="mail-card ${message.message_id === state.selectedMessageId ? "active" : ""}" data-message-id="${escapeHtml(message.message_id)}">
          <strong>${escapeHtml(message.subject || "(no subject)")}</strong>
          <div class="mail-meta">${escapeHtml(message.from_email)} -> ${escapeHtml(message.to.join(", "))}</div>
          <div class="mail-snippet">${escapeHtml(message.body_text)}</div>
          <div class="mail-tags">${tags.map((tag) => `<span>${escapeHtml(tag)}</span>`).join("")}</div>
        </article>
      `;
    })
    .join("");
}

function renderDetail() {
  const message = lookupSelectedMessage();
  if (!message) {
    ui.detailView.innerHTML = `
      <div class="empty-state">
        <strong>No message selected</strong>
        <p>Select a message from the list to read it here.</p>
      </div>
    `;
    return;
  }
  const suspicious = Boolean(message.security_flags?.suspicious);
  const statusLabel = describeMessageStatus(message);
  const securityState = describeSecurityState(message);
  const e2eBox =
    message.e2e_encrypted
      ? `
        <div class="security-box safe">
          <strong>End-to-end encrypted message</strong>
          <div class="mail-snippet">
            ${
              message.security_flags?.e2e_decrypted_local
                ? "Decrypted locally in this browser. The server only handled protected ciphertext."
                : "Protected content was delivered. Your local private key is required to open the message text."
            }
          </div>
        </div>
      `
      : "";
  const previewMarkup =
    state.preview && state.preview.messageId === message.message_id
      ? `
        <div class="attachment-preview">
          <span>Image Preview</span>
          <img src="${state.preview.url}" alt="${escapeHtml(state.preview.filename)}">
        </div>
      `
      : "";
  ui.detailView.innerHTML = `
    <article class="detail-shell">
      <div>
        <h3 class="detail-title">${escapeHtml(message.subject || "(no subject)")}</h3>
        <div class="mail-meta">${escapeHtml(message.from_email)} -> ${escapeHtml(message.to.join(", "))}</div>
      </div>
      <div class="meta-grid">
        <div><span>Status</span><strong>${escapeHtml(statusLabel)}</strong></div>
        <div><span>Created</span><strong>${escapeHtml(formatTime(message.created_at))}</strong></div>
      </div>
      <div class="security-box ${suspicious ? "" : "safe"}">
        <strong>${escapeHtml(securityState.title)}</strong>
        <div class="mail-snippet">${escapeHtml(securityState.body)}</div>
      </div>
      ${e2eBox}
      <div class="detail-body">${escapeHtml(message.body_text)}</div>
      <div class="detail-block">
        <span>Highlights</span>
        <div class="mail-tags">${message.keywords.map((keyword) => `<span>${escapeHtml(keyword)}</span>`).join("") || "<span>None</span>"}</div>
      </div>
      <div class="detail-block">
        <span>Attachments</span>
        <div class="attachment-stack">
          ${
            message.attachments.length
              ? message.attachments
                  .map(
                    (attachment) => renderAttachmentAnalysisCard(attachment, true)
                  )
                  .join("")
              : '<div class="text-list">No attachments on this message.</div>'
          }
        </div>
        ${previewMarkup}
      </div>
      <div class="detail-block">
        <span>Message Tools</span>
        <div class="detail-actions">
          ${message.folder === "inbox" && !message.is_read ? `<button type="button" data-detail-action="mark-read">Mark As Read</button>` : ""}
          ${message.folder === "sent" && !message.recalled ? `<button type="button" class="secondary-button" data-detail-action="recall">Recall Message</button>` : ""}
          ${message.folder === "draft" ? `<button type="button" class="ghost-button" data-detail-action="load-draft">Open Draft</button>` : ""}
          ${
            !message.folder || (message.folder !== "draft" && message.folder !== "sent" && message.folder !== "inbox")
              ? ""
              : ""
          }
        </div>
      </div>
      <div class="detail-block">
        <span>Suggested Replies</span>
        <div class="detail-replies">
          ${
            message.quick_replies.length
              ? message.quick_replies
                  .map(
                    (reply) => `
                      <button type="button" class="ghost-button" data-detail-action="quick-reply" data-reply-text="${escapeHtml(reply)}">
                        ${escapeHtml(reply)}
                      </button>
                    `
                  )
                  .join("")
              : '<div class="text-list">No suggested replies for this message.</div>'
          }
        </div>
      </div>
      <div class="detail-block">
        <span>Helpful Actions</span>
        <div class="detail-actions">
          ${
            message.actions.length
              ? message.actions
                  .map(
                    (action) => `
                      <button type="button" class="secondary-button" data-detail-action="execute-token" data-token="${escapeHtml(action.token)}">
                        ${escapeHtml(action.label)}
                      </button>
                    `
                  )
                  .join("")
              : '<div class="text-list">No suggested actions for this message.</div>'
          }
        </div>
      </div>
    </article>
  `;
}

async function previewAttachment(attachmentId, filename) {
  revokePreview();
  const response = await fetch(`/v1/attachments/${attachmentId}`, {
    headers: {
      Authorization: `Bearer ${state.session.session_token}`,
    },
  });
  if (!response.ok) {
    throw await parseError(response);
  }
  const blob = await response.blob();
  state.preview = {
    messageId: state.selectedMessageId,
    filename,
    url: URL.createObjectURL(blob),
  };
  renderDetail();
}

async function transformAttachmentToComposer(attachmentId, mode) {
  if (!requireSession()) {
    return;
  }
  const transformed = await runClientGuard(`transform_${attachmentId}_${mode}`, async () => {
    return signedPost(`/v1/attachments/${attachmentId}/transform`, { mode });
  });
  if (!transformed) {
    return;
  }
  state.composeAttachments.push(transformed);
  renderAttachments();
  showToast(`${transformed.filename} was added to the message.`);
}

function revokePreview() {
  if (state.preview?.url) {
    URL.revokeObjectURL(state.preview.url);
  }
  state.preview = null;
}

function currentMailboxMessages() {
  return state.mailboxes[state.activeMailbox] || [];
}

function lookupSelectedMessage() {
  if (!state.selectedMessageId) {
    return null;
  }
  const allMessages = [
    ...state.mailboxes.inbox,
    ...state.mailboxes.sent,
    ...state.mailboxes.drafts,
    ...state.mailboxes.search,
  ];
  return allMessages.find((message) => message.message_id === state.selectedMessageId) || null;
}

function requireSession() {
  if (state.session) {
    return true;
  }
  showToast("Please sign in first.", true);
  return false;
}

async function runClientGuard(key, action) {
  const now = Date.now();
  const lastRun = actionCooldowns.get(key) || 0;
  if (actionLocks.has(key)) {
    showToast("This action is already running.", true);
    return null;
  }
  if (now - lastRun < CLIENT_ACTION_COOLDOWN_MS) {
    showToast("Please slow down and wait a moment before repeating that action.", true);
    return null;
  }
  actionLocks.add(key);
  try {
    const result = await action();
    actionCooldowns.set(key, Date.now());
    return result;
  } catch (error) {
    showToast(normalizeError(error), true);
    return null;
  } finally {
    actionLocks.delete(key);
  }
}

async function authGet(path, params = null) {
  const query = params ? `?${new URLSearchParams(params).toString()}` : "";
  return fetchJson(`${path}${query}`, {
    headers: {
      Authorization: `Bearer ${state.session.session_token}`,
    },
  });
}

async function signedPost(path, body) {
  const headers = await buildSignedHeaders(path, body);
  const result = await fetchJson(path, {
    method: "POST",
    body,
    headers: {
      Authorization: `Bearer ${state.session.session_token}`,
      ...headers,
    },
  });
  syncSessionCard();
  return result;
}

function friendlyMessageTags(message) {
  const tags = [];
  if (message.recalled) {
    tags.push("Recalled");
  } else if (message.delivery_state) {
    tags.push(describeMessageStatus(message));
  }
  if (message.classification && message.classification !== "General" && message.classification !== "Encrypted") {
    tags.push(message.classification);
  }
  if (message.e2e_encrypted) {
    tags.push("Private");
  }
  if (message.security_flags?.suspicious) {
    tags.push("Review");
  }
  return tags;
}

function describeMessageStatus(message) {
  if (message.recalled || message.recall_status === "recalled") {
    return "Recalled";
  }
  const state = String(message.delivery_state || "").toLowerCase();
  if (state === "queued") {
    return "Sending";
  }
  if (state === "partial") {
    return "Partially delivered";
  }
  if (state === "failed") {
    return "Needs attention";
  }
  if (state === "recalled") {
    return "Recalled";
  }
  if (state === "draft") {
    return "Draft";
  }
  return "Delivered";
}

function describeSecurityState(message) {
  if (message.security_flags?.suspicious) {
    const reasons = Array.isArray(message.security_flags?.reasons)
      ? message.security_flags.reasons.map((reason) => humanizeSecurityReason(reason))
      : [];
    return {
      title: "This message may be risky",
      body: reasons.length
        ? `Warning signs detected: ${reasons.join(", ")}.`
        : "The message looks unusual, so treat links and requests carefully.",
    };
  }
  if (message.e2e_encrypted) {
    return {
      title: "Private message protection is active",
      body: "This message was delivered as end-to-end encrypted content and decrypted locally in your browser when possible.",
    };
  }
  return {
    title: "No strong warning sign was detected",
    body: "Basic phishing and content checks did not flag this message.",
  };
}

function humanizeSecurityReason(reason) {
  const labels = {
    credentials_visible: "visible password or credentials",
    credential_prompt_ui: "login prompt styling",
    invoice_like_content: "invoice-like content",
    payment_language_in_image: "payment wording",
    banking_language_in_image: "banking wording",
    verification_language_in_image: "verification request",
    qr_code_present: "QR code",
    suspicious_filename_tokens: "suspicious filename",
    tracking_pixel_like: "tracking-pixel pattern",
    very_small_image: "very small image",
    extreme_aspect_ratio: "extreme image shape",
    low_visual_diversity: "very low visual variation",
    too_many_links: "too many links",
    urgent_language: "urgent language",
    password_request: "password request",
    payment_request: "payment request",
    remote_domain_mismatch: "sender/domain mismatch",
    suspicious_tld: "unusual top-level domain",
    hf_label_phishing: "model-based phishing signal",
    local_llm_reviewed: "reviewed by local smart module",
  };
  return labels[reason] || reason.replace(/_/g, " ");
}

async function buildSignedHeaders(path, body) {
  if (!window.crypto?.subtle) {
    throw new Error("This browser does not provide Web Crypto for secure request signing.");
  }
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

function encoder() {
  return new TextEncoder();
}

function decoder() {
  return new TextDecoder();
}

function randomBytes(length) {
  const bytes = new Uint8Array(length);
  window.crypto.getRandomValues(bytes);
  return bytes;
}

function bytesToBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4 || 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

async function importRecipientPublicKey(publicKeyB64) {
  return window.crypto.subtle.importKey(
    "raw",
    base64UrlToBytes(publicKeyB64),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );
}

async function deriveWrapKey(sharedBits, saltBytes) {
  const hkdfKey = await window.crypto.subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);
  return window.crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: saltBytes,
      info: encoder().encode("secure-email-e2e-wrap-v1"),
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
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

function normalizeError(error) {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

function randomId() {
  if (window.crypto?.randomUUID) {
    return window.crypto.randomUUID();
  }
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function csv(value) {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

async function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = String(reader.result);
      resolve(result.split(",", 2)[1]);
    };
    reader.onerror = () => reject(new Error("Failed to read file."));
    reader.readAsDataURL(file);
  });
}

function formatTime(value) {
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
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

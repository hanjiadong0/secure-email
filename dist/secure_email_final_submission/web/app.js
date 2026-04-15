const STORAGE_KEY = `secure-email:web:${window.location.origin}`;
const LEGACY_STORAGE = window.localStorage;
const SESSION_STORAGE = window.sessionStorage;

const state = {
  domain: "",
  smartStatus: null,
  composeAssistStatus: null,
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
  groups: [],
  savedAttachments: [],
  searchContacts: [],
  selectedMessageId: null,
  composeDraftMessageId: null,
  composeThreadId: null,
  composeContextMessageId: null,
  composeUndoSnapshot: null,
  composeAttachments: [],
  selectedLocalAttachment: null,
  preview: null,
};

const ui = {};
const actionLocks = new Set();
const actionCooldowns = new Map();
const CLIENT_ACTION_COOLDOWN_MS = 900;
const MAILBOX_AUTO_REFRESH_MS = 3000;
const attachmentImageUrls = new Map();
const attachmentImageLoads = new Map();
let autoRefreshTimer = null;

document.addEventListener("DOMContentLoaded", () => {
  void initialize();
});

async function initialize() {
  cacheUi();
  bindUi();
  restoreSession();
  syncSessionCard();
  syncComposeMode();
  renderComposeAssistStatus();
  renderSecurityEvidence();
  renderSelectedAttachmentPreview();
  renderAttachments();
  renderSavedAttachmentsLibrary();
  renderSavedGroups();
  renderMailboxTabs();
  renderMailboxList();
  renderDetail();
  await loadHealth();
  if (state.session) {
    startAutoRefresh();
    await refreshAll();
  }
}

function cacheUi() {
  ui.domainBadge = document.getElementById("domainBadge");
  ui.serviceStatus = document.getElementById("serviceStatus");
  ui.sessionUser = document.getElementById("sessionUser");
  ui.smartStatus = document.getElementById("smartStatus");
  ui.smartStatusDetail = document.getElementById("smartStatusDetail");
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
  ui.composeGroupPicker = document.getElementById("composeGroupPicker");
  ui.composeGroupPreview = document.getElementById("composeGroupPreview");
  ui.addGroupToToButton = document.getElementById("addGroupToToButton");
  ui.addGroupToCcButton = document.getElementById("addGroupToCcButton");
  ui.editSelectedGroupButton = document.getElementById("editSelectedGroupButton");
  ui.composeSubject = document.getElementById("composeSubject");
  ui.composeBody = document.getElementById("composeBody");
  ui.composeAssistPrompt = document.getElementById("composeAssistPrompt");
  ui.composeAssistDraftButton = document.getElementById("composeAssistDraftButton");
  ui.composeAssistContinueButton = document.getElementById("composeAssistContinueButton");
  ui.composeAssistPolishButton = document.getElementById("composeAssistPolishButton");
  ui.composeAssistUndoButton = document.getElementById("composeAssistUndoButton");
  ui.composeAssistStatus = document.getElementById("composeAssistStatus");
  ui.composeE2E = document.getElementById("composeE2E");
  ui.composeE2EHint = document.getElementById("composeE2EHint");
  ui.attachmentFile = document.getElementById("attachmentFile");
  ui.uploadAttachmentButton = document.getElementById("uploadAttachmentButton");
  ui.saveDraftButton = document.getElementById("saveDraftButton");
  ui.clearComposeButton = document.getElementById("clearComposeButton");
  ui.selectedAttachmentPreview = document.getElementById("selectedAttachmentPreview");
  ui.attachmentList = document.getElementById("attachmentList");
  ui.attachmentLibrarySearch = document.getElementById("attachmentLibrarySearch");
  ui.attachmentLibrarySummary = document.getElementById("attachmentLibrarySummary");
  ui.attachmentLibraryList = document.getElementById("attachmentLibraryList");
  ui.searchForm = document.getElementById("searchForm");
  ui.searchQuery = document.getElementById("searchQuery");
  ui.clearSearchButton = document.getElementById("clearSearchButton");
  ui.refreshButton = document.getElementById("refreshButton");
  ui.searchContacts = document.getElementById("searchContacts");
  ui.groupCreateForm = document.getElementById("groupCreateForm");
  ui.groupName = document.getElementById("groupName");
  ui.groupMembers = document.getElementById("groupMembers");
  ui.savedGroupsList = document.getElementById("savedGroupsList");
  ui.runSecuritySimulationButton = document.getElementById("runSecuritySimulationButton");
  ui.refreshSecurityEvidenceButton = document.getElementById("refreshSecurityEvidenceButton");
  ui.securitySummary = document.getElementById("securitySummary");
  ui.securityAttackerDefenderImage = document.getElementById("securityAttackerDefenderImage");
  ui.securityScenarioMatrixImage = document.getElementById("securityScenarioMatrixImage");
  ui.mailboxTabs = document.getElementById("mailboxTabs");
  ui.mailboxList = document.getElementById("mailboxList");
  ui.detailView = document.getElementById("detailView");
  ui.imagePreviewModal = document.getElementById("imagePreviewModal");
  ui.imagePreviewImage = document.getElementById("imagePreviewImage");
  ui.imagePreviewCaption = document.getElementById("imagePreviewCaption");
  ui.closeImagePreviewButton = document.getElementById("closeImagePreviewButton");
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
  ui.composeAssistDraftButton?.addEventListener("click", () => {
    void handleComposeAssist("draft");
  });
  ui.composeAssistContinueButton?.addEventListener("click", () => {
    void handleComposeAssist("continue");
  });
  ui.composeAssistPolishButton?.addEventListener("click", () => {
    void handleComposeAssist("polish");
  });
  ui.composeAssistUndoButton?.addEventListener("click", handleComposeUndo);
  ui.attachmentFile?.addEventListener("change", () => {
    void handleSelectedAttachmentChange();
  });
  ui.uploadAttachmentButton.addEventListener("click", () => {
    void handleUploadAttachment();
  });
  ui.saveDraftButton.addEventListener("click", () => {
    void handleSaveDraft();
  });
  ui.clearComposeButton.addEventListener("click", clearCompose);
  ui.attachmentLibrarySearch?.addEventListener("input", renderSavedAttachmentsLibrary);
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
  ui.composeGroupPicker?.addEventListener("change", renderSavedGroups);
  ui.addGroupToToButton?.addEventListener("click", () => {
    applySelectedGroupToCompose("to");
  });
  ui.addGroupToCcButton?.addEventListener("click", () => {
    applySelectedGroupToCompose("cc");
  });
  ui.editSelectedGroupButton?.addEventListener("click", () => {
    loadSelectedGroupIntoEditor();
  });
  ui.savedGroupsList?.addEventListener("click", (event) => {
    const actionNode = event.target.closest("[data-group-action]");
    if (!actionNode) {
      return;
    }
    const groupName = actionNode.dataset.groupName;
    if (!groupName) {
      return;
    }
    if (actionNode.dataset.groupAction === "edit") {
      loadGroupIntoEditor(groupName);
      return;
    }
    if (actionNode.dataset.groupAction === "compose") {
      selectComposeGroup(groupName);
      applySelectedGroupToCompose("to");
    }
  });
  ui.attachmentLibraryList?.addEventListener("click", (event) => {
    const actionNode = event.target.closest("[data-attachment-action]");
    if (!actionNode) {
      return;
    }
    const attachmentId = actionNode.dataset.attachmentId;
    if (!attachmentId) {
      return;
    }
    const action = actionNode.dataset.attachmentAction;
    if (action === "attach") {
      addSavedAttachmentToCompose(attachmentId);
      return;
    }
    if (action === "open") {
      const filename = actionNode.dataset.filename || "attachment";
      const contentType = actionNode.dataset.contentType || "application/octet-stream";
      void openAttachmentFile(attachmentId, filename, contentType);
      return;
    }
    if (action === "delete") {
      void deleteSavedAttachment(attachmentId);
      return;
    }
    if (action === "compress") {
      void compressAttachmentCopy(attachmentId, { addToCompose: false });
      return;
    }
    if (action === "transform") {
      const mode = actionNode.dataset.mode;
      if (mode) {
        void transformAttachmentToComposer(attachmentId, mode);
      }
    }
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
  ui.closeImagePreviewButton?.addEventListener("click", closeImagePreview);
  ui.imagePreviewModal?.addEventListener("click", (event) => {
    if (event.target === ui.imagePreviewModal) {
      closeImagePreview();
    }
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && ui.imagePreviewModal && !ui.imagePreviewModal.hidden) {
      closeImagePreview();
    }
  });
  document.addEventListener("visibilitychange", () => {
    if (state.session && document.visibilityState === "visible") {
      startAutoRefresh();
      void refreshAll({ silent: true });
      return;
    }
    if (document.visibilityState !== "visible") {
      stopAutoRefresh();
    }
  });
  window.addEventListener("focus", () => {
    if (state.session) {
      startAutoRefresh();
      void refreshAll({ silent: true });
    }
  });
}

function humanizeSmartBackend(backend) {
  const labels = {
    heuristic: "Heuristic",
    heuristic_fallback: "Fallback",
    ollama: "Ollama",
    huggingface_local: "Hugging Face",
    openai: "OpenAI",
  };
  return labels[String(backend || "").toLowerCase()] || backend || "Smart module";
}

function describeGlobalSmartStatus(smart) {
  if (!smart) {
    return {
      title: "Unknown",
      detail: "Smart-module health is not available yet.",
    };
  }
  const configured = humanizeSmartBackend(smart.configured_backend);
  const effective = humanizeSmartBackend(smart.effective_backend);
  const backend = String(smart.effective_backend || smart.configured_backend || "").toLowerCase();
  if (smart.available && backend === "ollama") {
    return {
      title: "Local LLM Ready",
      detail: smart.detail || `Local Ollama is connected${smart.configured_model ? ` with ${smart.configured_model}` : ""}.`,
    };
  }
  if (smart.available && backend === "huggingface_local") {
    return {
      title: "Local NLP Ready",
      detail: smart.detail || `Local Hugging Face model${smart.configured_model ? ` ${smart.configured_model}` : ""} is ready.`,
    };
  }
  if (smart.available && backend === "openai") {
    return {
      title: "LLM Ready",
      detail: smart.detail || `Configured backend ${effective} is ready.`,
    };
  }
  if (backend === "heuristic_fallback") {
    return {
      title: "Fallback Active",
      detail: smart.detail || `${configured} is unavailable, so heuristic checks are active.`,
    };
  }
  if (backend === "heuristic") {
    return {
      title: "Heuristic Only",
      detail: smart.detail || `${configured} is not configured, so heuristic checks are active.`,
    };
  }
  return {
    title: effective,
    detail: smart.detail || `${configured} is configured.`,
  };
}

function syncSmartStatusCard() {
  if (!ui.smartStatus || !ui.smartStatusDetail) {
    return;
  }
  const summary = describeGlobalSmartStatus(state.smartStatus);
  ui.smartStatus.textContent = summary.title;
  ui.smartStatusDetail.textContent = summary.detail;
  renderComposeAssistStatus();
}

function lookupMessageById(messageId) {
  if (!messageId) {
    return null;
  }
  const allMessages = [
    ...state.mailboxes.inbox,
    ...state.mailboxes.sent,
    ...state.mailboxes.drafts,
    ...state.mailboxes.search,
  ];
  return allMessages.find((message) => message.message_id === messageId) || null;
}

function composeContextMessage() {
  const stored = lookupMessageById(state.composeContextMessageId);
  if (stored) {
    return stored;
  }
  const selected = lookupSelectedMessage();
  if (!selected || selected.folder === "draft") {
    return null;
  }
  if (!csv(ui.composeTo?.value || "").length && !ui.composeSubject?.value.trim() && !ui.composeBody?.value.trim()) {
    return selected;
  }
  if (state.composeThreadId && selected.thread_id === state.composeThreadId) {
    return selected;
  }
  return null;
}

function replySubject(subject) {
  const trimmed = String(subject || "").trim();
  if (!trimmed) {
    return "Re: Message";
  }
  return /^re:/i.test(trimmed) ? trimmed : `Re: ${trimmed}`;
}

function prepareComposeReplyFromMessage(message) {
  if (!message) {
    return;
  }
  state.composeDraftMessageId = null;
  state.composeUndoSnapshot = null;
  if (!csv(ui.composeTo.value).length) {
    ui.composeTo.value = message.folder === "inbox" ? message.from_email : message.to.join(", ");
  }
  if (!ui.composeSubject.value.trim()) {
    ui.composeSubject.value = replySubject(message.subject);
  }
  state.composeThreadId = message.thread_id || state.composeThreadId;
  state.composeContextMessageId = message.message_id;
  renderComposeAssistStatus();
}

function scrollComposeIntoView() {
  if (ui.composeForm?.scrollIntoView) {
    ui.composeForm.scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

function normalizeComparisonText(value) {
  return String(value || "")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

function mergeComposeDraftAtHead(existingText, suggestedText) {
  const existing = String(existingText || "").trim();
  const suggested = String(suggestedText || "").trim();
  if (!suggested) {
    return existing;
  }
  if (!existing) {
    return suggested;
  }
  const existingNorm = normalizeComparisonText(existing);
  const suggestedNorm = normalizeComparisonText(suggested);
  if (existingNorm === suggestedNorm) {
    return existing;
  }
  if (suggestedNorm.includes(existingNorm)) {
    return suggested;
  }
  return `${suggested}\n\n${existing}`;
}

function mergeComposeContinuation(existingText, suggestedText) {
  const existing = String(existingText || "").trim();
  const suggested = String(suggestedText || "").trim();
  if (!suggested) {
    return existing;
  }
  if (!existing) {
    return suggested;
  }
  const existingNorm = normalizeComparisonText(existing);
  const suggestedNorm = normalizeComparisonText(suggested);
  if (existingNorm === suggestedNorm) {
    return existing;
  }
  if (suggestedNorm.startsWith(existingNorm)) {
    const continuation = suggested.slice(existing.length).trim();
    return continuation ? `${existing}\n\n${continuation}` : existing;
  }
  return `${existing}\n\n${suggested}`;
}

function captureComposeSnapshot() {
  return {
    draftMessageId: state.composeDraftMessageId,
    threadId: state.composeThreadId,
    contextMessageId: state.composeContextMessageId,
    to: ui.composeTo.value,
    cc: ui.composeCc.value,
    subject: ui.composeSubject.value,
    body: ui.composeBody.value,
    assistPrompt: ui.composeAssistPrompt?.value || "",
  };
}

function restoreComposeSnapshot(snapshot) {
  if (!snapshot) {
    return;
  }
  state.composeDraftMessageId = snapshot.draftMessageId || null;
  state.composeThreadId = snapshot.threadId || null;
  state.composeContextMessageId = snapshot.contextMessageId || null;
  ui.composeTo.value = snapshot.to || "";
  ui.composeCc.value = snapshot.cc || "";
  ui.composeSubject.value = snapshot.subject || "";
  ui.composeBody.value = snapshot.body || "";
  if (ui.composeAssistPrompt) {
    ui.composeAssistPrompt.value = snapshot.assistPrompt || "";
  }
  renderComposeAssistStatus();
}

function applyComposeAssistResult(action, currentSubject, currentBody, result) {
  const suggestedSubject = String(result?.subject || "").trim();
  const suggestedBody = String(result?.body_text || "").trim();
  const nextSubject =
    action === "polish"
      ? suggestedSubject || currentSubject
      : currentSubject || suggestedSubject;
  let nextBody = currentBody;
  if (action === "polish") {
    nextBody = suggestedBody || currentBody;
  } else if (action === "continue") {
    nextBody = mergeComposeContinuation(currentBody, suggestedBody);
  } else {
    nextBody = mergeComposeDraftAtHead(currentBody, suggestedBody);
  }
  return {
    subject: nextSubject,
    body: nextBody,
  };
}

function stageReplyInCompose(message, replyText, sourceLabel) {
  prepareComposeReplyFromMessage(message);
  ui.composeBody.value = mergeComposeDraftAtHead(ui.composeBody.value, replyText);
  setComposeAssistStatus(`${sourceLabel} was added to the compose form. Review and send it manually.`, false);
  scrollComposeIntoView();
  ui.composeBody.focus();
}

function handleComposeUndo() {
  if (!state.composeUndoSnapshot) {
    return;
  }
  restoreComposeSnapshot(state.composeUndoSnapshot);
  state.composeUndoSnapshot = null;
  setComposeAssistStatus("The previous draft version was restored.", false);
  scrollComposeIntoView();
  ui.composeBody.focus();
  showToast("Previous AI draft restored.");
}

function defaultComposeAssistStatus() {
  const smart = state.smartStatus;
  const context = composeContextMessage();
  const contextText = context
    ? ` Reply context is active for "${context.subject || "(no subject)"}".`
    : "";
  if (!smart) {
    return {
      text: `The helper can use your prompt plus the current subject and body.${contextText}`.trim(),
      isError: false,
    };
  }
  if (smart.available) {
    const backend = humanizeSmartBackend(smart.effective_backend);
    const model = smart.configured_model ? ` (${smart.configured_model})` : "";
    return {
      text: `${backend}${model} is ready to help draft or continue your email.${contextText}`.trim(),
      isError: false,
    };
  }
  return {
    text: `${smart.detail || "Smart drafting is unavailable right now, so only guided templates can be used."}${contextText}`.trim(),
    isError: true,
  };
}

function setComposeAssistStatus(text, isError = false) {
  state.composeAssistStatus = { text, isError };
  renderComposeAssistStatus();
}

function syncComposeUndoButton() {
  if (!ui.composeAssistUndoButton) {
    return;
  }
  ui.composeAssistUndoButton.disabled = !state.composeUndoSnapshot;
}

function renderComposeAssistStatus() {
  if (!ui.composeAssistStatus) {
    return;
  }
  const message = state.composeAssistStatus || defaultComposeAssistStatus();
  ui.composeAssistStatus.textContent = message.text;
  ui.composeAssistStatus.classList.toggle("is-error", Boolean(message.isError));
  syncComposeUndoButton();
}

async function loadHealth(options = {}) {
  try {
    const data = await fetchJson("/health");
    state.domain = data.domain;
    state.smartStatus = data.smart || null;
    ui.domainBadge.textContent = data.domain;
    ui.serviceStatus.textContent = data.status === "ok" ? "Ready" : data.status.toUpperCase();
    syncSmartStatusCard();
  } catch (error) {
    ui.serviceStatus.textContent = "Offline";
    state.smartStatus = {
      configured_backend: "heuristic",
      effective_backend: "heuristic_fallback",
      available: false,
      detail: "Health check failed, so smart-module status could not be loaded.",
    };
    syncSmartStatusCard();
    if (!options.silent) {
      showToast(normalizeError(error), true);
    }
  }
}

function restoreSession() {
  try {
    const raw = SESSION_STORAGE.getItem(STORAGE_KEY);
    if (!raw) {
      LEGACY_STORAGE.removeItem(STORAGE_KEY);
      return;
    }
    state.session = JSON.parse(raw);
  } catch {
    state.session = null;
  }
}

function persistSession() {
  if (!state.session) {
    SESSION_STORAGE.removeItem(STORAGE_KEY);
    LEGACY_STORAGE.removeItem(STORAGE_KEY);
    return;
  }
  SESSION_STORAGE.setItem(STORAGE_KEY, JSON.stringify(state.session));
  LEGACY_STORAGE.removeItem(STORAGE_KEY);
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

function startAutoRefresh() {
  if (!state.session || autoRefreshTimer || document.visibilityState !== "visible") {
    return;
  }
  autoRefreshTimer = window.setInterval(() => {
    if (!state.session || document.visibilityState !== "visible") {
      stopAutoRefresh();
      return;
    }
    void refreshAll({ silent: true });
  }, MAILBOX_AUTO_REFRESH_MS);
}

function stopAutoRefresh() {
  if (autoRefreshTimer) {
    window.clearInterval(autoRefreshTimer);
    autoRefreshTimer = null;
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
    startAutoRefresh();
    await ensureE2EIdentityPublished();
    syncSessionCard();
    ui.loginForm.reset();
    state.activeMailbox = "inbox";
    await refreshAll();
    showToast(`Signed in as ${email}.`);
  });
}

function handleLogout() {
  stopAutoRefresh();
  state.session = null;
  state.refreshPromise = null;
  state.securityEvidence = null;
  state.mailboxes = { inbox: [], sent: [], drafts: [], search: [] };
  state.todos = [];
  state.calendarEvents = [];
  state.groups = [];
  state.savedAttachments = [];
  state.searchContacts = [];
  state.selectedMessageId = null;
  state.composeDraftMessageId = null;
  state.composeThreadId = null;
  state.composeContextMessageId = null;
  state.composeUndoSnapshot = null;
  state.composeAttachments = [];
  clearSelectedAttachmentPreview();
  revokeAttachmentImageCache();
  closeImagePreview();
  revokePreview();
  persistSession();
  syncSessionCard();
  renderSelectedAttachmentPreview();
  renderAttachments();
  renderSavedAttachmentsLibrary();
  renderSavedGroups();
  renderMailboxTabs();
  renderMailboxList();
  renderDetail();
  renderSecurityEvidence();
  showToast("Signed out.");
}

async function refreshAll(options = {}) {
  if (!requireSession()) {
    return;
  }
  if (state.refreshPromise) {
    return state.refreshPromise;
  }
  state.refreshPromise = (async () => {
    try {
      await ensureE2EIdentityPublished();
      const [dashboard, savedAttachments] = await Promise.all([
        authGet("/v1/mail/dashboard"),
        authGet("/v1/attachments"),
        loadHealth({ silent: true }),
      ]);
      state.mailboxes.inbox = await hydrateMailbox(dashboard.inbox || []);
      state.mailboxes.sent = await hydrateMailbox(dashboard.sent || []);
      state.mailboxes.drafts = await hydrateMailbox(dashboard.drafts || []);
      state.todos = dashboard.todos || [];
      state.calendarEvents = dashboard.calendar_events || [];
      state.groups = dashboard.groups || [];
      state.savedAttachments = savedAttachments || [];
      if (!lookupSelectedMessage() && state.mailboxes.inbox.length) {
        state.selectedMessageId = state.mailboxes.inbox[0].message_id;
      }
      renderSavedAttachmentsLibrary();
      renderSavedGroups();
      renderMailboxTabs();
      renderMailboxList();
      renderDetail();
      await refreshSecurityEvidence({ silent: true });
      syncSessionCard();
    } catch (error) {
      if (!options.silent) {
        showToast(normalizeError(error), true);
      }
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

async function refreshSavedAttachments(options = {}) {
  if (!state.session) {
    state.savedAttachments = [];
    renderSavedAttachmentsLibrary();
    return [];
  }
  try {
    state.savedAttachments = await authGet("/v1/attachments");
    renderSavedAttachmentsLibrary();
    return state.savedAttachments;
  } catch (error) {
    if (!options.silent) {
      showToast(normalizeError(error), true);
    }
    return [];
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

async function handleSelectedAttachmentChange() {
  clearSelectedAttachmentPreview();
  const file = ui.attachmentFile.files?.[0];
  if (!file) {
    renderSelectedAttachmentPreview();
    return;
  }
  state.selectedLocalAttachment = {
    filename: file.name,
    contentType: file.type || "application/octet-stream",
    sizeBytes: file.size || 0,
    previewUrl: file.type.startsWith("image/") ? await fileToDataUrl(file) : null,
  };
  renderSelectedAttachmentPreview();
}

function clearSelectedAttachmentPreview() {
  if (
    state.selectedLocalAttachment?.previewUrl &&
    ui.imagePreviewImage?.getAttribute("src") === state.selectedLocalAttachment.previewUrl
  ) {
    closeImagePreview();
  }
  state.selectedLocalAttachment = null;
}

function renderSelectedAttachmentPreview() {
  if (!ui.selectedAttachmentPreview) {
    return;
  }
  const item = state.selectedLocalAttachment;
  if (!item) {
    ui.selectedAttachmentPreview.innerHTML = "";
    return;
  }
  const thumbnail =
    item.previewUrl
      ? `
        <button type="button" class="attachment-thumb-button" data-local-preview-image="true">
          <div class="attachment-thumb">
            <img src="${item.previewUrl}" alt="${escapeHtml(item.filename)}">
          </div>
        </button>
      `
      : "";
  ui.selectedAttachmentPreview.innerHTML = `
    <div class="attachment-chip-card">
      <strong>${escapeHtml(item.filename)}</strong>
      <div class="text-list">${escapeHtml(formatBytes(item.sizeBytes))} | ${escapeHtml(item.contentType || "application/octet-stream")}</div>
      ${thumbnail || '<div class="text-list">Preview is available after upload for non-image attachments.</div>'}
    </div>
  `;
  ui.selectedAttachmentPreview.querySelector("[data-local-preview-image]")?.addEventListener("click", () => {
    openImagePreview(item.previewUrl, item.filename);
  });
}

function revokeAttachmentImageCache() {
  attachmentImageUrls.clear();
  attachmentImageLoads.clear();
}

function revokeAttachmentImageUrl(attachmentId) {
  attachmentImageUrls.delete(attachmentId);
  attachmentImageLoads.delete(attachmentId);
}

async function ensureAttachmentImageUrl(attachmentId) {
  if (attachmentImageUrls.has(attachmentId)) {
    return attachmentImageUrls.get(attachmentId);
  }
  if (attachmentImageLoads.has(attachmentId)) {
    return attachmentImageLoads.get(attachmentId);
  }
  const load = (async () => {
    const response = await fetch(`/v1/attachments/${attachmentId}`, {
      headers: {
        Authorization: `Bearer ${state.session.session_token}`,
      },
    });
    if (!response.ok) {
      throw await parseError(response);
    }
    const blob = await response.blob();
    if (!String(blob.type || "").toLowerCase().startsWith("image/")) {
      throw new Error("This attachment is not an image preview.");
    }
    const url = await blobToDataUrl(blob);
    attachmentImageUrls.set(attachmentId, url);
    attachmentImageLoads.delete(attachmentId);
    return url;
  })().catch((error) => {
    attachmentImageLoads.delete(attachmentId);
    throw error;
  });
  attachmentImageLoads.set(attachmentId, load);
  return load;
}

async function hydrateAttachmentThumbnails(root) {
  if (!root || !state.session) {
    return;
  }
  const nodes = root.querySelectorAll("[data-attachment-thumbnail]");
  await Promise.all(
    Array.from(nodes).map(async (node) => {
      const attachmentId = node.dataset.attachmentThumbnail;
      const filename = node.dataset.filename || "attachment";
      if (!attachmentId) {
        return;
      }
      try {
        const url = await ensureAttachmentImageUrl(attachmentId);
        if (!node.isConnected) {
          return;
        }
        node.innerHTML = `<img src="${url}" alt="${escapeHtml(filename)}">`;
      } catch (error) {
        if (node.isConnected) {
          node.textContent = normalizeError(error);
        }
      }
    })
  );
}

async function openAttachmentImagePreview(attachmentId, filename) {
  const url = await ensureAttachmentImageUrl(attachmentId);
  openImagePreview(url, filename);
}

function openImagePreview(url, caption) {
  if (!ui.imagePreviewModal || !ui.imagePreviewImage || !ui.imagePreviewCaption) {
    return;
  }
  ui.imagePreviewImage.src = url;
  ui.imagePreviewCaption.textContent = caption || "Attachment Preview";
  ui.imagePreviewModal.hidden = false;
}

function closeImagePreview() {
  if (!ui.imagePreviewModal || !ui.imagePreviewImage) {
    return;
  }
  ui.imagePreviewModal.hidden = true;
  ui.imagePreviewImage.removeAttribute("src");
}

async function handleUploadAttachment() {
  if (!requireSession()) {
    return;
  }
  if (ui.composeE2E.checked) {
    showToast("Encrypted message mode is text-only right now, so attachment uploads are unavailable.", true);
    return;
  }
  await uploadPendingSelectedAttachment();
}

async function uploadPendingSelectedAttachment(options = {}) {
  if (!requireSession()) {
    return null;
  }
  const file = ui.attachmentFile.files?.[0];
  if (!file) {
    if (!options.silentMissing) {
      showToast("Choose a file first.", true);
    }
    return null;
  }
  const contentBase64 = await fileToBase64(file);
  const body = { filename: file.name, content_base64: contentBase64 };
  const uploaded = await runClientGuard("upload", async () => {
    const attachment = await signedPost("/v1/attachments/upload", body);
    state.composeAttachments.push(attachment);
    await refreshSavedAttachments({ silent: true });
    clearSelectedAttachmentPreview();
    renderSelectedAttachmentPreview();
    renderAttachments();
    ui.attachmentFile.value = "";
    if (!options.suppressToast) {
      showToast(`Added ${attachment.filename} to the message.`);
    }
    return attachment;
  });
  return uploaded;
}

async function handleSendMail() {
  if (!requireSession()) {
    return;
  }
  if (ui.composeE2E.checked && state.composeAttachments.length) {
    showToast("Encrypted sending is text-only for now. Remove attachments before sending.", true);
    return;
  }
  if (!ui.composeE2E.checked && ui.attachmentFile.files?.[0]) {
    const uploaded = await uploadPendingSelectedAttachment({ suppressToast: true });
    if (!uploaded) {
      return;
    }
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
  if (ui.attachmentFile.files?.[0]) {
    const uploaded = await uploadPendingSelectedAttachment({ suppressToast: true });
    if (!uploaded) {
      return;
    }
  }
  const body = {
    message_id: state.composeDraftMessageId,
    to: csv(ui.composeTo.value),
    cc: csv(ui.composeCc.value),
    subject: ui.composeSubject.value.trim(),
    body_text: ui.composeBody.value.trim(),
    attachment_ids: state.composeAttachments.map((attachment) => attachment.id),
    thread_id: state.composeThreadId,
    send_now: false,
  };
  await runClientGuard("save_draft", async () => {
    const result = await signedPost("/v1/mail/draft", body);
    state.composeDraftMessageId = result.message_id;
    await refreshAll();
    state.activeMailbox = "drafts";
    state.selectedMessageId = result.message_id;
    renderMailboxTabs();
    renderMailboxList();
    renderDetail();
    showToast("Draft saved.");
  });
}

async function handleComposeAssist(action, options = {}) {
  if (!requireSession()) {
    return;
  }
  const contextMessage = options.contextMessage || composeContextMessage();
  if (contextMessage) {
    prepareComposeReplyFromMessage(contextMessage);
  }
  const instruction = ui.composeAssistPrompt?.value.trim() || options.defaultInstruction || "";
  const currentSubject = ui.composeSubject.value.trim();
  const currentBody = ui.composeBody.value.trim();
  const beforeSnapshot = captureComposeSnapshot();
  if (action === "draft" && !instruction && !currentSubject && !currentBody) {
    setComposeAssistStatus("Add a short prompt so the assistant knows what kind of email to draft.", true);
    showToast("Add a short prompt for the draft helper first.", true);
    return;
  }
  if (action === "continue" && !currentBody) {
    setComposeAssistStatus("Start the body or use Draft With AI before asking the assistant to continue it.", true);
    showToast("Write something first or use Draft With AI.", true);
    return;
  }
  if (action === "polish" && !currentBody && !instruction) {
    setComposeAssistStatus("Add some draft text or a prompt before asking the assistant to polish it.", true);
    showToast("There is nothing to polish yet.", true);
    return;
  }
  setComposeAssistStatus("Working on your draft with the smart module...", false);
  const composeTo = csv(ui.composeTo.value);
  const composeCc = csv(ui.composeCc.value);
  const body = {
    action,
    instruction,
    to: composeTo,
    cc: composeCc,
    subject: currentSubject,
    body_text: currentBody,
    thread_id: state.composeThreadId,
    context_message_id: contextMessage?.message_id || state.composeContextMessageId,
    preferred_language: null,
  };
  const result = await runClientGuard(`compose_assist_${action}`, async () => {
    return signedPost("/v1/smart/compose", body);
  });
  if (!result) {
    setComposeAssistStatus("Draft generation did not finish. Please try again.", true);
    return;
  }
  const applied = applyComposeAssistResult(action, currentSubject, currentBody, result);
  ui.composeSubject.value = applied.subject;
  ui.composeBody.value = applied.body;
  state.composeUndoSnapshot = beforeSnapshot;
  if (contextMessage) {
    state.composeThreadId = contextMessage.thread_id || state.composeThreadId;
    state.composeContextMessageId = contextMessage.message_id;
  }
  const backend = humanizeSmartBackend(result.smart_backend);
  const model = result.smart_model ? ` (${result.smart_model})` : "";
  setComposeAssistStatus(
    `${backend}${model} ${result.language ? `(${result.language}) ` : ""}: ${result.detail || "Draft updated."}`.replace(/\s+:/, ":"),
    Boolean(result.used_fallback)
  );
  showToast(
    result.used_fallback
      ? "Draft updated with the guided helper because LLM writing was unavailable."
      : "Draft updated with AI support."
  );
  if (action === "polish") {
    setComposeAssistStatus(
      `${backend}${model} ${result.language ? `(${result.language}) ` : ""}: ${result.detail || "Draft updated."} Use Undo Last AI Change if you want the previous version back.`.replace(/\s+:/, ":"),
      Boolean(result.used_fallback)
    );
  }
  scrollComposeIntoView();
  ui.composeBody.focus();
}

function clearCompose() {
  ui.composeForm.reset();
  state.composeDraftMessageId = null;
  state.composeThreadId = null;
  state.composeContextMessageId = null;
  state.composeUndoSnapshot = null;
  state.composeAttachments = [];
  state.composeAssistStatus = null;
  clearSelectedAttachmentPreview();
  syncComposeMode();
  renderComposeAssistStatus();
  renderSelectedAttachmentPreview();
  renderAttachments();
  renderSavedAttachmentsLibrary();
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
    const result = await signedPost("/v1/groups/create", { name, members });
    await refreshAll();
    selectComposeGroup(result.name || name);
    showToast(`Saved the group ${result.name || name}.`);
  });
}

function findGroup(name) {
  return state.groups.find((group) => group.name === name) || null;
}

function selectedGroup() {
  const name = ui.composeGroupPicker?.value || "";
  return name ? findGroup(name) : null;
}

function selectComposeGroup(name) {
  if (!ui.composeGroupPicker) {
    return;
  }
  ui.composeGroupPicker.value = name || "";
  renderSavedGroups();
}

function renderSavedGroups() {
  const groups = Array.isArray(state.groups) ? state.groups : [];
  if (ui.composeGroupPicker) {
    const selectedName = ui.composeGroupPicker.value;
    ui.composeGroupPicker.innerHTML = `
      <option value="">No saved group selected</option>
      ${groups
        .map(
          (group) => `<option value="${escapeHtml(group.name)}">${escapeHtml(group.name)} (${group.members.length})</option>`
        )
        .join("")}
    `;
    if (selectedName && groups.some((group) => group.name === selectedName)) {
      ui.composeGroupPicker.value = selectedName;
    }
  }
  const group = selectedGroup();
  if (ui.composeGroupPreview) {
    ui.composeGroupPreview.textContent = group
      ? `${group.members.length} member${group.members.length === 1 ? "" : "s"}: ${group.members.join(", ")}`
      : groups.length
        ? "Choose a saved group to preview and insert its members."
        : "No saved groups yet. Save one below, then insert it directly into the main send form.";
  }
  if (ui.savedGroupsList) {
    ui.savedGroupsList.innerHTML = groups.length
      ? groups
          .map(
            (groupItem) => `
              <article class="mail-card">
                <strong>${escapeHtml(groupItem.name)}</strong>
                <div class="mail-snippet">${escapeHtml(groupItem.members.join(", "))}</div>
                <div class="mail-meta">Updated ${escapeHtml(formatTime(groupItem.created_at))}</div>
                <div class="detail-actions">
                  <button type="button" class="secondary-button" data-group-action="compose" data-group-name="${escapeHtml(groupItem.name)}">Use In Compose</button>
                  <button type="button" class="ghost-button" data-group-action="edit" data-group-name="${escapeHtml(groupItem.name)}">Edit Group</button>
                </div>
              </article>
            `
          )
          .join("")
      : '<div class="empty-state"><strong>No saved groups yet</strong><p>Create a group once, then reuse it from the compose form.</p></div>';
  }
}

function mergeRecipients(currentValue, nextMembers) {
  return Array.from(new Set([...csv(currentValue), ...nextMembers])).join(", ");
}

function applySelectedGroupToCompose(target) {
  const group = selectedGroup();
  if (!group) {
    showToast("Choose a saved group first.", true);
    return;
  }
  if (target === "cc") {
    ui.composeCc.value = mergeRecipients(ui.composeCc.value, group.members);
    showToast(`Added ${group.name} to Cc.`);
    return;
  }
  ui.composeTo.value = mergeRecipients(ui.composeTo.value, group.members);
  showToast(`Added ${group.name} to To.`);
}

function loadGroupIntoEditor(name) {
  const group = findGroup(name);
  if (!group) {
    showToast("That saved group is no longer available.", true);
    return;
  }
  ui.groupName.value = group.name;
  ui.groupMembers.value = group.members.join(", ");
  selectComposeGroup(group.name);
  ui.groupName.focus();
  showToast(`Loaded ${group.name} for editing.`);
}

function loadSelectedGroupIntoEditor() {
  const group = selectedGroup();
  if (!group) {
    showToast("Choose a saved group first.", true);
    return;
  }
  loadGroupIntoEditor(group.name);
}

function findSavedAttachment(attachmentId) {
  return state.savedAttachments.find((attachment) => attachment.id === attachmentId) || null;
}

function filteredSavedAttachments() {
  const attachments = Array.isArray(state.savedAttachments) ? state.savedAttachments : [];
  const query = String(ui.attachmentLibrarySearch?.value || "").trim().toLowerCase();
  if (!query) {
    return attachments;
  }
  return attachments.filter((attachment) => {
    const labels = Array.isArray(attachment?.analysis?.labels) ? attachment.analysis.labels.join(" ") : "";
    const haystack = `${attachment.filename} ${attachment.content_type} ${labels}`.toLowerCase();
    return haystack.includes(query);
  });
}

function renderSavedAttachmentsLibrary() {
  if (!ui.attachmentLibraryList || !ui.attachmentLibrarySummary) {
    return;
  }
  if (!state.session) {
    ui.attachmentLibrarySummary.textContent = "Sign in to manage your saved attachments.";
    ui.attachmentLibraryList.innerHTML = `
      <div class="empty-state">
        <strong>No saved attachments yet</strong>
        <p>Your uploaded files will appear here after you sign in.</p>
      </div>
    `;
    return;
  }
  const attachments = filteredSavedAttachments();
  const total = Array.isArray(state.savedAttachments) ? state.savedAttachments.length : 0;
  ui.attachmentLibrarySummary.textContent = total
    ? `${attachments.length} of ${total} saved attachment${total === 1 ? "" : "s"} shown.`
    : "Upload a file once, then reuse it from here without uploading again.";
  if (!attachments.length) {
    ui.attachmentLibraryList.innerHTML = total
      ? `
        <div class="empty-state">
          <strong>No saved attachments match this filter</strong>
          <p>Try another filename or clear the search box.</p>
        </div>
      `
      : `
        <div class="empty-state">
          <strong>No saved attachments yet</strong>
          <p>Use the upload button above and your files will stay available here.</p>
        </div>
      `;
    return;
  }
  ui.attachmentLibraryList.innerHTML = attachments
    .map((attachment) => renderSavedAttachmentCard(attachment))
    .join("");
  ui.attachmentLibraryList.querySelectorAll("[data-attachment-preview-button]").forEach((button) => {
    button.addEventListener("click", () => {
      const attachmentId = button.dataset.attachmentPreviewButton;
      const filename = button.dataset.filename || "attachment";
      void openAttachmentImagePreview(attachmentId, filename);
    });
  });
  void hydrateAttachmentThumbnails(ui.attachmentLibraryList);
}

function renderSavedAttachmentCard(attachment) {
  const analysis = attachment.analysis || {};
  const labels = Array.isArray(analysis.labels) ? analysis.labels : [];
  const reasons = Array.isArray(analysis.reasons) ? analysis.reasons : [];
  const transformModes = Array.isArray(analysis.transform_modes) ? analysis.transform_modes : [];
  const storageState = attachment.deletable
    ? "Stored only. Safe to delete."
    : `Used in ${attachment.linked_folders.length ? attachment.linked_folders.join(", ") : "mail history"}.`;
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
              <button type="button" class="ghost-button" data-attachment-action="transform" data-attachment-id="${escapeHtml(attachment.id)}" data-mode="${escapeHtml(mode)}">
                ${escapeHtml(label)}
              </button>
            `;
          })
          .join("")
      : "";
  const thumbnail =
    isImageAttachment(attachment) && analysis.preview_ready !== false
      ? `
        <button type="button" class="attachment-thumb-button" data-attachment-preview-button="${escapeHtml(attachment.id)}" data-filename="${escapeHtml(attachment.filename)}">
          <div class="attachment-thumb" data-attachment-thumbnail="${escapeHtml(attachment.id)}" data-filename="${escapeHtml(attachment.filename)}">
            Loading preview...
          </div>
        </button>
      `
      : "";
  return `
    <article class="attachment-card">
      <div class="attachment-head">
        <strong>${escapeHtml(attachment.filename)}</strong>
        <span class="attachment-status">${escapeHtml(attachment.deletable ? "Unused" : "In Mail")}</span>
      </div>
      ${thumbnail}
      <div class="text-list">${escapeHtml(analysis.summary || composeAttachmentSummary(attachment))}</div>
      <div class="text-list">
        ${escapeHtml(formatBytes(attachment.size_bytes))} | ${escapeHtml(attachment.content_type || "application/octet-stream")} | saved ${escapeHtml(formatTime(attachment.created_at))}
      </div>
      <div class="text-list">${escapeHtml(storageState)}</div>
      <div class="mail-tags">
        ${(labels.length ? labels : [isImageAttachment(attachment) ? "image" : "file"]).map((label) => `<span>${escapeHtml(label)}</span>`).join("")}
      </div>
      ${
        reasons.length
          ? `<div class="text-list">Review notes: ${escapeHtml(reasons.map((reason) => humanizeSecurityReason(reason)).join(", "))}</div>`
          : ""
      }
      <div class="detail-actions">
        <button type="button" class="secondary-button" data-attachment-action="attach" data-attachment-id="${escapeHtml(attachment.id)}">Add To Message</button>
        <button type="button" class="ghost-button" data-attachment-action="compress" data-attachment-id="${escapeHtml(attachment.id)}">Compress Copy</button>
        <button type="button" class="ghost-button" data-attachment-action="open" data-attachment-id="${escapeHtml(attachment.id)}" data-filename="${escapeHtml(attachment.filename)}" data-content-type="${escapeHtml(attachment.content_type || "application/octet-stream")}">Open File</button>
        ${transformButtons}
        <button type="button" class="ghost-button" data-attachment-action="delete" data-attachment-id="${escapeHtml(attachment.id)}" ${attachment.deletable ? "" : "disabled"}>Delete</button>
      </div>
    </article>
  `;
}

function addSavedAttachmentToCompose(attachmentId) {
  if (ui.composeE2E.checked) {
    showToast("Encrypted message mode is text-only right now, so saved attachments cannot be inserted.", true);
    return;
  }
  const attachment = findSavedAttachment(attachmentId);
  if (!attachment) {
    showToast("That saved attachment is no longer available.", true);
    return;
  }
  if (state.composeAttachments.some((item) => item.id === attachmentId)) {
    showToast("That attachment is already in the message.", true);
    return;
  }
  state.composeAttachments.push(attachment);
  renderAttachments();
  showToast(`Added ${attachment.filename} to the message.`);
}

async function deleteSavedAttachment(attachmentId) {
  if (!requireSession()) {
    return;
  }
  const attachment = findSavedAttachment(attachmentId);
  if (!attachment) {
    showToast("That saved attachment is no longer available.", true);
    return;
  }
  const deleted = await runClientGuard(`delete_attachment_${attachmentId}`, async () => {
    return signedPost(`/v1/attachments/${attachmentId}/delete`, {});
  });
  if (!deleted) {
    return;
  }
  state.savedAttachments = state.savedAttachments.filter((item) => item.id !== attachmentId);
  state.composeAttachments = state.composeAttachments.filter((item) => item.id !== attachmentId);
  renderSavedAttachmentsLibrary();
  renderAttachments();
  showToast(`${attachment.filename} was removed from saved storage.`);
}

async function compressAttachmentCopy(attachmentId, options = {}) {
  if (!requireSession()) {
    return null;
  }
  const sourceAttachment = findSavedAttachment(attachmentId) || state.composeAttachments.find((item) => item.id === attachmentId) || null;
  const created = await runClientGuard(`compress_attachment_${attachmentId}`, async () => {
    return signedPost(`/v1/attachments/${attachmentId}/compress`, {});
  });
  if (!created) {
    return null;
  }
  await refreshSavedAttachments({ silent: true });
  const composeIndex = state.composeAttachments.findIndex((item) => item.id === attachmentId);
  if (composeIndex >= 0) {
    state.composeAttachments.splice(composeIndex, 1, created);
    renderAttachments();
  } else if (options.addToCompose && !state.composeAttachments.some((item) => item.id === created.id)) {
    state.composeAttachments.push(created);
    renderAttachments();
  }
  const savedBytes = Number(created?.analysis?.compression?.saved_bytes || 0);
  const ratioPercent = created?.analysis?.compression?.ratio_percent;
  const draftReplacements = Number(created?.analysis?.draft_replacements || 0);
  const replacedLabel =
    composeIndex >= 0 && sourceAttachment
      ? `${sourceAttachment.filename} was replaced in this message with ${created.filename}. `
      : "";
  const draftLabel = draftReplacements > 0 ? `${draftReplacements} saved draft${draftReplacements === 1 ? "" : "s"} now use the compressed copy. ` : "";
  if (savedBytes > 0) {
    showToast(
      `${replacedLabel}${draftLabel}${created.filename} is ready. Saved ${formatBytes(savedBytes)}${ratioPercent ? ` (${ratioPercent}% of the original size)` : ""}.`
    );
  } else {
    showToast(`${replacedLabel}${draftLabel}${created.filename} was created as an archive copy for easier reuse.`);
  }
  return created;
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
      stageReplyInCompose(message, replyText, "Suggested reply");
      showToast("Reply draft moved to the compose form.");
      return;
    }
    if (action === "smart-reply") {
      prepareComposeReplyFromMessage(message);
      if (ui.composeAssistPrompt && !ui.composeAssistPrompt.value.trim()) {
        ui.composeAssistPrompt.value = "Write a helpful reply to this message.";
      }
      await handleComposeAssist("draft", {
        contextMessage: message,
        defaultInstruction: ui.composeAssistPrompt?.value.trim() || "Write a helpful reply to this message.",
      });
      scrollComposeIntoView();
      ui.composeBody.focus();
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
      scrollComposeIntoView();
      ui.composeBody.focus();
      return;
    }
    if (action === "preview-attachment") {
      const attachmentId = node.dataset.attachmentId;
      const filename = node.dataset.filename;
      await previewAttachment(attachmentId, filename);
      return;
    }
    if (action === "open-attachment") {
      const attachmentId = node.dataset.attachmentId;
      const filename = node.dataset.filename || "attachment";
      const contentType = node.dataset.contentType || "application/octet-stream";
      await openAttachmentFile(attachmentId, filename, contentType);
      return;
    }
    if (action === "compress-attachment") {
      const attachmentId = node.dataset.attachmentId;
      await compressAttachmentCopy(attachmentId, { addToCompose: false });
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
  state.composeDraftMessageId = message.folder === "draft" ? message.message_id : null;
  state.composeUndoSnapshot = null;
  ui.composeTo.value = message.to.join(", ");
  ui.composeCc.value = message.cc.join(", ");
  ui.composeSubject.value = message.subject;
  ui.composeBody.value = message.body_text;
  ui.composeE2E.checked = Boolean(message.e2e_encrypted);
  state.composeThreadId = message.thread_id || null;
  state.composeContextMessageId = null;
  state.composeAttachments = [...message.attachments];
  state.composeAssistStatus = {
    text: "Draft loaded into the composer. You can continue or polish it with the AI helper.",
    isError: false,
  };
  syncComposeMode();
  renderComposeAssistStatus();
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
    thread_id: state.composeThreadId,
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
      const compressButton = `
        <button type="button" class="ghost-button" data-compress-compose-attachment="${escapeHtml(attachment.id)}">
          Compress Copy
        </button>
      `;
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
      const thumbnail =
        isImageAttachment(attachment) && attachment.analysis?.preview_ready !== false
          ? `
            <button type="button" class="attachment-thumb-button" data-attachment-preview-button="${escapeHtml(attachment.id)}" data-filename="${escapeHtml(attachment.filename)}">
              <div class="attachment-thumb compact" data-attachment-thumbnail="${escapeHtml(attachment.id)}" data-filename="${escapeHtml(attachment.filename)}">
                Loading preview...
              </div>
            </button>
          `
          : "";
      return `
        <div class="attachment-chip-card">
          <div class="chip">
            <span>${escapeHtml(attachment.filename)}</span>
            <button type="button" data-remove-attachment="${escapeHtml(attachment.id)}" aria-label="Remove attachment">x</button>
          </div>
          ${thumbnail}
          <div class="text-list">${escapeHtml(composeAttachmentSummary(attachment))}</div>
          <div class="inline-actions">${compressButton}${transformButtons}</div>
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
  ui.attachmentList.querySelectorAll("[data-compress-compose-attachment]").forEach((button) => {
    button.addEventListener("click", () => {
      const attachmentId = button.dataset.compressComposeAttachment;
      void compressAttachmentCopy(attachmentId, { addToCompose: true });
    });
  });
  ui.attachmentList.querySelectorAll("[data-attachment-preview-button]").forEach((button) => {
    button.addEventListener("click", () => {
      const attachmentId = button.dataset.attachmentPreviewButton;
      const filename = button.dataset.filename || "attachment";
      void openAttachmentImagePreview(attachmentId, filename);
    });
  });
  void hydrateAttachmentThumbnails(ui.attachmentList);
}

function composeAttachmentSummary(attachment) {
  const analysis = attachment.analysis || {};
  const contentType = attachment.content_type || "application/octet-stream";
  const compression = analysis.compression || null;
  if (compression && Number(compression.saved_bytes || 0) > 0) {
    return `${formatBytes(compression.compressed_size_bytes)} | saved ${formatBytes(compression.saved_bytes)}`;
  }
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
  const openAction = `
    <button type="button" class="ghost-button" data-detail-action="open-attachment" data-attachment-id="${escapeHtml(attachment.id)}" data-filename="${escapeHtml(attachment.filename)}" data-content-type="${escapeHtml(attachment.content_type || "application/octet-stream")}">
      Open File
    </button>
  `;
  const compressAction = `
    <button type="button" class="ghost-button" data-detail-action="compress-attachment" data-attachment-id="${escapeHtml(attachment.id)}">
      Save Compressed Copy
    </button>
  `;
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
      <div class="detail-actions">${openAction}${compressAction}${previewAction}${transformActions}</div>
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
  const smartReview = describeMessageSmartReview(message);
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
      <div class="detail-block">
        <span>Smart Review</span>
        <div class="text-list">${escapeHtml(smartReview)}</div>
      </div>
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
          ${message.folder === "inbox" && !message.e2e_encrypted ? `<button type="button" class="secondary-button" data-detail-action="smart-reply">Reply With AI</button>` : ""}
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
    url: await blobToDataUrl(blob),
  };
  renderDetail();
}

async function openAttachmentFile(attachmentId, filename, contentType) {
  if (!requireSession()) {
    return;
  }
  const response = await fetch(`/v1/attachments/${attachmentId}`, {
    headers: {
      Authorization: `Bearer ${state.session.session_token}`,
    },
  });
  if (!response.ok) {
    throw await parseError(response);
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  if (isInlineOpenable(contentType)) {
    const popup = window.open(url, "_blank", "noopener");
    if (!popup) {
      const link = document.createElement("a");
      link.href = url;
      link.target = "_blank";
      link.rel = "noopener";
      link.click();
    }
    window.setTimeout(() => {
      URL.revokeObjectURL(url);
    }, 60000);
    return;
  }
  const link = document.createElement("a");
  link.href = url;
  link.download = filename || "attachment";
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => {
    URL.revokeObjectURL(url);
  }, 5000);
}

async function transformAttachmentToComposer(attachmentId, mode) {
  if (!requireSession()) {
    return;
  }
  if (ui.composeE2E.checked) {
    showToast("Encrypted message mode is text-only right now, so image transforms cannot be added.", true);
    return;
  }
  const transformed = await runClientGuard(`transform_${attachmentId}_${mode}`, async () => {
    return signedPost(`/v1/attachments/${attachmentId}/transform`, { mode });
  });
  if (!transformed) {
    return;
  }
  state.composeAttachments.push(transformed);
  await refreshSavedAttachments({ silent: true });
  renderAttachments();
  showToast(`${transformed.filename} was added to the message.`);
}

function revokePreview() {
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

function describeMessageSmartReview(message) {
  const flags = message.security_flags || {};
  const backend = String(flags.smart_backend || "heuristic").toLowerCase();
  const model = flags.smart_model ? ` (${flags.smart_model})` : "";
  if (backend === "ollama") {
    return `Reviewed by the local Ollama smart module${model}.`;
  }
  if (backend === "huggingface_local") {
    return `Reviewed by the local Hugging Face smart module${model}.`;
  }
  if (backend === "openai") {
    return `Reviewed by the configured LLM backend${model}.`;
  }
  if (backend === "heuristic_fallback") {
    const error = String(flags.smart_error || "").trim();
    return error
      ? `LLM review was unavailable, so heuristic fallback was used. Reason: ${error}`
      : "LLM review was unavailable, so heuristic fallback was used.";
  }
  return "Heuristic smart checks were used without an LLM review.";
}

function describeSecurityState(message) {
  const smartReview = describeMessageSmartReview(message);
  if (message.security_flags?.suspicious) {
    const reasons = Array.isArray(message.security_flags?.reasons)
      ? message.security_flags.reasons.map((reason) => humanizeSecurityReason(reason))
      : [];
    return {
      title: "This message may be risky",
      body: reasons.length
        ? `Warning signs detected: ${reasons.join(", ")}. ${smartReview}`
        : `The message looks unusual, so treat links and requests carefully. ${smartReview}`,
    };
  }
  if (message.e2e_encrypted) {
    return {
      title: "Private message protection is active",
      body: `This message was delivered as end-to-end encrypted content and decrypted locally in your browser when possible. ${smartReview}`,
    };
  }
  return {
    title: "No strong warning sign was detected",
    body: `Basic phishing and content checks did not flag this message. ${smartReview}`,
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

function formatBytes(value) {
  const size = Number(value || 0);
  if (!Number.isFinite(size) || size <= 0) {
    return "0 B";
  }
  if (size < 1024) {
    return `${size} B`;
  }
  if (size < 1024 * 1024) {
    return `${(size / 1024).toFixed(1)} KB`;
  }
  return `${(size / (1024 * 1024)).toFixed(1)} MB`;
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

async function fileToDataUrl(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(new Error("Failed to build attachment preview."));
    reader.readAsDataURL(file);
  });
}

async function blobToDataUrl(blob) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(new Error("Failed to build attachment preview."));
    reader.readAsDataURL(blob);
  });
}

function formatTime(value) {
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function isInlineOpenable(contentType) {
  const value = String(contentType || "").toLowerCase();
  return (
    value.startsWith("image/") ||
    value === "application/pdf" ||
    value.startsWith("text/")
  );
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

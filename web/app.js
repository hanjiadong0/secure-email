const STORAGE_KEY = `secure-email:web:${window.location.origin}`;

const state = {
  domain: "",
  session: null,
  activeMailbox: "inbox",
  mailboxes: {
    inbox: [],
    sent: [],
    drafts: [],
    search: [],
  },
  todos: [],
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
    ui.serviceStatus.textContent = data.status.toUpperCase();
  } catch (error) {
    ui.serviceStatus.textContent = "OFFLINE";
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
  ui.sessionSeq.textContent = state.session ? String(state.session.seq_no) : "0";
  ui.logoutButton.disabled = !state.session;
}

async function handleRegister() {
  const email = ui.registerEmail.value.trim();
  const password = ui.registerPassword.value;
  const confirmPassword = ui.registerConfirmPassword.value;
  if (!email || !password || !confirmPassword) {
    showToast("Registration needs email, password, and confirm password.", true);
    return;
  }
  if (password !== confirmPassword) {
    showToast("Password confirmation does not match.", true);
    return;
  }
  await runClientGuard("register", async () => {
    const result = await fetchJson("/v1/auth/register", {
      method: "POST",
      body: { email, password, confirm_password: confirmPassword },
    });
    ui.loginEmail.value = email;
    ui.registerForm.reset();
    showToast(`Registered ${result.email}. You can log in now.`);
  });
}

async function handleLogin() {
  const email = ui.loginEmail.value.trim();
  const password = ui.loginPassword.value;
  if (!email || !password) {
    showToast("Login needs both email and password.", true);
    return;
  }
  await runClientGuard("login", async () => {
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
    syncSessionCard();
    ui.loginForm.reset();
    state.activeMailbox = "inbox";
    await refreshAll();
    showToast(`Logged in as ${email}.`);
  });
}

function handleLogout() {
  state.session = null;
  state.mailboxes = { inbox: [], sent: [], drafts: [], search: [] };
  state.todos = [];
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
  showToast("Logged out.");
}

async function refreshAll() {
  if (!requireSession()) {
    return;
  }
  try {
    const [inbox, sent, drafts, todos] = await Promise.all([
      authGet("/v1/mail/inbox"),
      authGet("/v1/mail/sent"),
      authGet("/v1/mail/drafts"),
      authGet("/v1/todos"),
    ]);
    state.mailboxes.inbox = inbox;
    state.mailboxes.sent = sent;
    state.mailboxes.drafts = drafts;
    state.todos = todos;
    if (!lookupSelectedMessage() && inbox.length) {
      state.selectedMessageId = inbox[0].message_id;
    }
    renderMailboxTabs();
    renderMailboxList();
    renderDetail();
    syncSessionCard();
  } catch (error) {
    showToast(normalizeError(error), true);
  }
}

async function handleUploadAttachment() {
  if (!requireSession()) {
    return;
  }
  const file = ui.attachmentFile.files?.[0];
  if (!file) {
    showToast("Choose a PNG or JPEG file first.", true);
    return;
  }
  const contentBase64 = await fileToBase64(file);
  const body = { filename: file.name, content_base64: contentBase64 };
  await runClientGuard("upload", async () => {
    const attachment = await signedPost("/v1/attachments/upload", body);
    state.composeAttachments.push(attachment);
    renderAttachments();
    ui.attachmentFile.value = "";
    showToast(`Uploaded ${attachment.filename}.`);
  });
}

async function handleSendMail() {
  if (!requireSession()) {
    return;
  }
  const body = buildComposeBody();
  await runClientGuard("send_mail", async () => {
    const result = await signedPost("/v1/mail/send", body);
    clearCompose();
    await refreshAll();
    state.activeMailbox = "sent";
    state.selectedMessageId = result.message_id;
    renderMailboxTabs();
    renderMailboxList();
    renderDetail();
    showToast(`Mail queued with id ${result.message_id}.`);
  });
}

async function handleSaveDraft() {
  if (!requireSession()) {
    return;
  }
  const body = { ...buildComposeBody(), message_id: null, send_now: false };
  await runClientGuard("save_draft", async () => {
    const result = await signedPost("/v1/mail/draft", body);
    await refreshAll();
    state.activeMailbox = "drafts";
    state.selectedMessageId = result.message_id;
    renderMailboxTabs();
    renderMailboxList();
    renderDetail();
    showToast(`Draft saved with id ${result.message_id}.`);
  });
}

function clearCompose() {
  ui.composeForm.reset();
  state.composeAttachments = [];
  renderAttachments();
}

async function handleSearch() {
  if (!requireSession()) {
    return;
  }
  const query = ui.searchQuery.value.trim();
  if (!query) {
    showToast("Enter a search query first.", true);
    return;
  }
  try {
    const result = await authGet("/v1/mail/search", { q: query });
    state.mailboxes.search = result.messages;
    state.searchContacts = result.contacts;
    state.activeMailbox = "search";
    renderSearchContacts();
    renderMailboxTabs();
    renderMailboxList();
    showToast(`Search returned ${result.messages.length} messages.`);
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
    showToast("Group name is required.", true);
    return;
  }
  await runClientGuard("group_create", async () => {
    await signedPost("/v1/groups/create", { name, members });
    ui.groupCreateForm.reset();
    showToast(`Saved group ${name}.`);
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
    showToast("Group send needs name, subject, and body.", true);
    return;
  }
  await runClientGuard("group_send", async () => {
    await signedPost("/v1/mail/send_group", body);
    ui.groupSendForm.reset();
    await refreshAll();
    showToast(`Sent mail to group ${body.group_name}.`);
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
        showToast("Message marked as read.");
      });
      return;
    }
    if (action === "recall") {
      await runClientGuard("recall", async () => {
        const result = await signedPost("/v1/mail/recall", { message_id: message.message_id });
        await refreshAll();
        showToast(`Recall result: ${JSON.stringify(result.statuses)}`);
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
        showToast("Quick reply sent.");
      });
      return;
    }
    if (action === "execute-token") {
      const token = node.dataset.token;
      await runClientGuard("execute_action", async () => {
        await signedPost("/v1/actions/execute", { token });
        await refreshAll();
        showToast("Quick action executed.");
      });
      return;
    }
    if (action === "load-draft") {
      fillComposeFromMessage(message);
      showToast("Draft loaded into composer.");
      return;
    }
    if (action === "preview-attachment") {
      const attachmentId = node.dataset.attachmentId;
      const filename = node.dataset.filename;
      await previewAttachment(attachmentId, filename);
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
  state.composeAttachments = [...message.attachments];
  renderAttachments();
}

function buildComposeBody() {
  return {
    to: csv(ui.composeTo.value),
    cc: csv(ui.composeCc.value),
    subject: ui.composeSubject.value.trim(),
    body_text: ui.composeBody.value.trim(),
    attachment_ids: state.composeAttachments.map((attachment) => attachment.id),
    thread_id: null,
  };
}

function renderAttachments() {
  if (!state.composeAttachments.length) {
    ui.attachmentList.innerHTML = '<div class="text-list">No uploaded attachments attached to the current draft.</div>';
    return;
  }
  ui.attachmentList.innerHTML = state.composeAttachments
    .map(
      (attachment) => `
        <div class="chip">
          <span>${escapeHtml(attachment.filename)}</span>
          <code class="mono">${escapeHtml(attachment.id)}</code>
          <button type="button" data-remove-attachment="${escapeHtml(attachment.id)}" aria-label="Remove attachment">x</button>
        </div>
      `
    )
    .join("");
  ui.attachmentList.querySelectorAll("[data-remove-attachment]").forEach((button) => {
    button.addEventListener("click", () => {
      const attachmentId = button.dataset.removeAttachment;
      state.composeAttachments = state.composeAttachments.filter((item) => item.id !== attachmentId);
      renderAttachments();
    });
  });
}

function renderSearchContacts() {
  if (!state.searchContacts.length) {
    ui.searchContacts.innerHTML = "";
    return;
  }
  ui.searchContacts.innerHTML = `
    <strong>Contacts</strong>
    <ul>
      ${state.searchContacts
        .map((contact) => `<li>${escapeHtml(contact.email)} <span class="mono">score=${contact.score.toFixed(2)}</span></li>`)
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
        <strong>Sign in to load mail</strong>
        <p>The browser UI is live, but mailbox data stays locked until you log in.</p>
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
                <div class="mail-meta mono">${escapeHtml(todo.id)}</div>
                <div class="mail-snippet">Message: ${escapeHtml(todo.message_id)}</div>
              </article>
            `
          )
          .join("")
      : `
        <div class="empty-state">
          <strong>No todos yet</strong>
          <p>Quick actions can create TODO items from selected messages.</p>
        </div>
      `;
    return;
  }
  const messages = currentMailboxMessages();
  if (!messages.length) {
    ui.mailboxList.innerHTML = `
      <div class="empty-state">
        <strong>No messages in ${escapeHtml(state.activeMailbox)}</strong>
        <p>Try refreshing or sending a cross-domain message from another window.</p>
      </div>
    `;
    return;
  }
  ui.mailboxList.innerHTML = messages
    .map((message) => {
      const tags = [
        message.delivery_state,
        message.classification,
        message.recalled ? "recalled" : null,
        message.security_flags?.suspicious ? "suspicious" : null,
      ].filter(Boolean);
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
        <p>Pick a message from the mailbox list to inspect it here.</p>
      </div>
    `;
    return;
  }
  const suspicious = Boolean(message.security_flags?.suspicious);
  const previewMarkup =
    state.preview && state.preview.messageId === message.message_id
      ? `
        <div class="attachment-preview">
          <span>Preview</span>
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
        <div><span>Message ID</span><strong class="mono">${escapeHtml(message.message_id)}</strong></div>
        <div><span>Thread ID</span><strong class="mono">${escapeHtml(message.thread_id)}</strong></div>
        <div><span>Folder</span><strong>${escapeHtml(message.folder)}</strong></div>
        <div><span>Delivery</span><strong>${escapeHtml(message.delivery_state || "delivered")}</strong></div>
        <div><span>Created</span><strong>${escapeHtml(formatTime(message.created_at))}</strong></div>
      </div>
      <div class="security-box ${suspicious ? "" : "safe"}">
        <strong>${suspicious ? "Suspicious message flagged" : "No high-risk phishing flag triggered"}</strong>
        <div class="mail-snippet">
          Score: ${escapeHtml(String(message.security_flags?.phishing_score ?? 0))}
          ${message.security_flags?.reasons?.length ? ` | Reasons: ${escapeHtml(message.security_flags.reasons.join(", "))}` : ""}
        </div>
      </div>
      <div class="detail-body">${escapeHtml(message.body_text)}</div>
      <div class="detail-block">
        <span>Keywords</span>
        <div class="mail-tags">${message.keywords.map((keyword) => `<span>${escapeHtml(keyword)}</span>`).join("") || "<span>None</span>"}</div>
      </div>
      <div class="detail-block">
        <span>Attachments</span>
        <div class="detail-actions">
          ${
            message.attachments.length
              ? message.attachments
                  .map(
                    (attachment) => `
                      <button type="button" class="ghost-button" data-detail-action="preview-attachment" data-attachment-id="${escapeHtml(attachment.id)}" data-filename="${escapeHtml(attachment.filename)}">
                        Preview ${escapeHtml(attachment.filename)}
                      </button>
                    `
                  )
                  .join("")
              : '<div class="text-list">No attachments.</div>'
          }
        </div>
        ${previewMarkup}
      </div>
      <div class="detail-block">
        <span>Message Actions</span>
        <div class="detail-actions">
          ${message.folder === "inbox" && !message.is_read ? `<button type="button" data-detail-action="mark-read">Mark Read</button>` : ""}
          ${message.folder === "sent" && !message.recalled ? `<button type="button" class="secondary-button" data-detail-action="recall">Recall</button>` : ""}
          ${message.folder === "draft" ? `<button type="button" class="ghost-button" data-detail-action="load-draft">Load Draft Into Composer</button>` : ""}
          ${
            !message.folder || (message.folder !== "draft" && message.folder !== "sent" && message.folder !== "inbox")
              ? ""
              : ""
          }
        </div>
      </div>
      <div class="detail-block">
        <span>Quick Replies</span>
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
              : '<div class="text-list">No quick replies for this message.</div>'
          }
        </div>
      </div>
      <div class="detail-block">
        <span>Quick Actions</span>
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
              : '<div class="text-list">No quick actions available.</div>'
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
  showToast("Log in first to use authenticated mail features.", true);
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

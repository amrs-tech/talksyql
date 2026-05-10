const databases = [
  ["PostgreSQL", "PG", "CTEs, JSONB, windows"],
  ["MySQL", "MY", "InnoDB and common joins"],
  ["SQL Server", "MS", "T-SQL syntax"],
  ["SQLite", "SQ", "Portable local SQL"],
  ["Oracle", "OR", "Enterprise SQL"],
  ["BigQuery", "BQ", "Warehouse analytics"],
  ["Snowflake", "SF", "Cloud warehouse"],
  ["Redshift", "RS", "AWS analytics"],
  ["MariaDB", "MA", "MySQL-family SQL"],
  ["DuckDB", "DB", "Local analytics"]
];

const state = {
  selectedDb: "PostgreSQL",
  mediaRecorder: null,
  audioChunks: [],
  audioFile: null,
  user: null,
  admin: null,
  adminTab: "users",
  resetToken: 0
};

const el = {
  themeSelect: document.querySelector("#themeSelect"),
  providerStatus: document.querySelector("#providerStatus"),
  storageStatus: document.querySelector("#storageStatus"),
  loginButton: document.querySelector("#loginButton"),
  historyButton: document.querySelector("#historyButton"),
  adminButton: document.querySelector("#adminButton"),
  databaseGrid: document.querySelector("#databaseGrid"),
  selectedDbPill: document.querySelector("#selectedDbPill"),
  recordButton: document.querySelector("#recordButton"),
  recordingState: document.querySelector("#recordingState"),
  recordTitle: document.querySelector("#recordTitle"),
  recordMeta: document.querySelector("#recordMeta"),
  audioFile: document.querySelector("#audioFile"),
  transcribeButton: document.querySelector("#transcribeButton"),
  clearAudioButton: document.querySelector("#clearAudioButton"),
  transcriptInput: document.querySelector("#transcriptInput"),
  extraInput: document.querySelector("#extraInput"),
  generateButton: document.querySelector("#generateButton"),
  sqlOutput: document.querySelector("#sqlOutput"),
  copyButton: document.querySelector("#copyButton"),
  loginDialog: document.querySelector("#loginDialog"),
  loginEmail: document.querySelector("#loginEmail"),
  loginCode: document.querySelector("#loginCode"),
  requestCodeButton: document.querySelector("#requestCodeButton"),
  verifyCodeButton: document.querySelector("#verifyCodeButton"),
  loginNote: document.querySelector("#loginNote"),
  historyDialog: document.querySelector("#historyDialog"),
  historyList: document.querySelector("#historyList"),
  closeHistoryButton: document.querySelector("#closeHistoryButton"),
  adminDialog: document.querySelector("#adminDialog"),
  closeAdminButton: document.querySelector("#closeAdminButton"),
  adminLogin: document.querySelector("#adminLogin"),
  adminWorkspace: document.querySelector("#adminWorkspace"),
  adminEmail: document.querySelector("#adminEmail"),
  adminPassword: document.querySelector("#adminPassword"),
  adminLoginButton: document.querySelector("#adminLoginButton"),
  adminLogoutButton: document.querySelector("#adminLogoutButton"),
  llmModel: document.querySelector("#llmModel"),
  llmApiKey: document.querySelector("#llmApiKey"),
  sttModel: document.querySelector("#sttModel"),
  sttApiKey: document.querySelector("#sttApiKey"),
  smtpHost: document.querySelector("#smtpHost"),
  smtpPort: document.querySelector("#smtpPort"),
  smtpSecure: document.querySelector("#smtpSecure"),
  smtpFromEmail: document.querySelector("#smtpFromEmail"),
  smtpFromName: document.querySelector("#smtpFromName"),
  smtpUsername: document.querySelector("#smtpUsername"),
  smtpPassword: document.querySelector("#smtpPassword"),
  saveSettingsButton: document.querySelector("#saveSettingsButton"),
  adminList: document.querySelector("#adminList"),
  toast: document.querySelector("#toast")
};

init();

async function init() {
  setupTheme();
  renderDatabaseGrid();
  bindEvents();
  await refreshMe();
  await refreshProviderStatus();
  await refreshAdmin();
}

function bindEvents() {
  el.themeSelect.addEventListener("change", () => setTheme(el.themeSelect.value));
  el.loginButton.addEventListener("click", onLoginClick);
  el.historyButton.addEventListener("click", openHistory);
  el.adminButton.addEventListener("click", openAdmin);
  el.recordButton.addEventListener("click", toggleRecording);
  el.audioFile.addEventListener("change", () => {
    state.audioFile = el.audioFile.files?.[0] || null;
    updateAudioMeta();
  });
  el.transcribeButton.addEventListener("click", transcribeAudio);
  el.clearAudioButton.addEventListener("click", clearAudio);
  el.generateButton.addEventListener("click", generateSql);
  el.copyButton.addEventListener("click", copySql);
  el.requestCodeButton.addEventListener("click", requestLoginCode);
  el.verifyCodeButton.addEventListener("click", verifyLoginCode);
  el.closeHistoryButton.addEventListener("click", () => el.historyDialog.close());
  el.closeAdminButton.addEventListener("click", () => el.adminDialog.close());
  el.adminLoginButton.addEventListener("click", adminLogin);
  el.adminLogoutButton.addEventListener("click", adminLogout);
  el.saveSettingsButton.addEventListener("click", saveSettings);

  document.querySelectorAll("[data-admin-tab]").forEach((button) => {
    button.addEventListener("click", () => {
      state.adminTab = button.dataset.adminTab;
      document.querySelectorAll("[data-admin-tab]").forEach((tab) => tab.classList.toggle("active", tab === button));
      loadAdminList();
    });
  });
}

function setupTheme() {
  const saved = localStorage.getItem("talksyql-theme") || "system";
  el.themeSelect.value = saved;
  setTheme(saved);
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
    if (el.themeSelect.value === "system") setTheme("system", false);
  });
}

function setTheme(theme, persist = true) {
  const resolved = theme === "system"
    ? (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")
    : theme;
  document.documentElement.dataset.theme = resolved;
  if (persist) localStorage.setItem("talksyql-theme", theme);
}

function renderDatabaseGrid() {
  el.databaseGrid.innerHTML = "";
  for (const [name, icon, subtitle] of databases) {
    const button = document.createElement("button");
    button.className = "database-card";
    button.type = "button";
    button.role = "radio";
    button.ariaChecked = String(name === state.selectedDb);
    button.innerHTML = `
      <span class="db-icon">${escapeHtml(icon)}</span>
      <span><strong>${escapeHtml(name)}</strong><small>${escapeHtml(subtitle)}</small></span>
    `;
    button.addEventListener("click", () => {
      state.selectedDb = name;
      el.selectedDbPill.textContent = name;
      renderDatabaseGrid();
    });
    el.databaseGrid.appendChild(button);
  }
}

async function refreshMe() {
  const data = await api("/api/me");
  state.user = data.user;
  renderAuth();
}

async function refreshProviderStatus() {
  try {
    const data = await api("/api/provider-status");
    el.providerStatus.textContent = providerStatusText(data.settings);
  } catch {
    el.providerStatus.textContent = "Provider status unavailable.";
  }
}

function renderAuth() {
  if (state.user) {
    el.loginButton.textContent = "Logout";
    el.storageStatus.textContent = `Logged in as ${state.user.email}. Runs are saved.`;
  } else {
    el.loginButton.textContent = "Login";
    el.storageStatus.textContent = "Anonymous output is not stored.";
  }
}

async function onLoginClick() {
  if (state.user) {
    await api("/api/auth/logout", { method: "POST" });
    state.user = null;
    resetUserSessionUi();
    renderAuth();
    toast("Logged out.");
    return;
  }
  el.loginDialog.showModal();
}

async function requestLoginCode() {
  setBusy(el.requestCodeButton, true, "Sending...");
  try {
    const data = await api("/api/auth/request", {
      method: "POST",
      body: { email: el.loginEmail.value }
    });
    el.loginNote.textContent = `A 6-digit code was sent to ${data.email}.`;
    toast("Login code sent.");
  } catch (error) {
    toast(error.message);
  } finally {
    setBusy(el.requestCodeButton, false, "Send code");
  }
}

async function verifyLoginCode() {
  setBusy(el.verifyCodeButton, true, "Verifying...");
  try {
    const data = await api("/api/auth/verify", {
      method: "POST",
      body: { email: el.loginEmail.value, code: el.loginCode.value }
    });
    state.user = data.user;
    renderAuth();
    el.loginDialog.close();
    toast("Logged in.");
  } catch (error) {
    toast(error.message);
  } finally {
    setBusy(el.verifyCodeButton, false, "Verify and login");
  }
}

async function toggleRecording() {
  if (state.mediaRecorder?.state === "recording") {
    state.mediaRecorder.stop();
    return;
  }

  if (!navigator.mediaDevices?.getUserMedia || !window.MediaRecorder) {
    toast("This browser cannot record audio. Upload an audio file instead.");
    return;
  }

  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    state.audioChunks = [];
    state.mediaRecorder = new MediaRecorder(stream);
    const recorderResetToken = state.resetToken;
    state.mediaRecorder.addEventListener("dataavailable", (event) => {
      if (event.data.size) state.audioChunks.push(event.data);
    });
    state.mediaRecorder.addEventListener("stop", () => {
      stream.getTracks().forEach((track) => track.stop());
      if (recorderResetToken !== state.resetToken) return;
      state.audioFile = new File(state.audioChunks, `talksyql-${Date.now()}.webm`, { type: "audio/webm" });
      document.body.classList.remove("is-recording");
      el.recordingState.textContent = "Recorded";
      updateAudioMeta();
    });
    state.mediaRecorder.start();
    document.body.classList.add("is-recording");
    el.recordingState.textContent = "Recording";
    el.recordTitle.textContent = "Recording...";
    el.recordMeta.textContent = "Tap the neon record button again to stop.";
  } catch (error) {
    toast(error.message || "Microphone permission was not granted.");
  }
}

function updateAudioMeta() {
  if (!state.audioFile) {
    el.recordingState.textContent = "Idle";
    el.recordTitle.textContent = "Record audio";
    el.recordMeta.textContent = "Use your microphone or upload an audio file.";
    return;
  }
  el.recordingState.textContent = "Ready";
  el.recordTitle.textContent = state.audioFile.name || "Audio ready";
  el.recordMeta.textContent = `${formatBytes(state.audioFile.size)} selected for transcription.`;
}

function clearAudio() {
  state.audioFile = null;
  state.audioChunks = [];
  state.mediaRecorder = null;
  el.audioFile.value = "";
  updateAudioMeta();
}

function resetWorkspace() {
  state.resetToken += 1;
  if (state.mediaRecorder?.state === "recording") {
    state.mediaRecorder.stop();
  }
  document.body.classList.remove("is-recording");
  clearAudio();
  state.selectedDb = "PostgreSQL";
  el.selectedDbPill.textContent = state.selectedDb;
  el.transcriptInput.value = "";
  el.extraInput.value = "";
  el.sqlOutput.textContent = "Your SQL will appear here.";
  renderDatabaseGrid();
}

function resetUserSessionUi() {
  resetWorkspace();
  el.loginEmail.value = "";
  el.loginCode.value = "";
  el.loginNote.textContent = "A 6-digit code will be sent to your email.";
  el.historyList.innerHTML = "";
  if (el.loginDialog.open) el.loginDialog.close();
  if (el.historyDialog.open) el.historyDialog.close();
}

async function transcribeAudio() {
  if (!state.audioFile) {
    toast("Record or upload audio first.");
    return;
  }

  setBusy(el.transcribeButton, true, "Transcribing...");
  try {
    const audioBase64 = await fileToBase64(state.audioFile);
    const data = await api("/api/transcribe", {
      method: "POST",
      body: {
        audioBase64,
        mimeType: state.audioFile.type || "audio/webm",
        fileName: state.audioFile.name || "talksyql-audio.webm"
      }
    });
    el.transcriptInput.value = data.text;
    toast("Transcript ready.");
  } catch (error) {
    toast(error.message);
  } finally {
    setBusy(el.transcribeButton, false, "Transcribe");
  }
}

async function generateSql() {
  setBusy(el.generateButton, true, "Generating...");
  el.sqlOutput.textContent = "Generating SQL...";
  try {
    const data = await api("/api/generate-sql", {
      method: "POST",
      body: {
        transcript: el.transcriptInput.value,
        extraInstructions: el.extraInput.value,
        databaseStyle: state.selectedDb
      }
    });
    el.sqlOutput.textContent = data.sql;
    toast(data.stored ? "SQL generated and saved." : "SQL generated. Anonymous runs are not stored.");
  } catch (error) {
    el.sqlOutput.textContent = "Your SQL will appear here.";
    toast(error.message);
  } finally {
    setBusy(el.generateButton, false, "Generate SQL");
  }
}

async function copySql() {
  const text = el.sqlOutput.textContent.trim();
  if (!text || text === "Your SQL will appear here.") return;
  await navigator.clipboard.writeText(text);
  toast("SQL copied.");
}

async function openHistory() {
  if (!state.user) {
    toast("Login with email to save and view history.");
    el.loginDialog.showModal();
    return;
  }
  el.historyDialog.showModal();
  el.historyList.innerHTML = `<p class="modal-note">Loading history...</p>`;
  try {
    const data = await api("/api/history");
    renderHistory(data.items);
  } catch (error) {
    el.historyList.innerHTML = `<p class="modal-note">${escapeHtml(error.message)}</p>`;
  }
}

function renderHistory(items) {
  if (!items.length) {
    el.historyList.innerHTML = `<p class="modal-note">No saved SQL yet.</p>`;
    return;
  }
  el.historyList.innerHTML = "";
  for (const item of items) {
    const node = document.createElement("article");
    node.className = "list-item";
    node.innerHTML = `
      <div class="list-item-header">
        <strong>${escapeHtml(item.databaseStyle)} · ${escapeHtml(formatDate(item.createdAt))}</strong>
        <button class="danger-button" type="button">Delete</button>
      </div>
      <p>${escapeHtml(item.transcript).slice(0, 220)}</p>
      <pre>${escapeHtml(item.sql)}</pre>
    `;
    node.querySelector("button").addEventListener("click", async () => {
      await api(`/api/history?id=${encodeURIComponent(item.id)}`, { method: "DELETE" });
      await openHistory();
    });
    el.historyList.appendChild(node);
  }
}

async function refreshAdmin() {
  try {
    const data = await api("/api/admin/me");
    state.admin = data.admin;
  } catch {
    state.admin = null;
  }
}

async function openAdmin() {
  await refreshAdmin();
  renderAdminShell();
  el.adminDialog.showModal();
  if (state.admin) {
    await loadSettings();
    await loadAdminList();
  }
}

function renderAdminShell() {
  el.adminLogin.classList.toggle("hidden", Boolean(state.admin));
  el.adminWorkspace.classList.toggle("hidden", !state.admin);
}

async function adminLogin() {
  setBusy(el.adminLoginButton, true, "Logging in...");
  try {
    const data = await api("/api/admin/login", {
      method: "POST",
      body: { email: el.adminEmail.value, password: el.adminPassword.value }
    });
    state.admin = data.admin;
    renderAdminShell();
    await loadSettings();
    await loadAdminList();
    toast("Admin logged in.");
  } catch (error) {
    toast(error.message);
  } finally {
    setBusy(el.adminLoginButton, false, "Login as admin");
  }
}

async function adminLogout() {
  await api("/api/admin/logout", { method: "POST" });
  state.admin = null;
  renderAdminShell();
  toast("Admin logged out.");
}

async function loadSettings() {
  const data = await api("/api/admin/settings");
  el.llmModel.value = data.settings.llm.model || "gemini-3.1-flash-lite-preview";
  el.sttModel.value = data.settings.stt.model || "whisper-large-v3-turbo";
  el.smtpHost.value = data.settings.email.host || "";
  el.smtpPort.value = data.settings.email.port || 587;
  el.smtpSecure.value = String(Boolean(data.settings.email.secure));
  el.smtpFromEmail.value = data.settings.email.fromEmail || "";
  el.smtpFromName.value = data.settings.email.fromName || "talksyql";
  el.smtpUsername.value = data.settings.email.username || "";
  el.providerStatus.textContent = providerStatusText(data.settings);
}

async function saveSettings() {
  setBusy(el.saveSettingsButton, true, "Saving...");
  try {
    await api("/api/admin/settings", {
      method: "PUT",
      body: {
        llmModel: el.llmModel.value,
        llmApiKey: el.llmApiKey.value,
        sttModel: el.sttModel.value,
        sttApiKey: el.sttApiKey.value,
        smtpHost: el.smtpHost.value,
        smtpPort: el.smtpPort.value,
        smtpSecure: el.smtpSecure.value,
        smtpFromEmail: el.smtpFromEmail.value,
        smtpFromName: el.smtpFromName.value,
        smtpUsername: el.smtpUsername.value,
        smtpPassword: el.smtpPassword.value
      }
    });
    el.llmApiKey.value = "";
    el.sttApiKey.value = "";
    el.smtpPassword.value = "";
    await loadSettings();
    await refreshProviderStatus();
    toast("Provider and email settings saved.");
  } catch (error) {
    toast(error.message);
  } finally {
    setBusy(el.saveSettingsButton, false, "Save provider and email settings");
  }
}

async function loadAdminList() {
  if (!state.admin) return;
  el.adminList.innerHTML = `<p class="modal-note">Loading...</p>`;
  const endpoint = state.adminTab === "users" ? "/api/admin/users" : "/api/admin/histories";
  try {
    const data = await api(endpoint);
    if (state.adminTab === "users") renderAdminUsers(data.users);
    else renderAdminHistories(data.items);
  } catch (error) {
    el.adminList.innerHTML = `<p class="modal-note">${escapeHtml(error.message)}</p>`;
  }
}

function renderAdminUsers(users) {
  if (!users.length) {
    el.adminList.innerHTML = `<p class="modal-note">No users yet.</p>`;
    return;
  }
  el.adminList.innerHTML = "";
  for (const user of users) {
    const node = document.createElement("article");
    node.className = "list-item";
    node.innerHTML = `
      <div class="list-item-header">
        <strong>${escapeHtml(user.email)}</strong>
        <button class="danger-button" type="button">Delete user</button>
      </div>
      <p>${user.historyCount} saved runs · Joined ${escapeHtml(formatDate(user.createdAt))}</p>
    `;
    node.querySelector("button").addEventListener("click", async () => {
      if (!confirm(`Delete ${user.email} and all saved input-output records?`)) return;
      await api(`/api/admin/users?id=${encodeURIComponent(user.id)}`, { method: "DELETE" });
      await loadAdminList();
    });
    el.adminList.appendChild(node);
  }
}

function renderAdminHistories(items) {
  if (!items.length) {
    el.adminList.innerHTML = `<p class="modal-note">No saved input-output records yet.</p>`;
    return;
  }
  el.adminList.innerHTML = "";
  for (const item of items) {
    const node = document.createElement("article");
    node.className = "list-item";
    node.innerHTML = `
      <div class="list-item-header">
        <strong>${escapeHtml(item.userEmail)} · ${escapeHtml(item.databaseStyle)}</strong>
        <button class="danger-button" type="button">Delete record</button>
      </div>
      <p>${escapeHtml(formatDate(item.createdAt))}</p>
      <p>${escapeHtml(item.transcript).slice(0, 240)}</p>
      <pre>${escapeHtml(item.sql)}</pre>
    `;
    node.querySelector("button").addEventListener("click", async () => {
      await api(`/api/admin/histories?id=${encodeURIComponent(item.id)}`, { method: "DELETE" });
      await loadAdminList();
    });
    el.adminList.appendChild(node);
  }
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    method: options.method || "GET",
    headers: options.body ? { "Content-Type": "application/json" } : undefined,
    body: options.body ? JSON.stringify(options.body) : undefined
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || `Request failed with ${response.status}`);
  }
  return data;
}

function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result).split(",")[1] || "");
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

function setBusy(button, busy, label) {
  button.disabled = busy;
  button.textContent = label;
}

function toast(message) {
  const openDialog = document.querySelector("dialog[open]");
  const targetParent = openDialog || document.body;
  if (el.toast.parentElement !== targetParent) {
    targetParent.appendChild(el.toast);
  }
  el.toast.textContent = message;
  el.toast.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => el.toast.classList.remove("show"), 3600);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function formatBytes(bytes) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / 1024 ** index).toFixed(index ? 1 : 0)} ${units[index]}`;
}

function formatDate(value) {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(new Date(value));
}

function providerStatusText(settings) {
  return [
    `Gemini ${settings.llm.hasApiKey ? "configured" : "missing"}`,
    `Groq Whisper ${settings.stt.hasApiKey ? "configured" : "missing"}`,
    `Email ${settings.email.configured ? "configured" : "missing"}`
  ].join(" · ");
}

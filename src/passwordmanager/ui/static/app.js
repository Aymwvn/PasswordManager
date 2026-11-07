"use strict";
// Security note: vault data is only ever rendered via textContent / DOM APIs (see el()),
// never through HTML strings, so a malicious entry name or note cannot inject markup or script.
(() => {
  const $ = (id) => document.getElementById(id);
  const CLIP_CLEAR_MS = 15000;
  const PING_EVERY_MS = 20000;
  const POLL_EVERY_MS = 5000;

  let entries = [];
  let selectedName = null;
  let editingName = null;
  let vaultExists = true;
  let pollTimer = null;
  let searchTimer = null;
  let lastPing = 0;
  let totpTimer = null;
  let breachConsent = false; // ask once per session before the first network lookup
  let nativeClipboard = false; // set at boot from /api/capabilities
  let csrfToken = null; // lives in memory only; sent on every write as X-CSRF-Token

  // ---- helpers ---------------------------------------------------------------------------

  function el(tag, props = {}, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(props)) {
      if (key === "class") node.className = value;
      else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, value);
    }
    node.append(...children); // strings become text nodes
    return node;
  }

  async function api(method, path, body) {
    const headers = {};
    if (body) headers["Content-Type"] = "application/json";
    if (method !== "GET" && csrfToken) headers["X-CSRF-Token"] = csrfToken;
    const res = await fetch(`/api${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
      credentials: "same-origin",
    });
    let data = null;
    try { data = await res.json(); } catch { /* empty body */ }
    if (!res.ok) {
      if (res.status === 401 && path !== "/unlock" && path !== "/init") {
        lockUi("Session locked. Please unlock again.");
      }
      const detail = data && typeof data.detail === "string" ? data.detail : null;
      const err = new Error(detail || `Request failed (${res.status})`);
      err.status = res.status;
      throw err;
    }
    return data;
  }

  let toastTimer = null;
  function toast(message) {
    const t = $("toast");
    t.textContent = message;
    t.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove("show"), 2500);
  }

  function estimate(pw) {
    let pool = 0;
    if (/[a-z]/.test(pw)) pool += 26;
    if (/[A-Z]/.test(pw)) pool += 26;
    if (/[0-9]/.test(pw)) pool += 10;
    if (/[^A-Za-z0-9]/.test(pw)) pool += 33;
    const bits = pool ? pw.length * Math.log2(pool) : 0;
    const label = bits < 40 ? "weak" : bits < 60 ? "fair" : bits < 80 ? "good" : "strong";
    return { bits, label };
  }

  function fmtTime(seconds) {
    const m = Math.floor(seconds / 60);
    const s = String(seconds % 60).padStart(2, "0");
    return `${m}:${s}`;
  }

  function safeHttpUrl(value) {
    try {
      const u = new URL(value);
      return u.protocol === "http:" || u.protocol === "https:" ? u.href : null;
    } catch { return null; } // rejects javascript:, data:, etc.
  }

  async function copyText(text, what) {
    try {
      await navigator.clipboard.writeText(text);
    } catch { toast("Clipboard unavailable"); return; }
    if (what === "Password") {
      toast("Password copied (clears in 15s)");
      setTimeout(() => navigator.clipboard.writeText("").catch(() => {}), CLIP_CLEAR_MS);
    } else {
      toast(`${what} copied`);
    }
  }

  // Secrets: prefer the server-side native clipboard (kept out of Windows clipboard history,
  // cleared only if still ours, wiped on lock). Fall back to the browser clipboard.
  async function copySecret(entryName, field, what, fallbackValue) {
    if (nativeClipboard) {
      try {
        await api("POST", "/copy", { name: entryName, field });
        toast(`${what} copied (clears in 15s)`);
        return;
      } catch (err) {
        toast(`${err.message}; using the browser clipboard`);
      }
    }
    await copyText(fallbackValue, what);
  }

  // ---- auth screen -----------------------------------------------------------------------

  function showAuth(exists, message = "") {
    vaultExists = exists;
    $("screen-app").classList.add("hidden");
    $("screen-auth").classList.remove("hidden");
    $("auth-password").value = "";
    $("auth-confirm").value = "";
    $("auth-password").setAttribute("autocomplete", exists ? "current-password" : "new-password");
    $("auth-confirm-row").classList.toggle("hidden", exists);
    $("auth-confirm").required = !exists;
    $("auth-submit").textContent = exists ? "Unlock" : "Create vault";
    $("auth-hint").textContent = exists
      ? "Enter your master password to unlock the vault."
      : "No vault found. Create one with a strong master password (12+ characters). " +
        "There is no recovery if you forget it.";
    $("auth-error").textContent = message;
    $("auth-password").focus();
  }

  function lockUi(message) {
    clearInterval(pollTimer);
    stopTotp();
    breachConsent = false;
    csrfToken = null;
    entries = [];
    selectedName = null;
    renderList();
    renderDetail(null);
    if ($("entry-dialog").open) $("entry-dialog").close();
    showAuth(true, message);
  }

  $("auth-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const pw = $("auth-password").value;
    $("auth-error").textContent = "";
    if (!vaultExists && pw !== $("auth-confirm").value) {
      $("auth-error").textContent = "Passwords don't match.";
      return;
    }
    $("auth-submit").disabled = true;
    try {
      const session = await api("POST", vaultExists ? "/unlock" : "/init", { master_password: pw });
      csrfToken = session.csrf_token;
      await showApp();
    } catch (err) {
      $("auth-error").textContent = err.message;
    } finally {
      $("auth-submit").disabled = false;
      $("auth-password").value = "";
      $("auth-confirm").value = "";
    }
  });

  // ---- main screen -----------------------------------------------------------------------

  async function showApp() {
    vaultExists = true;
    $("screen-auth").classList.add("hidden");
    $("screen-app").classList.remove("hidden");
    $("search").value = "";
    selectedName = null;
    await loadEntries();
    renderDetail(null);
    clearInterval(pollTimer);
    pollTimer = setInterval(poll, POLL_EVERY_MS);
    poll();
  }

  async function poll() {
    try {
      const st = await api("GET", "/status");
      if (!st.unlocked) { lockUi("Locked due to inactivity."); return; }
      csrfToken = st.csrf_token;
      $("timer").textContent = `Auto-lock in ${fmtTime(st.seconds_left)}`;
    } catch {
      $("timer").textContent = "Server unreachable";
    }
  }

  async function loadEntries() {
    const q = $("search").value.trim();
    entries = await api("GET", `/entries?q=${encodeURIComponent(q)}`);
    renderList();
  }

  function renderList() {
    const ul = $("entry-list");
    ul.replaceChildren();
    if (!entries.length) {
      ul.append(el("li", { class: "empty muted" }, "No entries"));
      return;
    }
    for (const e of entries) {
      const cls = "item" + (e.name === selectedName ? " active" : "");
      ul.append(el("li", {},
        el("button", { type: "button", class: cls, onclick: () => selectEntry(e.name) },
          el("span", { class: "item-name" }, e.name),
          el("span", { class: "item-sub muted" }, e.username || "-"))));
    }
  }

  async function selectEntry(name) {
    selectedName = name;
    renderList();
    try {
      renderDetail(await api("GET", `/entries/${encodeURIComponent(name)}`));
    } catch (err) { toast(err.message); }
  }

  function stopTotp() {
    clearInterval(totpTimer);
    totpTimer = null;
  }

  function totpRow(entry) {
    const HIDDEN = "\u2022\u2022\u2022 \u2022\u2022\u2022";
    let revealed = false;
    let code = "";
    let left = 0;
    const value = el("span", { class: "value mono" }, HIDDEN);
    const timer = el("span", { class: "muted small" }, "");
    const paint = () => {
      const half = code.length / 2;
      value.textContent = revealed && code ? `${code.slice(0, half)} ${code.slice(half)}` : HIDDEN;
      timer.textContent = code ? `${left}s` : "";
    };
    const refresh = async () => {
      try {
        const r = await api("GET", `/totp/${encodeURIComponent(entry.name)}`);
        code = r.code;
        left = r.seconds_remaining;
      } catch (err) {
        code = "";
        left = 5; // back off instead of hammering the server on errors
        value.textContent = err.message;
        return;
      }
      paint();
    };
    const revealBtn = el("button", { type: "button" }, "Reveal");
    revealBtn.addEventListener("click", () => {
      revealed = !revealed;
      revealBtn.textContent = revealed ? "Hide" : "Reveal";
      paint();
    });
    stopTotp();
    refresh();
    totpTimer = setInterval(() => {
      left -= 1;
      if (left <= 0) refresh();
      else paint();
    }, 1000);
    return el("div", { class: "field" },
      el("span", { class: "label" }, "2FA code"), value, timer, revealBtn,
      el("button", { type: "button",
        onclick: () => code && copySecret(entry.name, "totp", "Code", code) }, "Copy"));
  }

  function breachRow(entry) {
    const result = el("span", { class: "value" }, "Not checked");
    const btn = el("button", { type: "button" }, "Check");
    btn.addEventListener("click", async () => {
      if (!breachConsent) {
        const ok = window.confirm(
          "This sends the first 5 characters of the password's SHA-1 hash to " +
          "api.pwnedpasswords.com (k-anonymity). The password itself never leaves your computer. " +
          "Continue?");
        if (!ok) return;
        breachConsent = true;
      }
      btn.disabled = true;
      result.className = "value";
      result.textContent = "Checking...";
      try {
        const r = await api("POST", `/breach/${encodeURIComponent(entry.name)}`);
        result.textContent = r.breached
          ? `Found in ${r.count.toLocaleString()} known breaches. Change it.`
          : "Not found in known breaches";
        result.className = r.breached ? "value danger-text" : "value ok-text";
      } catch (err) {
        result.textContent = err.message;
      } finally {
        btn.disabled = false;
      }
    });
    return el("div", { class: "field" }, el("span", { class: "label" }, "Breach check"), result, btn);
  }

  function renderDetail(entry) {
    const box = $("detail");
    stopTotp();
    box.replaceChildren();
    if (!entry) {
      box.append(el("p", { class: "muted" }, "Select an entry or create a new one."));
      return;
    }
    const MASK = "\u2022".repeat(12);
    const field = (label, value, extra = [], cls = "") =>
      el("div", { class: `field ${cls}` },
        el("span", { class: "label" }, label), el("span", { class: "value" }, value), ...extra);

    box.append(el("h2", {}, entry.name));
    if (entry.username) {
      box.append(field("Username", entry.username, [
        el("button", { type: "button", onclick: () => copyText(entry.username, "Username") }, "Copy"),
      ]));
    }
    if (entry.url) {
      const href = safeHttpUrl(entry.url);
      const value = href
        ? el("a", { href, target: "_blank", rel: "noopener noreferrer" }, entry.url)
        : entry.url;
      box.append(field("URL", value));
    }

    let revealed = false;
    const pwValue = el("span", { class: "value mono" }, MASK);
    const revealBtn = el("button", { type: "button" }, "Reveal");
    revealBtn.addEventListener("click", () => {
      revealed = !revealed;
      pwValue.textContent = revealed ? entry.password : MASK;
      revealBtn.textContent = revealed ? "Hide" : "Reveal";
    });
    box.append(el("div", { class: "field" },
      el("span", { class: "label" }, "Password"), pwValue, revealBtn,
      el("button", { type: "button",
        onclick: () => copySecret(entry.name, "password", "Password", entry.password) }, "Copy")));

    if (entry.totp) box.append(totpRow(entry));
    box.append(breachRow(entry));
    if (entry.notes) box.append(field("Notes", entry.notes, [], "notes"));
    box.append(field("Updated", new Date(entry.updated * 1000).toLocaleString()));
    box.append(el("div", { class: "actions" },
      el("button", { type: "button", onclick: () => openDialog(entry) }, "Edit"),
      el("button", { type: "button", class: "danger", onclick: () => removeEntry(entry.name) },
        "Delete")));
  }

  async function removeEntry(name) {
    if (!window.confirm(`Delete "${name}"? This cannot be undone.`)) return;
    try {
      await api("DELETE", `/entries/${encodeURIComponent(name)}`);
      selectedName = null;
      await loadEntries();
      renderDetail(null);
      toast("Deleted");
    } catch (err) { toast(err.message); }
  }

  // ---- entry dialog ----------------------------------------------------------------------

  function updateMeter() {
    const pw = $("f-password").value;
    const bar = $("meter-bar");
    if (!pw) { bar.className = "meter-bar"; $("meter-label").textContent = ""; return; }
    const { bits, label } = estimate(pw);
    bar.className = `meter-bar lvl-${label}`;
    $("meter-label").textContent = `${label} (~${Math.round(bits)} bits)`;
  }

  function openDialog(entry) {
    editingName = entry ? entry.name : null;
    $("entry-title").textContent = entry ? "Edit entry" : "New entry";
    $("f-name").value = entry ? entry.name : "";
    $("f-name").readOnly = Boolean(entry);
    $("f-username").value = entry ? entry.username : "";
    $("f-url").value = entry ? entry.url : "";
    $("f-password").value = entry ? entry.password : "";
    $("f-password").type = "password";
    $("btn-toggle-pw").textContent = "Show";
    $("f-notes").value = entry ? entry.notes : "";
    $("f-totp").value = entry ? entry.totp : "";
    $("entry-error").textContent = "";
    updateMeter();
    $("entry-dialog").showModal();
    (entry ? $("f-username") : $("f-name")).focus();
  }

  $("entry-dialog").addEventListener("close", () => {
    $("f-password").value = ""; // don't leave secrets sitting in hidden inputs
    $("f-totp").value = "";
  });
  $("btn-cancel").addEventListener("click", () => $("entry-dialog").close());
  $("btn-new").addEventListener("click", () => openDialog(null));
  $("f-password").addEventListener("input", updateMeter);

  $("btn-toggle-pw").addEventListener("click", () => {
    const hidden = $("f-password").type === "password";
    $("f-password").type = hidden ? "text" : "password";
    $("btn-toggle-pw").textContent = hidden ? "Hide" : "Show";
  });

  $("btn-generate").addEventListener("click", async () => {
    const length = Number($("gen-length").value) || 20;
    try {
      const r = await api("GET", `/generate?length=${length}&symbols=${$("gen-symbols").checked}`);
      $("f-password").value = r.password;
      $("f-password").type = "text";
      $("btn-toggle-pw").textContent = "Hide";
      updateMeter();
    } catch (err) { $("entry-error").textContent = err.message; }
  });

  $("entry-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const fields = {
      username: $("f-username").value,
      url: $("f-url").value,
      password: $("f-password").value,
      notes: $("f-notes").value,
      totp: $("f-totp").value,
    };
    try {
      let name = editingName;
      if (editingName === null) {
        name = $("f-name").value.trim();
        await api("POST", "/entries", { name, ...fields });
      } else {
        await api("PUT", `/entries/${encodeURIComponent(editingName)}`, fields);
      }
      $("entry-dialog").close();
      selectedName = name;
      await loadEntries();
      await selectEntry(name);
      toast("Saved");
    } catch (err) {
      $("entry-error").textContent = err.message;
    }
  });

  // ---- top bar + activity ----------------------------------------------------------------

  $("search").addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => loadEntries().catch((e) => toast(e.message)), 150);
  });

  $("btn-lock").addEventListener("click", async () => {
    try { await api("POST", "/lock"); } catch { /* already locked */ }
    lockUi("");
  });

  // Real user activity (not polling) keeps the server-side session alive.
  const onActivity = () => {
    const now = Date.now();
    if (now - lastPing < PING_EVERY_MS || $("screen-app").classList.contains("hidden")) return;
    lastPing = now;
    api("POST", "/ping").catch(() => {});
  };
  for (const ev of ["mousemove", "keydown", "click", "scroll"]) {
    document.addEventListener(ev, onActivity, { passive: true });
  }

  // ---- boot ------------------------------------------------------------------------------

  (async () => {
    try {
      try {
        nativeClipboard = (await api("GET", "/capabilities")).native_clipboard === true;
      } catch { nativeClipboard = false; }
      const st = await api("GET", "/status");
      if (st.unlocked) { csrfToken = st.csrf_token; await showApp(); }
      else showAuth(st.vault_exists);
    } catch (err) {
      document.body.textContent = `Cannot reach the local server: ${err.message}`;
    }
  })();
})();

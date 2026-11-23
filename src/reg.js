import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { t, has, stripErr } from "./i18n.js";
import { ic } from "./icons.js";
import { esc, toast } from "./ui.js";

const STEPS = {
  register: [
    "open-signup", "signup-form", "await-email", "open-link",
    "complete-signup", "back-to-authorize", "confirm-authorize", "done",
  ],
  login: ["confirm-authorize", "done"],
  observe: [],
};

const PAGE_KEYS = {
  "zai-signup": "signup",
  "zai-auth": "zaiAuth",
  "zai-authorize": "zaiAuthorize",
  "zai-other": "zaiOther",
  "bigmodel-login": "bigmodel",
  "zcode-bridge": "bridge",
  other: "other",
};

const MAX_LOGS = 200;

const LINK_POLL_MS = 3000;
const LINK_POLL_TRIES = 30;
const LINK_MAX_AUTO = 3;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const sessions = new Map();
const flowIndex = new Map();
let activeKey = "";
let drawer = null;
let modal = null;
let modalKind = null;
let modalSessionKey = "";

let onSkip = null;
export function setRegSkip(fn) {
  onSkip = fn;
}

function normKey(email) {
  return String(email || "").trim().toLowerCase();
}

function createSession(key, mode, provider, batchEmail = "") {
  return {
    key,
    mode,
    provider,
    flow: "",
    phase: "",
    note: "",
    logs: [],
    closed: false,
    failed: false,
    startedAt: Date.now(),
    signupEmail: batchEmail || "",
    batchEmail: batchEmail || "",
    linkAuto: 0,
    submittedAt: 0,
    linkBusy: false,
  };
}

function currentSession() {
  if (activeKey && sessions.has(activeKey)) return sessions.get(activeKey);
  const first = sessions.values().next().value || null;
  if (first) activeKey = first.key;
  return first;
}

function resolveSession(ev) {
  if (ev && ev.flow && flowIndex.has(ev.flow)) {
    const k = flowIndex.get(ev.flow);
    if (sessions.has(k)) return sessions.get(k);
  }
  if (ev && ev.email) {
    const k = normKey(ev.email);
    if (sessions.has(k)) {
      const s = sessions.get(k);
      if (ev.flow && !s.flow) {
        s.flow = ev.flow;
        flowIndex.set(ev.flow, k);
      }
      return s;
    }
  }
  const cur = currentSession();
  if (cur && ev && ev.flow && !cur.flow) {
    cur.flow = ev.flow;
    flowIndex.set(ev.flow, cur.key);
  }
  return cur;
}

function tr(group, key, params) {
  const k = `${group}.${key}`;
  return has(k) ? t(k, params) : `${key}`;
}

function nowLabel() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function stepsFor(mode) {
  return STEPS[mode] || STEPS.login;
}

export function regActive() {
  return sessions.size > 0;
}

export function regStart(mode, provider) {
  sessions.clear();
  flowIndex.clear();
  const s = createSession("__manual__", mode, provider, "");
  sessions.set(s.key, s);
  activeKey = s.key;
  pushLog(s, "info", "connected", provider);
  render();
}

export function regBatchSet(email) {
  const cur = currentSession();
  if (cur) {
    cur.batchEmail = email || "";
    if (email && !cur.signupEmail) cur.signupEmail = email;
  }
}

export function regStartBatch(email, provider) {
  const k = normKey(email) || "__manual__";
  if (sessions.has("__manual__") && k !== "__manual__") {
    sessions.delete("__manual__");
  }
  const s = createSession(k, "register", provider, email || "");
  sessions.set(k, s);
  if (!activeKey || !sessions.has(activeKey)) {
    activeKey = k;
  }
  pushLog(s, "info", "connected", provider);
  render();
  return s;
}

export function regBindFlow(email, flow) {
  if (!flow) return;
  const k = normKey(email);
  const s = (k && sessions.get(k)) || currentSession();
  if (s) {
    s.flow = flow;
    flowIndex.set(flow, s.key);
  }
}

export function regRemoveBatch(email) {
  const k = normKey(email);
  if (!k) return;
  const s = sessions.get(k);
  if (s && s.flow) flowIndex.delete(s.flow);
  sessions.delete(k);
  if (modalSessionKey === k) closeModal();
  if (activeKey === k) {
    const next = sessions.keys().next().value || "";
    activeKey = next;
  }
  if (sessions.size === 0) {
    regClose();
  } else {
    render();
  }
}

export function regClose() {
  closeModal();
  sessions.clear();
  flowIndex.clear();
  activeKey = "";
  document.body.classList.remove("reg-open");
  if (drawer) {
    drawer.remove();
    drawer = null;
  }
}

export function regEvent(ev) {
  if (!ev || typeof ev !== "object") return;
  const s = resolveSession(ev);
  if (!s) return;
  switch (ev.kind) {
    case "ready":
      pushLog(s, "info", "connected", ev.provider || s.provider);
      break;
    case "page":
      pushLog(s, "info", "page", tr("reg.page", PAGE_KEYS[ev.page] || "other"));
      break;
    case "phase":
      s.phase = ev.phase;
      if (ev.phase === "unsupported") s.failed = true;
      break;
    case "note":
      s.note = !ev.code || ev.code === "clear" ? "" : tr("reg.note", ev.code, { a: ev.a });
      break;
    case "ask":
      if (s.batchEmail) {
        if (ev.ask === "signup") autoSignup(s);
        else autoFetchLink(s);
      } else if (ev.ask === "link") {
        autoFetchLink(s);
      } else {
        openAsk(ev.ask, s);
      }
      break;
    case "log":
      if (ev.code === "submitted") s.submittedAt = Date.now();
      pushLog(s, ev.level || "info", ev.code, ev.a, ev.b);
      break;
    case "closed":
      s.closed = true;
      s.note = "";
      pushLog(s, "warn", "windowClosed");
      break;
    default:
      return;
  }
  render();
}

function pushLog(s, level, code, a, b) {
  if (!s) return;
  const text = tr("reg.log", code, { a: a || "", b: b || "" });
  s.logs.push({ level, text, at: nowLabel() });
  if (s.logs.length > MAX_LOGS) s.logs.splice(0, s.logs.length - MAX_LOGS);
}

async function autoSignup(s) {
  const email = s && s.batchEmail;
  if (!email) return;
  try {
    const r = await invoke("pool_get", { email });
    s.signupEmail = r.email;
    await invoke("reg_input", {
      ask: "signup",
      value: { name: randName(), email: r.email, password: r.password },
      flow: s.flow || null,
      email: s.batchEmail || null,
    });
    pushLog(s, "info", "batchSignup", r.email);
  } catch (e) {
    pushLog(s, "warn", "batchSignupFail", stripErr(e));
  }
  render();
}

function pickLink(links) {
  const verify = links.find((u) => /verify|token=|confirm|activ|signup/i.test(u));
  return verify || links[0] || "";
}

function isCredentialError(msg) {
  return /invalid_grant|AADSTS70000|AADSTS70008|AADSTS50173|AADSTS7000215/i.test(String(msg || ""));
}

async function autoFetchLink(s) {
  if (!s || s.linkBusy) return;
  const email = s.signupEmail || s.batchEmail;
  if (!email) return startManualLink(s, "noEmail");
  if (s.linkAuto >= LINK_MAX_AUTO) return startManualLink(s, "loop");

  s.linkBusy = true;
  pushLog(s, "info", "fetchLinkStart", email);
  render();

  const anchor = s.submittedAt || s.startedAt || Date.now();
  const sinceMs = anchor - 60_000;

  let link = "";
  let fail = "";
  let info = "";
  for (let i = 0; i < LINK_POLL_TRIES && !s.closed && sessions.has(s.key); i++) {
    try {
      const r = await invoke("reg_fetch_link", { email, limit: 15, since: sinceMs });
      const links = (r && r.links) || [];
      if (links.length) {
        link = pickLink(links);
        break;
      }
      const n = Number(r && r.scanned) || 0;
      const subj = String((r && r.newestSubject) || "").trim();
      info = subj ? t("reg.linkNewest", { n, s: subj }) : t("reg.linkEmptyBox", { n });
      fail = "";
    } catch (e) {
      fail = stripErr(e);
      pushLog(s, "warn", "fetchLinkErr", fail);
      if (isCredentialError(fail)) {
        s.linkBusy = false;
        toast(t("reg.linkDead"), "err", fail);
        if (onSkip) onSkip(s.batchEmail || email);
        return;
      }
      break;
    }
    pushLog(s, "info", "fetchLinkPolling", String(Math.round(((i + 1) * LINK_POLL_MS) / 1000)), String(i + 1));
    render();
    await sleep(LINK_POLL_MS);
  }
  s.linkBusy = false;
  if (!sessions.has(s.key) || s.closed) return;

  if (!link) return startManualLink(s, fail || info || "timeout");

  s.linkAuto += 1;
  try {
    await invoke("reg_input", {
      ask: "link",
      value: link,
      flow: s.flow || null,
      email: s.batchEmail || null,
    });
    pushLog(s, "ok", "fetchLinkFound", link);
  } catch (e) {
    pushLog(s, "warn", "fetchLinkPushFail", stripErr(e));
    startManualLink(s, "pushFail");
  }
  render();
}

function startManualLink(s, reason) {
  if (!s || !sessions.has(s.key)) return;
  if (modalKind === "link" && modalSessionKey === s.key) return;
  if (reason) pushLog(s, "warn", "fetchLinkManual", reason);
  render();
  openAsk("link", s);
}

function modeLabel(mode) {
  return tr("reg.mode", mode);
}

function ensureDrawer() {
  if (!drawer) {
    drawer = document.createElement("aside");
    drawer.className = "drw";
    document.body.appendChild(drawer);
  }
  return drawer;
}

function statusOf(s) {
  if (s.closed) return { key: "closed", cls: "off" };
  if (s.failed) return { key: "attention", cls: "warn" };
  if (s.phase === "done") return { key: "done", cls: "ok" };
  return { key: "live", cls: "run" };
}

function stepState(s, step) {
  const list = stepsFor(s.mode);
  const cur = list.indexOf(s.phase);
  const idx = list.indexOf(step);
  if (cur < 0) return "";
  if (idx < cur) return "done";
  if (idx === cur) return "cur";
  return "";
}

function shortEmail(em) {
  const s = String(em || "").trim();
  if (!s) return "";
  const at = s.indexOf("@");
  return at > 0 ? s.slice(0, at) : s;
}

function render() {
  const S = currentSession();
  if (!S) return;
  const root = ensureDrawer();
  document.body.classList.add("reg-open");
  const list = stepsFor(S.mode);
  const status = statusOf(S);

  const tabsHtml = sessions.size > 1
    ? `<div class="drw-tabs">${[...sessions.values()].map((item, idx) => {
        const st = statusOf(item);
        const label = shortEmail(item.batchEmail || item.signupEmail) || `#${idx + 1}`;
        return `<button class="drw-tab ${item.key === S.key ? "on" : ""}" data-tab="${esc(item.key)}" title="${esc(item.batchEmail || item.signupEmail || "")}">
          <span class="dot ${st.cls}"></span>
          <span class="tx">${esc(label)}</span>
        </button>`;
      }).join("")}</div>`
    : "";

  const stepsHtml = list.length
    ? `<div class="drw-steps">${list.map((s) => `
        <span class="drw-step ${stepState(S, s)}"><i></i>${esc(tr("reg.step", s))}</span>`).join("")}</div>`
    : "";

  const logsHtml = S.logs.map((l) => `
    <div class="drw-line ${esc(l.level)}">
      <span class="at">${esc(l.at)}</span>
      <span class="tx">${esc(l.text)}</span>
    </div>`).join("");

  root.innerHTML = `
    <div class="drw-h">
      <span class="dot ${status.cls}"></span>
      <span class="drw-title">${esc(t("reg.title"))} · ${esc(modeLabel(S.mode))}</span>
      <span class="chip new">${esc(S.provider || "")}</span>
      <span class="spacer"></span>
      <span class="drw-status ${status.cls}">${esc(tr("reg.status", status.key))}</span>
      <button class="iconbtn" data-act="close" title="${esc(t("reg.btn.close"))}" style="color:var(--ink-2)">${ic("x", 14)}</button>
    </div>
    ${tabsHtml}
    <div class="bar" style="border-bottom:1px solid var(--line);padding:9px 14px;gap:6px">
      ${S.mode === "register" ? "" : `<button class="btn sm" data-act="to-register">${ic("userPlus", 12)} ${esc(t("reg.btn.toRegister"))}</button>`}
      <button class="btn sm" data-act="reveal">${ic("play", 12)} ${esc(t("reg.btn.reveal"))}</button>
      <button class="btn sm" data-act="retry">${ic("refresh", 12)} ${esc(t("reg.btn.retry"))}</button>
      ${S.batchEmail ? `<button class="btn sm" data-act="skip">${ic("x", 12)} ${esc(t("reg.btn.skip"))}</button>` : ""}
    </div>
    ${S.note ? `<div class="drw-note">${ic("alert", 14)}<span>${esc(S.note)}</span></div>` : ""}
    ${stepsHtml}
    <div class="drw-log" id="reg-log">${logsHtml || `<div class="drw-line"><span class="tx" style="color:var(--ink-3)">${esc(t("reg.waiting"))}</span></div>`}</div>
    ${S.closed ? `<div style="padding:14px"><button class="btn g" data-act="close">${esc(t("reg.btn.close"))}</button></div>` : ""}
  `;

  const log = root.querySelector("#reg-log");
  if (log) log.scrollTop = log.scrollHeight;

  root.querySelectorAll("[data-tab]").forEach((b) => {
    b.addEventListener("click", () => {
      activeKey = b.dataset.tab || "";
      render();
    });
  });

  root.querySelectorAll("[data-act]").forEach((b) => {
    b.addEventListener("click", () => onAction(b.dataset.act));
  });
}

async function onAction(act) {
  const S = currentSession();
  if (act === "close") {
    if (S && S.batchEmail && sessions.size > 1) {
      regRemoveBatch(S.batchEmail);
      return;
    }
    return regClose();
  }
  if (!S) return;
  const target = { flow: S.flow || null, email: S.batchEmail || null };
  try {
    if (act === "reveal") await invoke("reg_action", { action: "reveal", ...target });
    else if (act === "retry") {
      S.failed = false;
      await invoke("reg_action", { action: "retry", ...target });
    } else if (act === "skip") {
      if (onSkip) onSkip(S.batchEmail);
      return;
    } else if (act === "to-register") {
      const m = await invoke("reg_set_mode", { mode: "register", ...target });
      S.mode = m;
      S.note = "";
      S.logs.push({ level: "info", text: tr("reg.log", "modeSwitch", { a: modeLabel(m) }), at: nowLabel() });
    }
  } catch (e) {
    toast(String(e).replace(/^[a-z_]+:/, ""), "err");
  }
  render();
}

function closeModal() {
  if (modal) {
    modal.remove();
    modal = null;
  }
  modalKind = null;
  modalSessionKey = "";
}

function field(id, label, type, placeholder, extra = "") {
  return `
    <label class="fld">
      <span>${esc(label)}</span>
      <input id="${id}" class="inp" type="${type}" placeholder="${esc(placeholder)}"
        autocomplete="off" spellcheck="false" ${extra}>
    </label>`;
}

function randName() {
  const A = "abcdefghijklmnopqrstuvwxyz";
  let s = "";
  for (let i = 0; i < 6; i++) s += A[Math.floor(Math.random() * A.length)];
  return s;
}

async function importAccounts(mask) {
  const err = mask.querySelector(".errline");
  const btn = mask.querySelector(".reg-import-btn");
  const sel = mask.querySelector(".reg-acct");
  btn.disabled = true;
  try {
    const r = await invoke("pool_list");
    const list = ((r && r.accounts) || []).filter((a) => a.status !== "verified");
    if (!list.length) {
      err.textContent = t("mb.nothingToVerify");
      return;
    }
    err.textContent = "";
    sel.innerHTML = list
      .map((a) => `<option value="${esc(a.email)}">${esc(a.email)}</option>`)
      .join("");
    sel.hidden = false;
    sel.onchange = () => fillFromPool(mask, sel.value);
    fillFromPool(mask, list[0].email);
  } catch (e) {
    err.textContent = stripErr(e);
  } finally {
    btn.disabled = false;
  }
}

async function fillFromPool(mask, email) {
  try {
    const r = await invoke("pool_get", { email });
    const em = mask.querySelector("#reg-email");
    const pw = mask.querySelector("#reg-pw");
    if (em) em.value = r.email || "";
    if (pw) pw.value = r.password || "";
  } catch (e) {
    const err = mask.querySelector(".errline");
    if (err) err.textContent = stripErr(e);
  }
}

function openAsk(kind, session) {
  const S = session || currentSession();
  if (!S) return;
  closeModal();
  modalKind = kind;
  modalSessionKey = S.key;
  const isSignup = kind === "signup";
  const who = S.batchEmail || S.signupEmail;
  const mask = document.createElement("div");
  mask.className = "ov reg bottom";
  mask.innerHTML = `
    <div class="sheet" role="dialog" aria-modal="true">
      <div class="grabber"></div>
      <div class="mhead">${ic(isSignup ? "userPlus" : "mail", 16)} <span>${esc(tr("reg.ask", `${kind}.label`))}${who ? ` · ${esc(who)}` : ""}</span></div>
      <div class="mbody">
        <div class="mnote" style="margin-bottom:14px">${esc(tr("reg.ask", `${kind}.hint`))}</div>
        ${isSignup
          ? `<div class="importrow">
               <button type="button" class="btn sm reg-import-btn">${ic("import", 13)} ${esc(t("reg.ask.signup.import"))}</button>
               <select class="inp reg-acct" hidden></select>
             </div>`
            + field("reg-name", t("reg.ask.signup.name"), "text", t("reg.ask.signup.namePh"))
            + field("reg-email", t("reg.ask.signup.email"), "email", t("reg.ask.signup.emailPh"))
            + field("reg-pw", t("reg.ask.signup.password"), "password", t("reg.ask.signup.passwordPh"))
          : `<label class="fld">
               <span>${esc(t("reg.ask.link.ph"))}</span>
               <textarea id="reg-link" class="inp" rows="3"
                 placeholder="${esc(t("reg.ask.link.ph"))}" spellcheck="false"></textarea>
             </label>`}
        <div class="errline"></div>
      </div>
      <div class="mfoot">
        <button class="btn g reg-cancel">${esc(t("common.cancel"))}</button>
        <button class="btn p reg-go">${ic("check", 14)} ${esc(t("reg.ask.submit"))}</button>
      </div>
    </div>`;
  document.body.appendChild(mask);
  modal = mask;

  if (isSignup) {
    const nameEl = mask.querySelector("#reg-name");
    if (nameEl && !nameEl.value) nameEl.value = randName();
    const importBtn = mask.querySelector(".reg-import-btn");
    if (importBtn) importBtn.addEventListener("click", () => importAccounts(mask));
  }

  const err = mask.querySelector(".errline");
  const close = () => { closeModal(); };
  mask.addEventListener("click", (e) => { if (e.target === mask) close(); });
  mask.querySelector(".reg-cancel").addEventListener("click", close);

  const first = mask.querySelector("input, textarea");
  if (first) first.focus();

  const submit = async () => {
    let value;
    if (isSignup) {
      const name = mask.querySelector("#reg-name").value.trim();
      const email = mask.querySelector("#reg-email").value.trim();
      const password = mask.querySelector("#reg-pw").value;
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return (err.textContent = t("reg.err.email"));
      if (password.length < 6) return (err.textContent = t("reg.err.password"));
      S.signupEmail = email;
      value = { name, email, password };
    } else {
      const link = mask.querySelector("#reg-link").value.trim();
      if (!/^https?:\/\//i.test(link)) return (err.textContent = t("reg.err.link"));
      S.linkAuto = LINK_MAX_AUTO;
      value = link;
    }
    const go = mask.querySelector(".reg-go");
    go.disabled = true;
    try {
      await invoke("reg_input", {
        ask: kind,
        value,
        flow: S.flow || null,
        email: S.batchEmail || null,
      });
      closeModal();
      pushLog(S, "info", isSignup ? "submittedSignup" : "submittedLink");
      render();
      if (drawer) drawer.scrollIntoView({ block: "end" });
    } catch (e) {
      err.textContent = String(e).replace(/^[a-z_]+:/, "");
      go.disabled = false;
    }
  };
  mask.querySelector(".reg-go").addEventListener("click", submit);
  mask.addEventListener("keydown", (e) => {
    if (e.key === "Escape") close();
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) submit();
    else if (e.key === "Enter" && !isSignup) submit();
  });
}

listen("reg://event", (ev) => regEvent(ev.payload)).catch(() => {});

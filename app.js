/* To Do — 四列看板 + GitHub 加密同步
 * 数据在本地和云端都以密文形式存在（PBKDF2-SHA256 → AES-GCM-256），
 * 密码只存在于你的脑子 + 当前标签页的 sessionStorage 里。
 */
(function () {
"use strict";

/* ==================== 常量 ==================== */
const COLS = ["inbox", "todo", "doing", "done"];
const COL_NAME = { inbox: "想法池", todo: "待办", doing: "进行中", done: "已完成" };
const ITER = 210000;                       // PBKDF2 迭代次数
const LS = {
  enc:   "todo.enc.v1",                    // 本地密文
  plain: "todo.plain.v1",                  // 不加密模式（file:// 兜底）
  cfg:   "todo.gh.v1",                     // GitHub 配置
  salt:  "todo.salt.v1"                    // 本机 salt
};
const SS = { pw: "todo.pw.session" };      // 当前标签页会话内的密码

const CAN_ENCRYPT = !!(window.crypto && window.crypto.subtle);

/* ==================== 运行时状态 ==================== */
let state = emptyState();
let cfg = { owner: "", repo: "", path: "todo.enc.json", token: "" };
let mode = "enc";              // "enc" | "plain"
let cryptoKey = null;
let keySalt = null;            // Uint8Array
let filter = "";
let editingId = null;
let remoteSha = null;
let syncTimer = null;
let saveChain = Promise.resolve();

function emptyState() {
  return { version: 1, updatedAt: 0, items: { inbox: [], todo: [], doing: [], done: [] } };
}

/* ==================== 小工具 ==================== */
const $  = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

function uid() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}
function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.add("on");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => t.classList.remove("on"), 2400);
}
function fmtTime(ts) {
  if (!ts) return "";
  const d = new Date(ts), now = new Date();
  const hm = String(d.getHours()).padStart(2, "0") + ":" + String(d.getMinutes()).padStart(2, "0");
  if (d.toDateString() === now.toDateString()) return "今天 " + hm;
  const md = (d.getMonth() + 1) + "月" + d.getDate() + "日";
  return d.getFullYear() === now.getFullYear() ? md + " " + hm : d.getFullYear() + "/" + md;
}
function truncate(s, n) { return s.length > n ? s.slice(0, n) + "…" : s; }

/* ==================== 编码 / 加密 ==================== */
function b64(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let bin = "";
  const CH = 0x8000;
  for (let i = 0; i < bytes.length; i += CH) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CH));
  }
  return btoa(bin);
}
function unb64(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function b64ToUtf8(s) {
  const bin = atob(String(s).replace(/\s/g, ""));
  const bytes = Uint8Array.from(bin, c => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}
function utf8ToB64(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = "";
  const CH = 0x8000;
  for (let i = 0; i < bytes.length; i += CH) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CH));
  }
  return btoa(bin);
}

async function deriveKey(password, saltBytes, iter) {
  const base = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBytes, iterations: iter || ITER, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function newSalt() { return crypto.getRandomValues(new Uint8Array(16)); }

/** 用密码派生并缓存 key，同时把 salt / 密码记到本机 */
async function installKey(password, saltBytes) {
  cryptoKey = await deriveKey(password, saltBytes, ITER);
  keySalt = saltBytes;
  sessionStorage.setItem(SS.pw, password);
  localStorage.setItem(LS.salt, b64(saltBytes));
}

async function encryptState(obj) {
  const salt = keySalt || unb64(localStorage.getItem(LS.salt) || b64(newSalt()));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const pt = new TextEncoder().encode(JSON.stringify(obj));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, pt);
  return {
    v: 1,
    alg: "AES-GCM",
    kdf: "PBKDF2-SHA256",
    iter: ITER,
    salt: b64(salt),
    iv: b64(iv),
    data: b64(new Uint8Array(ct))
  };
}

/** 解密一段密文。password 不传则用当前会话的 key */
async function decryptPayload(payload, password) {
  if (!payload || !payload.data) throw new Error("不是有效的加密数据");
  const salt = unb64(payload.salt);
  const iter = payload.iter || ITER;

  let key;
  if (!password && cryptoKey && keySalt && b64(keySalt) === payload.salt) {
    key = cryptoKey;                                   // salt 一致 → 复用缓存的 key
  } else {
    key = await deriveKey(password || sessionStorage.getItem(SS.pw) || "", salt, iter);
  }

  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: unb64(payload.iv) }, key, unb64(payload.data)
  );
  return JSON.parse(new TextDecoder().decode(pt));
}

/* ==================== 配置 ==================== */
function loadCfg() {
  try {
    const raw = localStorage.getItem(LS.cfg);
    if (raw) cfg = Object.assign(cfg, JSON.parse(raw));
  } catch (e) { /* 忽略损坏的配置 */ }
}
function saveCfg() { localStorage.setItem(LS.cfg, JSON.stringify(cfg)); }
function ghReady() { return !!(cfg.owner && cfg.repo && cfg.token); }

/* ==================== 持久化 ==================== */
function normalize(d) {
  const out = emptyState();
  if (d && d.items) {
    COLS.forEach(c => { out.items[c] = Array.isArray(d.items[c]) ? d.items[c] : []; });
    out.updatedAt = d.updatedAt || 0;
  }
  return out;
}

function persist() {
  state.updatedAt = Date.now();
  saveChain = saveChain.then(doPersist).catch(e => console.warn("保存失败", e));
  scheduleSync();
  return saveChain;
}

async function doPersist() {
  if (mode === "plain") {
    localStorage.setItem(LS.plain, JSON.stringify(state));
    return;
  }
  const payload = await encryptState(state);
  localStorage.setItem(LS.enc, JSON.stringify(payload));
}

async function loadStored() {
  if (mode === "plain") {
    const raw = localStorage.getItem(LS.plain);
    if (!raw) return null;
    return normalize(JSON.parse(raw));
  }
  const raw = localStorage.getItem(LS.enc);
  if (!raw) return null;
  return normalize(await decryptPayload(JSON.parse(raw)));
}

function applyState(d) {
  state = normalize(d);
  render();
}

/* ==================== 渲染 ==================== */
function allItems() {
  const out = [];
  COLS.forEach(c => state.items[c].forEach(it => out.push({ it, col: c })));
  return out;
}
function findItem(id) {
  for (const c of COLS) {
    const i = state.items[c].findIndex(x => x.id === id);
    if (i >= 0) return { col: c, index: i, item: state.items[c][i] };
  }
  return null;
}

function render() {
  const q = filter.trim().toLowerCase();

  COLS.forEach(col => {
    const body = $(`.col-body[data-body="${col}"]`);
    if (!body) return;
    const list = state.items[col];
    const shown = q ? list.filter(it => (it.title || "").toLowerCase().includes(q)) : list;

    body.innerHTML = "";
    if (shown.length === 0) {
      const e = document.createElement("div");
      e.className = "empty";
      e.textContent = q ? "没有匹配的任务" : emptyHint(col);
      body.appendChild(e);
    } else {
      shown.forEach(it => body.appendChild(cardEl(it, col)));
    }

    const counter = $(`.col[data-col="${col}"] .count`);
    if (counter) counter.textContent = list.length;
  });
}

function emptyHint(col) {
  return {
    inbox: "想到什么就先丢这里",
    todo: "把想法池里要做的挪过来",
    doing: "一次只专注一件事",
    done: "还没有完成的任务"
  }[col] || "空";
}

function cardEl(it, col) {
  const el = document.createElement("div");
  el.className = "card";
  el.dataset.id = it.id;

  const tick = document.createElement("button");
  tick.className = "tick";
  tick.title = col === "done" ? "重开" : "标记完成";
  tick.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>';
  tick.addEventListener("click", ev => {
    ev.stopPropagation();
    moveTo(it.id, col === "done" ? "doing" : "done");
  });
  el.appendChild(tick);

  const body = document.createElement("div");
  body.className = "body";
  const title = document.createElement("div");
  title.className = "title";
  title.textContent = it.title;
  body.appendChild(title);

  const bits = [];
  if (it.createdAt) bits.push(fmtTime(it.createdAt));
  if (col === "done" && it.doneAt) bits.push("完成于 " + fmtTime(it.doneAt));
  if (bits.length) {
    const meta = document.createElement("div");
    meta.className = "meta";
    meta.textContent = bits.join(" · ");
    body.appendChild(meta);
  }
  el.appendChild(body);

  const acts = document.createElement("div");
  acts.className = "acts";
  const nextMap = {
    inbox: ["todo", "→", "挪到待办"],
    todo:  ["doing", "▶", "开始"],
    doing: ["done", "✓", "完成"],
    done:  ["doing", "↺", "重开"]
  };
  const nx = nextMap[col];
  if (nx) {
    const b = document.createElement("button");
    b.textContent = nx[1];
    b.title = nx[2];
    b.addEventListener("click", ev => { ev.stopPropagation(); moveTo(it.id, nx[0]); });
    acts.appendChild(b);
  }
  const del = document.createElement("button");
  del.className = "del";
  del.textContent = "×";
  del.title = "删除";
  del.addEventListener("click", ev => { ev.stopPropagation(); removeItem(it.id); });
  acts.appendChild(del);
  el.appendChild(acts);

  title.addEventListener("dblclick", ev => {
    ev.stopPropagation();
    startEdit(it.id, el, title);
  });

  return el;
}

function startEdit(id, cardElm, titleElm) {
  if (editingId) return;
  editingId = id;
  cardElm.classList.add("editing");

  const ta = document.createElement("textarea");
  ta.className = "editinput";
  ta.value = titleElm.textContent;
  ta.rows = 1;
  titleElm.replaceWith(ta);
  ta.focus();
  ta.setSelectionRange(ta.value.length, ta.value.length);
  const auto = () => { ta.style.height = "auto"; ta.style.height = ta.scrollHeight + "px"; };
  auto();
  ta.addEventListener("input", auto);

  let finished = false;
  const finish = commit => {
    if (finished) return;
    finished = true;
    editingId = null;
    const v = ta.value.trim();
    const found = findItem(id);
    if (commit && found) {
      if (v) {
        found.item.title = v;
        found.item.updatedAt = Date.now();
      } else {
        state.items[found.col].splice(found.index, 1);
      }
      persist();
    }
    render();
  };

  ta.addEventListener("keydown", e => {
    if (e.key === "Enter" && !e.shiftKey && !e.isComposing) { e.preventDefault(); finish(true); }
    else if (e.key === "Escape") { e.preventDefault(); finish(false); }
  });
  ta.addEventListener("blur", () => finish(true));
}

/* ==================== 数据操作 ==================== */
function addItem(title, col) {
  title = String(title || "").trim();
  if (!title) return null;
  const it = { id: uid(), title, createdAt: Date.now(), updatedAt: Date.now() };
  state.items[col || "inbox"].push(it);
  persist();
  render();
  return it;
}

function moveTo(id, targetCol) {
  const found = findItem(id);
  if (!found || found.col === targetCol) return;
  const [it] = state.items[found.col].splice(found.index, 1);
  it.updatedAt = Date.now();
  if (targetCol === "done") it.doneAt = Date.now();
  else delete it.doneAt;
  state.items[targetCol].push(it);
  persist();
  render();
}

function removeItem(id) {
  const found = findItem(id);
  if (!found) return;
  const removed = state.items[found.col].splice(found.index, 1)[0];
  persist();
  render();
  toast("已删除「" + truncate(removed.title, 18) + "」");
}

/* ==================== 拖拽 ==================== */
let drag = null;

function onPointerDown(e) {
  if (filter.trim()) return;                       // 搜索状态下禁止拖拽，避免顺序错乱
  if (e.button !== undefined && e.button !== 0) return;
  const card = e.target.closest(".card");
  if (!card) return;
  if (e.target.closest("button") || e.target.closest(".editinput")) return;
  if (editingId) return;

  drag = {
    card,
    id: card.dataset.id,
    pointerId: e.pointerId,
    startX: e.clientX,
    startY: e.clientY,
    active: false,
    ghost: null,
    placeholder: null,
    offsetX: 0,
    offsetY: 0,
    targetCol: null,
    dropIndex: -1,
    holdTimer: null,
    isTouch: e.pointerType === "touch"
  };

  if (drag.isTouch) {
    // 移动端长按 220ms 才进入拖拽，否则让页面正常滚动
    drag.holdTimer = setTimeout(() => {
      if (drag && !drag.active) startDrag(e.clientX, e.clientY);
    }, 220);
  }
  window.addEventListener("pointermove", onPointerMove, { passive: false });
  window.addEventListener("pointerup", onPointerUp);
  window.addEventListener("pointercancel", onPointerUp);
}

function startDrag(x, y) {
  const { card } = drag;
  const rect = card.getBoundingClientRect();
  drag.offsetX = x - rect.left;
  drag.offsetY = y - rect.top;
  drag.active = true;

  const ghost = card.cloneNode(true);
  ghost.classList.add("ghost");
  ghost.style.width = rect.width + "px";
  ghost.style.left = rect.left + "px";
  ghost.style.top = rect.top + "px";
  document.body.appendChild(ghost);
  drag.ghost = ghost;

  const ph = document.createElement("div");
  ph.className = "placeholder";
  ph.style.height = rect.height + "px";
  card.after(ph);
  drag.placeholder = ph;

  card.classList.add("is-dragging");
  document.body.style.userSelect = "none";
  if (navigator.vibrate) navigator.vibrate(8);
}

function onPointerMove(e) {
  if (!drag || e.pointerId !== drag.pointerId) return;

  if (!drag.active) {
    if (drag.isTouch) return;                      // 触摸靠长按激活
    const dx = e.clientX - drag.startX;
    const dy = e.clientY - drag.startY;
    if (Math.hypot(dx, dy) <= 6) return;
    startDrag(e.clientX, e.clientY);
  }

  e.preventDefault();
  drag.ghost.style.left = (e.clientX - drag.offsetX) + "px";
  drag.ghost.style.top = (e.clientY - drag.offsetY) + "px";
  updateDrop(e.clientX, e.clientY);
}

function updateDrop(x, y) {
  const under = document.elementFromPoint(x, y);
  const col = under && under.closest ? under.closest(".col") : null;
  $$(".col-body").forEach(b => b.classList.remove("droptarget"));

  if (!col) {
    drag.placeholder.style.display = "none";
    drag.targetCol = null;
    drag.dropIndex = -1;
    return;
  }

  const body = col.querySelector(".col-body");
  body.classList.add("droptarget");
  drag.targetCol = col.dataset.col;

  // 找到插入点：第一张"中线在指针下方"的卡片
  const cards = $$(".card:not(.is-dragging)", body);
  let ref = null, idx = cards.length;
  for (let i = 0; i < cards.length; i++) {
    const r = cards[i].getBoundingClientRect();
    if (y < r.top + r.height / 2) { ref = cards[i]; idx = i; break; }
  }
  drag.dropIndex = idx;

  const empty = body.querySelector(".empty");
  if (empty) empty.remove();

  drag.placeholder.style.display = "";
  if (ref) body.insertBefore(drag.placeholder, ref);
  else body.appendChild(drag.placeholder);
}

function onPointerUp(e) {
  if (!drag) return;
  if (drag.pointerId !== undefined && e.pointerId !== drag.pointerId) return;

  clearTimeout(drag.holdTimer);
  window.removeEventListener("pointermove", onPointerMove);
  window.removeEventListener("pointerup", onPointerUp);
  window.removeEventListener("pointercancel", onPointerUp);
  $$(".col-body").forEach(b => b.classList.remove("droptarget"));
  document.body.style.userSelect = "";

  const d = drag;
  drag = null;

  if (d.ghost) d.ghost.remove();
  if (d.placeholder) d.placeholder.remove();

  if (!d.active) return;                            // 只是点了一下
  if (!d.targetCol || d.dropIndex < 0) { render(); return; }

  applyDrop(d.id, d.targetCol, d.dropIndex);
}

function applyDrop(id, targetCol, index) {
  const found = findItem(id);
  if (!found) { render(); return; }

  const [it] = state.items[found.col].splice(found.index, 1);
  it.updatedAt = Date.now();
  if (targetCol === "done" && found.col !== "done") it.doneAt = Date.now();
  if (targetCol !== "done") delete it.doneAt;

  // index 是"排除自己之后"的位置，摘出后数组正好一致
  const arr = state.items[targetCol];
  arr.splice(Math.max(0, Math.min(index, arr.length)), 0, it);

  persist();
  render();
}

/* ==================== 开始下一个 ==================== */
function startNext() {
  if (state.items.doing.length > 0) {
    const first = state.items.doing[0];
    toast("正在做「" + truncate(first.title, 16) + "」，先把它完成吧");
    const el = $(`.card[data-id="${first.id}"]`);
    if (el) {
      el.style.transition = "box-shadow .2s";
      el.style.boxShadow = "0 0 0 3px rgba(217,140,43,.35)";
      setTimeout(() => { el.style.boxShadow = ""; }, 900);
      el.scrollIntoView({ block: "center", behavior: "smooth" });
    }
    return;
  }
  if (state.items.todo.length === 0) {
    toast(state.items.inbox.length
      ? "待办是空的 —— 先把想法池里要做的挪到待办"
      : "先记一条吧");
    return;
  }
  const first = state.items.todo[0];
  moveTo(first.id, "doing");
  toast("开始：「" + truncate(first.title, 18) + "」");
}

/* ==================== GitHub 同步 ==================== */
function setSync(s, text) {
  const chip = $("#syncChip");
  if (!chip) return;
  chip.dataset.s = s;
  $("#syncText").textContent = text || ({ off: "本地", ok: "已同步", busy: "同步中", err: "同步出错" }[s]) || "本地";
}

function ghHeaders() {
  return {
    "Authorization": "Bearer " + cfg.token,
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28"
  };
}

function ghUrl() {
  const path = (cfg.path || "todo.enc.json").replace(/^\/+/, "");
  return "https://api.github.com/repos/" +
    encodeURIComponent(cfg.owner) + "/" + encodeURIComponent(cfg.repo) +
    "/contents/" + path.split("/").map(encodeURIComponent).join("/");
}

async function safeErr(res) {
  try {
    const j = await res.json();
    if (j && j.message) return res.status + " " + j.message;
  } catch (e) { /* 无 body */ }
  return "HTTP " + res.status;
}

/** 读云端密文；返回 null 表示文件还不存在 */
async function ghFetch() {
  const res = await fetch(ghUrl() + "?t=" + Date.now(), {
    headers: ghHeaders(),
    cache: "no-store"
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(await safeErr(res));
  const j = await res.json();
  let payload;
  try {
    payload = JSON.parse(b64ToUtf8(j.content || ""));
  } catch (e) {
    throw new Error("云端文件不是有效的加密数据");
  }
  return { sha: j.sha, payload };
}

async function ghUpload() {
  if (mode === "plain") throw new Error("当前是不加密模式，出于安全考虑不会上传");
  const payload = await encryptState(state);
  const body = {
    message: "todo: 更新于 " + new Date().toLocaleString("zh-CN"),
    content: utf8ToB64(JSON.stringify(payload, null, 2))
  };

  let sha = remoteSha;
  if (!sha) {
    const cur = await ghFetch();
    sha = cur ? cur.sha : null;
  }
  if (sha) body.sha = sha;

  const res = await fetch(ghUrl(), {
    method: "PUT",
    headers: Object.assign({ "Content-Type": "application/json" }, ghHeaders()),
    body: JSON.stringify(body)
  });
  if (!res.ok) throw new Error(await safeErr(res));
  const j = await res.json();
  remoteSha = j.content ? j.content.sha : sha;
  return true;
}

function scheduleSync() {
  if (!ghReady() || mode === "plain") { setSync("off", "本地"); return; }
  clearTimeout(syncTimer);
  syncTimer = setTimeout(doSync, 2500);
}

async function doSync() {
  if (!ghReady() || mode === "plain") return;
  setSync("busy", "同步中");
  try {
    await ghUpload();
    setSync("ok", "已同步");
  } catch (e) {
    console.warn(e);
    setSync("err", "同步出错");
    remoteSha = null;
    toast("云端同步失败：" + e.message);
  }
}

/** 启动时对齐本地与云端 */
async function reconcile() {
  setSync("busy", "同步中");
  try {
    const cur = await ghFetch();
    if (!cur) {                                  // 云端还没有 → 把本地推上去
      if (allItems().length > 0) await ghUpload();
      setSync("ok", "已同步");
      return;
    }
    remoteSha = cur.sha;

    let remoteData;
    try {
      remoteData = await decryptPayload(cur.payload);
    } catch (e) {
      setSync("err", "密码不匹配");
      toast("云端数据用别的密码加密过，暂时读不了");
      return;
    }

    const rCount = COLS.reduce((n, c) => n + (remoteData.items[c] || []).length, 0);
    const lCount = allItems().length;
    const remoteNewer = (remoteData.updatedAt || 0) > (state.updatedAt || 0);

    if (lCount === 0 && rCount > 0) {
      applyState(remoteData);
      toast("已载入云端 " + rCount + " 条任务");
    } else if (remoteNewer && rCount > 0) {
      applyState(remoteData);
      toast("已载入云端最新版本");
    } else if (lCount > 0 && !remoteNewer) {
      await ghUpload();
    }
    setSync("ok", "已同步");
  } catch (e) {
    console.warn(e);
    setSync("err", "同步出错");
  }
}

/* ==================== 锁屏 / 密码 ==================== */
let lockMode = "unlock";        // "unlock" | "setup"

function showLock(kind) {
  lockMode = kind;
  $("#lock").classList.add("on");

  const hasSalt = !!localStorage.getItem(LS.salt);
  const hasData = hasSalt && !!localStorage.getItem(LS.enc);
  const sw = $("#switchMode");
  const note = $("#lockNote");

  $("#lockInput").value = "";
  $("#lockInput2").value = "";
  $("#lockErr").textContent = "";
  $("#rcErr").textContent = "";

  if (kind === "setup") {
    $("#lockSub").textContent = "先设一个密码，数据用它加密";
    $("#lockInput").placeholder = "设置密码（至少 8 位）";
    $("#lockInput2").style.display = "";
    note.style.display = "";
    note.innerHTML = "密码不会写进任何文件，<b>只在你脑子里</b>。仓库里存的是密文，别人下载也只能看到乱码。" +
      "代价是：<b>密码忘了，数据就永久解不开</b> —— 解锁后请偶尔点「导出 JSON」留个备份。";
    $("#lockBtn").textContent = "设置并进入";
    // 本机已有数据时不给"重设密码"的入口，避免把旧数据锁死
    sw.style.display = hasData ? "" : "none";
    sw.textContent = "已有密码？返回解锁";
  } else {
    // 关键：密码跟着「数据」走，不跟着「这台电脑」走。
    // 新设备没有本机 salt 时也要先问密码，而不是让他重设。
    $("#lockSub").textContent = hasSalt ? "输入密码解锁" : "这台设备上还没有数据";
    $("#lockInput").placeholder = "密码";
    $("#lockInput2").style.display = "none";
    note.style.display = hasSalt ? "none" : "";
    if (!hasSalt) {
      note.innerHTML = "密码跟着<b>数据</b>走，不跟着这台电脑。<br>" +
        "之前在别的设备用过 → 点「已有数据？从云端恢复」，填仓库信息和<b>你原来那个密码</b>。<br>" +
        "真是第一次用 → 点「第一次使用？设置新密码」。";
    }
    $("#lockBtn").textContent = "解锁";
    sw.style.display = hasSalt ? "none" : "";
    sw.textContent = "第一次使用？设置新密码";
  }

  setTimeout(() => $("#lockInput").focus(), 80);
}

async function submitLock() {
  const err = $("#lockErr");
  err.textContent = "";
  const v = $("#lockInput").value;

  if (!v) { err.textContent = "请输入密码"; return; }

  if (lockMode === "setup") {
    // 本机已有加密数据时绝不允许在这里重设 —— 换了 salt 旧密文就永远解不开了
    if (localStorage.getItem(LS.salt) && localStorage.getItem(LS.enc)) {
      err.textContent = "这台设备上已经有数据了。要改密码请进「设置 → 修改密码」";
      return;
    }
    if (v.length < 8) { err.textContent = "至少 8 位，长一点更安全"; return; }
    if (v !== $("#lockInput2").value) { err.textContent = "两次输入不一致"; return; }
    const salt = newSalt();
    await installKey(v, salt);
    $("#lock").classList.remove("on");
    await enterApp(true);
    return;
  }

  // 解锁：本机没有 salt 就说明这台设备还没接过数据，别拿空 salt 去派生
  if (!localStorage.getItem(LS.salt)) {
    err.textContent = "这台设备还没有数据。请用下方「已有数据？从云端恢复」";
    return;
  }

  try {
    const salt = unb64(localStorage.getItem(LS.salt));
    await installKey(v, salt);
    const data = await loadStored();            // 解密失败 = 密码错
    if (data) applyState(data);
    $("#lock").classList.remove("on");
    await enterApp(false);
  } catch (e) {
    cryptoKey = null;
    keySalt = null;
    sessionStorage.removeItem(SS.pw);
    err.textContent = "密码不对";
    $("#lockInput").value = "";
    $("#lockInput").focus();
  }
}

/** 从云端恢复：用原密码解密，成功后接管本机 salt */
async function recoverFromCloud() {
  const err = $("#rcErr");
  err.textContent = "";
  const owner = $("#rcOwner").value.trim();
  const repo = $("#rcRepo").value.trim();
  const path = $("#rcPath").value.trim() || "todo.enc.json";
  const token = $("#rcToken").value.trim();
  const pass = $("#rcPass").value;

  if (!owner || !repo || !token) { err.textContent = "用户名 / 仓库 / Token 都要填"; return; }
  if (!pass) { err.textContent = "请输入原密码"; return; }

  err.style.color = "var(--muted)";
  err.textContent = "正在拉取…";

  const backup = { owner: cfg.owner, repo: cfg.repo, path: cfg.path, token: cfg.token };
  cfg = { owner, repo, path, token };

  try {
    const cur = await ghFetch();
    if (!cur) { err.style.color = ""; err.textContent = "这个仓库里找不到该文件"; cfg = backup; return; }

    const data = await decryptPayload(cur.payload, pass);
    remoteSha = cur.sha;

    // 接管：把本机 salt / key 换成这份数据对应的
    const salt = unb64(cur.payload.salt);
    await installKey(pass, salt);

    saveCfg();
    applyState(data);
    localStorage.setItem(LS.enc, JSON.stringify(cur.payload));

    $("#lock").classList.remove("on");
    await enterApp(false);
    toast("已恢复 " + allItems().length + " 条任务");
  } catch (e) {
    cfg = backup;
    err.style.color = "";
    err.textContent = /decrypt|operation/i.test(String(e)) ? "密码不对，解不开这份数据" : ("恢复失败：" + e.message);
  }
}

/* ==================== 设置面板 ==================== */
function openSettings() {
  $("#ghOwner").value = cfg.owner || "";
  $("#ghRepo").value = cfg.repo || "";
  $("#ghPath").value = cfg.path || "todo.enc.json";
  $("#ghToken").value = cfg.token || "";
  const gs = $("#ghStatus");
  gs.className = "status";
  gs.textContent = mode === "plain"
    ? "当前是不加密模式，同步已禁用"
    : (ghReady() ? "已配置" : "尚未配置（不配置也能用，数据只存在本机）");

  $("#pwStatus").textContent = "";
  $("#dataStatus").textContent = "共 " + allItems().length + " 条任务";
  $("#settings").showModal();
}

async function saveGithub() {
  cfg.owner = $("#ghOwner").value.trim();
  cfg.repo = $("#ghRepo").value.trim();
  cfg.path = $("#ghPath").value.trim() || "todo.enc.json";
  cfg.token = $("#ghToken").value.trim();
  saveCfg();

  const st = $("#ghStatus");
  if (mode === "plain") {
    st.className = "status err";
    st.textContent = "不加密模式不会上传。请用 https / localhost 打开后再配置。";
    return;
  }
  if (!ghReady()) {
    st.className = "status err";
    st.textContent = "三项都要填：用户名 / 仓库名 / Token";
    return;
  }

  st.className = "status";
  st.textContent = "正在连接…";
  try {
    const cur = await ghFetch();
    remoteSha = cur ? cur.sha : null;

    if (!cur) {
      await ghUpload();
      st.className = "status ok";
      st.textContent = "连接成功，已把本地 " + allItems().length + " 条加密上传";
      setSync("ok", "已同步");
      return;
    }

    let remoteData = null;
    try { remoteData = await decryptPayload(cur.payload); } catch (e) { remoteData = null; }

    if (!remoteData) {
      st.className = "status err";
      st.textContent = "云端有数据，但用的是另一个密码加密的。用「从云端拉取」输入原密码。";
      setSync("err", "密码不匹配");
      return;
    }

    const rCount = COLS.reduce((n, c) => n + (remoteData.items[c] || []).length, 0);
    const lCount = allItems().length;
    st.className = "status ok";
    st.textContent = "连接成功。本地 " + lCount + " 条 / 云端 " + rCount + " 条。";

    if (lCount === 0 && rCount > 0) {
      applyState(remoteData);
      st.textContent = "连接成功，已载入云端 " + rCount + " 条";
      toast("已从云端载入 " + rCount + " 条");
    } else if (lCount > 0 && rCount === 0) {
      await ghUpload();
      st.textContent = "连接成功，本地 " + lCount + " 条已上传";
    } else if (lCount > 0 && rCount > 0) {
      st.textContent += " 用「拉取」或「上传」决定以谁为准。";
    }
    setSync("ok", "已同步");
  } catch (e) {
    st.className = "status err";
    st.textContent = "连接失败：" + e.message;
    setSync("err", "同步出错");
  }
}

/* ==================== 事件绑定 ==================== */
function bind() {
  // 添加
  const addInput = $("#addInput");
  const doAdd = () => {
    if (!addInput.value.trim()) return;
    addItem(addInput.value, "inbox");
    addInput.value = "";
    addInput.focus();
  };
  $("#addBtn").addEventListener("click", doAdd);
  addInput.addEventListener("keydown", e => {
    if (e.key === "Enter" && !e.isComposing) { e.preventDefault(); doAdd(); }
  });

  // 列头 +
  $$(".coladd").forEach(b => {
    b.addEventListener("click", () => {
      const col = b.dataset.add;
      const v = prompt("添加到「" + COL_NAME[col] + "」：");
      if (v && v.trim()) addItem(v, col);
    });
  });

  // 搜索
  $("#q").addEventListener("input", e => { filter = e.target.value; render(); });

  // 开始下一个
  $("#nextBtn").addEventListener("click", startNext);

  // 设置
  $("#setBtn").addEventListener("click", openSettings);
  $("#dlgClose").addEventListener("click", () => $("#settings").close());
  $("#settings").addEventListener("click", e => {
    if (e.target === $("#settings")) $("#settings").close();
  });

  // 云端
  $("#ghSave").addEventListener("click", saveGithub);

  $("#ghPull").addEventListener("click", async () => {
    const st = $("#ghStatus");
    if (mode === "plain") { st.className = "status err"; st.textContent = "不加密模式不会联网"; return; }
    if (!ghReady()) { st.className = "status err"; st.textContent = "先填好并保存配置"; return; }
    st.className = "status"; st.textContent = "正在拉取…";
    try {
      const cur = await ghFetch();
      if (!cur) { st.className = "status err"; st.textContent = "云端还没有数据"; return; }

      let data;
      try {
        data = await decryptPayload(cur.payload);
      } catch (e) {
        // 云端是另一个密码加密的 → 让用户输入原密码
        const p = prompt("云端数据是用另一个密码加密的。请输入那个密码：");
        if (!p) { st.className = "status err"; st.textContent = "已取消"; return; }
        data = await decryptPayload(cur.payload, p);
        await installKey(p, unb64(cur.payload.salt));
        st.className = "status ok";
        st.textContent = "已切换为本机密码 = 云端密码";
      }

      const n = COLS.reduce((a, c) => a + (data.items[c] || []).length, 0);
      if (!confirm("用云端数据覆盖本地？云端 " + n + " 条，本地 " + allItems().length + " 条。")) return;
      remoteSha = cur.sha;
      applyState(data);
      await persist();
      st.className = "status ok";
      st.textContent = "已拉取 " + n + " 条";
      setSync("ok", "已同步");
      toast("已从云端拉取");
    } catch (e) {
      st.className = "status err";
      st.textContent = "拉取失败：" + e.message;
    }
  });

  $("#ghPush").addEventListener("click", async () => {
    const st = $("#ghStatus");
    if (mode === "plain") { st.className = "status err"; st.textContent = "不加密模式不会上传"; return; }
    if (!ghReady()) { st.className = "status err"; st.textContent = "先填好并保存配置"; return; }
    st.className = "status"; st.textContent = "正在上传…";
    try {
      remoteSha = null;
      await ghUpload();
      st.className = "status ok";
      st.textContent = "已上传 " + allItems().length + " 条（密文）";
      setSync("ok", "已同步");
    } catch (e) {
      st.className = "status err";
      st.textContent = "上传失败：" + e.message;
    }
  });

  // 改密码
  $("#pwSave").addEventListener("click", async () => {
    const st = $("#pwStatus");
    if (mode === "plain") { st.className = "status err"; st.textContent = "不加密模式下没有密码可改"; return; }
    const a = $("#pwNew").value;
    const b = $("#pwNew2").value;
    if (a.length < 8) { st.className = "status err"; st.textContent = "至少 8 位"; return; }
    if (a !== b) { st.className = "status err"; st.textContent = "两次输入不一致"; return; }

    st.className = "status"; st.textContent = "正在用新密码重新加密…";
    try {
      const salt = newSalt();
      await installKey(a, salt);
      await doPersist();
      $("#pwNew").value = "";
      $("#pwNew2").value = "";
      st.className = "status ok";
      st.textContent = "已改好。正在同步到云端…";
      if (ghReady()) {
        remoteSha = null;
        await ghUpload();
        st.textContent = "已改好并同步到云端";
        setSync("ok", "已同步");
      }
    } catch (e) {
      st.className = "status err";
      st.textContent = "改密码失败：" + e.message;
    }
  });

  $("#pwLock").addEventListener("click", () => {
    if (mode === "plain") { toast("不加密模式没有锁"); return; }
    sessionStorage.removeItem(SS.pw);
    cryptoKey = null;
    keySalt = null;
    $("#settings").close();
    showLock("unlock");
  });

  // 数据
  $("#exportBtn").addEventListener("click", () => {
    // 导出的是明文 JSON —— 提醒用户别乱放
    const blob = new Blob([JSON.stringify(state, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    const d = new Date();
    const stamp = d.getFullYear() + String(d.getMonth() + 1).padStart(2, "0") + String(d.getDate()).padStart(2, "0");
    a.href = URL.createObjectURL(blob);
    a.download = "todo-backup-" + stamp + ".json";
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    $("#dataStatus").textContent = "已导出 " + allItems().length + " 条（注意：备份文件是明文）";
  });

  $("#importBtn").addEventListener("click", () => $("#importFile").click());
  $("#importFile").addEventListener("change", async e => {
    const f = e.target.files && e.target.files[0];
    if (!f) return;
    try {
      const d = JSON.parse(await f.text());
      if (!d || !d.items) throw new Error("文件格式不对");
      const n = COLS.reduce((a, c) => a + ((d.items[c] || []).length), 0);
      if (!confirm("导入会覆盖当前全部任务（共 " + allItems().length + " 条）。继续？")) return;
      applyState(d);
      await persist();
      $("#dataStatus").textContent = "已导入 " + n + " 条";
      toast("已导入 " + n + " 条");
    } catch (err) {
      $("#dataStatus").textContent = "导入失败：" + err.message;
    }
    e.target.value = "";
  });

  $("#clearDone").addEventListener("click", async () => {
    const n = state.items.done.length;
    if (!n) { toast("已完成是空的"); return; }
    if (!confirm("清空 " + n + " 条已完成的任务？")) return;
    state.items.done = [];
    await persist();
    render();
    $("#dataStatus").textContent = "已清空 " + n + " 条已完成";
  });

  // 锁屏
  $("#lockBtn").addEventListener("click", submitLock);
  $("#lockInput").addEventListener("keydown", e => {
    if (e.key !== "Enter" || e.isComposing) return;
    if (lockMode === "setup" && !$("#lockInput2").value) { $("#lockInput2").focus(); return; }
    submitLock();
  });
  $("#lockInput2").addEventListener("keydown", e => {
    if (e.key === "Enter" && !e.isComposing) submitLock();
  });

  // 从云端恢复
  $("#switchMode").addEventListener("click", () => {
    showLock(lockMode === "setup" ? "unlock" : "setup");
  });
  $("#recoverLink").addEventListener("click", () => {
    const box = $("#recoverBox");
    const show = box.style.display === "none";
    box.style.display = show ? "" : "none";
    if (show) $("#rcOwner").focus();
  });
  $("#rcBtn").addEventListener("click", recoverFromCloud);

  // 拖拽
  $("#board").addEventListener("pointerdown", onPointerDown);

  // 快捷键
  document.addEventListener("keydown", e => {
    if (editingId) return;
    if ($("#lock").classList.contains("on")) return;
    const tag = document.activeElement && document.activeElement.tagName;
    const inField = /^(INPUT|TEXTAREA|SELECT)$/.test(tag);
    if (e.key === "n" && !inField && !e.metaKey && !e.ctrlKey && !e.altKey) {
      e.preventDefault();
      $("#addInput").focus();
    }
    if (e.key === "/" && !inField) {
      e.preventDefault();
      $("#q").focus();
    }
  });
}

/* ==================== 进入应用 ==================== */
async function enterApp(isFirstSetup) {
  let data = null;
  try {
    data = await loadStored();
  } catch (e) {
    console.warn("本地数据读取失败", e);
  }

  if (data) applyState(data);
  else render();

  // 首次设密码：把可能存在的旧明文数据迁移过来
  if (isFirstSetup) {
    try {
      const legacy = localStorage.getItem("todo.data.v1");
      if (legacy) {
        const d = JSON.parse(legacy);
        if (d && d.items) {
          applyState(d);
          localStorage.removeItem("todo.data.v1");
        }
      }
    } catch (e) { /* 忽略 */ }
    await doPersist();
  }

  if (ghReady() && mode === "enc") await reconcile();
  else setSync("off", "本地");
}

function startPlainMode() {
  mode = "plain";
  loadCfg();
  cfg = { owner: "", repo: "", path: cfg.path, token: "" };   // 不加密模式不联网
  bind();
  try {
    const raw = localStorage.getItem(LS.plain);
    if (raw) applyState(JSON.parse(raw));
    else render();
  } catch (e) { render(); }
  setSync("off", "本地");
  toast("不加密模式：数据只在本机，不会上传");
}

/* ==================== 启动 ==================== */
async function boot() {
  loadCfg();

  if (!CAN_ENCRYPT) {
    $("#unsupported").classList.add("on");
    $("#forceBtn").addEventListener("click", () => {
      $("#unsupported").classList.remove("on");
      startPlainMode();
    });
    return;
  }

  bind();

  const hasSalt = !!localStorage.getItem(LS.salt);
  const savedPw = sessionStorage.getItem(SS.pw);

  // 同一标签页刷新 → 用会话里的密码静默解锁
  if (hasSalt && savedPw) {
    try {
      await installKey(savedPw, unb64(localStorage.getItem(LS.salt)));
      const data = await loadStored();
      if (data) applyState(data);
      else render();
      $("#lock").classList.remove("on");
      if (ghReady() && mode === "enc") await reconcile();
      else setSync("off", "本地");
      return;
    } catch (e) {
      cryptoKey = null;
      keySalt = null;
      sessionStorage.removeItem(SS.pw);
    }
  }

  // 一律先问密码：密码属于数据，不属于这台设备。
  // 本机没有 salt 时 showLock 会给出「从云端恢复 / 第一次使用」两条路。
  showLock("unlock");
}

boot();

})();

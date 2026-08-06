"use strict";

const $ = (id) => document.getElementById(id);
const tokenKey = "causeway_token";
let servers = [];
let currentRole = "";
let umodalData = null;
let umodalAction = null;
let term = null;
let termWS = null;
let termFit = null;

/* ---------- 基础工具 ---------- */

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function api(path, opts = {}) {
  opts.headers = Object.assign(
    { Authorization: "Bearer " + localStorage.getItem(tokenKey) },
    opts.headers || {}
  );
  return apiPublic(path, opts).then((data) => {
    if (data && data.error === "unauthorized") {
      showLogin();
      throw new Error("未授权，请重新登录");
    }
    return data;
  });
}

function apiPublic(path, opts = {}) {
  if (opts.body && typeof opts.body !== "string") {
    opts.body = JSON.stringify(opts.body);
  }
  return fetch(path, opts).then(async (res) => {
    if (res.status === 401) {
      const data = await res.json().catch(() => ({}));
      const err = new Error(data.error || "unauthorized");
      err.status = 401;
      throw err;
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || res.statusText);
    return data;
  });
}

function showToast(msg, type = "info") {
  const el = document.createElement("div");
  el.className = "toast " + type;
  el.textContent = msg;
  $("toasts").appendChild(el);
  setTimeout(() => {
    el.classList.add("out");
    setTimeout(() => el.remove(), 320);
  }, 3600);
}

function confirmDialog(title, text) {
  return new Promise((resolve) => {
    $("cmodal-title").textContent = title;
    $("cmodal-text").textContent = text;
    $("cmodal").classList.remove("hidden");
    $("cmodal-ok").onclick = () => { $("cmodal").classList.add("hidden"); resolve(true); };
    $("cmodal-cancel").onclick = () => { $("cmodal").classList.add("hidden"); resolve(false); };
  });
}

/* ---------- 登录 ---------- */

function switchLoginTab(which) {
  $("login-account").classList.toggle("hidden", which !== "account");
  $("login-token").classList.toggle("hidden", which !== "token");
  $("tab-account").classList.toggle("active", which === "account");
  $("tab-token").classList.toggle("active", which === "token");
  $("login-msg").textContent = "";
}

function loginAccount() {
  const username = $("user-input").value.trim();
  const password = $("pass-input").value;
  $("login-msg").textContent = "";
  apiPublic("/api/login", { method: "POST", body: { username, password } })
    .then((d) => {
      localStorage.setItem(tokenKey, d.token);
      currentRole = d.role;
      showApp();
    })
    .catch((e) => ($("login-msg").textContent = "登录失败: " + e.message));
}

function loginToken() {
  const token = $("token-input").value.trim();
  $("login-msg").textContent = "";
  localStorage.setItem(tokenKey, token);
  api("/api/me")
    .then(() => showApp())
    .catch(() => {
      localStorage.removeItem(tokenKey);
      $("login-msg").textContent = "Token 无效";
    });
}

function logout() {
  api("/api/logout", { method: "POST" }).catch(() => {});
  localStorage.removeItem(tokenKey);
  showLogin();
}

function showLogin() {
  $("login").classList.remove("hidden");
  $("app").classList.add("hidden");
  $("terminal-view").classList.add("hidden");
}

function showApp() {
  $("login").classList.add("hidden");
  $("app").classList.remove("hidden");
  api("/api/me").then((d) => {
    currentRole = d.role;
    $("whoami").textContent = d.username + (d.role === "admin" ? " · 管理员" : "");
    $("admin-btn").classList.toggle("hidden", d.role !== "admin");
  }).catch(() => {});
  loadServers();
  setInterval(() => {
    if (!document.hidden && !$("app").classList.contains("hidden")) loadServers();
  }, 5000);
}

/* ---------- 服务器 ---------- */

function loadServers() {
  $("conn-state").textContent = "加载中…";
  api("/api/servers")
    .then((d) => {
      servers = d.servers;
      $("conn-state").textContent = "";
      render();
    })
    .catch((e) => {
      $("conn-state").textContent = "";
      if (e.status !== 401) showToast("加载服务器失败: " + e.message, "error");
    });
}

function render() {
  const online = servers.filter((s) => s.online).length;
  $("stat-total").textContent = servers.length;
  $("stat-online").textContent = online;
  $("stat-offline").textContent = servers.length - online;
  $("empty").classList.toggle("hidden", servers.length > 0);

  const tbody = document.querySelector("#servers tbody");
  tbody.innerHTML = "";
  for (const s of servers) {
    const tr = document.createElement("tr");
    if (!s.online) tr.classList.add("offline");
    const adminLabel = s.admin_enabled ? "停用服务器" : "启用服务器";
    const proxyLabel = s.proxy_enabled ? "关闭代理" : "开启代理";
    tr.innerHTML = `
      <td><div class="srv-name"><strong>${esc(s.name)}</strong><span class="muted">${esc(s.hostname || "")}</span></div></td>
      <td><span class="pill ${s.online ? "on" : "off"}">${s.online ? "在线" : "离线"}</span></td>
      <td><code>${s.port}</code></td>
      <td>${esc(s.default_user || "—")}</td>
      <td><span class="ver">${esc(s.agent_version || "—")}</span></td>
      <td><span class="muted">${esc(s.last_seen || "—")}</span></td>
      <td class="act">
        <button class="menu-btn" id="menu-btn-${s.id}"
          onclick="event.stopPropagation(); toggleMenu(${s.id})" title="操作">⋯</button>
        <div class="menu hidden" id="menu-${s.id}">
          <button class="mi" onclick="openTerminal(${s.id}); closeMenus()">打开终端</button>
          <button class="mi" onclick="showLogs(${s.id}); closeMenus()">查看日志</button>
          <button class="mi" onclick="upgradeAgent(${s.id}); closeMenus()" ${s.online ? "" : "disabled"}>升级 Agent</button>
          <button class="mi" onclick="showInstall(${s.id}); closeMenus()">安装命令</button>
          <button class="mi" onclick="reconnect(${s.id}); closeMenus()" ${s.online ? "" : "disabled"}>重连</button>
          <button class="mi" onclick="chooseDefaultUser(${s.id}); closeMenus()">设置默认用户</button>
          <button class="mi" onclick="toggleAdmin(${s.id}, ${!s.admin_enabled}); closeMenus()">${adminLabel}</button>
          <button class="mi" onclick="toggleProxy(${s.id}, ${!s.proxy_enabled}); closeMenus()">${proxyLabel}</button>
          <button class="mi danger" onclick="deleteServer(${s.id}); closeMenus()">删除服务器</button>
        </div>
      </td>`;
    tbody.appendChild(tr);
  }
}

function toggleMenu(id) {
  closeMenus();
  const menu = $("menu-" + id);
  if (!menu) return;
  menu.classList.remove("hidden");
  const btn = $("menu-btn-" + id);
  const r = btn.getBoundingClientRect();
  const mh = menu.offsetHeight;
  const mw = menu.offsetWidth;
  const gap = 6;
  let top = r.bottom + gap;
  if (top + mh > window.innerHeight - 8) {
    top = Math.max(8, r.top - mh - gap);
  }
  let left = Math.min(r.left, window.innerWidth - mw - 8);
  left = Math.max(8, left);
  menu.style.top = top + "px";
  menu.style.left = left + "px";
}

function closeMenus() {
  document.querySelectorAll(".menu").forEach((m) => m.classList.add("hidden"));
}
document.addEventListener("click", (e) => {
  if (!e.target.closest(".menu")) closeMenus();
});
window.addEventListener("scroll", closeMenus, true);
window.addEventListener("resize", closeMenus);

function addServer() {
  const name = $("new-name").value.trim();
  $("add-msg").textContent = "";
  if (!name) return showToast("请输入服务器名称", "error");
  api("/api/servers", { method: "POST", body: { name } })
    .then((d) => {
      $("new-name").value = "";
      $("install-script").value = d.install;
      $("install-panel").classList.remove("hidden");
      $("install-panel").scrollIntoView({ behavior: "smooth" });
      showToast("服务器 " + d.server.name + " 已添加，请复制安装命令", "success");
      loadServers();
    })
    .catch((e) => ($("add-msg").textContent = e.message));
}

async function deleteServer(id) {
  const s = servers.find((x) => x.id === id);
  if (!s) return;
  const ok = await confirmDialog("删除服务器", "确定删除 " + s.name + "？删除后需重新安装 Agent 才能恢复。");
  if (!ok) return;
  api("/api/servers/" + id, { method: "DELETE" })
    .then(() => { showToast("已删除 " + s.name, "success"); loadServers(); })
    .catch((e) => showToast("删除失败: " + e.message, "error"));
}

async function toggleAdmin(id, on) {
  const s = servers.find((x) => x.id === id);
  const ok = await confirmDialog(
    on ? "启用服务器" : "停用服务器",
    (on ? "启用 " : "停用 ") + (s ? s.name : "") + "？停用后该服务器立即可达性会断开，Agent 重连会被拒绝。"
  );
  if (!ok) return;
  api("/api/servers/" + id, { method: "PUT", body: { admin_enabled: on } })
    .then(() => { showToast(on ? "已启用" : "已停用", "success"); loadServers(); })
    .catch((e) => showToast("操作失败: " + e.message, "error"));
}

async function toggleProxy(id, on) {
  const s = servers.find((x) => x.id === id);
  const ok = await confirmDialog(
    on ? "开启代理" : "关闭代理",
    (on ? "开启 " : "关闭 ") + (s ? s.name : "") + " 的代理？开启后该目标机可借用工作站网络访问外网。"
  );
  if (!ok) return;
  api("/api/servers/" + id, { method: "PUT", body: { proxy_enabled: on } })
    .then(() => { showToast(on ? "代理已开启" : "代理已关闭", "success"); loadServers(); })
    .catch((e) => showToast("操作失败: " + e.message, "error"));
}

function reconnect(id) {
  api("/api/servers/" + id + "/reconnect", { method: "POST" })
    .then(() => { showToast("已请求重连", "success"); setTimeout(loadServers, 3000); })
    .catch((e) => showToast("重连失败: " + e.message, "error"));
}

async function upgradeAgent(id) {
  const s = servers.find((x) => x.id === id);
  if (!s || !s.online) return showToast("Agent 离线，无法升级", "error");
  const ok = await confirmDialog("升级 Agent", "升级 " + s.name + " 的 Agent？升级期间会短暂离线，完成后自动重连。");
  if (!ok) return;
  try {
    const d = await api("/api/servers/" + id + "/upgrade", { method: "POST" });
    showToast(s.name + " 升级中，目标版本 " + d.version, "success");
    setTimeout(loadServers, 3000);
    setTimeout(loadServers, 6000);
  } catch (e) {
    showToast("升级失败: " + e.message, "error");
  }
}

function showInstall(id) {
  api("/api/servers/" + id + "/install").then((d) => {
    $("install-script").value = d.install;
    $("install-panel").classList.remove("hidden");
    $("install-panel").scrollIntoView({ behavior: "smooth" });
  }).catch((e) => showToast(e.message, "error"));
}

function copyInstall() {
  const ta = $("install-script");
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(ta.value).then(
      () => showToast("已复制到剪贴板", "success"),
      () => fallbackCopy(ta)
    );
  } else {
    fallbackCopy(ta);
  }
}

function fallbackCopy(ta) {
  ta.select();
  document.execCommand("copy");
  showToast("已复制到剪贴板", "success");
}

function closeInstall() {
  $("install-panel").classList.add("hidden");
}

function showLogs(id) {
  const s = servers.find((x) => x.id === id);
  $("logs-title").textContent = s ? "· " + s.name : "";
  api("/api/servers/" + id + "/logs")
    .then((d) => {
      const lines = d.logs
        .map((l) => `[${l.ts}] ${l.user ? l.user + " " : ""}${l.kind}  ${l.detail}`)
        .join("\n");
      $("logs").textContent = lines || "(暂无日志)";
      $("logs-panel").classList.remove("hidden");
      $("logs-panel").scrollIntoView({ behavior: "smooth" });
    })
    .catch((e) => showToast("加载日志失败: " + e.message, "error"));
}

function closeLogs() {
  $("logs-panel").classList.add("hidden");
}

/* ---------- 用户管理 ---------- */

function showUsersPanel() {
  $("users-panel").classList.remove("hidden");
  $("users-panel").scrollIntoView({ behavior: "smooth" });
  loadUsers();
}

function closeUsersPanel() {
  $("users-panel").classList.add("hidden");
}

function loadUsers() {
  api("/api/users").then((d) => {
    const tbody = $("users-tbody");
    tbody.innerHTML = "";
    for (const u of d.users) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong>${esc(u.username)}</strong></td>
        <td>${u.role === "admin" ? "管理员" : "成员"}</td>
        <td><span class="pill ${u.enabled ? "on" : "off"}">${u.enabled ? "启用" : "禁用"}</span></td>
        <td>${u.key_count} 把 <button class="btn" onclick="manageKeys(${u.id}, '${esc(u.username)}')">管理</button></td>
        <td class="actions-cell">
          <button class="btn" onclick="toggleUser(${u.id}, ${!u.enabled})">${u.enabled ? "禁用" : "启用"}</button>
          <button class="btn" onclick="setUserRole(${u.id}, '${u.role === "admin" ? "member" : "admin"}')">${u.role === "admin" ? "降为成员" : "设为管理员"}</button>
          <button class="btn" onclick="resetUserPass(${u.id})">重置密码</button>
          <button class="btn danger" onclick="deleteUser(${u.id}, '${esc(u.username)}')">删除</button>
        </td>`;
      tbody.appendChild(tr);
    }
  }).catch((e) => showToast("加载用户失败: " + e.message, "error"));
}

function addUser() {
  const username = $("nu-name").value.trim();
  const password = $("nu-pass").value;
  const role = $("nu-role").value;
  $("nu-msg").textContent = "";
  api("/api/users", { method: "POST", body: { username, password, role } })
    .then(() => {
      $("nu-name").value = "";
      $("nu-pass").value = "";
      showToast("用户 " + username + " 已创建", "success");
      loadUsers();
    })
    .catch((e) => ($("nu-msg").textContent = e.message));
}

function toggleUser(id, on) {
  api("/api/users/" + id, { method: "PUT", body: { enabled: on } })
    .then(() => loadUsers())
    .catch((e) => showToast(e.message, "error"));
}

function setUserRole(id, role) {
  api("/api/users/" + id, { method: "PUT", body: { role } })
    .then(() => loadUsers())
    .catch((e) => showToast(e.message, "error"));
}

function resetUserPass(id) {
  const p = prompt("输入新密码（至少 8 位）:");
  if (!p) return;
  if (p.length < 8) return showToast("密码至少 8 位", "error");
  api("/api/users/" + id, { method: "PUT", body: { password: p } })
    .then(() => showToast("密码已重置", "success"))
    .catch((e) => showToast(e.message, "error"));
}

async function deleteUser(id, name) {
  const ok = await confirmDialog("删除用户", "确定删除用户 " + name + "？其密钥将同时失效。");
  if (!ok) return;
  api("/api/users/" + id, { method: "DELETE" })
    .then(() => { showToast("用户已删除", "success"); loadUsers(); })
    .catch((e) => showToast(e.message, "error"));
}

function manageKeys(userId, username) {
  api("/api/users/" + userId + "/keys").then((d) => {
    const list = d.keys.length
      ? d.keys.map((k) => `
          <li>
            <code>${esc(k.public_key.split(" ")[0])}…</code>
            <span class="muted">${esc(k.comment || "")}</span>
            <button class="btn danger" onclick="delKey(${k.id})">删除</button>
          </li>`).join("")
      : "<li class='muted'>（暂无密钥）</li>";
    umodalData = { userId };
    umodalAction = "keys";
    $("umodal-title").textContent = "用户 " + username + " 的密钥";
    $("umodal-body").innerHTML = `
      <ul>${list}</ul>
      <textarea id="new-key" placeholder="粘贴用户的 SSH 公钥，如 ssh-ed25519 AAAA..."></textarea>
      <button class="btn" onclick="addKey(${userId})">添加密钥</button>
      <p class="hint">密钥用于 SSH 直连：ssh -p 端口 用户名@工作站，平台会自动下发给所有 Agent。</p>`;
    $("umodal-ok").classList.add("hidden");
    $("umodal").classList.remove("hidden");
  }).catch((e) => showToast(e.message, "error"));
}

function addKey(userId) {
  const pk = $("new-key").value.trim();
  if (!pk) return;
  api("/api/users/" + userId + "/keys", { method: "POST", body: { public_key: pk, comment: "" } })
    .then(() => { showToast("密钥已添加", "success"); manageKeys(userId, ""); })
    .catch((e) => showToast("添加失败: " + e.message, "error"));
}

async function delKey(keyId) {
  const ok = await confirmDialog("删除密钥", "确定删除这把密钥？删除后该密钥将无法连接任何服务器。");
  if (!ok) return;
  const uid = umodalData.userId;
  api("/api/users/" + uid + "/keys/" + keyId, { method: "DELETE" })
    .then(() => { showToast("密钥已删除", "success"); manageKeys(uid, ""); })
    .catch((e) => showToast(e.message, "error"));
}

/* ---------- 默认用户 ---------- */

function chooseDefaultUser(id) {
  api("/api/servers/" + id + "/users").then((d) => {
    const opts = d.users.map((u) => `<option value="${esc(u)}">${esc(u)}</option>`).join("");
    umodalData = { id };
    umodalAction = "default_user";
    $("umodal-title").textContent = "选择默认用户";
    $("umodal-body").innerHTML = `
      <p class="hint">会话将以该 OS 用户执行（Agent 用 sudo 切换）。列表来自目标机的真实用户。</p>
      <select id="du-select">
        <option value="">（Agent 自身用户）</option>
        ${opts}
      </select>`;
    const sel = $("du-select");
    if (d.default_user) sel.value = d.default_user;
    $("umodal-ok").classList.remove("hidden");
    $("umodal").classList.remove("hidden");
  }).catch((e) => showToast("获取用户列表失败: " + e.message, "error"));
}

function umodalOk() {
  if (umodalAction === "default_user") {
    const user = $("du-select").value;
    api("/api/servers/" + umodalData.id, { method: "PUT", body: { default_user: user } })
      .then(() => {
        umodalClose();
        showToast("默认用户已更新", "success");
        loadServers();
      })
      .catch((e) => showToast(e.message, "error"));
  }
}

function umodalClose() {
  $("umodal").classList.add("hidden");
  umodalData = null;
  umodalAction = null;
}

/* ---------- Web 终端 ---------- */

function openTerminal(id) {
  const s = servers.find((x) => x.id === id);
  if (!s) return;
  $("app").classList.add("hidden");
  $("terminal-view").classList.remove("hidden");
  $("term-title").textContent = s.name + " · 端口 " + s.port;

  term = new Terminal({ cursorBlink: true, fontSize: 13, theme: { background: "#101216" } });
  termFit = new FitAddon.FitAddon();
  term.loadAddon(termFit);
  term.open($("terminal"));
  termFit.fit();

  const inputQueue = [];
  term.onData((data) => {
    const payload = JSON.stringify({
      t: "input",
      d: btoa(unescape(encodeURIComponent(data))),
    });
    if (termWS && termWS.readyState === 1) {
      termWS.send(payload);
    } else {
      inputQueue.push(payload);
    }
  });
  term.onResize(() => sendResize());

  const proto = location.protocol === "https:" ? "wss" : "ws";
  termWS = new WebSocket(
    proto + "://" + location.host + "/ws/terminal/" + id +
    "?token=" + encodeURIComponent(localStorage.getItem(tokenKey))
  );
  termWS.binaryType = "arraybuffer";

  termWS.onopen = () => {
    while (inputQueue.length && termWS.readyState === 1) {
      termWS.send(inputQueue.shift());
    }
    sendResize();
    term.focus();
  };
  termWS.onmessage = (ev) => {
    if (typeof ev.data === "string") {
      term.write(ev.data);
    } else {
      term.write(new Uint8Array(ev.data));
    }
  };
  termWS.onclose = () => {
    term.write("\r\n[连接已关闭]\r\n[若始终无响应，请按 Ctrl+F5 强制刷新]\r\n");
    setTimeout(() => closeTerminal(), 1500);
  };
  termWS.onerror = () => {
    term.write("\r\n[连接失败]\r\n");
  };
}

function sendResize() {
  if (!termFit || !termWS || termWS.readyState !== 1) return;
  const d = termFit.proposeDimensions();
  termWS.send(JSON.stringify({ t: "resize", cols: d.cols, rows: d.rows }));
}

function closeTerminal() {
  if (termWS) {
    termWS.onclose = null;
    termWS.close();
    termWS = null;
  }
  if (term) {
    term.dispose();
    term = null;
    termFit = null;
  }
  $("terminal-view").classList.add("hidden");
  $("app").classList.remove("hidden");
}

/* ---------- 启动 ---------- */

if (!localStorage.getItem(tokenKey)) {
  showLogin();
} else {
  showApp();
}

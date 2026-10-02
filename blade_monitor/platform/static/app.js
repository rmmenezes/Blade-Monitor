/* Blade Monitor Platform — painel web (JS puro, sem dependências). */
"use strict";

const SEV = ["critical", "high", "medium", "low", "info"];
const SEV_PT = {critical: "crítica", high: "alta", medium: "média", low: "baixa", info: "info"};
const STATUS_PT = {open: "aberto", resolved: "resolvido", accepted: "risco aceito",
  false_positive: "falso positivo", queued: "na fila", running: "executando", done: "concluída",
  failed: "falhou", pending: "pendente", active: "ativo", suspended: "suspenso"};
const ROLE_PT = {admin: "Admin da plataforma", partner_admin: "Admin do parceiro",
  partner_analyst: "Analista do parceiro", org_admin: "Admin do cliente", org_viewer: "Leitor do cliente"};
const $app = document.getElementById("app");
let ME = null;

// ------------------------------------------------------------------ utilidades
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) =>
  ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));
const fmtDate = (s) => s ? new Date(s).toLocaleString("pt-BR", {dateStyle: "short", timeStyle: "short"}) : "—";
const money = (n, cur = "USD") => Number(n).toLocaleString("pt-BR", {style: "currency", currency: cur});
const pct = (x) => `${Math.round(x * 100)}%`;
const grade = (g, cls = "") => g ? `<span class="grade g-${esc(g)} ${cls}">${esc(g)}</span>` : `<span class="grade ${cls}">–</span>`;
const sev = (s) => `<span class="sev ${esc(s)}">${esc(SEV_PT[s] || s)}</span>`;
const pill = (s) => {
  const tone = {done: "ok", active: "ok", resolved: "ok", failed: "bad", open: "bad", suspended: "bad",
    pending: "warn", queued: "warn", running: "warn", accepted: "warn"}[s] || "";
  return `<span class="pill ${tone}">${esc(STATUS_PT[s] || s)}</span>`;
};
const isPartner = () => ME && ["partner_admin", "partner_analyst"].includes(ME.user.role);
const isAdmin = () => ME && ME.user.role === "admin";
const canWrite = () => ME && ME.user.role !== "org_viewer";

class ApiError extends Error { constructor(status, msg) { super(msg); this.status = status; } }

async function api(method, path, body) {
  const opts = {method, headers: {}, credentials: "same-origin"};
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  if (method !== "GET" && ME && ME.csrf) opts.headers["X-CSRF-Token"] = ME.csrf;
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(res.status, data.error || res.statusText);
  return data;
}

function toast(msg, err = false) {
  document.querySelectorAll(".toast").forEach((t) => t.remove());
  const el = document.createElement("div");
  el.className = "toast" + (err ? " err" : "");
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 4500);
}

function formData(form) {
  const out = {};
  for (const el of form.elements) {
    if (!el.name) continue;
    out[el.name] = el.type === "checkbox" ? el.checked : el.value;
  }
  return out;
}

/* Aplica estilos dinâmicos via CSSOM (a CSP bloqueia atributos style inline). */
function applyDynamic(root) {
  root.querySelectorAll("[data-w]").forEach((el) => { el.style.width = el.dataset.w + "%"; });
  root.querySelectorAll("[data-bg]").forEach((el) => { el.style.background = el.dataset.bg; });
}

/* Liga handlers declarados como data-act="nome" a funções do objeto acts. */
function bind(root, acts) {
  root.querySelectorAll("[data-act]").forEach((el) => {
    const fn = acts[el.dataset.act];
    if (!fn) return;
    const ev = el.tagName === "FORM" ? "submit" : (el.tagName === "SELECT" ? "change" : "click");
    el.addEventListener(ev, async (e) => {
      e.preventDefault();
      if (el.disabled) return;
      const btn = el.tagName === "FORM" ? el.querySelector("button[type=submit]") : el;
      if (btn) btn.disabled = true;
      try { await fn(el, e); } catch (err) { toast(err.message, true); }
      finally { if (btn && btn.isConnected) btn.disabled = false; }
    });
  });
}

// ----------------------------------------------------------------- layout
const SHIELD = `<svg width="22" height="22" viewBox="0 0 32 32" aria-hidden="true"><path d="M16 2 4 7v8c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V7z" fill="var(--accent)"/></svg>`;

function brandName() {
  if (ME && ME.brand) return ME.brand.name;
  if (ME && ME.partner) return ME.partner.brand_name || ME.partner.name;
  return "Blade Monitor";
}

function shell(content, active) {
  const nav = [];
  const link = (href, label, key) => nav.push(`<a class="nav ${active === key ? "on" : ""}" href="${href}">${label}</a>`);
  if (ME.user.org_id) {
    const o = ME.user.org_id;
    link(`#/orgs/${o}`, "Visão geral", "overview");
    link(`#/orgs/${o}/issues`, "Achados", "issues");
    link(`#/orgs/${o}/assets`, "Ativos", "assets");
    link(`#/orgs/${o}/vendors`, "Fornecedores", "vendors");
    link(`#/orgs/${o}/scans`, "Varreduras", "scans");
    if (ME.user.role === "org_admin") link(`#/orgs/${o}/settings`, "Configurações", "settings");
  } else {
    link("#/", isPartner() ? "Portfólio de clientes" : "Clientes", "home");
  }
  if (isPartner()) {
    nav.push(`<div class="sep">Programa de parceiros</div>`);
    link("#/partner", "Nível e benefícios", "partner");
    link("#/partner/prospects", "Avaliar prospects", "prospects");
    if (ME.user.role === "partner_admin") {
      link("#/partner/branding", "Marca (white-label)", "branding");
      link("#/partner/statement", "Extrato", "statement");
      link("#/partner/team", "Equipe", "team");
    }
  }
  if (isAdmin()) {
    nav.push(`<div class="sep">Administração</div>`);
    link("#/admin/partners", "Parceiros", "admin-partners");
    link("#/admin/audit", "Auditoria", "audit");
  }
  nav.push(`<div class="sep">Conta</div>`);
  link("#/keys", "Chaves de API", "keys");
  $app.innerHTML = `
    <div class="topbar"><span class="brand">${SHIELD}${esc(brandName())}</span>
      <button class="btn sm" data-act="menu">Menu</button></div>
    <div class="shell">
      <aside class="side"><div class="brand">${SHIELD}<span>${esc(brandName())}</span></div>
        ${nav.join("")}
        <div class="who"><b>${esc(ME.user.name || ME.user.email)}</b>${esc(ROLE_PT[ME.user.role])}
          ${ME.partner ? `<br>${esc(ME.partner.name)}` : ""}
          <br><a href="#" data-act="logout">Sair</a></div>
      </aside>
      <main id="main">${content}</main>
    </div>`;
  bind($app, {
    logout: async () => { await api("POST", "/api/v1/auth/logout"); ME = null; location.hash = "#/login"; },
    menu: () => $app.querySelector(".side").classList.toggle("open"),
  });
  const color = (ME.brand && ME.brand.color) || (ME.partner && ME.partner.brand_color);
  if (color) document.documentElement.style.setProperty("--accent", color);
  const main = document.getElementById("main");
  applyDynamic(main);
  return main;
}

// ----------------------------------------------------------- telas públicas
function viewLogin() {
  $app.innerHTML = `<div class="auth"><div class="brand">${SHIELD}Blade Monitor</div>
    <div class="card"><h1>Entrar</h1><p class="sub">Gestão de superfície de ataque externa</p>
    <form class="stack" data-act="login">
      <label>E-mail<input name="email" type="email" autocomplete="username" required></label>
      <label>Senha<input name="password" type="password" autocomplete="current-password" required></label>
      <button class="btn primary" type="submit">Entrar</button>
    </form></div>
    <p class="small muted">É uma consultoria? <a href="#/apply">Seja parceiro</a> ·
      Empresa? <a href="#/signup">Crie sua conta</a></p></div>`;
  bind($app, {login: async (f) => {
    await api("POST", "/api/v1/auth/login", formData(f));
    ME = await api("GET", "/api/v1/me");
    location.hash = "#/";
    route();
  }});
}

async function viewApply() {
  const prog = await api("GET", "/api/v1/program");
  const tiers = prog.tiers.map((t) => `<div class="card tier"><h3>${esc(t.label)}</h3>
    <div class="muted small">a partir de ${t.min_clients} clientes</div>
    <p><b>${pct(t.discount)}</b> de margem na revenda</p>
    <div class="small">${t.white_label ? "✔ Relatórios white-label" : "Relatórios co-branded"}<br>
    ${t.prospects_per_month === null ? "Prospects ilimitados" : `${t.prospects_per_month} avaliações de prospects/mês`}</div></div>`).join("");
  $app.innerHTML = `<div class="auth wide" id="apply"><div class="brand">${SHIELD}Blade Monitor</div>
    <h1>Programa de parceiros</h1>
    <p class="sub">Para consultorias e MSSPs: gerencie a superfície de ataque dos seus clientes em um só lugar,
    com sua marca, margem na revenda e ${pct(prog.referral_commission)} de comissão recorrente nas indicações.</p>
    <div class="tiers">${tiers}</div>
    <div class="card" id="apply-card"><h2>Candidatar-se</h2>
    <form class="stack" data-act="apply">
      <label>Consultoria<input name="company" required></label>
      <label>Site<input name="website" type="url" placeholder="https://"></label>
      <label>Seu nome<input name="name" required></label>
      <label>E-mail corporativo<input name="email" type="email" required></label>
      <label>Senha (mín. 10 caracteres)<input name="password" type="password" minlength="10" required></label>
      <button class="btn primary" type="submit">Enviar candidatura</button>
    </form></div>
    <p class="small"><a href="#/login">Voltar ao login</a></p></div>`;
  bind($app, {apply: async (f) => {
    const r = await api("POST", "/api/v1/partners/apply", formData(f));
    $app.querySelector("#apply-card").innerHTML = `<h2>Candidatura recebida</h2><p>${esc(r.message)}</p>
      <p>Você já pode <a href="#/login">entrar</a> e conhecer o painel.</p>`;
  }});
}

async function viewSignup() {
  const prog = await api("GET", "/api/v1/program");
  const ref = new URLSearchParams(location.hash.split("?")[1] || "").get("ref") || "";
  const plans = Object.entries(prog.plans).map(([k, p]) =>
    `<option value="${k}">${esc(p.label)} — ${money(p.price, prog.currency)}/mês · ${p.max_assets} ativos</option>`).join("");
  $app.innerHTML = `<div class="auth"><div class="brand">${SHIELD}Blade Monitor</div>
    <div class="card"><h1>Criar conta</h1><p class="sub">Monitore o que sua empresa expõe na internet.</p>
    <form class="stack" data-act="signup">
      <label>Empresa<input name="company" required></label>
      <label>Seu nome<input name="name" required></label>
      <label>E-mail<input name="email" type="email" required></label>
      <label>Senha (mín. 10 caracteres)<input name="password" type="password" minlength="10" required></label>
      <label>Plano<select name="plan">${plans}</select></label>
      <label>Código de indicação (opcional)<input name="referral_code" value="${esc(ref)}"></label>
      <button class="btn primary" type="submit">Criar conta</button>
    </form></div><p class="small"><a href="#/login">Já tenho conta</a></p></div>`;
  bind($app, {signup: async (f) => {
    const d = formData(f);
    await api("POST", "/api/v1/signup", d);
    await api("POST", "/api/v1/auth/login", {email: d.email, password: d.password});
    ME = await api("GET", "/api/v1/me");
    location.hash = "#/";
  }});
}

// ------------------------------------------------------------- portfólio
async function viewHome() {
  if (ME.user.org_id) { location.hash = `#/orgs/${ME.user.org_id}`; return; }
  const orgs = await api("GET", "/api/v1/orgs");
  const scored = orgs.filter((o) => o.last_scan);
  const avg = scored.length ? Math.round(scored.reduce((a, o) => a + o.last_scan.score, 0) / scored.length) : null;
  const crit = orgs.reduce((a, o) => a + o.open_issues.critical, 0);
  const high = orgs.reduce((a, o) => a + o.open_issues.high, 0);
  const pending = ME.partner && ME.partner.status !== "active";
  const rows = orgs.map((o) => `<tr class="click" data-href="#/orgs/${o.id}">
      <td>${grade(o.last_scan && o.last_scan.grade)}</td>
      <td><b>${esc(o.name)}</b><div class="small muted">${esc(o.plan_info.label)}${o.status !== "active" ? " · " + pill(o.status) : ""}</div></td>
      <td class="num">${o.last_scan ? o.last_scan.score : "—"}</td>
      <td><div class="counts small">${SEV.slice(0, 3).map((s) => `<span class="sev ${s}">${o.open_issues[s]}</span>`).join("")}</div></td>
      <td class="num">${o.assets.verified}/${o.assets.total}</td>
      <td class="small">${o.last_scan ? fmtDate(o.last_scan.finished_at) : "nunca"}</td></tr>`).join("");
  const main = shell(`
    <div class="spread"><div><h1>${isPartner() ? "Portfólio de clientes" : "Clientes"}</h1>
      <p class="sub">Postura de exposição externa de todos os clientes gerenciados.</p></div>
      ${canWrite() && !pending ? `<button class="btn primary" data-act="new">Novo cliente</button>` : ""}</div>
    ${pending ? `<div class="callout warn"><b>Conta de parceiro em análise.</b> Assim que aprovada você poderá cadastrar clientes e avaliar prospects.</div>` : ""}
    <div id="new-org"></div>
    <div class="kpis">
      <div class="kpi"><b>${orgs.length}</b><span>clientes</span></div>
      <div class="kpi"><b>${avg ?? "—"}</b><span>nota média</span></div>
      <div class="kpi"><b class="sev critical">${crit}</b><span>achados críticos abertos</span></div>
      <div class="kpi"><b class="sev high">${high}</b><span>achados altos abertos</span></div>
    </div>
    <div class="table-wrap"><table><thead><tr><th>Nota</th><th>Cliente</th><th class="num">Score</th>
      <th>Abertos (crít/alto/méd)</th><th class="num">Ativos verif.</th><th>Última varredura</th></tr></thead>
      <tbody>${rows || `<tr><td colspan="6" class="empty">Nenhum cliente ainda.</td></tr>`}</tbody></table></div>`, "home");
  main.querySelectorAll("tr[data-href]").forEach((tr) => tr.addEventListener("click", () => { location.hash = tr.dataset.href; }));
  bind(main, {new: async () => {
    const prog = await api("GET", "/api/v1/program");
    const box = main.querySelector("#new-org");
    box.innerHTML = `<div class="card"><h3>Novo cliente</h3><form class="inline" data-act="create">
      <label>Nome<input name="name" required></label>
      <label>Plano<select name="plan">${Object.entries(prog.plans).map(([k, p]) => `<option value="${k}">${esc(p.label)} (${money(p.price)})</option>`).join("")}</select></label>
      <label>E-mail do admin do cliente (opcional)<input name="admin_email" type="email"></label>
      <label>Senha inicial<input name="admin_password" type="password" minlength="10"></label>
      <button class="btn primary" type="submit">Criar</button></form></div>`;
    bind(box, {create: async (f) => {
      const d = formData(f);
      if (!d.admin_email) { delete d.admin_email; delete d.admin_password; }
      const org = await api("POST", "/api/v1/orgs", d);
      toast("Cliente criado. Cadastre e verifique os ativos.");
      location.hash = `#/orgs/${org.id}/assets`;
    }});
  }});
}

// ------------------------------------------------------------ organização
function orgHeader(org, tab) {
  const t = (key, label) => `<a class="${tab === key ? "on" : ""}" href="#/orgs/${org.id}${key === "overview" ? "" : "/" + key}">${label}</a>`;
  const back = ME.user.org_id ? "" : `<a class="small" href="#/">← Portfólio</a>`;
  return `${back}<div class="spread"><div><h1>${esc(org.name)}</h1>
    <p class="sub">${esc(org.plan_info.label)} · varredura a cada ${org.plan_info.scan_every_hours}h ·
    ${org.assets.verified}/${org.assets.total} ativos verificados</p></div>
    ${canWrite() ? `<button class="btn primary" data-act="scan">Varrer agora</button>` : ""}</div>
    ${ME.user.org_id ? "" : `<nav class="tabs">${t("overview", "Visão geral")}${t("issues", "Achados")}${t("assets", "Ativos")}${t("vendors", "Fornecedores")}${t("scans", "Varreduras")}${t("settings", "Configurações")}</nav>`}`;
}

const orgActs = (org) => ({
  scan: async () => {
    const r = await api("POST", `/api/v1/orgs/${org.id}/scans`);
    toast(`Varredura #${r.scan_id} enfileirada.`);
    location.hash = `#/orgs/${org.id}/scans`;
  },
});

function trendChart(history) {
  if (history.length < 2) return `<p class="muted small">A tendência aparece após duas varreduras.</p>`;
  const W = 600, H = 180, P = 28;
  const x = (i) => P + (i * (W - 2 * P)) / (history.length - 1);
  const lo = Math.max(0, Math.floor((Math.min(...history.map((h) => h.score)) - 10) / 10) * 10);
  const y = (s) => H - P - ((s - lo) / (100 - lo)) * (H - 2 * P);
  const pts = history.map((h, i) => `${x(i).toFixed(1)},${y(h.score).toFixed(1)}`).join(" ");
  const grid = [60, 70, 80, 90, 100].filter((g) => g >= lo).map((g) => `<line class="gridline" x1="${P}" x2="${W - P}" y1="${y(g)}" y2="${y(g)}"/>
    <text x="4" y="${y(g) + 4}">${g}</text>`).join("");
  const dots = history.map((h, i) => `<circle class="dot" cx="${x(i)}" cy="${y(h.score)}" r="3.5"><title>${esc(fmtDate(h.finished_at))}: ${h.score} (${h.grade})</title></circle>`).join("");
  return `<svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="Evolução da nota">${grid}<polyline class="line" points="${pts}"/>${dots}</svg>`;
}

function categoryBars(cats) {
  return `<div class="bars">${Object.values(cats).map((c) => `<div class="bar">
    <span>${esc(c.label)}</span><div class="track"><div class="fill g-${c.grade}" data-w="${c.score}"></div></div>
    <span class="num">${grade(c.grade)}</span></div>`).join("")}</div>`;
}

async function viewOrgOverview(id) {
  const [org, history] = await Promise.all([api("GET", `/api/v1/orgs/${id}`), api("GET", `/api/v1/orgs/${id}/history`)]);
  const last = org.last_scan;
  let body;
  if (!last) {
    body = `<div class="callout ${org.assets.verified ? "" : "warn"}">
      ${org.assets.verified ? "Nenhuma varredura concluída ainda. Clique em <b>Varrer agora</b>."
        : `Cadastre os domínios/IPs e <a href="#/orgs/${id}/assets">verifique a posse</a> para iniciar o monitoramento.`}</div>`;
  } else {
    const detail = await api("GET", `/api/v1/scans/${last.id}`);
    const ch = detail.changes || {};
    const changeList = [
      ["Novos hosts", ch.new_hosts], ["Novos serviços", ch.new_services],
      ["Serviços fechados", ch.closed_services], ["Hosts removidos", ch.removed_hosts],
    ].filter(([, v]) => v && v.length).map(([l, v]) => `<p><b>${l}:</b> ${v.slice(0, 15).map((x) => `<code>${esc(x)}</code>`).join(" ")}</p>`).join("");
    const newF = (ch.new_findings || []).slice(0, 8).map((f) => `<li>${sev(f.severity)} <code>${esc(f.asset)}</code> ${esc(f.title)}</li>`).join("");
    body = `<div class="grid">
      <div class="card"><div class="hero">${grade(last.grade, "xl")}<div>
        <div class="muted small">Nota de segurança</div><div class="kpi-big"><b>${last.score}</b>/100</div>
        <div class="small muted">${fmtDate(last.finished_at)}</div>
        <p><a class="btn sm" href="/reports/scan/${last.id}" target="_blank" rel="noopener">Relatório executivo</a></p></div></div></div>
      <div class="card"><h3>Notas por categoria</h3>${categoryBars(detail.categories)}</div></div>
    <div class="kpis">${SEV.slice(0, 4).map((s) => `<a class="kpi" href="#/orgs/${id}/issues"><b class="sev ${s}">${org.open_issues[s]}</b><span>${{critical: "críticos", high: "altos", medium: "médios", low: "baixos"}[s]} abertos</span></a>`).join("")}
      <div class="kpi"><b>${last.hosts}</b><span>hosts expostos</span></div>
      <div class="kpi"><b>${last.services}</b><span>serviços</span></div></div>
    <div class="grid"><div class="card"><h3>Evolução da nota</h3>${trendChart(history)}</div>
      <div class="card"><h3>Mudanças na última varredura</h3>${changeList || ""}
        ${newF ? `<p><b>Novos achados:</b></p><ul>${newF}</ul>` : ""}
        ${!changeList && !newF ? `<p class="muted">Nenhuma mudança relevante.</p>` : ""}</div></div>`;
  }
  const main = shell(orgHeader(org, "overview") + body, "overview");
  bind(main, orgActs(org));
}

async function viewIssues(id) {
  const status = new URLSearchParams(location.hash.split("?")[1] || "").get("status") || "open";
  const [org, issues] = await Promise.all([api("GET", `/api/v1/orgs/${id}`), api("GET", `/api/v1/orgs/${id}/issues?status=${status}`)]);
  const opts = ["open", "accepted", "false_positive", "resolved", "all"].map((s) =>
    `<option value="${s}" ${s === status ? "selected" : ""}>${s === "all" ? "todos" : STATUS_PT[s]}</option>`).join("");
  const rows = issues.map((i) => `<tr><td>${sev(i.severity)}</td><td><code>${esc(i.asset)}</code></td>
    <td><b>${esc(i.title)}</b><div class="small muted">${esc(i.detail)}</div>
      ${i.note ? `<div class="small">📝 ${esc(i.note)}</div>` : ""}</td>
    <td class="small">${fmtDate(i.first_seen)}<br><span class="muted">visto ${fmtDate(i.last_seen)}</span></td>
    <td>${pill(i.status)}</td>
    <td>${canWrite() ? (i.status === "open"
      ? `<div class="row"><button class="btn sm" data-act="accept" data-id="${i.id}">Aceitar risco</button>
         <button class="btn sm" data-act="fp" data-id="${i.id}">Falso positivo</button></div>`
      : (["accepted", "false_positive"].includes(i.status) ? `<button class="btn sm" data-act="reopen" data-id="${i.id}">Reabrir</button>` : "")) : ""}</td></tr>`).join("");
  const main = shell(orgHeader(org, "issues") + `
    <div class="row"><label>Status<select data-act="filter">${opts}</select></label>
      <span class="muted small">${issues.length} achado(s). Achados somem sozinhos quando corrigidos (detectado na próxima varredura).</span></div>
    <div class="table-wrap"><table><thead><tr><th>Severidade</th><th>Ativo</th><th>Achado</th><th>Detectado</th><th>Status</th><th></th></tr></thead>
    <tbody>${rows || `<tr><td colspan="6" class="empty">Nenhum achado neste filtro. 🎉</td></tr>`}</tbody></table></div>`, "issues");
  const setStatus = async (el, st) => {
    let note = "";
    if (st !== "open") {
      note = prompt(st === "accepted" ? "Justificativa para aceitar o risco:" : "Por que é falso positivo?") || "";
      if (!note.trim()) return;
    }
    await api("PATCH", `/api/v1/issues/${el.dataset.id}`, {status: st, note});
    toast("Achado atualizado.");
    route();
  };
  bind(main, {...orgActs(org),
    filter: (el) => { location.hash = `#/orgs/${id}/issues?status=${el.value}`; },
    accept: (el) => setStatus(el, "accepted"),
    fp: (el) => setStatus(el, "false_positive"),
    reopen: (el) => setStatus(el, "open")});
}

async function viewAssets(id) {
  const [org, assets] = await Promise.all([api("GET", `/api/v1/orgs/${id}`), api("GET", `/api/v1/orgs/${id}/assets`)]);
  const rows = assets.map((a) => {
    let how = "";
    if (!a.verified_at && a.instructions) {
      how = `<details class="small"><summary>Como verificar</summary>
        <p><b>Opção 1 — DNS TXT</b><br>Nome: <code>${esc(a.instructions.dns.name)}</code><br>
        Valor: <code>${esc(a.instructions.dns.value)}</code></p>
        <p><b>Opção 2 — arquivo HTTP</b><br>URL: <code>${esc(a.instructions.http.url)}</code><br>
        Conteúdo: <code>${esc(a.instructions.http.content)}</code></p></details>`;
    } else if (!a.verified_at) {
      how = `<div class="small muted">IPs/redes exigem atestado de autorização (contrato ou carta).</div>`;
    }
    const status = a.verified_at ? `<span class="pill ok">verificado (${esc(a.verified_method)})</span>`
      : `<span class="pill warn">aguardando verificação</span>`;
    const actions = !canWrite() ? "" : `<div class="row">
      ${!a.verified_at && a.kind === "domain" ? `<button class="btn sm primary" data-act="verify" data-id="${a.id}">Verificar</button>` : ""}
      ${!a.verified_at && a.kind !== "domain" && ["admin", "partner_admin", "org_admin"].includes(ME.user.role) ? `<button class="btn sm primary" data-act="attest" data-id="${a.id}">Atestar</button>` : ""}
      <button class="btn sm danger" data-act="del" data-id="${a.id}">Remover</button></div>`;
    return `<tr><td>${esc(a.kind)}</td><td><code>${esc(a.value)}</code>${how}
      ${a.attestation_note ? `<div class="small muted">Atestado: ${esc(a.attestation_note)}</div>` : ""}</td>
      <td>${status}</td><td>${actions}</td></tr>`;
  }).join("");
  const main = shell(orgHeader(org, "assets") + `
    <div class="callout">Varreduras ativas só rodam em ativos com <b>posse verificada</b>. Subdomínios são descobertos
    automaticamente via Certificate Transparency a partir dos domínios-raiz.</div>
    ${canWrite() ? `<form class="inline card" data-act="add">
      <label>Tipo<select name="kind"><option value="domain">Domínio</option><option value="ip">IP</option><option value="cidr">Rede (CIDR)</option></select></label>
      <label>Valor<input name="value" placeholder="empresa.com.br" required></label>
      <button class="btn primary" type="submit">Adicionar</button>
      <span class="small muted">${assets.length}/${org.plan_info.max_assets} no plano</span></form>` : ""}
    <h2>Ativos-raiz</h2>
    <div class="table-wrap"><table><thead><tr><th>Tipo</th><th>Ativo</th><th>Status</th><th></th></tr></thead>
    <tbody>${rows || `<tr><td colspan="4" class="empty">Nenhum ativo cadastrado.</td></tr>`}</tbody></table></div>`, "assets");
  bind(main, {...orgActs(org),
    add: async (f) => { await api("POST", `/api/v1/orgs/${id}/assets`, formData(f)); toast("Ativo adicionado."); route(); },
    verify: async (el) => {
      const r = await api("POST", `/api/v1/assets/${el.dataset.id}/verify`);
      toast(r.verified ? `Posse verificada via ${r.method}.` : "Registro não encontrado ainda (a propagação de DNS pode levar alguns minutos).", !r.verified);
      route();
    },
    attest: async (el) => {
      const note = prompt("Referência da autorização (nº do contrato, carta, escopo):");
      if (!note || !note.trim()) return;
      await api("POST", `/api/v1/assets/${el.dataset.id}/attest`, {note});
      toast("Atestado registrado na auditoria."); route();
    },
    del: async (el) => {
      if (!confirm("Remover este ativo do monitoramento?")) return;
      await api("DELETE", `/api/v1/assets/${el.dataset.id}`); route();
    }});
}

function watchTable(rows, removable) {
  return `<div class="table-wrap"><table><thead><tr><th>Nota</th><th>Nome</th><th>Domínio</th><th>Última avaliação</th><th></th></tr></thead><tbody>
    ${rows.map((w) => `<tr><td>${grade(w.grade)}</td><td><b>${esc(w.name)}</b>${w.criticality && w.kind === "vendor" ? `<div class="small muted">criticidade ${esc(SEV_PT[w.criticality])}</div>` : ""}</td>
      <td><code>${esc(w.domain)}</code></td>
      <td class="small">${w.scan_status === "done" ? fmtDate(w.finished_at) + ` · ${w.score}/100` : pill(w.scan_status || "pending")}</td>
      <td><div class="row">${w.scan_status === "done" ? `<a class="btn sm" href="/reports/scan/${w.scan_id}" target="_blank" rel="noopener">Relatório</a>` : ""}
        ${canWrite() ? `<button class="btn sm" data-act="rescan" data-id="${w.id}">Reavaliar</button>` : ""}
        ${removable && canWrite() ? `<button class="btn sm danger" data-act="rm" data-id="${w.id}">Remover</button>` : ""}</div></td></tr>`).join("")
      || `<tr><td colspan="5" class="empty">Nada cadastrado ainda.</td></tr>`}</tbody></table></div>`;
}

const watchActs = {
  rescan: async (el) => { await api("POST", `/api/v1/watch/${el.dataset.id}/scan`); toast("Avaliação enfileirada."); route(); },
  rm: async (el) => { if (confirm("Remover?")) { await api("DELETE", `/api/v1/watch/${el.dataset.id}`); route(); } },
};

async function viewVendors(id) {
  const [org, vendors] = await Promise.all([api("GET", `/api/v1/orgs/${id}`), api("GET", `/api/v1/orgs/${id}/vendors`)]);
  const main = shell(orgHeader(org, "vendors") + `
    <p class="sub">Risco de terceiros: avaliação <b>passiva</b> (Certificate Transparency, DNS e uma visita HTTP/HTTPS por host —
    o mesmo que um navegador). Não exige autorização do fornecedor e não faz varredura de portas.</p>
    ${canWrite() ? `<form class="inline card" data-act="add">
      <label>Fornecedor<input name="name" required></label>
      <label>Domínio<input name="domain" placeholder="fornecedor.com" required></label>
      <label>Criticidade<select name="criticality"><option value="low">baixa</option><option value="medium" selected>média</option><option value="high">alta</option><option value="critical">crítica</option></select></label>
      <button class="btn primary" type="submit">Monitorar</button>
      <span class="small muted">${vendors.length}/${org.plan_info.vendors} no plano</span></form>` : ""}
    <h2>Fornecedores monitorados</h2>${watchTable(vendors, true)}`, "vendors");
  bind(main, {...orgActs(org), ...watchActs,
    add: async (f) => { await api("POST", `/api/v1/orgs/${id}/vendors`, formData(f)); toast("Fornecedor adicionado; avaliação enfileirada."); route(); }});
}

async function viewScans(id) {
  const [org, scans] = await Promise.all([api("GET", `/api/v1/orgs/${id}`), api("GET", `/api/v1/orgs/${id}/scans`)]);
  const rows = scans.map((s) => `<tr class="${s.status === "done" ? "click" : ""}" data-href="#/scans/${s.id}">
    <td>#${s.id}</td><td>${pill(s.status)}${s.error ? `<div class="small muted">${esc(s.error)}</div>` : ""}</td>
    <td>${grade(s.grade)} ${s.score ?? ""}</td><td class="num">${s.hosts ?? "—"}</td><td class="num">${s.services ?? "—"}</td>
    <td class="num">${s.findings ?? "—"}</td><td class="small">${esc(s.trigger)}</td><td class="small">${fmtDate(s.finished_at || s.queued_at)}</td></tr>`).join("");
  const main = shell(orgHeader(org, "scans") + `
    <div class="table-wrap"><table><thead><tr><th>ID</th><th>Status</th><th>Nota</th><th class="num">Hosts</th><th class="num">Serviços</th>
    <th class="num">Achados</th><th>Origem</th><th>Quando</th></tr></thead>
    <tbody>${rows || `<tr><td colspan="8" class="empty">Nenhuma varredura.</td></tr>`}</tbody></table></div>`, "scans");
  main.querySelectorAll("tr.click").forEach((tr) => tr.addEventListener("click", () => { location.hash = tr.dataset.href; }));
  bind(main, orgActs(org));
  if (scans.some((s) => ["queued", "running"].includes(s.status))) {
    const h = location.hash;
    setTimeout(() => { if (location.hash === h) route(); }, 5000);
  }
}

async function viewScan(id) {
  const s = await api("GET", `/api/v1/scans/${id}`);
  const data = s.data || {services: [], hosts: {}};
  const services = data.services.map((v) => `<tr><td>${esc(v.host)}</td><td class="mono">${esc(v.ip)}</td><td class="num">${v.port}</td>
    <td class="small">${v.tls ? esc(v.tls.protocol) + (v.tls.days_left !== null ? ` · ${v.tls.days_left}d` : "") : ""}</td>
    <td class="small">${v.http && v.http.status ? `${v.http.status} ${esc(v.http.title)}` : ""}</td>
    <td class="small mono">${esc(v.banner)}</td></tr>`).join("");
  const back = s.org_id ? `#/orgs/${s.org_id}/scans` : (ME.user.org_id ? `#/orgs/${ME.user.org_id}/vendors` : "#/partner/prospects");
  shell(`<a class="small" href="${back}">← Voltar</a>
    <div class="spread"><div><h1>Varredura #${s.id}</h1><p class="sub">${esc(s.mode === "active" ? "ativa" : "passiva")} · ${fmtDate(s.finished_at)}</p></div>
    ${s.status === "done" ? `<a class="btn" href="/reports/scan/${s.id}" target="_blank" rel="noopener">Relatório executivo</a>` : ""}</div>
    <div class="grid"><div class="card"><div class="hero">${grade(s.grade, "xl")}<div><b>${s.score ?? "—"}</b>/100<br>
      <span class="muted small">${s.hosts} hosts · ${s.services} serviços · ${s.findings} achados</span></div></div></div>
      ${s.categories ? `<div class="card"><h3>Categorias</h3>${categoryBars(s.categories)}</div>` : ""}</div>
    <h2>Inventário de serviços</h2>
    <div class="table-wrap"><table><thead><tr><th>Host</th><th>IP</th><th class="num">Porta</th><th>TLS</th><th>HTTP</th><th>Banner</th></tr></thead>
    <tbody>${services || `<tr><td colspan="6" class="empty">Nenhum serviço exposto.</td></tr>`}</tbody></table></div>`, "scans");
}

async function viewSettings(id) {
  const org = await api("GET", `/api/v1/orgs/${id}`);
  const users = ["admin", "partner_admin", "org_admin"].includes(ME.user.role)
    ? (await api("GET", "/api/v1/users")).filter((u) => u.org_id === org.id) : [];
  const prog = await api("GET", "/api/v1/program");
  const managerial = ["admin", "partner_admin"].includes(ME.user.role);
  const main = shell(orgHeader(org, "settings") + `<div class="grid">
    <div class="card"><h3>Monitoramento e alertas</h3>
    <form class="stack" data-act="save">
      <label>Nome<input name="name" value="${esc(org.name)}" required></label>
      ${managerial ? `<label>Plano<select name="plan">${Object.entries(prog.plans).map(([k, p]) => `<option value="${k}" ${k === org.plan ? "selected" : ""}>${esc(p.label)}</option>`).join("")}</select></label>
      <label>Status<select name="status"><option value="active">ativo</option><option value="suspended" ${org.status === "suspended" ? "selected" : ""}>suspenso</option></select></label>` : ""}
      <label>Excluir do monitoramento (glob, um por linha)<textarea name="exclude" placeholder="*.dev.empresa.com">${esc(org.exclude)}</textarea></label>
      <label>Webhook de alertas (Slack/Teams/Mattermost)<input name="webhook_url" type="url" value="${esc(org.webhook_url)}" placeholder="https://hooks.slack.com/..."></label>
      <label>Severidade mínima para alertar<select name="alert_min_severity">${SEV.map((s) => `<option value="${s}" ${s === org.alert_min_severity ? "selected" : ""}>${SEV_PT[s]}</option>`).join("")}</select></label>
      ${canWrite() ? `<button class="btn primary" type="submit">Salvar</button>` : ""}
    </form></div>
    ${users.length || ["admin", "partner_admin", "org_admin"].includes(ME.user.role) ? `<div class="card"><h3>Usuários do cliente</h3>
      ${users.map((u) => `<div class="spread small"><span>${esc(u.email)} · ${esc(ROLE_PT[u.role])}${u.active ? "" : " (inativo)"}</span>
        ${u.active && u.id !== ME.user.id ? `<button class="btn sm danger" data-act="deact" data-id="${u.id}">Desativar</button>` : ""}</div>`).join("") || `<p class="muted small">Nenhum usuário.</p>`}
      <h3 class="mt">Convidar</h3><form class="stack" data-act="adduser">
        <label>E-mail<input name="email" type="email" required></label>
        <label>Nome<input name="name"></label>
        <label>Senha inicial<input name="password" type="password" minlength="10" required></label>
        <label>Papel<select name="role"><option value="org_viewer">Leitor</option><option value="org_admin">Admin</option></select></label>
        <button class="btn" type="submit">Criar usuário</button></form></div>` : ""}</div>`, "settings");
  bind(main, {...orgActs(org),
    save: async (f) => { await api("PATCH", `/api/v1/orgs/${id}`, formData(f)); toast("Configurações salvas."); route(); },
    adduser: async (f) => { await api("POST", "/api/v1/users", {...formData(f), org_id: org.id}); toast("Usuário criado."); route(); },
    deact: async (el) => { if (confirm("Desativar usuário?")) { await api("DELETE", `/api/v1/users/${el.dataset.id}`); route(); } }});
}

// -------------------------------------------------------------- parceiro
async function viewPartner() {
  const p = await api("GET", "/api/v1/partner");
  const t = p.tier;
  const link = `${location.origin}/#/signup?ref=${encodeURIComponent(p.referral_code)}`;
  const tiers = p.program.tiers.map((x) => `<div class="card tier ${x.tier === t.tier ? "on" : ""}"><h3>${esc(x.label)}</h3>
    <div class="small muted">${x.min_clients}+ clientes</div><p><b>${pct(x.discount)}</b> de margem</p>
    <div class="small">${x.white_label ? "✔ White-label" : "Co-branded"}<br>${x.prospects_per_month === null ? "Prospects ilimitados" : x.prospects_per_month + " prospects/mês"}</div></div>`).join("");
  const progress = t.next_tier ? Math.round(100 * t.managed_clients / (t.managed_clients + t.next_tier.clients_needed)) : 100;
  shell(`<h1>Programa de parceiros</h1><p class="sub">${esc(p.name)} · ${pill(p.status)}</p>
    <div class="grid"><div class="card"><div class="muted small">Seu nível</div><h1>${esc(t.label)}</h1>
      <p>${t.managed_clients} clientes gerenciados · <b>${pct(t.discount)}</b> de desconto no atacado</p>
      ${t.next_tier ? `<div class="progress"><div data-w="${progress}"></div></div>
      <p class="small muted">Faltam ${t.next_tier.clients_needed} cliente(s) para ${esc(t.next_tier.label)}.</p>` : `<p class="small muted">Nível máximo.</p>`}</div>
    <div class="card"><h3>Indicação</h3><p class="small">Clientes que contratarem direto com seu código geram
      <b>${pct(p.program.referral_commission)}</b> de comissão recorrente.</p>
      <p>Código: <code>${esc(p.referral_code)}</code></p><p class="small">Link: <code>${esc(link)}</code></p></div></div>
    <h2>Níveis</h2><div class="tiers">${tiers}</div>
    <h2>Como funciona</h2><div class="grid">
      <div class="card"><h3>1. Revenda gerenciada</h3><p class="small muted">Cadastre clientes no portfólio, gerencie ativos, achados e relatórios. Você paga o atacado e define o preço final.</p></div>
      <div class="card"><h3>2. Pré-venda com prospects</h3><p class="small muted">Gere uma avaliação passiva de qualquer domínio e use o relatório com sua marca na abordagem comercial.</p></div>
      <div class="card"><h3>3. Serviços de remediação</h3><p class="small muted">Cada achado aberto é uma oportunidade de serviço: correção, hardening e pentest.</p></div></div>`, "partner");
}

async function viewBranding() {
  const p = await api("GET", "/api/v1/partner");
  const main = shell(`<h1>Marca nos relatórios</h1><p class="sub">Relatórios e painel dos seus clientes exibem sua marca.
    ${p.tier.white_label ? "Seu nível permite white-label completo." : "White-label completo a partir do nível Silver."}</p>
    <div class="grid"><div class="card"><form class="stack" data-act="save">
      <label>Nome exibido<input name="brand_name" value="${esc(p.brand_name)}"></label>
      <label>Cor principal<div class="row"><input name="brand_color" value="${esc(p.brand_color)}" pattern="#[0-9a-fA-F]{6}"><span class="swatch" data-bg="${esc(p.brand_color)}"></span></div></label>
      <label>URL do logo (https)<input name="logo_url" type="url" value="${esc(p.logo_url)}"></label>
      <label>E-mail de suporte<input name="support_email" type="email" value="${esc(p.support_email)}"></label>
      <label class="row"><input type="checkbox" name="white_label" ${p.white_label ? "checked" : ""} ${p.tier.white_label ? "" : "disabled"}> Ocultar “Blade Monitor” (white-label)</label>
      <button class="btn primary" type="submit">Salvar</button></form></div></div>`, "branding");
  bind(main, {save: async (f) => {
    const d = formData(f);
    if (!p.tier.white_label) delete d.white_label;
    await api("PATCH", "/api/v1/partner", d);
    ME = await api("GET", "/api/v1/me");
    toast("Marca atualizada."); route();
  }});
}

async function viewStatement() {
  const month = new URLSearchParams(location.hash.split("?")[1] || "").get("month") || new Date().toISOString().slice(0, 7);
  const s = await api("GET", `/api/v1/partner/statement?month=${month}`);
  const c = s.currency;
  const managed = s.managed.map((m) => `<tr><td>${esc(m.org)}</td><td>${esc(m.plan)}</td><td class="num">${money(m.list_price, c)}</td>
    <td class="num">${money(m.wholesale, c)}</td><td class="num">${money(m.margin, c)}</td></tr>`).join("");
  const refs = s.referrals.map((r) => `<tr><td>${esc(r.org)}</td><td>${esc(r.plan)}</td><td class="num">${money(r.list_price, c)}</td>
    <td class="num">${money(r.commission, c)}</td></tr>`).join("");
  const main = shell(`<h1>Extrato do parceiro</h1>
    <form class="inline" data-act="month"><label>Mês<input type="month" name="month" value="${esc(s.month)}"></label><button class="btn" type="submit">Ver</button></form>
    <div class="kpis"><div class="kpi"><b>${money(s.totals.wholesale_due, c)}</b><span>atacado a pagar</span></div>
      <div class="kpi"><b>${money(s.totals.resale_margin, c)}</b><span>margem de revenda (preço de lista)</span></div>
      <div class="kpi"><b>${money(s.totals.referral_commission, c)}</b><span>comissões de indicação</span></div>
      <div class="kpi"><b>${money(s.totals.net_payable, c)}</b><span>líquido a pagar</span></div></div>
    <p class="small muted">Nível ${esc(s.tier.label)} · desconto ${pct(s.tier.discount)}</p>
    <h2>Clientes gerenciados</h2><div class="table-wrap"><table><thead><tr><th>Cliente</th><th>Plano</th><th class="num">Lista</th><th class="num">Atacado</th><th class="num">Margem</th></tr></thead>
    <tbody>${managed || `<tr><td colspan="5" class="empty">Sem clientes no período.</td></tr>`}</tbody></table></div>
    <h2>Indicações</h2><div class="table-wrap"><table><thead><tr><th>Cliente</th><th>Plano</th><th class="num">Lista</th><th class="num">Comissão</th></tr></thead>
    <tbody>${refs || `<tr><td colspan="4" class="empty">Sem indicações ativas.</td></tr>`}</tbody></table></div>`, "statement");
  bind(main, {month: (f) => { location.hash = `#/partner/statement?month=${formData(f).month}`; }});
}

async function viewTeam() {
  const users = (await api("GET", "/api/v1/users")).filter((u) => u.partner_id);
  const main = shell(`<h1>Equipe</h1><p class="sub">Analistas acessam todos os clientes do portfólio; admins também gerenciam marca, extrato e equipe.</p>
    <div class="grid"><div class="card">${users.map((u) => `<div class="spread small"><span>${esc(u.name || u.email)} · ${esc(u.email)} · ${esc(ROLE_PT[u.role])}${u.active ? "" : " (inativo)"}</span>
      ${u.active && u.id !== ME.user.id ? `<button class="btn sm danger" data-act="deact" data-id="${u.id}">Desativar</button>` : ""}</div>`).join("")}</div>
    <div class="card"><h3>Adicionar</h3><form class="stack" data-act="add">
      <label>E-mail<input name="email" type="email" required></label><label>Nome<input name="name"></label>
      <label>Senha inicial<input name="password" type="password" minlength="10" required></label>
      <label>Papel<select name="role"><option value="partner_analyst">Analista</option><option value="partner_admin">Admin</option></select></label>
      <button class="btn primary" type="submit">Criar</button></form></div></div>`, "team");
  bind(main, {
    add: async (f) => { await api("POST", "/api/v1/users", formData(f)); toast("Usuário criado."); route(); },
    deact: async (el) => { if (confirm("Desativar usuário?")) { await api("DELETE", `/api/v1/users/${el.dataset.id}`); route(); } }});
}

async function viewProspects() {
  const rows = await api("GET", "/api/v1/partner/prospects");
  const quota = ME.partner.tier.prospects_per_month;
  const main = shell(`<h1>Avaliar prospects</h1>
    <p class="sub">Avaliação passiva (sem varredura de portas) de qualquer empresa, com relatório na sua marca para a abordagem comercial.
    Cota: ${quota === null ? "ilimitada" : `${quota}/mês`}.</p>
    ${ME.partner.status === "active" ? `<form class="inline card" data-act="add">
      <label>Empresa<input name="name" required></label><label>Domínio<input name="domain" placeholder="prospect.com.br" required></label>
      <button class="btn primary" type="submit">Avaliar</button></form>`
      : `<div class="callout warn">Disponível após a aprovação da sua conta de parceiro.</div>`}
    <h2>Avaliações</h2>${watchTable(rows, true)}`, "prospects");
  bind(main, {...watchActs, add: async (f) => { await api("POST", "/api/v1/partner/prospects", formData(f)); toast("Avaliação enfileirada."); route(); }});
  if (rows.some((r) => ["queued", "running"].includes(r.scan_status))) {
    const h = location.hash;
    setTimeout(() => { if (location.hash === h) route(); }, 5000);
  }
}

// --------------------------------------------------------------- admin
async function viewAdminPartners() {
  const list = await api("GET", "/api/v1/admin/partners");
  const tiers = ["", "registered", "silver", "gold", "platinum"];
  const main = shell(`<h1>Parceiros</h1><p class="sub">Aprovação de candidaturas e níveis negociados.</p>
    <div class="table-wrap"><table><thead><tr><th>Parceiro</th><th>Status</th><th>Nível</th><th class="num">Clientes</th><th>Desde</th><th></th></tr></thead><tbody>
    ${list.map((p) => `<tr><td><b>${esc(p.name)}</b><div class="small muted">${esc(p.website)} · ${esc(p.support_email)}</div></td>
      <td>${pill(p.status)}</td>
      <td><select data-act="tier" data-id="${p.id}">${tiers.map((t) => `<option value="${t}" ${(p.tier_override || "") === t ? "selected" : ""}>${t ? t : `automático (${p.tier.label})`}</option>`).join("")}</select></td>
      <td class="num">${p.tier.managed_clients}</td><td class="small">${fmtDate(p.created_at)}</td>
      <td>${p.status !== "active" ? `<button class="btn sm primary" data-act="approve" data-id="${p.id}">Aprovar</button>`
        : `<button class="btn sm danger" data-act="suspend" data-id="${p.id}">Suspender</button>`}</td></tr>`).join("")
      || `<tr><td colspan="6" class="empty">Nenhum parceiro.</td></tr>`}</tbody></table></div>`, "admin-partners");
  bind(main, {
    approve: async (el) => { await api("POST", `/api/v1/admin/partners/${el.dataset.id}`, {status: "active"}); toast("Parceiro aprovado."); route(); },
    suspend: async (el) => { if (confirm("Suspender parceiro?")) { await api("POST", `/api/v1/admin/partners/${el.dataset.id}`, {status: "suspended"}); route(); } },
    tier: async (el) => { await api("POST", `/api/v1/admin/partners/${el.dataset.id}`, {tier_override: el.value}); toast("Nível atualizado."); route(); }});
}

async function viewAudit() {
  const rows = await api("GET", "/api/v1/admin/audit?limit=200");
  shell(`<h1>Auditoria</h1><div class="table-wrap"><table><thead><tr><th>Quando</th><th>Usuário</th><th>Org</th><th>Ação</th><th>Detalhe</th></tr></thead><tbody>
    ${rows.map((r) => `<tr><td class="small">${fmtDate(r.at)}</td><td>${r.user_id ?? ""}</td><td>${r.org_id ?? ""}</td><td><code>${esc(r.action)}</code></td><td class="small">${esc(r.detail)}</td></tr>`).join("")}
    </tbody></table></div>`, "audit");
}

async function viewKeys() {
  const keys = await api("GET", "/api/v1/api-keys");
  const main = shell(`<h1>Chaves de API</h1><p class="sub">Integre com SIEM, ticketing ou CI. A chave herda as permissões do seu usuário.</p>
    <form class="inline card" data-act="create"><label>Nome<input name="name" placeholder="integração SIEM" required></label><button class="btn primary" type="submit">Gerar chave</button></form>
    <div id="newkey"></div>
    <div class="table-wrap"><table><thead><tr><th>Nome</th><th>Prefixo</th><th>Criada</th><th>Último uso</th><th></th></tr></thead><tbody>
    ${keys.map((k) => `<tr><td>${esc(k.name)}</td><td><code>bm_${esc(k.prefix)}_…</code></td><td class="small">${fmtDate(k.created_at)}</td><td class="small">${fmtDate(k.last_used)}</td>
      <td><button class="btn sm danger" data-act="del" data-id="${k.id}">Revogar</button></td></tr>`).join("") || `<tr><td colspan="5" class="empty">Nenhuma chave.</td></tr>`}
    </tbody></table></div>
    <h2>Exemplo</h2><pre>curl -H "Authorization: Bearer $BLADE_KEY" ${esc(location.origin)}/api/v1/orgs</pre>`, "keys");
  bind(main, {
    create: async (f) => {
      const r = await api("POST", "/api/v1/api-keys", formData(f));
      main.querySelector("#newkey").innerHTML = `<div class="callout warn"><b>${esc(r.warning)}</b><pre>${esc(r.key)}</pre></div>`;
    },
    del: async (el) => { if (confirm("Revogar chave?")) { await api("DELETE", `/api/v1/api-keys/${el.dataset.id}`); route(); } }});
}

// ---------------------------------------------------------------- roteador
const ROUTES = [
  [/^\/$/, viewHome],
  [/^\/orgs\/(\d+)$/, viewOrgOverview],
  [/^\/orgs\/(\d+)\/issues$/, viewIssues],
  [/^\/orgs\/(\d+)\/assets$/, viewAssets],
  [/^\/orgs\/(\d+)\/vendors$/, viewVendors],
  [/^\/orgs\/(\d+)\/scans$/, viewScans],
  [/^\/orgs\/(\d+)\/settings$/, viewSettings],
  [/^\/scans\/(\d+)$/, viewScan],
  [/^\/partner$/, viewPartner],
  [/^\/partner\/branding$/, viewBranding],
  [/^\/partner\/statement$/, viewStatement],
  [/^\/partner\/team$/, viewTeam],
  [/^\/partner\/prospects$/, viewProspects],
  [/^\/admin\/partners$/, viewAdminPartners],
  [/^\/admin\/audit$/, viewAudit],
  [/^\/keys$/, viewKeys],
];
const PUBLIC = {"/login": viewLogin, "/apply": viewApply, "/signup": viewSignup};

async function route() {
  const path = (location.hash.slice(1) || "/").split("?")[0];
  try {
    if (PUBLIC[path]) return await PUBLIC[path]();
    if (!ME) {
      try { ME = await api("GET", "/api/v1/me"); }
      catch (e) { location.hash = "#/login"; return; }
    }
    for (const [re, fn] of ROUTES) {
      const m = path.match(re);
      if (m) return await fn(...m.slice(1));
    }
    location.hash = "#/";
  } catch (err) {
    if (err.status === 401) { ME = null; location.hash = "#/login"; return; }
    toast(err.message, true);
  }
}

window.addEventListener("hashchange", route);
route();

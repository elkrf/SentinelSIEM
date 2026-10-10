/* SentinelSIEM — console web */
'use strict';

// ------------------------------------------------------------------ utilitaires
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const lsGet = (k, d) => { try { return localStorage.getItem(k) ?? d; } catch { return d; } };
const lsSet = (k, v) => { try { localStorage.setItem(k, v); } catch { /* ignore */ } };

const state = { hours: +lsGet('siem-hours', 24), charts: [], timers: [], onAlert: null, newCount: 0, ws: null };

async function api(path, opts = {}) {
  const o = { ...opts, headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) } };
  if (o.body && typeof o.body !== 'string') o.body = JSON.stringify(o.body);
  const r = await fetch(path, o);
  if (r.status === 401) { location.href = '/login'; throw new Error('Non authentifié'); }
  if (!r.ok) {
    let d; try { d = (await r.json()).detail; } catch { /* */ }
    throw new Error(d || r.statusText);
  }
  return (r.headers.get('content-type') || '').includes('json') ? r.json() : r.text();
}

const pad = (n) => String(n).padStart(2, '0');
function fmtTs(ts) {
  if (!ts) return '—';
  const d = new Date(ts * 1000);
  return `${pad(d.getDate())}/${pad(d.getMonth() + 1)} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}
function fmtFull(ts) { return ts ? new Date(ts * 1000).toLocaleString('fr-FR') : '—'; }
function fmtRel(ts) {
  if (!ts) return 'jamais';
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return `il y a ${Math.round(s)} s`;
  if (s < 3600) return `il y a ${Math.round(s / 60)} min`;
  if (s < 86400) return `il y a ${Math.round(s / 3600)} h`;
  return `il y a ${Math.round(s / 86400)} j`;
}
function fmtDur(s) {
  s = Math.round(s); const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return d ? `${d} j ${h} h` : h ? `${h} h ${m} min` : `${m} min`;
}
function fmtBytes(b) {
  if (b == null) return '—';
  const u = ['o', 'Ko', 'Mo', 'Go', 'To']; let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return `${b.toFixed(b < 10 && i ? 1 : 0)} ${u[i]}`;
}
const fmtN = (n) => (n ?? 0).toLocaleString('fr-FR');
function lvlClass(l) { return l >= 15 ? 'sev' : l >= 12 ? 'crit' : l >= 7 ? 'high' : l >= 4 ? 'med' : 'low'; }
const lvl = (l) => `<span class="lvl ${lvlClass(l)}" title="Niveau ${l}">${l}</span>`;
const mitreTags = (csv) => (csv || '').split(',').filter(Boolean).map((t) => `<span class="tag mitre" data-mitre="${esc(t)}">${esc(t)}</span>`).join('');
const MODULES = {
  logs: 'Journaux macOS', fim: 'Intégrité fichiers', process: 'Processus', network: 'Réseau', malware: 'Malware',
  persistence: 'Persistance', system: 'Comptes & USB', sca: 'Config. (SCA)', active_response: 'Réponse active', siem: 'Plateforme',
};
const modName = (m) => MODULES[m] || m;
const STATUS = { new: 'Nouvelle', acknowledged: 'Acquittée', resolved: 'Résolue', false_positive: 'Faux positif' };
const statusTag = (s) => `<span class="tag ${s === 'new' ? 'warn' : s === 'resolved' ? 'ok' : s === 'false_positive' ? '' : 'info'}">${STATUS[s] || esc(s)}</span>`;
const SEV_COLORS = { critical: '#ef4d5e', high: '#f07d32', medium: '#e3b341', low: '#5d7aa6' };
const SEV_LABELS = { critical: 'Critique (12-15)', high: 'Élevé (7-11)', medium: 'Moyen (4-6)', low: 'Faible (0-3)' };
const PALETTE = ['#3595f9', '#2fbf71', '#f5a524', '#ef4d5e', '#b84bf2', '#20c3c9', '#f07d32', '#8aa1c4', '#e45ea8', '#7bd148', '#5d7aa6'];

function toast(title, body, cls = '', onclick) {
  const t = document.createElement('div');
  t.className = `toast ${cls}`;
  t.innerHTML = `<b>${esc(title)}</b>${esc(body)}`;
  if (onclick) t.addEventListener('click', onclick);
  $('#toasts').appendChild(t);
  setTimeout(() => t.remove(), 7000);
}
const ok = (m) => toast('✓', m);
const fail = (e) => toast('Erreur', e.message || String(e), 'crit');

function cssVar(n) { return getComputedStyle(document.documentElement).getPropertyValue(n).trim(); }
function chart(canvas, cfg) {
  Chart.defaults.color = cssVar('--text-2');
  Chart.defaults.borderColor = cssVar('--border');
  Chart.defaults.font.family = cssVar('--sans');
  Chart.defaults.font.size = 11.5;
  const c = new Chart(canvas, cfg);
  state.charts.push(c);
  return c;
}
function every(ms, fn) { state.timers.push(setInterval(fn, ms)); }
function hashParams() {
  const i = location.hash.indexOf('?');
  return new URLSearchParams(i >= 0 ? location.hash.slice(i + 1) : '');
}
function timeLabel(ts, bucket) {
  const d = new Date(ts * 1000);
  return bucket >= 86400 ? `${pad(d.getDate())}/${pad(d.getMonth() + 1)}` : bucket >= 21600 ? `${pad(d.getDate())}/${pad(d.getMonth() + 1)} ${pad(d.getHours())}h` : `${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
function histChart(canvas, data) {
  const keys = ['low', 'medium', 'high', 'critical'];
  return chart(canvas, {
    type: 'bar',
    data: {
      labels: data.labels.map((l) => timeLabel(l, data.bucket)),
      datasets: keys.map((k) => ({ label: SEV_LABELS[k], data: data.series[k], backgroundColor: SEV_COLORS[k], borderRadius: 2, maxBarThickness: 28 })),
    },
    options: {
      maintainAspectRatio: false, animation: false,
      plugins: { legend: { position: 'bottom', labels: { boxWidth: 10, boxHeight: 10 } } },
      scales: { x: { stacked: true, grid: { display: false } }, y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } } },
    },
  });
}
function panel(title, body, extra = '', sub = '') {
  return `<div class="panel"><div class="panel-h"><h3>${title} ${sub ? `<span class="sub">${sub}</span>` : ''}</h3><div class="actions">${extra}</div></div>${body}</div>`;
}
function kpi(label, value, hint = '', color = '', href = '') {
  return `<div class="panel kpi" style="--kc:${color || 'var(--accent)'}" ${href ? `data-href="${href}"` : ''}>
    <div class="label">${label}</div><div class="value">${value}</div><div class="hint">${hint}</div></div>`;
}
function bindKpis(el) { $$('.kpi[data-href]', el).forEach((k) => k.addEventListener('click', () => { location.hash = k.dataset.href; })); }
function bindMitre(el) {
  el.addEventListener('click', (e) => {
    const t = e.target.closest('[data-mitre]');
    if (t) { e.stopPropagation(); location.hash = `#/events?mitre=${encodeURIComponent(t.dataset.mitre)}`; }
  });
}

// ------------------------------------------------------------------ tableau d'alertes réutilisable
function alertTable(el, opts = {}) {
  const fixed = opts.fixed || {};
  const p = opts.params || new URLSearchParams();
  const f = {
    q: p.get('q') || '', min_level: p.get('min_level') ?? (opts.minLevel ?? ''), module: p.get('module') || '',
    status: p.get('status') || '', mitre: p.get('mitre') || '', rule_id: p.get('rule_id') || '', group: p.get('group') || '',
  };
  const size = opts.pageSize || 50;
  let offset = 0, total = 0, selected = new Set(), histo = null;

  el.innerHTML = `
    <div class="toolbar">
      <div class="search"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg>
        <input type="text" class="q" placeholder='Rechercher… ex: level>=10 module:process mitre:T1059 "reverse"' value="${esc(f.q)}"></div>
      <select class="min-level" title="Niveau minimum">
        <option value="">Tous niveaux</option><option value="3">Niveau ≥ 3</option><option value="4">Niveau ≥ 4</option><option value="7">Niveau ≥ 7</option><option value="10">Niveau ≥ 10</option><option value="12">Niveau ≥ 12</option>
      </select>
      ${fixed.module ? '' : `<select class="module"><option value="">Tous modules</option>${Object.entries(MODULES).map(([k, v]) => `<option value="${k}">${v}</option>`).join('')}</select>`}
      <select class="status"><option value="">Tous statuts</option>${Object.entries(STATUS).map(([k, v]) => `<option value="${k}">${v}</option>`).join('')}</select>
      <button class="btn refresh" title="Rafraîchir">↻</button>
    </div>
    <div class="chips toolbar ${f.mitre || f.rule_id || f.group ? '' : 'hide'}"></div>
    ${opts.histogram ? '<div class="panel" style="margin-bottom:14px"><div class="panel-b"><div class="chart-box sm"><canvas class="histo"></canvas></div></div></div>' : ''}
    <div class="panel">
      <div class="panel-h"><h3><span class="total">…</span> <span class="sub">alertes</span></h3>
        <div class="actions">
          <span class="sel-actions hide flex"><span class="muted small sel-n"></span>
            <button class="btn sm" data-st="acknowledged">Acquitter</button><button class="btn sm" data-st="resolved">Résoudre</button><button class="btn sm" data-st="false_positive">Faux positif</button></span>
          <button class="btn sm ack-all" title="Acquitter toutes les alertes filtrées">Tout acquitter</button>
          <button class="btn sm exp" data-fmt="csv">⬇ CSV</button><button class="btn sm exp" data-fmt="json">⬇ JSON</button>
        </div></div>
      <div class="tbl-wrap"><table class="tbl"><thead><tr>
        <th style="width:28px"><input type="checkbox" class="all"></th><th>Date</th><th>Module</th><th>Description</th><th>Niveau</th><th>Règle</th><th>MITRE</th><th>Statut</th>
      </tr></thead><tbody></tbody></table></div>
      <div class="pager"><span class="range"></span><span class="flex"><button class="btn sm prev">‹ Préc.</button><button class="btn sm next">Suiv. ›</button></span></div>
    </div>`;
  $('.min-level', el).value = f.min_level;
  if ($('.module', el)) $('.module', el).value = f.module;
  $('.status', el).value = f.status;

  const renderChips = () => {
    const c = $('.chips', el);
    const chips = [['mitre', 'MITRE'], ['rule_id', 'Règle'], ['group', 'Groupe']].filter(([k]) => f[k]);
    c.classList.toggle('hide', !chips.length);
    c.innerHTML = chips.map(([k, l]) => `<span class="tag info">${l} : ${esc(f[k])} <a href="#" data-rm="${k}">✕</a></span>`).join('');
    $$('[data-rm]', c).forEach((a) => a.addEventListener('click', (e) => { e.preventDefault(); f[a.dataset.rm] = ''; offset = 0; renderChips(); load(); }));
  };
  renderChips();

  const params = () => {
    const q = new URLSearchParams({ hours: state.hours, limit: size, offset });
    for (const [k, v] of Object.entries({ ...f, ...fixed })) if (v !== '' && v != null) q.set(k, v);
    return q;
  };
  const row = (a) => `<tr class="click" data-id="${a.id}">
      <td><input type="checkbox" class="sel" data-id="${a.id}" ${selected.has(a.id) ? 'checked' : ''}></td>
      <td class="nowrap mono">${fmtTs(a.ts)}</td>
      <td class="nowrap">${esc(modName(a.module))}</td>
      <td class="desc" title="${esc(a.description)}">${esc(a.description.length > 220 ? a.description.slice(0, 220) + '…' : a.description)}</td>
      <td>${lvl(a.level)}</td>
      <td class="mono">${a.rule_id}</td>
      <td>${mitreTags(a.mitre)}</td>
      <td>${statusTag(a.status)}</td></tr>`;

  async function load() {
    try {
      const d = await api('/api/alerts?' + params());
      total = d.total;
      $('.total', el).textContent = fmtN(total);
      $('tbody', el).innerHTML = d.items.length ? d.items.map(row).join('') : `<tr><td colspan="8" class="empty">Aucune alerte pour ces critères sur la période sélectionnée.</td></tr>`;
      $('.range', el).textContent = total ? `${offset + 1}–${Math.min(offset + size, total)} sur ${fmtN(total)}` : '';
      $('.prev', el).disabled = offset === 0;
      $('.next', el).disabled = offset + size >= total;
      if (opts.histogram) {
        const h = await api('/api/alerts/histogram?' + params());
        if (histo) histo.destroy();
        histo = histChart($('.histo', el), h);
      }
    } catch (e) { fail(e); }
  }
  const updSel = () => {
    $('.sel-actions', el).classList.toggle('hide', !selected.size);
    $('.sel-n', el).textContent = `${selected.size} sélectionnée(s)`;
  };
  let deb;
  $('.q', el).addEventListener('input', () => { clearTimeout(deb); deb = setTimeout(() => { f.q = $('.q', el).value; offset = 0; load(); }, 350); });
  $('.min-level', el).addEventListener('change', (e) => { f.min_level = e.target.value; offset = 0; load(); });
  $('.module', el)?.addEventListener('change', (e) => { f.module = e.target.value; offset = 0; load(); });
  $('.status', el).addEventListener('change', (e) => { f.status = e.target.value; offset = 0; load(); });
  $('.refresh', el).addEventListener('click', load);
  $('.prev', el).addEventListener('click', () => { offset = Math.max(0, offset - size); load(); });
  $('.next', el).addEventListener('click', () => { offset += size; load(); });
  $$('.exp', el).forEach((b) => b.addEventListener('click', () => {
    const q = params(); q.delete('limit'); q.delete('offset'); q.set('format', b.dataset.fmt);
    location.href = '/api/alerts/export?' + q;
  }));
  $('.ack-all', el).addEventListener('click', async () => {
    if (!confirm(`Acquitter les ${total} alertes correspondant aux filtres ?`)) return;
    const q = params(); q.delete('limit'); q.delete('offset'); q.set('status', 'acknowledged');
    await api('/api/alerts/status_all?' + q, { method: 'POST' }).catch(fail);
    load();
  });
  $('.all', el).addEventListener('change', (e) => {
    $$('.sel', el).forEach((c) => { c.checked = e.target.checked; const id = +c.dataset.id; e.target.checked ? selected.add(id) : selected.delete(id); });
    updSel();
  });
  $$('[data-st]', el).forEach((b) => b.addEventListener('click', async () => {
    await api('/api/alerts/status', { method: 'POST', body: { ids: [...selected], status: b.dataset.st } }).catch(fail);
    selected.clear(); updSel(); $('.all', el).checked = false; load();
  }));
  $('tbody', el).addEventListener('click', (e) => {
    if (e.target.classList.contains('sel')) {
      const id = +e.target.dataset.id; e.target.checked ? selected.add(id) : selected.delete(id); updSel(); return;
    }
    if (e.target.closest('[data-mitre]')) return;
    const tr = e.target.closest('tr[data-id]');
    if (tr) showAlert(+tr.dataset.id, load);
  });
  bindMitre($('tbody', el));
  load();

  return {
    reload: load,
    onAlert(a) {
      if (offset !== 0) return;
      if (fixed.module && !fixed.module.split(',').includes(a.module)) return;
      if (f.module && f.module !== a.module) return;
      if (f.min_level && a.level < +f.min_level) return;
      if (f.q || f.mitre || f.rule_id || f.status || f.group) return;
      const tb = $('tbody', el);
      if (tb.querySelector('.empty')) tb.innerHTML = '';
      tb.insertAdjacentHTML('afterbegin', row(a));
      tb.firstElementChild.classList.add('flash');
      while (tb.children.length > size) tb.lastElementChild.remove();
      total++; $('.total', el).textContent = fmtN(total);
    },
  };
}

// ------------------------------------------------------------------ détail d'une alerte (flyout)
function closeFly() { $('#fly').classList.remove('open'); $('#fly-bg').classList.remove('open'); }
$('#fly-bg').addEventListener('click', closeFly);
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeFly(); });

async function showAlert(id, onChange) {
  let a;
  try { a = await api(`/api/alerts/${id}`); } catch (e) { return fail(e); }
  const d = a.data || {};
  $('#fly-h').innerHTML = `${lvl(a.level)}<div><h2>${esc(a.description)}</h2>
    <div class="muted small" style="margin-top:4px">Alerte #${a.id} · ${fmtFull(a.ts)} · Règle ${a.rule_id}</div></div>
    <button class="close" title="Fermer">×</button>`;
  $('#fly-h .close').addEventListener('click', closeFly);
  const actions = [];
  actions.push(`<button class="btn sm" data-st="acknowledged">Acquitter</button>`, `<button class="btn sm" data-st="resolved">Résoudre</button>`, `<button class="btn sm" data-st="false_positive">Faux positif</button>`);
  if (d.pid && (a.module === 'process' || a.module === 'network')) actions.push(`<button class="btn sm danger" data-kill="${d.pid}">⨯ Terminer le processus ${d.pid}</button>`);
  if (d.path && ['fim', 'malware', 'process'].includes(a.module) && !d.quarantine_id && d.path.startsWith('/')) actions.push(`<button class="btn sm danger" data-quar="${esc(d.path)}">Mettre en quarantaine</button>`);
  if (d.path && a.module === 'fim') actions.push(`<button class="btn sm" data-scan="${esc(d.path)}">Analyser (ClamAV/YARA)</button>`);
  if (d.quarantine_id) actions.push(`<a class="btn sm" href="#/malware">Voir la quarantaine</a>`);

  const r = a.rule || {};
  const dataRows = Object.entries(d).filter(([k]) => !['raw', 'arguments'].includes(k) || String(d[k]).length < 400)
    .map(([k, v]) => `<div>${esc(k)}</div><div class="mono">${esc(typeof v === 'object' ? JSON.stringify(v) : v)}</div>`).join('');
  $('#fly-b').innerHTML = `
    <div class="actions" style="margin-bottom:14px">${actions.join('')}</div>
    <div class="kv">
      <div>Statut</div><div>${statusTag(a.status)}</div>
      <div>Agent</div><div>${esc(a.agent)}</div>
      <div>Module</div><div>${esc(modName(a.module))}</div>
      <div>Règle</div><div><span class="mono">${a.rule_id}</span> · niveau ${a.level} · <a href="#/events?rule_id=${a.rule_id}">voir toutes les alertes de cette règle</a></div>
      <div>Groupes</div><div>${(a.groups || '').split(',').filter(Boolean).map((g) => `<a class="tag" href="#/events?group=${encodeURIComponent(g)}">${esc(g)}</a>`).join('') || '—'}</div>
      <div>MITRE ATT&amp;CK</div><div>${(a.mitre_details || []).map((m) => `<span class="tag mitre" data-mitre="${esc(m.id)}">${esc(m.id)}</span> ${esc(m.name)}`).join('<br>') || '—'}</div>
      <div>Tactiques</div><div>${esc((a.tactics || '').replaceAll(',', ', ')) || '—'}</div>
    </div>
    <div class="section-t">Journal complet</div>
    <pre class="code">${esc(a.full_log)}</pre>
    <div class="section-t">Champs décodés</div>
    <div class="kv">${dataRows}</div>
    <div class="section-t">Définition de la règle</div>
    <pre class="code">${esc(JSON.stringify({ id: r.id, level: r.level, description: r.description, module: r.module, type: r.types, match: r.match, mitre: r.mitre, groups: r.groups, frequency: r.frequency || undefined, timeframe: r.correlation ? r.timeframe : undefined, if_matched_sid: r.if_matched_sid || undefined, file: r.source }, null, 2))}</pre>`;
  bindMitre($('#fly-b'));
  $$('#fly-b [data-st]').forEach((b) => b.addEventListener('click', async () => {
    await api('/api/alerts/status', { method: 'POST', body: { ids: [a.id], status: b.dataset.st } }).catch(fail);
    ok(`Alerte #${a.id} : ${STATUS[b.dataset.st]}`); closeFly(); onChange && onChange();
  }));
  $('#fly-b [data-kill]')?.addEventListener('click', async (e) => {
    if (!confirm(`Terminer le processus ${d.pid} (${d.name || d.process || ''}) ?`)) return;
    try { const r2 = await api('/api/response/kill', { method: 'POST', body: { pid: +e.target.dataset.kill } }); ok(`Processus ${r2.name} terminé`); } catch (er) { fail(er); }
  });
  $('#fly-b [data-quar]')?.addEventListener('click', async (e) => {
    if (!confirm(`Mettre en quarantaine ${e.target.dataset.quar} ?`)) return;
    try { await api('/api/quarantine', { method: 'POST', body: { path: e.target.dataset.quar } }); ok('Fichier mis en quarantaine'); } catch (er) { fail(er); }
  });
  $('#fly-b [data-scan]')?.addEventListener('click', async (e) => {
    try { await api('/api/malware/scan', { method: 'POST', body: { path: e.target.dataset.scan } }); ok('Analyse lancée — résultats dans « Détection de malwares »'); } catch (er) { fail(er); }
  });
  $('#fly').classList.add('open'); $('#fly-bg').classList.add('open');
}

// ------------------------------------------------------------------ pages
async function pOverview(main) {
  main.innerHTML = `
    <div class="page-head"><div><h1>Vue d'ensemble</h1><p>Synthèse de la sécurité de ce Mac sur la période sélectionnée. Les données se mettent à jour en temps réel.</p></div>
      <div class="actions"><a class="btn" href="#/hunting">Chasse aux menaces</a><a class="btn primary" href="#/malware">Analyser des fichiers</a></div></div>
    <div class="kpis" id="kpis"></div>
    <div class="grid g-2-1">
      ${panel('Évolution des alertes', '<div class="panel-b"><div class="chart-box"><canvas id="c-time"></canvas></div></div>', '', 'par sévérité')}
      ${panel('Alertes par module', '<div class="panel-b"><div class="chart-box"><canvas id="c-mod"></canvas></div></div>')}
    </div>
    <div class="grid g2">
      ${panel('Top 10 des règles déclenchées', '<div class="panel-b"><div class="chart-box"><canvas id="c-rules"></canvas></div></div>')}
      ${panel('Tactiques MITRE ATT&amp;CK', '<div class="panel-b"><div class="chart-box"><canvas id="c-tac"></canvas></div></div>', '<a class="btn sm" href="#/mitre">Matrice</a>')}
    </div>
    <div class="grid g-2-1">
      ${panel('Alertes récentes de niveau ≥ 7', '<div class="tbl-wrap scroll-y"><table class="tbl"><thead><tr><th>Date</th><th>Description</th><th>Niv.</th><th>MITRE</th></tr></thead><tbody id="recent"></tbody></table></div>', '<a class="btn sm" href="#/events?min_level=7">Tout voir</a>')}
      ${panel('Top techniques MITRE', '<div class="tbl-wrap scroll-y"><table class="tbl"><tbody id="topm"></tbody></table></div>')}
    </div>`;
  let charts = {};
  async function load() {
    let d;
    try { d = await api(`/api/stats/overview?hours=${state.hours}`); } catch (e) { return fail(e); }
    const s = d.severity;
    $('#kpis').innerHTML = [
      kpi('Alertes', fmtN(d.total), `${fmtN(d.unresolved)} non traitées (≥7)`, 'var(--accent)', '#/events'),
      kpi('Critiques', fmtN(s.critical), 'niveau 12 à 15', SEV_COLORS.critical, '#/events?min_level=12'),
      kpi('Élevées', fmtN(s.high), 'niveau 7 à 11', SEV_COLORS.high, '#/events?min_level=7'),
      kpi('Échecs d\'auth.', fmtN(d.auth_failures), `${fmtN(d.auth_success)} connexions réussies`, '#e3b341', '#/events?group=authentication_failed'),
      kpi('Malwares', fmtN(d.malware), `${fmtN(d.quarantined)} en quarantaine`, '#b84bf2', '#/malware'),
      kpi('Changements FIM', fmtN(d.fim), 'fichiers surveillés', '#20c3c9', '#/fim'),
      kpi('Score SCA', `${d.sca.score}%`, `${d.sca.failed} contrôles en échec`, d.sca.score >= 80 ? 'var(--ok)' : d.sca.score >= 60 ? 'var(--warn)' : 'var(--danger)', '#/sca'),
    ].join('');
    bindKpis($('#kpis'));
    Object.values(charts).forEach((c) => { c.destroy(); state.charts = state.charts.filter((x) => x !== c); });
    charts.time = histChart($('#c-time'), d.timeline);
    charts.mod = chart($('#c-mod'), {
      type: 'doughnut',
      data: { labels: d.by_module.map((m) => modName(m.module)), datasets: [{ data: d.by_module.map((m) => m.c), backgroundColor: PALETTE, borderWidth: 0 }] },
      options: { maintainAspectRatio: false, animation: false, cutout: '62%', plugins: { legend: { position: 'right', labels: { boxWidth: 10, boxHeight: 10 } } },
        onClick: (_, els) => { if (els.length) location.hash = `#/events?module=${d.by_module[els[0].index].module}`; } },
    });
    charts.rules = chart($('#c-rules'), {
      type: 'bar',
      data: { labels: d.top_rules.map((r) => `${r.rule_id} · ${r.description.slice(0, 42)}`), datasets: [{ data: d.top_rules.map((r) => r.c), backgroundColor: d.top_rules.map((r) => SEV_COLORS[r.level >= 12 ? 'critical' : r.level >= 7 ? 'high' : r.level >= 4 ? 'medium' : 'low']), borderRadius: 3 }] },
      options: { indexAxis: 'y', maintainAspectRatio: false, animation: false, plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, ticks: { precision: 0 } }, y: { grid: { display: false }, ticks: { font: { size: 11 } } } },
        onClick: (_, els) => { if (els.length) location.hash = `#/events?rule_id=${d.top_rules[els[0].index].rule_id}`; } },
    });
    charts.tac = chart($('#c-tac'), {
      type: 'bar',
      data: { labels: d.tactics.map((t) => t.name), datasets: [{ data: d.tactics.map((t) => t.c), backgroundColor: '#b84bf2', borderRadius: 3 }] },
      options: { maintainAspectRatio: false, animation: false, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } }, x: { grid: { display: false }, ticks: { maxRotation: 50, minRotation: 35, font: { size: 10.5 } } } } },
    });
    $('#recent').innerHTML = d.recent.length ? d.recent.map((a) => `<tr class="click" data-id="${a.id}"><td class="nowrap mono">${fmtTs(a.ts)}</td><td>${esc(a.description)}</td><td>${lvl(a.level)}</td><td>${mitreTags(a.mitre)}</td></tr>`).join('')
      : '<tr><td colspan="4" class="empty">Aucune alerte significative 🎉</td></tr>';
    $('#topm').innerHTML = d.top_mitre.length ? d.top_mitre.map((m) => `<tr class="click" data-m="${esc(m.id)}"><td><span class="tag mitre" data-mitre="${esc(m.id)}">${esc(m.id)}</span></td><td>${esc(m.name)}</td><td class="num"><b>${m.c}</b></td></tr>`).join('')
      : '<tr><td class="empty">Aucune technique détectée</td></tr>';
  }
  $('#recent').addEventListener('click', (e) => { const tr = e.target.closest('tr[data-id]'); if (tr && !e.target.closest('[data-mitre]')) showAlert(+tr.dataset.id, load); });
  bindMitre($('#recent')); bindMitre($('#topm'));
  $('#topm').addEventListener('click', (e) => { const tr = e.target.closest('tr[data-m]'); if (tr) location.hash = `#/events?mitre=${tr.dataset.m}`; });
  await load();
  every(30000, load);
  let deb; state.onAlert = () => { clearTimeout(deb); deb = setTimeout(load, 2000); };
}

function pEvents(main, params) {
  main.innerHTML = `<div class="page-head"><div><h1>Événements de sécurité</h1><p>Toutes les alertes générées par le moteur de règles. Cliquez sur une ligne pour le détail, les données brutes et les actions de réponse.</p></div></div><div id="tbl"></div>`;
  const t = alertTable($('#tbl'), { params });
  state.onAlert = t.onAlert;
}

function pHunting(main, params) {
  const ex = ['level>=12', 'module:process', 'mitre:T1059', 'group:authentication_failed', 'module:malware level>=7', 'tactic:Persistence', 'status:new level>=10', 'sudo', 'path:Downloads'];
  main.innerHTML = `<div class="page-head"><div><h1>Chasse aux menaces</h1><p>Recherchez dans l'ensemble des évènements avec le langage de requête : champs <code>level</code>, <code>module</code>, <code>rule</code>, <code>mitre</code>, <code>tactic</code>, <code>group</code>, <code>status</code>, n'importe quel champ de données (<code>user:</code>, <code>path:</code>, <code>process:</code>…) et du texte libre.</p></div></div>
    <div class="toolbar"><span class="muted small">Exemples :</span>${ex.map((x) => `<a href="#/hunting?q=${encodeURIComponent(x)}" class="tag info">${esc(x)}</a>`).join('')}</div>
    <div id="tbl"></div>`;
  const t = alertTable($('#tbl'), { params, histogram: true });
  state.onAlert = t.onAlert;
}

async function pMitre(main) {
  main.innerHTML = `<div class="page-head"><div><h1>MITRE ATT&amp;CK</h1><p>Couverture de détection et techniques observées sur la période. Les couleurs indiquent le niveau maximal d'alerte. Cliquez sur une technique pour voir les évènements.</p></div></div>
    <div class="panel"><div class="panel-b"><div class="mitre" id="mx">Chargement…</div></div></div>`;
  const d = await api(`/api/mitre?hours=${state.hours}`);
  $('#mx').innerHTML = d.matrix.map((t) => `<div class="col"><h4>${esc(t.name)}<span>${t.total} alerte(s)</span></h4>
    ${t.techniques.map((x) => {
      const c = x.count ? SEV_COLORS[x.max_level >= 12 ? 'critical' : x.max_level >= 7 ? 'high' : x.max_level >= 4 ? 'medium' : 'low'] : '';
      return `<div class="tech" data-mitre="${x.id}" style="${c ? `background:${c}22;border-color:${c}` : ''}"><b>${x.id}${x.count ? `<span class="n">${x.count}</span>` : ''}</b>${esc(x.name)}</div>`;
    }).join('')}</div>`).join('');
  bindMitre($('#mx'));
}

async function pMalware(main) {
  main.innerHTML = `<div class="page-head"><div><h1>Détection de malwares</h1><p>Chaque fichier nouveau ou modifié dans les emplacements à risque est analysé par ClamAV (signatures mises à jour toutes les 12 h), par les règles YARA et par des heuristiques macOS. Les menaces sont mises en quarantaine automatiquement.</p></div>
      <div class="actions"><button class="btn" id="b-test">Tester la détection (EICAR)</button><button class="btn" id="b-upd">Mettre à jour les signatures</button></div></div>
    <div class="kpis" id="mk"></div>
    <div class="grid g2">
      ${panel('Analyse à la demande', `<div class="panel-b">
          <div class="flex"><input type="text" id="scan-path" style="flex:1" placeholder="/chemin/à/analyser" value="~/Downloads"><button class="btn primary" id="b-scan">Analyser</button></div>
          <div class="toolbar" style="margin:10px 0 0"><span class="muted small">Raccourcis :</span>
            ${[['~/Downloads', 'Téléchargements'], ['~/Desktop', 'Bureau'], ['~/Documents', 'Documents'], ['/Applications', 'Applications'], ['~/Library/LaunchAgents', 'LaunchAgents'], ['/Users/Shared', 'Partagé'], ['~', 'Dossier personnel (long)']].map(([p, l]) => `<a href="#" class="tag" data-p="${p}">${l}</a>`).join('')}</div>
          <div id="jobs" style="margin-top:14px"></div></div>`)}
      ${panel('Moteurs', '<div class="panel-b" id="engines"></div>')}
    </div>
    <div class="grid">${panel('Quarantaine', '<div class="tbl-wrap scroll-y"><table class="tbl"><thead><tr><th>Date</th><th>Fichier d\'origine</th><th>Détection</th><th>Moteur</th><th>SHA-256</th><th>Taille</th><th>Statut</th><th></th></tr></thead><tbody id="qt"></tbody></table></div>')}</div>
    <h3 style="margin:18px 0 10px">Alertes malware & réponse active</h3><div id="tbl"></div>`;
  async function load() {
    const d = await api('/api/malware');
    const running = d.jobs.some((j) => j.status === 'running');
    $('#mk').innerHTML = [
      kpi('ClamAV', d.clamav.available ? '<span style="color:var(--ok)">Actif</span>' : '<span style="color:var(--warn)">Repli</span>', d.clamav.available ? 'démon clamd' : 'clamscan (lent)', d.clamav.available ? 'var(--ok)' : 'var(--warn)'),
      kpi('Règles YARA', d.yara_rules, d.yara_error ? 'erreur de compilation' : 'compilées', '#b84bf2'),
      kpi('Fichiers analysés', fmtN(d.scanned), 'depuis le démarrage'),
      kpi('Détections', fmtN(d.detections), 'depuis le démarrage', 'var(--danger)'),
      kpi('File d\'attente', d.queue, 'analyses temps réel', '#20c3c9'),
    ].join('');
    $('#engines').innerHTML = `<div class="kv">
      <div>ClamAV</div><div>${d.clamav.available ? '<span class="status-dot on"></span>' : '<span class="status-dot warn"></span>'}${esc(d.clamav.version || 'version inconnue')}</div>
      <div>Signatures</div><div>Dernière mise à jour : ${fmtRel(d.last_update)} ${d.update_running ? '<span class="tag info">mise à jour en cours…</span>' : ''}</div>
      <div>YARA</div><div>${d.yara_rules} règles ${d.yara_error ? `<span class="tag fail">${esc(d.yara_error)}</span>` : '<span class="tag ok">OK</span>'}</div>
      <div>Quarantaine auto</div><div>${d.auto_quarantine ? '<span class="tag ok">Activée</span>' : '<span class="tag warn">Désactivée</span>'} <a href="#/settings" class="small">modifier</a></div>
      <div>Analyse temps réel</div><div class="small mono">${(d.scan_paths || []).map(esc).join('<br>')}</div>
    </div>${d.update_output ? `<details><summary class="small muted">Sortie de freshclam</summary><pre class="code">${esc(d.update_output)}</pre></details>` : ''}`;
    $('#jobs').innerHTML = d.jobs.length ? d.jobs.slice(0, 6).map((j) => {
      const pct = j.total ? Math.round((100 * j.scanned) / j.total) : (j.status === 'done' ? 100 : 0);
      return `<div style="margin-bottom:12px"><div class="flex small"><b class="mono" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:60%">${esc(j.path)}</b><span class="spacer"></span>
        ${j.status === 'running' ? `<span class="muted">${fmtN(j.scanned)}/${fmtN(j.total)}</span><button class="btn sm" data-cancel="${j.id}">Annuler</button>` : `<span class="tag ${j.detections.length ? 'fail' : 'ok'}">${j.status === 'done' ? 'Terminé' : esc(j.status)} · ${j.detections.length} détection(s)</span>`}</div>
        <div class="progress" style="margin-top:5px"><div style="width:${pct}%;${j.detections.length ? 'background:var(--danger)' : ''}"></div></div>
        ${j.status === 'running' ? `<div class="muted small mono" style="margin-top:3px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(j.current)}</div>` : `<div class="muted small">${fmtN(j.scanned)} fichiers · ${fmtRel(j.finished)}${j.errors ? ` · ${j.errors} illisible(s)` : ''}</div>`}
        ${j.detections.map((x) => `<div class="small" style="margin-top:3px">⚠ <span class="mono">${esc(x.path)}</span> — ${x.findings.map((f) => esc(f.signature)).join(', ')} ${x.quarantined ? '<span class="tag fail">quarantaine</span>' : ''}</div>`).join('')}</div>`;
    }).join('') : '<div class="muted small">Aucune analyse lancée.</div>';
    $$('[data-cancel]').forEach((b) => b.addEventListener('click', () => api(`/api/malware/scan/${b.dataset.cancel}/cancel`, { method: 'POST' }).then(load)));
    const q = await api('/api/quarantine');
    $('#qt').innerHTML = q.length ? q.map((x) => `<tr><td class="nowrap mono">${fmtTs(x.ts)}</td><td class="mono trunc" title="${esc(x.original_path)}">${esc(x.original_path)}</td><td>${esc(x.reason)}</td><td>${esc(x.engine)}</td>
        <td class="mono small" title="${esc(x.sha256)}">${esc((x.sha256 || '').slice(0, 16))}…</td><td class="nowrap">${fmtBytes(x.size)}</td>
        <td>${x.status === 'quarantined' ? '<span class="tag fail">En quarantaine</span>' : x.status === 'restored' ? '<span class="tag warn">Restauré</span>' : '<span class="tag">Supprimé</span>'}</td>
        <td class="nowrap">${x.status === 'quarantined' ? `<button class="btn sm" data-restore="${x.id}">Restaurer</button> <button class="btn sm danger" data-del="${x.id}">Supprimer</button>` : ''}</td></tr>`).join('')
      : '<tr><td colspan="8" class="empty">La quarantaine est vide.</td></tr>';
    return running;
  }
  $('#qt').addEventListener('click', async (e) => {
    const r = e.target.dataset.restore, dl = e.target.dataset.del;
    try {
      if (r && confirm('Restaurer ce fichier à son emplacement d\'origine ? Il pourrait être dangereux.')) { const x = await api(`/api/quarantine/${r}/restore`, { method: 'POST' }); ok(`Restauré : ${x.path}`); }
      if (dl && confirm('Supprimer définitivement ce fichier ?')) { await api(`/api/quarantine/${dl}`, { method: 'DELETE' }); ok('Fichier supprimé définitivement'); }
    } catch (er) { fail(er); }
    load();
  });
  $$('[data-p]').forEach((a) => a.addEventListener('click', (e) => { e.preventDefault(); $('#scan-path').value = a.dataset.p; }));
  $('#b-scan').addEventListener('click', async () => {
    try { await api('/api/malware/scan', { method: 'POST', body: { path: $('#scan-path').value } }); ok('Analyse lancée'); load(); } catch (e) { fail(e); }
  });
  $('#b-upd').addEventListener('click', async () => { await api('/api/malware/update', { method: 'POST' }).catch(fail); ok('Mise à jour des signatures lancée (peut prendre quelques minutes)'); setTimeout(load, 1000); });
  $('#b-test').addEventListener('click', async () => {
    try { const r = await api('/api/malware/test', { method: 'POST' }); ok(`Fichier de test EICAR déposé : ${r.path}. Il doit être détecté et mis en quarantaine en quelques secondes.`); setTimeout(load, 4000); setTimeout(load, 12000); } catch (e) { fail(e); }
  });
  const t = alertTable($('#tbl'), { fixed: { module: 'malware,active_response' }, pageSize: 25 });
  await load();
  every(3000, async () => { const r = await load().catch(() => false); });
  state.onAlert = t.onAlert;
}

async function pFim(main) {
  main.innerHTML = `<div class="page-head"><div><h1>Intégrité des fichiers (FIM)</h1><p>Empreinte SHA-256, permissions et propriétaire de chaque fichier des répertoires sensibles. Toute création, modification ou suppression génère un évènement en temps réel (FSEvents), y compris les changements survenus pendant l'arrêt du SIEM.</p></div></div>
    <div class="kpis" id="fk"></div>
    <div class="grid g-1-2">
      ${panel('Répertoires surveillés', '<div class="tbl-wrap"><table class="tbl"><thead><tr><th>Chemin</th><th>Récursif</th><th class="num">Fichiers</th></tr></thead><tbody id="roots"></tbody></table></div>', '<a class="btn sm" href="#/settings">Configurer</a>')}
      ${panel('Base de référence', `<div class="panel-b" style="padding-bottom:0"><div class="search"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg><input type="text" id="fq" placeholder="Filtrer par chemin…"></div></div>
        <div class="tbl-wrap scroll-y" style="margin-top:10px"><table class="tbl"><thead><tr><th>Fichier</th><th>SHA-256</th><th>Taille</th><th>Mode</th><th>Propriétaire</th><th>Vu</th></tr></thead><tbody id="files"></tbody></table></div>`)}
    </div>
    <h3 style="margin:18px 0 10px">Évènements d'intégrité</h3><div id="tbl"></div>`;
  async function load() {
    const d = await api(`/api/fim?q=${encodeURIComponent($('#fq').value)}`);
    const c = d.changes_24h || {};
    $('#fk').innerHTML = [
      kpi('Fichiers indexés', fmtN(d.total), d.baseline_done ? 'baseline établie' : 'indexation en cours…'),
      kpi('Ajouts (24 h)', fmtN(c.added || 0), '', 'var(--ok)'),
      kpi('Modifications (24 h)', fmtN(c.modified || 0), '', 'var(--warn)'),
      kpi('Suppressions (24 h)', fmtN(c.deleted || 0), '', 'var(--danger)'),
      kpi('En attente', d.pending, 'évènements à traiter', '#20c3c9'),
    ].join('');
    $('#roots').innerHTML = d.roots.map((r) => `<tr><td class="mono">${esc(r.path)}</td><td>${r.recursive ? 'oui' : 'non'}</td><td class="num">${fmtN(r.files)}</td></tr>`).join('');
    $('#files').innerHTML = d.files.map((f) => `<tr><td class="mono trunc" title="${esc(f.path)}">${esc(f.path)}</td><td class="mono small" title="${esc(f.sha256 || '')}">${esc((f.sha256 || '—').slice(0, 12))}</td><td class="nowrap">${f.is_dir ? 'dossier' : fmtBytes(f.size)}</td><td class="mono">${(f.mode ?? 0).toString(8)}</td><td>${esc(f.owner)}</td><td class="nowrap small">${fmtRel(f.updated)}</td></tr>`).join('') || '<tr><td colspan="6" class="empty">Aucun fichier</td></tr>';
  }
  let deb; $('#fq').addEventListener('input', () => { clearTimeout(deb); deb = setTimeout(load, 300); });
  const t = alertTable($('#tbl'), { fixed: { module: 'fim' }, pageSize: 25 });
  await load();
  every(15000, load);
  state.onAlert = t.onAlert;
}

async function pSca(main) {
  main.innerHTML = `<div class="page-head"><div><h1>Évaluation de la configuration (SCA)</h1><p>Audit de durcissement de macOS inspiré du CIS Apple macOS Benchmark. Les contrôles sont réévalués toutes les heures ; une régression (contrôle conforme devenu non conforme) génère une alerte de niveau 10.</p></div>
      <div class="actions"><button class="btn primary" id="run">Lancer l'évaluation</button></div></div>
    <div class="grid g-1-2">
      ${panel('Score de conformité', '<div class="panel-b score-ring"><div style="width:190px;height:190px;position:relative"><canvas id="ring"></canvas><div id="ring-t" style="position:absolute;inset:0;display:grid;place-items:center;font-size:30px;font-weight:700"></div></div><div id="sc-c"></div></div>')}
      ${panel('Par catégorie', '<div class="panel-b"><div class="chart-box sm"><canvas id="cat"></canvas></div></div>')}
    </div>
    ${panel('Contrôles', '<div class="tbl-wrap"><table class="tbl"><thead><tr><th>Résultat</th><th>ID</th><th>Contrôle</th><th>Catégorie</th><th>Sévérité</th><th>Référence</th></tr></thead><tbody id="checks"></tbody></table></div>', '', 'cliquez pour voir le détail et la remédiation')}`;
  let charts = [];
  async function load() {
    const d = await api('/api/sca');
    const s = d.score;
    $('#run').disabled = d.running; $('#run').textContent = d.running ? 'Évaluation en cours…' : 'Lancer l\'évaluation';
    charts.forEach((c) => c.destroy()); charts = [];
    const col = s.score >= 80 ? '#2fbf71' : s.score >= 60 ? '#f5a524' : '#ef4d5e';
    charts.push(chart($('#ring'), { type: 'doughnut', data: { labels: ['Conformes', 'Non conformes', 'N/A'], datasets: [{ data: [s.passed, s.failed, s.not_applicable], backgroundColor: ['#2fbf71', '#ef4d5e', '#5d7aa6'], borderWidth: 0 }] }, options: { cutout: '74%', animation: false, plugins: { legend: { display: false } } } }));
    $('#ring-t').innerHTML = `<span style="color:${col}">${s.score}%</span>`;
    $('#sc-c').innerHTML = `<div class="kv" style="grid-template-columns:140px auto;margin:0;min-width:240px"><div>Conformes</div><div><b style="color:var(--ok)">${s.passed}</b></div><div>Non conformes</div><div><b style="color:var(--danger)">${s.failed}</b></div><div>Non applicables</div><div>${s.not_applicable}</div><div>Dernière éval.</div><div class="small">${fmtRel(d.checks[0]?.ts)}</div></div>`;
    const cats = {};
    d.checks.forEach((c) => { cats[c.category] = cats[c.category] || { pass: 0, fail: 0, na: 0 }; cats[c.category][c.status]++; });
    const labels = Object.keys(cats);
    charts.push(chart($('#cat'), { type: 'bar', data: { labels, datasets: [{ label: 'Conformes', data: labels.map((l) => cats[l].pass), backgroundColor: '#2fbf71' }, { label: 'Non conformes', data: labels.map((l) => cats[l].fail), backgroundColor: '#ef4d5e' }, { label: 'N/A', data: labels.map((l) => cats[l].na), backgroundColor: '#5d7aa6' }] },
      options: { maintainAspectRatio: false, animation: false, indexAxis: 'y', plugins: { legend: { position: 'bottom', labels: { boxWidth: 10 } } }, scales: { x: { stacked: true, ticks: { precision: 0 } }, y: { stacked: true, grid: { display: false } } } } }));
    const sevTag = { critical: 'fail', high: 'warn', medium: 'info', low: '' };
    $('#checks').innerHTML = d.checks.map((c) => `<tr class="click" data-c="${esc(c.check_id)}"><td>${c.status === 'pass' ? '<span class="tag ok">Conforme</span>' : c.status === 'fail' ? '<span class="tag fail">Non conforme</span>' : '<span class="tag">N/A</span>'}</td>
      <td class="mono">${esc(c.check_id)}</td><td><b>${esc(c.title)}</b></td><td>${esc(c.category)}</td><td><span class="tag ${sevTag[c.severity] || ''}">${esc(c.severity)}</span></td><td class="small">${esc(c.cis)}</td></tr>
      <tr class="hide" data-d="${esc(c.check_id)}"><td colspan="6" style="background:var(--panel-2)"><div class="section-t">Résultat</div><pre class="code" style="margin-bottom:10px">${esc(c.detail)}</pre><div class="section-t">Remédiation</div><div class="mono small">${esc(c.remediation)}</div></td></tr>`).join('')
      || '<tr><td colspan="6" class="empty">Évaluation en cours…</td></tr>';
  }
  $('#checks').addEventListener('click', (e) => { const tr = e.target.closest('tr[data-c]'); if (tr) $(`tr[data-d="${tr.dataset.c}"]`).classList.toggle('hide'); });
  $('#run').addEventListener('click', async () => { await api('/api/sca/run', { method: 'POST' }); ok('Évaluation lancée (jusqu\'à 2-3 minutes : vérification des mises à jour)'); setTimeout(load, 800); });
  await load();
  every(10000, load);
}

async function pProcesses(main) {
  main.innerHTML = `<div class="page-head"><div><h1>Processus</h1><p>Processus en cours d'exécution (rafraîchi toutes les 5 s). Chaque nouveau processus est analysé par les règles comportementales (reverse shells, vol d'identifiants, contournement des protections, minage…).</p></div></div>
    <div class="toolbar"><div class="search"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg><input type="text" id="pq" placeholder="Filtrer : nom, PID, utilisateur, ligne de commande…"></div><span class="muted small" id="pn"></span></div>
    <div class="panel"><div class="tbl-wrap" style="max-height:520px;overflow-y:auto"><table class="tbl"><thead><tr><th data-s="pid">PID</th><th data-s="name">Nom</th><th data-s="user">Utilisateur</th><th data-s="cpu" class="num">CPU %</th><th data-s="mem" class="num">Mémoire</th><th data-s="started">Démarré</th><th>Ligne de commande</th><th></th></tr></thead><tbody id="pt"></tbody></table></div></div>
    <h3 style="margin:18px 0 10px">Alertes de comportement des processus</h3><div id="tbl"></div>`;
  let data = [], sort = 'cpu', dir = -1;
  const render = () => {
    const q = $('#pq').value.toLowerCase();
    const rows = data.filter((p) => !q || `${p.pid} ${p.name} ${p.user} ${p.cmdline} ${p.exe}`.toLowerCase().includes(q))
      .sort((a, b) => ((a[sort] ?? '') > (b[sort] ?? '') ? 1 : -1) * dir);
    $('#pn').textContent = `${rows.length} / ${data.length} processus`;
    $('#pt').innerHTML = rows.slice(0, 400).map((p) => `<tr><td class="mono">${p.pid}</td><td><b>${esc(p.name)}</b></td><td>${esc(p.user || '—')}</td>
      <td class="num" style="${p.cpu > 50 ? 'color:var(--danger);font-weight:700' : ''}">${p.cpu.toFixed(1)}</td><td class="num nowrap">${fmtBytes(p.mem)}</td><td class="nowrap small">${fmtTs(p.started)}</td>
      <td class="mono small trunc" title="${esc(p.cmdline || p.exe)}">${esc(p.cmdline || p.exe || '')}</td><td><button class="btn sm danger" data-k="${p.pid}" data-n="${esc(p.name)}">Terminer</button></td></tr>`).join('');
  };
  async function load() { data = await api('/api/inventory/processes'); render(); }
  $('#pq').addEventListener('input', render);
  $$('th[data-s]', main).forEach((th) => { th.style.cursor = 'pointer'; th.addEventListener('click', () => { const s = th.dataset.s; dir = sort === s ? -dir : -1; sort = s; render(); }); });
  $('#pt').addEventListener('click', async (e) => {
    const b = e.target.closest('[data-k]'); if (!b) return;
    if (!confirm(`Terminer le processus ${b.dataset.n} (PID ${b.dataset.k}) ?`)) return;
    try { await api('/api/response/kill', { method: 'POST', body: { pid: +b.dataset.k } }); ok(`${b.dataset.n} terminé`); load(); } catch (er) { fail(er); }
  });
  const t = alertTable($('#tbl'), { fixed: { module: 'process' }, pageSize: 25 });
  await load(); every(5000, load);
  state.onAlert = t.onAlert;
}

async function pNetwork(main) {
  main.innerHTML = `<div class="page-head"><div><h1>Réseau</h1><p>Ports en écoute et connexions actives des processus de l'utilisateur. Détection des ports de C2/minage, des IP malveillantes (IOC) et des interpréteurs connectés à Internet.</p></div></div>
    <div class="grid g2">
      ${panel('Ports en écoute', '<div class="tbl-wrap scroll-y"><table class="tbl"><thead><tr><th>Processus</th><th>PID</th><th>Proto</th><th>Adresse</th><th>Exposition</th></tr></thead><tbody id="lt"></tbody></table></div>')}
      ${panel('Connexions établies', '<div class="tbl-wrap scroll-y"><table class="tbl"><thead><tr><th>Processus</th><th>PID</th><th>Local</th><th>Distant</th><th>État</th></tr></thead><tbody id="et"></tbody></table></div>', '', '<span id="en"></span>')}
    </div>
    <h3 style="margin:8px 0 10px">Alertes réseau</h3><div id="tbl"></div>`;
  async function load() {
    const d = await api('/api/inventory/network');
    const exp = (h) => ['*', '0.0.0.0', '::', '[::]'].includes(h);
    $('#lt').innerHTML = (d.listening || []).map((r) => `<tr><td><b>${esc(r.process)}</b></td><td class="mono">${r.pid}</td><td>${r.proto}</td><td class="mono">${esc(r.local)}</td><td>${exp(r.local_host) ? '<span class="tag warn">Réseau</span>' : '<span class="tag ok">Local</span>'}</td></tr>`).join('') || '<tr><td colspan="5" class="empty">Aucun port</td></tr>';
    $('#et').innerHTML = (d.established || []).map((r) => `<tr><td><b>${esc(r.process)}</b></td><td class="mono">${r.pid}</td><td class="mono small">${esc(r.local)}</td><td class="mono small">${esc(r.remote)}</td><td class="small">${esc(r.state)}</td></tr>`).join('') || '<tr><td colspan="5" class="empty">Aucune connexion</td></tr>';
    $('#en').textContent = `${(d.established || []).length} connexions · ${fmtRel(d.ts)}`;
  }
  const t = alertTable($('#tbl'), { fixed: { module: 'network' }, pageSize: 25 });
  await load(); every(15000, load);
  state.onAlert = t.onAlert;
}

async function pPersistence(main) {
  main.innerHTML = `<div class="page-head"><div><h1>Persistance</h1><p>Inventaire des mécanismes de démarrage automatique : LaunchAgents, LaunchDaemons, tâches cron et scripts de démarrage du shell. Tout ajout ou modification déclenche une alerte ; les éléments pointant vers des emplacements suspects sont signalés comme critiques.</p></div></div>
    ${panel('Éléments de démarrage', '<div class="tbl-wrap scroll-y"><table class="tbl"><thead><tr><th>Type</th><th>Label</th><th>Programme</th><th>Au démarrage</th><th>Fichier</th></tr></thead><tbody id="it"></tbody></table></div>')}
    <h3 style="margin:18px 0 10px">Alertes de persistance</h3><div id="tbl"></div>`;
  const d = await api('/api/inventory/persistence');
  $('#it').innerHTML = d.map((i) => `<tr><td class="nowrap"><span class="tag">${esc(i.kind)}</span></td><td><b>${esc(i.label)}</b></td><td class="mono small trunc" title="${esc(i.arguments || i.program)}">${esc(i.kind.startsWith('Script') ? '(script shell)' : (i.arguments || i.program))}</td><td>${i.run_at_load ? 'oui' : i.keep_alive ? 'keep-alive' : '—'}</td><td class="mono small trunc">${esc(i.path)}</td></tr>`).join('') || '<tr><td colspan="5" class="empty">Aucun élément</td></tr>';
  const t = alertTable($('#tbl'), { fixed: { module: 'persistence' }, pageSize: 25 });
  state.onAlert = t.onAlert;
}

async function pInventory(main) {
  main.innerHTML = `<div class="page-head"><div><h1>Inventaire système</h1><p>Matériel, système, applications installées, paquets Homebrew, comptes et périphériques de ce Mac.</p></div></div>
    <div class="kpis" id="sk"></div>
    <div class="grid g2">${panel('Système', '<div class="panel-b" id="sys"></div>')}${panel('Comptes & périphériques', '<div class="panel-b" id="acc"></div>')}</div>
    <div class="panel"><div class="panel-b"><div class="tabs"><button class="on" data-t="apps">Applications</button><button data-t="pkgs">Paquets Homebrew</button></div><div id="tab"></div></div></div>`;
  const s = await api('/api/inventory/system');
  const meter = (p) => `<div class="meter"><div style="width:${p}%;background:${p > 85 ? 'var(--danger)' : p > 65 ? 'var(--warn)' : 'var(--ok)'}"></div></div>`;
  $('#sk').innerHTML = [
    kpi('CPU', `${s.cpu_percent.toFixed(0)}%`, `${s.cores} cœurs · charge ${s.load.map((x) => x.toFixed(1)).join(' / ')}` + meter(s.cpu_percent)),
    kpi('Mémoire', `${s.ram_percent.toFixed(0)}%`, `${fmtBytes(s.ram_total)} au total` + meter(s.ram_percent)),
    kpi('Disque', `${s.disk_percent.toFixed(0)}%`, `${fmtBytes(s.disk_used)} / ${fmtBytes(s.disk_total)}` + meter(s.disk_percent)),
    kpi('Uptime', fmtDur(s.uptime), `démarré le ${fmtFull(s.boot_time)}`),
  ].join('');
  $('#sys').innerHTML = `<div class="kv" style="margin:0"><div>Nom d'hôte</div><div>${esc(s.hostname)}</div><div>Système</div><div>${esc(s.os)}</div><div>Noyau</div><div>Darwin ${esc(s.kernel)} (${esc(s.arch)})</div><div>Modèle</div><div>${esc(s.model)}</div><div>Processeur</div><div>${esc(s.cpu)}</div><div>Interfaces</div><div class="mono">${s.interfaces.map((i) => `${esc(i.iface)} : ${esc(i.ip)}`).join('<br>') || '—'}</div></div>`;
  const a = await api('/api/inventory/accounts');
  $('#acc').innerHTML = `<div class="kv" style="margin:0"><div>Utilisateurs</div><div>${(a.users || []).map((u) => `<span class="tag">${esc(u.name)} <span class="muted">${u.uid}</span></span>`).join('')}</div>
    <div>Administrateurs</div><div>${(a.admins || []).map((u) => `<span class="tag warn">${esc(u)}</span>`).join('')}</div>
    <div>Périphériques USB</div><div>${(a.usb || []).map((u) => `${esc(u.name)} <span class="muted small">${esc(u.vendor)}</span>`).join('<br>') || '—'}</div>
    <div>Volumes</div><div>${(a.volumes || []).map(esc).join('<br>') || '—'}</div></div>`;
  async function tab(t) {
    $$('.tabs button', main).forEach((b) => b.classList.toggle('on', b.dataset.t === t));
    if (t === 'apps') {
      const apps = await api('/api/inventory/apps');
      $('#tab').innerHTML = `<div class="tbl-wrap scroll-y"><table class="tbl"><thead><tr><th>Application</th><th>Version</th><th>Identifiant</th><th>Modifiée</th><th>Signature</th></tr></thead><tbody>${apps.map((x) => `<tr><td><b>${esc(x.name)}</b></td><td>${esc(x.version)}</td><td class="mono small">${esc(x.bundle_id)}</td><td class="small nowrap">${fmtTs(x.mtime)}</td><td class="sig"><button class="btn sm" data-sig="${esc(x.path)}">Vérifier</button></td></tr>`).join('')}</tbody></table></div><div class="muted small" style="margin-top:8px">${apps.length} applications</div>`;
    } else {
      const p = await api('/api/inventory/packages');
      $('#tab').innerHTML = `<div class="tbl-wrap scroll-y"><table class="tbl"><thead><tr><th>Paquet</th><th>Version</th><th>Source</th></tr></thead><tbody>${p.map((x) => `<tr><td><b>${esc(x.name)}</b></td><td class="mono">${esc(x.version)}</td><td>${esc(x.source)}</td></tr>`).join('')}</tbody></table></div>`;
    }
  }
  $('#tab').addEventListener('click', async (e) => {
    const b = e.target.closest('[data-sig]'); if (!b) return;
    b.disabled = true; b.textContent = '…';
    try {
      const r = await api('/api/inventory/signature?path=' + encodeURIComponent(b.dataset.sig));
      b.parentElement.innerHTML = r.signed ? `<span class="tag ok" title="${esc(r.gatekeeper)}">Signée</span> <span class="small">${esc(r.authority[0] || '')}</span>` : `<span class="tag fail" title="${esc(r.gatekeeper)}">Non signée</span>`;
    } catch (er) { fail(er); }
  });
  $$('.tabs button', main).forEach((b) => b.addEventListener('click', () => tab(b.dataset.t)));
  tab('apps');
}

async function pRules(main) {
  main.innerHTML = `<div class="page-head"><div><h1>Règles</h1><p>Règles de détection au format YAML (style Wazuh) dans <code>~/SentinelSIEM/rules/</code> et règles YARA dans <code>~/SentinelSIEM/yara/</code>. Ajoutez vos règles dans <code>9000-local_rules.yml</code> puis rechargez.</p></div>
      <div class="actions"><button class="btn primary" id="reload">Recharger les règles</button></div></div>
    <div class="tabs"><button class="on" data-t="list">Règles de corrélation</button><button data-t="files">Fichiers de règles</button><button data-t="yara">YARA</button></div><div id="tab"></div>`;
  async function tab(t) {
    $$('.tabs button', main).forEach((b) => b.classList.toggle('on', b.dataset.t === t));
    if (t === 'list') {
      const rules = await api('/api/rules');
      $('#tab').innerHTML = `<div class="toolbar"><div class="search"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg><input type="text" id="rq" placeholder="Filtrer les règles…"></div><span class="muted small" id="rn"></span></div>
        <div class="panel"><div class="tbl-wrap"><table class="tbl"><thead><tr><th>ID</th><th>Niv.</th><th>Description</th><th>Module</th><th>Groupes</th><th>MITRE</th><th>Fichier</th><th class="num">Alertes</th></tr></thead><tbody id="rt"></tbody></table></div></div>`;
      const render = () => {
        const q = $('#rq').value.toLowerCase();
        const rows = rules.filter((r) => !q || JSON.stringify(r).toLowerCase().includes(q));
        $('#rn').textContent = `${rows.length} règles`;
        $('#rt').innerHTML = rows.map((r) => `<tr class="click" data-r="${r.id}"><td class="mono">${r.id}</td><td>${lvl(r.level)}</td><td>${esc(r.description)}${r.correlation ? ` <span class="tag info">corrélation : ${r.frequency}× en ${r.timeframe}s ← ${r.if_matched_sid}</span>` : ''}</td><td>${esc(modName(r.module || ''))}</td><td>${r.groups.map((g) => `<span class="tag">${esc(g)}</span>`).join('')}</td><td>${mitreTags(r.mitre.join(','))}</td><td class="small mono">${esc(r.source)}</td><td class="num">${r.alerts ? `<b>${fmtN(r.alerts)}</b>` : '0'}</td></tr>`).join('');
      };
      $('#rq').addEventListener('input', render); render();
      bindMitre($('#rt'));
      $('#rt').addEventListener('click', (e) => { const tr = e.target.closest('tr[data-r]'); if (tr && !e.target.closest('[data-mitre]')) location.hash = `#/events?rule_id=${tr.dataset.r}`; });
    } else {
      const f = await api('/api/rules/files');
      const list = t === 'files' ? f.rules : f.yara;
      $('#tab').innerHTML = list.map((x) => `<div class="panel" style="margin-bottom:14px"><div class="panel-h"><h3 class="mono">${esc(x.name)}</h3></div><div class="panel-b"><pre class="code" style="max-height:420px;margin:0">${esc(x.content)}</pre></div></div>`).join('');
    }
  }
  $$('.tabs button', main).forEach((b) => b.addEventListener('click', () => tab(b.dataset.t)));
  $('#reload').addEventListener('click', async () => {
    try { const r = await api('/api/rules/reload', { method: 'POST' }); ok(`${r.rules} règles et ${r.yara} règles YARA chargées${r.yara_error ? ' — erreur YARA : ' + r.yara_error : ''}`); tab('list'); } catch (e) { fail(e); }
  });
  tab('list');
}

async function pModules(main) {
  main.innerHTML = `<div class="page-head"><div><h1>Modules &amp; agent</h1><p>État des collecteurs de l'agent local et du pipeline d'évènements.</p></div>
      <div class="actions"><button class="btn danger" id="restart">Redémarrer le service</button></div></div>
    <div class="kpis" id="bk"></div><div class="grid g3" id="mods"></div>`;
  async function load() {
    const d = await api('/api/modules');
    const b = d.bus;
    $('#bk').innerHTML = [
      kpi('Agent', esc(d.agent), 'macOS · local', 'var(--ok)'),
      kpi('Évènements traités', fmtN(b.events), 'depuis le démarrage'),
      kpi('Alertes générées', fmtN(b.alerts), 'depuis le démarrage', 'var(--warn)'),
      kpi('Évènements perdus', fmtN(b.dropped), 'file saturée', b.dropped ? 'var(--danger)' : 'var(--ok)'),
      kpi('Uptime', fmtDur(Date.now() / 1000 - b.started), 'service SentinelSIEM'),
    ].join('');
    $('#mods').innerHTML = d.modules.map((m) => `<div class="panel mod-card"><h4><span class="status-dot ${m.status === 'running' ? (m.last_error ? 'warn' : 'on') : 'off'}"></span>${esc(m.title)}<span class="spacer"></span><span class="tag mono">${esc(m.name)}</span></h4>
      <p>${esc(m.description)}</p>
      <div class="stats"><div><b>${fmtN(m.events)}</b>évènements</div><div><b>${m.status === 'running' ? 'Actif' : 'Arrêté'}</b>état</div><div><b>${fmtRel(m.last_run)}</b>dernière activité</div></div>
      ${m.last_error ? `<div class="warnbox">${esc(m.last_error)}</div>` : ''}${m.warnings.map((w) => `<div class="warnbox">${esc(w)}</div>`).join('')}</div>`).join('');
  }
  $('#restart').addEventListener('click', async () => {
    if (!confirm('Redémarrer le service SentinelSIEM ?')) return;
    await api('/api/system/restart', { method: 'POST' }).catch(() => {});
    ok('Redémarrage… la page va se recharger');
    setTimeout(() => location.reload(), 6000);
  });
  await load(); every(5000, load);
}

async function pSettings(main) {
  const s = await api('/api/settings');
  const row = (label, hint, input) => `<div class="form-row"><label><b>${label}</b><small>${hint}</small></label><div>${input}</div></div>`;
  main.innerHTML = `<div class="page-head"><div><h1>Paramètres</h1><p>Configuration de l'agent et du moteur de détection. Certains changements (chemins FIM, intervalles) nécessitent un redémarrage du service.</p></div>
      <div class="actions"><button class="btn" id="restart">Redémarrer le service</button><button class="btn primary" id="save">Enregistrer</button></div></div>
    <div class="grid g2">
      ${panel('Détection & réponse', `<div class="panel-b">
        ${row('Quarantaine automatique', 'Isoler les fichiers détectés par ClamAV / YARA (critique/élevé)', `<label class="switch"><input type="checkbox" id="auto_quarantine" ${s.auto_quarantine ? 'checked' : ''}><span></span></label>`)}
        ${row('Notifications macOS', 'Niveau minimal déclenchant une notification', `<input type="number" id="notify_min_level" min="0" max="16" value="${s.notify_min_level}" style="width:90px">`)}
        ${row('Rétention', 'Durée de conservation des alertes (jours)', `<input type="number" id="retention_days" min="1" value="${s.retention_days}" style="width:90px">`)}
        ${row('Seuil CPU (%)', 'Alerte si un processus dépasse ce seuil pendant 2 min', `<input type="number" id="cpu_alert_threshold" min="10" max="100" value="${s.cpu_alert_threshold}" style="width:90px">`)}
        ${row('Intervalle processus (s)', 'Fréquence de scrutation des processus', `<input type="number" id="process_poll_interval" min="1" value="${s.process_poll_interval}" style="width:90px">`)}
        ${row('Intervalle réseau (s)', 'Fréquence de scrutation des connexions', `<input type="number" id="network_poll_interval" min="5" value="${s.network_poll_interval}" style="width:90px">`)}
        ${row('Taille max. analysée (Mo)', 'Fichiers plus gros ignorés par l\'antimalware', `<input type="number" id="max_scan_size_mb" min="1" value="${s.max_scan_size_mb}" style="width:90px">`)}
      </div>`)}
      ${panel('Indicateurs de compromission (IOC)', `<div class="panel-b">
        <div class="section-t">Adresses IP malveillantes (une par ligne)</div><textarea id="ioc_ips">${esc((s.ioc_ips || []).join('\n'))}</textarea>
        <div class="section-t" style="margin-top:12px">Hashs SHA-256 malveillants (un par ligne)</div><textarea id="ioc_hashes">${esc((s.ioc_hashes || []).join('\n'))}</textarea>
        <div class="section-t" style="margin-top:12px">Ports suspects (séparés par des virgules)</div><input type="text" id="suspicious_ports" style="width:100%" value="${esc((s.suspicious_ports || []).join(', '))}">
      </div>`)}
    </div>
    <div class="grid g2">
      ${panel('Intégrité des fichiers', `<div class="panel-b"><div class="section-t">Répertoires surveillés (JSON)</div><textarea id="fim_paths" style="min-height:260px">${esc(JSON.stringify(s.fim_paths, null, 2))}</textarea>
        <div class="section-t" style="margin-top:12px">Exclusions (regex, une par ligne)</div><textarea id="fim_ignore">${esc((s.fim_ignore || []).join('\n'))}</textarea></div>`)}
      ${panel('Analyse antimalware temps réel', `<div class="panel-b"><div class="section-t">Emplacements analysés automatiquement (un par ligne)</div><textarea id="scan_paths" style="min-height:200px">${esc((s.scan_paths || []).join('\n'))}</textarea></div>`)}
    </div>
    ${panel('Compte administrateur', `<div class="panel-b"><div class="flex" style="flex-wrap:wrap"><input type="password" id="pw-cur" placeholder="Mot de passe actuel"><input type="password" id="pw-new" placeholder="Nouveau mot de passe (8+ car.)"><button class="btn" id="pw">Changer le mot de passe</button></div></div>`)}`;
  const lines = (id) => $(id).value.split('\n').map((x) => x.trim()).filter(Boolean);
  $('#save').addEventListener('click', async () => {
    let fimPaths;
    try { fimPaths = JSON.parse($('#fim_paths').value); } catch { return fail(new Error('JSON des répertoires FIM invalide')); }
    const body = {
      auto_quarantine: $('#auto_quarantine').checked,
      notify_min_level: +$('#notify_min_level').value, retention_days: +$('#retention_days').value,
      cpu_alert_threshold: +$('#cpu_alert_threshold').value, process_poll_interval: +$('#process_poll_interval').value,
      network_poll_interval: +$('#network_poll_interval').value, max_scan_size_mb: +$('#max_scan_size_mb').value,
      ioc_ips: lines('#ioc_ips'), ioc_hashes: lines('#ioc_hashes').map((h) => h.toLowerCase()),
      suspicious_ports: $('#suspicious_ports').value.split(',').map((x) => +x.trim()).filter(Boolean),
      fim_paths: fimPaths, fim_ignore: lines('#fim_ignore'), scan_paths: lines('#scan_paths'),
    };
    try { await api('/api/settings', { method: 'PUT', body }); ok('Paramètres enregistrés'); } catch (e) { fail(e); }
  });
  $('#pw').addEventListener('click', async () => {
    try { await api('/api/password', { method: 'POST', body: { current: $('#pw-cur').value, new: $('#pw-new').value } }); ok('Mot de passe modifié'); $('#pw-cur').value = $('#pw-new').value = ''; } catch (e) { fail(e); }
  });
  $('#restart').addEventListener('click', async () => {
    await api('/api/system/restart', { method: 'POST' }).catch(() => {});
    ok('Redémarrage…'); setTimeout(() => location.reload(), 6000);
  });
}

// ------------------------------------------------------------------ routeur
const PAGES = {
  overview: ["Vue d'ensemble", pOverview], events: ['Événements de sécurité', pEvents], hunting: ['Chasse aux menaces', pHunting],
  mitre: ['MITRE ATT&CK', pMitre], malware: ['Détection de malwares', pMalware], fim: ['Intégrité des fichiers', pFim],
  sca: ['Évaluation de la configuration', pSca], processes: ['Processus', pProcesses], network: ['Réseau', pNetwork],
  persistence: ['Persistance', pPersistence], inventory: ['Inventaire système', pInventory], rules: ['Règles', pRules],
  modules: ['Modules & agent', pModules], settings: ['Paramètres', pSettings],
};

function cleanup() {
  state.charts.forEach((c) => c.destroy()); state.charts = [];
  state.timers.forEach(clearInterval); state.timers = [];
  state.onAlert = null;
  closeFly();
}

async function route() {
  cleanup();
  const h = location.hash.replace(/^#\/?/, '');
  const name = h.split('?')[0] || 'overview';
  const [title, fn] = PAGES[name] || PAGES.overview;
  $$('#nav a').forEach((a) => a.classList.toggle('active', a.dataset.page === name));
  $('#crumbs').innerHTML = `<span>SentinelSIEM</span><span>›</span><b>${esc(title)}</b>`;
  document.title = `${title} · SentinelSIEM`;
  if (name === 'events') { state.newCount = 0; updBadge(); }
  const main = $('#main');
  main.innerHTML = '<div class="empty">Chargement…</div>';
  main.scrollTop = 0;
  try { await fn(main, hashParams()); } catch (e) { fail(e); }
}

function updBadge() {
  const b = $('#new-count');
  b.textContent = state.newCount > 99 ? '99+' : state.newCount;
  b.classList.toggle('hide', !state.newCount);
}

// ------------------------------------------------------------------ temps réel
function connectWS() {
  const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`);
  state.ws = ws;
  ws.onopen = () => { $('#live').classList.add('on'); $('#live-t').textContent = 'Temps réel'; };
  ws.onclose = () => { $('#live').classList.remove('on'); $('#live-t').textContent = 'Reconnexion…'; setTimeout(connectWS, 3000); };
  ws.onmessage = (m) => {
    const msg = JSON.parse(m.data);
    if (msg.type !== 'alert') return;
    const a = msg.alert;
    if (a.level >= 7 && !location.hash.startsWith('#/events')) { state.newCount++; updBadge(); }
    if (a.level >= 10) toast(`Niveau ${a.level} · ${modName(a.module)}`, a.description, a.level >= 12 ? 'crit' : 'high', () => showAlert(a.id));
    if (state.onAlert) state.onAlert(a);
  };
  setInterval(() => { if (ws.readyState === 1) ws.send('ping'); }, 30000);
}

// ------------------------------------------------------------------ init
(async function init() {
  $$('#range button').forEach((b) => {
    b.classList.toggle('on', +b.dataset.h === state.hours);
    b.addEventListener('click', () => {
      state.hours = +b.dataset.h; lsSet('siem-hours', state.hours);
      $$('#range button').forEach((x) => x.classList.toggle('on', x === b));
      route();
    });
  });
  $('#theme').addEventListener('click', () => {
    const t = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
    document.documentElement.dataset.theme = t; lsSet('siem-theme', t); route();
  });
  $('#logout').addEventListener('click', async () => { await api('/api/logout', { method: 'POST' }).catch(() => {}); location.href = '/login'; });
  try { const me = await api('/api/me'); $('#who').textContent = `${me.user}@${me.agent}`; } catch { return; }
  window.addEventListener('hashchange', route);
  connectWS();
  route();
})();

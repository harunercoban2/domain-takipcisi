'use strict';

const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
const DAY = 86400000;

const state = {
  domains: [],
  filter: 'all',
  search: '',
  sort: { key: 'days', dir: 'asc' },
  threshold: Number(localStorage.getItem('threshold')) || 30,
  busy: new Set(),
};

// ------------------------------------------------------------ API

async function api(path, opts = {}) {
  const res = await fetch(path, {
    method: opts.method || 'GET',
    headers: opts.body ? { 'Content-Type': 'application/json' } : {},
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Hata (${res.status})`);
  return data;
}

async function load() {
  state.domains = await api('/api/domains');
  render();
}

// ------------------------------------------------------------ Yardımcılar

function daysLeft(d) {
  if (!d.expiry) return null;
  const e = new Date(d.expiry);
  const today = new Date();
  const a = Date.UTC(e.getUTCFullYear(), e.getUTCMonth(), e.getUTCDate());
  const b = Date.UTC(today.getFullYear(), today.getMonth(), today.getDate());
  return Math.round((a - b) / DAY);
}

function statusOf(d) {
  const n = daysLeft(d);
  if (n === null) return 'unknown';
  if (n < 0) return 'expired';
  if (n <= state.threshold) return 'soon';
  return 'ok';
}

const fmtDate = (iso) => iso
  ? new Date(iso).toLocaleDateString('tr-TR', { day: '2-digit', month: 'short', year: 'numeric', timeZone: 'UTC' })
  : '—';

function fmtRelative(iso) {
  if (!iso) return 'hiç';
  const diff = Date.now() - Date.parse(iso);
  const m = Math.round(diff / 60000);
  if (m < 1) return 'az önce';
  if (m < 60) return `${m} dk önce`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h} sa önce`;
  return `${Math.round(h / 24)} gün önce`;
}

function badgeText(n) {
  if (n === null) return 'Bilinmiyor';
  if (n < 0) return `${-n} gün geçti`;
  if (n === 0) return 'Bugün!';
  if (n === 1) return 'Yarın';
  if (n < 60) return `${n} gün`;
  if (n < 730) return `${n} gün`;
  return `${(n / 365).toFixed(1).replace('.', ',')} yıl`;
}

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

let toastTimer;
function toast(msg, ms = 3200) {
  const t = $('#toast');
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toastTimer);
  if (ms) toastTimer = setTimeout(() => (t.hidden = true), ms);
}

// ------------------------------------------------------------ Çizim

function render() {
  const counts = { all: 0, expired: 0, soon: 0, ok: 0, unknown: 0 };
  for (const d of state.domains) { counts.all++; counts[statusOf(d)]++; }
  $('#sTotal').textContent = counts.all;
  $('#sExpired').textContent = counts.expired;
  $('#sSoon').textContent = counts.soon;
  $('#sOk').textContent = counts.ok;
  $('#sUnknown').textContent = counts.unknown;
  $('#sSoonLabel').textContent = state.threshold;
  $$('.stat').forEach((b) => b.classList.toggle('active', b.dataset.filter === state.filter && state.filter !== 'all'));
  $$('#filterSeg button').forEach((b) => b.classList.toggle('on', b.dataset.filter === state.filter));

  const q = state.search.toLowerCase();
  let rows = state.domains.filter((d) => {
    if (state.filter !== 'all' && statusOf(d) !== state.filter) return false;
    if (!q) return true;
    return [d.name, d.displayName, d.registrar, d.note, ...(d.tags || [])].some((v) => v && v.toLowerCase().includes(q));
  });

  const { key, dir } = state.sort;
  const val = (d) => {
    switch (key) {
      case 'name': return d.displayName || d.name;
      case 'registrar': return (d.registrar || '￿').toLowerCase();
      case 'checked': return d.lastChecked || '';
      case 'expiry':
      case 'days': { const n = daysLeft(d); return n === null ? Infinity : n; }
    }
  };
  rows.sort((a, b) => {
    const x = val(a), y = val(b);
    const r = typeof x === 'string' ? x.localeCompare(y, 'tr') : x - y;
    return dir === 'asc' ? r : -r;
  });

  $$('th[data-sort]').forEach((th) => {
    th.classList.toggle('sorted', th.dataset.sort === key);
    th.classList.toggle('desc', th.dataset.sort === key && dir === 'desc');
  });

  $('#empty').hidden = state.domains.length > 0;
  if (state.domains.length && !rows.length) {
    $('#tbody').innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:30px">Eşleşen alan adı yok.</td></tr>`;
    return;
  }

  $('#tbody').innerHTML = rows.map((d) => {
    const n = daysLeft(d);
    const st = statusOf(d);
    const busy = state.busy.has(d.id);
    const pct = n === null ? 0 : Math.max(2, Math.min(100, (n / 365) * 100));
    const shown = d.displayName || d.name;
    return `<tr data-id="${d.id}">
      <td>
        <div class="dn"><a href="https://${esc(d.name)}" target="_blank" rel="noopener">${esc(shown)}</a></div>
        ${shown !== d.name ? `<div class="sub">${esc(d.name)}</div>` : ''}
        ${(d.tags || []).map((t) => `<span class="tag">${esc(t)}</span>`).join('')}
        ${d.error ? `<div class="err">⚠ ${esc(d.error)}</div>` : ''}
      </td>
      <td>
        ${busy ? `<span class="badge loading">Sorgulanıyor…</span>` : `<span class="badge ${st}">${badgeText(n)}</span>`}
        ${!busy && d.expiry ? `<div class="date-sm">${fmtDate(d.expiry)}</div>` : ''}
        ${!busy && n !== null && n >= 0 ? `<div class="bar" style="color:var(--${st === 'ok' ? 'ok' : st === 'soon' ? 'warn' : 'danger'})"><i style="width:${pct}%"></i></div>` : ''}
      </td>
      <td class="hide-sm">
        <div class="date">${fmtDate(d.expiry)}</div>
        ${d.source ? `<div class="src">${d.source === 'manual' ? 'Elle girildi' : esc(String(d.source).toLocaleUpperCase('en'))}</div>` : ''}
      </td>
      <td class="hide-sm">${esc(d.registrar || '—')}</td>
      <td class="hide-md"><div class="note" title="${esc(d.note)}">${esc(d.note || '')}</div></td>
      <td class="hide-md" title="${d.lastChecked ? new Date(d.lastChecked).toLocaleString('tr-TR') : ''}"><span class="sub">${fmtRelative(d.lastChecked)}</span></td>
      <td>
        <div class="actions">
          <button class="icon-btn ${busy ? 'spin' : ''}" data-act="refresh" title="Yeniden sorgula">↻</button>
          <button class="icon-btn" data-act="edit" title="Düzenle">✎</button>
          <button class="icon-btn del" data-act="delete" title="Sil">🗑</button>
        </div>
      </td>
    </tr>`;
  }).join('');
}

// ------------------------------------------------------------ Eylemler

async function addDomains(text) {
  const list = text.split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean);
  if (!list.length) return;
  const btn = $('#addBtn');
  btn.disabled = true;
  btn.textContent = 'Sorgulanıyor…';
  toast(`${list.length} alan adı sorgulanıyor…`, 0);
  try {
    const { added, skipped } = await api('/api/domains', { method: 'POST', body: { domains: list } });
    await load();
    const msgs = [];
    if (added.length) msgs.push(`${added.length} alan adı eklendi`);
    if (skipped.length) msgs.push(`${skipped.length} atlandı (${[...new Set(skipped.map((s) => s.reason.toLowerCase()))].join(', ')})`);
    toast(msgs.join(' · ') || 'Değişiklik yok');
    if (added.length) $('#addInput').value = '';
    autosize();
  } catch (e) {
    toast('Hata: ' + e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Ekle ve sorgula';
  }
}

async function refreshOne(id) {
  state.busy.add(id); render();
  try {
    const rec = await api(`/api/domains/${id}/refresh`, { method: 'POST' });
    const i = state.domains.findIndex((d) => d.id === id);
    if (i >= 0) state.domains[i] = rec;
    toast(rec.error ? `${rec.displayName || rec.name}: ${rec.error}` : `${rec.displayName || rec.name} güncellendi`);
  } catch (e) {
    toast('Hata: ' + e.message);
  } finally {
    state.busy.delete(id); render();
  }
}

async function refreshAll() {
  if (!state.domains.length) return;
  const btn = $('#refreshAllBtn');
  btn.disabled = true;
  // Tek tek yenile ki ilerleme görünsün
  let i = 0;
  for (const d of [...state.domains]) {
    i++;
    btn.textContent = `↻ ${i}/${state.domains.length}`;
    state.busy.add(d.id); render();
    try {
      const rec = await api(`/api/domains/${d.id}/refresh`, { method: 'POST' });
      const k = state.domains.findIndex((x) => x.id === d.id);
      if (k >= 0) state.domains[k] = rec;
    } catch { /* devam */ }
    state.busy.delete(d.id); render();
  }
  btn.disabled = false;
  btn.textContent = '↻ Tümünü yenile';
  toast('Tüm alan adları güncellendi');
}

async function removeOne(id) {
  const d = state.domains.find((x) => x.id === id);
  if (!d || !confirm(`"${d.displayName || d.name}" listeden silinsin mi?`)) return;
  await api(`/api/domains/${id}`, { method: 'DELETE' });
  state.domains = state.domains.filter((x) => x.id !== id);
  render();
  toast('Silindi');
}

let editingId = null;
function openEdit(id) {
  const d = state.domains.find((x) => x.id === id);
  if (!d) return;
  editingId = id;
  $('#editTitle').textContent = d.displayName || d.name;
  $('#editExpiry').value = d.expiry ? d.expiry.slice(0, 10) : '';
  $('#editRegistrar').value = d.registrar || '';
  $('#editTags').value = (d.tags || []).join(', ');
  $('#editNote').value = d.note || '';
  const det = [];
  if (d.created) det.push(`<div>Kayıt tarihi: <b>${fmtDate(d.created)}</b></div>`);
  if (d.nameservers?.length) det.push(`<div>DNS: <b>${d.nameservers.map(esc).join(', ')}</b></div>`);
  if (d.status?.length) det.push(`<div>Durum: <b>${d.status.map(esc).join(', ')}</b></div>`);
  det.push(`<div>Eklenme: <b>${fmtDate(d.addedAt)}</b> · Son kontrol: <b>${fmtRelative(d.lastChecked)}</b></div>`);
  $('#editDetails').innerHTML = det.join('');
  $('#editDialog').showModal();
}

async function saveEdit() {
  if (!editingId) return;
  try {
    const rec = await api(`/api/domains/${editingId}`, {
      method: 'PUT',
      body: {
        expiry: $('#editExpiry').value || null,
        registrar: $('#editRegistrar').value,
        tags: $('#editTags').value,
        note: $('#editNote').value,
      },
    });
    const i = state.domains.findIndex((d) => d.id === editingId);
    if (i >= 0) state.domains[i] = rec;
    render();
    toast('Kaydedildi');
  } catch (e) {
    toast('Hata: ' + e.message);
  }
}

// ------------------------------------------------------------ Dışa / içe aktarma

function download(name, content, type) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([content], { type }));
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

const stamp = () => new Date().toISOString().slice(0, 10);

function exportCsv() {
  const q = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const rows = [['Alan adı', 'Bitiş tarihi', 'Kalan gün', 'Durum', 'Kayıt firması', 'Etiketler', 'Not', 'Son kontrol']];
  const lbl = { expired: 'Süresi dolmuş', soon: 'Yaklaşıyor', ok: 'Güvende', unknown: 'Bilinmiyor' };
  for (const d of state.domains) {
    rows.push([d.displayName || d.name, d.expiry ? d.expiry.slice(0, 10) : '', daysLeft(d) ?? '', lbl[statusOf(d)],
      d.registrar || '', (d.tags || []).join(', '), d.note || '', d.lastChecked ? d.lastChecked.slice(0, 16).replace('T', ' ') : '']);
  }
  download(`domainler-${stamp()}.csv`, '﻿' + rows.map((r) => r.map(q).join(';')).join('\r\n'), 'text/csv;charset=utf-8');
}

function exportIcs() {
  const withDate = state.domains.filter((d) => d.expiry);
  if (!withDate.length) return toast('Bitiş tarihi bilinen alan adı yok');
  const ymd = (dt) => dt.toISOString().slice(0, 10).replace(/-/g, '');
  const now = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d+/, '');
  const lines = ['BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//Domain Takipcisi//TR', 'CALSCALE:GREGORIAN', 'X-WR-CALNAME:Alan Adı Bitişleri'];
  for (const d of withDate) {
    const e = new Date(d.expiry);
    const next = new Date(e.getTime() + DAY);
    const name = d.displayName || d.name;
    lines.push('BEGIN:VEVENT', `UID:${d.id}@domaintakip`, `DTSTAMP:${now}`,
      `DTSTART;VALUE=DATE:${ymd(e)}`, `DTEND;VALUE=DATE:${ymd(next)}`,
      `SUMMARY:⚠ ${name} alan adının süresi doluyor`,
      `DESCRIPTION:${name} alan adının bitiş tarihi. Kayıt firması: ${(d.registrar || 'bilinmiyor').replace(/[,;]/g, ' ')}`,
      'BEGIN:VALARM', 'ACTION:DISPLAY', `DESCRIPTION:${name} 30 gün sonra doluyor`, 'TRIGGER:-P30D', 'END:VALARM',
      'BEGIN:VALARM', 'ACTION:DISPLAY', `DESCRIPTION:${name} 7 gün sonra doluyor`, 'TRIGGER:-P7D', 'END:VALARM',
      'END:VEVENT');
  }
  lines.push('END:VCALENDAR');
  download(`domain-bitisleri-${stamp()}.ics`, lines.join('\r\n'), 'text/calendar;charset=utf-8');
  toast(`${withDate.length} hatırlatıcı takvim dosyasına eklendi`);
}

function exportJson() {
  download(`domain-yedek-${stamp()}.json`, JSON.stringify({ exportedAt: new Date().toISOString(), domains: state.domains }, null, 2), 'application/json');
}

async function importJson(file) {
  try {
    const data = JSON.parse(await file.text());
    const { imported } = await api('/api/import', { method: 'POST', body: data });
    await load();
    toast(`${imported} alan adı geri yüklendi`);
  } catch (e) {
    toast('Yedek okunamadı: ' + e.message);
  }
}

// ------------------------------------------------------------ Olaylar

function autosize() {
  const t = $('#addInput');
  t.style.height = 'auto';
  t.style.height = Math.min(t.scrollHeight + 2, 240) + 'px';
}

function setFilter(f) { state.filter = f; render(); }

$('#addForm').addEventListener('submit', (e) => { e.preventDefault(); addDomains($('#addInput').value); });
$('#addInput').addEventListener('input', autosize);
$('#addInput').addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); $('#addForm').requestSubmit(); }
});
$('#addInput').addEventListener('paste', () => setTimeout(autosize));

$('#search').addEventListener('input', (e) => { state.search = e.target.value; render(); });
$$('#filterSeg button').forEach((b) => b.addEventListener('click', () => setFilter(b.dataset.filter)));
$$('.stat').forEach((b) => b.addEventListener('click', () => setFilter(state.filter === b.dataset.filter ? 'all' : b.dataset.filter)));

$('#threshold').value = String(state.threshold);
if (!$('#threshold').value) $('#threshold').value = '30';
$('#threshold').addEventListener('change', (e) => {
  state.threshold = Number(e.target.value);
  localStorage.setItem('threshold', state.threshold);
  render();
});

$$('th[data-sort]').forEach((th) => th.addEventListener('click', () => {
  const k = th.dataset.sort;
  state.sort = state.sort.key === k ? { key: k, dir: state.sort.dir === 'asc' ? 'desc' : 'asc' } : { key: k, dir: 'asc' };
  render();
}));

$('#tbody').addEventListener('click', (e) => {
  const btn = e.target.closest('[data-act]');
  if (!btn) return;
  const id = btn.closest('tr').dataset.id;
  if (btn.dataset.act === 'refresh') refreshOne(id);
  if (btn.dataset.act === 'edit') openEdit(id);
  if (btn.dataset.act === 'delete') removeOne(id);
});
$('#tbody').addEventListener('dblclick', (e) => {
  const tr = e.target.closest('tr[data-id]');
  if (tr && !e.target.closest('a,button')) openEdit(tr.dataset.id);
});

$('#editDialog').addEventListener('close', () => {
  if ($('#editDialog').returnValue === 'save') saveEdit();
  editingId = null;
});

$('#refreshAllBtn').addEventListener('click', refreshAll);

$('#menuBtn').addEventListener('click', (e) => { e.stopPropagation(); $('#menuList').hidden = !$('#menuList').hidden; });
document.addEventListener('click', () => ($('#menuList').hidden = true));
$('#menuList').addEventListener('click', (e) => {
  const act = e.target.dataset.act;
  if (act === 'csv') exportCsv();
  if (act === 'ics') exportIcs();
  if (act === 'json') exportJson();
  if (act === 'import') $('#importFile').click();
});
$('#importFile').addEventListener('change', (e) => { if (e.target.files[0]) importJson(e.target.files[0]); e.target.value = ''; });

// Açık sekmede, arka plandaki otomatik yenilemeleri yansıtmak için ara ara yeniden yükle
setInterval(() => { if (!state.busy.size && !document.hidden && !$('#editDialog').open) load().catch(() => {}); }, 5 * 60000);

load().catch((e) => toast('Sunucuya bağlanılamadı: ' + e.message, 0));

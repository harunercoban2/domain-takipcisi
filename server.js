// Domain Takipçisi — alan adı bitiş tarihlerini takip eden küçük web uygulaması.
// Bağımlılık yok: Node.js 18+ yeterli. Çalıştırma: `node server.js`, sonra http://localhost:3000

const http = require('http');
const fs = require('fs');
const path = require('path');
const net = require('net');
const url = require('url');
const crypto = require('crypto');

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '127.0.0.1';
const DATA_DIR = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'domains.json');
const PUBLIC_DIR = path.join(__dirname, 'public');
const AUTO_REFRESH_HOURS = Number(process.env.AUTO_REFRESH_HOURS) || 24;

// ---------------------------------------------------------------- Depolama

function loadDb() {
  let raw;
  try {
    raw = fs.readFileSync(DATA_FILE, 'utf8');
  } catch (e) {
    if (e.code === 'ENOENT') return { domains: [] }; // ilk çalıştırma
    throw e;
  }
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || !Array.isArray(parsed.domains)) throw new Error('domains dizisi yok');
    return parsed;
  } catch (e) {
    // Bozuk dosyanın üzerine boş liste yazıp veriyi kaybetmemek için önce yedeğini al.
    const backup = `${DATA_FILE}.bozuk-${Date.now()}`;
    fs.copyFileSync(DATA_FILE, backup);
    console.error(`  ⚠ ${DATA_FILE} okunamadı (${e.message}). Yedeği: ${backup}`);
    return { domains: [] };
  }
}

let db = loadDb();

function saveDb() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DATA_FILE);
}

// ---------------------------------------------------------------- Alan adı yardımcıları

function normalizeDomain(input) {
  let s = String(input || '').trim().toLowerCase();
  if (!s) return null;
  s = s.replace(/^[a-z]+:\/\//, '');      // protokol
  s = s.split(/[\/?#\s]/)[0];             // yol, sorgu
  s = s.replace(/^.*@/, '');              // kullanıcı bilgisi
  s = s.replace(/:\d+$/, '');             // port
  s = s.replace(/^www\./, '');
  s = s.replace(/\.+$/, '');
  if (!s.includes('.')) return null;
  const ascii = url.domainToASCII(s);     // IDN → punycode (ör. türkçe.com)
  if (!ascii || !/^[a-z0-9.-]+$/.test(ascii)) return null;
  if (ascii.length > 253 || ascii.split('.').some((p) => !p || p.length > 63 || p.startsWith('-') || p.endsWith('-'))) return null;
  if (!/[a-z]/.test(tldOf(ascii))) return null; // IP adresi ya da sayısal uzantı
  return { ascii, unicode: url.domainToUnicode(ascii) || ascii };
}

function tldOf(domain) {
  return domain.split('.').pop();
}

// ---------------------------------------------------------------- RDAP

let rdapBootstrap = null;
let rdapBootstrapAt = 0;

async function fetchJson(target, timeoutMs = 12000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(target, {
      signal: ctrl.signal,
      headers: { Accept: 'application/rdap+json, application/json' },
      redirect: 'follow',
    });
    if (!res.ok) {
      const err = new Error(`HTTP ${res.status}`);
      err.status = res.status;
      throw err;
    }
    return await res.json();
  } finally {
    clearTimeout(t);
  }
}

async function getRdapBase(tld) {
  if (!rdapBootstrap || Date.now() - rdapBootstrapAt > 24 * 3600e3) {
    try {
      rdapBootstrap = await fetchJson('https://data.iana.org/rdap/dns.json');
      rdapBootstrapAt = Date.now();
    } catch {
      if (!rdapBootstrap) return null;
    }
  }
  for (const [tlds, urls] of rdapBootstrap.services || []) {
    if (tlds.includes(tld)) {
      return urls.find((u) => u.startsWith('https')) || urls[0];
    }
  }
  return null;
}

function vcardName(entity) {
  const arr = entity && entity.vcardArray && entity.vcardArray[1];
  if (!Array.isArray(arr)) return null;
  const fn = arr.find((x) => x[0] === 'fn') || arr.find((x) => x[0] === 'org');
  return fn ? String(fn[3]).trim() || null : null;
}

async function lookupRdap(domain) {
  const base = await getRdapBase(tldOf(domain));
  if (!base) return null;
  const data = await fetchJson(base.replace(/\/?$/, '/') + 'domain/' + domain);
  const ev = (name) => {
    const e = (data.events || []).find((x) => x.eventAction === name);
    const t = e ? Date.parse(e.eventDate) : NaN;
    return Number.isNaN(t) ? null : new Date(t).toISOString();
  };
  let registrar = null;
  for (const ent of data.entities || []) {
    if ((ent.roles || []).includes('registrar')) {
      registrar = vcardName(ent) || (ent.publicIds && ent.publicIds[0] && `IANA #${ent.publicIds[0].identifier}`);
      break;
    }
  }
  return {
    expiry: ev('expiration'),
    created: ev('registration'),
    updated: ev('last changed'),
    registrar,
    status: data.status || [],
    nameservers: (data.nameservers || []).map((n) => (n.ldhName || '').toLowerCase()).filter(Boolean),
    source: 'rdap',
  };
}

// ---------------------------------------------------------------- WHOIS (RDAP yoksa yedek)

function whoisQuery(server, query, timeoutMs = 12000) {
  return new Promise((resolve, reject) => {
    let out = '';
    const sock = net.createConnection({ host: server, port: 43 });
    sock.setTimeout(timeoutMs);
    sock.on('connect', () => sock.write(query + '\r\n'));
    sock.on('data', (d) => {
      out += d.toString('utf8');
      if (out.length > WHOIS_MAX_BYTES) sock.destroy(); // aşırı büyük yanıtı kes
    });
    sock.on('end', () => resolve(out));
    sock.on('close', () => resolve(out));
    sock.on('timeout', () => { sock.destroy(); reject(new Error('WHOIS zaman aşımı')); });
    sock.on('error', reject);
  });
}

const WHOIS_MAX_BYTES = 256 * 1024;
const HOSTNAME_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i;

const whoisServerCache = {};
async function whoisServerFor(tld) {
  if (whoisServerCache[tld] !== undefined) return whoisServerCache[tld];
  const txt = await whoisQuery('whois.iana.org', tld);
  const m = txt.match(/^\s*(?:whois|refer):\s*(\S+)/im);
  whoisServerCache[tld] = m && HOSTNAME_RE.test(m[1]) ? m[1] : null;
  return whoisServerCache[tld];
}

const MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11,
  oca: 0, şub: 1, sub: 1, nis: 3, haz: 5, tem: 6, ağu: 7, agu: 7, eyl: 8, eki: 9, kas: 10, ara: 11 };

function parseLooseDate(raw) {
  if (!raw) return null;
  let s = String(raw).trim().replace(/\.$/, '').replace(/\s*\(.*\)$/, '');
  let m;
  const mk = (y, mo, d) => {
    const dt = new Date(Date.UTC(+y, mo, +d));
    if (isNaN(dt) || +y < 1985 || +y > 2200) return null;
    if (dt.getUTCMonth() !== mo || dt.getUTCDate() !== +d) return null; // ör. 2027-13-45 ya da 31 Şubat
    return dt.toISOString();
  };
  if ((m = s.match(/^(\d{4})[-.\/](\d{1,2})[-.\/](\d{1,2})(?:$|[T\s])/))) {
    const full = Date.parse(s.replace(' ', 'T'));
    if (!isNaN(full) && /T|\d:\d/.test(s)) return new Date(full).toISOString();
    return mk(m[1], +m[2] - 1, m[3]);
  }
  if ((m = s.match(/^(\d{1,2})[-.\/](\d{1,2})[-.\/](\d{4})/))) return mk(m[3], +m[2] - 1, m[1]);
  if ((m = s.match(/^(\d{4})-([a-zçğıöşü]{3})[a-z]*-(\d{1,2})/i))) {
    const mo = MONTHS[m[2].toLowerCase()];
    if (mo !== undefined) return mk(m[1], mo, m[3]);
  }
  if ((m = s.match(/^(\d{1,2})[-\s]([a-zçğıöşü]{3})[a-z]*[-\s,]+(\d{4})/i))) {
    const mo = MONTHS[m[2].toLowerCase()];
    if (mo !== undefined) return mk(m[3], mo, m[1]);
  }
  if ((m = s.match(/^(\d{4})(\d{2})(\d{2})$/))) return mk(m[1], +m[2] - 1, m[3]);
  const p = Date.parse(s);
  return isNaN(p) ? null : new Date(p).toISOString();
}

function whoisField(txt, labels) {
  for (const label of labels) {
    const re = new RegExp('^\\s*' + label + '\\s*[.:]*\\s*[:.]\\s*(.+)$', 'im');
    const m = txt.match(re);
    if (m && m[1].trim()) return m[1].trim();
  }
  return null;
}

function parseWhois(txt) {
  const expiryRaw = whoisField(txt, [
    'Registry Expiry Date', 'Registrar Registration Expiration Date', 'Expiration Date', 'Expiry Date',
    'Expires on', 'Expires On', 'Expire Date', 'Expiration Time', 'paid-till', 'Valid Until', 'Expires',
    'expire', 'Renewal Date', 'renewal date', 'Domain Expiration Date', 'Bitiş Tarihi',
  ]);
  const createdRaw = whoisField(txt, [
    'Creation Date', 'Created On', 'Created on', 'Registration Time', 'Registered on', 'created',
    'Domain Registration Date', 'Oluşturulma Tarihi',
  ]);
  let registrar = whoisField(txt, ['Registrar', 'Sponsoring Registrar', 'registrar', 'Organization Name']);
  if (!registrar) {
    const m = txt.match(/\*\*\s*Registrar:\s*\n(?:.*\n)*?\s*Organization Name\s*:\s*(.+)/i);
    if (m) registrar = m[1].trim();
  }
  const ns = [...txt.matchAll(/^\s*(?:Name Server|nserver|Nameserver)s?\s*:\s*(\S+)/gim)].map((m) => m[1].toLowerCase());
  return {
    expiry: parseLooseDate(expiryRaw),
    created: parseLooseDate(createdRaw),
    registrar,
    nameservers: [...new Set(ns)],
    notFound: /no match|not found|no data found|no entries found|status:\s*free|is available|no object found/i.test(txt),
  };
}

async function lookupWhois(domain) {
  const server = await whoisServerFor(tldOf(domain));
  if (!server) return null;
  const query = server === 'whois.denic.de' ? `-T dn ${domain}` : domain;
  let txt = await whoisQuery(server, query);
  let parsed = parseWhois(txt);
  // İnce kayıt (thin) — kayıt firmasının WHOIS sunucusuna yönlendirme
  const refer = whoisField(txt, ['Registrar WHOIS Server', 'Whois Server']);
  const referHost = refer && refer.replace(/^[a-z]+:\/\//i, '').replace(/[\/:].*$/, '');
  if (!parsed.expiry && referHost && referHost !== server && HOSTNAME_RE.test(referHost)) {
    try {
      txt = await whoisQuery(referHost, domain);
      const p2 = parseWhois(txt);
      parsed = { ...parsed, ...Object.fromEntries(Object.entries(p2).filter(([, v]) => v && (!Array.isArray(v) || v.length))) };
    } catch { /* yoksay */ }
  }
  if (parsed.notFound && !parsed.expiry) {
    const e = new Error('Alan adı kayıtlı görünmüyor (boşta olabilir)');
    e.notFound = true;
    throw e;
  }
  return { ...parsed, status: [], source: 'whois' };
}

async function lookupDomain(domain) {
  let rdapErr = null;
  try {
    const r = await lookupRdap(domain);
    if (r && r.expiry) return r;
    if (r) rdapErr = new Error('RDAP bitiş tarihi vermedi');
  } catch (e) {
    rdapErr = e;
    if (e.status === 404) {
      const nf = new Error('Alan adı kayıtlı görünmüyor (boşta olabilir)');
      nf.notFound = true;
      throw nf;
    }
  }
  try {
    const w = await lookupWhois(domain);
    if (w) return w;
  } catch (e) {
    if (e.notFound) throw e;
    throw new Error(`Sorgulanamadı: ${e.message}${rdapErr ? ' / RDAP: ' + rdapErr.message : ''}`);
  }
  throw rdapErr || new Error('Bu uzantı için sorgu sunucusu bulunamadı');
}

async function refreshRecord(rec) {
  rec.lastChecked = new Date().toISOString();
  try {
    const info = await lookupDomain(rec.name);
    rec.error = null;
    if (info.expiry) { rec.expiry = info.expiry; rec.manualExpiry = false; }
    for (const k of ['created', 'registrar', 'source']) if (info[k]) rec[k] = info[k];
    if (info.status && info.status.length) rec.status = info.status;
    if (info.nameservers && info.nameservers.length) rec.nameservers = info.nameservers;
    if (!info.expiry && !rec.expiry) rec.error = 'Bitiş tarihi bulunamadı — elle girebilirsiniz';
  } catch (e) {
    rec.error = e.message || String(e);
  }
  return rec;
}

// ---------------------------------------------------------------- HTTP

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy':
    "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; " +
    "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
};

function send(res, code, body, type = 'application/json; charset=utf-8') {
  const data = typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body);
  res.writeHead(code, { ...SECURITY_HEADERS, 'Content-Type': type, 'Cache-Control': 'no-store' });
  res.end(data);
}

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

const MAX_BODY_BYTES = 2 * 1024 * 1024;

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let done = false;
    const fail = (err) => { if (!done) { done = true; reject(err); } };
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        fail(new HttpError(413, 'İstek çok büyük (en fazla 2 MB)'));
        req.resume(); // kalan veriyi boşalt, bağlantı askıda kalmasın
        return;
      }
      if (!done) chunks.push(c);
    });
    req.on('end', () => {
      if (done) return;
      done = true;
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw) return resolve({});
      try { resolve(JSON.parse(raw)); } catch { reject(new HttpError(400, 'Geçersiz JSON')); }
    });
    req.on('error', fail);
  });
}

// DNS rebinding ve CSRF koruması: API yalnızca bu uygulamanın kendi sayfasından çağrılabilir.
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);
const isLoopbackBind = ['127.0.0.1', 'localhost', '::1'].includes(HOST);

function hostnameOf(hostHeader) {
  const m = String(hostHeader || '').toLowerCase().match(/^(\[[^\]]+\]|[^:]+)(?::\d+)?$/);
  return m ? m[1] : null;
}

function checkRequestOrigin(req) {
  const host = String(req.headers.host || '').toLowerCase();
  const hostname = hostnameOf(host);
  if (!hostname) throw new HttpError(400, 'Geçersiz Host başlığı');
  // Yalnız yerelde dinlerken: başka bir alan adı bu adrese yönlendirilmişse (DNS rebinding) reddet.
  if (isLoopbackBind && !LOOPBACK_HOSTS.has(hostname) && !hostname.endsWith('.localhost')) {
    throw new HttpError(403, 'Yalnızca localhost üzerinden erişilebilir');
  }
  // Tarayıcılar başka sitelerden gelen isteklerde Origin gönderir; kendi adresimiz değilse reddet.
  const origin = req.headers.origin;
  if (origin) {
    let o;
    try { o = new URL(origin); } catch { throw new HttpError(403, 'Geçersiz Origin'); }
    if (o.host.toLowerCase() !== host) throw new HttpError(403, 'Başka bir siteden gelen istek reddedildi');
  }
  if (req.headers['sec-fetch-site'] && !['same-origin', 'none'].includes(req.headers['sec-fetch-site'])) {
    throw new HttpError(403, 'Başka bir siteden gelen istek reddedildi');
  }
}

function parseExpiryInput(value) {
  if (!value) return null;
  const iso = parseLooseDate(value);
  if (!iso) throw new HttpError(400, `Geçersiz tarih: ${String(value).slice(0, 40)}`);
  return iso;
}

const strList = (v, max, len) => (Array.isArray(v) ? v : [])
  .filter((x) => typeof x === 'string' && x.trim()).map((x) => x.trim().slice(0, len)).slice(0, max);
const isoOrNull = (v) => {
  const t = typeof v === 'string' ? Date.parse(v) : NaN;
  return Number.isNaN(t) ? null : new Date(t).toISOString();
};

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.json': 'application/json' };

function serveStatic(req, res, pathname) {
  if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, 'İzin verilmeyen yöntem', 'text/plain; charset=utf-8');
  const file = path.normalize(path.join(PUBLIC_DIR, pathname === '/' ? 'index.html' : pathname));
  if (!file.startsWith(PUBLIC_DIR + path.sep)) return send(res, 403, 'Yasak', 'text/plain; charset=utf-8');
  fs.readFile(file, (err, buf) => {
    if (err) return send(res, 404, 'Bulunamadı', 'text/plain; charset=utf-8');
    send(res, 200, req.method === 'HEAD' ? '' : buf, MIME[path.extname(file)] || 'application/octet-stream');
  });
}

const findRec = (id) => db.domains.find((d) => d.id === id);

async function handleApi(req, res, pathname) {
  const parts = pathname.split('/').filter(Boolean); // ['api', 'domains', ':id', 'refresh']
  const method = req.method;

  if (pathname === '/api/domains' && method === 'GET') return send(res, 200, db.domains);

  if (pathname === '/api/domains' && method === 'POST') {
    const body = await readBody(req);
    const inputs = Array.isArray(body.domains) ? body.domains : String(body.domains || body.name || '').split(/[\s,;]+/);
    if (inputs.length > MAX_ADD) throw new HttpError(400, `Tek seferde en fazla ${MAX_ADD} alan adı eklenebilir`);
    const manualExpiry = parseExpiryInput(body.expiry);
    const added = [], skipped = [];
    for (const raw of inputs) {
      if (!String(raw).trim()) continue;
      const n = normalizeDomain(raw);
      if (!n) { skipped.push({ input: raw, reason: 'Geçersiz alan adı' }); continue; }
      if (db.domains.some((d) => d.name === n.ascii) || added.some((d) => d.name === n.ascii)) {
        skipped.push({ input: raw, reason: 'Zaten listede' }); continue;
      }
      const rec = {
        id: crypto.randomUUID(), name: n.ascii, displayName: n.unicode,
        expiry: null, created: null, registrar: null, status: [], nameservers: [],
        source: null, manualExpiry: false, note: String(body.note || '').slice(0, 1000), tags: [],
        addedAt: new Date().toISOString(), lastChecked: null, error: null,
      };
      if (manualExpiry) { rec.expiry = manualExpiry; rec.manualExpiry = true; rec.source = 'manual'; }
      added.push(rec);
    }
    db.domains.push(...added);
    saveDb();
    // Sorguları sırayla yap (sunuculara yüklenmemek için)
    for (const rec of added) { await refreshRecord(rec); saveDb(); }
    return send(res, 201, { added, skipped });
  }

  if (parts[0] === 'api' && parts[1] === 'domains' && parts[2]) {
    const rec = findRec(parts[2]);
    if (!rec) return send(res, 404, { error: 'Kayıt bulunamadı' });

    if (parts[3] === 'refresh' && method === 'POST') {
      await refreshRecord(rec); saveDb();
      return send(res, 200, rec);
    }
    if (!parts[3] && method === 'PUT') {
      const body = await readBody(req);
      if ('expiry' in body) {
        const iso = parseExpiryInput(body.expiry);
        rec.expiry = iso;
        rec.manualExpiry = !!iso;
        if (iso) { rec.source = 'manual'; rec.error = null; }
      }
      if ('note' in body) rec.note = String(body.note || '').slice(0, 1000);
      if ('registrar' in body) rec.registrar = String(body.registrar || '').slice(0, 200) || null;
      if ('tags' in body) rec.tags = (Array.isArray(body.tags) ? body.tags : String(body.tags ?? '').split(','))
        .map((t) => String(t).trim().slice(0, 50)).filter(Boolean).slice(0, 20);
      saveDb();
      return send(res, 200, rec);
    }
    if (!parts[3] && method === 'DELETE') {
      db.domains = db.domains.filter((d) => d.id !== rec.id);
      saveDb();
      return send(res, 200, { ok: true });
    }
  }

  if (pathname === '/api/refresh-all' && method === 'POST') {
    for (const rec of db.domains) { await refreshRecord(rec); saveDb(); }
    return send(res, 200, db.domains);
  }

  if (pathname === '/api/import' && method === 'POST') {
    const body = await readBody(req);
    const list = Array.isArray(body) ? body : body && body.domains;
    if (!Array.isArray(list)) return send(res, 400, { error: 'Geçersiz yedek dosyası' });
    if (list.length > 5000) return send(res, 400, { error: 'Yedek dosyasında çok fazla kayıt var (en fazla 5000)' });
    let count = 0;
    for (const item of list) {
      if (!item || typeof item !== 'object') continue;
      const n = normalizeDomain(item.name);
      if (!n || db.domains.some((d) => d.name === n.ascii)) continue;
      const expiry = item.expiry ? parseLooseDate(item.expiry) : null;
      db.domains.push({
        id: crypto.randomUUID(), name: n.ascii, displayName: n.unicode,
        expiry, created: isoOrNull(item.created),
        registrar: typeof item.registrar === 'string' ? item.registrar.slice(0, 200) || null : null,
        status: strList(item.status, 20, 100), nameservers: strList(item.nameservers, 20, 253),
        source: ['rdap', 'whois', 'manual'].includes(item.source) ? item.source : null,
        manualExpiry: !!item.manualExpiry && !!expiry,
        note: typeof item.note === 'string' ? item.note.slice(0, 1000) : '', tags: strList(item.tags, 20, 50),
        addedAt: isoOrNull(item.addedAt) || new Date().toISOString(), lastChecked: isoOrNull(item.lastChecked), error: null,
      });
      count++;
    }
    saveDb();
    return send(res, 200, { imported: count });
  }

  return send(res, 404, { error: 'Bilinmeyen istek' });
}

const MAX_ADD = 200;

const server = http.createServer(async (req, res) => {
  try {
    let pathname;
    try {
      pathname = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    } catch {
      throw new HttpError(400, 'Geçersiz adres');
    }
    if (pathname.includes('\0')) throw new HttpError(400, 'Geçersiz adres');
    if (pathname.startsWith('/api/')) {
      checkRequestOrigin(req);
      return await handleApi(req, res, pathname);
    }
    return serveStatic(req, res, pathname);
  } catch (e) {
    if (res.headersSent) return res.destroy();
    if (e instanceof HttpError) return send(res, e.status, { error: e.message });
    console.error(e);
    send(res, 500, { error: 'Sunucu hatası' });
  }
});
// Toplu eklemede sorgular sırayla yapıldığı için uzun sürebilir; Node'un 5 dk varsayılanını uzat.
server.requestTimeout = 30 * 60e3;

// ---------------------------------------------------------------- Otomatik yenileme

let autoRunning = false;
async function autoRefresh() {
  if (autoRunning) return;
  autoRunning = true;
  try {
    const cutoff = Date.now() - AUTO_REFRESH_HOURS * 3600e3;
    for (const rec of db.domains) {
      if (!rec.lastChecked || Date.parse(rec.lastChecked) < cutoff) {
        await refreshRecord(rec);
        saveDb();
        await new Promise((r) => setTimeout(r, 1500));
      }
    }
  } finally {
    autoRunning = false;
  }
}

if (require.main === module) {
  server.on('error', (e) => {
    if (e.code === 'EADDRINUSE') console.error(`\n  ⚠ ${PORT} portu kullanımda. Başka bir port deneyin: PORT=3001 node server.js\n`);
    else console.error(e);
    process.exit(1);
  });
  server.listen(PORT, HOST, () => {
    console.log(`\n  Domain Takipçisi çalışıyor →  http://localhost:${PORT}\n  (Durdurmak için Ctrl+C)\n`);
    setTimeout(autoRefresh, 5000);
    setInterval(autoRefresh, 3600e3);
  });
}

module.exports = { server, normalizeDomain, parseLooseDate, parseWhois };

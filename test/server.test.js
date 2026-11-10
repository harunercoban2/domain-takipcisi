// Ağa çıkmayan testler: `npm test` (Node.js 18+ yerleşik test çalıştırıcısı).
'use strict';

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'domaintakip-test-'));
process.env.DATA_DIR = DATA_DIR;
const { server, normalizeDomain, parseLooseDate, parseWhois } = require('../server.js');

describe('normalizeDomain', () => {
  test('protokol, www, yol ve port temizlenir', () => {
    assert.equal(normalizeDomain('https://www.Ornek.com:8080/yol?x=1#a').ascii, 'ornek.com');
  });
  test('Türkçe alan adı punycode olur', () => {
    assert.deepEqual(normalizeDomain('türkçe.com'), { ascii: 'xn--trke-2oa7j.com', unicode: 'türkçe.com' });
  });
  test('geçersiz girdiler reddedilir', () => {
    for (const bad of ['', 'abc', 'ör nek', '1.2.3.4', 'ornek.123', '-ornek.com', 'ornek-.com', 'a..com', `${'a'.repeat(64)}.com`]) {
      assert.equal(normalizeDomain(bad), null, bad);
    }
  });
});

describe('parseLooseDate', () => {
  const d = (s) => parseLooseDate(s)?.slice(0, 10) ?? null;
  test('yaygın WHOIS biçimleri', () => {
    assert.equal(d('2027-03-15T04:00:00Z'), '2027-03-15');
    assert.equal(d('2027-03-15'), '2027-03-15');
    assert.equal(d('15.03.2027'), '2027-03-15');
    assert.equal(d('15-Mar-2027'), '2027-03-15');
    assert.equal(d('2027-Oca-05'), '2027-01-05');
    assert.equal(d('20270315'), '2027-03-15');
  });
  test('geçersiz takvim tarihleri kaymaz, null döner', () => {
    assert.equal(d('2027-13-45'), null);
    assert.equal(d('31.02.2027'), null);
    assert.equal(d('1900-01-01'), null);
    assert.equal(d('yarın'), null);
  });
});

describe('parseWhois', () => {
  test('bitiş, kayıt firması ve DNS okunur', () => {
    const r = parseWhois([
      'Domain Name: ORNEK.COM',
      'Registrar: Ornek Registrar Inc.',
      'Creation Date: 2015-06-01T10:00:00Z',
      'Registry Expiry Date: 2027-06-01T10:00:00Z',
      'Name Server: NS1.ORNEK.COM',
      'Name Server: NS2.ORNEK.COM',
    ].join('\n'));
    assert.equal(r.expiry.slice(0, 10), '2027-06-01');
    assert.equal(r.registrar, 'Ornek Registrar Inc.');
    assert.deepEqual(r.nameservers, ['ns1.ornek.com', 'ns2.ornek.com']);
    assert.equal(r.notFound, false);
  });
  test('boştaki alan adı tanınır', () => {
    assert.equal(parseWhois('No match for "BOS-ALAN-ADI.COM".').notFound, true);
  });
});

describe('HTTP API', () => {
  let base, port;
  before(async () => {
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    port = server.address().port;
    base = `http://127.0.0.1:${port}`;
  });
  after(() => {
    server.close();
    fs.rmSync(DATA_DIR, { recursive: true, force: true });
  });

  const req = (p, opts = {}) => fetch(base + p, opts);
  const json = (method, body, headers = {}) => ({
    method, headers: { 'Content-Type': 'application/json', ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });

  test('ana sayfa güvenlik başlıklarıyla gelir', async () => {
    const r = await req('/');
    assert.equal(r.status, 200);
    assert.match(r.headers.get('content-security-policy'), /frame-ancestors 'none'/);
    assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(r.headers.get('x-frame-options'), 'DENY');
  });

  test('public dışına çıkılamaz', async () => {
    for (const p of ['/../server.js', '/%2e%2e/server.js', '/..%2fserver.js', '/%2e%2e%2fpackage.json']) {
      const r = await req(p);
      assert.ok([403, 404].includes(r.status), `${p} → ${r.status}`);
      assert.doesNotMatch(await r.text(), /require\(|"scripts"/);
    }
  });

  test('bozuk URL kodlaması 400 döner', async () => {
    assert.equal((await req('/%E0%A4%A')).status, 400);
  });

  test('bozuk JSON 500 değil 400 döner', async () => {
    const r = await req('/api/import', json('POST', '{bozuk'));
    assert.equal(r.status, 400);
    assert.equal((await r.json()).error, 'Geçersiz JSON');
  });

  test('2 MB üstü istek 413 döner ve sunucu takılmaz', async () => {
    const r = await req('/api/import', json('POST', JSON.stringify({ x: 'a'.repeat(2.5 * 1024 * 1024) })));
    assert.equal(r.status, 413);
    assert.equal((await req('/api/domains')).status, 200);
  });

  test('başka siteden gelen istek (CSRF) reddedilir', async () => {
    const r = await req('/api/import', json('POST', { domains: [{ name: 'kotu.com' }] }, { Origin: 'https://kotu-site.example' }));
    assert.equal(r.status, 403);
    const list = await (await req('/api/domains')).json();
    assert.ok(!list.some((d) => d.name === 'kotu.com'));
  });

  test('cross-site Sec-Fetch-Site reddedilir', async () => {
    const r = await req('/api/domains', { headers: { 'Sec-Fetch-Site': 'cross-site' } });
    assert.equal(r.status, 403);
  });

  test('yabancı Host başlığı (DNS rebinding) reddedilir', async () => {
    const http = require('node:http');
    const status = await new Promise((resolve, reject) => {
      http.get({ host: '127.0.0.1', port, path: '/api/domains', headers: { Host: `kotu-site.example:${port}` } },
        (res) => { res.resume(); resolve(res.statusCode); }).on('error', reject);
    });
    assert.equal(status, 403);
  });

  test('aynı kaynaktan gelen istek kabul edilir', async () => {
    const r = await req('/api/domains', { headers: { Origin: base } });
    assert.equal(r.status, 200);
  });

  let id;
  test('yedekten geri yükleme verileri temizler', async () => {
    const r = await req('/api/import', json('POST', {
      domains: [
        { name: 'https://www.Ornek.com/', expiry: '2030-01-01', status: 'bozuk', tags: ['a', 5, ''], note: { x: 1 }, source: 'hack', addedAt: 'dün' },
        { name: 'ornek.com' },      // tekrar
        { name: '1.2.3.4' },        // geçersiz
        null, 'metin',
      ],
    }));
    assert.equal(r.status, 200);
    assert.equal((await r.json()).imported, 1);
    const [rec] = await (await req('/api/domains')).json();
    id = rec.id;
    assert.equal(rec.name, 'ornek.com');
    assert.equal(rec.expiry.slice(0, 10), '2030-01-01');
    assert.deepEqual(rec.status, []);
    assert.deepEqual(rec.tags, ['a']);
    assert.equal(rec.note, '');
    assert.equal(rec.source, null);
    assert.ok(!Number.isNaN(Date.parse(rec.addedAt)));
  });

  test('düzenleme: geçerli tarih kaydedilir, geçersiz tarih 400 döner', async () => {
    let r = await req(`/api/domains/${id}`, json('PUT', { expiry: '2031-05-01', tags: 'müşteri, kritik', note: 'not' }));
    assert.equal(r.status, 200);
    const rec = await r.json();
    assert.equal(rec.expiry.slice(0, 10), '2031-05-01');
    assert.equal(rec.manualExpiry, true);
    assert.deepEqual(rec.tags, ['müşteri', 'kritik']);

    r = await req(`/api/domains/${id}`, json('PUT', { expiry: '2031-13-45' }));
    assert.equal(r.status, 400);
    const after = (await (await req('/api/domains')).json())[0];
    assert.equal(after.expiry.slice(0, 10), '2031-05-01', 'geçersiz istek veriyi bozmamalı');
  });

  test('tek seferde çok fazla alan adı eklenemez', async () => {
    const r = await req('/api/domains', json('POST', { domains: Array.from({ length: 201 }, (_, i) => `a${i}.com`) }));
    assert.equal(r.status, 400);
  });

  test('olmayan kayıt 404, silme çalışır', async () => {
    assert.equal((await req('/api/domains/yok', { method: 'DELETE' })).status, 404);
    assert.equal((await req(`/api/domains/${id}`, { method: 'DELETE' })).status, 200);
    assert.deepEqual(await (await req('/api/domains')).json(), []);
  });

  test('veriler diske yazılır', () => {
    const saved = JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'domains.json'), 'utf8'));
    assert.deepEqual(saved.domains, []);
  });
});

test('bozuk veri dosyası silinmez, yedeği alınır', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'domaintakip-bozuk-'));
  fs.writeFileSync(path.join(dir, 'domains.json'), '{ yarım kalmış');
  execFileSync(process.execPath, ['-e', `require(${JSON.stringify(path.join(__dirname, '..', 'server.js'))})`], {
    env: { ...process.env, DATA_DIR: dir }, stdio: 'pipe',
  });
  const files = fs.readdirSync(dir);
  assert.ok(files.some((f) => f.startsWith('domains.json.bozuk-')), files.join(', '));
  assert.equal(fs.readFileSync(path.join(dir, 'domains.json'), 'utf8'), '{ yarım kalmış');
  fs.rmSync(dir, { recursive: true, force: true });
});

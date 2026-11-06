// Billy's Couches Dashboard
// Railway variables:
//   APP_PASSWORD                password to get in
//   SHEETS_API_URL              the Apps Script Web app URL
//   SHEETS_KEY                  the SECRET phrase in the Apps Script
//   UPSTASH_REDIS_REST_URL      \ where purchases + expenses are saved
//   UPSTASH_REDIS_REST_TOKEN    / (same Upstash database as the order app is fine)
//   JOTFORM_API_KEY             Jotform API key (Payroll tab reads the Work Log form)
//   WORKLOG_FORM_ID             optional: defaults to 260845178882066
//   JOTFORM_API_BASE            optional: defaults to https://api.jotform.com
//   THANKYOU_FORM_ID            optional: scheduling form ID(s) for the Thank You Cards tab (auto-found by title if blank)
//   APIFY_TOKEN                 Competitor Ads tab (same token the old Ad Tracker used)
//   ADS_REDIS_URL / ADS_REDIS_TOKEN  optional: the old Ad Tracker's Upstash, to keep its ad history
//   PLAID_CLIENT_ID / PLAID_SECRET / PLAID_ENV   Daily Cash bank balances (PLAID_ENV = production or sandbox)
//   TEXTMAGIC_USERNAME / TEXTMAGIC_API_KEY   texts you each Cash for Your Couch submission
//   OFFER_ALERT_PHONES          optional: who gets the text, comma separated (default 13148997503)
//   TEAM_PAY_KEY                shared secret the team scorecard uses to read each person's weekly pay
//   STRIPE_SECRET_KEY           restricted key with Balance: Read (Cash tab pulls the Stripe balance)
// Without SHEETS_API_URL it runs on demo data.

const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const compression = require('compression');
const app = express();
app.use(compression());
app.use('/api/photo', express.json({ limit: '4mb' }));
app.use('/api/justsold/pick', express.json({ limit: '4mb' }));
app.use('/api/drops/photo', express.json({ limit: '6mb' }));
app.use('/public/couch-offer', express.json({ limit: '15mb' }));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

const CFG = {
  PORT: process.env.PORT || 3000,
  PASSWORD: process.env.APP_PASSWORD || '',
  API: (process.env.SHEETS_API_URL || '').trim(),
  KEY: (process.env.SHEETS_KEY || '').trim(),
  REDIS_URL: (process.env.UPSTASH_REDIS_REST_URL || '').trim(),
  REDIS_TOKEN: (process.env.UPSTASH_REDIS_REST_TOKEN || '').trim(),
  JOTFORM_KEY: (process.env.JOTFORM_API_KEY || '').trim(),
  JOTFORM_BASE: (process.env.JOTFORM_API_BASE || 'https://api.jotform.com').trim().replace(/\/$/, ''),
  WORKLOG_FORM: (process.env.WORKLOG_FORM_ID || '260845178882066').trim(),
  STRIPE_KEY: (process.env.STRIPE_SECRET_KEY || '').trim(),
};

// ---------- login security ----------
// Password (+ optional 6-digit authenticator code) -> a random session token saved in Redis.
// Sessions last 30 days and can all be revoked from /security. 5 wrong tries locks that device out for 15 minutes.
const SECRET = crypto.createHash('sha256').update('bcd:' + CFG.PASSWORD).digest('hex');   // still signs client-portal cookies
const SESS_KEY = 'bcd:sessions', TOTP_KEY = 'bcd:totp', SESS_DAYS = 30;
let SESS = null, TOTP = null, secLoading = null;
const loadSec = () => secLoading || (secLoading = (async () => {
  try { SESS = (await kget(SESS_KEY, {})) || {}; TOTP = await kget(TOTP_KEY, null); } catch (e) { console.log('security load failed', e.message); SESS = SESS || {}; secLoading = null; }
})());
app.use(async (req, res, next) => { if (!SESS) await loadSec(); next(); });
// Basic browser protections on every response.
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
  if (!req.path.startsWith('/public/')) res.setHeader('X-Frame-Options', 'DENY');
  next();
});
const cookieTok = req => { const c = (req.headers.cookie || '').split(';').map(x => x.trim()).find(x => x.startsWith('bcd=')); return c ? c.slice(4) : ''; };
function authed(req) {
  const t = cookieTok(req), s = t && SESS && SESS[t];
  return !!CFG.PASSWORD && !!s && s.exp > Date.now();
}
const saveSess = () => { const now = Date.now(); Object.keys(SESS).forEach(k => { if (!(SESS[k].exp > now)) delete SESS[k]; }); return kset(SESS_KEY, SESS); };
const clientIp = req => String(req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim();
const sameStr = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
// TOTP (Google Authenticator / Authy style), RFC 6238 with 30-second steps.
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const b32dec = str => { let bits = '', out = []; for (const ch of String(str).replace(/=+$/, '').toUpperCase()) { const v = B32.indexOf(ch); if (v < 0) continue; bits += v.toString(2).padStart(5, '0'); } for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2)); return Buffer.from(out); };
const b32enc = buf => { let bits = ''; for (const b of buf) bits += b.toString(2).padStart(8, '0'); let out = ''; for (let i = 0; i < bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)]; return out; };
function totpAt(secret, step) {
  const msg = Buffer.alloc(8); msg.writeUInt32BE(Math.floor(step / 0x100000000), 0); msg.writeUInt32BE(step >>> 0, 4);
  const h = crypto.createHmac('sha1', b32dec(secret)).update(msg).digest(), o = h[h.length - 1] & 15;
  return String(((h.readUInt32BE(o) & 0x7fffffff) % 1000000)).padStart(6, '0');
}
const totpOk = (secret, code) => { code = String(code || '').replace(/\D/g, ''); if (code.length !== 6) return false; const st = Math.floor(Date.now() / 30000); return [-1, 0, 1].some(d => sameStr(totpAt(secret, st + d), code)); };
const safeNext = n => /^\/[\w\/?=&-]*$/.test(n || '') && !String(n).startsWith('//') ? String(n).replace(/[?&]bad=\w+/, '') : '/';
const loginFails = new Map();
app.get('/login-info', (req, res) => res.json({ twofa: !!(TOTP && TOTP.on) }));
app.post('/login', async (req, res) => {
  const ip = clientIp(req), now = Date.now(), n = safeNext(req.body.next), back = why => res.redirect(n + (n.includes('?') ? '&' : '?') + 'bad=' + why);
  const fails = (loginFails.get(ip) || []).filter(t => now - t < 15 * 60 * 1000);
  if (fails.length >= 5) return back('locked');
  const fail = why => { fails.push(now); loginFails.set(ip, fails); if (fails.length === 5) textAlert(`Billy's HQ: 5 wrong login attempts from ${ip}. That device is locked out for 15 min. If this wasn't you, change APP_PASSWORD in Railway.`).catch(() => {}); return back(why); };
  if (!CFG.PASSWORD || !sameStr(req.body.password || '', CFG.PASSWORD)) return fail('1');
  if (TOTP && TOTP.on && !totpOk(TOTP.secret, req.body.code)) return fail('code');
  loginFails.delete(ip);
  const tok = crypto.randomBytes(32).toString('hex');
  SESS[tok] = { exp: now + SESS_DAYS * 864e5, created: now, ip, ua: String(req.headers['user-agent'] || '').slice(0, 160) };
  try { await saveSess(); } catch (e) { console.log('session save failed', e.message); }
  res.setHeader('Set-Cookie', `bcd=${tok}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESS_DAYS * 86400}; Secure`);
  res.redirect(n);
});
app.get('/logout', async (req, res) => {
  const t = cookieTok(req); if (t && SESS && SESS[t]) { delete SESS[t]; try { await saveSess(); } catch (e) {} }
  res.setHeader('Set-Cookie', 'bcd=; Path=/; Max-Age=0'); res.redirect('/');
});
app.get('/', (req, res) => res.sendFile(path.join(__dirname, authed(req) ? 'index.html' : 'login.html')));
app.get('/healthz', (req, res) => res.send('ok'));
const longCache = { headers: { 'Cache-Control': 'public, max-age=604800' } };
app.get('/chart.js', (req, res) => res.sendFile(path.join(__dirname, 'node_modules', 'chart.js', 'dist', 'chart.umd.js'), longCache));
['favicon.png', 'icon-180.png', 'icon-192.png', 'icon-512.png', 'manifest.json'].forEach(f => app.get('/' + f, (req, res) => res.sendFile(path.join(__dirname, f), longCache)));
app.get('/favicon.ico', (req, res) => res.sendFile(path.join(__dirname, 'favicon.png'), longCache));
app.use('/api', (req, res, next) => authed(req) ? next() : res.status(401).json({ error: 'login' }));
// ---------- /security page: sessions + two-step login ----------
app.get('/security', (req, res) => res.sendFile(path.join(__dirname, authed(req) ? 'security.html' : 'login.html')));
app.get('/api/security', (req, res) => {
  const cur = cookieTok(req), now = Date.now();
  res.json({ ok: true, twofa: !!(TOTP && TOTP.on), sessions: Object.entries(SESS || {}).filter(([, v]) => v.exp > now).map(([k, v]) => ({ id: k.slice(0, 8), current: k === cur, created: v.created, ip: v.ip, ua: v.ua })).sort((a, b) => b.created - a.created) });
});
app.post('/api/security/logout-others', async (req, res) => {
  const cur = cookieTok(req); Object.keys(SESS).forEach(k => { if (k !== cur) delete SESS[k]; });
  try { await saveSess(); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});
let totpPending = null;
app.post('/api/security/2fa/start', (req, res) => {
  totpPending = b32enc(crypto.randomBytes(20));
  res.json({ ok: true, secret: totpPending, uri: `otpauth://totp/Billy's%20HQ:Billy?secret=${totpPending}&issuer=Billy's%20HQ&period=30&digits=6` });
});
app.post('/api/security/2fa/confirm', async (req, res) => {
  if (!totpPending) return res.status(400).json({ error: 'Start setup again' });
  if (!totpOk(totpPending, req.body.code)) return res.status(400).json({ error: "That code didn't match. Use the newest code in your app." });
  TOTP = { on: true, secret: totpPending, at: Date.now() }; totpPending = null;
  try { await kset(TOTP_KEY, TOTP); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/security/2fa/off', async (req, res) => {
  if (!(TOTP && TOTP.on)) return res.json({ ok: true });
  if (!totpOk(TOTP.secret, req.body.code)) return res.status(400).json({ error: 'Enter a current code from your app to turn this off' });
  TOTP = null; try { await kset(TOTP_KEY, null); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});


// ---------- storage: Upstash Redis, or a local file as fallback ----------
const FILE = path.join(__dirname, 'data', 'store.json');
async function kget(key, dflt) {
  if (CFG.REDIS_URL) {
    const r = await fetch(`${CFG.REDIS_URL}/get/${encodeURIComponent(key)}`, { headers: { Authorization: `Bearer ${CFG.REDIS_TOKEN}` } });
    const j = await r.json();
    if (j.error) throw new Error('Redis: ' + j.error);
    return j.result ? JSON.parse(j.result) : dflt;
  }
  try { return JSON.parse(fs.readFileSync(FILE, 'utf8'))[key] ?? dflt; } catch { return dflt; }
}
async function kset(key, val) {
  if (CFG.REDIS_URL) {
    const r = await fetch(`${CFG.REDIS_URL}/set/${encodeURIComponent(key)}`, {
      method: 'POST', headers: { Authorization: `Bearer ${CFG.REDIS_TOKEN}` }, body: JSON.stringify(val),
    });
    const j = await r.json();
    if (j.error) throw new Error('Redis: ' + j.error);
    return;
  }
  let all = {};
  try { all = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch {}
  all[key] = val;
  fs.mkdirSync(path.dirname(FILE), { recursive: true });
  fs.writeFileSync(FILE, JSON.stringify(all));
}
const KEYS = { purchases: 'bcd:purchases', expenses: 'bcd:expenses', loads: 'bcd:loads', cash: 'bcd:cash',
  rates: 'bcd:payrollRates', openhouses: 'bcd:openhouses', adj: 'bcd:payrollAdj', paid: 'bcd:payrollPaid' };

// Past months imported from Ivy Flip (Jan-Sep 2026).
let HISTORY = { sales: [], expenses: [] };
try { HISTORY = require('./history.json'); } catch { console.log('No history.json'); }

// ---------- Google (sales, showings, bstock) ----------
// Google is slow (5-30s). Serve the last copy instantly and refresh it in the
// background. The last copy is also saved to Redis so a redeploy starts warm.
let cache = { at: 0, data: null }, inflight = null;
async function fetchGoogle() {
  const r = await fetch(`${CFG.API}?key=${encodeURIComponent(CFG.KEY)}`);
  const text = await r.text();
  let j;
  try { j = JSON.parse(text); } catch { throw new Error('Apps Script did not return data. Check the deployment.'); }
  if (j.error) throw new Error('Sheet: ' + j.error);
  cache = { at: Date.now(), data: j };
  kset('bcd:googleCache', cache).catch(() => {});
  return j;
}
function refreshGoogle() {
  if (!inflight) inflight = fetchGoogle().finally(() => { inflight = null; });
  return inflight;
}
async function google(force) {
  if (!CFG.API) return demoData();
  if (!cache.data) { try { const c = await kget('bcd:googleCache', null); if (c && c.data) cache = c; } catch {} }
  if (cache.data) {
    if (force || Date.now() - cache.at > 60 * 1000) refreshGoogle().catch(e => console.log('Google refresh failed:', e.message));
    return { ...cache.data, cachedAt: cache.at };
  }
  return refreshGoogle();
}
// Keep it warm: refresh every 5 minutes even when nobody is looking.
if (CFG.API) setInterval(() => refreshGoogle().catch(() => {}), 5 * 60 * 1000);

// imports.json: one-time records (e.g. Ivy Flip months after the history cutoff).
// Each record has a fixed id, so it is added once and never duplicated.
// Deleted imports are remembered so they don't come back.
async function getExpenses() {
  let list = await kget(KEYS.expenses, []);
  let imp = [];
  try { imp = JSON.parse(fs.readFileSync(path.join(__dirname, 'imports.json'), 'utf8')).expenses || []; } catch {}
  if (imp.length) {
    const gone = new Set(await kget('bcd:deletedImports', []));
    const have = new Set(list.map(x => x.id));
    const add = imp.filter(x => !have.has(x.id) && !gone.has(x.id));
    if (add.length) { list = list.concat(add); await kset(KEYS.expenses, list); }
  }
  return list;
}

// Open houses: starts with the events from the Open House Tracker sheet.
const OH_SEED = [
  ['2026-08-22', '11am-2pm', 15, 5, null, null, null], ['2026-09-05', '10am-1pm', 8, 5, null, null, 16],
  ['2026-09-12', '11am-2pm', 12, 5, null, null, 10], ['2026-09-26', '1pm-4pm', 14, 5, 24, 5, 8],
  ['2026-10-08', '5-8pm', 5, 1, null, 6, 7, 'Grand opening'], ['2026-10-11', '2-5pm', 7, 1, 19, 2, 2],
  ['2026-10-18', '1-3pm', 8, 3, 21, 5, 2], ['2026-10-24', '10am-12pm', 8, 0, 14, 3, 4, '$50 off every couch'],
].map(([date, time, walkins, sales, floor, promoDays, leads, note]) => ({ id: 'oh-' + date, date, time, walkins, sales, floor, promoDays, leads, note: note || '', checks: {} }));
async function getOpenHouses() {
  let list = await kget(KEYS.openhouses, null);
  if (list === null) { list = OH_SEED; await kset(KEYS.openhouses, list); }
  return list;
}
const optNum = v => v === '' || v == null ? null : Number(v);
app.post('/api/openhouse', async (req, res) => {
  try {
    const d = req.body || {};
    if (!/^\d{4}-\d{2}-\d{2}$/.test(d.date)) return res.status(400).json({ error: 'Date is required' });
    const list = await getOpenHouses();
    let o = d.id && list.find(x => x.id === d.id);
    if (!o) { o = { id: 'oh-' + Date.now().toString(36), checks: {} }; list.push(o); }
    Object.assign(o, { date: d.date, time: clean(d.time, 40), note: clean(d.note, 120),
      walkins: optNum(d.walkins), sales: optNum(d.sales), floor: optNum(d.floor), promoDays: optNum(d.promoDays), leads: optNum(d.leads) });
    await kset(KEYS.openhouses, list);
    res.json({ ok: true, id: o.id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/openhouse/check', async (req, res) => {
  try {
    const { id, idx, on } = req.body || {};
    const list = await getOpenHouses(), o = list.find(x => x.id === id);
    if (!o) return res.status(404).json({ error: 'Not found' });
    o.checks = o.checks || {}; if (on) o.checks[idx] = true; else delete o.checks[idx];
    await kset(KEYS.openhouses, list);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Small saved lists edited in the dashboard: content plan, ad checklist, goal game plan, after-sale upsells, open house plans.
const STORE_KEYS = ['content', 'adChecks', 'gamePlan', 'upsellAdds', 'dream', 'ppl', 'slots', 'shots'];
app.post('/api/store/:k', async (req, res) => {
  try {
    if (!STORE_KEYS.includes(req.params.k)) return res.status(400).json({ error: 'bad key' });
    const v = (req.body || {}).value; if (JSON.stringify(v ?? null).length > 200000) return res.status(400).json({ error: 'too big' });
    await kset('bcd:store:' + req.params.k, v ?? null); res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// Edit an expense you logged (or an imported one).
app.post('/api/expense/update', async (req, res) => {
  try {
    const d = req.body || {}, amount = Number(d.amount);
    if (!(amount > 0)) return res.status(400).json({ error: 'Amount is required' });
    const list = await getExpenses(), x = list.find(e => e.id === d.id);
    if (!x) return res.status(404).json({ error: 'Expense not found' });
    Object.assign(x, { date: /^\d{4}-\d{2}-\d{2}$/.test(d.date) ? d.date : x.date, category: clean(d.category, 40) || x.category,
      amount: Math.round(amount * 100) / 100, vendor: clean(d.vendor, 80), notes: clean(d.notes) });
    await kset(KEYS.expenses, list); res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/data', async (req, res) => {
  try {
    const [g, purchases, expenses, loads, openhouses] = await Promise.all([
      google(req.query.fresh === '1'), getPurchases(), getExpenses(), getLoads(), getOpenHouses(),
    ]);
    const photos = await kget('bcd:photos', {}).catch(() => ({}));
    const goals = await getGoals().catch(() => ({}));
    const extra = {}; await Promise.all(STORE_KEYS.map(async k => { extra[k] = await kget('bcd:store:' + k, null).catch(() => null); }));
    res.json({ ...g, purchases, expenses, loads, openhouses, photos, goals, store: extra, history: HISTORY, storage: CFG.REDIS_URL ? 'redis' : 'file' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------- purchases + expenses ----------
const clean = (v, n = 200) => String(v ?? '').trim().slice(0, n);
app.post('/api/add', async (req, res) => {
  try {
    const { action, data = {} } = req.body || {};
    const date = /^\d{4}-\d{2}-\d{2}$/.test(data.date) ? data.date : new Date().toISOString().slice(0, 10);
    const id = Date.now().toString(36) + crypto.randomBytes(3).toString('hex');
    if (action === 'addPurchase') {
      const cost = Number(data.cost);
      if (!(cost >= 0)) return res.status(400).json({ error: 'Cost is required' });
      const list = await kget(KEYS.purchases, []);
      list.push({ id, date, source: clean(data.source, 40) || 'Other', item: clean(data.item), units: Math.max(1, parseInt(data.units) || 1),
        cost: Math.round(cost * 100) / 100, loadId: clean(data.loadId, 40), notes: clean(data.notes), status: 'in', soldPrice: 0, soldDate: '' });
      await kset(KEYS.purchases, list);
    } else if (action === 'addExpense') {
      const amount = Number(data.amount);
      if (!(amount > 0)) return res.status(400).json({ error: 'Amount is required' });
      const list = await kget(KEYS.expenses, []);
      list.push({ id, date, category: clean(data.category, 40) || 'Other', amount: Math.round(amount * 100) / 100,
        vendor: clean(data.vendor, 80), notes: clean(data.notes) });
      await kset(KEYS.expenses, list);
    } else return res.status(400).json({ error: 'bad action' });
    res.json({ ok: true, id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/delete', async (req, res) => {
  try {
    const { kind, id } = req.body || {};
    if (!['purchases', 'expenses', 'loads', 'openhouses'].includes(kind)) return res.status(400).json({ error: 'bad kind' });
    const list = await kget(KEYS[kind], []);
    await kset(KEYS[kind], list.filter(x => x.id !== id));
    if (/^(ivy-|imp-)/.test(String(id))) { const g = await kget('bcd:deletedImports', []); g.push(id); await kset('bcd:deletedImports', g); }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------- B-Stock loads ----------
// First run: loads-seed.json (Aug-Oct loads from the Bstock sheet) becomes the starting list.
// Adds records from imports.json (by id) once; ids you delete are remembered and never re-added.
async function mergeImports(key, list, field) {
  let imp = [];
  try { imp = JSON.parse(fs.readFileSync(path.join(__dirname, 'imports.json'), 'utf8'))[field] || []; } catch {}
  if (!imp.length) return list;
  const gone = new Set(await kget('bcd:deletedImports', [])), have = new Set(list.map(x => x.id));
  const add = imp.filter(x => !have.has(x.id) && !gone.has(x.id));
  if (add.length) { list = list.concat(add); await kset(key, list); }
  return list;
}
async function getPurchases() { return mergeImports(KEYS.purchases, await kget(KEYS.purchases, []), 'purchases'); }
async function getLoads() {
  let loads = await kget(KEYS.loads, null);
  if (!loads || !loads.length) {
    let seed = null;
    try { seed = JSON.parse(fs.readFileSync(path.join(__dirname, 'loads-seed.json'), 'utf8')); } catch (e) { console.log('loads-seed.json not readable:', e.message); }
    if (Array.isArray(seed) && seed.length) { loads = seed; await kset(KEYS.loads, loads); }
    else loads = loads || [];
  }
  return mergeImports(KEYS.loads, loads, 'loads');
}
// Landed cost is split only across sectionals, sofas, sleepers and loveseats.
// Chairs, recliners, ottomans, consoles, mattresses get $0.
const PAID = /sectional|sofa|sleeper|loveseat|love seat|couch|sect\b|\bmod\b|modular/i;
function allocate(load) {
  const paid = load.units.filter(u => PAID.test(u.name));
  const each = paid.length ? Math.round(load.landed / paid.length * 100) / 100 : 0;
  load.units.forEach(u => { u.cost = PAID.test(u.name) ? each : 0; });
  return load;
}
app.post('/api/loads', async (req, res) => {
  try {
    const d = req.body || {};
    const landed = Number(d.landed);
    if (!(landed > 0)) return res.status(400).json({ error: 'Total landed cost is required' });
    const units = (Array.isArray(d.units) ? d.units : []).map((u, i) => ({
      uid: 'u' + i + crypto.randomBytes(2).toString('hex'), name: clean(u.name, 120), comp: Math.max(0, Number(u.comp) || 0),
      status: 'in', soldPrice: 0, soldDate: '',
    })).filter(u => u.name);
    if (!units.length) return res.status(400).json({ error: 'Add at least one unit' });
    const loads = await getLoads();
    const load = allocate({ id: Date.now().toString(36) + crypto.randomBytes(3).toString('hex'), loadId: clean(d.loadId, 40),
      origin: clean(d.origin, 60), date: /^\d{4}-\d{2}-\d{2}$/.test(d.date) ? d.date : new Date().toISOString().slice(0, 10),
      landed: Math.round(landed * 100) / 100, notes: clean(d.notes), units });
    loads.push(load);
    await kset(KEYS.loads, loads);
    res.json({ ok: true, id: load.id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/loads/unit', async (req, res) => {
  try {
    const { id, uid, status, soldPrice, soldDate } = req.body || {};
    const loads = await getLoads();
    const u = (loads.find(l => l.id === id) || { units: [] }).units.find(x => x.uid === uid);
    if (!u) return res.status(404).json({ error: 'Unit not found' });
    if (!['in', 'sold', 'dud'].includes(status)) return res.status(400).json({ error: 'bad status' });
    u.status = status;
    u.soldPrice = status === 'sold' ? Math.max(0, Number(soldPrice) || 0) : 0;
    u.soldDate = status === 'sold' ? (/^\d{4}-\d{2}-\d{2}$/.test(soldDate) ? soldDate : new Date().toISOString().slice(0, 10)) : '';
    u.soldAt = status === 'sold' ? (u.soldAt || new Date().toISOString()) : '';
    saleDetails(u, req.body || {}, status);
    await kset(KEYS.loads, loads);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Combine two units from the same load into one listing (sofa + loveseat = sofa set). Cost and comp add together.
app.post('/api/loads/combine', async (req, res) => {
  try {
    const { id, keep, merge } = req.body || {}, loads = await getLoads(), l = loads.find(x => x.id === id);
    const a = l && l.units.find(u => u.uid === keep), b = l && l.units.find(u => u.uid === merge);
    if (!a || !b || a === b) return res.status(404).json({ error: 'Units not found' });
    if (a.status !== 'in' || b.status !== 'in') return res.status(400).json({ error: 'Only couches still in stock can be combined' });
    a.cost = Math.round(((Number(a.cost) || 0) + (Number(b.cost) || 0)) * 100) / 100;
    a.comp = (Number(a.comp) || 0) + (Number(b.comp) || 0);
    a.parts = [...(a.parts || [a.name]), ...(b.parts || [b.name])];
    if (!a.photo && b.photo) a.photo = b.photo;
    l.units = l.units.filter(u => u !== b);
    await kset(KEYS.loads, loads);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Rename a couch (B-Stock unit or used pickup).
app.post('/api/couch/rename', async (req, res) => {
  try {
    const { target, id, uid } = req.body || {}, name = clean(req.body.name, 120);
    if (!name) return res.status(400).json({ error: 'Name required' });
    if (target === 'purchase') {
      const list = await getPurchases(), p = list.find(x => x.id === id); if (!p) return res.status(404).json({ error: 'Not found' });
      p.item = name; await kset(KEYS.purchases, list);
    } else {
      const loads = await getLoads(), u = (loads.find(l => l.id === id) || { units: [] }).units.find(x => x.uid === uid);
      if (!u) return res.status(404).json({ error: 'Not found' }); u.name = name; await kset(KEYS.loads, loads);
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Couch price, delivery fee and upsells recorded when a couch is marked sold.
function saleDetails(target, body, status) {
  const sold = status === 'sold';
  target.soldDelivery = sold ? Math.max(0, Number(body.delivery) || 0) : 0;
  target.soldUpsells = sold && Array.isArray(body.upsells) ? body.upsells.map(u => ({ label: clean(u.label, 40), price: Math.max(0, Number(u.price) || 0) })).filter(u => u.label && u.price) : [];
  target.soldUpsellTotal = target.soldUpsells.reduce((a, u) => a + u.price, 0);
  target.soldCustomer = sold ? clean(body.customer, 60) : '';
}

// Log (or undo) the sale of a used pickup
app.post('/api/purchases/sale', async (req, res) => {
  try {
    const { id, status, soldPrice, soldDate } = req.body || {};
    const list = await kget(KEYS.purchases, []);
    const p = list.find(x => x.id === id);
    if (!p) return res.status(404).json({ error: 'Not found' });
    p.status = status === 'sold' ? 'sold' : 'in';
    p.soldPrice = p.status === 'sold' ? Math.max(0, Number(soldPrice) || 0) : 0;
    p.soldAt = p.status === 'sold' ? (p.soldAt || new Date().toISOString()) : '';
    p.soldDate = p.status === 'sold' ? (/^\d{4}-\d{2}-\d{2}$/.test(soldDate) ? soldDate : new Date().toISOString().slice(0, 10)) : '';
    saleDetails(p, req.body || {}, p.status);
    await kset(KEYS.purchases, list);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------- payroll (reads the Jotform Work Log) ----------
// Default hourly rates. Editable on the Payroll tab (saved in Redis).
const DEFAULT_RATES = { collin: 20, luke: 20, zach: 20, joey: 20, gunnarr: 18, finley: 21 };
let wl = { at: 0, data: null };

const lc = s => String(s || '').toLowerCase();
function ansText(a) {
  if (a == null) return '';
  if (typeof a === 'string' || typeof a === 'number') return String(a);
  if (a.first || a.last) return [a.first, a.last].filter(Boolean).join(' ');
  return Object.values(a).filter(v => typeof v === 'string').join(' ');
}
function ansDate(q) {
  const a = q.answer;
  if (a && typeof a === 'object' && a.year && a.month && a.day) return `${a.year}-${String(a.month).padStart(2, '0')}-${String(a.day).padStart(2, '0')}`;
  const t = String(q.prettyFormat || a || '');
  let m = t.match(/(\d{4})-(\d{1,2})-(\d{1,2})/); if (m) return `${m[1]}-${m[2].padStart(2, '0')}-${m[3].padStart(2, '0')}`;
  m = t.match(/(\d{1,2})[\/-](\d{1,2})[\/-](\d{4})/); if (m) return `${m[3]}-${m[1].padStart(2, '0')}-${m[2].padStart(2, '0')}`;
  return '';
}
function ansMinutes(q) {
  const a = q.answer;
  let h, mi, ap;
  if (a && typeof a === 'object' && (a.hourSelect || a.timeInput)) {
    if (a.timeInput) { const m = String(a.timeInput).match(/(\d{1,2}):(\d{2})/); if (m) { h = +m[1]; mi = +m[2]; } }
    else { h = +a.hourSelect; mi = +(a.minuteSelect || 0); }
    ap = a.ampm;
  } else {
    const m = String(q.prettyFormat || a || '').match(/(\d{1,2}):(\d{2})\s*(am|pm)?/i);
    if (!m) return null; h = +m[1]; mi = +m[2]; ap = m[3];
  }
  if (isNaN(h)) return null;
  if (ap && /pm/i.test(ap) && h < 12) h += 12;
  if (ap && /am/i.test(ap) && h === 12) h = 0;
  return h * 60 + (mi || 0);
}
const numOf = v => { const n = parseFloat(String(v ?? '').replace(/[^\d.\-]/g, '')); return isNaN(n) ? 0 : n; };

// Find each field by its question text so it keeps working if the form changes order.
function parseWorkLog(subs) {
  const fieldsSeen = {};
  const entries = subs.filter(s => s.status !== 'DELETED').map(s => {
    const qs = Object.values(s.answers || {}).filter(q => q && q.text && q.answer !== undefined && q.answer !== '');
    const find = (re, not) => qs.find(q => re.test(q.text) && !(not && not.test(q.text)));
    const mark = (k, q) => { if (q) fieldsSeen[k] = q.text; return q; };
    const qName = mark('name', find(/name|employee|who/i, /customer|client/i));
    const qDate = mark('date', find(/date|day/i, /birth/i) || qs.find(q => q.type === 'control_datetime'));
    const qHours = mark('hours', find(/hours/i, /bonus/i));
    const qTip = mark('tips', find(/tip/i));
    const qIn = mark('start', find(/start time|^start\b|clock.?in|time.?in|arriv/i));
    const qOut = mark('end', find(/end time|^end\b|clock.?out|time.?out|time you left/i));
    const qDeep = mark('deep cleans', find(/deep/i));
    const qSpot = mark('spot cleans', find(/spot/i));
    const qSold = mark('showings sold', find(/sold|purchas|convert|bought|closed/i, /deep|spot|hour|clean/i));
    const qShows = mark('showings', find(/showing/i, /sold|purchas|convert|bought|closed/i));
    let hours = qHours ? numOf(ansText(qHours.answer)) : 0;
    if (!hours && qIn && qOut) {
      const a = ansMinutes(qIn), b = ansMinutes(qOut);
      if (a != null && b != null) hours = Math.round(((b - a + (b < a ? 1440 : 0)) / 60) * 100) / 100;
    }
    const date = (qDate && ansDate(qDate)) || String(s.created_at || '').slice(0, 10);
    return {
      id: s.id, date, name: qName ? ansText(qName.answer).trim() : 'Unknown',
      hours, deep: qDeep ? numOf(ansText(qDeep.answer)) : 0, spot: qSpot ? numOf(ansText(qSpot.answer)) : 0,
      sold: qSold ? numOf(ansText(qSold.answer)) : 0, shows: qShows ? numOf(ansText(qShows.answer)) : 0,
      tip: qTip ? numOf(ansText(qTip.answer)) : 0,
    };
  });
  return { entries, fieldsSeen };
}

async function workLog(force) {
  if (!CFG.JOTFORM_KEY) return { entries: [], fieldsSeen: {}, error: 'Add JOTFORM_API_KEY in Railway to load the Work Log.' };
  if (!force && wl.data && Date.now() - wl.at < 2 * 60 * 1000) return wl.data;
  const url = `${CFG.JOTFORM_BASE}/form/${CFG.WORKLOG_FORM}/submissions?apiKey=${encodeURIComponent(CFG.JOTFORM_KEY)}&limit=1000&orderby=created_at`;
  const r = await fetch(url);
  const j = await r.json();
  if (j.responseCode && j.responseCode !== 200) throw new Error('Jotform: ' + (j.message || j.responseCode));
  wl = { at: Date.now(), data: parseWorkLog(j.content || []) };
  return wl.data;
}

app.get('/api/payroll', async (req, res) => {
  try {
    let log;
    try { log = await workLog(req.query.fresh === '1'); } catch (e) { log = { entries: [], fieldsSeen: {}, error: e.message }; }
    const [rates, adj, paid, goals] = await Promise.all([kget(KEYS.rates, {}), kget(KEYS.adj, {}), kget(KEYS.paid, {}), kget('bcd:teamGoals', {})]);
    res.json({ ok: true, ...log, rates: { ...DEFAULT_RATES, ...rates }, adj, paid, goals });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// ---------- thank-you cards (every scheduling / order-confirmation form submission) ----------
// Uses THANKYOU_FORM_ID (comma-separated OK) if set; otherwise finds your Jotform forms
// whose title mentions "schedul" or "order confirmation".
let ty = { at: 0, data: null, forms: null };
// The Signature & Agreement form is always included too: that's where "Pick up today" buyers give their address.
async function thankYouForms() {
  if (ty.forms) return ty.forms;
  const env = String(process.env.THANKYOU_FORM_ID || '').split(',').map(s => s.trim()).filter(Boolean);
  const r = await fetch(`${CFG.JOTFORM_BASE}/user/forms?apiKey=${encodeURIComponent(CFG.JOTFORM_KEY)}&limit=500`);
  const j = await r.json(), all = (j.content || []).filter(f => f.status !== 'DELETED');
  const sched = env.length ? env : all.filter(f => /schedul|order confirm|delivery confirm|pickup confirm/i.test(f.title || '')).map(f => f.id);
  // Only the customer "Signature and Agreement" form (SIGNATURE_FORM_ID in Railway overrides) — not employee/contractor agreements.
  const sigEnv = String(process.env.SIGNATURE_FORM_ID || '').split(',').map(s => s.trim()).filter(Boolean);
  const sig = (sigEnv.length ? sigEnv : all.filter(f => /signature\s*(and|&)\s*agreement/i.test(f.title || '') && !/employ|contractor|hire|hiring|team|staff|w-?9|onboard|application|driver|cleaner/i.test(f.title || '')).map(f => f.id)).filter(id => !sched.includes(id));
  ty.forms = [...sched, ...sig]; ty.sigForms = sig; return ty.forms;
}
function parseAddress(q) {
  const a = q && q.answer; if (!a) return null;
  if (typeof a === 'object') {
    const line1 = [a.addr_line1, a.addr_line2].filter(Boolean).join(', ');
    const line2 = [a.city, [a.state, a.postal].filter(Boolean).join(' ')].filter(Boolean).join(', ');
    return { line1, line2 };
  }
  const t = String(a).trim(); if (!t) return null;
  return { line1: t, line2: '' };
}
function parseThankYou(subs, formId) {
  return subs.filter(s => s.status !== 'DELETED').map(s => {
    const qs = Object.values(s.answers || {}).filter(q => q && q.text && q.answer !== undefined && q.answer !== '');
    const find = (re, not) => qs.find(q => re.test(q.text) && !(not && not.test(q.text)));
    const qName = qs.find(q => q.type === 'control_fullname') || find(/name/i, /couch|item|product|employee|driver/i);
    const qAddr = qs.find(q => q.type === 'control_address') || find(/address|street/i, /email/i);
    const qCity = !qAddr || qAddr.type !== 'control_address' ? find(/city/i) : null;
    const qType = find(/delivery or|pick.?up or|delivery\/pick|pickup\/deliv|how.*(get|receiv)|method/i);
    const qDate = find(/date|day/i, /birth/i) || qs.find(q => q.type === 'control_datetime');
    const addr = parseAddress(qAddr) || { line1: '', line2: '' };
    if (qCity && !addr.line2) addr.line2 = ansText(qCity.answer);
    return {
      id: s.id, form: formId, name: qName ? ansText(qName.answer).trim() : 'Unknown',
      phone: (() => { const q = qs.find(x => x.type === 'control_phone') || find(/phone/i); return q ? ansText(q.answer).trim() : ''; })(),
      line1: addr.line1, line2: addr.line2,
      type: qType ? ansText(qType.answer).trim() : '',
      date: (qDate && ansDate(qDate)) || String(s.created_at || '').slice(0, 10),
      submitted: String(s.created_at || '').slice(0, 10),
    };
  });
}
// Bookings made on HQ's own scheduling page become cards too.
async function schedCards() {
  const m = await kget('bcd:sched', {}).catch(() => ({}));
  return Object.values(m).filter(o => o.booking).map(o => ({ id: 's' + o.token, form: 'hq', name: o.name,
    line1: o.type === 'delivery' ? o.booking.address : '', line2: o.type === 'delivery' ? `${o.booking.city}, MO ${o.booking.zip}` : '',
    type: o.type === 'delivery' ? 'Delivery' : 'Pick up', date: o.booking.date, submitted: new Date(o.booking.at || o.created).toISOString().slice(0, 10) }));
}
// Pick-up-today buyers from the Signature & Agreement form -> the Customers sheet (once each).
async function logSignatureCustomers(cards) {
  if (!CFG.API || !cards.length) return;
  const done = new Set(await kget('bcd:custLogged', []).catch(() => [])), fresh = cards.filter(c => !done.has(c.id)).slice(0, 25);
  if (!done.size) { await kset('bcd:custLogged', cards.map(c => c.id)); return; }   // first run: don't back-fill old ones
  for (const c of fresh) {
    try { const u = new URL(CFG.API); u.searchParams.set('key', CFG.KEY); u.searchParams.set('action', 'customer');
      u.searchParams.set('row', JSON.stringify([c.submitted, c.name, c.phone || '', c.line1, c.line2, '', 'Pick up today', '', '', c.submitted, 'Signature form']));
      await fetch(u); done.add(c.id); } catch (e) { console.log('Customer row failed', e.message); }
  }
  await kset('bcd:custLogged', [...done].slice(-5000));
}
async function thankYouList(force) {
  if (!force && ty.data && Date.now() - ty.at < 2 * 60 * 1000) return ty.data;
  const hq = await schedCards();
  if (!CFG.JOTFORM_KEY) return { cards: hq, error: hq.length ? '' : 'Add JOTFORM_API_KEY in Railway to load thank-you cards.' };
  const forms = await thankYouForms();
  const lists = await Promise.all(forms.map(async id => {
    const r = await fetch(`${CFG.JOTFORM_BASE}/form/${id}/submissions?apiKey=${encodeURIComponent(CFG.JOTFORM_KEY)}&limit=1000&orderby=created_at`);
    const j = await r.json();
    if (j.responseCode && j.responseCode !== 200) throw new Error('Jotform: ' + (j.message || j.responseCode));
    const cards = parseThankYou(j.content || [], id);
    if (!(ty.sigForms || []).includes(id)) return cards;
    // Signature form: only buyers who gave an address (Pick up today), from the day this was turned on (older ones were already handled), and send them to the Customers sheet.
    let since = await kget('bcd:tySigSince', null).catch(() => null);
    if (!since) { since = new Date().toISOString().slice(0, 10); await kset('bcd:tySigSince', since).catch(() => {}); }
    const withAddr = cards.filter(c => c.line1 && c.submitted >= since).map(c => ({ ...c, type: c.type || 'Pick up today' }));
    logSignatureCustomers(withAddr).catch(() => {});
    return withAddr;
  }));
  ty.at = Date.now(); ty.data = { cards: [...lists.flat(), ...hq], forms };
  return ty.data;
}
app.get('/api/thankyou', async (req, res) => {
  try {
    let d; try { d = await thankYouList(req.query.fresh === '1'); } catch (e) { d = { cards: [], error: e.message }; }
    let written = await kget('bcd:thankyou', {});
    // One-time start: everything submitted before the tab went live counts as already written.
    if (d.cards.length && !(await kget('bcd:thankyouInit', null))) {
      const today = new Date().toISOString().slice(0, 10);
      d.cards.forEach(c => { if (!written[c.id]) written[c.id] = today; });
      await kset('bcd:thankyou', written); await kset('bcd:thankyouInit', today);
    }
    res.json({ ok: true, ...d, written });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/thankyou/mark', async (req, res) => {
  try {
    const ids = (Array.isArray(req.body.ids) ? req.body.ids : [req.body.id]).map(x => clean(x, 40)).filter(Boolean).slice(0, 5000);
    if (!ids.length) return res.status(400).json({ error: 'id required' });
    const w = await kget('bcd:thankyou', {}), today = new Date().toISOString().slice(0, 10);
    ids.forEach(id => { if (req.body.done) w[id] = w[id] || today; else delete w[id]; });
    await kset('bcd:thankyou', w); res.json({ ok: true, written: w });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Personal goals each team member sees on the scorecard after entering their PIN.
const GOAL_METRICS = ['custom', 'hours', 'deep', 'sold', 'shows', 'days'];
app.post('/api/payroll/goals', async (req, res) => {
  try {
    const key = lc(clean(req.body.name, 40)).split(' ')[0]; if (!key) return res.status(400).json({ error: 'Name required' });
    const list = (Array.isArray(req.body.goals) ? req.body.goals : []).map(g => ({
      text: clean(g.text, 120), metric: GOAL_METRICS.includes(g.metric) ? g.metric : 'custom', target: Math.max(0, Number(g.target) || 0), done: !!g.done,
    })).filter(g => g.text || (g.metric !== 'custom' && g.target)).slice(0, 3);
    const all = await kget('bcd:teamGoals', {}); all[key] = list; await kset('bcd:teamGoals', all);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/payroll/rate', async (req, res) => {
  try {
    const key = lc(clean(req.body.name, 40)).split(' ')[0];
    const rate = Number(req.body.rate);
    if (!key || !(rate >= 0)) return res.status(400).json({ error: 'Name and rate required' });
    const rates = await kget(KEYS.rates, {}); rates[key] = rate; await kset(KEYS.rates, rates);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/payroll/adjust', async (req, res) => {
  try {
    const { week, name, amount, note } = req.body || {};
    if (!/^\d{4}-\d{2}-\d{2}$/.test(week)) return res.status(400).json({ error: 'bad week' });
    const key = lc(clean(name, 40)).split(' ')[0];
    const adj = await kget(KEYS.adj, {});
    adj[week] = adj[week] || {};
    adj[week][key] = { amount: Number(amount) || 0, note: clean(note, 120) };
    await kset(KEYS.adj, adj);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// Mark a week paid: adds one Payroll expense per person (dated the Sunday). Undo removes them.
app.post('/api/payroll/paid', async (req, res) => {
  try {
    const { week, lines, undo } = req.body || {};
    if (!/^\d{4}-\d{2}-\d{2}$/.test(week)) return res.status(400).json({ error: 'bad week' });
    const paid = await kget(KEYS.paid, {});
    let list = await kget(KEYS.expenses, []);
    list = list.filter(x => !String(x.id).startsWith('pay-' + week + '-'));
    if (undo) { delete paid[week]; }
    else {
      const sun = new Date(week + 'T12:00:00Z'); sun.setUTCDate(sun.getUTCDate() + 6);
      const d = sun.toISOString().slice(0, 10);
      // Skip anyone whose Venmo payment already came in from the bank (no double payroll).
      const fromBank = l => list.some(x => x.auto && /payroll/i.test(x.category) && Math.abs((Number(x.amount) || 0) - Number(l.total)) < 0.01 && Math.abs(Date.parse(x.date) - Date.parse(d)) <= 4 * 864e5);
      (Array.isArray(lines) ? lines : []).filter(l => Number(l.total) > 0 && !fromBank(l)).forEach(l => list.push({
        id: `pay-${week}-${lc(l.name).replace(/[^a-z0-9]/g, '')}`, date: d, category: 'Payroll',
        amount: Math.round(Number(l.total) * 100) / 100, vendor: clean(l.name, 60), notes: 'Weekly payroll ' + week,
      }));
      paid[week] = new Date().toLocaleDateString('en-CA', { timeZone: 'America/Chicago' });
    }
    await kset(KEYS.expenses, list); await kset(KEYS.paid, paid);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------- cash position ----------
let stripeCache = { at: 0, data: null };
async function stripeBalance(force) {
  if (!CFG.STRIPE_KEY) return { error: 'Add STRIPE_SECRET_KEY in Railway to pull Stripe automatically.' };
  if (!force && stripeCache.data && Date.now() - stripeCache.at < 2 * 60 * 1000) return stripeCache.data;
  const r = await fetch('https://api.stripe.com/v1/balance', { headers: { Authorization: `Bearer ${CFG.STRIPE_KEY}` } });
  const j = await r.json();
  if (j.error) return { error: 'Stripe: ' + j.error.message };
  const usd = arr => (arr || []).filter(x => x.currency === 'usd').reduce((a, x) => a + x.amount, 0) / 100;
  const data = { pending: usd(j.pending), available: usd(j.available), total: usd(j.pending) + usd(j.available), at: new Date().toISOString() };
  stripeCache = { at: Date.now(), data };
  return data;
}
const CASH_FIELDS = ['checking9926', 'taxReserve7229', 'safe', 'venmo', 'ink2078', 'ink1602', 'amex91000',
  'personal5908', 'marcus6620', 'marcus6569', 'capone8760', 'discover6166', 'stocks', 'bills', 'stripe'];
// Balances from before the dashboard (imports.json "cash"), added once by date.
async function getCash() {
  let snaps = await kget(KEYS.cash, []);
  let imp = [];
  try { imp = JSON.parse(fs.readFileSync(path.join(__dirname, 'imports.json'), 'utf8')).cash || []; } catch {}
  if (imp.length) {
    const gone = new Set(await kget('bcd:deletedCash', [])), have = new Set(snaps.map(x => x.date));
    const add = imp.filter(x => !have.has(x.date) && !gone.has(x.date));
    if (add.length) { snaps = snaps.concat(add).sort((a, b) => a.date.localeCompare(b.date)); await kset(KEYS.cash, snaps); }
  }
  return snaps;
}
app.get('/api/cash', async (req, res) => {
  try {
    const [snaps, stripe] = await Promise.all([getCash(), stripeBalance(req.query.fresh === '1').catch(e => ({ error: e.message }))]);
    res.json({ ok: true, snaps, stripe });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/cash', async (req, res) => {
  try {
    const d = req.body || {};
    const date = /^\d{4}-\d{2}-\d{2}$/.test(d.date) ? d.date : new Date().toISOString().slice(0, 10);
    const snap = { date, savedAt: new Date().toISOString(), note: clean(d.note, 200) };
    CASH_FIELDS.forEach(k => { snap[k] = Math.round(Math.abs(numOf(d[k])) * 100) / 100; });
    if (d.stripe === '' || d.stripe == null) {
      const sb = await stripeBalance(true).catch(() => ({}));
      snap.stripe = sb.total || 0; snap.stripeAuto = !sb.error;
    }
    let snaps = (await kget(KEYS.cash, [])).filter(x => x.date !== date);
    snaps.push(snap); snaps.sort((a, b) => a.date.localeCompare(b.date));
    await kset(KEYS.cash, snaps);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/cash/delete', async (req, res) => {
  try {
    const snaps = (await kget(KEYS.cash, [])).filter(x => x.date !== req.body.date);
    await kset(KEYS.cash, snaps);
    const g = await kget('bcd:deletedCash', []); if (!g.includes(req.body.date)) { g.push(req.body.date); await kset('bcd:deletedCash', g); }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------- competitor ads (moved from the separate Ad Tracker) ----------
// Pulls competitors' Meta ads from the Facebook Ad Library through Apify once a day
// and keeps every ad it has seen, so you can rank them by how long they've run.
const ADS = {
  TOKEN: (process.env.APIFY_TOKEN || '').trim(),
  ACTOR: process.env.APIFY_ACTOR || 'apify~facebook-ads-scraper',
  PER_BRAND: Number(process.env.RESULTS_PER_BRAND || 100),
  HOUR_CT: Number(process.env.RUN_HOUR_CT || 6),
  BASE: process.env.APIFY_BASE || 'https://api.apify.com',
  // Point these at the old Ad Tracker's Upstash to keep its history (defaults to the dashboard's).
  REDIS_URL: (process.env.ADS_REDIS_URL || process.env.UPSTASH_REDIS_REST_URL || '').trim(),
  REDIS_TOKEN: (process.env.ADS_REDIS_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN || '').trim(),
  KEY: 'adtracker:v1',
};
let BRANDS = [];
try { BRANDS = JSON.parse(fs.readFileSync(path.join(__dirname, 'brands.json'), 'utf8')); } catch { console.log('No brands.json'); }
let adsMem = null, adsRunning = false;
async function adsLoad() {
  if (ADS.REDIS_URL) {
    try {
      const r = await fetch(`${ADS.REDIS_URL}/get/${ADS.KEY}`, { headers: { Authorization: `Bearer ${ADS.REDIS_TOKEN}` } });
      const j = await r.json();
      if (j.result) return JSON.parse(j.result);
    } catch (e) { console.error('Ads load failed:', e.message); }
  }
  else { try { const v = await kget(ADS.KEY, null); if (v) return v; } catch {} }
  return adsMem || { ads: {}, pages: {}, lastRun: null, lastError: null, runs: [] };
}
async function adsSave(state) {
  adsMem = state;
  if (!ADS.REDIS_URL) { try { await kset(ADS.KEY, state); } catch {} return; }
  try { await fetch(`${ADS.REDIS_URL}/set/${ADS.KEY}`, { method: 'POST', headers: { Authorization: `Bearer ${ADS.REDIS_TOKEN}` }, body: JSON.stringify(state) }); }
  catch (e) { console.error('Ads save failed:', e.message); }
}
const adsNorm = s => String(s || '').toLowerCase().replace(/[^a-z0-9]/g, '');
function adsLibraryUrl(brand, pageId) {
  const base = 'https://www.facebook.com/ads/library/?active_status=all&ad_type=all&country=US&media_type=all';
  if (pageId) return `${base}&search_type=page&view_all_page_id=${pageId}`;
  return `${base}&search_type=keyword_exact_phrase&q=${encodeURIComponent('"' + brand.name + '"')}`;
}
async function adsRunApify(startUrls) {
  const t = ADS.TOKEN;
  const start = await fetch(`${ADS.BASE}/v2/acts/${ADS.ACTOR}/runs?token=${t}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ startUrls: startUrls.map(url => ({ url })), resultsLimit: ADS.PER_BRAND * startUrls.length, activeStatus: '', isDetailsPerAd: false }),
  });
  const sj = await start.json();
  if (!sj.data || !sj.data.id) throw new Error('Apify did not start: ' + JSON.stringify(sj).slice(0, 300));
  let run = sj.data;
  for (let i = 0; i < 80 && ['READY', 'RUNNING'].includes(run.status); i++) {
    await new Promise(r => setTimeout(r, 15000));
    run = (await (await fetch(`${ADS.BASE}/v2/actor-runs/${sj.data.id}?token=${t}`)).json()).data;
  }
  if (run.status !== 'SUCCEEDED') throw new Error('Apify run ended with status ' + run.status);
  return (await fetch(`${ADS.BASE}/v2/datasets/${run.defaultDatasetId}/items?clean=true&format=json&token=${t}`)).json();
}
function adsToAd(it, brandName, now) {
  const s = it.snapshot || {}, card = (s.cards && s.cards[0]) || {}, vid = (s.videos && s.videos[0]) || {}, img = (s.images && s.images[0]) || {};
  const video = vid.videoHdUrl || vid.videoSdUrl || card.videoHdUrl || card.videoSdUrl || null;
  const image = vid.videoPreviewImageUrl || card.videoPreviewImageUrl || img.originalImageUrl || img.resizedImageUrl || card.originalImageUrl || card.resizedImageUrl || null;
  const body = (s.body && (s.body.text || s.body)) || card.body || '';
  return { id: String(it.adArchiveID || it.adArchiveId || it.ad_archive_id), brand: brandName, pageId: String(it.pageID || it.pageId || ''), pageName: it.pageName || '',
    start: it.startDate ? it.startDate * 1000 : null, end: it.endDate ? it.endDate * 1000 : null, active: !!it.isActive, platforms: it.publisherPlatform || [],
    format: (s.displayFormat || (video ? 'VIDEO' : 'IMAGE')).toUpperCase(), title: s.title || card.title || '', body: typeof body === 'string' ? body : '',
    cta: s.ctaText || card.ctaText || '', link: s.linkUrl || card.linkUrl || '', video, image, versions: (s.cards && s.cards.length) || 1, lastSeen: now };
}
async function adsRefresh() {
  if (adsRunning) return { skipped: true };
  if (!ADS.TOKEN) throw new Error('APIFY_TOKEN is not set');
  adsRunning = true;
  const state = await adsLoad(), now = Date.now();
  try {
    const items = await adsRunApify(BRANDS.map(b => adsLibraryUrl(b, b.pageId || state.pages[b.name])));
    const seen = new Set();
    for (const it of items) {
      const pn = adsNorm(it.pageName);
      const brand = BRANDS.find(b => adsNorm(b.name) === pn || (b.pageId && String(it.pageID) === String(b.pageId)) || (state.pages[b.name] && String(it.pageID) === state.pages[b.name]));
      if (!brand) continue;
      if (it.pageID && !state.pages[brand.name]) state.pages[brand.name] = String(it.pageID);
      const ad = adsToAd(it, brand.name, now);
      if (!ad.id || ad.id === 'undefined') continue;
      const prev = state.ads[ad.id];
      ad.firstSeen = prev ? prev.firstSeen : now;
      state.ads[ad.id] = { ...prev, ...ad };
      seen.add(ad.id);
    }
    for (const ad of Object.values(state.ads)) if (ad.active && !seen.has(ad.id)) { ad.active = false; ad.end = ad.end && ad.end < now ? ad.end : now; }
    state.lastRun = now; state.lastError = null;
    state.runs = [{ at: now, items: items.length, kept: seen.size }, ...(state.runs || [])].slice(0, 30);
    await adsSave(state);
    return { items: items.length, kept: seen.size };
  } catch (e) { state.lastError = { at: now, message: e.message }; await adsSave(state); throw e; }
  finally { adsRunning = false; }
}
const ctHour = () => Number(new Date().toLocaleString('en-US', { timeZone: 'America/Chicago', hour: 'numeric', hour12: false }));
if (ADS.TOKEN) {
  setInterval(async () => {
    const s = await adsLoad();
    if ((!s.lastRun || Date.now() - s.lastRun > 20 * 3600 * 1000) && ctHour() === ADS.HOUR_CT) adsRefresh().catch(e => console.error('Scheduled ads refresh failed:', e.message));
  }, 10 * 60 * 1000);
}
app.get('/api/ads', async (req, res) => {
  try {
    const s = await adsLoad(), now = Date.now();
    const ads = Object.values(s.ads).map(a => { const endAt = a.active ? now : (a.end || a.lastSeen || now); return { ...a, days: a.start ? Math.max(1, Math.round((endAt - a.start) / 86400000)) : null }; });
    res.json({ ok: true, brands: BRANDS.map(b => b.name), mine: BRANDS.filter(b => b.mine).map(b => b.name), ads, lastRun: s.lastRun, lastError: s.lastError, running: adsRunning, hasToken: !!ADS.TOKEN });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/ads/refresh', (req, res) => {
  if (!ADS.TOKEN) return res.status(400).json({ error: 'Add APIFY_TOKEN in Railway first.' });
  if (adsRunning) return res.json({ ok: true, running: true });
  adsRefresh().catch(e => console.error('Manual ads refresh failed:', e.message));
  res.json({ ok: true, started: true });
});

// ---------- goals ----------
const GOAL_SEED = { '2026-10': { sales: 50 }, '2026-11': { sales: 55, revenue: 70000, net: 20000, avg: 1275 } };
async function getGoals() { let g = await kget('bcd:goals', null); if (g === null) { g = GOAL_SEED; await kset('bcd:goals', g); } return g; }
app.post('/api/goals', async (req, res) => {
  try {
    const { month, goals } = req.body || {};
    if (!/^\d{4}-\d{2}$/.test(month)) return res.status(400).json({ error: 'bad month' });
    const g = await getGoals(), o = {};
    ['sales', 'revenue', 'net', 'avg', 'labor'].forEach(k => { const v = Number(goals && goals[k]); if (v > 0) o[k] = v; });
    g[month] = o; await kset('bcd:goals', g);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------- couch photos ----------
// Each photo is shrunk in the browser (about 100-300 KB) and saved in Upstash under its own key.
const photoKey = k => 'bcd:photo:' + String(k).replace(/[^a-zA-Z0-9:_-]/g, '').slice(0, 120);
app.post('/api/photo', async (req, res) => {
  try {
    const { key, data } = req.body || {};
    if (!key || !/^data:image\/(jpeg|png|webp);base64,/.test(data || '')) return res.status(400).json({ error: 'Pick a photo' });
    if (data.length > 1.3e6) return res.status(400).json({ error: 'Photo too large' });
    await kset(photoKey(key), data);
    const idx = await kget('bcd:photos', {}); idx[key] = Date.now(); await kset('bcd:photos', idx);
    res.json({ ok: true, v: idx[key] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/photo/delete', async (req, res) => {
  try {
    const idx = await kget('bcd:photos', {}); delete idx[req.body.key]; await kset('bcd:photos', idx);
    await kset(photoKey(req.body.key), '');
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/photo/:key', async (req, res) => {
  try {
    const data = await kget(photoKey(req.params.key), '');
    const m = String(data).match(/^data:(image\/[a-z]+);base64,(.*)$/);
    if (!m) return res.status(404).send('No photo');
    res.setHeader('Content-Type', m[1]); res.setHeader('Cache-Control', 'private, max-age=604800');
    res.send(Buffer.from(m[2], 'base64'));
  } catch (e) { res.status(500).send(e.message); }
});

// ---------- bank balances (Plaid) ----------
// Railway variables: PLAID_CLIENT_ID, PLAID_SECRET, PLAID_ENV (sandbox | production).
// Bank access tokens are encrypted at rest (AES-256-GCM). Key: PLAID_ENC_KEY, or derived from APP_PASSWORD.
const PLAID_KEY = require('crypto').createHash('sha256').update('bcd-plaid:' + (process.env.PLAID_ENC_KEY || process.env.APP_PASSWORD || '')).digest();
function plaidSeal(obj) {
  const c = require('crypto'), iv = c.randomBytes(12), ci = c.createCipheriv('aes-256-gcm', PLAID_KEY, iv);
  const data = Buffer.concat([ci.update(JSON.stringify(obj), 'utf8'), ci.final()]);
  return { enc: 1, iv: iv.toString('base64'), tag: ci.getAuthTag().toString('base64'), data: data.toString('base64') };
}
function plaidOpen(v) {
  if (Array.isArray(v)) return v;                       // older unencrypted value
  if (!v || !v.enc) return [];
  try { const d = require('crypto').createDecipheriv('aes-256-gcm', PLAID_KEY, Buffer.from(v.iv, 'base64')); d.setAuthTag(Buffer.from(v.tag, 'base64'));
    return JSON.parse(Buffer.concat([d.update(Buffer.from(v.data, 'base64')), d.final()]).toString('utf8')); } catch { return []; }
}
async function getPlaidItems() { const v = await kget('bcd:plaidItems', []); const items = plaidOpen(v); if (Array.isArray(v) && v.length) await setPlaidItems(items); return items; }
async function setPlaidItems(items) { await kset('bcd:plaidItems', plaidSeal(items || [])); }
// Each bank login is one "Item". Access tokens are kept in Upstash, never sent to the browser.
const PLAID = {
  ID: (process.env.PLAID_CLIENT_ID || '').trim(),
  SECRET: (process.env.PLAID_SECRET || '').trim(),
  ENV: (process.env.PLAID_ENV || 'production').trim(),
};
// Last 4 of each account -> the Daily Cash field it fills.
const MASK_FIELD = { '9926': 'checking9926', '7229': 'taxReserve7229', '5908': 'personal5908', '6620': 'marcus6620', '6569': 'marcus6569',
  '2078': 'ink2078', '1602': 'ink1602', '1000': 'amex91000', '91000': 'amex91000', '8760': 'capone8760', '6166': 'discover6166' };
async function plaid(pathname, body) {
  if (!PLAID.ID || !PLAID.SECRET) throw new Error('Add PLAID_CLIENT_ID and PLAID_SECRET in Railway first.');
  const r = await fetch(`https://${PLAID.ENV}.plaid.com${pathname}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_id: PLAID.ID, secret: PLAID.SECRET, ...body }),
  });
  const j = await r.json();
  if (j.error_code) throw new Error(`Plaid: ${j.display_message || j.error_message} (${j.error_code})`);
  return j;
}
app.post('/api/plaid/link-token', async (req, res) => {
  try {
    const body = { user: { client_user_id: 'billys-couches-owner' }, client_name: "Billy's HQ", country_codes: ['US'], language: 'en' };
    if (req.body && req.body.itemId) {   // re-connect a bank that needs a fresh login
      const items = await getPlaidItems(), it = items.find(x => x.item_id === req.body.itemId);
      if (!it) return res.status(404).json({ error: 'Bank not found' });
      body.access_token = it.access_token;
    } else body.products = ['transactions'];
    const j = await plaid('/link/token/create', body);
    res.json({ ok: true, link_token: j.link_token });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/plaid/exchange', async (req, res) => {
  try {
    const { public_token, institution } = req.body || {};
    const j = await plaid('/item/public_token/exchange', { public_token });
    const items = (await getPlaidItems()).filter(x => x.item_id !== j.item_id);
    items.push({ item_id: j.item_id, access_token: j.access_token, institution: clean(institution, 60) || 'Bank', added: new Date().toISOString() });
    await setPlaidItems( items);
    plaidCache = { at: 0, data: null };
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/plaid/remove', async (req, res) => {
  try {
    const items = await getPlaidItems(), it = items.find(x => x.item_id === req.body.itemId);
    if (it) { try { await plaid('/item/remove', { access_token: it.access_token }); } catch {} }
    await setPlaidItems( items.filter(x => x.item_id !== req.body.itemId));
    plaidCache = { at: 0, data: null };
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
let plaidCache = { at: 0, data: null };
// live = ask each bank right now (Plaid Balance, billed per call). Otherwise Plaid's saved balance (free, can be hours old).
async function plaidBalances(force, live) {
  if (!force && !live && plaidCache.data && Date.now() - plaidCache.at < 10 * 60 * 1000) return plaidCache.data;
  const items = await getPlaidItems(), banks = [], fields = {};
  let liveNote = '';
  for (const it of items) {
    try {
      let j;
      if (live) { try { j = await plaid('/accounts/balance/get', { access_token: it.access_token }); }
        catch (e) { if (/ITEM_LOGIN_REQUIRED|PENDING_EXPIRATION/.test(e.message)) throw e; liveNote = 'Live balance not available for some banks (' + e.message.slice(0, 80) + '), showing saved balance'; j = await plaid('/accounts/get', { access_token: it.access_token }); } }
      else j = await plaid('/accounts/get', { access_token: it.access_token });
      const accounts = j.accounts.map(a => {
        const field = MASK_FIELD[a.mask] || MASK_FIELD[String(a.mask || '').slice(-4)] || '';
        const bal = a.balances.current != null ? a.balances.current : a.balances.available;
        const val = Math.round(Math.abs(Number(bal) || 0) * 100) / 100;   // cards: amount owed
        if (field) fields[field] = (fields[field] || 0) + val;
        return { name: a.official_name || a.name, mask: a.mask, type: a.type, subtype: a.subtype, current: a.balances.current, available: a.balances.available, field };
      });
      banks.push({ item_id: it.item_id, institution: it.institution, accounts });
    } catch (e) { banks.push({ item_id: it.item_id, institution: it.institution, error: e.message, relink: /ITEM_LOGIN_REQUIRED|PENDING_EXPIRATION/.test(e.message) }); }
  }
  plaidCache = { at: Date.now(), data: { banks, fields, at: new Date().toISOString(), live: !!live && !liveNote, liveNote, configured: !!(PLAID.ID && PLAID.SECRET), env: PLAID.ENV } };
  return plaidCache.data;
}
app.get('/api/plaid/balances', async (req, res) => {
  try { res.json({ ok: true, ...(await plaidBalances(req.query.fresh === '1', req.query.live === '1')) }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// ===================================================================
// AUTO EXPENSES from linked banks + cards (Plaid /transactions/sync)
// Business accounts -> Sales Tracker expenses. Personal accounts -> Personal P&L (rent / groceries / other).
// Transfers, card payments and money coming in are skipped. Anything unsure waits in "Review new".
// ===================================================================
const TXN = { ignored: 'bcd:txnIgnored', rules: 'bcd:txnRules', inbox: 'bcd:txnInbox', seen: 'bcd:txnSeen', cursor: 'bcd:txnCursor', ppl: 'bcd:pplTxns', meta: 'bcd:txnMeta', all: 'bcd:txnAll' };
const BIZ_CATS = ['Advertising', 'Payroll', 'Rent', 'Fuel', 'Supplies', 'Software', 'Truck', 'Insurance', 'Utilities', 'Freight', 'Equipment', 'Other'];
const PPL_CATS = { rent: 'Rent', groceries: 'Groceries', eatingOut: 'Eating out', subscriptions: 'Subscriptions', needs: 'Needs', education: 'Education', travel: 'Travel', otherOut: 'Other', otherIn: 'Other income' };
// Built-in guesses (your own "remember this" rules always win).
const BIZ_GUESS = [[/facebook|facebk|meta ?ads|^fb |fb ads|instagram|google ?ads|tiktok ads|nextdoor/i, 'Advertising'], [/zapier|railway|upstash|jotform|textmagic|squarespace|google ?(workspace|gsuite)|canva|notion|openai|anthropic|claude|stripe fee|apify|ivy ?flip|quickbooks|adobe|capcut/i, 'Software'],
  [/shell|qt |quiktrip|bp |exxon|mobil|phillips 66|casey|speedway|marathon|circle k|\bgas\b|fuel/i, 'Fuel'], [/home depot|lowe|menards|uline|harbor freight|walmart|amazon|scotchgard|ace hardware/i, 'Supplies'],
  [/u-?haul|penske|ryder|tire|jiffy|valvoline|autozone|o.?reilly|advance auto/i, 'Truck'], [/progressive|state farm|geico|insurance|next insurance/i, 'Insurance'], [/ameren|spire|at&t|verizon|t-?mobile|comcast|spectrum|water/i, 'Utilities'],
  [/b-?stock|ch robinson|freight|uship/i, 'Freight'], [/forklift/i, 'Equipment']];
const PPL_GUESS = [[/schnucks|aldi|dierbergs|hy-?vee|kroger|trader joe|whole foods|sam'?s club|costco|grocery|walmart super/i, 'groceries'],
  [/netflix|spotify|hulu|disney|youtube premium|apple\.com\/bill|icloud|amazon prime|hbo|max\.com|peacock|paramount|chatgpt|gym|planet fitness|crunch|audible|patreon/i, 'subscriptions'],
  [/mcdonald|chick-?fil|starbucks|chipotle|taco bell|wendy|burger|panera|subway|domino|pizza|doordash|uber ?eats|grubhub|restaurant|grill|cafe|coffee|bar & grill|wingstop|raising cane/i, 'eatingOut'],
  [/airline|delta|american air|united|southwest|spirit|frontier|hotel|marriott|hilton|airbnb|vrbo|expedia|booking\.com|uber(?! ?eats)|lyft/i, 'travel'],
  [/udemy|coursera|skool|masterclass|book|barnes|tuition|school|course/i, 'education'],
  [/walgreens|cvs|pharmacy|target|clinic|doctor|dental|haircut|barber|great clips|laundry/i, 'needs']];
const P2P = /venmo|zelle|cash ?app|paypal|apple cash/i;
const vkey = t => String((P2P.test((t.name || '') + ' ' + (t.merchant_name || '')) ? t.name : (t.merchant_name || t.name)) || '').toLowerCase().replace(/[#*]\S*|\d{3,}/g, ' ').replace(/[^a-z&' ]+/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 40);
// Nothing is dropped. These just get a note and go to Review so you decide.
const skipNote = t => {
  if (!(t.amount > 0)) return 'Money in';
  if (P2P.test((t.name || '') + ' ' + (t.merchant_name || ''))) return '';
  const pf = t.personal_finance_category || {}, p = pf.primary || '', d = pf.detailed || '';
  if (p === 'INCOME' || p === 'TRANSFER_IN') return 'Money in';
  if (p === 'LOAN_PAYMENTS' || /\b(autopay|card ?pmt|online pymt|credit card payment|payment thank you|thank you)\b/i.test(t.name || '')) return 'Looks like a card/loan payment';
  if (/^TRANSFER_OUT_(ACCOUNT_TRANSFER|SAVINGS|INVESTMENT)/.test(d)) return 'Looks like a move between your accounts';
  return '';
};
async function txnRules(){ const r = (await kget(TXN.rules, null)) || {}; r.accounts = r.accounts || {}; r.vendors = r.vendors || {}; return r; }
// Accounts + their scope (business / personal / ignore). Guessed from the Daily Cash mapping until you set it.
async function txnAccounts(){
  const pb = await plaidBalances(false).catch(() => ({ banks: [] })), rules = await txnRules(), out = [];
  (pb.banks || []).forEach(b => (b.accounts || []).forEach(a => {
    const f = a.field || '', guess = /personal/.test(f) ? 'personal' : /checking|ink|amex/.test(f) ? 'business' : '';
    const id = `${b.item_id}:${a.mask || a.name}`;
    out.push({ id, item_id: b.item_id, institution: b.institution, name: a.name, mask: a.mask, type: a.type, scope: rules.accounts[id] || guess, guessed: !rules.accounts[id] && !!guess });
  }));
  return out;
}
let txnBusy = null;
async function txnSync(){
  if (txnBusy) return txnBusy;
  txnBusy = (async () => {
    if (!PLAID.ID || !PLAID.SECRET) return { error: 'Plaid is not set up' };
    const items = await getPlaidItems(); if (!items.length) return { added: 0 };
    const meta = (await kget(TXN.meta, null)) || {};
    if (!meta.since) { meta.since = new Date().toLocaleDateString('en-CA', { timeZone: 'America/Chicago' }).slice(0, 8) + '01'; }   // start with this month, no back-fill
    const cursors = (await kget(TXN.cursor, null)) || {}, seen = new Set((await kget(TXN.seen, [])) || []), rules = await txnRules(), accts = await txnAccounts();
    const scopeOf = (item, t) => { const a = accts.find(x => x.item_id === item && x.mask && x.mask === t.account_mask); return a ? a.scope : ''; };
    const exp = await kget(KEYS.expenses, []), ppl = (await kget(TXN.ppl, [])) || [], inbox = (await kget(TXN.inbox, [])) || [];
    const have = new Set([...((await kget(TXN.ignored, [])) || []), ...exp.filter(x => x.auto).map(x => String(x.id).replace(/^tx_/, '')), ...ppl.map(x => x.id), ...inbox.map(x => x.id)]);
    let added = 0, queued = 0, skipped = 0, errors = [];
    const allTx = (await kget(TXN.all, null)) || {};   // every posted transaction we got, so nothing can go missing
    const hasVenmo = items.some(x => /venmo/i.test(x.institution || ''));
    for (const it of items) {
      let cursor = cursors[it.item_id] || '', more = true, guard = 0, accMap = {};
      try {
        while (more && guard++ < 20) {
          const j = await plaid('/transactions/sync', { access_token: it.access_token, cursor: cursor || undefined, count: 500 });
          (j.accounts || []).forEach(a => { accMap[a.account_id] = a.mask; });
          for (const t of [...(j.added || []), ...(j.modified || [])]) {
            if (!t.pending && (t.authorized_date || t.date) >= meta.since) allTx[t.transaction_id] = { id: t.transaction_id, date: t.authorized_date || t.date, name: (P2P.test((t.name || '') + ' ' + (t.merchant_name || '')) ? t.name : t.merchant_name) || t.name, raw: t.name, amount: Math.round(t.amount * 100) / 100, item: it.item_id, institution: it.institution, mask: accMap[t.account_id] || '', pfc: ((t.personal_finance_category || {}).detailed || '') };
            if (t.pending || seen.has(t.transaction_id) || have.has(t.transaction_id)) continue;
            const date = t.authorized_date || t.date; if (!date || date < meta.since) { seen.add(t.transaction_id); continue; }
            seen.add(t.transaction_id);
            t.account_mask = accMap[t.account_id];
            const note = skipNote(t);
            const scope = scopeOf(it.item_id, t), key = vkey(t), rule = rules.vendors[key], amount = Math.round(t.amount * 100) / 100, review = x => { inbox.push({ ...base, scope: scope === 'ignore' ? '' : scope, suggest: '', ...x }); queued++; };
            const base = { id: t.transaction_id, date, name: (P2P.test((t.name || '') + ' ' + (t.merchant_name || '')) ? t.name : t.merchant_name) || t.name, raw: t.name, amount, key, item: it.item_id, mask: t.account_mask || '', institution: it.institution, pfc: ((t.personal_finance_category || {}).detailed || '') };
            if (rule === 'ignore') { skipped++; continue; }   // only vendors YOU said to ignore
            if (note) { review({ note }); continue; }
            // Venmo linked too? The bank line is just Venmo pulling money; the real payment (with the name) comes from the Venmo account.
            if (hasVenmo && !/venmo/i.test(it.institution || '') && /venmo/i.test(base.raw + ' ' + base.name)) { review({ note: 'Bank side of a Venmo payment. The Venmo account already has it, so Ignore this one' }); continue; }
            if (scope === 'ignore') { review({ note: 'From an account set to Ignore' }); continue; }
            if (!scope || (rule && rule.scope && rule.scope !== scope && !P2P.test(t.name || ''))) { inbox.push({ ...base, scope: scope || '', suggest: rule ? rule.cat : '' }); queued++; continue; }
            if (scope === 'business') {
              const xfer = /^TRANSFER_OUT/.test(base.pfc);
              const cat = rule && rule.scope === 'business' ? rule.cat : (!P2P.test(base.raw) && !xfer && (BIZ_GUESS.find(([re]) => re.test(base.name + ' ' + base.raw)) || [])[1]);
              // already typed in by hand (same amount within 3 days)? don't add it twice
              if (exp.some(x => !x.auto && Math.abs((Number(x.amount) || 0) - amount) < 0.01 && Math.abs(Date.parse(x.date) - Date.parse(date)) <= 3 * 864e5)) { if (allTx[t.transaction_id]) allTx[t.transaction_id].dupe = true; skipped++; continue; }
              if (cat) { exp.push({ id: 'tx_' + t.transaction_id, date, category: cat, amount, vendor: base.name, notes: `Auto · ${it.institution}${base.mask ? ' ••' + base.mask : ''}`, auto: true }); added++; }
              else { inbox.push({ ...base, scope, suggest: /DIGITAL_ADVERTISING|ADVERTISING/.test(base.pfc) ? 'Advertising' : '' }); queued++; }
            } else {
              const cat = rule && rule.scope === 'personal' ? rule.cat : (P2P.test(base.raw) || /^TRANSFER_OUT/.test(base.pfc)) ? '' : ((PPL_GUESS.find(([re]) => re.test(base.name)) || [])[1] || (/GROCERIES/.test(base.pfc) ? 'groceries' : /RENT_AND_UTILITIES_RENT/.test(base.pfc) ? 'rent' : /FOOD_AND_DRINK/.test(base.pfc) ? 'eatingOut' : /^TRAVEL/.test(base.pfc) ? 'travel' : /SUBSCRIPTION|STREAMING/.test(base.pfc) ? 'subscriptions' : /EDUCATION/.test(base.pfc) ? 'education' : /MEDICAL|PERSONAL_CARE|PHARMAC/.test(base.pfc) ? 'needs' : 'otherOut'));
              if (cat) { ppl.push({ id: t.transaction_id, date, amount, name: base.name, cat }); added++; }
              else { inbox.push({ ...base, scope, suggest: 'otherOut' }); queued++; }
            }
          }
          cursor = j.next_cursor; more = j.has_more;
        }
        cursors[it.item_id] = cursor;
      } catch (e) { errors.push(`${it.institution}: ${e.message}`); }
    }
    await kset(KEYS.expenses, exp); await kset(TXN.ppl, ppl.slice(-5000)); await kset(TXN.inbox, inbox.slice(-3000)); { const ks = Object.keys(allTx); if (ks.length > 6000) ks.sort((a, b) => allTx[a].date.localeCompare(allTx[b].date)).slice(0, ks.length - 6000).forEach(k => delete allTx[k]); } await kset(TXN.all, allTx); await kset(TXN.cursor, cursors); await kset(TXN.seen, [...seen].slice(-8000));
    meta.lastSync = new Date().toISOString(); meta.lastErrors = errors; await kset(TXN.meta, meta);
    return { added, queued, skipped, errors };
  })().finally(() => { txnBusy = null; });
  return txnBusy;
}
// Keep it fresh: every 3 hours, and when HQ is opened if it's been 30+ minutes.
setInterval(() => txnSync().catch(e => console.log('Txn sync failed', e.message)), 3 * 3600e3);
async function txnMaybeSync(){ const m = (await kget(TXN.meta, null)) || {}; if (!m.lastSync || Date.now() - Date.parse(m.lastSync) > 30 * 60e3) txnSync().catch(() => {}); }
app.get('/api/txn', async (req, res) => {
  try { if (req.query.sync === '1') await txnSync(); else txnMaybeSync().catch(() => {});
    const [inbox, accounts, rules, meta, ppl] = await Promise.all([kget(TXN.inbox, []), txnAccounts(), txnRules(), kget(TXN.meta, null), kget(TXN.ppl, [])]);
    res.json({ ok: true, inbox: inbox || [], accounts, vendors: rules.vendors, meta: meta || {}, ppl: ppl || [], bizCats: BIZ_CATS, pplCats: PPL_CATS, configured: !!(PLAID.ID && PLAID.SECRET) }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/txn/account', async (req, res) => {
  try { const r = await txnRules(), id = clean(req.body.id, 120), scope = ['business', 'personal', 'ignore', ''].includes(req.body.scope) ? req.body.scope : '';
    if (scope) r.accounts[id] = scope; else delete r.accounts[id]; await kset(TXN.rules, r); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
// Review: { id, scope: business|personal|ignore, cat, remember } or { all: true } to accept every suggestion.
app.post('/api/txn/review', async (req, res) => {
  try {
    const inbox = (await kget(TXN.inbox, [])) || [], r = await txnRules(), exp = await kget(KEYS.expenses, []), ppl = (await kget(TXN.ppl, [])) || [];
    const todo = req.body.all ? inbox.filter(t => t.scope && !t.note && (t.suggest || t.scope === 'personal')).map(t => ({ id: t.id, scope: t.scope, cat: t.suggest || (t.scope === 'personal' ? 'otherOut' : ''), remember: false })) : [req.body];
    let done = 0; const ign = (await kget(TXN.ignored, [])) || [];
    for (const q of todo) {
      const i = inbox.findIndex(t => t.id === q.id); if (i < 0) continue; const t = inbox[i], scope = q.scope;
      if (scope === 'business') { const cat = BIZ_CATS.includes(q.cat) ? q.cat : ''; if (!cat) continue;
        exp.push({ id: 'tx_' + t.id, date: t.date, category: cat, amount: t.amount, vendor: t.name, notes: `Auto · ${t.institution}${t.mask ? ' ••' + t.mask : ''}`, auto: true });
        if (q.remember) r.vendors[t.key] = { scope, cat }; }
      else if (scope === 'personal') { const cat = PPL_CATS[q.cat] ? q.cat : 'otherOut'; ppl.push({ id: t.id, date: t.date, amount: t.amount, name: t.name, cat });
        if (q.remember) r.vendors[t.key] = { scope, cat }; }
      else if (scope === 'ignore') { if (q.remember) r.vendors[t.key] = 'ignore'; ign.push(t.id); }
      else continue;
      inbox.splice(i, 1); done++;
    }
    await Promise.all([kset(TXN.inbox, inbox), kset(TXN.rules, r), kset(KEYS.expenses, exp), kset(TXN.ppl, ppl), kset(TXN.ignored, ign.slice(-3000))]);
    res.json({ ok: true, done, left: inbox.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// Every synced transaction this month and where it went.
app.get('/api/txn/all', async (req, res) => {
  try {
    const [all, exp, ppl, inbox, ign, rules] = await Promise.all([kget(TXN.all, {}), kget(KEYS.expenses, []), kget(TXN.ppl, []), kget(TXN.inbox, []), kget(TXN.ignored, []), txnRules()]);
    const e = new Map((exp || []).filter(x => x.auto).map(x => [String(x.id).replace(/^tx_/, ''), x])), p = new Map((ppl || []).map(x => [x.id, x])), q = new Set((inbox || []).map(x => x.id)), g = new Set(ign || []);
    const month = (req.query.month || new Date().toLocaleDateString('en-CA', { timeZone: 'America/Chicago' }).slice(0, 7));
    const list = Object.values(all || {}).filter(t => t.date.startsWith(month)).map(t => {
      const x = e.get(t.id), y = p.get(t.id);
      const status = t.dupe ? 'Already on tracker' : x ? 'Business: ' + x.category : y ? 'Personal: ' + (PPL_CATS[y.cat] || y.cat) : q.has(t.id) ? 'In Review' : g.has(t.id) ? 'Ignored' : rules.vendors[vkey({ name: t.raw, merchant_name: t.name })] === 'ignore' ? 'Ignored by rule' : 'Not sorted';
      return { ...t, status, canRedo: !x && !y && !q.has(t.id) };
    }).sort((a, b) => b.date.localeCompare(a.date) || b.amount - a.amount);
    res.json({ ok: true, list });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// Send an ignored / unsorted transaction back to Review.
app.post('/api/txn/redo', async (req, res) => {
  try {
    const id = clean(req.body.id, 120), all = (await kget(TXN.all, {})) || {}, t = all[id]; if (!t) return res.status(404).json({ error: 'Not found' });
    if (t.dupe) { delete t.dupe; await kset(TXN.all, all); }
    const inbox = (await kget(TXN.inbox, [])) || [], ign = ((await kget(TXN.ignored, [])) || []).filter(x => x !== id), accts = await txnAccounts();
    if (!inbox.some(x => x.id === id)) { const a = accts.find(x => x.item_id === t.item && x.mask && x.mask === t.mask), scope = a && a.scope !== 'ignore' ? a.scope : '';
      inbox.push({ ...t, key: vkey({ name: t.raw, merchant_name: t.name }), scope, suggest: '', note: 'Sent back to review' }); }
    await kset(TXN.inbox, inbox); await kset(TXN.ignored, ign); res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// Re-check everything since the start date (picks up transfers the old rules skipped, like rent paid by Zelle).
app.post('/api/txn/rescan', async (req, res) => {
  try {
    const since = /^\d{4}-\d{2}-\d{2}$/.test(req.body.since || '') ? req.body.since : '';
    if (since) { const m = (await kget(TXN.meta, null)) || {}; if (!m.since || since < m.since) { m.since = since; await kset(TXN.meta, m); } }
    await kset(TXN.cursor, {}); await kset(TXN.seen, []); const j = await txnSync(); res.json({ ok: true, ...j }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/txn/rule-delete', async (req, res) => {
  try { const r = await txnRules(); delete r.vendors[clean(req.body.key, 60)]; await kset(TXN.rules, r); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});
// Move one personal transaction to another bucket (or remove it).
app.post('/api/txn/ppl', async (req, res) => {
  try { let l = (await kget(TXN.ppl, [])) || []; const x = l.find(t => t.id === req.body.id); if (!x) return res.status(404).json({ error: 'not found' });
    if (req.body.cat === 'remove') l = l.filter(t => t.id !== x.id); else if (PPL_CATS[req.body.cat]) x.cat = req.body.cat; await kset(TXN.ppl, l); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
// ===================== END AUTO EXPENSES =====================

// Every morning at 7am Central: if no entry exists for today, save one from the banks
// (safe, Venmo, stocks and rent carry over from your last entry; Stripe is pulled live).
async function autoCashSnapshot() {
  const items = await getPlaidItems();
  if (!items.length) return;
  const today = new Date().toLocaleDateString('en-CA', { timeZone: 'America/Chicago' });
  const snaps = await getCash();
  if (snaps.some(s => s.date === today)) return;
  const pb = await plaidBalances(true), last = snaps[snaps.length - 1] || {};
  if (!Object.keys(pb.fields).length) return;
  const snap = { ...last, date: today, savedAt: new Date().toISOString(), note: 'Auto from banks', auto: true, score: undefined, imported: undefined };
  Object.assign(snap, pb.fields);
  const sb = await stripeBalance(true).catch(() => ({}));
  if (!sb.error) { snap.stripe = sb.total || 0; snap.stripeAuto = true; }
  await kset(KEYS.cash, snaps.concat(snap).sort((a, b) => a.date.localeCompare(b.date)));
}
setInterval(() => { if (ctHour() === 7) autoCashSnapshot().catch(e => console.error('Auto cash failed:', e.message)); }, 15 * 60 * 1000);


// ---------- Cash for Your Couch (public form on billyscouches.com) ----------
const OFFER_ORIGINS = ['https://www.billyscouches.com', 'https://billyscouches.com'];
const offerHits = new Map();
const escH = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
function offerCors(req, res) {
  const o = req.headers.origin || '';
  if (OFFER_ORIGINS.includes(o) || /\.squarespace\.com$/.test(o)) { res.setHeader('Access-Control-Allow-Origin', o); res.setHeader('Vary', 'Origin'); }
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}
async function textAlert(msg) {
  const user = (process.env.TEXTMAGIC_USERNAME || '').trim(), key = (process.env.TEXTMAGIC_API_KEY || '').trim();
  const phones = (process.env.OFFER_ALERT_PHONES || '13148997503').replace(/[^\d,]/g, '');
  if (!user || !key) { console.log('[offer text skipped: add TEXTMAGIC_USERNAME + TEXTMAGIC_API_KEY]\n' + msg); return false; }
  const r = await fetch('https://rest.textmagic.com/api/v2/messages', {
    method: 'POST', headers: { 'X-TM-Username': user, 'X-TM-Key': key, 'Content-Type': 'application/json' },
    body: JSON.stringify({ text: msg, phones }),
  });
  if (!r.ok) { console.error('TextMagic', r.status, await r.text()); return false; }
  return true;
}
app.options('/public/couch-offer', (req, res) => { offerCors(req, res); res.sendStatus(204); });
app.post('/public/couch-offer', async (req, res) => {
  offerCors(req, res);
  try {
    const d = req.body || {};
    if (d.website) return res.json({ ok: true });               // honeypot: bots fill hidden fields
    const ip = String(req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim();
    const now = Date.now(), hits = (offerHits.get(ip) || []).filter(t => now - t < 10 * 60 * 1000);
    if (hits.length >= 5) return res.status(429).json({ error: 'Too many submissions. Please call (314) 899-7503.' });
    offerHits.set(ip, hits.concat(now));
    const first = clean(d.firstName, 40), last = clean(d.lastName, 40), phone = clean(d.phone, 30);
    const photos = (Array.isArray(d.photos) ? d.photos : []).filter(x => /^data:image\/(jpeg|png|webp);base64,/.test(x) && x.length < 1400000).slice(0, 10);
    if (!first || phone.replace(/\D/g, '').length < 10 || !clean(d.brand) || !photos.length || !clean(d.street) || !clean(d.heard))
      return res.status(400).json({ error: 'Please fill in every required field and add at least one photo.' });
    const id = now.toString(36) + crypto.randomBytes(3).toString('hex');
    const offer = {
      id, at: new Date().toISOString(), status: 'new',
      brand: clean(d.brand, 60), issues: (Array.isArray(d.issues) ? d.issues : []).map(x => clean(x, 40)).slice(0, 10),
      details: clean(d.details, 1000), asking: clean(d.asking, 60), helpLoad: clean(d.helpLoad, 5),
      firstName: first, lastName: last, phone, email: clean(d.email, 120),
      street: clean(d.street, 120), street2: clean(d.street2, 80), city: clean(d.city, 60), state: clean(d.state, 30), zip: clean(d.zip, 12),
      heard: clean(d.heard, 80), photoCount: photos.length,
    };
    for (let i = 0; i < photos.length; i++) await kset(`bcd:offerphoto:${id}:${i}`, photos[i]);
    const list = await kget('bcd:offers', []);
    list.unshift(offer); await kset('bcd:offers', list.slice(0, 500));
    const host = (process.env.PUBLIC_URL || 'https://hq.billyscouches.com').replace(/\/$/, '');
    textAlert(`🛋️ New couch offer\n${offer.brand} · asking ${offer.asking || '?'}\n${offer.issues.length ? 'Issues: ' + offer.issues.join(', ') + '\n' : ''}${first} ${last} · ${phone}\n${offer.city || offer.zip}\n${photos.length} photo${photos.length > 1 ? 's' : ''}: ${host}/?offer=${id}`).catch(e => console.error('text failed', e.message));
    res.json({ ok: true });
  } catch (e) { console.error('offer failed', e); res.status(500).json({ error: 'Something went wrong. Please call (314) 899-7503.' }); }
});
const OFFER_STATUS = { new: 'New', contacted: 'Contacted', scheduled: 'Scheduled', bought: 'Bought', passed: 'Passed' };
app.get('/offers', (req, res) => res.redirect('/?tab=offers'));
app.get('/api/offers', async (req, res) => {
  try { res.json({ ok: true, offers: await kget('bcd:offers', []) }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/offers/status', async (req, res) => {
  try {
    const list = await kget('bcd:offers', []), o = list.find(x => x.id === req.body.id);
    if (!o || !OFFER_STATUS[req.body.status]) return res.status(400).json({ error: 'Bad offer or status' });
    o.status = req.body.status; await kset('bcd:offers', list); res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/offers/:id/photo/:n', async (req, res) => {
  if (!authed(req)) return res.sendStatus(401);
  const d = await kget(`bcd:offerphoto:${req.params.id}:${Number(req.params.n) || 0}`, null);
  if (!d) return res.sendStatus(404);
  const m = String(d).match(/^data:(image\/\w+);base64,(.+)$/);
  res.set('Cache-Control', 'private, max-age=86400').type(m[1]).send(Buffer.from(m[2], 'base64'));
});
app.get('/offers/:id', (req, res) => res.redirect('/?offer=' + encodeURIComponent(req.params.id)));


// ---------- "Just sold" pop-ups on billyscouches.com (real sales only) ----------
let recentCache = { at: 0, data: null }, recentPhotos = {};
const cleanCouchName = n => String(n || '')
  .replace(/\([^)]*\)/g, ' ').replace(/\b(?=[A-Z0-9-]*\d)[A-Z0-9-]{6,}\b/g, ' ')   // drop SKUs / model codes
  .replace(/\b(sku|item|lot|qty|#)\s*:?\s*\S+/gi, ' ')
  .replace(/\bLthr\b/gi, 'Leather').replace(/\bPwr\b/gi, 'Power').replace(/\bRecl\b/gi, 'Reclining').replace(/\bFab\b/gi, 'Fabric')
  .replace(/\bMod\b/gi, 'Modular').replace(/\bSect?\b/gi, 'Sectional').replace(/\bTMV\b/g, 'Thomasville').replace(/\bLTG\b/g, 'Light Gray')
  .replace(/\b(\d+)\s*PC\b/gi, '$1-Piece').replace(/\s{2,}/g, ' ').trim().slice(0, 60);
app.get('/public/just-sold.js', (req, res) => res.set('Cache-Control', 'public, max-age=60').type('application/javascript').sendFile(path.join(__dirname, 'just-sold.js')));
app.options('/public/recent-sales', (req, res) => { offerCors(req, res); res.sendStatus(204); });
app.get('/public/recent-sales', async (req, res) => {
  offerCors(req, res);
  try {
    await buildRecent();
    res.set('Cache-Control', 'public, max-age=60').json({ ok: true, sales: recentCache.data });
  } catch (e) { res.status(500).json({ error: 'unavailable' }); }
});
// Couches on billyscouches.com/currentinventory (title + first photo). Remembered for 90 days so sold
// couches that come off the site can still be picked for the pop-up.
const SITE_URL = (process.env.SITE_INVENTORY_URL || 'https://www.billyscouches.com/currentinventory').trim();
let siteCache = { at: 0 };
const decodeHtml = t => String(t || '').replace(/<[^>]+>/g, ' ').replace(/&amp;/g, '&').replace(/&#39;|&rsquo;|&#8217;/g, "'").replace(/&quot;/g, '"').replace(/&nbsp;/g, ' ').replace(/&[a-z#0-9]+;/gi, ' ').replace(/\s+/g, ' ').trim();
function siteCouches(force) {
  if (force || !siteCache.p || Date.now() - siteCache.at > 30 * 60 * 1000) { siteCache.at = Date.now(); siteCache.p = refreshSite(); }
  return siteCache.p;
}
async function refreshSite() {
  const saved = await kget('bcd:siteCouches', {}).catch(() => ({}));
  {
    try {
      const html = await (await fetch(SITE_URL, { headers: { 'User-Agent': 'BillysHQ/1.0' } })).text();
      let img = null; const now = Date.now();
      html.split(/<section\b/i).slice(1).forEach(sec => {
        const tm = sec.match(/<p[^>]*class="[^"]*sqsrte-large[^"]*"[^>]*>([\s\S]*?)<\/p>/i);
        const title = tm ? decodeHtml(tm[1]) : '';
        if (title && title.length > 3 && title.length < 90 && !/^last updated/i.test(title)) {
          const k = title.toLowerCase(); saved[k] = { title, img: img || (saved[k] && saved[k].img) || '', seen: now, live: true }; img = null; return;
        }
        const im = sec.match(/(?:data-src|src)="(https:\/\/images\.squarespace-cdn\.com\/[^"?]+)/i);
        if (im) img = im[1];
      });
      const liveNow = new Set(Object.keys(saved).filter(k => saved[k].seen === now));
      Object.keys(saved).forEach(k => { if (!liveNow.has(k)) saved[k].live = false; if (now - (saved[k].seen || 0) > 90 * 864e5) delete saved[k]; });
      await kset('bcd:siteCouches', saved);
    } catch (e) { console.log('Site inventory unavailable', e.message); }
  }
  return Object.values(saved).sort((a, b) => (b.live - a.live) || (b.seen - a.seen));
}
const GENERIC = new Set('the a and with of in pc piece pieces sectional sofa couch set leather fabric power reclining recliner modular sleeper gray grey cream white black brown beige blue tan loveseat chaise 2pc 3pc 4pc 5pc 6pc 2 3 4 5 6 one two three four five six'.split(' '));
const words = n => String(n || '').toLowerCase().replace(/[^a-z0-9 ]/g, ' ').split(/\s+/).filter(w => w.length > 1);
function bestSiteMatch(name, list) {
  const a = new Set(words(name)); let best = null, bestS = 0;
  list.forEach(c => { let s = 0, key = 0; words(c.title).forEach(w => { if (a.has(w)) { if (GENERIC.has(w)) s += 1; else { s += 3; key++; } } }); if (key && s > bestS) { bestS = s; best = c; } });
  return best;
}
const saleKey = l => l.ts ? 't' + l.ts : 'r' + l.day + '|' + l.name.toLowerCase().replace(/\s+/g, ' ') + '|' + l.price;
// Sales Log rows (with exact receipt time when there is one).
async function salesLogRows() {
  const log = [];
  const g = await google(false), sh = (g.sales && g.sales.headers) || [], rows = (g.sales && g.sales.rows) || [];
  const H = sh.map(x => String(x).toLowerCase().trim());
  const col = (keys, not) => { for (const k of keys) { const i = H.indexOf(k); if (i > -1) return i; }
    for (const k of keys) { const i = H.findIndex(x => x.includes(k) && !(not || []).some(n => x.includes(n))); if (i > -1) return i; } return -1; };
  const C = { date: col(['date']), name: col(['customer', 'name'], ['first']), price: col(['couch price', 'price'], ['total', 'sale']), disc: col(['discount']), receipt: col(['receipt']) };
  const num = v => Number(String(v ?? '').replace(/[^\d.\-]/g, '')) || 0;
  rows.forEach((r, i) => {
    const m = String(C.receipt > -1 ? r[C.receipt] : '').match(/receipt\/(\d{13})/), ts = m ? Number(m[1]) : null;
    const d = ts ? new Date(ts) : new Date(String(r[C.date] || '')); if (isNaN(d)) return;
    const price = num(r[C.price]), net = price - Math.abs(num(r[C.disc]));
    const l = { i, day: d.toLocaleDateString('en-CA', { timeZone: 'America/Chicago' }), ts, name: String(r[C.name] || '').trim(), price, net, used: false };
    l.key = saleKey(l); log.push(l);
  });
  return log;
}
// Every Sales Log order in the last 5 days becomes a pop-up. The couch comes from (1) what you picked in HQ,
// (2) the couch marked Sold on the Sales Tracker for that order, else it says "a couch".
// Sale window (same times as the public order app). While it runs, the Just Sold pop-up says how much each buyer saved.
const SALE_WIN = { start: Date.parse(process.env.SALE_START || '2026-11-04T22:00:00-06:00'), end: Date.parse(process.env.SALE_END || '2026-11-06T23:59:00-06:00'), big: 250, small: 100, min: 999 };
const saleLive = () => process.env.SALE !== 'off' && Date.now() >= SALE_WIN.start && Date.now() < SALE_WIN.end;
const inSale = t => t >= SALE_WIN.start && t < SALE_WIN.end;
const saleSaved = (salePrice, listPrice) => listPrice ? (listPrice >= SALE_WIN.min ? SALE_WIN.big : SALE_WIN.small) : (Number(salePrice) + SALE_WIN.big >= SALE_WIN.min ? SALE_WIN.big : SALE_WIN.small);
async function recentOrders(days) {
  const [loads, purchases, picks, site, pidx, drops] = await Promise.all([getLoads(), getPurchases(), kget('bcd:soldPicks', {}).catch(() => ({})), siteCouches(false), kget('bcd:photos', {}).catch(() => ({})), getDrops().catch(() => [])]);
  let log = []; try { log = await salesLogRows(); } catch (e) { console.log('Just sold: Sales Log unavailable', e.message); }
  const dayDiff = (a, b) => Math.round((Date.parse(a) - Date.parse(b)) / 864e5);
  const sold = [];
  loads.forEach(l => (l.units || []).forEach(u => { if (u.status === 'sold' && u.soldDate) sold.push({ name: u.name, date: u.soldDate, price: u.soldPrice, pkey: 'u:' + l.id + ':' + u.uid, cust: u.soldCustomer }); }));
  purchases.forEach(p => { if (p.status === 'sold' && p.soldDate) sold.push({ name: p.item, date: p.soldDate, price: p.soldPrice, pkey: 'p:' + p.id, cust: p.soldCustomer }); });
  sold.sort((a, b) => (b.cust ? 1 : 0) - (a.cust ? 1 : 0));
  sold.forEach(c => {   // match tracker couches to Sales Log orders
    const cu = String(c.cust || '').toLowerCase().trim(), last = cu.split(/\s+/).pop();
    const pool = log.filter(l => !l.couch && dayDiff(c.date, l.day) >= -1 && dayDiff(c.date, l.day) <= 10);
    const byName = cu ? pool.filter(l => l.name.toLowerCase().includes(last)) : [];
    const byPrice = pool.filter(l => Math.abs(l.price - c.price) < 1 || Math.abs(l.net - c.price) < 1);
    const hit = (byName.length ? byName : byPrice).sort((a, b) => Math.abs(dayDiff(c.date, a.day)) - Math.abs(dayDiff(c.date, b.day)))[0];
    if (hit) hit.couch = c;
  });
  const cutoff = Date.now() - days * 864e5;
  // Couches marked Sold in the Drops tab: match each to its Sales Log order (same price, logged within a few days).
  const soldDrops = drops.filter(d => d.status === 'sold' && d.soldAt && d.soldAt > cutoff - 3 * 864e5).sort((a, b) => b.soldAt - a.soldAt);
  const ctDay = t => new Date(t).toLocaleDateString('en-CA', { timeZone: 'America/Chicago' });
  const extra = [];
  soldDrops.forEach(d => {
    const sd = ctDay(d.soldAt);
    const off = inSale(d.soldAt) ? saleSaved(0, d.price) : 0, near = (a, b) => Math.abs(a - b) < 1 || (off && Math.abs(a - (b - off)) < 1);
    const pool = log.filter(l => !l.drop && dayDiff(sd, l.day) >= -2 && dayDiff(sd, l.day) <= 4 && (near(l.price, d.price) || near(l.net, d.price)));
    const hit = pool.sort((a, b) => Math.abs(dayDiff(sd, a.day)) - Math.abs(dayDiff(sd, b.day)))[0];
    if (hit) hit.drop = d;
    else if (d.soldAt > cutoff && d.soldAt <= Date.now()) extra.push({ key: 'd' + d.id, at: new Date(d.soldAt).toISOString(), exact: true, customer: d.soldCustomer || '', price: d.price, title: d.title, photo: (d.photos || [])[0] ? dropPhotoUrl(d.photos[0]) : '', from: 'drops' });
  });
  return log.map(l => {
    const at = l.ts || Math.min(Date.now(), Date.parse(l.day + 'T12:00:00-05:00'));
    if (!(at > cutoff && at <= Date.now())) return null;
    const pick = picks[l.key], c = l.couch;
    let title = '', photo = '', from = '';
    if (pick && pick.title) { title = pick.title; photo = pick.img || ''; from = 'picked'; }
    else if (l.drop) { title = l.drop.title; photo = (l.drop.photos || [])[0] ? dropPhotoUrl(l.drop.photos[0]) : ''; from = 'drops'; }
    if (pick && pick.photo) { photo = `/public/justsold-photo/${pick.photo}?v=${pick.at}`; if (!title && c) { title = cleanCouchName(c.name); from = 'tracker'; } }
    else if (c && !photo) {
      title = cleanCouchName(c.name); from = 'tracker';
      if (pidx[c.pkey]) { const t = crypto.createHash('sha1').update(c.pkey).digest('hex').slice(0, 16); photo = `/public/sale-photo/${t}?v=${pidx[c.pkey]}`; recentPhotos[t] = c.pkey; }
      else { const m = bestSiteMatch(c.name, site); if (m && m.img) photo = m.img; }
    }
    return { key: l.key, at: new Date(at).toISOString(), exact: !!l.ts, customer: l.name, price: l.price, title, photo, from, saved: inSale(at) ? saleSaved(l.price, l.drop && l.drop.price) : 0 };
  }).filter(Boolean).concat(extra).sort((a, b) => b.at.localeCompare(a.at));
}
async function buildRecent() {
  if (recentCache.data && Date.now() - recentCache.at < 5 * 60 * 1000 && recentCache.live === saleLive()) return;
  const shortName = n => { const w = String(n || '').trim().split(/\s+/).filter(Boolean); if (!w.length) return '';
    const f = w[0][0].toUpperCase() + w[0].slice(1).toLowerCase(); return w.length > 1 ? f + ' ' + w[w.length - 1][0].toUpperCase() + '.' : f; };
  const list = await recentOrders(5);
  recentCache = { at: Date.now(), live: saleLive(), data: list.slice(0, 20).map(o => {
    const row = { title: o.title || 'A couch from our showroom', at: o.at, exact: o.exact };
    if (saleLive() && o.saved) row.saved = o.saved;   // only while the sale is on
    const who = shortName(o.customer); if (who) row.who = who;
    if (o.photo) row.photo = /^https?:/.test(o.photo) ? o.photo + '?format=300w' : o.photo;
    return row; }) };
}
// HQ: pick which website couch each recent order bought (for the pop-up title + photo).
app.get('/api/justsold', async (req, res) => {
  try { const [orders, site, drops] = await Promise.all([recentOrders(7), siteCouches(req.query.fresh === '1'), getDrops()]);
    const seen = new Set(), all = [];
    drops.filter(d => (d.photos || []).length).forEach(d => { const k = d.title.toLowerCase(); if (seen.has(k)) return; seen.add(k); all.push({ title: d.title, img: dropPhotoUrl(d.photos[0]), live: d.status === 'live' || d.status === 'emailed' }); });
    site.forEach(c => { const k = c.title.toLowerCase(); if (seen.has(k)) return; seen.add(k); all.push({ title: c.title, img: c.img, live: c.live }); });
    res.json({ ok: true, orders, site: all }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/justsold/pick', async (req, res) => {
  try {
    const key = clean(req.body.key, 80); if (!key) return res.status(400).json({ error: 'key required' });
    const picks = await kget('bcd:soldPicks', {}), cur = picks[key] || {};
    const next = { ...cur, at: Date.now() };
    if (req.body.title !== undefined) { next.title = clean(req.body.title, 90); next.img = (/^https:\/\/images\.squarespace-cdn\.com\//.test(req.body.img || '') || String(req.body.img || '').startsWith(PUBLIC_BASE + '/public/dphoto/')) ? String(req.body.img).slice(0, 300) : ''; }
    if (req.body.photo !== undefined) {
      const id = crypto.createHash('sha1').update(key).digest('hex').slice(0, 16);
      if (req.body.photo && /^data:image\/(jpeg|png|webp);base64,/.test(req.body.photo)) { await kset('bcd:soldPhoto:' + id, String(req.body.photo)); next.photo = id; }
      else { await kset('bcd:soldPhoto:' + id, ''); delete next.photo; }
    }
    if (next.title || next.photo) picks[key] = next; else delete picks[key];
    Object.keys(picks).forEach(k => { if (Date.now() - (picks[k].at || 0) > 60 * 864e5) delete picks[k]; });
    await kset('bcd:soldPicks', picks); recentCache.at = 0; res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/public/justsold-photo/:id', async (req, res) => {
  try { const m = String(await kget('bcd:soldPhoto:' + String(req.params.id).replace(/[^a-f0-9]/g, ''), '')).match(/^data:(image\/\w+);base64,(.+)$/); if (!m) return res.sendStatus(404);
    res.set('Cache-Control', 'public, max-age=86400').type(m[1]).send(Buffer.from(m[2], 'base64')); } catch (e) { res.sendStatus(404); }
});
// Photo for a couch in the "Just sold" feed (only couches currently in that feed are reachable).
app.get('/public/sale-photo/:t', async (req, res) => {
  try {
    if (!recentPhotos[req.params.t]) { recentCache.at = 0; await buildRecent(); }
    const key = recentPhotos[req.params.t]; if (!key) return res.sendStatus(404);
    const m = String(await kget(photoKey(key), '')).match(/^data:(image\/\w+);base64,(.+)$/); if (!m) return res.sendStatus(404);
    res.set('Cache-Control', 'public, max-age=86400').type(m[1]).send(Buffer.from(m[2], 'base64'));
  } catch (e) { res.sendStatus(404); }
});


// ---------- Drops: one place to list couches (First Dibs email, website, Marketplace/Craigslist) ----------
// Couches live in bcd:drops. Status: draft -> emailed (First Dibs only) -> live (on the website) -> sold / hidden.
// Photos uploaded in HQ are stored as bcd:dphoto:<id> and served publicly so emails and the website can show them.
const DROP_STATUS = ['draft', 'emailed', 'live', 'sold', 'hidden'];
const PUBLIC_BASE = (process.env.PUBLIC_BASE_URL || 'https://hq.billyscouches.com').trim().replace(/\/$/, '');
const dropPhotoUrl = ph => /^https?:/.test(ph) ? ph : `${PUBLIC_BASE}/public/dphoto/${ph}.jpg`;
const getDrops = () => kget('bcd:drops', []);
const setDrops = list => kset('bcd:drops', list);
let dropsAt = 0;
function cleanDrop(b, old) {
  const arr = (v, n) => (Array.isArray(v) ? v : String(v || '').split('\n')).map(x => clean(x, 160)).filter(Boolean).slice(0, n);
  const d = { ...(old || {}) };
  if (b.title !== undefined) d.title = clean(b.title, 120);
  if (b.price !== undefined) d.price = Math.max(0, Math.round(Number(String(b.price).replace(/[^\d.]/g, '')) || 0));
  if (b.retail !== undefined) d.retail = Math.max(0, Math.round(Number(String(b.retail).replace(/[^\d.]/g, '')) || 0));
  if (b.grade !== undefined) d.grade = /^[ABC]$/.test(b.grade) ? b.grade : '';
  if (b.details !== undefined) d.details = arr(b.details, 12);
  if (b.imperfections !== undefined) d.imperfections = arr(b.imperfections, 8);
  if (b.dimensions !== undefined) d.dimensions = clean(b.dimensions, 200);
  if (b.notes !== undefined) d.notes = clean(b.notes, 300);
  if (b.photos !== undefined) d.photos = (Array.isArray(b.photos) ? b.photos : []).map(x => String(x)).filter(x => /^[a-f0-9]{16}$/.test(x) || /^https:\/\/images\.squarespace-cdn\.com\//.test(x)).slice(0, 12);
  return d;
}
app.get('/api/drops', async (req, res) => {
  try { res.json({ ok: true, drops: await getDrops(), base: PUBLIC_BASE }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/drops/save', async (req, res) => {
  try {
    const list = await getDrops(), b = req.body || {};
    let d = b.id ? list.find(x => x.id === b.id) : null;
    if (b.id && !d) return res.status(404).json({ error: 'Couch not found' });
    const next = cleanDrop(b, d);
    if (!next.title) return res.status(400).json({ error: 'Add a title' });
    if (d) Object.assign(d, next, { updatedAt: Date.now() });
    else { d = { id: crypto.randomBytes(6).toString('hex'), status: 'draft', createdAt: Date.now(), updatedAt: Date.now(), photos: [], details: [], imperfections: [], ...next }; list.unshift(d); }
    await setDrops(list); dropsAt = Date.now(); res.json({ ok: true, drop: d });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/drops/status', async (req, res) => {
  try {
    const st = String(req.body.status || ''); if (!DROP_STATUS.includes(st)) return res.status(400).json({ error: 'bad status' });
    const ids = new Set((req.body.ids || []).map(String)), list = await getDrops(), now = Date.now();
    list.forEach(d => { if (!ids.has(d.id)) return; d.status = st; d.updatedAt = now;
      if (st === 'emailed' && !d.emailedAt) d.emailedAt = now; if (st === 'live' && !d.liveAt) d.liveAt = now; if (st === 'sold') d.soldAt = now; if (st !== 'sold') delete d.soldAt; });
    await setDrops(list); dropsAt = now; recentCache.at = 0; res.json({ ok: true, drops: list });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/drops/delete', async (req, res) => {
  try {
    const list = await getDrops(), d = list.find(x => x.id === req.body.id); if (!d) return res.status(404).json({ error: 'not found' });
    await Promise.all((d.photos || []).filter(p => /^[a-f0-9]{16}$/.test(p)).map(p => kset('bcd:dphoto:' + p, '')));
    await setDrops(list.filter(x => x.id !== d.id)); dropsAt = Date.now(); res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/drops/reorder', async (req, res) => {
  try {
    const order = (req.body.ids || []).map(String), list = await getDrops();
    list.sort((a, b) => { const i = order.indexOf(a.id), j = order.indexOf(b.id); return (i < 0 ? 1e9 : i) - (j < 0 ? 1e9 : j); });
    await setDrops(list); dropsAt = Date.now(); res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/drops/photo', async (req, res) => {
  try {
    const m = String(req.body.data || '').match(/^data:image\/(jpeg|png|webp);base64,/); if (!m) return res.status(400).json({ error: 'Not an image' });
    if (req.body.data.length > 5.5e6) return res.status(400).json({ error: 'Photo too big' });
    const id = crypto.randomBytes(8).toString('hex'); await kset('bcd:dphoto:' + id, String(req.body.data)); res.json({ ok: true, id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// Pull every couch off the current Squarespace page into HQ (one time, when switching over).
app.post('/api/drops/import', async (req, res) => {
  try {
    const { parse } = require('node-html-parser');
    const html = await (await fetch(SITE_URL, { headers: { 'User-Agent': 'BillysHQ/1.0' } })).text();
    const root = parse(html), scripts = root.querySelectorAll('script').map(x => x.textContent).join('\n');
    const items = parseSiteInventory(root, scripts);
    const list = await getDrops(), have = new Set(list.map(d => d.title.toLowerCase())), now = Date.now(); let added = 0;
    items.forEach((it, i) => { if (have.has(it.title.toLowerCase())) return; added++;
      list.push({ id: crypto.randomBytes(6).toString('hex'), status: 'live', createdAt: now - i, updatedAt: now, liveAt: now, title: it.title.slice(0, 120), price: it.price, retail: it.retail,
        grade: it.grade, details: it.details.slice(0, 12), imperfections: it.imperfections.slice(0, 8), dimensions: it.dimensions.slice(0, 200), photos: it.photos.slice(0, 12), imported: true }); });
    await setDrops(list); dropsAt = now; res.json({ ok: true, found: items.length, added });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
function parseSiteInventory(root, scriptsText) {
  const txt = el => (el ? (el.textContent || '') : '').replace(/\s+/g, ' ').trim();
  const NAMED = { nbsp: ' ', amp: '&', quot: '"', apos: "'", lt: '<', gt: '>', times: 'x', ndash: '-', mdash: '-', rsquo: "'", lsquo: "'", rdquo: '"', ldquo: '"', bull: '•', middot: '·', frac12: '1/2', deg: '°', prime: "'", Prime: '"' };
  const decode = s => String(s).replace(/&#x([0-9a-f]+);/gi, (m, h) => String.fromCodePoint(parseInt(h, 16))).replace(/&#(\d+);/g, (m, d) => String.fromCodePoint(+d)).replace(/&([a-z]+\d*);/gi, (m, n) => NAMED[n] ?? m).replace(/\u00a0/g, ' ');
  const lines = el => el ? decode(el.innerHTML.replace(/<br\s*\/?>/gi, '\n').replace(/<\/(p|li|div|h\d)>/gi, '\n').replace(/<[^>]+>/g, '')).split('\n').map(x => x.trim()).filter(Boolean) : [];
  const G = {}; const gi = scriptsText.indexOf('var GRADES');
  if (gi > -1) scriptsText.slice(scriptsText.indexOf('{', gi) + 1, scriptsText.indexOf('}', gi)).replace(/'([^']+)'\s*:\s*'([ABC])'/g, (m, k, v) => { G[k] = v; });
  const items = []; let pend = [];
  root.querySelectorAll('section').forEach(s => {
    if (!/page-section/.test(s.getAttribute('class') || '')) return;
    const title = decode(txt(s.querySelector('p.sqsrte-large')));
    if (title && !/last updated/i.test(title)) {
      const pr = Array.from(s.querySelectorAll('.sqs-block-html p')).map(txt).find(x => /^\$/.test(x)) || '';
      const nums = (pr.match(/\$[\d,.]+/g) || []).map(x => Number(x.replace(/[$,]/g, '')));
      const A = {}; Array.from(s.querySelectorAll('.accordion-item')).forEach(a => { A[txt(a.querySelector('.accordion-item__title')).slice(0, 4).toLowerCase()] = lines(a.querySelector('.accordion-item__description')); });
      const det = (A.deta || []).filter(l => !/delivery|further out|^•/i.test(l));
      const gm = (det.find(l => /^condition:/i.test(l)) || '').match(/grade\s*([ABC])/i), key = Object.keys(G).find(k => title.toLowerCase().includes(k.toLowerCase()));
      items.push({ title, price: Math.round(nums[0] || 0), retail: Math.round(nums[1] || 0), grade: (gm && gm[1].toUpperCase()) || (key ? G[key] : ''),
        details: det.filter(l => !/^condition:/i.test(l)).map(l => l.replace(/^\d+\.\s*/, '')),
        imperfections: (A.impe || []).map(l => l.replace(/^\d+\.\s*/, '')).filter(l => !/^none\.?$/i.test(l)), dimensions: (A.dime || []).join(' '), photos: pend });
      pend = [];
    } else {
      const im = []; Array.from(s.querySelectorAll('img')).forEach(i => { const u = (i.getAttribute('data-src') || i.getAttribute('src') || '').split('?')[0]; if (/^https:\/\/images\.squarespace-cdn\.com\//.test(u) && !im.includes(u)) im.push(u); });
      if (im.length) pend = im;
    }
  });
  return items;
}
// Photos for a post kit (phone): same-origin copies of website photos so the phone can save them.
app.get('/api/drops/img', async (req, res) => {
  try {
    const u = String(req.query.u || ''); if (!/^https:\/\/images\.squarespace-cdn\.com\//.test(u)) return res.sendStatus(400);
    const r = await fetch(u + '?format=1500w'); if (!r.ok) return res.sendStatus(404);
    res.set('Cache-Control', 'private, max-age=86400').type(r.headers.get('content-type') || 'image/jpeg').send(Buffer.from(await r.arrayBuffer()));
  } catch (e) { res.sendStatus(404); }
});
// Flat delivery fee shown on listings: $199 from Nov 1, 2026 (DELIVERY_FEE overrides).
const deliveryFee = () => Number(process.env.DELIVERY_FEE) || (Date.now() >= Date.parse('2026-11-01T00:00:00-05:00') ? 199 : 150);
function dropCors(res) { res.setHeader('Access-Control-Allow-Origin', '*'); }
app.get('/public/dphoto/:id', async (req, res) => {
  try {
    const id = String(req.params.id).replace(/\.jpg$/, '').replace(/[^a-f0-9]/g, '');
    const m = String(await kget('bcd:dphoto:' + id, '')).match(/^data:(image\/\w+);base64,(.+)$/); if (!m) return res.sendStatus(404);
    dropCors(res); res.set('Cache-Control', 'public, max-age=604800, immutable').type(m[1]).send(Buffer.from(m[2], 'base64'));
  } catch (e) { res.sendStatus(404); }
});
// The website's Current Inventory page reads this (see /public/inventory.js).
// Website prices during the sale: sale price + the old price + how much off. Back to normal when it ends.
// (Only the website feed. The public order app applies the sale itself, so /public/orderable stays at full price.)
function salePrice(p) { const price = Number(p) || 0; if (!saleLive() || !price) return { price }; const off = saleSaved(0, price); return { price: Math.max(price - off, 0), was: price, saleOff: off, saleEnds: new Date(SALE_WIN.end).toISOString() }; }
app.get('/public/inventory', async (req, res) => {
  dropCors(res);
  try {
    const list = (await getDrops()).filter(d => d.status === 'live');
    res.set('Cache-Control', 'public, max-age=30').json({ ok: true, deliveryFee: deliveryFee(), updated: list.reduce((m, d) => Math.max(m, d.updatedAt || 0), 0) || null, couches: list.map(d => ({ id: d.id, title: d.title, ...salePrice(d.price), retail: d.retail || 0, grade: d.grade || '',
      details: d.details || [], imperfections: d.imperfections || [], dimensions: d.dimensions || '', photos: (d.photos || []).map(dropPhotoUrl) })) });
  } catch (e) { res.status(500).json({ error: 'unavailable' }); }
});
// Public order app (order.billyscouches.com) reads this: everything a customer can buy right now,
// including First Dibs couches that were emailed but aren't on the website yet.
app.get('/public/orderable', async (req, res) => {
  dropCors(res);
  try {
    const list = (await getDrops()).filter(d => d.status === 'live' || d.status === 'emailed');
    res.set('Cache-Control', 'public, max-age=30').json({ ok: true, couches: list.map(d => ({ id: d.id, title: d.title, price: d.price, photo: (d.photos || [])[0] ? dropPhotoUrl(d.photos[0]) : '' })) });
  } catch (e) { res.status(500).json({ error: 'unavailable' }); }
});
// Private order app (team checkout): marks the couches it just sold as Sold in Drops, so they leave the
// website + public order app and the website's "just sold" pop-up gets the right title and photo.
// Only accepted from the order app's own page (Origin check), and only flips live/emailed couches.
const ORDER_ORIGINS = (process.env.ORDER_APP_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
const orderOriginOk = o => { if (ORDER_ORIGINS.includes(o)) return true; try { const h = new URL(o).hostname; return h.includes('billys-couches-proxy') || h === 'billyscouches.com' || h.endsWith('.billyscouches.com'); } catch { return false; } };
function orderCors(req, res) { const o = req.get('origin') || ''; if (orderOriginOk(o)) { res.setHeader('Access-Control-Allow-Origin', o); res.setHeader('Vary', 'Origin'); res.setHeader('Access-Control-Allow-Headers', 'Content-Type'); res.setHeader('Access-Control-Allow-Methods', 'GET, POST'); return true; } return false; }
// Private order app: today's showings so the team can tap a customer instead of typing them in.
// Only answered for the order app's own page (Origin check). Returns first-name-level info + phone for today only.
app.options('/public/today-showings', (req, res) => { orderCors(req, res); res.sendStatus(204); });
app.get('/public/today-showings', async (req, res) => {
  if (!orderCors(req, res)) return res.status(403).json({ error: 'forbidden' });
  res.setHeader('Cache-Control', 'no-store');
  try {
    const g = await google(false), today = new Date().toLocaleDateString('en-CA', { timeZone: 'America/Chicago' });
    const list = (g.showings || []).filter(r => new Date(r[0]).toLocaleDateString('en-CA', { timeZone: 'America/Chicago' }) === today && !/cancel/i.test(r[1] || ''))
      .map(([iso, title, , phone]) => ({ at: iso, name: String(title || '').replace(/\(.*?\)/g, '').replace(/^\s*showing\s*(for)?\s*/i, '').trim(), phone: phone || '' }))
      .filter(x => x.name).sort((a, b) => a.at.localeCompare(b.at));
    res.json({ ok: true, showings: list });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.options('/public/order-sold', (req, res) => { orderCors(req, res); res.sendStatus(204); });
app.post('/public/order-sold', async (req, res) => {
  if (!orderCors(req, res)) return res.status(403).json({ error: 'forbidden' });
  try {
    const ids = new Set((req.body.ids || []).map(String).slice(0, 10)), who = clean(req.body.customer, 60), list = await getDrops(), now = Date.now(); let n = 0;
    list.forEach(d => { if (!ids.has(d.id) || !['live', 'emailed'].includes(d.status)) return; d.status = 'sold'; d.soldAt = now; d.updatedAt = now; if (who) d.soldCustomer = who; d.soldVia = 'order app'; n++; });
    if (n) { await setDrops(list); dropsAt = now; recentCache.at = 0; }
    res.json({ ok: true, marked: n });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// ===================================================================
// SCHEDULING (replaces the Jotform scheduling form)
// Order apps create an order here -> the receipt text links to /s/<token> -> the customer picks an open
// window, confirms the address and can add upsells -> HQ puts it on the Billy's Couches calendar (with the
// couch photo + add-ons), the Customers sheet, Thank You Cards and the Today's deliveries strip.
// Delivery/pickup windows are edited in HQ > Scheduling (store key "slots").
// ===================================================================
const SCHED_KEY = 'bcd:sched';
const SCHED_PROXY = (process.env.ORDER_PROXY_URL || 'https://billys-couches-proxy-production.up.railway.app').replace(/\/$/, '');
const SCHED_TAX = Number(process.env.SCHED_TAX_RATE || 9.738), SCHED_FEE = 0.03;
const SCHED_ADDONS = [
  { id: 'scotchgard', label: 'Scotchgard', price: 49, pitch: 'Stain and spill protection, applied before it leaves', match: /scotch/i },
  { id: 'wrap', label: 'Plastic Wrap', price: 99, pitch: 'Wrapped and protected for the ride', match: /wrap/i },
  { id: 'removal', label: 'Couch Removal', price: 125, pitch: 'We haul your old couch away on delivery day', match: /remov|haul/i, deliveryOnly: true },
];
const SLOT_DEFAULT = {
  delivery: { days: { 2: { on: true, win: ['16-18', '18-20', '20-22'], cap: 1 }, 5: { on: true, win: ['16-18', '18-20', '20-22'], cap: 1 }, 6: { on: true, win: ['10-12', '12-14', '14-16', '16-18'], cap: 1 } } },
  pickup: { days: { 1: { on: true, win: ['12-14', '14-16', '16-18'], cap: 2 }, 2: { on: true, win: ['12-14', '14-16', '16-18'], cap: 2 }, 3: { on: true, win: ['12-14', '14-16', '16-18'], cap: 2 }, 4: { on: true, win: ['12-14', '14-16', '16-18'], cap: 2 }, 5: { on: true, win: ['12-14', '14-16', '16-18'], cap: 2 }, 6: { on: true, win: ['10-12', '12-14', '14-16'], cap: 2 } } },
  blocked: [], maxDays: 14, noticeHours: 12,
};
const getSched = () => kget(SCHED_KEY, {});
const setSched = m => kset(SCHED_KEY, m);
async function slotCfg() { const s = await kget('bcd:store:slots', null).catch(() => null); return s && s.delivery ? { ...SLOT_DEFAULT, ...s } : SLOT_DEFAULT; }
const ctParts = d => { const p = Object.fromEntries(new Intl.DateTimeFormat('en-US', { timeZone: 'America/Chicago', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23', weekday: 'short' }).formatToParts(d).map(x => [x.type, x.value])); return p; };
const ctYmd = d => { const p = ctParts(d); return `${p.year}-${p.month}-${p.day}`; };
// A wall-clock time in St. Louis -> real Date (handles daylight saving).
function ctAt(ymd, min) {
  const guess = new Date(`${ymd}T${String(Math.floor(min / 60)).padStart(2, '0')}:${String(min % 60).padStart(2, '0')}:00Z`);
  for (const off of [5, 6]) { const d = new Date(guess.getTime() + off * 3600e3), p = ctParts(d); if (`${p.year}-${p.month}-${p.day}` === ymd && +p.hour * 60 + +p.minute === min) return d; }
  return new Date(guess.getTime() + 6 * 3600e3);
}
const parseWin = w => { const m = String(w).match(/^(\d{1,2})(?::(\d\d))?-(\d{1,2})(?::(\d\d))?$/); if (!m) return null; const a = +m[1] * 60 + (+m[2] || 0), b = +m[3] * 60 + (+m[4] || 0); return b > a ? [a, b] : null; };
const minLabel = m => { const h = Math.floor(m / 60), mm = m % 60; return (h % 12 || 12) + (mm ? ':' + String(mm).padStart(2, '0') : ''); };
const winLabel = w => { const p = parseWin(w); if (!p) return w; const ap = m => (m < 720 ? 'am' : 'pm'); return minLabel(p[0]) + (ap(p[0]) !== ap(p[1]) ? ap(p[0]) : '') + ' – ' + minLabel(p[1]) + ap(p[1]); };
// Open windows for the next maxDays days, minus what's on the calendar and what was just booked here.
async function openSlots(kind, skipToken) {
  const cfg = await slotCfg(), conf = (cfg[kind] || SLOT_DEFAULT[kind]).days || {};
  const g = await google(false).catch(() => ({})), sched = await getSched();
  const calIds = new Set(), busy = [];
  (g.deliveries || []).forEach(([s, e, title, , , id]) => { const isPick = /pick\s*-?\s*up/i.test(title || ''); if ((kind === 'pickup') !== isPick) return; calIds.add(id); busy.push({ s: Date.parse(s), e: Date.parse(e), id }); });
  Object.values(sched).forEach(o => { const b = o.booking; if (!b || o.token === skipToken || o.type !== kind) return;
    if (b.eventId && calIds.has(b.eventId)) { if (skipToken) {} return; }
    const w = parseWin(b.win); if (w) busy.push({ s: ctAt(b.date, w[0]).getTime(), e: ctAt(b.date, w[1]).getTime() }); });
  if (skipToken && sched[skipToken] && sched[skipToken].booking && sched[skipToken].booking.eventId) { const own = sched[skipToken].booking.eventId; for (let i = busy.length - 1; i >= 0; i--) if (busy[i].id === own) busy.splice(i, 1); }
  const now = Date.now(), days = [], blocked = new Set(cfg.blocked || []);
  for (let i = 0; i <= (cfg.maxDays || 14); i++) {
    const ymd = ctYmd(new Date(now + i * 864e5)); if (blocked.has(ymd)) continue;
    const dow = new Date(ymd + 'T12:00:00Z').getUTCDay(), d = conf[dow]; if (!d || !d.on) continue;
    // Pick ups: the windows are open hours, split into 30-minute times (slotMins in the settings).
    const step = kind === 'pickup' ? Number((cfg.pickup || {}).slotMins) || 30 : 0;
    const wins = step ? (d.win || []).flatMap(w => { const p = parseWin(w); if (!p) return []; const out = []; for (let t = p[0]; t + step <= p[1]; t += step) { const a = t, b = t + step, f = m => Math.floor(m / 60) + (m % 60 ? ':' + String(m % 60).padStart(2, '0') : ''); out.push(f(a) + '-' + f(b)); } return out; }) : (d.win || []);
    const slots = wins.map(w => { const p = parseWin(w); if (!p) return null; const s = ctAt(ymd, p[0]).getTime(), e = ctAt(ymd, p[1]).getTime();
      if (s - now < (cfg.noticeHours || 0) * 3600e3) return null;
      const used = busy.filter(b => b.s < e && b.e > s).length, left = Math.max(0, (d.cap || 1) - used);
      return { win: w, label: step ? minLabel(p[0]) + (p[0] < 720 ? 'am' : 'pm') : winLabel(w), left }; }).filter(Boolean);
    if (slots.length) days.push({ date: ymd, dow: new Date(ymd + 'T12:00:00Z').toLocaleDateString('en-US', { weekday: 'short', timeZone: 'UTC' }), day: +ymd.slice(8), label: new Date(ymd + 'T12:00:00Z').toLocaleDateString('en-US', { weekday: 'long', month: 'short', day: 'numeric', timeZone: 'UTC' }), slots });
  }
  return days;
}
const schedLink = t => `${PUBLIC_BASE}/s/${t}`;
// Order app -> HQ: remember the order so the scheduling page knows the couch, photo and add-ons.
app.options('/public/order-create', (req, res) => { orderCors(req, res); res.sendStatus(204); });
app.post('/public/order-create', async (req, res) => {
  if (!orderCors(req, res)) return res.status(403).json({ error: 'forbidden' });
  try {
    const b = req.body || {}, name = clean(b.name, 80); if (!name) return res.status(400).json({ error: 'name required' });
    const drops = await getDrops().catch(() => []);
    const couches = (Array.isArray(b.couches) ? b.couches : []).slice(0, 6).map(c => {
      const title = clean(c.title || c.name, 120), d = drops.find(x => (c.dropId && x.id === c.dropId) || (title && x.title.toLowerCase() === title.toLowerCase()));
      return { title: title || (d && d.title) || 'Couch', dropId: d ? d.id : '', photo: d && (d.photos || [])[0] ? dropPhotoUrl(d.photos[0]) : (/^https:\/\//.test(c.photo || '') ? String(c.photo).slice(0, 300) : '') };
    });
    const token = crypto.randomBytes(6).toString('hex'), type = /pick/i.test(b.type || '') ? 'pickup' : 'delivery';
    const m = await getSched();
    // keep the store small: drop unbooked orders older than 60 days and booked ones 90 days past their date
    const cut = Date.now() - 60 * 864e5; Object.keys(m).forEach(k => { const o = m[k]; if ((!o.booking && o.created < cut) || (o.booking && Date.parse(o.booking.date) < Date.now() - 90 * 864e5)) delete m[k]; });
    m[token] = { token, created: Date.now(), name, phone: String(b.phone || '').replace(/\D/g, '').slice(-10), type, couches,
      addons: (Array.isArray(b.addons) ? b.addons : []).map(a => clean(a && a.label || a, 40)).filter(Boolean), total: Number(b.total) || 0, payment: clean(b.payment, 30), zip: clean(b.zip, 10), from: clean(b.from, 20) };
    await setSched(m); res.json({ ok: true, token, url: schedLink(token) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/s/:token', (req, res) => res.sendFile(path.join(__dirname, 'schedule.html')));
const schedPublic = (o, days) => ({ name: o.name, first: o.name.split(/\s+/)[0], phone: o.phone, type: o.type, couches: o.couches, addons: o.addons, zip: o.zip,
  booking: o.booking ? { date: o.booking.date, win: o.booking.win, label: o.booking.label, address: o.booking.address, city: o.booking.city, zip: o.booking.zip, room: o.booking.room, notes: o.booking.notes, extras: o.booking.extras || [] } : null,
  upsells: SCHED_ADDONS.filter(a => !(a.deliveryOnly && o.type !== 'delivery') && !o.addons.some(x => a.match.test(x)) && !((o.booking && o.booking.extras) || []).some(x => a.match.test(x))).map(({ id, label, price, pitch }) => ({ id, label, price, pitch })),
  days, taxRate: SCHED_TAX, feeRate: SCHED_FEE });
app.get('/public/sched/:token', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try { const o = (await getSched())[String(req.params.token)]; if (!o) return res.status(404).json({ error: 'This link has expired. Text us at (314) 899-7503 and we\'ll get you scheduled.' });
    res.json({ ok: true, ...schedPublic(o, await openSlots(o.type, o.token)) }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
async function sheetsBook(q) {
  if (!CFG.API) return { eventId: q.eventId || 'demo-' + Date.now() };
  const u = new URL(CFG.API); Object.entries({ key: CFG.KEY, action: 'book', ...q }).forEach(([k, v]) => u.searchParams.set(k, v));
  const j = await (await fetch(u)).json(); if (j.error) throw new Error(j.error); return j;
}
const fmtPhone = p => p && p.length === 10 ? `(${p.slice(0, 3)}) ${p.slice(3, 6)}-${p.slice(6)}` : p;
app.post('/public/sched/:token', async (req, res) => {
  try {
    const m = await getSched(), o = m[String(req.params.token)]; if (!o) return res.status(404).json({ error: 'This link has expired. Text us at (314) 899-7503.' });
    const b = req.body || {}, date = clean(b.date, 10), win = clean(b.win, 12);
    const days = await openSlots(o.type, o.token), day = days.find(d => d.date === date), slot = day && day.slots.find(s => s.win === win);
    if (!slot || slot.left < 1) return res.status(409).json({ error: 'That time just filled up. Please pick another.', days });
    const isDel = o.type === 'delivery', address = clean(b.address, 120), city = clean(b.city, 60), zip = clean(b.zip, 10).replace(/[^\d]/g, '');
    if (isDel && (!address || !city || zip.length !== 5)) return res.status(400).json({ error: 'Add your full address and ZIP code.' });
    const phone = String(b.phone || o.phone || '').replace(/\D/g, '').slice(-10) || o.phone;
    const offered = schedPublic(o, []).upsells, extrasNew = offered.filter(a => (b.extras || []).includes(a.id));
    const prev = o.booking || {}, w = parseWin(win), start = ctAt(date, w[0]), end = ctAt(date, w[1]);
    const extras = [...(prev.extras || []), ...extrasNew.map(a => a.label)];
    const room = clean(b.room, 80), notes = clean(b.notes, 300), couch = o.couches.map(c => c.title).join(' + ');
    const allAdds = [...o.addons, ...extras];
    const desc = [`Phone Number:`, fmtPhone(phone), `Address:`, isDel ? `${address}, ${city}, MO, ${zip}` : 'Pickup at warehouse', `Pick up or Delivery? :`, isDel ? 'Delivery' : 'Pick up', '',
      `Couch: ${couch}`, `Add-ons: ${allAdds.length ? allAdds.join(', ') : 'None'}`, room ? `Room: ${room}` : '', notes ? `Notes: ${notes}` : '',
      extrasNew.length ? `Added when scheduling: ${extrasNew.map(a => a.label).join(', ')} (paid by card link)` : '',
      o.couches[0] && o.couches[0].photo ? `Photo: ${o.couches[0].photo}` : ''].filter(x => x !== '').join('\n');
    const row = [new Date().toLocaleDateString('en-US', { timeZone: 'America/Chicago' }), o.name, fmtPhone(phone), isDel ? address : '', isDel ? city : '', isDel ? zip : '', isDel ? 'Delivery' : 'Pickup', couch, allAdds.join(', '), `${date} ${winLabel(win)}`, o.from || 'Order app'];
    const j = await sheetsBook({ eventId: prev.eventId || '', title: `${isDel ? 'Delivery' : 'Pick up'} for ${o.name}`, start: start.toISOString(), end: end.toISOString(),
      location: isDel ? `${address}, ${city}, MO ${zip}` : '126 E Orleans St, Pacific, MO 63069', desc, photo: (o.couches[0] && o.couches[0].photo) || '', photoName: (couch || 'couch').replace(/[^\w -]/g, '').slice(0, 60) + '.jpg', row: JSON.stringify(row) });
    // Card link for anything they added now (couch + tax + 3% card fee), made by the order proxy like the team app does.
    let payUrl = '', due = 0;
    if (extrasNew.length) {
      const sub = extrasNew.reduce((a, x) => a + x.price, 0), tax = Math.round(sub * SCHED_TAX) / 100; due = Math.round((sub + tax) * (1 + SCHED_FEE) * 100) / 100;
      try { const r = await fetch(SCHED_PROXY + '/create-stripe-link', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ customerName: o.name, orderType: 'Add-ons: ' + extrasNew.map(a => a.label).join(', '), totalCents: Math.round(due * 100), totalDisplay: '$' + due.toFixed(2), redirectUrl: schedLink(o.token) + '?paid=1' }) });
        const d = await r.json(); payUrl = d.url || ''; } catch (e) { console.log('Add-on pay link failed', e.message); }
    }
    o.booking = { date, win, label: `${day.label} · ${slot.label}`, address, city, zip, room, notes, phone, extras, eventId: j.eventId || prev.eventId || '', at: Date.now(), moved: !!prev.date, photoAttached: !!j.attached };
    if (extrasNew.length) o.extraDue = (o.extraDue || 0) + due;
    m[o.token] = o; await setSched(m);
    cache.at = 0;   // so the next HQ load re-reads the calendar
    textAlert(`${prev.date ? 'RESCHEDULED' : 'BOOKED'}: ${isDel ? 'Delivery' : 'Pickup'} ${o.booking.label}\n${o.name} ${fmtPhone(phone)}\n${couch}${allAdds.length ? '\nAdd-ons: ' + allAdds.join(', ') : ''}${extrasNew.length ? `\nNEW ADD-ONS: ${extrasNew.map(a => a.label).join(', ')} ($${due.toFixed(2)} link sent)` : ''}${isDel ? '\n' + address + ', ' + city : ''}`).catch(() => {});
    res.json({ ok: true, payUrl, due, ...schedPublic(o, []) });
  } catch (e) { console.log('Schedule failed', e.message); res.status(500).json({ error: 'Could not book that time. Please text us at (314) 899-7503.' }); }
});
// Public order app's "next delivery" banner.
app.get('/public/next-slot', async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*'); res.setHeader('Cache-Control', 'public, max-age=120');
  try { const d = (await openSlots('delivery')).map(x => ({ ...x, slots: x.slots.filter(s => s.left > 0) })).find(x => x.slots.length);
    if (!d) return res.json({ nextDate: null, spotsLeft: 0, live: true });
    const daysOut = Math.round((Date.parse(d.date + 'T12:00:00Z') - Date.parse(ctYmd(new Date()) + 'T12:00:00Z')) / 864e5);
    res.json({ nextDate: d.date, dayName: new Date(d.date + 'T12:00:00Z').toLocaleDateString('en-US', { weekday: 'long', timeZone: 'UTC' }), dateLabel: new Date(d.date + 'T12:00:00Z').toLocaleDateString('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' }), daysOut, spotsLeft: d.slots.length, slots: d.slots.map(s => s.label.replace(' – ', '–')), live: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// HQ: bookings list for the Scheduling tab.
app.get('/api/sched', async (req, res) => {
  try { const m = await getSched(), list = Object.values(m).sort((a, b) => (b.booking ? b.booking.date : '').localeCompare(a.booking ? a.booking.date : '') || b.created - a.created).slice(0, 200)
    .map(o => ({ token: o.token, name: o.name, phone: o.phone, type: o.type, couch: o.couches.map(c => c.title).join(' + '), photo: (o.couches[0] || {}).photo || '', addons: [...o.addons, ...((o.booking || {}).extras || [])], created: o.created, booking: o.booking || null, link: schedLink(o.token), extraDue: o.extraDue || 0 }));
    res.json({ ok: true, list, cfg: await slotCfg(), defaults: SLOT_DEFAULT }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
// HQ: remove a booking (and its calendar event).
app.post('/api/sched/delete', async (req, res) => {
  try { const m = await getSched(), o = m[String(req.body.token || '')]; if (!o) return res.status(404).json({ error: 'not found' });
    if (o.booking && o.booking.eventId && !/^demo-/.test(o.booking.eventId)) { try { await sheetsBook({ op: 'delete', eventId: o.booking.eventId, start: new Date().toISOString(), end: new Date().toISOString() }); } catch (e) { console.log('Calendar delete failed', e.message); } }
    delete m[o.token]; await setSched(m); cache.at = 0; ty.at = 0; res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
// ===================== END SCHEDULING =====================
app.get('/public/inventory.js', (req, res) => res.set('Cache-Control', 'public, max-age=300').type('application/javascript').sendFile(path.join(__dirname, 'inventory.js')));

// ---------- Coaching (Billy Price Coaching): admin at /coach, client portal at /client ----------
const COACH = { clients: 'bcd:coach:clients', leads: 'bcd:coach:leads', videos: 'bcd:coach:videos', settings: 'bcd:coach:settings', reels: 'bcd:coach:reels', calendly: 'bcd:coach:calendly' };
const cid = () => crypto.randomBytes(6).toString('hex');
const weekKey = (d = new Date()) => { const t = new Date(d.toLocaleDateString('en-CA', { timeZone: 'America/Chicago' }) + 'T12:00:00Z'); t.setUTCDate(t.getUTCDate() - ((t.getUTCDay() + 6) % 7)); return t.toISOString().slice(0, 10); };
async function getClients() {
  let list = await kget(COACH.clients, null);
  if (!list) { list = [seedEthan()]; await kset(COACH.clients, list); }
  return list;
}
function seedEthan() {
  const t = (text, month, done) => ({ id: cid(), text, month, done: !!done });
  const r = (text) => ({ id: cid(), text, recurring: true, doneWeek: '' });
  return { id: cid(), name: 'Ethan Virin', active: true, pin: '', phone: '+1 530 270 6431', email: 'ethanvirin9@gmail.com', market: 'Folsom, CA', business: 'Super Couch Show Room',
    links: { ig: 'https://www.instagram.com/supercouchshowroom/', fb: 'https://www.facebook.com/profile.php?id=61593250757881', tiktok: 'https://www.tiktok.com/@supercouchshowroom' },
    calendly: 'https://calendly.com/billyprice/billy-price-1-1-call',
    program: { length: '3-month', start: '2026-09-26', end: '2026-12-26', plan: 'Payment plan - $1k/month',
      payments: [{ label: 'Month 1', amount: 1000, paid: true, paidAt: '2026-09-26' }, { label: 'Month 2', amount: 1000, paid: false }, { label: 'Month 3', amount: 1000, paid: false }] },
    start: { experience: 'Intermediate', truck: 'Pickup Truck', flips: 14, profit: 5000, revenue: '8,500-11k', employees: 'No', inventory: '100% Local Pickups', social: 'Just started posting', bottleneck: 'Sales' },
    goals: { flips: 25, revenue: 13000, profit: '8-10k/month', other: 'Hire first employee and build out a team for more freedom' },
    calls: [
      { id: cid(), title: 'Onboarding Call', date: '2026-09-26', link: '', notes: '' },
      { id: cid(), title: 'Call #1', date: '2026-09-30', link: '', notes: '' },
      { id: cid(), title: 'Call #2', date: '2026-10-05', link: '', notes: '' },
      { id: cid(), title: 'Call #3', date: '2026-10-13', link: 'https://fathom.video/share/5fxUtgbpdJ95xDWDZLxCCBFJBEswRJyV', notes: '' },
      { id: cid(), title: 'Bonus Call - Profile Visits Set up', date: '2026-10-14', link: '', notes: '' },
      { id: cid(), title: 'Call #4', date: '2026-10-20', link: '', notes: '' },
      { id: cid(), title: 'Call #5', date: '2026-10-27', link: 'https://fathom.video/share/iQkMx5qR4V75sFkyCWfsvWxzT5yu92Kx', notes: '' }],
    tasks: [
      t('Create Bstock account.', 2, false), t('Improve showing page with HTMLs.', 2, true), t('Improve tracking: showing tracker, Meta Ads tracker, Sales Tracker.', 2, true),
      t('Fix couch images and details section.', 2, true), t('Re-create 3 concepts of the garage opening video.', 2, false), t('Turn off ad with 0 leads and replace it with fresh creative.', 2, true),
      r('Post 2-4 times a day'), r('Post 4-5 Stories daily'), r('Post story posts and vulnerable posts in local FB groups (2x / week)'), r('Post bait posts weekly'), r('Create 4 new ad creatives weekly')],
    checkins: [], notes: '', createdAt: Date.now() };
}
const coachList = k => kget(COACH[k], []);
// Marketplace posting helper (opened from a facebook.com tab; hands it the newest couches + photos).
app.get('/bridge', (req, res) => res.sendFile(path.join(__dirname, authed(req) ? 'bridge.html' : 'login.html')));
app.get('/coach', (req, res) => res.sendFile(path.join(__dirname, authed(req) ? 'coach.html' : 'login.html')));
// ---------- Calendly: every qualification-call booking becomes a Pipeline lead ----------
// Needs CALENDLY_TOKEN in Railway (Calendly > Integrations > API & Webhooks > Personal access token). Works on the free plan.
// CALENDLY_EVENT (optional) = words in the event name to match; defaults to "qualification".
let calLast = 0;
async function calendlySync(force) {
  const tok = process.env.CALENDLY_TOKEN; if (!tok) return { skipped: 'no token' };
  if (!force && Date.now() - calLast < 3 * 60 * 1000) return { skipped: 'recent' }; calLast = Date.now();
  const api = async u => { const r = await fetch(u.startsWith('http') ? u : 'https://api.calendly.com' + u, { headers: { Authorization: 'Bearer ' + tok } });
    const j = await r.json(); if (!r.ok) throw new Error('Calendly: ' + (j.message || j.title || r.status)); return j; };
  const st = (await kget(COACH.calendly, null)) || {};
  if (!st.user) st.user = (await api('/users/me')).resource.uri;
  const want = new RegExp(process.env.CALENDLY_EVENT || 'qualification', 'i');
  const since = new Date(Date.now() - 45 * 864e5).toISOString();
  let url = `/scheduled_events?user=${encodeURIComponent(st.user)}&min_start_time=${encodeURIComponent(since)}&count=100&sort=start_time:desc`, evs = [], g = 0;
  while (url && g++ < 5) { const j = await api(url); evs.push(...(j.collection || [])); url = j.pagination && j.pagination.next_page; }
  evs = evs.filter(e => want.test(e.name || ''));
  const leads = await coachList('leads'); let added = 0, changed = 0;
  for (const ev of evs) {
    const evId = ev.uri.split('/').pop(), callDate = new Date(ev.start_time).toLocaleDateString('en-CA', { timeZone: 'America/Chicago' });
    const callTime = new Date(ev.start_time).toLocaleTimeString('en-US', { timeZone: 'America/Chicago', hour: 'numeric', minute: '2-digit' });
    let l = leads.find(x => x.calendlyId === evId);
    if (l) {   // keep the date/cancel status current; never overwrite your stage or notes otherwise
      const canceled = ev.status === 'canceled';
      if (l.callDate !== callDate || !!l.canceled !== canceled) { l.callDate = callDate; l.callTime = callTime; l.canceled = canceled; changed++; }
      continue;
    }
    const inv = ((await api(ev.uri + '/invitees?count=5')).collection || [])[0] || {};
    const qa = (inv.questions_and_answers || []).map(q => `${q.question}: ${q.answer}`).join('\n');
    const phone = inv.text_reminder_number || ((inv.questions_and_answers || []).find(q => /phone|number/i.test(q.question)) || {}).answer || '';
    leads.unshift({ id: cid(), createdAt: Date.now(), calendlyId: evId, name: inv.name || 'Calendly booking', contact: [phone, inv.email].filter(Boolean).join(' · '),
      source: 'Calendly', stage: 'Call booked', date: new Date(inv.created_at || ev.created_at || Date.now()).toLocaleDateString('en-CA', { timeZone: 'America/Chicago' }),
      callDate, callTime, canceled: ev.status === 'canceled', value: '', notes: (qa ? qa + '\n' : '') + `Booked on Calendly for ${callDate} at ${callTime}` });
    added++;
  }
  if (added || changed) await kset(COACH.leads, leads);
  st.lastSync = new Date().toISOString(); await kset(COACH.calendly, st);
  return { added, changed };
}
if (process.env.CALENDLY_TOKEN) setInterval(() => calendlySync(true).catch(e => console.log('Calendly sync failed', e.message)), 15 * 60 * 1000);
app.post('/api/coach/calendly/sync', async (req, res) => { try { res.json({ ok: true, ...(await calendlySync(true)) }); } catch (e) { res.status(500).json({ error: e.message }); } });
// IG Reels planner (same setup as the Billy's Couches Content tab), saved as one object.
app.post('/api/coach/reels/save', async (req, res) => {
  try { const d = req.body.data; if (!d || typeof d !== 'object' || JSON.stringify(d).length > 300000) return res.status(400).json({ error: 'Bad data' });
    await kset(COACH.reels, d); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/coach', async (req, res) => {
  try { await calendlySync().catch(e => console.log('Calendly sync failed', e.message));
    const [clients, leads, videos, settings, reels] = await Promise.all([getClients(), coachList('leads'), coachList('videos'), kget(COACH.settings, {}), kget(COACH.reels, null)]);
    res.json({ ok: true, clients, leads, videos, settings: settings || {}, reels, calendly: !!process.env.CALENDLY_TOKEN, week: weekKey() }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/coach/client/save', async (req, res) => {
  try {
    const c = req.body.client || {}; if (!clean(c.name, 80)) return res.status(400).json({ error: 'Add a name' });
    if (JSON.stringify(c).length > 150000) return res.status(400).json({ error: 'Too big' });
    const list = await getClients();
    if (c.pin) { c.pin = String(c.pin).replace(/\D/g, '').slice(0, 6); if (c.pin.length < 4) return res.status(400).json({ error: 'PIN must be 4-6 digits' });
      if (list.some(x => x.id !== c.id && x.pin === c.pin)) return res.status(400).json({ error: 'Another client already has that PIN' }); }
    const i = list.findIndex(x => x.id === c.id);
    if (i < 0) { c.id = cid(); c.createdAt = Date.now(); list.unshift(c); } else list[i] = { ...list[i], ...c };
    await kset(COACH.clients, list); res.json({ ok: true, client: list.find(x => x.id === c.id) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/coach/settings', async (req, res) => {
  try { const cur = (await kget(COACH.settings, {})) || {}, t = req.body.callTemplate;
    if (typeof t === 'string') cur.callTemplate = t.slice(0, 8000);
    await kset(COACH.settings, cur); res.json({ ok: true, settings: cur }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/coach/client/delete', async (req, res) => {
  try { await kset(COACH.clients, (await getClients()).filter(x => x.id !== req.body.id)); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});
// YouTube videos get Google Calendar events (via the Apps Script): an all-day "Post:" event on the post date,
// and a "Film:" event on the film date (timed if a film time is set, otherwise all-day).
async function ytCalSync(it, old) {
  if (!CFG.API) return;
  const call = async q => { const u = new URL(CFG.API); Object.entries({ key: CFG.KEY, action: 'yt', ...q }).forEach(([k, v]) => u.searchParams.set(k, v));
    const j = await (await fetch(u)).json(); if (j.error) throw new Error(j.error); return j; };
  const slots = [
    { id: 'eventId', date: 'date', time: null, title: 'Post: ' + it.title, oldTitle: old && 'Post: ' + old.title },
    { id: 'filmEventId', date: 'filmDate', time: 'filmTime', title: 'Film: ' + it.title, oldTitle: old && 'Film: ' + old.title }];
  const errs = [];
  for (const sl of slots) {
    try {
      const d = it[sl.date], t = sl.time ? it[sl.time] || '' : '';
      if (d && it.title) {
        const same = old && old[sl.date] === d && (!sl.time || (old[sl.time] || '') === t) && old.title === it.title && it.calTitled;
        if (!same || !it[sl.id]) { const j = await call({ op: 'upsert', eventId: it[sl.id] || '', title: sl.title, date: d, time: t }); it[sl.id] = j.eventId; }
      } else if (it[sl.id]) { await call({ op: 'delete', eventId: it[sl.id] }); it[sl.id] = ''; }
    } catch (e) { errs.push(e.message); }
  }
  it.calTitled = true; it.calError = errs.join('; ');
  if (errs.length) console.log('YouTube calendar sync failed:', it.calError);
}
app.post('/api/coach/:kind/save', async (req, res) => {
  try {
    const k = req.params.kind; if (!['leads', 'videos'].includes(k)) return res.status(400).json({ error: 'bad kind' });
    const it = req.body.item || {}; if (JSON.stringify(it).length > 20000) return res.status(400).json({ error: 'Too big' });
    const list = await coachList(k), i = list.findIndex(x => x.id === it.id), old = i > -1 ? { ...list[i] } : null;
    if (i < 0) { it.id = cid(); it.createdAt = Date.now(); list.unshift(it); } else list[i] = { ...list[i], ...it, updatedAt: Date.now() };
    if (k === 'videos') await ytCalSync(list.find(x => x.id === it.id), old);
    await kset(COACH[k], list); res.json({ ok: true, item: list.find(x => x.id === it.id) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/coach/:kind/delete', async (req, res) => {
  try { const k = req.params.kind; if (!['leads', 'videos'].includes(k)) return res.status(400).json({ error: 'bad kind' });
    const all = await coachList(k), gone = all.find(x => x.id === req.body.id);
    if (k === 'videos' && gone && (gone.eventId || gone.filmEventId)) { gone.date = ''; gone.filmDate = ''; await ytCalSync(gone, null); }
    await kset(COACH[k], all.filter(x => x.id !== req.body.id)); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});
// Client portal: each client logs in with their own PIN and only ever sees their own page.
const portalSig = c => crypto.createHmac('sha256', SECRET).update('client:' + c.id + ':' + c.pin).digest('hex').slice(0, 32);
const portalTries = {};
async function portalClient(req) {
  const m = String(req.headers.cookie || '').match(/(?:^|;\s*)bcc=([a-f0-9]+)\.([a-f0-9]{32})/); if (!m) return null;
  const c = (await getClients()).find(x => x.id === m[1] && x.active !== false && x.pin);
  return c && portalSig(c) === m[2] ? c : null;
}
function portalView(c) {
  const wk = weekKey();
  return { name: c.name, business: c.business || '', calendly: c.calendly || '', program: { length: c.program?.length, start: c.program?.start, end: c.program?.end },
    start: c.start || {}, goals: c.goals || {}, calls: (c.calls || []).map(x => ({ id: x.id, title: x.title, date: x.date, link: x.link, notes: x.notes })),
    tasks: (c.tasks || []).map(t => ({ id: t.id, text: t.text, month: t.month, recurring: !!t.recurring, done: t.recurring ? t.doneWeek === wk : !!t.done })),
    checkins: (c.checkins || []).slice().sort((a, b) => a.week.localeCompare(b.week)), week: wk };
}
app.get('/client', (req, res) => res.set('X-Robots-Tag', 'noindex').sendFile(path.join(__dirname, 'portal.html')));
app.post('/client/api/login', async (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.ip, now = Date.now(), t = portalTries[ip] = (portalTries[ip] || []).filter(x => now - x < 10 * 60 * 1000);
  if (t.length >= 10) return res.status(429).json({ error: 'Too many tries. Wait 10 minutes.' });
  const pin = String((req.body || {}).pin || '').replace(/\D/g, '');
  const c = pin.length >= 4 && (await getClients()).find(x => x.pin === pin && x.active !== false);
  if (!c) { t.push(now); return res.status(401).json({ error: 'That PIN didn\'t work.' }); }
  res.setHeader('Set-Cookie', `bcc=${c.id}.${portalSig(c)}; Path=/client; HttpOnly; SameSite=Lax; Max-Age=${60 * 60 * 24 * 120}; Secure`);
  res.json({ ok: true });
});
app.get('/client/api/logout', (req, res) => { res.setHeader('Set-Cookie', 'bcc=; Path=/client; Max-Age=0'); res.redirect('/client'); });
app.get('/client/api/me', async (req, res) => {
  const c = await portalClient(req); if (!c) return res.status(401).json({ error: 'login' });
  res.set('Cache-Control', 'no-store').json({ ok: true, me: portalView(c) });
});
app.post('/client/api/task', async (req, res) => {
  try {
    const me = await portalClient(req); if (!me) return res.status(401).json({ error: 'login' });
    const list = await getClients(), c = list.find(x => x.id === me.id), t = (c.tasks || []).find(x => x.id === req.body.id); if (!t) return res.status(404).json({ error: 'not found' });
    if (t.recurring) t.doneWeek = req.body.done ? weekKey() : ''; else { t.done = !!req.body.done; t.doneAt = t.done ? Date.now() : null; }
    await kset(COACH.clients, list); res.json({ ok: true, me: portalView(c) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/client/api/checkin', async (req, res) => {
  try {
    const me = await portalClient(req); if (!me) return res.status(401).json({ error: 'login' });
    const b = req.body || {}, n = v => Math.max(0, Math.round(Number(String(v ?? '').replace(/[^\d.]/g, '')) || 0));
    const week = /^\d{4}-\d{2}-\d{2}$/.test(b.week || '') ? weekKey(new Date(b.week + 'T12:00:00Z')) : weekKey();
    const list = await getClients(), c = list.find(x => x.id === me.id); c.checkins = (c.checkins || []).filter(x => x.week !== week);
    c.checkins.push({ week, flips: n(b.flips), revenue: n(b.revenue), profit: n(b.profit), leads: n(b.leads), win: clean(b.win, 500), stuck: clean(b.stuck, 500), at: Date.now() });
    await kset(COACH.clients, list); res.json({ ok: true, me: portalView(c) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------- weekly pay for the team scorecard ("My pay") ----------
// Same math as the Payroll tab: hours x rate + $20 per showing sold + $20 once deep cleans hit 4 + adjustments.
// Tips are shown but not added (customers tip the team directly). Protected by TEAM_PAY_KEY.
const ctDate = d => d.toLocaleDateString('en-CA', { timeZone: 'America/Chicago' });
function weekBounds(offset) {
  const t = new Date(ctDate(new Date()) + 'T12:00:00Z'); t.setUTCDate(t.getUTCDate() - ((t.getUTCDay() + 6) % 7) + 7 * offset);
  const sun = new Date(t); sun.setUTCDate(sun.getUTCDate() + 6);
  return { mon: t.toISOString().slice(0, 10), sun: sun.toISOString().slice(0, 10) };
}
app.get('/public/team-pay', async (req, res) => {
  const key = (process.env.TEAM_PAY_KEY || '').trim();
  if (!key || req.query.key !== key) return res.status(401).json({ error: 'bad key' });
  try {
    const log = await workLog(false);
    const [rates0, adj, paid, goals] = await Promise.all([kget(KEYS.rates, {}), kget(KEYS.adj, {}), kget(KEYS.paid, {}), kget('bcd:teamGoals', {})]);
    const rates = { ...DEFAULT_RATES, ...rates0 };
    const fname = n => String(n || '').trim().split(/\s+/)[0] || 'Unknown';
    const pk = n => fname(n).toLowerCase().replace(/^gunarr$/, 'gunnarr');
    const week = offset => {
      const W = weekBounds(offset), people = {};
      (log.entries || []).filter(e => e.date >= W.mon && e.date <= W.sun).forEach(e => {
        const k = pk(e.name), p = people[k] = people[k] || { key: k, name: fname(e.name), hours: 0, deep: 0, spot: 0, sold: 0, shows: 0, tip: 0, days: 0 };
        p.hours += e.hours; p.deep += e.deep; p.spot += e.spot; p.sold += e.sold; p.shows += e.shows; p.tip += e.tip || 0; p.days++;
      });
      const A = adj[W.mon] || {};
      Object.values(people).forEach(p => {
        p.rate = rates[p.key] ?? 0; p.hourly = Math.round(p.hours * p.rate * 100) / 100;
        p.showBonus = p.sold * 20; p.cleanBonus = p.deep >= 4 ? 20 : 0; p.deepToGo = Math.max(0, 4 - p.deep);
        p.adj = (A[p.key] && A[p.key].amount) || 0; p.adjNote = (A[p.key] && A[p.key].note) || '';
        p.total = Math.round((p.hourly + p.showBonus + p.cleanBonus + p.adj) * 100) / 100;
      });
      return { ...W, paid: paid[W.mon] || '', people };
    };
    const tw = week(0), lw = week(-1), G = {};
    Object.entries(goals).forEach(([k, list]) => { G[k] = (list || []).map(g => {
      const have = g.metric === 'custom' ? null : Math.round((((tw.people[k] || {})[g.metric]) || 0) * 100) / 100;
      return { ...g, have, hit: g.metric === 'custom' ? g.done : have >= g.target };
    }); });
    res.json({ ok: true, thisWeek: tw, lastWeek: lw, goals: G });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------- demo data (only before SHEETS_API_URL is set) ----------
function demoData() {
  const H = ['Date', 'Source', 'Customer', 'Phone', 'Payment', 'Order Type', 'ZIP', 'Tax Rate', 'Couch Price',
    'Discount', 'Delivery', 'Subtotal', 'Tax', 'Fee', 'Total', 'Receipt', 'Add-Ons', 'Add-Ons $'];
  const src = ['Meta Ads', 'Marketplace', 'Facebook or Instagram Ad', 'TikTok', 'Referral', 'Google', 'Meta Ads', 'Craigslist'];
  const now = new Date();
  const rows = [], showings = [];
  for (let m = 0; m < 3; m++) {
    for (let i = 0; i < 34 - m * 4; i++) {
      const d = new Date(now.getFullYear(), now.getMonth() - m, 1 + (i * 7) % 27);
      const price = [899, 1050, 1250, 1299, 1499, 1650, 1950, 699][i % 8];
      const del = i % 3 === 0 ? 0 : 150;
      rows.push([d.toISOString().slice(0, 10), src[i % 8], 'Customer ' + i, '', i % 4 ? 'Card' : 'Venmo',
        del ? 'Delivery' : 'Pickup', '63069', '9.68%', price, 0, del, price + del, 0, 0, 0, '',
        ['', 'Scotchgard', '', 'Plastic Wrap, Scotchgard', '', 'Couch Removal', '', ''][i % 8], [0, 49, 0, 148, 0, 125, 0, 0][i % 8]]);
    }
    for (let i = 0; i < 90; i++) {
      const d = new Date(now.getFullYear(), now.getMonth() - m, 1 + i % 28, 10 + i % 8, (i % 3) * 20);
      const t = i % 9 === 0 ? '(No show) ' : i % 2 ? '(Canceled) ' : '';
      showings.push([d.toISOString(), t + 'Showing for Customer ' + i, !t && i % 4 === 0 ? '2' : '']);
    }
  }
  return { ok: true, demo: true, at: new Date().toISOString(), sales: { headers: H, rows }, showings };
}

app.listen(CFG.PORT, () => console.log('Billy\'s Couches dashboard on ' + CFG.PORT));

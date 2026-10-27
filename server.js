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

// ---------- password ----------
const SECRET = crypto.createHash('sha256').update('bcd:' + CFG.PASSWORD).digest('hex');
function authed(req) {
  const c = (req.headers.cookie || '').split(';').map(x => x.trim()).find(x => x.startsWith('bcd='));
  return !!CFG.PASSWORD && !!c && c.slice(4) === SECRET;
}
const safeNext = n => /^\/[\w\/?=&-]*$/.test(n || '') && !String(n).startsWith('//') ? String(n).replace(/[?&]bad=1/, '') : '/';
app.post('/login', (req, res) => {
  if (CFG.PASSWORD && req.body.password === CFG.PASSWORD) {
    res.setHeader('Set-Cookie', `bcd=${SECRET}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60 * 60 * 24 * 60}; Secure`);
    return res.redirect(safeNext(req.body.next));
  }
  const n = safeNext(req.body.next); res.redirect(n + (n.includes('?') ? '&' : '?') + 'bad=1');
});
app.get('/logout', (req, res) => { res.setHeader('Set-Cookie', 'bcd=; Path=/; Max-Age=0'); res.redirect('/'); });
app.get('/', (req, res) => res.sendFile(path.join(__dirname, authed(req) ? 'index.html' : 'login.html')));
app.get('/healthz', (req, res) => res.send('ok'));
const longCache = { headers: { 'Cache-Control': 'public, max-age=604800' } };
app.get('/chart.js', (req, res) => res.sendFile(path.join(__dirname, 'node_modules', 'chart.js', 'dist', 'chart.umd.js'), longCache));
['icon-180.png', 'icon-192.png', 'icon-512.png', 'manifest.json'].forEach(f => app.get('/' + f, (req, res) => res.sendFile(path.join(__dirname, f), longCache)));
app.use('/api', (req, res, next) => authed(req) ? next() : res.status(401).json({ error: 'login' }));


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

app.get('/api/data', async (req, res) => {
  try {
    const [g, purchases, expenses, loads, openhouses] = await Promise.all([
      google(req.query.fresh === '1'), getPurchases(), getExpenses(), getLoads(), getOpenHouses(),
    ]);
    const photos = await kget('bcd:photos', {}).catch(() => ({}));
    const goals = await getGoals().catch(() => ({}));
    res.json({ ...g, purchases, expenses, loads, openhouses, photos, goals, history: HISTORY, storage: CFG.REDIS_URL ? 'redis' : 'file' });
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
      (Array.isArray(lines) ? lines : []).filter(l => Number(l.total) > 0).forEach(l => list.push({
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
      const items = await kget('bcd:plaidItems', []), it = items.find(x => x.item_id === req.body.itemId);
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
    const items = (await kget('bcd:plaidItems', [])).filter(x => x.item_id !== j.item_id);
    items.push({ item_id: j.item_id, access_token: j.access_token, institution: clean(institution, 60) || 'Bank', added: new Date().toISOString() });
    await kset('bcd:plaidItems', items);
    plaidCache = { at: 0, data: null };
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/plaid/remove', async (req, res) => {
  try {
    const items = await kget('bcd:plaidItems', []), it = items.find(x => x.item_id === req.body.itemId);
    if (it) { try { await plaid('/item/remove', { access_token: it.access_token }); } catch {} }
    await kset('bcd:plaidItems', items.filter(x => x.item_id !== req.body.itemId));
    plaidCache = { at: 0, data: null };
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
let plaidCache = { at: 0, data: null };
async function plaidBalances(force) {
  if (!force && plaidCache.data && Date.now() - plaidCache.at < 10 * 60 * 1000) return plaidCache.data;
  const items = await kget('bcd:plaidItems', []), banks = [], fields = {};
  for (const it of items) {
    try {
      const j = await plaid('/accounts/get', { access_token: it.access_token });
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
  plaidCache = { at: Date.now(), data: { banks, fields, at: new Date().toISOString(), configured: !!(PLAID.ID && PLAID.SECRET), env: PLAID.ENV } };
  return plaidCache.data;
}
app.get('/api/plaid/balances', async (req, res) => {
  try { res.json({ ok: true, ...(await plaidBalances(req.query.fresh === '1')) }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
// Every morning at 7am Central: if no entry exists for today, save one from the banks
// (safe, Venmo, stocks and rent carry over from your last entry; Stripe is pulled live).
async function autoCashSnapshot() {
  const items = await kget('bcd:plaidItems', []);
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
app.options('/public/recent-sales', (req, res) => { offerCors(req, res); res.sendStatus(204); });
app.get('/public/recent-sales', async (req, res) => {
  offerCors(req, res);
  try {
    await buildRecent();
    res.set('Cache-Control', 'public, max-age=300').json({ ok: true, sales: recentCache.data });
  } catch (e) { res.status(500).json({ error: 'unavailable' }); }
});
async function buildRecent() {
    if (!recentCache.data || Date.now() - recentCache.at > 10 * 60 * 1000) {
      const [loads, purchases] = await Promise.all([getLoads(), getPurchases()]);
      const cutoff = Date.now() - 5 * 864e5, out = [], pidx = await kget('bcd:photos', {}).catch(() => ({}));
      const shortName = n => { const w = String(n || '').trim().split(/\s+/).filter(Boolean); if (!w.length) return '';
        const f = w[0][0].toUpperCase() + w[0].slice(1).toLowerCase(); return w.length > 1 ? f + ' ' + w[w.length - 1][0].toUpperCase() + '.' : f; };
      // Sales Log rows: when the customer actually paid (receipt link carries the exact time) and who bought.
      const log = [];
      try {
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
          log.push({ i, day: d.toLocaleDateString('en-CA', { timeZone: 'America/Chicago' }), ts, name: String(r[C.name] || '').trim(), price, net, used: false });
        });
      } catch (e) { console.log('Just sold: Sales Log unavailable', e.message); }
      const dayDiff = (a, b) => Math.round((Date.parse(a) - Date.parse(b)) / 864e5);
      const findSale = (soldDate, soldPrice, cust) => {
        const c = String(cust || '').toLowerCase().trim(), last = c.split(/\s+/).pop();
        const pool = log.filter(l => !l.used && dayDiff(soldDate, l.day) >= -1 && dayDiff(soldDate, l.day) <= 10);
        const byName = c ? pool.filter(l => l.name.toLowerCase().includes(last)) : [];
        const byPrice = pool.filter(l => Math.abs(l.price - soldPrice) < 1 || Math.abs(l.net - soldPrice) < 1);
        const hit = (byName.length ? byName : byPrice).sort((a, b) => Math.abs(dayDiff(soldDate, a.day)) - Math.abs(dayDiff(soldDate, b.day)))[0];
        if (hit) hit.used = true; return hit || null;
      };
      const add = (name, soldDate, soldPrice, pkey, cust) => {
        const hit = findSale(soldDate, soldPrice, cust);
        const exact = !!(hit && hit.ts), at = exact ? hit.ts : Math.min(Date.now(), Date.parse((hit ? hit.day : soldDate) + 'T12:00:00-05:00'));
        const title = cleanCouchName(name);
        if (!(title.length >= 4 && at > cutoff && at <= Date.now())) return;
        const row = { title, at: new Date(at).toISOString(), exact };
        const who = shortName(cust || (hit && hit.name)); if (who) row.who = who;
        if (pidx[pkey]) { const t = crypto.createHash('sha1').update(pkey).digest('hex').slice(0, 16); row.photo = `/public/sale-photo/${t}?v=${pidx[pkey]}`; recentPhotos[t] = pkey; }
        out.push(row);
      };
      const sold = [];
      loads.forEach(l => (l.units || []).forEach(u => { if (u.status === 'sold' && u.soldDate) sold.push([u.name, u.soldDate, u.soldPrice, 'u:' + l.id + ':' + u.uid, u.soldCustomer]); }));
      purchases.forEach(p => { if (p.status === 'sold' && p.soldDate) sold.push([p.item, p.soldDate, p.soldPrice, 'p:' + p.id, p.soldCustomer]); });
      sold.sort((a, b) => (b[4] ? 1 : 0) - (a[4] ? 1 : 0));   // couches with a customer name claim their sale first
      sold.forEach(x => add(...x));
      out.sort((a, b) => b.at.localeCompare(a.at));
      recentCache = { at: Date.now(), data: out.slice(0, 20) };
      const keep = new Set(recentCache.data.filter(r => r.photo).map(r => r.photo.split('/').pop().split('?')[0]));
      Object.keys(recentPhotos).forEach(t => { if (!keep.has(t)) delete recentPhotos[t]; });
    }
}

// Photo for a couch in the "Just sold" feed (only couches currently in that feed are reachable).
app.get('/public/sale-photo/:t', async (req, res) => {
  try {
    if (!recentPhotos[req.params.t]) await buildRecent();
    const key = recentPhotos[req.params.t]; if (!key) return res.sendStatus(404);
    const m = String(await kget(photoKey(key), '')).match(/^data:(image\/\w+);base64,(.+)$/); if (!m) return res.sendStatus(404);
    res.set('Cache-Control', 'public, max-age=86400').type(m[1]).send(Buffer.from(m[2], 'base64'));
  } catch (e) { res.sendStatus(404); }
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

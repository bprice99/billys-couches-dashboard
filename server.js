// Billy's Couches Dashboard
// Railway variables:
//   APP_PASSWORD                password to get in
//   SHEETS_API_URL              the Apps Script Web app URL
//   SHEETS_KEY                  the SECRET phrase in the Apps Script
//   UPSTASH_REDIS_REST_URL      \ where purchases + expenses are saved
//   UPSTASH_REDIS_REST_TOKEN    / (same Upstash database as the order app is fine)
//   INVENTORY_URL               optional: defaults to billyscouches.com/currentinventory
// Without SHEETS_API_URL it runs on demo data.

const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const cheerio = require('cheerio');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

const CFG = {
  PORT: process.env.PORT || 3000,
  PASSWORD: process.env.APP_PASSWORD || '',
  API: (process.env.SHEETS_API_URL || '').trim(),
  KEY: (process.env.SHEETS_KEY || '').trim(),
  REDIS_URL: (process.env.UPSTASH_REDIS_REST_URL || '').trim(),
  REDIS_TOKEN: (process.env.UPSTASH_REDIS_REST_TOKEN || '').trim(),
  INV_URL: (process.env.INVENTORY_URL || 'https://www.billyscouches.com/currentinventory').trim(),
};

// ---------- password ----------
const SECRET = crypto.createHash('sha256').update('bcd:' + CFG.PASSWORD).digest('hex');
function authed(req) {
  const c = (req.headers.cookie || '').split(';').map(x => x.trim()).find(x => x.startsWith('bcd='));
  return !!CFG.PASSWORD && !!c && c.slice(4) === SECRET;
}
app.post('/login', (req, res) => {
  if (CFG.PASSWORD && req.body.password === CFG.PASSWORD) {
    res.setHeader('Set-Cookie', `bcd=${SECRET}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60 * 60 * 24 * 60}; Secure`);
    return res.redirect('/');
  }
  res.redirect('/?bad=1');
});
app.get('/logout', (req, res) => { res.setHeader('Set-Cookie', 'bcd=; Path=/; Max-Age=0'); res.redirect('/'); });
app.get('/', (req, res) => res.sendFile(path.join(__dirname, authed(req) ? 'index.html' : 'login.html')));
app.get('/healthz', (req, res) => res.send('ok'));
app.get('/chart.js', (req, res) => res.sendFile(path.join(__dirname, 'node_modules', 'chart.js', 'dist', 'chart.umd.js')));
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
const KEYS = { purchases: 'bcd:purchases', expenses: 'bcd:expenses', seen: 'bcd:invseen', loads: 'bcd:loads' };

// Past months imported from Ivy Flip (Jan-Sep 2026).
let HISTORY = { sales: [], expenses: [] };
try { HISTORY = require('./history.json'); } catch { console.log('No history.json'); }

// ---------- Google (sales, showings, bstock) ----------
let cache = { at: 0, data: null };
async function google(force) {
  if (!CFG.API) return demoData();
  if (!force && cache.data && Date.now() - cache.at < 60 * 1000) return cache.data;
  const url = `${CFG.API}?key=${encodeURIComponent(CFG.KEY)}`;
  const r = await fetch(url);
  const text = await r.text();
  let j;
  try { j = JSON.parse(text); } catch { throw new Error('Apps Script did not return data. Check the deployment.'); }
  if (j.error) throw new Error('Sheet: ' + j.error);
  cache = { at: Date.now(), data: j };
  return j;
}

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

app.get('/api/data', async (req, res) => {
  try {
    const [g, purchases, expenses, loads] = await Promise.all([
      google(req.query.fresh === '1'), kget(KEYS.purchases, []), getExpenses(), getLoads(),
    ]);
    res.json({ ...g, purchases, expenses, loads, history: HISTORY, storage: CFG.REDIS_URL ? 'redis' : 'file' });
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
    if (!['purchases', 'expenses', 'loads'].includes(kind)) return res.status(400).json({ error: 'bad kind' });
    const list = await kget(KEYS[kind], []);
    await kset(KEYS[kind], list.filter(x => x.id !== id));
    if (String(id).startsWith('ivy-')) { const g = await kget('bcd:deletedImports', []); g.push(id); await kset('bcd:deletedImports', g); }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------- B-Stock loads ----------
// First run: loads-seed.json (Aug-Oct loads from the Bstock sheet) becomes the starting list.
async function getLoads() {
  let loads = await kget(KEYS.loads, null);
  if (!loads || !loads.length) {
    let seed = null;
    try { seed = JSON.parse(fs.readFileSync(path.join(__dirname, 'loads-seed.json'), 'utf8')); } catch (e) { console.log('loads-seed.json not readable:', e.message); }
    if (Array.isArray(seed) && seed.length) { loads = seed; await kset(KEYS.loads, loads); }
    else loads = loads || [];
  }
  return loads;
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
    await kset(KEYS.loads, loads);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Log (or undo) the sale of a used pickup
app.post('/api/purchases/sale', async (req, res) => {
  try {
    const { id, status, soldPrice, soldDate } = req.body || {};
    const list = await kget(KEYS.purchases, []);
    const p = list.find(x => x.id === id);
    if (!p) return res.status(404).json({ error: 'Not found' });
    p.status = status === 'sold' ? 'sold' : 'in';
    p.soldPrice = p.status === 'sold' ? Math.max(0, Number(soldPrice) || 0) : 0;
    p.soldDate = p.status === 'sold' ? (/^\d{4}-\d{2}-\d{2}$/.test(soldDate) ? soldDate : new Date().toISOString().slice(0, 10)) : '';
    await kset(KEYS.purchases, list);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------- couch list (reads the Current Inventory page) ----------
let inv = { at: 0, data: null };
function parseInventory(html) {
  const $ = cheerio.load(html);
  const secs = $('section.page-section').toArray();
  const items = [];
  secs.forEach((s, i) => {
    const $s = $(s);
    const hasBuy = $s.find('a').toArray().some(a => /buy now/i.test($(a).text()));
    if (!hasBuy) return;
    const els = $s.find('.sqs-block-html p, .sqs-block-html h1, .sqs-block-html h2, .sqs-block-html h3, .sqs-block-html h4').toArray()
      .map(e => $(e).text().replace(/\s+/g, ' ').trim()).filter(Boolean);
    const title = els.find(t => t.length > 12 && !/^\$?\d/.test(t) && !/details|imperfection|dimension|last updated/i.test(t));
    const priceTxt = els.find(t => /^\$?\d[\d,]{2,}/.test(t));
    if (!title || !priceTxt) return;
    const nums = (priceTxt.match(/\d[\d,]*(\.\d+)?/g) || []).map(n => parseFloat(n.replace(/,/g, '')));
    const all = els.join(' | ');
    const grade = (all.match(/grade\s*[:\-]?\s*([A-D][+-]?)\b/i) || [])[1] || '';
    let img = '';
    for (let k = i - 1; k >= 0 && k >= i - 2 && !img; k--) {
      const im = $(secs[k]).find('img').first();
      img = im.attr('data-src') || im.attr('src') || '';
    }
    if (!img) { const im = $s.find('img').first(); img = im.attr('data-src') || im.attr('src') || ''; }
    if (img.includes('squarespace-cdn')) img = img.split('?')[0] + '?format=300w';
    items.push({ title, price: nums[0] || 0, retail: nums[1] && nums[1] > nums[0] ? nums[1] : 0, grade, img });
  });
  return items;
}

app.get('/api/inventory', async (req, res) => {
  try {
    if (req.query.fresh !== '1' && inv.data && Date.now() - inv.at < 10 * 60 * 1000) return res.json(inv.data);
    const r = await fetch(CFG.INV_URL, { headers: { 'User-Agent': 'Mozilla/5.0 BillysCouchesDashboard' } });
    const items = parseInventory(await r.text());
    // Days on floor = days since the dashboard first saw this couch on the page.
    const seen = await kget(KEYS.seen, {});
    const today = new Date().toISOString().slice(0, 10);
    const count = {};
    items.forEach(it => {
      count[it.title] = (count[it.title] || 0) + 1;
      it.key = it.title + (count[it.title] > 1 ? ' #' + count[it.title] : '');
      if (!seen[it.key]) seen[it.key] = today;
      it.firstSeen = seen[it.key];
    });
    await kset(KEYS.seen, seen);
    inv = { at: Date.now(), data: { ok: true, at: new Date().toISOString(), items } };
    res.json(inv.data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------- demo data (only before SHEETS_API_URL is set) ----------
function demoData() {
  const H = ['Date', 'Source', 'Customer', 'Phone', 'Payment', 'Order Type', 'ZIP', 'Tax Rate', 'Couch Price',
    'Discount', 'Delivery', 'Subtotal', 'Tax', 'Fee', 'Total', 'Receipt'];
  const src = ['Meta Ads', 'Marketplace', 'Facebook or Instagram Ad', 'TikTok', 'Referral', 'Google', 'Meta Ads', 'Craigslist'];
  const now = new Date();
  const rows = [], showings = [];
  for (let m = 0; m < 3; m++) {
    for (let i = 0; i < 34 - m * 4; i++) {
      const d = new Date(now.getFullYear(), now.getMonth() - m, 1 + (i * 7) % 27);
      const price = [899, 1050, 1250, 1299, 1499, 1650, 1950, 699][i % 8];
      const del = i % 3 === 0 ? 0 : 150;
      rows.push([d.toISOString().slice(0, 10), src[i % 8], 'Customer ' + i, '', i % 4 ? 'Card' : 'Venmo',
        del ? 'Delivery' : 'Pickup', '63069', '9.68%', price, 0, del, price + del, 0, 0, 0, '']);
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

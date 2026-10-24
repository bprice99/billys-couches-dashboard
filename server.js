// Billy's Couches Dashboard
// Reads the Google Sheet through the "Dashboard" Apps Script and serves a
// password-protected dashboard. Railway variables:
//   APP_PASSWORD     password to get in
//   SHEETS_API_URL   the Apps Script Web app URL
//   SHEETS_KEY       the same SECRET phrase set in the Apps Script
// Without SHEETS_API_URL it runs on demo data so you can see it first.

const express = require('express');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

const CFG = {
  PORT: process.env.PORT || 3000,
  PASSWORD: process.env.APP_PASSWORD || '',
  API: process.env.SHEETS_API_URL || '',
  KEY: process.env.SHEETS_KEY || '',
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

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, authed(req) ? 'index.html' : 'login.html'));
});
app.use('/api', (req, res, next) => authed(req) ? next() : res.status(401).json({ error: 'login' }));

// ---------- data ----------
let cache = { at: 0, data: null };
// Past months imported from Ivy Flip (Jan-Sep 2026). Those months use this file
// for sales, cost of goods and expenses; later months use the live sheet.
let HISTORY = { sales: [], expenses: [] };
try { HISTORY = require('./history.json'); } catch (e) { console.log('No history.json'); }

async function sheetData(force) {
  if (!CFG.API) return demoData();
  if (!force && cache.data && Date.now() - cache.at < 60 * 1000) return cache.data;
  const r = await fetch(`${CFG.API}?key=${encodeURIComponent(CFG.KEY)}`);
  const j = await r.json();
  if (j.error) throw new Error('Sheet: ' + j.error);
  cache = { at: Date.now(), data: j };
  return j;
}

app.get('/api/data', async (req, res) => {
  try { res.json({ ...(await sheetData(req.query.fresh === '1')), history: HISTORY }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/add', async (req, res) => {
  const { action, data } = req.body || {};
  if (!['addPurchase', 'addExpense'].includes(action)) return res.status(400).json({ error: 'bad action' });
  if (!CFG.API) return res.json({ ok: true, demo: true });
  try {
    const r = await fetch(CFG.API, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: JSON.stringify({ key: CFG.KEY, action, data }),
    });
    const j = await r.json();
    cache.at = 0;                       // next load pulls fresh
    res.json(j);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/chart.js', (req, res) => res.sendFile(path.join(__dirname, 'node_modules', 'chart.js', 'dist', 'chart.umd.js')));
app.get('/healthz', (req, res) => res.send('ok'));

// ---------- demo data (only used before SHEETS_API_URL is set) ----------
function demoData() {
  const H = ['Date', 'Source', 'Name', 'Phone', 'Payment', 'Order Type', 'ZIP', 'Tax Rate', 'Couch Price',
    'Discount', 'Delivery', 'Subtotal', 'Tax', 'Fee', 'Total', 'Receipt'];
  const src = ['Meta Ads', 'Marketplace', 'Meta Ads', 'TikTok', 'Referral', 'Google', 'Meta Ads', 'Craigslist'];
  const now = new Date();
  const rows = [];
  for (let m = 0; m < 3; m++) {
    for (let i = 0; i < 34 - m * 4; i++) {
      const d = new Date(now.getFullYear(), now.getMonth() - m, 1 + (i * 7) % 27);
      const price = [899, 1050, 1250, 1299, 1499, 1650, 1950, 699][i % 8];
      const del = i % 3 === 0 ? 0 : 150;
      const sub = price + del;
      rows.push([d.toISOString().slice(0, 10), src[i % 8], 'Customer ' + i, '', i % 4 ? 'Card' : 'Venmo',
        del ? 'Delivery' : 'Pickup', '63069', '9.68%', price, 0, del, sub, +(sub * 0.0968).toFixed(2), 0, 0, '']);
    }
  }
  const pRows = [];
  for (let m = 0; m < 3; m++) {
    const base = new Date(now.getFullYear(), now.getMonth() - m, 1);
    pRows.push([new Date(base.getTime() + 6 * 864e5).toISOString().slice(0, 10), 'Bstock', 'DAL-7047878 load', 5, 3444.75, 'DAL-7047878', '']);
    pRows.push([new Date(base.getTime() + 11 * 864e5).toISOString().slice(0, 10), 'Bstock', 'GLD-7073270 load', 15, 7109.34, 'GLD-7073270', '']);
    for (let k = 0; k < 6; k++) pRows.push([new Date(base.getTime() + (3 + k * 4) * 864e5).toISOString().slice(0, 10), 'Marketplace', 'Used sectional', 1, 150 + k * 40, '', '']);
  }
  const eRows = [];
  const cats = [['Advertising', 4345], ['Rent', 2700], ['Supplies', 900], ['Payroll', 5200], ['Fuel', 640], ['Software', 320]];
  for (let m = 0; m < 3; m++) cats.forEach(([c, a], k) =>
    eRows.push([new Date(now.getFullYear(), now.getMonth() - m, 2 + k * 4).toISOString().slice(0, 10), c, a * (1 - m * 0.08), '', '']));
  return {
    ok: true, demo: true, at: new Date().toISOString(),
    sales: { headers: H, rows },
    purchases: { headers: ['Date', 'Source', 'Item', 'Units', 'Cost', 'Load ID', 'Notes'], rows: pRows },
    expenses: { headers: ['Date', 'Category', 'Amount', 'Vendor', 'Notes'], rows: eRows },
  };
}

app.listen(CFG.PORT, () => console.log('Billy\'s Couches dashboard on ' + CFG.PORT));

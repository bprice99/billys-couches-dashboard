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
app.use('/api/drops/read-dims', express.json({ limit: '6mb' }));
app.use('/public/couch-offer', express.json({ limit: '15mb' }));
app.use('/public/ai-room', express.json({ limit: '14mb' }));
app.use('/public/ai-sess', express.json({ limit: '14mb' }));
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
  // The sizing tool's "Arrange pieces" screen opens inside HQ itself, so /fit may be framed by HQ (same site only).
  if (req.path === '/fit' || req.path === '/jobs') res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  else if (!req.path.startsWith('/public/') && req.path !== '/brand-new' && req.path !== '/showing') res.setHeader('X-Frame-Options', 'DENY');   // /showing is embedded on billyscouches.com/visitshowroom
  next();
});
// "Will it fit?" on its own address (e.g. fit.billyscouches.com). Set FIT_BASE in Railway after adding the
// custom domain; that address only serves the sizing tool, never HQ.
const FIT_BASE = (process.env.FIT_BASE || '').trim().replace(/\/$/, '');
const FIT_HOST = FIT_BASE ? FIT_BASE.replace(/^https?:\/\//, '').toLowerCase() : '';
app.use((req, res, next) => {
  if (!FIT_HOST || String(req.headers.host || '').toLowerCase() !== FIT_HOST) return next();
  if (req.path === '/' || req.path === '/fit') return res.set('Cache-Control', 'no-cache').sendFile(path.join(__dirname, 'fit.html'));
  if (/^\/fit\/[a-f0-9]+$/.test(req.path) || req.path.startsWith('/public/') || ['/logo.png', '/favicon.png', '/favicon.ico'].includes(req.path)) return next();
  res.redirect('/');
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
// Weekly Cash: text Billy a link every Monday at 8am Central (once per week).
setInterval(async () => {
  try {
    const ct = new Date(new Date().toLocaleString('en-US', { timeZone: 'America/Chicago' }));
    if (ct.getDay() !== 1 || ct.getHours() < 8) return;
    const wk = ct.toLocaleDateString('en-CA'); if ((await kget('bcd:weeklySent', '')) === wk) return;
    await kset('bcd:weeklySent', wk);
    const from = new Date(ct); from.setDate(from.getDate() - 7); const to = new Date(ct); to.setDate(to.getDate() - 1);
    const f = d => d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    await textAlert(`Your weekly cash flow statement for ${f(from)} - ${f(to)} is ready: https://hq.billyscouches.com/weekly`);
  } catch (e) { console.log('weekly text failed', e.message); }
}, 10 * 60 * 1000);
// Monthly Cash: text Billy a link to last month's statement on the 1st at 8am Central.
setInterval(async () => {
  try {
    const ct = new Date(new Date().toLocaleString('en-US', { timeZone: 'America/Chicago' }));
    if (ct.getDate() !== 1 || ct.getHours() < 8) return;
    const mk = ct.toLocaleDateString('en-CA').slice(0, 7); if ((await kget('bcd:monthlySent', '')) === mk) return;
    await kset('bcd:monthlySent', mk);
    const lm = new Date(ct.getFullYear(), ct.getMonth() - 1, 1), key = lm.toLocaleDateString('en-CA').slice(0, 7);
    await textAlert(`Your ${lm.toLocaleDateString('en-US', { month: 'long' })} cash flow statement is ready: https://hq.billyscouches.com/weekly?m=${key}`);
  } catch (e) { console.log('monthly text failed', e.message); }
}, 10 * 60 * 1000);
const longCache = { headers: { 'Cache-Control': 'public, max-age=604800' } };
app.get('/chart.js', (req, res) => res.sendFile(path.join(__dirname, 'node_modules', 'chart.js', 'dist', 'chart.umd.js'), longCache));
['favicon.png', 'icon-180.png', 'icon-192.png', 'icon-512.png', 'manifest.json', 'logo.png'].forEach(f => app.get('/' + f, (req, res) => res.sendFile(path.join(__dirname, f), longCache)));
app.get('/sw.js', (req, res) => res.set('Cache-Control', 'no-cache').set('Service-Worker-Allowed', '/').type('application/javascript').sendFile(path.join(__dirname, 'sw.js')));
// Home page "one of one" photo: one-of-one.jpg if it's in the repo, otherwise the pasted-in text copy (one-of-one.b64.txt).
app.get('/public/one-of-one.jpg', (req, res) => {
  res.set('Cache-Control', 'public, max-age=86400').set('Access-Control-Allow-Origin', '*');
  const jpg = path.join(__dirname, 'one-of-one.jpg'), txt = path.join(__dirname, 'one-of-one.b64.txt');
  if (fs.existsSync(jpg)) return res.sendFile(jpg);
  try { res.type('image/jpeg').send(Buffer.from(fs.readFileSync(txt, 'utf8').replace(/[^A-Za-z0-9+/=]/g, ''), 'base64')); } catch (e) { res.sendStatus(404); }
});
// Billy's photo for customer emails (image.jpg in the repo).
app.get('/public/billy.jpg', (req, res) => res.set('Cache-Control', 'public, max-age=86400').set('Access-Control-Allow-Origin', '*').sendFile(path.join(__dirname, 'image.jpg')));
app.get('/public/logo.png', (req, res) => res.set('Cache-Control', 'public, max-age=86400').set('Access-Control-Allow-Origin', '*').sendFile(path.join(__dirname, 'logo.png')));
app.get('/favicon.ico', (req, res) => res.sendFile(path.join(__dirname, 'favicon.png'), longCache));
app.use('/api', (req, res, next) => authed(req) ? next() : res.status(401).json({ error: 'login' }));
// ---------- /security page: sessions + two-step login ----------
app.get('/weekly', (req, res) => res.sendFile(path.join(__dirname, authed(req) ? 'index.html' : 'login.html')));
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
// "Save my spot" sign-ups from billyscouches.com/openhouse (the page posts here as well as to the Google Sheet).
// HQ's Open Houses tab files each one under the next open house on or after the day they signed up.
const OHS_KEY = 'bcd:ohSignups', ohsHits = new Map();
async function addSignup(b, src) {
  const name = clean(b.name, 80), phone = String(b.phone || '').replace(/\D/g, '').replace(/^1(\d{10})$/, '$1');
  if (!name || phone.length !== 10) throw new Error('Add a name and a 10-digit phone number');
  const at = b.date && /^\d{4}-\d{2}-\d{2}$/.test(b.date) ? Date.parse(b.date + 'T12:00:00-06:00') : Date.now();
  const list = await kget(OHS_KEY, []), dupe = list.find(x => x.phone === phone && Math.abs(at - x.at) < 10 * 864e5);
  if (dupe) { dupe.name = name; if (b.couch) dupe.couch = clean(b.couch, 120); }
  else list.unshift({ id: crypto.randomBytes(5).toString('hex'), name, phone, couch: clean(b.couch, 120), at, src });
  await kset(OHS_KEY, list.slice(0, 1000));
}
app.options('/public/oh-signup', (req, res) => { res.setHeader('Access-Control-Allow-Origin', '*'); res.setHeader('Access-Control-Allow-Headers', 'Content-Type'); res.sendStatus(204); });
app.post('/public/oh-signup', async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  try {
    const b = req.body || {}; if (b.website) return res.json({ ok: true });   // honeypot = bot
    const ip = clientIp(req), now = Date.now(), h = (ohsHits.get(ip) || []).filter(t => now - t < 3600e3);
    if (h.length >= 10) return res.status(429).json({ error: 'Too many tries' }); h.push(now); ohsHits.set(ip, h);
    await addSignup({ name: b.name, phone: b.phone, couch: b.couch }, 'website'); res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.get('/api/oh-signups', async (req, res) => res.json({ ok: true, list: await kget(OHS_KEY, []) }));
app.post('/api/oh-signup/add', async (req, res) => { try { await addSignup(req.body || {}, 'hq'); res.json({ ok: true }); } catch (e) { res.status(400).json({ error: e.message }); } });
app.post('/api/oh-signup/remove', async (req, res) => { try { const id = String((req.body || {}).id || ''); await kset(OHS_KEY, (await kget(OHS_KEY, [])).filter(x => x.id !== id)); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });
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
const STORE_KEYS = ['content', 'adChecks', 'gamePlan', 'upsellAdds', 'dream', 'ppl', 'slots', 'shots', 'fitTexted'];
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
// B-Stock manifests abbreviate a lot (SEC, SECTNL, 6PC), so match those too.
const PAID = /sectional|sofa|sleeper|loveseat|love seat|couch|sect\b|\bsec\b|sectnl|\bmod\b|modular|\b\d+\s?pc\b/i;
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
    const off = status === 'sold' ? await soldOffWebsite({ kind: 'load', id, uid }, u.soldCustomer) : '';
    res.json({ ok: true, offWebsite: off });
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
      const loads = await getLoads(), ld = loads.find(l => l.id === id), u = (ld || { units: [] }).units.find(x => x.uid === uid);
      if (!u) return res.status(404).json({ error: 'Not found' }); u.name = name; allocate(ld); await kset(KEYS.loads, loads);
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// When a couch is marked sold in the Sales Tracker, take its website listing off too.
// Only the listing linked to that exact unit (no name guessing, so look-alike couches stay up).
const refKey = r => !r ? '' : r.kind === 'load' ? `load:${r.id}:${r.uid}` : r.kind === 'purchase' ? `purchase:${r.id}` : '';
async function soldOffWebsite(ref, who) {
  try {
    const k = refKey(ref); if (!k) return '';
    const list = await getDrops(), d = list.find(x => refKey(x.unitRef) === k && ['live', 'emailed', 'held'].includes(x.status));
    if (!d) return '';
    const now = Date.now(); d.status = 'sold'; d.soldAt = now; d.updatedAt = now; d.soldVia = 'sales tracker'; if (who) d.soldCustomer = who; delete d.heldFrom; delete d.heldRef;
    await setDrops(list); dropsAt = now; recentCache.at = 0; queueSoldStory(d, who); return d.title;
  } catch (e) { console.log('Sold-off-website failed', e.message); return ''; }
}
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
    const off = p.status === 'sold' ? await soldOffWebsite({ kind: 'purchase', id }, p.soldCustomer) : '';
    res.json({ ok: true, offWebsite: off });
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

// Shifts logged on HQ's own work log (hq.billyscouches.com/log). Merged with the old Jotform log below.
const HQLOG_KEY = 'bcd:workLogHQ';
const TEAM = ['Zach', 'Luke', 'Collin', 'Finley', 'Gunnarr', 'Joey'];
async function workLog(force) {
  const jf = await jotformWorkLog(force).catch(e => ({ entries: [], fieldsSeen: {}, error: e.message }));
  const mine = ((await kget(HQLOG_KEY, [])) || []).map(e => ({ id: e.id, date: e.date, name: e.name, hours: e.hours, deep: e.deep, spot: e.spot, sold: e.sold, shows: e.shows, tip: e.tip, pickups: e.pickups, deliveries: e.deliveries, start: e.start, end: e.end, src: 'hq' }));
  const hid = new Set(((await kget('bcd:wlHidden', [])) || []).map(String));
  return { ...jf, entries: (jf.entries || []).filter(e => !hid.has(String(e.id))).concat(mine), error: mine.length && jf.error && /JOTFORM_API_KEY/.test(jf.error) ? undefined : jf.error };
}
async function jotformWorkLog(force) {
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
    const lk = (process.env.TEAM_PAY_KEY || '').trim();
    res.json({ ok: true, ...log, rates: { ...DEFAULT_RATES, ...rates }, adj, paid, goals, logLink: `${PUBLIC_BASE}/log${lk ? '?k=' + encodeURIComponent(lk) : ''}` });
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
    line1: o.booking.address || '', line2: o.booking.address ? `${o.booking.city || ''}, MO ${o.booking.zip || ''}`.replace(/^, /, '') : '',
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
  const hq = [...await schedCards(), ...(await kget('bcd:manualCards', []).catch(() => []))];   // + cards added by hand in HQ
  // "Bought it today" buyers from the new signature form (proxy /sign) give their address there.
  hq.push(...await newSignForm(false).then(cs => cs.map(c => ({ id: 'ns' + c.id, form: 'sign', name: c.name, line1: c.line1, line2: c.line2, type: 'Pick up today', date: c.submitted, submitted: c.submitted }))).catch(() => []));
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
// Read-only check of the Signature & Agreement form: what the latest submissions look like and how they parse.
app.get('/api/thankyou/sigcheck', async (req, res) => {
  try {
    await thankYouForms(); const out = [];
    for (const id of (ty.sigForms || [])) {
      const r = await fetch(`${CFG.JOTFORM_BASE}/form/${id}/submissions?apiKey=${encodeURIComponent(CFG.JOTFORM_KEY)}&limit=6&orderby=created_at`); const j = await r.json();
      const subs = j.content || [], parsed = parseThankYou(subs, id);
      out.push({ id, since: await kget('bcd:tySigSince', null), subs: subs.map((s, i) => ({ created: s.created_at, status: s.status, parsed: { name: parsed[i] && parsed[i].name, line1: parsed[i] && parsed[i].line1, submitted: parsed[i] && parsed[i].submitted, type: parsed[i] && parsed[i].type }, qs: Object.values(s.answers || {}).filter(q => q && q.text && q.answer !== undefined && q.answer !== '').map(q => q.type + ' | ' + q.text) })) });
    }
    const fr = await fetch(`${CFG.JOTFORM_BASE}/user/forms?apiKey=${encodeURIComponent(CFG.JOTFORM_KEY)}&limit=500`); const fj = await fr.json();
    const forms = (fj.content || []).filter(f => f.status !== 'DELETED').sort((a, b) => String(b.last_submission || '').localeCompare(String(a.last_submission || ''))).slice(0, 15).map(f => [f.id, f.title, f.status, f.last_submission, f.count]);
    res.json({ ok: true, out, forms });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// Signed "Signature and Agreement" forms for HQ (top of Thank You Cards). Links cover buyers who signed under another
// name (spouse), on paper, or got a card added by hand.
// The new signature form (proxy /sign) keeps each signed agreement on the proxy; HQ reads them with SIGN_FEED_KEY.
async function newSignForm(all) {
  const key = (process.env.SIGN_FEED_KEY || '').trim(); if (!key) throw new Error('Set SIGN_FEED_KEY in HQ (same value as the proxy) to read the signature form.');
  const r = await fetch(SCHED_PROXY + '/api/sign/cards' + (all ? '?all=1' : ''), { headers: { 'x-sign-key': key }, signal: AbortSignal.timeout(15000) });
  const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error('Signature form: ' + (j.error || r.status));
  return j.cards || [];
}
app.get('/api/signed', async (req, res) => {
  const links = await kget('bcd:sigLinks', {}).catch(() => ({})), formUrl = SCHED_PROXY + '/sign';
  try {
    const signed = (await newSignForm(true)).map(c => ({ id: 'ns' + c.id, form: 'sign', name: c.name || 'Unknown', phone: c.phone || '', line1: c.line1 || '', line2: c.line2 || '',
      type: c.method || '', created: c.submitted || String(c.at || '').slice(0, 10), photo: SCHED_PROXY + '/sign/photo/' + encodeURIComponent(c.id) + '.jpg' }));
    res.json({ ok: true, signed: signed.sort((a, b) => b.created.localeCompare(a.created)), formUrl, links });
  } catch (e) { res.json({ ok: true, signed: [], formUrl, links, error: e.message }); }
});
app.post('/api/signed/link', async (req, res) => {
  try { const k = clean(req.body.key, 120); if (!k) return res.status(400).json({ error: 'key required' });
    const m = await kget('bcd:sigLinks', {}); if (req.body.val) m[k] = clean(req.body.val, 40); else delete m[k];
    await kset('bcd:sigLinks', m); res.json({ ok: true, links: m }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/thankyou/manual', async (req, res) => {
  try {
    const name = clean(req.body.name, 80); if (!name) return res.status(400).json({ error: 'Add a name' });
    const list = await kget('bcd:manualCards', []), date = /^\d{4}-\d{2}-\d{2}$/.test(req.body.date || '') ? req.body.date : new Date().toISOString().slice(0, 10);
    const c = { id: 'm' + crypto.randomBytes(5).toString('hex'), form: 'manual', name, line1: clean(req.body.line1, 120), line2: clean(req.body.line2, 120), type: clean(req.body.type, 30) || 'Pick up', date, submitted: date };
    list.unshift(c); await kset('bcd:manualCards', list.slice(0, 500)); ty.at = 0; res.json({ ok: true, card: c });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
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
// Daily Cash plan: cushion to keep, what a load costs, rent day, and bills/orders already committed (Behold, Peak Living, B-Stock won-not-paid).
const CASH_PLAN_DEFAULT = { cushion: 5000, loadCost: 9500, rentDay: 1, rent: 2700, utilities: null, commitments: [] };
app.get('/api/cash/plan', async (req, res) => res.json({ ok: true, plan: { ...CASH_PLAN_DEFAULT, ...((await kget('bcd:cashPlan', null)) || {}) } }));
app.post('/api/cash/plan', async (req, res) => {
  try {
    const b = req.body || {}, n = (v, d) => { const x = Math.abs(numOf(v)); return isFinite(x) && x > 0 ? Math.round(x * 100) / 100 : d; };
    const plan = { ...CASH_PLAN_DEFAULT, ...((await kget('bcd:cashPlan', null)) || {}) };
    if (b.cushion != null) plan.cushion = n(b.cushion, 0);
    if (b.loadCost != null) plan.loadCost = n(b.loadCost, plan.loadCost);
    if (b.rent != null) plan.rent = n(b.rent, 0);
    if ('utilities' in b) plan.utilities = b.utilities === '' || b.utilities == null ? null : n(b.utilities, 0);
    if (b.rentDay != null) plan.rentDay = Math.min(28, Math.max(1, parseInt(b.rentDay, 10) || 1));
    if (Array.isArray(b.commitments)) plan.commitments = b.commitments.slice(0, 50).map(c => ({
      id: String(c.id || crypto.randomBytes(5).toString('hex')).replace(/[^a-z0-9]/gi, '').slice(0, 16),
      label: clean(c.label, 80) || 'Bill', amount: n(c.amount, 0),
      due: /^\d{4}-\d{2}-\d{2}$/.test(c.due || '') ? c.due : '', paid: !!c.paid })).filter(c => c.amount > 0);
    await kset('bcd:cashPlan', plan); res.json({ ok: true, plan });
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
  PER_BRAND: Number(process.env.RESULTS_PER_BRAND || 20),
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
    if ((!s.lastRun || Date.now() - s.lastRun > 6.5 * 24 * 3600 * 1000) && ctHour() === ADS.HOUR_CT) adsRefresh().catch(e => console.error('Scheduled ads refresh failed:', e.message));
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
  if (j.error_code) throw new Error(`Plaid: ${j.display_message || j.error_message} (${j.error_code}${j.request_id ? ', request_id ' + j.request_id : ''})`);
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
        catch (e) { if (/ITEM_LOGIN_REQUIRED|PENDING_EXPIRATION/.test(e.message)) throw e; liveNote = 'Live balance not available for some banks (' + e.message.slice(0, 160) + '), showing saved balance'; j = await plaid('/accounts/get', { access_token: it.access_token }); } }
      else j = await plaid('/accounts/get', { access_token: it.access_token });
      // When did Plaid last actually hear from this bank? (cached balances can be hours old)
      let itemAsOf = null; try { const ig = await plaid('/item/get', { access_token: it.access_token }); itemAsOf = (ig.status && ig.status.transactions && ig.status.transactions.last_successful_update) || null; } catch {}
      const liveNow = live && !liveNote ? new Date().toISOString() : null;
      const accounts = j.accounts.map(a => {
        const field = MASK_FIELD[a.mask] || MASK_FIELD[String(a.mask || '').slice(-4)] || '';
        const bal = a.balances.current != null ? a.balances.current : a.balances.available;
        const val = Math.round(Math.abs(Number(bal) || 0) * 100) / 100;   // cards: amount owed
        if (field) fields[field] = (fields[field] || 0) + val;
        return { name: a.official_name || a.name, mask: a.mask, type: a.type, subtype: a.subtype, current: a.balances.current, available: a.balances.available, field, asOf: liveNow || a.balances.last_updated_datetime || itemAsOf };
      });
      banks.push({ item_id: it.item_id, institution: it.institution, accounts });
    } catch (e) { banks.push({ item_id: it.item_id, institution: it.institution, error: e.message, relink: /ITEM_LOGIN_REQUIRED|PENDING_EXPIRATION/.test(e.message) }); }
  }
  const asOfs = banks.flatMap(b => (b.accounts || []).filter(a => /^(checking9926|taxReserve7229|ink1602|ink2078|amex91000)$/.test(a.field) && a.asOf).map(a => a.asOf)).sort();
  plaidCache = { at: Date.now(), data: { banks, fields, oldestAsOf: asOfs[0] || null, at: new Date().toISOString(), live: !!live && !liveNote, liveNote, configured: !!(PLAID.ID && PLAID.SECRET), env: PLAID.ENV } };
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
// Business expenses before this date were tracked by hand (IvyFlip + typed in), so bank sync never auto-adds or asks about them.
const BIZ_FROM = (process.env.BIZ_AUTO_FROM || '2026-11-01').trim();
// Matches IRS Schedule C lines so the tax export lines up (Payroll = 1099 contractors, reported as Contract labor in the tax export).
const BIZ_CATS = ['Advertising', 'Payroll', 'Rent', 'Equipment rental', 'Utilities', 'Fuel', 'Truck', 'Insurance', 'Supplies', 'Software', 'Fees', 'Legal & professional', 'Taxes & licenses', 'Interest', 'Repairs', 'Meals', 'Travel', 'Coaching & education', 'Equipment', 'Freight', 'Other'];
const PPL_CATS = { rent: 'Rent', groceries: 'Groceries', eatingOut: 'Eating out', subscriptions: 'Subscriptions', needs: 'Needs', wants: 'Wants', education: 'Education', coachingExp: 'Coaching expense', travel: 'Travel', otherOut: 'Other', otherIn: 'Other income', ownerPay: "Owner's pay", coachIn: 'Coaching income' };
// Built-in guesses (your own "remember this" rules always win).
const BIZ_GUESS = [[/stripe fee|klarna|affirm|square fee|paypal fee|service charge|statement fee|monthly maintenance|overdraft|wire fee/i, 'Fees'], [/dark ?horse|cpa|legalzoom|attorney|law office|bookkeep/i, 'Legal & professional'],
  [/city of pacific|secretary of state|business license|dept of revenue license/i, 'Taxes & licenses'], [/interest charge|purchase interest|finance charge/i, 'Interest'], [/keon|roane|charles chy/i, 'Coaching & education'], [/facebook|facebk|meta ?ads|^fb |fb ads|instagram|google ?ads|tiktok ads|nextdoor/i, 'Advertising'], [/zapier|railway|upstash|jotform|textmagic|squarespace|google ?(workspace|gsuite)|canva|notion|openai|anthropic|claude|stripe fee|apify|ivy ?flip|quickbooks|adobe|capcut/i, 'Software'],
  [/shell|qt |quiktrip|bp |exxon|mobil|phillips 66|casey|speedway|marathon|circle k|\bgas\b|fuel/i, 'Fuel'], [/home depot|lowe|menards|uline|harbor freight|walmart|amazon|scotchgard|ace hardware/i, 'Supplies'],
  [/u-?haul|penske|ryder|tire|jiffy|valvoline|autozone|o.?reilly|advance auto/i, 'Truck'], [/progressive|state farm|geico|insurance|next insurance/i, 'Insurance'], [/ameren|spire|at&t|verizon|t-?mobile|comcast|spectrum|water/i, 'Utilities'],
  [/b-?stock|ch robinson|freight|uship/i, 'Freight'], [/forklift/i, 'Equipment rental']];
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
// One-time (Nov 2026): move saved expenses + vendor rules onto the Schedule C categories.
setTimeout(async () => { try {
  if (await kget('bcd:catMigr1', null)) return;
  const fixCat = (cat, vendor) => { const v = String(vendor || '').toLowerCase();
    if (/forklift america/.test(v)) return 'Equipment rental';
    if (/keon|roane/.test(v)) return 'Coaching & education';
    if (/anthropic|google cloud/.test(v) && cat === 'Other') return 'Software';
    if (/statement fee|deposited cash charges|bundled items charges/.test(v)) return 'Fees';
    if (/sure lock/.test(v) && cat === 'Other') return 'Repairs';
    return cat; };
  const list = await getExpenses(); let n = 0;
  list.forEach(x => { const c = fixCat(x.category, x.vendor); if (c !== x.category) { x.category = c; n++; } });
  await kset(KEYS.expenses, list);
  const r = await txnRules();
  Object.entries(r.vendors).forEach(([k, v]) => { if (v && typeof v === 'object' && v.scope === 'business') v.cat = fixCat(v.cat, k); });
  if (r.vendors['']) delete r.vendors[''];   // blank-name Venmo rule caught every emoji-only note; send those to Review instead
  await kset(TXN.rules, r); await kset('bcd:catMigr1', { at: Date.now(), n });
} catch (e) { console.error('category migration', e.message); } }, 8000);
// v2: Billy prefers the label Payroll (still exported as Schedule C line 11 Contract labor).
setTimeout(async () => { try {
  if (await kget('bcd:catMigr2', null)) return;
  const list = await getExpenses(); list.forEach(x => { if (x.category === 'Contract labor') x.category = 'Payroll'; }); await kset(KEYS.expenses, list);
  const r = await txnRules(); Object.values(r.vendors).forEach(v => { if (v && typeof v === 'object' && v.cat === 'Contract labor') v.cat = 'Payroll'; }); await kset(TXN.rules, r);
  await kset('bcd:catMigr2', { at: Date.now() });
} catch (e) { console.error('category migration v2', e.message); } }, 12000);
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
            if (scope === 'business' && date < BIZ_FROM) { skipped++; continue; }   // already tracked by hand
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
              const cat = rule && rule.scope === 'personal' ? rule.cat : (P2P.test(base.raw) || /^TRANSFER_OUT/.test(base.pfc)) ? '' : ((PPL_GUESS.find(([re]) => re.test(base.name)) || [])[1] || (/GROCERIES/.test(base.pfc) ? 'groceries' : /RENT_AND_UTILITIES_RENT/.test(base.pfc) ? 'rent' : /FOOD_AND_DRINK/.test(base.pfc) ? 'eatingOut' : /^TRAVEL/.test(base.pfc) ? 'travel' : /SUBSCRIPTION|STREAMING/.test(base.pfc) ? 'subscriptions' : /EDUCATION/.test(base.pfc) ? 'education' : /MEDICAL|PERSONAL_CARE|PHARMAC/.test(base.pfc) ? 'needs' : /CLOTHING|ENTERTAINMENT|SPORTING|GIFTS|ELECTRONICS/.test(base.pfc) ? 'wants' : 'otherOut'));
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
// Best guess for anything in Review with no suggestion yet. Your own past choices come first, then patterns.
const TEAM_RX = new RegExp(process.env.TEAM_NAMES || 'zach pierce|luke peters|finley lotzin|joey menendez|collin comer|kelly nelson|gunnarr|gunnar', 'i');
function txnGuess(t, H) {
  const txt = `${t.name || ''} ${t.raw || ''}`, low = txt.toLowerCase(), amt = Number(t.amount) || 0, inn = amt < 0, venmo = /venmo/i.test(t.institution || '');
  const G = (scope, cat, why) => ({ scope, cat: cat || '', why });
  // Moves of money that aren't income or spending.
  if (/standard transfer|instant transfer/i.test(txt) && venmo) return G('ignore', '', 'Venmo cash-out to your bank');
  if (/thank you|epay|e-?payment|credit cr?d|autopay|card payment/i.test(txt)) return G('ignore', '', 'Credit card payment');
  if (/stripe/i.test(txt) && inn) return G('ignore', '', 'Stripe payout (sales are already counted)');
  if (/transfer to other|transfer from other|online transfer|internet transfer to/i.test(txt)) return G('ignore', '', 'Move between your accounts');
  if (/transfer from commerce|transfer from .*dda/i.test(txt) && inn) {
    const BIZ_ACCTS = (process.env.BIZ_ACCOUNTS || '9926').split(',').map(x => x.trim()).filter(Boolean);
    return BIZ_ACCTS.some(m => txt.includes(m)) ? G('personal', 'ownerPay', 'Business account → you') : G('ignore', '', 'Move between your personal accounts'); }
  if (/department of revenue|mo rev tax/i.test(txt)) return G('ignore', '', 'Sales tax payment (set-aside money)');
  if (/internal revenue|irs usataxpymt|usataxpymt/i.test(txt)) return G('personal', 'otherOut', 'IRS tax payment');
  if (/bstkmp|b-?stock/i.test(txt)) return G('ignore', '', 'B-Stock load (cost is on the load)');
  if (inn && (/zelle payment received|deposit|couch|billyscouches|sectional|sofa|delivery|🛋/i.test(txt) || venmo)) return G('ignore', '', 'Customer payment (sale already counted)');
  // Team pay through Venmo/Zelle: Payroll, unless it's already on the tracker.
  if (!inn && TEAM_RX.test(low)) {
    return G('ignore', '', 'Team pay (already logged on the Payroll tab)');
  }
  if (/keon|roane/i.test(low)) return G('business', 'Advertising', 'Facebook ads coaching');
  if (/statement fee|bundled items|deposited cash charges|service charge|overdraft|wire fee/i.test(txt)) return G('business', 'Other', 'Bank fee');
  // Your own past choices for this vendor.
  const k = vkey({ name: t.raw || t.name, merchant_name: t.name }), h = H.byKey[k];
  if (h) return G(h.scope, h.cat, 'Same as last time');
  if (/hueffmeier|trucking/i.test(txt)) return G('business', 'Freight', 'Trucking');
  if (/vistaprint|sign exp|signs?\b/i.test(txt)) return G('business', 'Advertising', 'Print / signs');
  if (/shopify|puredocs/i.test(txt)) return G('business', 'Software', 'Software');
  if (/fastlane|car wash/i.test(txt)) return G('business', 'Truck', 'Truck wash');
  if (/lock ?& ?key|locksmith/i.test(txt)) return G('business', 'Supplies', 'Locks / keys');
  if (/costco|michaels|dollar tree|home depot|lowe|menards/i.test(txt) && t.scope !== 'personal') return G('business', 'Supplies', 'Supplies');
  if (t.scope === 'business' || !t.scope) { const b = BIZ_GUESS.find(([rx]) => rx.test(txt)); if (b) return G('business', b[1], 'Looks like ' + b[1].toLowerCase()); }
  const p = PPL_GUESS.find(([rx]) => rx.test(txt)); if (p) return G('personal', p[1], 'Looks like ' + (PPL_CATS[p[1]] || p[1]).toLowerCase());
  if (/bud'?s market/i.test(txt)) return G('personal', 'groceries', 'Grocery store');
  const pfc = t.pfc || '';
  if (/GROCERIES/.test(pfc)) return G('personal', 'groceries', 'Grocery store');
  if (/RESTAURANT|FAST_FOOD|COFFEE/.test(pfc)) return G('personal', 'eatingOut', 'Restaurant');
  if (/RENT_AND_UTILITIES_RENT/.test(pfc)) return G('personal', 'rent', 'Rent');
  if (/^TRAVEL/.test(pfc)) return G('personal', 'travel', 'Travel');
  if (/GAS/.test(pfc)) return G('business', 'Fuel', 'Gas');
  return null;
}
async function txnHistory() {
  const [exp, ppl] = await Promise.all([kget(KEYS.expenses, []), kget(TXN.ppl, [])]), byKey = {}, cnt = {};
  const add = (name, scope, cat) => { const k = vkey({ name, merchant_name: name }); if (!k) return; const id = scope + '|' + cat; cnt[k] = cnt[k] || {}; cnt[k][id] = (cnt[k][id] || 0) + 1; };
  (exp || []).filter(x => x.auto && x.vendor).forEach(x => add(x.vendor, 'business', x.category));
  (ppl || []).filter(x => x.name).forEach(x => add(x.name, 'personal', x.cat));
  Object.keys(cnt).forEach(k => { const [id] = Object.entries(cnt[k]).sort((a, b) => b[1] - a[1])[0]; const [scope, cat] = id.split('|'); byKey[k] = { scope, cat }; });
  return { byKey, exp: exp || [] };
}
app.get('/api/txn', async (req, res) => {
  try { if (req.query.sync === '1') await txnSync(); else txnMaybeSync().catch(() => {});
    const [inbox, accounts, rules, meta, ppl] = await Promise.all([kget(TXN.inbox, []), txnAccounts(), txnRules(), kget(TXN.meta, null), kget(TXN.ppl, [])]);
    { const keep = (inbox || []).filter(t => !(t.scope === 'business' && t.date < BIZ_FROM)); if (keep.length !== (inbox || []).length) { inbox.length = 0; inbox.push(...keep); await kset(TXN.inbox, keep); } }
    const oldAuto = ((await kget(KEYS.expenses, [])) || []).filter(x => x.auto && String(x.id).startsWith('tx_') && String(x.date) < BIZ_FROM);
    const H = await txnHistory(); (inbox || []).forEach(t => { if (!t.suggest) { const g = txnGuess(t, H); if (g) t.guess = g; } });
    res.json({ ok: true, bizFrom: BIZ_FROM, oldAuto: { n: oldAuto.length, total: Math.round(oldAuto.reduce((t, x) => t + (Number(x.amount) || 0), 0) * 100) / 100 }, inbox: inbox || [], accounts, vendors: rules.vendors, meta: meta || {}, ppl: ppl || [], bizCats: BIZ_CATS, pplCats: PPL_CATS, configured: !!(PLAID.ID && PLAID.SECRET) }); }
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
    const todo = Array.isArray(req.body.items) ? req.body.items.slice(0, 300) : req.body.all ? inbox.filter(t => t.scope && !t.note && (t.suggest || t.scope === 'personal')).map(t => ({ id: t.id, scope: t.scope, cat: t.suggest || (t.scope === 'personal' ? 'otherOut' : ''), remember: false })) : [req.body];
    let done = 0; const ign = (await kget(TXN.ignored, [])) || []; const amzN = (await kget(AMZ.notes, {})) || {};
    for (const q of todo) {
      const i = inbox.findIndex(t => t.id === q.id); if (i < 0) continue; const t = inbox[i], scope = q.scope; const note = (String(q.note || '').replace(/\s+/g, ' ').trim() || amzN[t.id] || '').slice(0, 120);
      if (scope === 'business' && t.date < BIZ_FROM) { inbox.splice(i, 1); done++; continue; }   // before HQ tracked expenses: already on the tracker by hand
      if (scope === 'business') { const cat = BIZ_CATS.includes(q.cat) ? q.cat : ''; if (!cat) continue;
        exp.push({ id: 'tx_' + t.id, date: t.date, category: cat, amount: t.amount, vendor: t.name, notes: `${note ? note + ' · ' : ''}Auto · ${t.institution}${t.mask ? ' ••' + t.mask : ''}`, auto: true });
        if (q.remember) r.vendors[t.key] = { scope, cat }; }
      else if (scope === 'personal') { const cat = PPL_CATS[q.cat] ? q.cat : 'otherOut'; ppl.push({ id: t.id, date: t.date, amount: t.amount, name: t.name, cat, ...(note ? { note } : {}) });
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
    await amzApply().catch(() => {}); const amzNotes = (await kget(AMZ.notes, {})) || {};
    const [all, exp, ppl, inbox, ign, rules] = await Promise.all([kget(TXN.all, {}), kget(KEYS.expenses, []), kget(TXN.ppl, []), kget(TXN.inbox, []), kget(TXN.ignored, []), txnRules()]);
    const e = new Map((exp || []).filter(x => x.auto).map(x => [String(x.id).replace(/^tx_/, ''), x])), p = new Map((ppl || []).map(x => [x.id, x])), q = new Set((inbox || []).map(x => x.id)), g = new Set(ign || []);
    const month = (req.query.month || new Date().toLocaleDateString('en-CA', { timeZone: 'America/Chicago' }).slice(0, 7));
    const list = Object.values(all || {}).filter(t => t.date.startsWith(month)).map(t => {
      const x = e.get(t.id), y = p.get(t.id);
      const status = t.dupe ? 'Already on tracker' : x ? 'Business: ' + x.category : y ? 'Personal: ' + (PPL_CATS[y.cat] || y.cat) : q.has(t.id) ? 'In Review' : g.has(t.id) ? 'Ignored' : rules.vendors[vkey({ name: t.raw, merchant_name: t.name })] === 'ignore' ? 'Ignored by rule' : 'Not sorted';
      const note = (y && y.note) || (x && x.notes && x.notes.includes(' · Auto') ? x.notes.split(' · Auto')[0] : '') || amzNotes[t.id] || '';
      return { ...t, status, note, canRedo: !x && !y && !q.has(t.id) };
    }).sort((a, b) => b.date.localeCompare(a.date) || b.amount - a.amount);
    res.json({ ok: true, list });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// Re-sort an ignored transaction straight into personal or business (and drop an "ignore" vendor rule so the next one shows up in Review).
app.post('/api/txn/unignore', async (req, res) => {
  try {
    const { id, scope, cat } = req.body || {};
    const [all, ign, rules, exp, ppl] = await Promise.all([kget(TXN.all, {}), kget(TXN.ignored, []), txnRules(), kget(KEYS.expenses, []), kget(TXN.ppl, [])]);
    const t = (all || {})[id]; if (!t) return res.status(404).json({ error: 'not found' });
    if (scope === 'business') { if (!BIZ_CATS.includes(cat)) return res.status(400).json({ error: 'bad category' });
      if (!exp.some(e => e.id === 'tx_' + id)) exp.push({ id: 'tx_' + id, date: t.date, category: cat, amount: t.amount, vendor: t.name, notes: `Auto · ${t.institution || ''}${t.mask ? ' ••' + t.mask : ''}`, auto: true }); }
    else if (scope === 'personal') { if (!PPL_CATS[cat]) return res.status(400).json({ error: 'bad category' });
      if (!ppl.some(p => p.id === id)) ppl.push({ id, date: t.date, amount: t.amount, name: t.name, cat }); }
    else return res.status(400).json({ error: 'bad scope' });
    const key = vkey({ name: t.raw || t.name, merchant_name: t.name }); if (rules.vendors[key] === 'ignore') delete rules.vendors[key];
    await Promise.all([kset(TXN.ignored, (ign || []).filter(x => x !== id)), kset(TXN.rules, rules), kset(KEYS.expenses, exp), kset(TXN.ppl, ppl)]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// Remove bank-synced business expenses dated before BIZ_FROM (those months were already tracked by hand).
app.post('/api/txn/cleanup-old', async (req, res) => {
  try {
    const exp = (await kget(KEYS.expenses, [])) || [], old = x => x.auto && String(x.id).startsWith('tx_') && String(x.date) < BIZ_FROM;
    const gone = exp.filter(old), keep = exp.filter(x => !old(x));
    await kset(KEYS.expenses, keep); res.json({ ok: true, removed: gone.length, total: Math.round(gone.reduce((t, x) => t + (Number(x.amount) || 0), 0) * 100) / 100 });
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
    if (req.body.note !== undefined) { const n = String(req.body.note || '').replace(/\s+/g, ' ').trim().slice(0, 120); if (n) x.note = n; else delete x.note; }
    const cat = String(req.body.cat || '');
    if (cat.startsWith('biz:')) {
      // Move a personal charge over to the business side (and remember the vendor for next time).
      const bc = cat.slice(4); if (!BIZ_CATS.includes(bc)) return res.status(400).json({ error: 'bad category' });
      const [exp, all, r] = await Promise.all([kget(KEYS.expenses, []), kget(TXN.all, {}), txnRules()]);
      if (!exp.some(e => e.id === 'tx_' + x.id)) exp.push({ id: 'tx_' + x.id, date: x.date, category: bc, amount: x.amount, vendor: x.name, notes: `${x.note ? x.note + ' · ' : ''}Auto · moved from personal`, auto: true });
      const raw = all && all[x.id]; const key = vkey({ name: (raw && raw.raw) || x.name, merchant_name: x.name }); if (key) r.vendors[key] = { scope: 'business', cat: bc };
      l = l.filter(t => t.id !== x.id);
      await Promise.all([kset(KEYS.expenses, exp), kset(TXN.rules, r)]);
    }
    else if (cat === 'remove') l = l.filter(t => t.id !== x.id); else if (PPL_CATS[cat]) x.cat = cat;
    await kset(TXN.ppl, l); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
// ---------- Amazon item notes ----------
// A Google Apps Script in Billy's Gmail posts each Amazon order email here. HQ pulls the order total + a 1-3 word
// item name, matches it to the Amazon card charge (same amount, within ~10 days) and fills that transaction's note
// (never overwrites a note Billy typed). Get the script at /api/amazon/script.
const AMZ = { key: 'bcd:amzKey', orders: 'bcd:amzOrders', notes: 'bcd:amzNotes' };
async function amzKey() { let k = await kget(AMZ.key, ''); if (!k) { k = crypto.randomBytes(18).toString('hex'); await kset(AMZ.key, k); } return k; }
const isAmazon = t => /amazon|amzn/i.test((t.name || '') + ' ' + (t.raw || ''));
function amzShortGuess(title) {
  const stop = /^(the|a|an|for|with|and|of|by|pack|set|new|amazon|basics|premium|upgraded|\d+(pcs|pack|ct|count|oz|ft|in)?)$/i;
  return String(title || '').replace(/["“”]/g, '').replace(/(\s[-–—]\s|[,(|:]).*$/, '').split(/\s+/).filter(w => w && !stop.test(w) && !/\d/.test(w)).slice(-3).join(' ');
}
async function amzRead(subject, body) {
  const out = { orderId: (String(body).match(/\b\d{3}-\d{7}-\d{7}\b/) || [])[0] || '', total: 0, short: '' };
  const tot = String(body).match(/(?:Order Total|Grand Total|Total)[^$\d]{0,30}\$\s?([\d,]+\.\d{2})/i); if (tot) out.total = Number(tot[1].replace(/,/g, ''));
  const subj = String(subject).match(/Ordered:\s*["“]?(.+?)["”]?(?:\s+and \d+ more items?)?$/i); out.short = amzShortGuess(subj ? subj[1] : '');
  try {
    const model = (await dimsModels())[0]; if (!model) return out;
    const j = await geminiQuick(model, [{ text: 'Amazon order email. Return JSON {"orderId": string, "total": number (order grand total charged, with tax, USD), "short": string (what was bought, 1-3 plain words like "Christmas Tree" or "Phone Charger"; if several items, name the main one)}.\nSubject: ' + subject + '\n\n' + String(body).slice(0, 6000) }]);
    const t = (((j.candidates || [])[0] || {}).content || { parts: [] }).parts.map(x => x.text || '').join('');
    const a = JSON.parse(t.replace(/^```(json)?|```$/g, '').trim());
    if (a.orderId) out.orderId = String(a.orderId).slice(0, 40); if (Number(a.total) > 0) out.total = Math.round(Number(a.total) * 100) / 100;
    if (a.short) out.short = String(a.short).replace(/\s+/g, ' ').trim().split(' ').slice(0, 3).join(' ').slice(0, 40);
  } catch (e) { console.log('Amazon read (AI) failed, using basic read:', e.message); }
  return out;
}
// Match unmatched orders to Amazon charges and fill notes that are still empty.
async function amzApply() {
  const [orders, all, notes, ppl, exp] = await Promise.all([kget(AMZ.orders, []), kget(TXN.all, {}), kget(AMZ.notes, {}), kget(TXN.ppl, []), kget(KEYS.expenses, [])]);
  const used = new Set(Object.keys(notes || {})), tx = Object.values(all || {}).filter(isAmazon); let hit = 0, pplCh = false, expCh = false;
  for (const o of orders || []) {
    if (o.txId || !o.total || !o.short) continue;
    const od = Date.parse(o.date || '') || 0;
    const c = tx.filter(t => !used.has(t.id) && Math.abs(Math.abs(t.amount) - o.total) <= 0.02 && od && (Date.parse(t.date) - od) / 864e5 >= -2 && (Date.parse(t.date) - od) / 864e5 <= 10)
      .sort((a, b) => Math.abs(Date.parse(a.date) - od) - Math.abs(Date.parse(b.date) - od))[0];
    if (!c) continue;
    o.txId = c.id; used.add(c.id); notes[c.id] = o.short; hit++;
    const p = (ppl || []).find(x => x.id === c.id); if (p && !p.note) { p.note = o.short; pplCh = true; }
    const e = (exp || []).find(x => x.id === 'tx_' + c.id); if (e && /^Auto ·/.test(e.notes || '')) { e.notes = o.short + ' · ' + e.notes; expCh = true; }
  }
  if (hit) await Promise.all([kset(AMZ.orders, orders), kset(AMZ.notes, notes), pplCh ? kset(TXN.ppl, ppl) : 0, expCh ? kset(KEYS.expenses, exp) : 0]);
  return hit;
}
app.post('/public/amazon-order', async (req, res) => {
  try {
    const b = req.body || {}; if (!b.key || b.key !== await amzKey()) return res.status(403).json({ error: 'bad key' });
    const orders = (await kget(AMZ.orders, [])) || [], mid = clean(b.id, 80);
    if (orders.some(o => o.mid === mid)) return res.json({ ok: true, duplicate: true });
    const r = await amzRead(clean(b.subject, 300), clean(b.body, 8000));
    if (r.orderId && orders.some(o => o.orderId === r.orderId)) return res.json({ ok: true, duplicate: true });
    orders.unshift({ mid, orderId: r.orderId, date: clean(b.date, 40), total: r.total, short: r.short, at: Date.now() });
    await kset(AMZ.orders, orders.slice(0, 1500)); const hit = await amzApply().catch(() => 0);
    res.json({ ok: true, total: r.total, short: r.short, matched: hit > 0 });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/amazon/orders', async (req, res) => { try { await amzApply(); res.json({ ok: true, orders: ((await kget(AMZ.orders, [])) || []).slice(0, 100) }); } catch (e) { res.status(500).json({ error: e.message }); } });
// The Gmail script, with this HQ's key baked in. Open while logged in, copy everything, paste into script.google.com.
app.get('/api/amazon/script', async (req, res) => {
  const k = await amzKey();
  res.type('text/plain').send(`// Billy's HQ: sends Amazon order emails to HQ so each Amazon charge gets a short item note.
// Setup: script.google.com > New project > paste this > Save > pick "setup" in the top bar > Run > Allow.
const HQ = '${PUBLIC_BASE}/public/amazon-order';
const KEY = '${k}';
function setup() {
  ScriptApp.getProjectTriggers().forEach(t => ScriptApp.deleteTrigger(t));
  ScriptApp.newTrigger('sendAmazonOrders').timeBased().everyHours(1).create();
  sendAmazonOrders();
}
function sendAmazonOrders() {
  const label = GmailApp.getUserLabelByName('HQ-amazon') || GmailApp.createLabel('HQ-amazon');
  const threads = GmailApp.search('from:(auto-confirm@amazon.com) -label:HQ-amazon newer_than:45d', 0, 50);
  threads.forEach(th => {
    let ok = true;
    th.getMessages().forEach(m => {
      const r = UrlFetchApp.fetch(HQ, { method: 'post', contentType: 'application/json', muteHttpExceptions: true,
        payload: JSON.stringify({ key: KEY, id: m.getId(), date: m.getDate().toISOString(), subject: m.getSubject(), body: m.getPlainBody().slice(0, 8000) }) });
      if (r.getResponseCode() !== 200) ok = false;
    });
    if (ok) th.addLabel(label);
  });
}
`);
});
// ===================== END AUTO EXPENSES =====================

// Every morning at 7am Central: if no entry exists for today, save one from the banks
// (safe, Venmo, stocks and rent carry over from your last entry; Stripe is pulled live).
async function bankSnapshot(live) {
  const items = await getPlaidItems();
  if (!items.length) return null;
  const today = new Date().toLocaleDateString('en-CA', { timeZone: 'America/Chicago' });
  const snaps = await getCash();
  if (!live && snaps.some(s => s.date === today)) return null;
  const pb = await plaidBalances(true, !!live), last = snaps[snaps.length - 1] || {};
  if (!Object.keys(pb.fields).length) return null;
  // Today's entry keeps what you typed (safe, Venmo); banks + Stripe get the newest numbers.
  const snap = { ...last, date: today, savedAt: new Date().toISOString(), note: last.date === today ? (last.note || '') : 'Auto from banks', auto: true, score: undefined, imported: undefined };
  Object.assign(snap, pb.fields); snap.bankAsOf = pb.oldestAsOf || null;
  const sb = await stripeBalance(true).catch(() => ({}));
  if (!sb.error) { snap.stripe = sb.total || 0; snap.stripeAuto = true; }
  await kset(KEYS.cash, snaps.filter(s => s.date !== today).concat(snap).sort((a, b) => a.date.localeCompare(b.date)));
  return snap;
}
const autoCashSnapshot = () => bankSnapshot(false);
// Buying Power tab: "Refresh from banks" pulls live balances into today's entry.
app.post('/api/cash/refresh', async (req, res) => {
  try { const snap = await bankSnapshot(true); if (!snap) return res.status(400).json({ error: 'No linked banks returned balances. Check Bank connections below.' }); res.json({ ok: true, snap }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
// Buying Power tab: type the safe or Venmo right on the page. Updates today's entry (made from the last one if needed).
app.post('/api/cash/quick', async (req, res) => {
  try {
    const b = req.body || {}, today = new Date().toLocaleDateString('en-CA', { timeZone: 'America/Chicago' });
    const snaps = await getCash(), last = snaps[snaps.length - 1] || {};
    const snap = last.date === today ? { ...last } : { ...last, date: today, note: '', auto: false, score: undefined, imported: undefined };
    ['safe', 'venmo'].forEach(k => { if (b[k] != null && b[k] !== '') snap[k] = Math.round(Math.abs(numOf(b[k])) * 100) / 100; });
    snap.savedAt = new Date().toISOString();
    await kset(KEYS.cash, snaps.filter(s => s.date !== today).concat(snap).sort((a, b) => a.date.localeCompare(b.date)));
    res.json({ ok: true, snap });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
setInterval(() => { if (ctHour() === 7) autoCashSnapshot().catch(e => console.error('Auto cash failed:', e.message)); }, 15 * 60 * 1000);


// ---------- Cash for Your Couch (public form on billyscouches.com) ----------
const OFFER_ORIGINS = ['http://127.0.0.1:5000', 'https://www.billyscouches.com', 'https://billyscouches.com'];
const offerHits = new Map();
const escH = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
function offerCors(req, res) {
  const o = req.headers.origin || '';
  if (OFFER_ORIGINS.includes(o) || /\.squarespace\.com$/.test(o)) { res.setHeader('Access-Control-Allow-Origin', o); res.setHeader('Vary', 'Origin'); }
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}
// ===================== PHONE PUSH NOTIFICATIONS =====================
// Works on iPhone (iOS 16.4+, HQ added to the Home Screen) and Android/desktop Chrome. Keys are made once
// and saved, so there's nothing to set up in Railway. PUSH=off turns every notification off.
let webpush = null; try { webpush = require('web-push'); } catch (e) { console.log('web-push not installed; phone notifications off'); }
const PUSH_KEY = 'bcd:push', PUSH_ON = (process.env.PUSH || 'on').toLowerCase() !== 'off';
let vapidP = null;
function vapid() {
  if (!webpush) return Promise.resolve(null);
  if (!vapidP) vapidP = (async () => {
    let v = await kget('bcd:vapid', null);
    if (!v || !v.publicKey) { v = webpush.generateVAPIDKeys(); await kset('bcd:vapid', v); }
    webpush.setVapidDetails('mailto:' + (process.env.PUSH_EMAIL || 'info@billyscouches.com'), v.publicKey, v.privateKey);
    return v;
  })().catch(e => { vapidP = null; throw e; });
  return vapidP;
}
async function pushAll(title, body, url, tag) {
  if (!PUSH_ON || !webpush) return 0;
  await vapid(); const subs = (await kget(PUSH_KEY, [])) || []; if (!subs.length) return 0;
  const payload = JSON.stringify({ title, body, url: url || '/', tag }); let sent = 0; const keep = [];
  for (const s of subs) {
    try { await webpush.sendNotification(s.sub, payload, { TTL: 86400 }); sent++; keep.push(s); }
    catch (e) { if (e.statusCode === 404 || e.statusCode === 410) console.log('Dropped expired phone subscription'); else { keep.push(s); console.log('Push failed', e.statusCode || e.message); } }
  }
  if (keep.length !== subs.length) await kset(PUSH_KEY, keep);
  return sent;
}
app.get('/api/push/key', async (req, res) => {
  try { const v = await vapid(); res.json({ ok: !!v, key: v ? v.publicKey : null, count: ((await kget(PUSH_KEY, [])) || []).length }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/push/subscribe', async (req, res) => {
  try {
    const sub = req.body && req.body.sub; if (!sub || !sub.endpoint || !/^https:\/\//.test(sub.endpoint)) return res.status(400).json({ error: 'bad subscription' });
    const subs = ((await kget(PUSH_KEY, [])) || []).filter(s => s.sub.endpoint !== sub.endpoint);
    subs.push({ sub, device: String(req.body.device || '').slice(0, 80), at: Date.now() }); await kset(PUSH_KEY, subs.slice(-10));
    res.json({ ok: true, count: subs.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/push/test', async (req, res) => {
  try { const n = await pushAll("Billy's HQ", 'Notifications are working ✅', '/', 'test'); res.json({ ok: true, sent: n }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/goals/snap', async (req, res) => {
  try { const b = req.body || {}; if (!/^\d{4}-\d{2}$/.test(b.month || '')) return res.status(400).json({ error: 'bad month' });
    await kset('bcd:goalSnap', { month: b.month, day: +b.day, days: +b.days, sales: b.sales, revenue: b.revenue, net: b.net, at: Date.now() }); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
// Goals nudge: every other day at 10am (from day 4 of the month) when you're behind pace on flips or revenue.
async function goalNudge(today, sent) {
  const g = await kget('bcd:goalSnap', null); if (!g || today.slice(0, 7) !== g.month || Date.now() - g.at > 2 * 864e5) return;
  const day = +today.slice(8, 10), days = g.days || 30; if (day < 4 || day >= days) return;
  if (sent.goal && (Date.parse(today) - Date.parse(sent.goal)) < 2 * 864e5) return;
  const lines = [], left = days - day + 1, S = g.sales || {}, R = g.revenue || {};
  if (S.t) { const should = S.t * (day - 1) / days, gap = Math.floor(should - S.a); if (gap >= 1) lines.push(`${gap} flip${gap === 1 ? '' : 's'} behind (${Math.round(S.a)} of ${S.t}). Need ${((S.t - S.a) / left).toFixed(1)}/day the rest of the month.`); }
  if (R.t) { const should = R.t * (day - 1) / days, gap = should - R.a; if (gap >= R.t * 0.05) lines.push(`$${Math.round(gap).toLocaleString('en-US')} behind on revenue ($${Math.round(R.a).toLocaleString('en-US')} of $${Math.round(R.t).toLocaleString('en-US')}).`); }
  if (!lines.length) return;
  await pushAll("You're behind this month", lines.join(' ') + ' Lock in.', '/?tab=goals', 'goals');
  sent.goal = today;
}
// Hourly checks (each once a day): 5+ thank-you cards waiting, 10+ transactions waiting in Review, price cuts / pulls due (9am).
async function pushChecks() {
  if (!PUSH_ON || !webpush || !((await kget(PUSH_KEY, [])) || []).length) return;
  const today = new Date().toLocaleDateString('en-CA', { timeZone: 'America/Chicago' }), hour = ctHour(), sent = (await kget('bcd:pushSent', {})) || {};
  if (hour >= 9 && hour <= 20 && sent.ty !== today) {
    try { const d = await thankYouList(false), w = (await kget('bcd:thankyou', {})) || {}, n = d.cards.filter(c => !w[c.id]).length;
      if (n >= 5) { await pushAll('Thank you cards', `${n} cards waiting to be written.`, '/?tab=thanks', 'thanks'); sent.ty = today; } } catch (e) {}
  }
  if (hour >= 9 && hour <= 20 && sent.tx !== today) {
    try { const inbox = (await kget(TXN.inbox, [])) || [], n = inbox.length;
      if (n >= 10) { const biz = inbox.filter(t => t.scope === 'business').length; await pushAll('Expenses to review', `${n} transactions waiting in Review${biz && biz < n ? ` (${biz} business, ${n - biz} personal)` : ''}.`, biz >= n - biz ? '/?tab=sales' : '/?tab=ppl', 'expenses'); sent.tx = today; } } catch (e) {}
  }
  if (hour >= 9 && sent.pc !== today) {
    const drops = await getDrops(), now = Date.now(); let due = 0, pull = 0;
    drops.filter(d => d.status === 'live').forEach(d => { const days = Math.floor((now - (d.listedAt || d.liveAt || d.createdAt || now)) / 864e5), done = Math.max(0, ...(d.cuts || []).map(c => c.step));
      if (days >= 56) pull++; else { const step = days >= 42 ? 3 : days >= 28 ? 2 : days >= 14 ? 1 : 0; if (step > done) due++; } });
    if (due || pull) await pushAll('Price cuts', [due ? `${due} price cut${due === 1 ? '' : 's'} due` : '', pull ? `${pull} couch${pull === 1 ? '' : 'es'} past day 56 to pull` : ''].filter(Boolean).join(' · '), '/?tab=cuts', 'cuts');
    sent.pc = today;
  }
  // Any single business charge of $500+ (once per charge, last 3 days only).
  try {
    const BIG = Number(process.env.PUSH_BIG || 500), all = (await kget(TXN.all, {})) || {}, seen = new Set((await kget('bcd:pushBig', [])) || []);
    const accs = await txnAccounts(), scope = new Map(accs.map(a => [`${a.item_id}:${a.mask}`, a.scope])), since = new Date(Date.now() - 3 * 864e5).toISOString().slice(0, 10);
    const big = Object.values(all).filter(t => t.amount >= BIG && t.date >= since && !seen.has(t.id) && scope.get(`${t.item}:${t.mask}`) === 'business' && !/TRANSFER|LOAN_PAYMENTS/i.test(t.pfc || '') && !P2P.test((t.raw || '') + ' ' + (t.name || '')));
    for (const t of big) { await pushAll('Big business charge', `$${t.amount.toLocaleString('en-US', { minimumFractionDigits: 2 })} · ${t.name} · ${t.institution || ''}${t.mask ? ' ••' + t.mask : ''}`, '/?tab=sales', 'big-' + t.id); seen.add(t.id); }
    if (big.length) await kset('bcd:pushBig', [...seen].slice(-500));
  } catch (e) { console.log('Big charge check failed', e.message); }
  if (hour >= 10 && hour <= 20) { try { await goalNudge(today, sent); } catch (e) { console.log('Goal nudge failed', e.message); } }
  await kset('bcd:pushSent', sent);
}
setInterval(() => pushChecks().catch(e => console.log('Push checks failed', e.message)), 60 * 60 * 1000);
setTimeout(() => pushChecks().catch(() => {}), 60 * 1000);
// ===================== END PHONE PUSH =====================
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
    pushAll('New couch offer', `${offer.brand} · asking ${offer.asking || '?'} · ${first} ${last}${offer.city ? ' · ' + offer.city : ''}`, '/?tab=offers', 'offer-' + id).catch(() => {});
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
// ===================== FIRST DIBS UNSUBSCRIBE =====================
// Link at the bottom of every First Dibs email. They type their email, HQ takes them off every First Dibs list in
// TextMagic, keeps a record (bcd:unsubs) and texts Billy.
const UNSUB_KEY = 'bcd:unsubs';
app.get('/public/unsubscribe', (req, res) => {
  res.set('X-Frame-Options', 'DENY').type('html').send(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Unsubscribe | Billy's Couches</title>
<style>body{margin:0;background:#f6f2ed;font-family:Helvetica,Arial,sans-serif;color:#2b1d16}.c{max-width:420px;margin:60px auto;background:#fff;border-radius:14px;padding:26px 22px;text-align:center}
h1{font-size:22px;margin:0 0 8px}p{color:#5a524b;font-size:15px;line-height:22px;margin:0 0 16px}input{width:100%;box-sizing:border-box;padding:13px;border:1px solid #d9d0c6;border-radius:10px;font-size:16px;margin-bottom:12px}
button{width:100%;background:#b0524c;color:#fff;border:0;border-radius:99px;padding:13px;font-size:16px;font-weight:bold;cursor:pointer}</style></head><body><div class="c" id="c">
<h1>Unsubscribe from First Dibs</h1><p>Enter your email and you won't get any more couch drop emails.</p>
<form id="f"><input type="email" id="e" placeholder="you@email.com" required autocomplete="email"><button>Unsubscribe</button></form></div>
<script>document.getElementById('f').onsubmit=async function(ev){ev.preventDefault();var b=this.querySelector('button');b.disabled=true;b.textContent='One sec...';
try{var r=await fetch('/public/unsubscribe',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:document.getElementById('e').value})});if(!r.ok)throw 0;
document.getElementById('c').innerHTML='<h1>You\'re unsubscribed</h1><p>You won\'t get First Dibs emails anymore. Changed your mind? Sign up again anytime at billyscouches.com.</p>';}
catch(e){b.disabled=false;b.textContent='Unsubscribe';alert('Something went wrong. Text us at (314) 899-7503 and we\'ll remove you.');}};</script></body></html>`);
});
const unsubHits = new Map();
app.post('/public/unsubscribe', async (req, res) => {
  const email = String((req.body && req.body.email) || '').trim().toLowerCase().slice(0, 120);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email' });
  const ip = String(req.headers['x-forwarded-for'] || req.ip || '').split(',')[0], n = (unsubHits.get(ip) || 0) + 1; unsubHits.set(ip, n);
  if (n > 20) return res.status(429).json({ error: 'Too many tries' });
  let removed = 0, note = '';
  try {
    const f = await tmApi('GET', `/api/v2/contacts/search?query=${encodeURIComponent(email)}&limit=20`);
    const ids = ((f.j && f.j.resources) || []).filter(c => String(c.email || '').toLowerCase() === email).map(c => c.id);
    for (const id of ids) {
      const l = await tmApi('GET', `/api/v2/contacts/${id}/lists?limit=100`);
      for (const list of ((l.j && l.j.resources) || []).filter(x => /first\s*dibs/i.test(x.name || ''))) {
        const d = await tmApi('DELETE', `/api/v2/lists/${list.id}/contacts`, { contacts: String(id) }); if (d.ok) removed++;
      }
    }
    if (!ids.length) note = 'not found in TextMagic';
  } catch (e) { note = 'TextMagic error: ' + e.message; }
  try { const list = await kget(UNSUB_KEY, []); list.push({ email, at: Date.now(), removed, note }); await kset(UNSUB_KEY, list.slice(-1000)); } catch (e) {}
  textAlert(`First Dibs unsubscribe: ${email}. ${removed ? 'Removed from ' + removed + ' list(s) in TextMagic.' : 'Remove them in TextMagic by hand (' + (note || 'no First Dibs list found') + ').'}`).catch(() => {});
  res.json({ ok: true });
});
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
  const C = { date: col(['date']), name: col(['customer', 'name'], ['first']), price: col(['couch price', 'price'], ['total', 'sale']), disc: col(['discount']), receipt: col(['receipt']), couch: (() => { const i = H.findIndex(x => x === 'couch' || x === 'couch name' || x === 'couch title'); return i > -1 ? i : (!H[18] ? 18 : -1); })() };
  const num = v => Number(String(v ?? '').replace(/[^\d.\-]/g, '')) || 0;
  rows.forEach((r, i) => {
    const m = String(C.receipt > -1 ? r[C.receipt] : '').match(/receipt\/(\d{13})/), ts = m ? Number(m[1]) : null;
    const d = ts ? new Date(ts) : new Date(String(r[C.date] || '')); if (isNaN(d)) return;
    const price = num(r[C.price]), net = price - Math.abs(num(r[C.disc]));
    const l = { i, day: d.toLocaleDateString('en-CA', { timeZone: 'America/Chicago' }), ts, name: String(r[C.name] || '').trim(), price, net, used: false, couchTitle: C.couch > -1 ? String(r[C.couch] || '').trim() : '' };
    l.key = saleKey(l); log.push(l);
  });
  return log;
}
// Every Sales Log order in the last 5 days becomes a pop-up. The couch comes from (1) what you picked in HQ,
// (2) the couch marked Sold on the Sales Tracker for that order, else it says "a couch".
// Sale window (same times as the public order app). While it runs, the Just Sold pop-up says how much each buyer saved.
// Black Friday 2026: $150 off every website couch, Nov 18 6pm through Cyber Monday. The 4 Black Friday-priced couches keep their own price.
const SALE_WIN = { start: Date.parse(process.env.SALE_START || '2026-11-18T18:00:00-06:00'), end: Date.parse(process.env.SALE_END || '2026-11-30T23:59:59-06:00'), big: Number(process.env.SALE_BIG || 150), small: Number(process.env.SALE_SMALL || 150), min: Number(process.env.SALE_MIN || 0) };
// Cyber Monday: Black Friday's $150 ends Sun 11/29 11:59pm; Mon 11/30 (until SALE_END) is $100 off. Same sale window,
// just a smaller amount, and the "ends" shown on the website points at Sunday night until Monday starts.
const CYBER_START = Date.parse(process.env.CYBER_START || '2026-11-30T00:00:00-06:00'), CYBER_AMT = Number(process.env.CYBER_AMOUNT || 100);
const cyberOn = () => Date.now() >= CYBER_START && Date.now() < SALE_WIN.end;
['big', 'small'].forEach(k => { const base = SALE_WIN[k]; Object.defineProperty(SALE_WIN, k, { get: () => cyberOn() ? CYBER_AMT : base }); });
const saleShownEnd = () => cyberOn() ? SALE_WIN.end : Math.min(SALE_WIN.end, CYBER_START - 1000);
const SALE_SKIP = new Set(String(process.env.SALE_SKIP || 'e5da102a0294,2ffd0f1748de,cce09a3338ea,56153d8a1b15').split(',').map(x => x.trim()).filter(Boolean));
const saleLive = () => process.env.SALE !== 'off' && Date.now() >= SALE_WIN.start && Date.now() < SALE_WIN.end;
const inSale = t => t >= SALE_WIN.start && t < SALE_WIN.end;
const saleSaved = (salePrice, listPrice) => listPrice ? (listPrice >= SALE_WIN.min ? SALE_WIN.big : SALE_WIN.small) : (Number(salePrice) + SALE_WIN.big >= SALE_WIN.min ? SALE_WIN.big : SALE_WIN.small);
async function recentOrders(days) {
  const [loads, purchases, picks, site, pidx, drops] = await Promise.all([getLoads(), getPurchases(), kget('bcd:soldPicks', {}).catch(() => ({})), siteCouches(false), kget('bcd:photos', {}).catch(() => ({})), getDrops().catch(() => [])]);
  const manual = await kget('bcd:manualSold', []).catch(() => []), hidden = new Set(await kget('bcd:soldHidden', []).catch(() => []));
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
    // Marked Sold by hand (off-form sale): only pair with an order logged within a day at the same price that isn't
    // already a different couch. Otherwise it gets its own pop-up.
    const manual = !d.soldVia, sameCouch = l => !l.couch || bestSiteMatch(l.couch.name, [{ title: d.title }]);
    const pool = log.filter(l => !l.drop && !hidden.has(l.key) && dayDiff(sd, l.day) >= (manual ? -1 : -2) && dayDiff(sd, l.day) <= (manual ? 1 : 4) && (near(l.price, d.price) || near(l.net, d.price)) && (!manual || sameCouch(l)));
    const hit = pool.sort((a, b) => Math.abs(dayDiff(sd, a.day)) - Math.abs(dayDiff(sd, b.day)))[0];
    if (hit) hit.drop = d;
    else if (d.soldAt > cutoff && d.soldAt <= Date.now() && !hidden.has('d' + d.id)) extra.push({ key: 'd' + d.id, at: new Date(d.soldAt).toISOString(), exact: true, customer: d.soldCustomer || '', price: d.price, title: d.title, photo: (d.photos || [])[0] ? dropPhotoUrl(d.photos[0]) : '', from: 'drops', saved: inSale(d.soldAt) ? saleSaved(0, d.price) : 0 });
  });
  return log.map(l => {
    const at = l.ts || Math.min(Date.now(), Date.parse(l.day + 'T12:00:00-05:00'));
    if (!(at > cutoff && at <= Date.now()) || hidden.has(l.key)) return null;
    const pick = picks[l.key], c = l.couch;
    let title = '', photo = '', from = '';
    if (pick && pick.title) { title = pick.title; photo = pick.img || ''; from = 'picked'; }
    else if (l.drop) { title = l.drop.title; photo = (l.drop.photos || [])[0] ? dropPhotoUrl(l.drop.photos[0]) : ''; from = 'drops'; }
    else if (l.couchTitle) { const m = bestSiteMatch(l.couchTitle, drops.filter(d => (d.photos || []).length).map(d => ({ title: d.title, img: dropPhotoUrl(d.photos[0]) })).concat(site)); title = m ? m.title : l.couchTitle; photo = m && m.img ? m.img : ''; from = 'order'; }
    if (pick && pick.photo) { photo = `/public/justsold-photo/${pick.photo}?v=${pick.at}`; if (!title && c) { title = cleanCouchName(c.name); from = 'tracker'; } }
    else if (c && !photo) {
      title = cleanCouchName(c.name); from = 'tracker';
      if (pidx[c.pkey]) { const t = crypto.createHash('sha1').update(c.pkey).digest('hex').slice(0, 16); photo = `/public/sale-photo/${t}?v=${pidx[c.pkey]}`; recentPhotos[t] = c.pkey; }
      else { const m = bestSiteMatch(c.name, site); if (m && m.img) photo = m.img; }
    }
    return { key: l.key, at: new Date(at).toISOString(), exact: !!l.ts, customer: l.name, price: l.price, title, photo, from, saved: inSale(at) ? saleSaved(l.price, l.drop && l.drop.price) : 0 };
  }).filter(Boolean).concat(extra, manualRows(manual, picks, cutoff)).sort((a, b) => b.at.localeCompare(a.at));
}
// Sales added by hand in HQ (paid off the forms). Same couch picker + photo upload as Sales Log orders.
function manualRows(list, picks, cutoff) {
  return (list || []).filter(m => m.at > cutoff && m.at <= Date.now()).map(m => {
    const key = 'm' + m.id, pick = picks[key] || {};
    const photo = pick.photo ? `/public/justsold-photo/${pick.photo}?v=${pick.at}` : (pick.img || '');
    return { key, at: new Date(m.at).toISOString(), exact: true, customer: m.customer, price: m.price || 0, title: pick.title || '', photo, from: 'manual', saved: inSale(m.at) ? saleSaved(m.price || 0) : 0 };
  });
}
app.post('/api/justsold/add', async (req, res) => {
  try { const customer = clean(req.body.customer, 60); if (!customer) return res.status(400).json({ error: 'Add a name' });
    const list = (await kget('bcd:manualSold', [])).filter(m => Date.now() - m.at < 30 * 864e5);
    list.unshift({ id: crypto.randomBytes(5).toString('hex'), at: Date.now(), customer, price: Number(req.body.price) || 0 });
    await kset('bcd:manualSold', list); recentCache.at = 0; res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/justsold/remove', async (req, res) => {
  try { const key = String(req.body.key || '');
    if (key.startsWith('m')) { const list = await kget('bcd:manualSold', []); await kset('bcd:manualSold', list.filter(m => 'm' + m.id !== key)); }
    else if (key) { const h = await kget('bcd:soldHidden', []); if (!h.includes(key)) h.push(key); await kset('bcd:soldHidden', h.slice(-200)); }   // test orders, Drops sales, Sales Log orders: hide from pop-ups
    recentCache.at = 0; res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
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
const DROP_STATUS = ['draft', 'emailed', 'live', 'held', 'sold', 'hidden'];
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
  if (b.pieces !== undefined) { const n = v => { const x = parseFloat(v); return x > 0 && x < 400 ? Math.round(x * 10) / 10 : null; };
    d.pieces = (Array.isArray(b.pieces) ? b.pieces : []).slice(0, 12).map(p => ({ name: clean(p.name, 40) || 'Piece', w: n(p.w), d: n(p.d), ret: n(p.ret), ch: n(p.ch), cw: n(p.cw), side: ['L', 'R', 'rev'].includes(p.side) ? p.side : '', qty: Math.min(8, Math.max(1, parseInt(p.qty, 10) || 1)) })).filter(p => p.w && p.d); }
  if (b.photos !== undefined) d.photos = (Array.isArray(b.photos) ? b.photos : []).map(x => String(x)).filter(x => /^[a-f0-9]{16}$/.test(x) || /^https:\/\/images\.squarespace-cdn\.com\//.test(x)).slice(0, 12);
  return d;
}
app.get('/api/drops', async (req, res) => {
  try { res.json({ ok: true, drops: (await getDrops()).map(d => ({ ...d, guessPieces: d.pieces && d.pieces.length ? undefined : piecesOf(d) })), base: PUBLIC_BASE }); } catch (e) { res.status(500).json({ error: e.message }); }
});
// Will it fit?: the showroom shape of a modular sectional (where each piece sits), saved from "Arrange pieces" in Drops.
app.get('/api/drops/:id/fit', async (req, res) => {
  const d = (await getDrops()).find(x => x.id === req.params.id); if (!d) return res.status(404).json({ error: 'Couch not found' });
  res.json({ ok: true, couch: { id: d.id, title: d.title, price: d.price, photos: [], pieces: piecesOf(d), shape: d.fitShape || null } });
});
app.post('/api/drops/:id/shape', async (req, res) => {
  try {
    const list = await getDrops(), d = list.find(x => x.id === req.params.id); if (!d) return res.status(404).json({ error: 'Couch not found' });
    const n = v => { const x = parseFloat(v); return isFinite(x) && Math.abs(x) < 2000 ? Math.round(x * 10) / 10 : 0; };
    const sh = (Array.isArray((req.body || {}).shape) ? req.body.shape : []).slice(0, 30).map(o => ({ k: String(o.k || '').replace(/[^0-9-]/g, '').slice(0, 8), x: n(o.x), y: n(o.y), r: [0, 90, 180, 270].includes(o.r) ? o.r : 0, f: !!o.f })).filter(o => o.k);
    d.fitShape = sh.length > 1 ? sh : null; d.updatedAt = Date.now(); await setDrops(list); dropsAt = Date.now();
    res.json({ ok: true, shape: d.fitShape });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/drops/save', async (req, res) => {
  try {
    const list = await getDrops(), b = req.body || {};
    let d = b.id ? list.find(x => x.id === b.id) : null;
    if (b.id && !d) return res.status(404).json({ error: 'Couch not found' });
    const next = cleanDrop(b, d);
    if (!next.title) return res.status(400).json({ error: 'Add a title' });
    // Link to its exact unit in the Sales Tracker (one website couch per unit).
    if (b.unitRef !== undefined) {
      if (!b.unitRef) next.unitRef = null;
      else {
        const r = await validUnitRef(b.unitRef); if (!r) return res.status(400).json({ error: "That unit wasn't found in the Sales Tracker" });
        const dup = list.find(x => x !== d && x.status !== 'hidden' && refKey(x.unitRef) === refKey(r));
        if (dup) return res.status(400).json({ error: `That unit is already linked to "${dup.title}"` });
        next.unitRef = r;
      }
    }
    if (d) Object.assign(d, next, { updatedAt: Date.now() });
    else { d = { id: crypto.randomBytes(6).toString('hex'), status: 'draft', createdAt: Date.now(), updatedAt: Date.now(), photos: [], details: [], imperfections: [], ...next }; list.unshift(d); }
    await setDrops(list); dropsAt = Date.now(); res.json({ ok: true, drop: d });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// Pick Gemini models from what the API key can actually use right now, so retired model names never break the reader.
// JSON answer with light thinking, so reading a diagram takes seconds, not a minute.
async function geminiQuick(model, parts) {
  const key = (process.env.GEMINI_API_KEY || '').trim(); if (!key) throw new Error('not set up');
  const call = async think => {
    const r = await fetch(AI_BASE + '/models/' + encodeURIComponent(model) + ':generateContent', { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-goog-api-key': key },
      body: JSON.stringify({ contents: [{ role: 'user', parts }], generationConfig: { responseMimeType: 'application/json', ...(think ? { thinkingConfig: think } : {}) } }) });
    const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error((j.error && j.error.message) || ('AI ' + r.status)); return j;
  };
  try { return await call(/^gemini-2/.test(model) ? { thinkingBudget: 512 } : { thinkingLevel: 'low' }); }
  catch (e) { if (/thinking/i.test(e.message)) return call(null); throw e; }
}
let dimsModelCache = { at: 0, list: [] };
async function dimsModels() {
  if (process.env.AI_DIMS_MODEL) return process.env.AI_DIMS_MODEL.split(',').map(x => x.trim()).filter(Boolean);
  if (Date.now() - dimsModelCache.at < 6 * 3600e3 && dimsModelCache.list.length) return dimsModelCache.list;
  let names = [];
  try {
    const r = await fetch(AI_BASE + '/models?pageSize=200', { signal: AbortSignal.timeout(8000), headers: { 'x-goog-api-key': (process.env.GEMINI_API_KEY || '').trim() } });
    const jj = await r.json();
    names = (jj.models || []).filter(x => (x.supportedGenerationMethods || []).includes('generateContent')).map(x => String(x.name).replace(/^models\//, ''))
      .filter(x => /^gemini-[\d.]+-(pro|flash)(-preview)?(-\d\d-\d\d)?$/.test(x));
  } catch (err) { /* fall back below */ }
  const ver = x => parseFloat((x.match(/gemini-([\d.]+)/) || [])[1]) || 0;
  const pro = names.filter(x => /-pro/.test(x)).sort((a, b) => ver(b) - ver(a)), flash = names.filter(x => /-flash/.test(x)).sort((a, b) => ver(b) - ver(a));
  const list = [flash[0], pro[0], flash[1]].filter(Boolean);
  dimsModelCache = { at: Date.now(), list: list.length ? list : ['gemini-3.8-flash', 'gemini-3.1-pro-preview'] };
  return dimsModelCache.list;
}
// Drop tab: read a manufacturer dimension diagram (photo) and fill Dimensions + the Will-it-fit pieces.
app.post('/api/drops/read-dims', async (req, res) => {
  try {
    const m = String((req.body || {}).image || '').match(/^data:(image\/(?:jpeg|png|webp));base64,(.+)$/);
    if (!m) return res.status(400).json({ error: 'Send a photo' });
    const title = clean((req.body || {}).title || '', 120), notes = clean((req.body || {}).details || '', 600);
    const prompt = 'This is a furniture dimension diagram' + (title ? ' for "' + title + '"' : '') + '. Read every labeled measurement (convert cm to inches, 1 decimal).\n' + (notes ? 'Listing details: ' + notes + '\n' : '') +
      'Return JSON only: {"labels": number[], "dimensions": string, "pieces": [{"name": string, "w": number, "d": number, "ret": number|null, "ch": number|null, "cw": number|null, "side": "L"|"R"|"rev"|"", "qty": number}]}\n' +
      'labels: every inch measurement printed on the image, exactly as printed (ignore cm).\n' +
      'dimensions: use ONLY numbers from labels, never invent or round. One line like "L: 142.5 x 70.5 in. | D: 37.7 in. | H: 36.7 in." (overall length x overall depth/return, seat depth, height).\n' +
      'pieces: the separate pieces a delivery crew carries in, for a to-scale room planner:\n' +
      '- Modular sectional: one entry per piece type with qty. Name each Corner, Armless, Arm chair, Left arm, Right arm, Chaise, Ottoman, Sofa, Loveseat or Chair. w = piece width, d = piece depth (use the labeled piece depth for every seat piece). Count the pieces in the picture. If a piece width is not labeled, solve it so the pieces along each side add up exactly to that side\'s labeled overall length (a corner counts on both sides).\n' +
      '- One-piece L sectional: name "Sectional", w = long side, d = seat depth, ret = the short side length.\n' +
      '- Sofa with attached chaise: name "Sofa", w = total width, d = depth, ch = chaise length, cw = chaise width.\n' +
      '- Separate sofa/loveseat/ottoman: one entry each.\n' +
      '- OTTOMANS: always list every ottoman as its own piece, including one pushed against a seat to make a chaise/lounge end. A chaise end that is deeper than the other seats on a modular = seat + ottoman: the ottoman depth is the chaise-side total depth minus the seat depth. The piece count in the title (e.g. 4-piece) includes the ottoman, so your pieces qty must add up to it.\n' +
      '- side "L" or "R" only when the piece is left- or right-arm specific; side "rev" for an ottoman/chaise that can go on either side or when the listing says reversible. Never guess numbers that cannot be derived; leave optional fields null.';
    // Newest Flash first (fast), then Pro, then older Flash. Busy = wait and retry once. Whole thing capped at ~75s.
    const models = await dimsModels(), started = Date.now();
    let j = null, lastErr = null; const tried = [];
    for (const md of models) {
      for (let n = 0; n < 2 && !j && Date.now() - started < 75000; n++) {
        try { j = await Promise.race([geminiQuick(md, [imgPart({ mime: m[1], b64: m[2] }), { text: prompt }]), new Promise((_, no) => setTimeout(() => no(new Error('took too long')), 30000))]); }
        catch (err) { lastErr = err; tried.push(md + ': ' + String(err.message).slice(0, 80)); if (/no longer available|not found|not supported|took too long/i.test(err.message)) break; await new Promise(r => setTimeout(r, 3000)); }
      }
      if (j) break;
    }
    if (!j) throw new Error(tried.join(' | ') || (lastErr && lastErr.message) || 'no model');
    const txt = ((((j.candidates || [])[0] || {}).content || {}).parts || []).map(p => p.text || '').join('');
    const out = JSON.parse(txt.slice(txt.indexOf('{'), txt.lastIndexOf('}') + 1));
    const n = x => { const y = parseFloat(x); return y > 0 && y < 400 ? Math.round(y * 10) / 10 : ''; };
    const pieces = (Array.isArray(out.pieces) ? out.pieces : []).slice(0, 12).map(p => ({ name: clean(p.name || 'Piece', 40), w: n(p.w), d: n(p.d), ret: n(p.ret), ch: n(p.ch), cw: n(p.cw),
      side: /^(L|R|rev)$/.test(p.side) ? p.side : '', qty: Math.max(1, Math.min(8, parseInt(p.qty, 10) || 1)) })).filter(p => p.w && p.d);
    // Sanity check: the overall length must be a number actually printed on the diagram.
    const labels = (Array.isArray(out.labels) ? out.labels : []).map(Number).filter(x => x > 0);
    const L = parseFloat((String(out.dimensions || '').match(/L:\s*([\d.]+)/) || [])[1]);
    if (!labels.length || !(L > 0) || !labels.some(x => Math.abs(x - L) < 0.6)) return res.status(422).json({ error: 'Could not read the measurements reliably. Try a clearer diagram or type them in.' });
    res.json({ ok: true, dimensions: clean(out.dimensions || '', 200), pieces });
  } catch (e) { res.status(500).json({ error: /not set up/.test(e.message) ? 'AI is not set up (GEMINI_API_KEY)' : 'Could not read that photo: ' + e.message }); }
});
app.post('/api/drops/status', async (req, res) => {
  try {
    const st = String(req.body.status || ''); if (!DROP_STATUS.includes(st)) return res.status(400).json({ error: 'bad status' });
    const ids = new Set((req.body.ids || []).map(String)), list = await getDrops(), now = Date.now();
    list.forEach(d => { if (!ids.has(d.id)) return; d.status = st; d.updatedAt = now; if (st === 'sold' && d.soldAt == null) delete d.soldVia;
      if (st === 'emailed' && !d.emailedAt) d.emailedAt = now; if (st === 'live' && !d.liveAt) d.liveAt = now; if (st === 'sold') d.soldAt = now; if (st !== 'sold') delete d.soldAt; });
    await setDrops(list); dropsAt = now; recentCache.at = 0; res.json({ ok: true, drops: list });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// Price Cuts: apply a markdown step to a website couch (price changes on the site + order app right away).
app.post('/api/drops/cut', async (req, res) => {
  try {
    const items = Array.isArray(req.body.items) ? req.body.items : [req.body], list = await getDrops(), now = Date.now(); let n = 0;
    items.forEach(it => { const d = list.find(x => x.id === String(it.id || '')); const step = Number(it.step), price = Math.round(Number(it.price) || 0);
      if (!d || !(step >= 1 && step <= 3) || !(price > 0)) return;
      d.cuts = (d.cuts || []).filter(c => c.step !== step); d.cuts.push({ step, from: d.price, to: price, at: now }); d.price = price; d.updatedAt = now; n++; });
    await setDrops(list); dropsAt = now; res.json({ ok: true, done: n, drops: list });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// Price Cuts: fix the date a couch went on the website (imported couches get the import date).
app.post('/api/drops/listed', async (req, res) => {
  try {
    const list = await getDrops(), d = list.find(x => x.id === String(req.body.id || '')); if (!d) return res.status(404).json({ error: 'not found' });
    const t = Date.parse(String(req.body.date || '') + 'T12:00:00-06:00'); if (!t) return res.status(400).json({ error: 'bad date' });
    d.listedAt = t; d.updatedAt = Date.now(); await setDrops(list); dropsAt = Date.now(); res.json({ ok: true, drops: list });
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
// ===================== AUTO "SOLD" INSTAGRAM STORY (one per couch) =====================
// When a website couch sells, HQ makes a 1080x1920 story (couch photo + SOLD stamp + thank-you) and posts it to
// Billy's Instagram Story. The buyer's first name + last initial shows only if they left "OK to shout you out" checked
// on the signature form; if no signed form shows up within 48 hours, it posts without a name.
// Needs IG_USER_ID and IG_TOKEN (instagram_content_publish) in Railway. Without them, stories wait in the queue.
const IGS_KEY = 'bcd:igStories', IG_WAIT_MS = 48 * 3600e3, IG_API = 'https://graph.facebook.com/v21.0';
const igName = full => { const w = String(full || '').trim().split(/\s+/).filter(Boolean); if (!w.length) return '';
  const f = w[0][0].toUpperCase() + w[0].slice(1).toLowerCase(); return w.length > 1 ? `${f} ${w[w.length - 1][0].toUpperCase()}.` : f; };
async function queueSoldStory(d, customer) {
  try {
    if (!d || (!(d.photos || []).length && !d.img)) return;
    const list = await kget(IGS_KEY, []); if (list.some(s => s.dropId === d.id)) return;
    list.unshift({ id: crypto.randomBytes(6).toString('hex'), dropId: d.id, title: d.title, photo: (d.photos || [])[0] || d.img,
      customer: clean(customer || d.soldCustomer || '', 60), at: Date.now(), status: 'waiting' });
    await kset(IGS_KEY, list.slice(0, 300));
  } catch (e) { console.log('Story queue failed', e.message); }
}
async function storyPhoto(ph) {
  if (/^[a-f0-9]{16}$/.test(ph)) { const m = String(await kget('bcd:dphoto:' + ph, '')).match(/^data:image\/\w+;base64,(.+)$/); return m ? Buffer.from(m[1], 'base64') : null; }
  const r = await fetch(ph, { signal: AbortSignal.timeout(20000) }); return r.ok ? Buffer.from(await r.arrayBuffer()) : null;
}
const xmlEsc = s => String(s).replace(/[<>&"']/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;' }[c]));
function wrapLines(t, max, n) {
  const out = []; let cur = '';
  String(t || '').split(/\s+/).forEach(w => { if ((cur + ' ' + w).trim().length > max && cur) { out.push(cur); cur = w; } else cur = (cur + ' ' + w).trim(); });
  if (cur) out.push(cur); if (out.length > n) { out.length = n; out[n - 1] = out[n - 1].replace(/\s*\S*$/, '') + '…'; } return out;
}
// Railway has no system fonts, so story text is drawn as outlines from the bundled Poppins font.
let otFonts = null;
function storyFonts() {
  if (otFonts) return otFonts;
  const ot = require('opentype.js'), dir = path.dirname(require.resolve('@fontsource/poppins/package.json')) + '/files/';
  const load = f => { const b = fs.readFileSync(dir + f); return ot.parse(b.buffer.slice(b.byteOffset, b.byteOffset + b.length)); };
  return (otFonts = { reg: load('poppins-latin-400-normal.woff'), bold: load('poppins-latin-700-normal.woff') });
}
function svgText(str, x, y, size, fill, opt = {}) {
  const f = storyFonts()[opt.bold ? 'bold' : 'reg'], ls = (opt.spacing || 0) / size;
  const w = f.getAdvanceWidth(str, size, { letterSpacing: ls }), left = opt.anchor === 'start' ? x : x - w / 2;
  return `<path d="${f.getPath(str, left, y, size, { letterSpacing: ls }).toPathData(1)}" fill="${fill}"/>`;
}
async function storyImage(s, name) {
  if (!sharp) throw new Error('sharp is not installed');
  const W = 1080, H = 1920, PH = 1280, buf = await storyPhoto(s.photo); if (!buf) throw new Error('No couch photo');
  const ph = await sharp(buf).rotate().resize(W, PH, { fit: 'cover' }).toBuffer();
  const top = PH - 70, title = wrapLines(s.title, 26, 3), ty = top + 200 + title.length * 66 + 40;
  const thanks = name ? [`Thank you ${name}`, 'for supporting my small business!'] : ['Thank you for supporting', 'my small business!'];
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}">
<g transform="translate(540 640) rotate(-10)"><rect x="-300" y="-120" width="600" height="240" rx="30" fill="#b0524c" fill-opacity="0.92" stroke="#ffffff" stroke-width="16"/>
${svgText('SOLD', 0, 62, 170, '#ffffff', { bold: true, spacing: 14 })}</g>
<rect x="0" y="${top}" width="${W}" height="${H - top + 60}" rx="60" fill="#f6f1ea"/>
${svgText("BILLY'S COUCHES", 540, top + 110, 40, '#b0524c', { bold: true, spacing: 6 })}
${title.map((l, i) => svgText(l, 540, top + 200 + i * 66, 54, '#2b1d16', { bold: true })).join('')}
${thanks.map((l, i) => svgText(l, 540, ty + i * 60, 44, '#2b1d16')).join('')}
<rect x="150" y="${H - 175}" width="780" height="100" rx="50" fill="#2b1d16"/>
${svgText('More couches: billyscouches.com', 540, H - 112, 36, '#ffffff', { bold: true })}</svg>`;
  return sharp({ create: { width: W, height: H, channels: 3, background: '#2b1d16' } })
    .composite([{ input: ph, top: 0, left: 0 }, { input: Buffer.from(svg), top: 0, left: 0 }]).jpeg({ quality: 88 }).toBuffer();
}
// Instagram fetches the picture from here when it posts.
app.get('/public/igstory/:id', async (req, res) => {
  try { const id = String(req.params.id).replace(/\.jpg$/, ''); const s = (await kget(IGS_KEY, [])).find(x => x.id === id); if (!s) return res.sendStatus(404);
    res.type('image/jpeg').set('Cache-Control', 'public, max-age=3600').send(await storyImage(s, s.name || '')); }
  catch (e) { res.status(500).send(e.message); }
});
// HQ: the queue, and a sample render (newest live couch, sample name) to check the look.
app.get('/api/igstories', async (req, res) => { try { res.json({ ok: true, connected: !!(process.env.IG_USER_ID && process.env.IG_TOKEN), stories: (await kget(IGS_KEY, [])).slice(0, 50) }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.get('/api/igstories/sample.jpg', async (req, res) => {
  try { const d = (await getDrops()).filter(x => x.status === 'live' && (x.photos || []).length).sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0))[0]; if (!d) return res.sendStatus(404);
    res.type('image/jpeg').send(await storyImage({ title: d.title, photo: d.photos[0] }, req.query.noname ? '' : 'Jessica R.')); }
  catch (e) { res.status(500).send(e.message); }
});
async function igPost(s) {
  const uid = (process.env.IG_USER_ID || '').trim(), tok = (process.env.IG_TOKEN || '').trim(); if (!uid || !tok) throw new Error('Instagram not connected');
  const c = await fetch(`${IG_API}/${uid}/media`, { method: 'POST', body: new URLSearchParams({ image_url: `${PUBLIC_BASE}/public/igstory/${s.id}.jpg`, media_type: 'STORIES', access_token: tok }) }).then(r => r.json());
  if (!c.id) throw new Error((c.error && c.error.message) || 'Instagram did not accept the picture');
  for (let i = 0; i < 10; i++) {
    const st = await fetch(`${IG_API}/${c.id}?fields=status_code&access_token=${encodeURIComponent(tok)}`).then(r => r.json()).catch(() => ({}));
    if (st.status_code === 'FINISHED') break; if (st.status_code === 'ERROR') throw new Error('Instagram could not read the picture');
    await new Promise(r => setTimeout(r, 3000));
  }
  const p = await fetch(`${IG_API}/${uid}/media_publish`, { method: 'POST', body: new URLSearchParams({ creation_id: c.id, access_token: tok }) }).then(r => r.json());
  if (!p.id) throw new Error((p.error && p.error.message) || 'Instagram publish failed'); return p.id;
}
// Every 10 minutes: post stories whose buyer has signed (name per their OK) or that have waited 48 hours (no name).
async function storySweep() {
  if (!(process.env.IG_USER_ID && process.env.IG_TOKEN)) return;
  const list = await kget(IGS_KEY, []), waiting = list.filter(s => s.status === 'waiting'); if (!waiting.length) return;
  let signed = []; try { signed = await newSignForm(true); } catch (e) {}
  const done = [];
  for (const s of waiting.slice(0, 3)) {
    const last = (String(s.customer || '').trim().split(/\s+/).pop() || '').toLowerCase();
    const g = last.length > 1 && signed.find(c => String(c.name || '').toLowerCase().split(/\s+/).includes(last) && Math.abs(Date.parse(c.at || c.submitted) - s.at) < 12 * 864e5);
    if (!g && Date.now() - s.at < IG_WAIT_MS) continue;
    s.name = igName(s.customer);   // no opt-in checkbox anymore: always first name + last initial
    try { s.postId = await igPost(s); s.status = 'posted'; s.postedAt = Date.now(); }
    catch (e) { s.tries = (s.tries || 0) + 1; s.error = e.message; if (s.tries >= 3) { s.status = 'failed'; textAlert(`Instagram story for ${s.title} didn't post: ${e.message}`).catch(() => {}); } }
    done.push(s);
  }
  if (!done.length) return;
  const fresh = await kget(IGS_KEY, []); done.forEach(s => { const f = fresh.find(x => x.id === s.id); if (f) Object.assign(f, s); }); await kset(IGS_KEY, fresh);
}
setInterval(() => storySweep().catch(e => console.log('Story sweep failed', e.message)), 10 * 60 * 1000);
// ===================== AI ROOM PREVIEW ("See it in your living room") =====================
// The website page sends a room photo + which couch + name/phone. HQ asks Google's image model to put that
// exact couch into the room, saves the picture, shows it on the page and texts the link. Every request is a lead.
// Setup (Railway variables): GEMINI_API_KEY (Google AI Studio key, billing on). Optional: AI_MODEL, AI_DAILY_CAP (default 60/day),
// AI_ROOM=off to pause it. The page shows a friendly "busy" message if anything is missing.
let sharp = null; try { sharp = require('sharp'); } catch (e) { console.log('sharp not installed; AI previews saved as-is'); }
const AI_MODEL = (process.env.AI_MODEL || 'gemini-3-pro-image-preview').trim();
const AI_BASE = (process.env.GEMINI_BASE || 'https://generativelanguage.googleapis.com/v1beta').replace(/\/$/, '');
const AI_CAP = Number(process.env.AI_DAILY_CAP || 120);
const aiJobs = new Map();   // id -> { status, url, error, at }  (status survives a redeploy via bcd:aiJob:<id>)
const aiDay = () => new Date().toLocaleDateString('en-CA', { timeZone: 'America/Chicago' });
const dataUrlParts = s => { const m = String(s || '').match(/^data:(image\/(?:jpeg|png|webp|heic|heif));base64,([A-Za-z0-9+/=]+)$/); return m ? { mime: m[1], b64: m[2] } : null; };
async function couchPhotoParts(d, n) {
  const out = [];
  for (const ph of (d.photos || []).slice(0, n || 4)) {
    try {
      if (/^[a-f0-9]{16}$/.test(ph)) { const p = dataUrlParts(await kget('bcd:dphoto:' + ph, '')); if (p) out.push(p); }
      else if (/^https:\/\//.test(ph)) {
        const u = /squarespace-cdn/.test(ph) ? ph.split('?')[0] + '?format=1000w' : ph;
        const r = await fetch(u); if (!r.ok) continue;
        let buf = Buffer.from(await r.arrayBuffer()), mime = (r.headers.get('content-type') || 'image/jpeg').split(';')[0];
        if (sharp) { try { const s = await shrink(buf, 1000); buf = s.buf; mime = s.mime; } catch (e) {} }
        out.push({ mime, b64: buf.toString('base64') });
      }
    } catch (e) {}
  }
  return out;
}
async function shrink(buf, max) {
  if (!sharp) return { buf, mime: 'image/png' };
  const out = await sharp(buf).rotate().resize({ width: max, height: max, fit: 'inside', withoutEnlargement: true }).jpeg({ quality: 84, mozjpeg: true }).toBuffer();
  return { buf: out, mime: 'image/jpeg' };
}
// What the listing says about the couch, so the AI doesn't add or drop seats.
function couchFacts(d) {
  const det = (d.details || []).filter(l => !/^condition|^grade|price|deliver/i.test(l)).slice(0, 8);
  return [`Name: ${d.title}`, d.dimensions ? `Real size: ${d.dimensions}` : '', det.length ? 'Listing details: ' + det.join('; ') : ''].filter(Boolean).join('\n');
}
async function gemini(model, parts, json, aspect) {
  const key = (process.env.GEMINI_API_KEY || '').trim(); if (!key) throw new Error('not set up');
  const r = await fetch(`${AI_BASE}/models/${encodeURIComponent(model)}:generateContent`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'x-goog-api-key': key },
    body: JSON.stringify({ contents: [{ role: 'user', parts }], generationConfig: json ? { responseMimeType: 'application/json' } : { responseModalities: ['TEXT', 'IMAGE'], ...(aspect ? { imageConfig: { aspectRatio: aspect } } : {}) } })
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error((j.error && j.error.message) || ('AI ' + r.status));
  return j;
}
const imgPart = p => ({ inline_data: { mime_type: p.mime, data: p.b64 } });
// Keep the picture the same shape as their room photo
const RATIOS = ['21:9', '16:9', '3:2', '4:3', '5:4', '1:1', '4:5', '3:4', '2:3', '9:16'];
async function roomAspect(room) {
  if (!sharp) return '';
  try { const m = await sharp(Buffer.from(room.b64, 'base64')).metadata(); const want = m.width / m.height;
    return RATIOS.reduce((best, r) => { const [a, b] = r.split(':').map(Number); return Math.abs(Math.log(a / b / want)) < Math.abs(Math.log(best.v / want)) ? { r, v: a / b } : best; }, { r: '', v: 1e9 }).r; } catch (e) { return ''; }
}
async function aiRender(job, problem) {
  // Short and simple works best: the room photo first, then ONE clean picture of the couch.
  const ref = job.cut ? [job.cut] : job.couch.slice(0, 2);
  const prompt = [
    'Edit the first image (a photo of a customer\'s living room). Put the main sofa shown in the ' + (ref.length > 1 ? 'other images (real photos of one sofa, different angles)' : 'second image') + ' into this room, in the spot where a couch naturally goes. If a couch is already there, replace it. Ignore everything around the sofa in the reference photos.',
    'Keep the first image exactly as it is everywhere else: same walls, windows, doors, floor, rug, tables, decor, lighting, camera angle and framing. Do not create a new room.',
    'Copy the sofa exactly as photographed, like a cut-and-paste: same shape, number of seats and pieces, arms, base and legs (do not add a base or legs it does not have), recliners closed if closed, same exact color and material. Do not redesign it. Scale it realistically.',
    'Only add the sofa, nothing else from the reference ' + (ref.length > 1 ? 'photos' : 'photo') + '.',
    'Sofa details: ' + job.facts.replace(/\n/g, '; '),
    problem ? 'Last try was wrong: ' + problem + '. Fix that.' : ''
  ].filter(Boolean).join('\n');
  const j = await gemini(AI_MODEL, [imgPart(job.room), ...ref.map(imgPart), { text: prompt }]);
  const out = (((j.candidates || [])[0] || {}).content || {}).parts || [];
  const hit = out.find(p => (p.inlineData || p.inline_data) && (p.inlineData || p.inline_data).data);
  if (!hit) throw new Error('AI returned no picture' + (j.promptFeedback && j.promptFeedback.blockReason ? ' (' + j.promptFeedback.blockReason + ')' : ''));
  return Buffer.from((hit.inlineData || hit.inline_data).data, 'base64');
}
// Second look: a quick, cheap AI pass compares the picture to the real couch photos. AI_CHECK=off skips it.
const AI_CHECK_MODEL = (process.env.AI_CHECK_MODEL || 'gemini-2.5-pro').trim();  // the careful checker; set gemini-2.5-flash for faster/looser
async function aiCheck(job, buf) {
  if ((process.env.AI_CHECK || '').toLowerCase() === 'off') return { ok: true };
  try {
    let p = { mime: 'image/png', b64: buf.toString('base64') };
    if (sharp) { const s = await shrink(buf, 1000); p = { mime: s.mime, b64: s.buf.toString('base64') }; }
    const prompt = 'Image 1 is an AI-edited photo that should show the customer\'s room (image 2) with one specific sofa added. Images 3+ are real showroom photos of that sofa.\n' + job.facts +
      '\nFirst: is image 1 clearly the same room as image 2 (same walls, floor, windows, angle)? If image 1 looks like the showroom instead, that is NOT a match.' +
      '\nCompare the sofa in image 1 to the real sofa. Ignore camera angle, lighting and the room. Is it the same sofa: same number of seats/sections/recliners, same arms, same chaise or corner layout, same color and material? Small differences are fine; extra or missing seats, a different shape, or a different color are not.' +
      '\nReply only JSON: {"match": true or false, "problem": "one short sentence if not a match"}';
    let rm = job.room;
    if (!rm) {
      const pc = 'Image 1 should be a clean catalog photo of the sofa shown in the other images (real showroom photos).\n' + job.facts + '\nIs image 1 the same sofa: same number of seats/sections/recliners, same arms, same chaise or corner layout, same color and material? Ignore background and angle. Reply only JSON: {"match": true or false, "problem": "one short sentence if not"}';
      const jc = await gemini(AI_CHECK_MODEL, [{ text: pc }, imgPart(p), ...job.couch.slice(0, 3).map(imgPart)], true);
      const tc = ((((jc.candidates || [])[0] || {}).content || {}).parts || []).map(x => x.text || '').join('');
      const rc = JSON.parse(tc.replace(/^```(json)?|```$/g, '').trim()); return { ok: rc.match !== false, problem: String(rc.problem || '').slice(0, 200) };
    }
    if (sharp) { try { const s = await shrink(Buffer.from(rm.b64, 'base64'), 800); rm = { mime: s.mime, b64: s.buf.toString('base64') }; } catch (e) {} }
    const j = await gemini(AI_CHECK_MODEL, [{ text: prompt }, imgPart(p), imgPart(rm), ...job.couch.slice(0, 3).map(imgPart)], true);
    const t = ((((j.candidates || [])[0] || {}).content || {}).parts || []).map(x => x.text || '').join('');
    const r = JSON.parse(t.replace(/^```(json)?|```$/g, '').trim());
    return { ok: r.match !== false, problem: String(r.problem || '').slice(0, 200) };
  } catch (e) { console.log('AI check skipped:', e.message); return { ok: true }; }
}
// Clean "studio" shot of each couch (showroom removed), made once per couch and reused for every customer.
// This stops showroom chairs/walls leaking into pictures and keeps the couch consistent. Checked against the real photos first.
const cutKey = d => 'bcd:aiCut:' + d.id + ':' + crypto.createHash('md5').update(JSON.stringify(d.photos || [])).digest('hex').slice(0, 8);
const cutBusy = new Map();
async function couchCutout(d, couch) {
  if ((process.env.AI_CUTOUT || '').toLowerCase() !== 'on') return null;  // off by default: AI-made couch shots drifted from the real couch
  const key = cutKey(d), have = await kget(key, null);
  if (have) return have === 'bad' ? null : dataUrlParts(have);
  if (cutBusy.has(key)) return cutBusy.get(key);
  const job = (async () => {
    try {
      couch = couch || await couchPhotoParts(d); if (!couch.length) return null;
      const prompt = ['These are real photos of ONE sofa in our showroom.', 'About it:\n' + couchFacts(d),
        'Make a clean catalog photo of this exact sofa alone on a plain white background, seen from the front at a slight angle so every seat and piece is visible.',
        'Copy it exactly: same number of seats, cushions, recliners, consoles, arms and sections, same layout (which side any chaise or corner is on), same color, material, stitching and legs.',
        'Remove EVERYTHING else: other couches, chairs, pillows that are not part of it, price tags, floor, walls. No text. Return only the photo.'].join('\n');
      const j = await gemini(AI_MODEL, [{ text: prompt }, ...couch.map(imgPart)], false, '16:9');
      const hit = ((((j.candidates || [])[0] || {}).content || {}).parts || []).find(p => (p.inlineData || p.inline_data) && (p.inlineData || p.inline_data).data);
      if (!hit) return null;
      let buf = Buffer.from((hit.inlineData || hit.inline_data).data, 'base64');
      const chk = await aiCheck({ facts: couchFacts(d), couch, room: null }, buf);
      if (!chk.ok) { console.log('Cutout rejected for', d.title, '-', chk.problem); await kset(key, 'bad'); return null; }
      const sm = await shrink(buf, 1200); const v = `data:${sm.mime};base64,${sm.buf.toString('base64')}`;
      await kset(key, v); return dataUrlParts(v);
    } catch (e) { console.log('Cutout failed for', d.title, e.message); return null; } finally { cutBusy.delete(key); }
  })();
  cutBusy.set(key, job); return job;
}
// Use the cutout only if it's already made; otherwise start making it for next time and don't make the customer wait.
async function cutoutIfReady(d) { if ((process.env.AI_CUTOUT || '').toLowerCase() !== 'on') return null; const have = await kget(cutKey(d), null); if (have && have !== 'bad') return dataUrlParts(have); if (!have) couchCutout(d).catch(() => {}); return null; }
// HQ: see the clean couch shot the AI uses (hq.billyscouches.com/api/ai-cut/<couch id>)
app.get('/api/ai-cut/:id', async (req, res) => {
  const d = (await getDrops()).find(x => x.id === req.params.id); if (!d) return res.sendStatus(404);
  const v = await kget(cutKey(d), null); if (!v || v === 'bad') return res.status(404).send(v === 'bad' ? 'Rejected by the check, using the real photos instead.' : 'Not made yet.');
  const m = v.match(/^data:(image\/\w+);base64,(.+)$/); res.type(m[1]).send(Buffer.from(m[2], 'base64'));
});
// Make cutouts for new couches ahead of time, so customers never wait on it.
async function warmCutouts() {
  if (!(process.env.GEMINI_API_KEY || '').trim() || (process.env.AI_ROOM || '').toLowerCase() === 'off' || (process.env.AI_CUTOUT || '').toLowerCase() !== 'on') return;
  for (const d of (await getDrops()).filter(x => x.status === 'live')) { if (!(await kget(cutKey(d), null))) await couchCutout(d); }
}
setTimeout(() => warmCutouts().catch(() => {}), 60 * 1000);
setInterval(() => warmCutouts().catch(() => {}), 60 * 60 * 1000);
const sessKey = sid => 'bcd:aiSess:' + sid;
const roomLink = sid => `${PUBLIC_BASE}/room/${sid}`;
async function sessTry(sid, id, patch) {
  const s = await kget(sessKey(sid), null); if (!s) return null;
  const t = (s.tries || []).find(x => x.id === id); if (t) Object.assign(t, patch);
  await kset(sessKey(sid), s); return s;
}
async function aiRun(id, job) {
  const set = async st => { const v = { ...st, at: Date.now() }; aiJobs.set(id, v); await kset('bcd:aiJob:' + id, v).catch(() => {}); };
  try {
    let out = null, last = null;
    for (let i = 0; i < 2 && !out; i++) { try { out = await aiRender(job); } catch (e) { last = e; if (/not set up|API key|PERMISSION|billing/i.test(e.message)) break; } }
    if (!out) throw last || new Error('failed');
    let chk = await aiCheck(job, out);
    if (!chk.ok) {
      console.log('AI check: redoing', job.title, '-', chk.problem);
      try { const again = await aiRender(job, chk.problem || 'the sofa did not match the product photos'); const c2 = await aiCheck(job, again); if (c2.ok || /room/i.test(chk.problem)) { out = again; chk = c2; } } catch (e) {}
      // Never show a picture of a different room.
      // Never show a different room or a different couch. AI_STRICT=off shows the best try anyway.
      if (!chk.ok && ((process.env.AI_STRICT || '').toLowerCase() !== 'off' || /room|showroom|different (space|place)/i.test(chk.problem))) throw new Error('bad result: ' + chk.problem);
    }
    const { buf, mime } = await shrink(out, 1600);
    await kset('bcd:aiImg:' + id, `data:${mime};base64,${buf.toString('base64')}`);
    const url = `${PUBLIC_BASE}/public/ai-room/img/${id}.jpg`;
    await set({ status: 'done', url });
    if (job.t0) { const a = (await kget('bcd:aiAvg', null)) || { ms: 25000 }; a.ms = Math.round(a.ms * 0.8 + (Date.now() - job.t0) * 0.2); await kset('bcd:aiAvg', a).catch(() => {}); }
    const s = await sessTry(job.sid, id, { status: 'done', url, redo: !chk.ok });
    if (s && !s.texted) {
      s.texted = true; await kset(sessKey(job.sid), s);
      sendText(s.phone, `Hi ${s.first}, it's Billy with Billy's Couches! Your room is ready. Tap here to see the ${job.title} in your space, and try any of our other couches in it too:\n${roomLink(job.sid)}`).catch(() => {});
    }
  } catch (e) {
    console.log('AI room preview failed:', e.message);
    await set({ status: 'error', error: /not set up/.test(e.message) ? 'setup' : 'failed' });
    await sessTry(job.sid, id, { status: 'failed' }).catch(() => {});
  }
}
// Every AI preview lead also goes to the "First Dibs Email List" Google Sheet (same script as billyscouches.com/firstdibs):
// phone + name always go to the "Phone Leads" tab; the email joins First Dibs only if they checked "Email me First Dibs".
// The script's address is read from the /firstdibs page (FIRSTDIBS_SCRIPT_URL overrides).
let fdUrlCache = { at: 0, url: '' };
async function firstDibsScriptUrl() {
  if (process.env.FIRSTDIBS_SCRIPT_URL) return process.env.FIRSTDIBS_SCRIPT_URL.trim();
  if (fdUrlCache.url && Date.now() - fdUrlCache.at < 6 * 3600 * 1000) return fdUrlCache.url;
  const html = await (await fetch('https://www.billyscouches.com/firstdibs', { headers: { 'User-Agent': 'BillysHQ/1.0' } })).text();
  const m = html.match(/https:\/\/script\.google\.com\/macros\/s\/[A-Za-z0-9_-]+\/exec/);
  if (m) fdUrlCache = { at: Date.now(), url: m[0] };
  return fdUrlCache.url;
}
async function saveLeadToSheet(l) {
  try {
    const url = await firstDibsScriptUrl(); if (!url) return console.log('First Dibs sheet: script address not found');
    const body = new URLSearchParams({ phone: l.phone, name: l.name, contactEmail: l.email || '', page: '/see-it-in-your-room (AI preview)', couch: l.couch || '' });
    if (l.emailOk && l.email) body.set('email', l.email);
    if (l.smsOk) body.set('smsOk', '1');
    await fetch(url, { method: 'POST', body });
  } catch (e) { console.log('First Dibs sheet save failed:', e.message); }
}
// Limits: 12 pictures per phone and 16 per device a day, plus the daily total (AI_DAILY_CAP).
async function aiLimit(phone, ip, vip) {
  if (vip || (process.env.AI_VIP_PHONES || '').split(',').map(x => x.replace(/\D/g, '').slice(-10)).includes(phone)) return '';
  const day = aiDay(), lim = (await kget('bcd:aiLimit', {})) || {}; if (lim.day !== day) { lim.day = day; lim.total = 0; lim.by = {}; }
  if ((lim.by[phone] || 0) >= 12 || (lim.by[ip] || 0) >= 16) return "That's the max for today. Text Billy at (314) 899-7503 and he'll make more for you.";
  if (lim.total >= AI_CAP) return "We're getting a lot of requests today. Text Billy at (314) 899-7503 and he'll send yours.";
  lim.total++; lim.by[phone] = (lim.by[phone] || 0) + 1; lim.by[ip] = (lim.by[ip] || 0) + 1; await kset('bcd:aiLimit', lim);
  return '';
}
async function roomPart(dataUrl) {
  const room = dataUrlParts(dataUrl); if (!room) return null;
  if (room.b64.length > 9e6) throw Object.assign(new Error('That photo is too big. Try another one.'), { user: true });
  if (sharp) {
    let out = null; try { const s = await shrink(Buffer.from(room.b64, 'base64'), 1536); out = { mime: s.mime, buf: s.buf }; } catch (e) {}
    if (out) { const m = await sharp(out.buf).metadata(); if (m.height > m.width * 1.05) throw Object.assign(new Error('Turn your phone sideways and take a wide photo. Couches need the whole wall in the shot.'), { user: true });
      return { mime: out.mime, b64: out.buf.toString('base64') }; }
  }
  return room;
}
async function startTry(s, d, ip, vip) {
  const msg = await aiLimit(s.phone, ip, vip); if (msg) throw Object.assign(new Error(msg), { user: true, code: 429 });
  const couch = await couchPhotoParts(d); if (!couch.length) throw Object.assign(new Error('That couch has no photo yet. Pick another one.'), { user: true });
  const room = dataUrlParts(await kget('bcd:aiRoomImg:' + s.sid, '')); if (!room) throw Object.assign(new Error('Add your room photo again.'), { user: true, code: 409 });
  const id = crypto.randomBytes(8).toString('hex');
  s.tries = (s.tries || []).filter(t => t.couchId !== d.id || t.status === 'working');
  s.tries.push({ id, couchId: d.id, title: d.title, status: 'working', at: Date.now() });
  await kset(sessKey(s.sid), s);
  aiJobs.set(id, { status: 'working', at: Date.now() });
  aiRun(id, { sid: s.sid, room, couch, cut: await cutoutIfReady(d), facts: couchFacts(d), title: d.title, aspect: await roomAspect(room), t0: Date.now() });
  return id;
}
const liveCouch = async id => (await getDrops()).find(x => x.id === String(id || '') && x.status === 'live');
const sidOf = req => String(req.params.sid || '').replace(/[^a-f0-9]/g, '').slice(0, 32);
const aiErr = (res, e) => { if (e.user) return res.status(e.code || 400).json({ error: e.message, code: e.code }); console.log('ai-room error', e.message); res.status(500).json({ error: 'Something went wrong. Try again in a minute.' }); };

// ---------- Will it fit? sizing tool ----------
// Website form: name + phone -> we text them their own link (hq.../fit/<id>). Measurements save on that link.
const fitKey = id => 'bcd:fitSess:' + id;
// Daily counts for the Will It Fit tab: page views (website sign-up page), sign-ups, link opens, pictures saved.
async function fitCount(k) { try { const day = new Date().toLocaleDateString('en-CA', { timeZone: 'America/Chicago' }), c = (await kget('bcd:fitDays', {})) || {}; c[day] = c[day] || {}; c[day][k] = (c[day][k] || 0) + 1;
  const keys = Object.keys(c).sort(); keys.slice(0, Math.max(0, keys.length - 120)).forEach(x => delete c[x]); await kset('bcd:fitDays', c); } catch (e) {} }
const fitViewHits = new Map();
app.options('/public/fit-view', (req, res) => { offerCors(req, res); res.sendStatus(204); });
app.post('/public/fit-view', async (req, res) => { offerCors(req, res); const ip = clientIp(req), now = Date.now();
  if (now - (fitViewHits.get(ip) || 0) > 30 * 60e3) { fitViewHits.set(ip, now); fitCount('views'); } res.json({ ok: true }); });
const fitLink = id => `${FIT_BASE || PUBLIC_BASE}/fit/${id}`;
const fitHits = new Map();
app.options('/public/fit', (req, res) => { offerCors(req, res); res.sendStatus(204); });
app.post('/public/fit', async (req, res) => {
  offerCors(req, res);
  try {
    const b = req.body || {}, ip = clientIp(req), now = Date.now();
    if (b.bc_hp_fld) return res.json({ ok: true });
    const phone = String(b.phone || '').replace(/\D/g, '').slice(-10), name = String(b.name || '').trim().slice(0, 60);
    if (!name || phone.length !== 10) return res.status(400).json({ error: 'Add your first name and a 10-digit phone number.' });
    const hits = (fitHits.get(ip) || []).filter(t => now - t < 3600e3); if (hits.length >= 6) return res.status(429).json({ error: 'Too many tries. Try again in an hour.' });
    hits.push(now); fitHits.set(ip, hits);
    const leads = (await kget('bcd:fitLeads', [])) || [], old = leads.find(x => x.phone === phone);
    const first = (name.split(/\s+/)[0] || 'there').replace(/^./, c => c.toUpperCase());
    let id = old && old.id && await kget(fitKey(old.id), null) ? old.id : crypto.randomBytes(9).toString('hex');
    const sess = (await kget(fitKey(id), null)) || { id, at: new Date().toISOString(), meas: {}, opens: 0 };
    const pre = String(b.couch || '').replace(/[^a-z0-9]/gi, '').slice(0, 20); if (pre && !sess.meas.couch) sess.meas.couch = pre;
    Object.assign(sess, { name, first, phone, smsOk: b.smsOk !== false });
    await kset(fitKey(id), sess);
    if (!old) { leads.push({ id, at: sess.at, name, phone, smsOk: sess.smsOk, page: clean(b.page, 120), couch: pre }); fitCount('signups'); await kset('bcd:fitLeads', leads.slice(-3000)); setTimeout(() => syncWarmLeads().catch(() => {}), 5000); }
    const sent = await sendText(phone, `Hi ${first}, it's Billy with Billy's Couches! Here's your free sizing tool. Tap any couch we have and see if it fits your space:\n${fitLink(id)}\n\nYour measurements save on that link, so come back when new couches land.`);
    if (!sent) { console.log('fit text failed', phone); return res.status(502).json({ error: "We couldn't text that number. Double-check it, or text Billy at (314) 899-7503." }); }
    res.json({ ok: true });
    if (!old) {
      const body = new URLSearchParams({ phone, name, page: '/will-it-fit (sizing tool)' }); if (sess.smsOk) body.set('smsOk', '1');
      firstDibsScriptUrl().then(u => u && fetch(u, { method: 'POST', body })).catch(() => {});
      pushAll('New sizing tool lead', name, '/', 'fit-' + id).catch(() => {});
    }
  } catch (e) { console.log('fit lead error', e.message); res.status(500).json({ error: "Couldn't send the text. Try again in a minute." }); }
});
app.get('/fit', (req, res) => res.set('Cache-Control', 'no-cache').sendFile(path.join(__dirname, 'fit.html')));
app.get('/fit/:id', (req, res) => res.set('X-Robots-Tag', 'noindex').set('Cache-Control', 'no-cache').sendFile(path.join(__dirname, 'fit.html')));
const fitId = req => String(req.params.id || '').replace(/[^a-f0-9]/g, '').slice(0, 24);
app.get('/public/fit-sess/:id', async (req, res) => {
  res.set('Cache-Control', 'no-store');
  const s = await kget(fitKey(fitId(req)), null); if (!s) return res.status(404).json({ error: 'gone' });
  if (req.query.open) { s.opens = (s.opens || 0) + 1; s.lastOpen = new Date().toISOString(); await kset(fitKey(s.id), s); fitCount('opens'); }
  res.json({ first: s.first, meas: s.meas || {} });
});
app.post('/public/fit-sess/:id', async (req, res) => {
  try {
    const s = await kget(fitKey(fitId(req)), null); if (!s) return res.status(404).json({ error: 'gone' });
    const m = (req.body || {}).meas || {}, n = (v, max) => { const x = parseFloat(v); return x >= -50 && x < (max || 2000) ? Math.round(x * 10) / 10 : null; };
    const items = (arr, max) => (Array.isArray(arr) ? arr : []).slice(0, max).map(o => ({ k: String(o.k || '').replace(/[^a-z0-9-]/gi, '').slice(0, 20), x: n(o.x), y: n(o.y), r: [0, 90, 180, 270].includes(o.r) ? o.r : 0, f: !!o.f, h: !!o.h }));
    s.meas = { roomW: n(m.roomW), roomD: n(m.roomD), couch: String(m.couch || '').replace(/[^a-z0-9]/gi, '').slice(0, 20), sig: String(m.sig || '').slice(0, 600), locked: m.locked !== false, layout: items(m.layout, 30), extras: items(m.extras, 6) };
    if (s.meas.couch) s.tried = [...new Set([...(s.tried || []), s.meas.couch])].slice(-40);
    await kset(fitKey(s.id), s); res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'save failed' }); }
});
app.post('/public/fit-sess/:id/saved', async (req, res) => {
  const s = await kget(fitKey(fitId(req)), null); if (!s) return res.sendStatus(404);
  s.saves = (s.saves || 0) + 1; s.lastSave = new Date().toISOString(); await kset(fitKey(s.id), s); fitCount('saves'); res.json({ ok: true });
});
// HQ: sizing tool leads as a spreadsheet. Hot = typed their room and tried 2+ couches or saved a picture, Warm = opened the link, Cold = never opened.
// Sidebar badges: one small read (lead ids only).
app.get('/api/badges', async (req, res) => {
  try { const L = ((await kget('bcd:fitLeads', [])) || []).slice(-800); res.json({ ok: true, fit: L.map(l => l.id) }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/fit', async (req, res) => {
  try {
    const drops = await getDrops(), title = id => (drops.find(d => d.id === id) || {}).title || '', L = ((await kget('bcd:fitLeads', [])) || []).slice(-600);
    const sess = await Promise.all(L.map(l => kget(fitKey(l.id), null).catch(() => null)));
    const leads = L.map((l, i) => { const s = sess[i] || {}, m = s.meas || {};
      return { at: l.at, name: l.name, phone: l.phone, smsOk: !!l.smsOk, score: fitScore(s), bought: l.bought || '', opens: s.opens || 0, lastOpen: s.lastOpen || '', saves: s.saves || 0,
        room: m.roomW ? [m.roomW, m.roomD] : null, tried: (s.tried || []).map(title).filter(Boolean), from: l.couch ? title(l.couch) : '', page: l.page || '', link: fitLink(l.id) }; }).reverse();
    res.json({ ok: true, leads, days: (await kget('bcd:fitDays', {})) || {}, base: FIT_BASE || PUBLIC_BASE });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
const fitScore = s => !s.opens ? 'Cold' : (s.meas && s.meas.roomW && ((s.tried || []).length >= 2 || s.saves)) ? 'Hot' : 'Warm';
app.get('/api/fit-leads.csv', async (req, res) => {
  const q = v => '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"', drops = await getDrops(), title = id => (drops.find(d => d.id === id) || {}).title || id;
  const rows = [];
  for (const l of ((await kget('bcd:fitLeads', [])) || []).slice(-1000).reverse()) {
    const s = await kget(fitKey(l.id), null) || {}, m = s.meas || {}, ft = x => x ? Math.floor(x / 12) + "' " + Math.round(x % 12) + '"' : '';
    rows.push([l.at, l.name, l.phone, fitScore(s), l.bought ? 'yes ' + String(l.bought).slice(0, 10) : '', l.smsOk ? 'yes' : 'no', s.opens || 0, s.lastOpen || '', m.roomW ? ft(m.roomW) + ' x ' + ft(m.roomD) : '', (s.tried || []).map(title).join(' | '), fitLink(l.id)].map(q).join(','));
  }
  res.type('text/csv').set('Content-Disposition', 'attachment; filename="sizing-tool-leads.csv"').send(['When,Name,Phone,Score,Bought,OK to text,Times opened,Last opened,Room,Couches tried,Their link'].concat(rows).join('\n'));
});

// Landing page (Squarespace): first picture + their info. Creates their own room page and texts them the link.
app.options('/public/ai-room', (req, res) => { offerCors(req, res); res.sendStatus(204); });
app.post('/public/ai-room', async (req, res) => {
  offerCors(req, res);
  try {
    if ((process.env.AI_ROOM || '').toLowerCase() === 'off') return res.status(503).json({ error: 'paused' });
    const b = req.body || {};
    const phone = String(b.phone || '').replace(/\D/g, '').slice(-10), name = String(b.name || '').trim().slice(0, 60), email = String(b.email || '').trim().slice(0, 120);
    const room = await roomPart(b.room); if (!room) return res.status(400).json({ error: 'Add a photo of your room.' });
    if (!name || phone.length !== 10) return res.status(400).json({ error: 'Add your name and a 10-digit phone number.' });
    const d = await liveCouch(b.couchId); if (!d) return res.status(400).json({ error: 'Pick a couch first.' });
    const sid = crypto.randomBytes(10).toString('hex'), first = (name.split(/\s+/)[0] || 'there').replace(/^./, c => c.toUpperCase());
    const emailOk = !!b.emailOk && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email), smsOk = !!b.smsOk;
    await kset('bcd:aiRoomImg:' + sid, `data:${room.mime};base64,${room.b64}`);
    const s = { sid, at: new Date().toISOString(), name, first, phone, email, emailOk, smsOk, tries: [], opens: 0, texted: false };
    const id = await startTry(s, d, clientIp(req), authed(req));
    const leads = (await kget('bcd:aiLeads', [])) || [], isNew = !leads.some(x => x.phone === phone);
    leads.push({ sid, at: s.at, name, phone, email, emailOk, smsOk, couch: d.title });
    await kset('bcd:aiLeads', leads.slice(-2000));
    res.json({ ok: true, id, sid, url: roomLink(sid) });
    if (isNew) saveLeadToSheet({ name, phone, email, emailOk, smsOk, couch: d.title });
    if (isNew) pushAll('New AI preview lead', `${name} · ${d.title}`, '/', 'ai-' + sid).catch(() => {});
  } catch (e) { aiErr(res, e); }
});
// Their own room page (the link we text them)
app.get('/room/:sid', (req, res) => res.set('X-Robots-Tag', 'noindex').set('Cache-Control', 'no-cache').sendFile(path.join(__dirname, 'room.html')));
app.get('/public/ai-sess/:sid', async (req, res) => {
  res.set('Cache-Control', 'no-store');
  const s = await kget(sessKey(sidOf(req)), null); if (!s) return res.status(404).json({ error: 'gone' });
  if (req.query.open) { s.opens = (s.opens || 0) + 1; s.lastOpen = new Date().toISOString(); await kset(sessKey(s.sid), s); }
  const avg = (await kget('bcd:aiAvg', null)) || { ms: 25000 };
  res.json({ avgSec: Math.max(8, Math.round(avg.ms / 1000)), first: s.first, room: `/public/ai-sess/${s.sid}/room.jpg?v=${s.roomV || 0}`, tries: (s.tries || []).map(t => ({ id: t.id, couchId: t.couchId, title: t.title, status: t.status, url: t.url || '' })) });
});
app.get('/public/ai-sess/:sid/room.jpg', async (req, res) => {
  const m = String(await kget('bcd:aiRoomImg:' + sidOf(req), '')).match(/^data:(image\/\w+);base64,(.+)$/); if (!m) return res.sendStatus(404);
  res.set('Cache-Control', 'public, max-age=86400').type(m[1]).send(Buffer.from(m[2], 'base64'));
});
app.post('/public/ai-sess/:sid/try', async (req, res) => {
  try {
    if ((process.env.AI_ROOM || '').toLowerCase() === 'off') return res.status(503).json({ error: 'The room preview is paused right now.' });
    const s = await kget(sessKey(sidOf(req)), null); if (!s) return res.status(404).json({ error: 'This link expired. Start a new one at billyscouches.com/see-it-in-your-room' });
    if ((s.tries || []).filter(t => t.status === 'working').length >= 2) return res.status(429).json({ error: 'Hang on, still working on your last one.' });
    const d = await liveCouch((req.body || {}).couchId); if (!d) return res.status(400).json({ error: 'That couch just sold. Pick another one.' });
    res.json({ ok: true, id: await startTry(s, d, clientIp(req), authed(req)) });
  } catch (e) { aiErr(res, e); }
});
app.post('/public/ai-sess/:sid/room', async (req, res) => {
  try {
    const s = await kget(sessKey(sidOf(req)), null); if (!s) return res.status(404).json({ error: 'gone' });
    const room = await roomPart((req.body || {}).room); if (!room) return res.status(400).json({ error: 'That photo type didn\'t work. Try a regular photo.' });
    await kset('bcd:aiRoomImg:' + s.sid, `data:${room.mime};base64,${room.b64}`);
    s.roomV = (s.roomV || 0) + 1; s.tries = []; await kset(sessKey(s.sid), s);
    res.json({ ok: true });
  } catch (e) { aiErr(res, e); }
});
app.get('/public/ai-room/status/:id', async (req, res) => {
  dropCors(res); res.set('Cache-Control', 'no-store');
  const id = String(req.params.id).replace(/[^a-f0-9]/g, '');
  const j = aiJobs.get(id) || await kget('bcd:aiJob:' + id, null);
  if (!j) return res.json({ status: 'working' });
  if (j.status === 'working' && Date.now() - j.at > 4 * 60 * 1000) return res.json({ status: 'error', error: 'failed' });
  res.json(j);
});
app.get('/public/ai-room/img/:id', async (req, res) => {
  try { const m = String(await kget('bcd:aiImg:' + String(req.params.id).replace(/\.jpg$/, '').replace(/[^a-f0-9]/g, ''), '')).match(/^data:(image\/\w+);base64,(.+)$/); if (!m) return res.sendStatus(404);
    dropCors(res); res.set('Cache-Control', 'public, max-age=604800, immutable').type(m[1]).send(Buffer.from(m[2], 'base64')); } catch (e) { res.sendStatus(404); }
});
// HQ: every AI preview lead as a spreadsheet: who, which couches they tried, whether they opened their link.
app.get('/api/ai-leads.csv', async (req, res) => {
  const q = v => '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"';
  const rows = [];
  for (const l of ((await kget('bcd:aiLeads', [])) || []).slice(-500).reverse()) {
    const s = l.sid ? await kget(sessKey(l.sid), null) : null, tr = s ? (s.tries || []).filter(t => t.status === 'done') : [];
    rows.push([l.at, l.name, l.phone, l.email, l.emailOk ? 'yes' : 'no', l.smsOk ? 'yes' : 'no', l.couch, tr.length, tr.map(t => t.title).join(' | '), s ? (s.opens || 0) : '', s && s.lastOpen || '', l.sid ? roomLink(l.sid) : (l.url || '')].map(q).join(','));
  }
  res.type('text/csv').set('Content-Disposition', 'attachment; filename="ai-preview-leads.csv"').send(['When,Name,Phone,Email,Joined First Dibs,OK to text sales,First couch,Couches tried,Which couches,Times opened link,Last opened,Their room page'].concat(rows).join('\n'));
});
// ===================== END AI ROOM PREVIEW =====================

// The website's Current Inventory page reads this (see /public/inventory.js).
// Website prices during the sale: sale price + the old price + how much off. Back to normal when it ends.
// (Only the website feed. The public order app applies the sale itself, so /public/orderable stays at full price.)
// Black Friday prices shown on the website: the 4 hand-priced couches show their pre-sale price crossed out and their real
// discount; other sectionals/sofas get the $150; chairs and anything else stay full price.
const BF_WAS = { e5da102a0294: 700, '2ffd0f1748de': 1670, cce09a3338ea: 1250, '56153d8a1b15': 930 };
function bfPrice(d) {
  const was = BF_WAS[d.id];
  if (was && saleLive() && was > d.price) return { price: d.price, was, saleOff: was - d.price, saleEnds: new Date(saleShownEnd()).toISOString() };
  if (SALE_SKIP.has(d.id) || !/sectional|sofa|loveseat|sleeper/i.test(d.title || '')) return { price: d.price };
  return salePrice(d.price);
}
function salePrice(p) { const price = Number(p) || 0; if (!saleLive() || !price) return { price }; const off = saleSaved(0, price); return { price: Math.max(price - off, 0), was: price, saleOff: off, saleEnds: new Date(saleShownEnd()).toISOString() }; }
// Will it fit?: every piece of the couch (sofa, loveseat, each modular section). Uses the pieces typed in Drops,
// else a best guess from the Dimensions line. ret = the other side of an L-shaped piece (chaise / corner).
const NUM = '(\\d+(?:\\.\\d+)?)';
function guessPiece(name, t, title) {
  const lab = re => { const m = t.match(new RegExp(re + '\\s*:\\s*' + NUM, 'i')); return m ? parseFloat(m[1]) : null; };
  let w = null, ret = null, dep = lab('\\bD(?:epth)?');
  let pair = t.match(new RegExp(NUM + '\\s*(?:in\\.?)?\\s*[x×]\\s*' + NUM + '(?:\\s*(?:in\\.?)?\\s*[x×]\\s*' + NUM + ')?', 'i'));
  const lw = t.match(new RegExp('\\b(?:L|W|Length|Width)\\s*:\\s*' + NUM, 'i')), sect = /sectional|chaise/i.test(title + ' ' + name);
  if (lw && pair && lw.index < pair.index && Number(lw[1]) !== Number(pair[1])) pair = null;
  if (pair) {
    const nums = [pair[1], pair[2], pair[3]].filter(Boolean).map(Number).sort((a, b) => b - a);
    w = nums[0];
    if (nums.length === 3) { if (sect || /chaise/i.test(t)) ret = nums[1]; else if (!dep) dep = nums[1]; }
    else if (nums[1] >= 55 && sect) ret = nums[1]; else if (!dep) dep = nums[1];
  } else if (lw) w = parseFloat(lw[1]);
  const cd = lab('chaise (?:depth|length)'); let ch = null; if (cd && !ret) ret = cd; else if (cd && cd !== ret) ch = cd;
  if (!w) return null;
  return { name, w, d: dep && dep < 70 ? dep : 38, ret: ret || null, ch: ch || null, cw: ch ? 34 : null, side: /reversible/i.test(title + ' ' + t) ? 'rev' : '', qty: /\beach\b/i.test(name) ? 2 : 1, guess: true };
}
function piecesOf(d) {
  if (Array.isArray(d.pieces) && d.pieces.length) return d.pieces.map(p => ({ ...p, guess: false }));
  const t = String(d.dimensions || ''), title = String(d.title || '');
  // "Sofa: L: 80 | D: 40 Loveseat: L: 58 ..." -> one piece per label
  const parts = t.split(/(?:^|\s)((?!(?:Length|Width|Height|Depth|Chaise|Seat|Arm)\b)(?:[A-Z][a-z]+)(?:\s\(each\))?|Each \w+):\s*(?=(?:L|W|Length|Width)\s*:|\d)/).filter(x => x != null);
  const out = [];
  if (parts.length > 2) for (let i = 1; i < parts.length; i += 2) { const p = guessPiece(parts[i].replace(/\s*\(each\)/i, ' (each)'), parts[i + 1] || '', title); if (p) out.push(p); }
  if (!out.length) { const p = guessPiece(/sectional/i.test(title) ? 'Sectional' : /sofa/i.test(title) ? 'Sofa' : 'Couch', t, title); if (p) out.push(p); }
  return out.map(p => ({ ...p, name: p.name.replace(/\s*\(each\)|^Each\s+/i, '').replace(/s$/, '').replace(/^./, c => c.toUpperCase()) }));
}
app.get('/public/inventory', async (req, res) => {
  dropCors(res);
  try {
    const list = (await getDrops()).filter(d => d.status === 'live');
    // The sizing tool (?fit=1) also gets the brand-new sectionals so people can try them in their room.
    let bnFit = []; if (req.query.fit) { try { const st = await bnGet(); bnFit = BN_PRODUCTS.filter(p => bnCount(st, p.id) < p.units).map(p => ({ id: 'bn-' + p.id, title: p.name.replace(' 5-Piece', '') + ' (Brand New, ' + p.color + ')', price: bnLive() ? p.price : p.launch, retail: 0, pieces: p.pieces, shape: null, photos: ['/public/bn/' + (p.fitPhoto || p.photos[0])] })); } catch {} }
    res.set('Cache-Control', 'public, max-age=30').json({ ok: true, deliveryFee: deliveryFee(), updated: list.reduce((m, d) => Math.max(m, d.updatedAt || 0), 0) || null, couches: bnFit.concat(list.map(d => ({ id: d.id, title: d.title, ...bfPrice(d), retail: d.retail || 0, grade: d.grade || '',
      details: d.details || [], imperfections: d.imperfections || [], dimensions: d.dimensions || '', pieces: piecesOf(d), shape: null, photos: (d.photos || []).map(dropPhotoUrl) }))) });
  } catch (e) { res.status(500).json({ error: 'unavailable' }); }
});
// Public order app (order.billyscouches.com) reads this: everything a customer can buy right now,
// including First Dibs couches that were emailed but aren't on the website yet.
// ?sale=1 (team order app): prices with the live sale already taken off. Without it (public order app), full price.
app.get('/public/orderable', async (req, res) => {
  dropCors(res);
  try {
    const list = (await getDrops()).filter(d => d.status === 'live' || d.status === 'emailed');
    res.set('Cache-Control', 'public, max-age=30').json({ ok: true, couches: list.map(d => ({ id: d.id, title: d.title, ...(req.query.sale === '1' ? bfPrice(d) : { price: d.price }), retail: d.retail || 0, photo: (d.photos || [])[0] ? dropPhotoUrl(d.photos[0]) : '' })) });
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
// ---------- TextMagic "Warm Leads (30 days)" list ----------
// Showings from the last 30 days that canceled, no-showed, or showed and didn't buy. Synced every hour:
// new people are added, anyone past 30 days (or who bought since) is taken off the list.
const WARM_LIST = process.env.TM_WARM_LIST || 'Warm Leads (30 days)';
const tmPhone = v => { const d = String(v || '').replace(/\D/g, ''); return d.length === 10 ? '1' + d : d.length === 11 && d[0] === '1' ? d : ''; };
async function tmApi(method, apiPath, form) {
  const user = (process.env.TEXTMAGIC_USERNAME || '').trim(), key = (process.env.TEXTMAGIC_API_KEY || '').trim();
  if (!user || !key) throw new Error('add TEXTMAGIC_USERNAME + TEXTMAGIC_API_KEY');
  const r = await fetch('https://rest.textmagic.com' + apiPath, { method, headers: { 'X-TM-Username': user, 'X-TM-Key': key, Accept: 'application/json',
    ...(form ? { 'Content-Type': 'application/x-www-form-urlencoded' } : {}) }, body: form ? new URLSearchParams(form).toString() : undefined });
  const j = await r.json().catch(() => ({})); return { ok: r.ok, status: r.status, j };
}
let warmSyncing = false;
async function syncWarmLeads() {
  if (warmSyncing || !CFG.API) return; warmSyncing = true;
  try {
    const g = await google(false), now = Date.now(), from = now - 30 * 864e5, to = now + 30 * 864e5;
    const rows = (g.showings || []).map(([iso, title, color, phone]) => {
      const t = String(title || ''), at = new Date(iso).getTime();
      const status = /cancel/i.test(t) ? 'canceled' : (/no.?show/i.test(t) || color === '8') ? 'noshow' : (color === '2' || color === '10') ? 'bought' : at > now ? 'upcoming' : 'showed';
      return { at, status, phone: tmPhone(phone), name: t.replace(/\(.*?\)/g, '').replace(/^\s*showing\s*(for)?\s*/i, '').trim() };
    }).filter(x => x.phone && !isNaN(x.at));
    const buyers = new Set(rows.filter(x => x.status === 'bought').map(x => x.phone));
    try { Object.values(await getSched()).forEach(o => { const p = tmPhone(o.phone); if (p) buyers.add(p); }); } catch {}
    const want = new Map();
    for (const x of rows) {
      if (buyers.has(x.phone)) continue;
      const inWin = x.status === 'canceled' ? x.at >= from && x.at <= to : (x.status === 'noshow' || x.status === 'showed') && x.at >= from && x.at <= now;
      if (inWin && (!want.has(x.phone) || want.get(x.phone).at < x.at)) want.set(x.phone, x);
    }
    // Will It Fit leads (who didn't opt out of texts and haven't bought) stay on the list too.
    try { ((await kget('bcd:fitLeads', [])) || []).forEach(l => { const phone = tmPhone(l.phone); if (!phone || l.smsOk === false || l.bought || buyers.has(phone) || want.has(phone)) return; want.set(phone, { at: Date.parse(l.at) || now, status: 'fit', phone, name: String(l.name || '') }); }); } catch {}
    const st = await kget('bcd:tmWarm', { listId: null, people: {} });
    if (!st.listId) {
      const f = await tmApi('GET', `/api/v2/lists/search?query=${encodeURIComponent(WARM_LIST)}&limit=50`);
      const hit = ((f.j && f.j.resources) || []).find(l => String(l.name).toLowerCase() === WARM_LIST.toLowerCase());
      st.listId = hit ? hit.id : (await tmApi('POST', '/api/v2/lists', { name: WARM_LIST, shared: '0' })).j.id;
      if (!st.listId) throw new Error('could not create TextMagic list');
    }
    let added = 0, removed = 0;
    for (const [phone, x] of want) {
      if (st.people[phone]) continue;
      const [firstName, ...rest] = x.name.split(/\s+/);
      let c = await tmApi('POST', '/api/v2/contacts', { phone, firstName: firstName || '', lastName: rest.join(' '), lists: String(st.listId) });
      let id = c.ok && c.j.id;
      if (!id) { const f = await tmApi('GET', `/api/v2/contacts/phone/${phone}`); id = f.j && f.j.id;
        if (id) await tmApi('PUT', `/api/v2/lists/${st.listId}/contacts`, { contacts: String(id) }); }
      if (id) { st.people[phone] = { id, at: x.at }; added++; }
      await new Promise(r => setTimeout(r, 800));
    }
    const drop = Object.keys(st.people).filter(p => !want.has(p));
    for (let i = 0; i < drop.length; i += 50) {
      const ids = drop.slice(i, i + 50).map(p => st.people[p].id).join(',');
      const r = await tmApi('DELETE', `/api/v2/lists/${st.listId}/contacts`, { contacts: ids });
      if (r.ok || r.status === 404) drop.slice(i, i + 50).forEach(p => { delete st.people[p]; removed++; });
    }
    st.syncedAt = Date.now(); st.count = Object.keys(st.people).length;
    await kset('bcd:tmWarm', st);
    console.log(`[warm leads] +${added} -${removed} = ${st.count}`);
  } catch (e) { console.log('[warm leads] sync failed:', e.message); }
  finally { warmSyncing = false; }
}
setTimeout(syncWarmLeads, 2 * 60 * 1000); setInterval(syncWarmLeads, 60 * 60 * 1000);
app.get('/api/warm-leads', async (req, res) => { const st = await kget('bcd:tmWarm', {}); res.json({ ok: true, list: WARM_LIST, count: st.count || 0, syncedAt: st.syncedAt || null }); });

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
    const done = [];
    list.forEach(d => { if (!ids.has(d.id) || !['live', 'emailed', 'held'].includes(d.status)) return; d.status = 'sold'; d.soldAt = now; d.updatedAt = now; if (who) d.soldCustomer = who; d.soldVia = 'order app'; delete d.heldFrom; delete d.heldRef; done.push(d); n++; });
    if (n) { await setDrops(list); dropsAt = now; recentCache.at = 0; }
    for (const d of done) { if (d.unitRef) await markUnitSold(d.unitRef, { price: d.price, customer: who }); queueSoldStory(d, who); }
    res.json({ ok: true, marked: n });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// ===================================================================
// UNIT LINKS + PENDING PAYMENTS
// Each website couch can be linked to its exact unit (a B-Stock load unit, or a used/new pickup), so a sale
// marks THAT unit sold. No name guessing, so look-alike couches never get mixed up.
// Orders that aren't paid yet wait in bcd:pending and keep the couch off the website (drop status "held").
// Card checkouts become sales only when Stripe confirms payment (unpaid ones release after 30 minutes).
// Venmo / Zelle / cash / Stripe links wait for ✓ Paid in HQ, with a text nudge after 24 hours.
// ===================================================================
const PEND_KEY = 'bcd:pending', CARD_HOLD_MS = 30 * 60e3, NUDGE_MS = 24 * 3600e3;
const getPending = () => kget(PEND_KEY, []);
const setPending = list => kset(PEND_KEY, list.filter(o => o.status === 'pending' || Date.now() - (o.doneAt || o.at) < 45 * 864e5).slice(0, 400));
async function validUnitRef(r) {
  if (!r || typeof r !== 'object') return null;
  if (r.kind === 'load') { const u = ((await getLoads()).find(l => l.id === String(r.id)) || { units: [] }).units.find(x => x.uid === String(r.uid)); return u ? { kind: 'load', id: String(r.id), uid: String(r.uid) } : null; }
  if (r.kind === 'purchase') { const p = (await getPurchases()).find(x => x.id === String(r.id)); return p ? { kind: 'purchase', id: String(r.id) } : null; }
  return null;
}
// Mark one exact unit sold with the order's price, delivery, add-ons and customer. Returns ok / already / missing.
async function markUnitSold(ref, s) {
  const body = { delivery: s.delivery, upsells: s.upsells || [], customer: s.customer }, today = ctYmd(new Date()), at = new Date().toISOString();
  const apply = x => { x.status = 'sold'; x.soldPrice = Math.max(0, Number(s.price) || 0); x.soldDate = today; x.soldAt = at; saleDetails(x, body, 'sold'); };
  if (ref && ref.kind === 'load') {
    const loads = await getLoads(), u = (loads.find(l => l.id === ref.id) || { units: [] }).units.find(x => x.uid === ref.uid);
    if (!u) return 'missing'; if (u.status === 'sold') return 'already';
    apply(u); await kset(KEYS.loads, loads); return 'ok';
  }
  if (ref && ref.kind === 'purchase') {
    const list = await getPurchases(), p = list.find(x => x.id === ref.id);
    if (!p) return 'missing'; if (p.status === 'sold') return 'already';
    apply(p); await kset(KEYS.purchases, list); return 'ok';
  }
  return 'missing';
}
function holdDrops(list, ids, ref) {
  const now = Date.now(), busy = [];
  list.forEach(d => { if (!ids.includes(d.id)) return;
    if (['live', 'emailed'].includes(d.status)) { d.heldFrom = d.status; d.status = 'held'; d.heldRef = ref; d.updatedAt = now; }
    else if (!(d.status === 'held' && d.heldRef === ref)) busy.push(d.title); });
  return busy;
}
function releaseDrops(list, ref) {
  const now = Date.now(); let n = 0;
  list.forEach(d => { if (d.status !== 'held' || d.heldRef !== ref) return; d.status = d.heldFrom || 'live'; delete d.heldFrom; delete d.heldRef; d.updatedAt = now; n++; });
  return n;
}
const pendTitles = o => (o.items || []).map(i => i.title).filter(Boolean).join(' + ') || 'their couch';
const money = n => '$' + (Number(n) || 0).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
// The order is paid: couch(es) sold on the website, exact unit(s) sold in the Sales Tracker, Sales Log row(s) added.
async function finalizeOrder(o, via) {
  const list = await getDrops(), now = Date.now(), unlinked = [], clash = [];
  const sold = [];
  (o.items || []).forEach(it => {
    const d = list.find(x => x.id === it.dropId);
    if (!d) { if (it.dropId) unlinked.push(it.title || 'a couch'); return; }   // no dropId = couch that was never on the website
    if (d.status === 'sold' && d.soldRef && d.soldRef !== o.ref) clash.push(d.title);
    else if (d.status !== 'sold' || !d.soldRef) { d.status = 'sold'; d.soldAt = now; d.updatedAt = now; d.soldVia = via; d.soldRef = o.ref; if (o.customer) d.soldCustomer = o.customer; delete d.heldFrom; delete d.heldRef; }
    sold.push({ it, d });
  });
  await setDrops(list); dropsAt = now; recentCache.at = 0;
  for (let i = 0; i < sold.length; i++) {
    const { it, d } = sold[i];
    if (clash.includes(d.title)) continue;
    const r = d.unitRef ? await markUnitSold(d.unitRef, { price: it.price, customer: o.customer,
      delivery: i === 0 ? o.delivery : 0, upsells: i === 0 ? o.addons : [] }) : 'missing';
    if (r === 'missing') unlinked.push(d.title);
    queueSoldStory(d, o.customer);
  }
  if (!o.logged && (o.rowIds || []).length) {
    try { const r = await fetch(SCHED_PROXY + '/log-sale', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ids: o.rowIds }), signal: AbortSignal.timeout(15000) });
      const j = await r.json().catch(() => ({})); o.logged = !!(j && j.success); } catch (e) { console.log('log-sale failed', e.message); }
    if (!o.logged) textAlert(`⚠️ ${o.customer || 'An order'} paid for ${pendTitles(o)} but it didn't reach the Sales Log. Add it by hand.`).catch(() => {});
  }
  o.status = 'paid'; o.doneAt = now; o.paidVia = via; o.unlinked = unlinked; o.clash = clash;
  if (unlinked.length) textAlert(`⚠️ Sold online, not linked: ${unlinked.join(', ')} (${o.customer || 'customer'}). Mark its exact unit Sold in HQ > Sales Tracker.`).catch(() => {});
  if (clash.length) textAlert(`🚨 ${o.customer || 'A customer'} paid for ${clash.join(', ')} but it was already sold to someone else. Refund or swap them.`).catch(() => {});
  return o;
}
const cleanOrder = b => {
  const items = (Array.isArray(b.items) ? b.items : []).slice(0, 10).map(i => ({ dropId: String(i.dropId || '').slice(0, 40), title: clean(i.title, 120), price: Math.max(0, Number(i.price) || 0) })).filter(i => i.dropId || i.title);
  return { ref: clean(b.ref, 60) || crypto.randomBytes(6).toString('hex'), at: Date.now(), source: b.source === 'team' ? 'team' : 'website',
    payment: clean(b.payment, 40), kind: ['card', 'manual', 'link', 'paid'].includes(b.kind) ? b.kind : 'manual', plink: /^plink_\w+$/.test(b.plink || '') ? b.plink : '',
    customer: clean(b.customer, 60), phone: clean(b.phone, 20), orderType: clean(b.orderType, 40), total: Math.max(0, Number(b.total) || 0),
    delivery: Math.max(0, Number(b.delivery) || 0), addons: (Array.isArray(b.addons) ? b.addons : []).slice(0, 10).map(a => ({ label: clean(a.label, 40), price: Math.max(0, Number(a.price) || 0) })).filter(a => a.label && a.price),
    items, rowIds: (Array.isArray(b.rowIds) ? b.rowIds : []).map(String).filter(x => /^\d+-[a-z0-9]+$/.test(x)).slice(0, 10), logged: !!b.logged, status: 'pending' };
};
// Order apps: an order was placed. kind "paid" (team took payment in person) = sold right away; anything else waits.
app.options('/public/order-hold', (req, res) => { orderCors(req, res); res.sendStatus(204); });
app.post('/public/order-hold', async (req, res) => {
  if (!orderCors(req, res)) return res.status(403).json({ error: 'forbidden' });
  try {
    const o = cleanOrder(req.body || {}); if (!o.items.length) return res.status(400).json({ error: 'No couches' });
    const pend = await getPending(); const old = pend.find(x => x.ref === o.ref);
    if (old && old.status !== 'pending') return res.json({ ok: true, status: old.status });
    if (old) pend.splice(pend.indexOf(old), 1);
    // Change payment (order app): this order replaces one sent a few minutes ago. Same couches, so the old order's
    // hold / sale moves over to the new one instead of clashing. The old order is marked "replaced" (kept, not deleted).
    const rep = clean((req.body || {}).replaces, 60), prev = rep && pend.find(x => x.ref === rep && x.source === 'team' && x.status !== 'replaced');
    if (prev) {
      const list = await getDrops(), now = Date.now();
      list.forEach(d => {
        if (d.status === 'held' && d.heldRef === prev.ref) { d.heldRef = o.ref; d.updatedAt = now; }
        else if (d.status === 'sold' && d.soldRef === prev.ref) {
          if (o.kind === 'paid') d.soldRef = o.ref;
          else { d.status = 'held'; d.heldFrom = 'live'; d.heldRef = o.ref; delete d.soldRef; delete d.soldAt; delete d.soldVia; delete d.soldCustomer; }
          d.updatedAt = now;
        }
      });
      await setDrops(list); dropsAt = now; recentCache.at = 0;
      prev.status = 'replaced'; prev.doneAt = now; prev.replacedBy = o.ref; o.replaces = prev.ref;
    }
    if (o.kind === 'paid') { await finalizeOrder(o, o.source === 'team' ? 'order app' : 'website'); pend.unshift(o); await setPending(pend); return res.json({ ok: true, status: 'paid' }); }
    const list = await getDrops(); o.busy = holdDrops(list, o.items.map(i => i.dropId), o.ref); await setDrops(list); dropsAt = Date.now(); recentCache.at = 0;
    pend.unshift(o); await setPending(pend);
    res.json({ ok: true, status: 'pending' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// Public order app's Stripe webhook: the customer paid. HQ double-checks the Checkout session with Stripe (via the proxy).
app.options('/public/order-paid', (req, res) => { orderCors(req, res); res.sendStatus(204); });
app.post('/public/order-paid', async (req, res) => {
  orderCors(req, res);
  try {
    const id = String((req.body || {}).session || ''); if (!/^cs_\w+$/.test(id)) return res.status(400).json({ error: 'bad session' });
    const r = await fetch(SCHED_PROXY + '/stripe-session', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id }), signal: AbortSignal.timeout(15000) });
    const s = await r.json().catch(() => ({}));
    if (!s.paid || !s.link) return res.json({ ok: false, reason: 'not paid' });
    const pend = await getPending(), o = pend.find(x => x.plink === s.link);
    if (!o) return res.json({ ok: false, reason: 'no matching order' });
    if (o.status === 'paid') return res.json({ ok: true, status: 'paid' });
    if (o.status === 'replaced') { textAlert(`⚠️ ${o.customer || 'A customer'} paid an OLD card link (${money(o.total)}) after their payment was changed. Check they didn't pay twice.`).catch(() => {}); return res.json({ ok: false, reason: 'replaced' }); }
    await finalizeOrder(o, 'website card'); await setPending(pend);
    res.json({ ok: true, status: 'paid' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/pending', async (req, res) => {
  try { const pend = await getPending(), wk = Date.now() - 7 * 864e5;
    res.json({ ok: true, pending: pend.filter(o => o.status === 'pending'), alerts: pend.filter(o => o.status === 'paid' && !o.ack && (o.doneAt || 0) > wk && ((o.unlinked || []).length || (o.clash || []).length)) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/pending/paid', async (req, res) => {
  try { const pend = await getPending(), o = pend.find(x => x.ref === String(req.body.ref || '') && x.status === 'pending'); if (!o) return res.status(404).json({ error: 'Order not found' });
    await finalizeOrder(o, 'marked paid in HQ'); await setPending(pend); res.json({ ok: true, order: o });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/pending/release', async (req, res) => {
  try { const pend = await getPending(), o = pend.find(x => x.ref === String(req.body.ref || '') && x.status === 'pending'); if (!o) return res.status(404).json({ error: 'Order not found' });
    const list = await getDrops(); releaseDrops(list, o.ref); await setDrops(list); dropsAt = Date.now(); recentCache.at = 0;
    o.status = 'released'; o.doneAt = Date.now(); await setPending(pend); res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// ---------- Follow up: abandoned quotes (sent by the order site) + orders that never got paid ----------
// Shows in HQ > Sales Tracker under Today's deliveries, each with a one-tap prefilled text for Billy to send himself.
const ABAND_KEY = 'bcd:abandons', FU_KEY = 'bcd:followups';
app.options('/public/abandon', (req, res) => { orderCors(req, res); res.sendStatus(204); });
app.post('/public/abandon', async (req, res) => {
  if (!orderCors(req, res)) return res.status(403).json({ error: 'forbidden' });
  try {
    const b = req.body || {}, phone = String(b.phone || '').replace(/\D/g, '').slice(-10); if (phone.length !== 10) return res.status(400).json({ error: 'phone' });
    const list = (await kget(ABAND_KEY, [])) || [], id = 'a' + (clean(b.rid, 20).replace(/\W/g, '') || phone);
    const rec = { id, phone, name: clean(b.name, 60), couches: (Array.isArray(b.couches) ? b.couches : []).slice(0, 6).map(c => ({ name: clean(c && c.name, 120), price: Number(c && c.price) || 0 })),
      total: Number(b.total) || 0, orderType: clean(b.orderType, 20), zip: clean(b.zip, 10), source: clean(b.source, 60), at: Number(b.at) || Date.now(),
      link: /^https:\/\/order\.billyscouches\.com\//.test(b.link || '') ? String(b.link).slice(0, 200) : '' };
    const old = list.findIndex(x => x.id === id || (x.phone === phone && Date.now() - x.at < 864e5));
    if (old >= 0) list.splice(old, 1, { ...list[old], ...rec }); else list.unshift(rec);
    await kset(ABAND_KEY, list.filter(x => Date.now() - x.at < 14 * 864e5).slice(0, 200)); res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/followups', async (req, res) => {
  try {
    const now = Date.now(), since = now - 7 * 864e5, st = (await kget(FU_KEY, {})) || {}, pend = await getPending(), ab = (await kget(ABAND_KEY, [])) || [];
    const d10 = p => String(p || '').replace(/\D/g, '').slice(-10), paid = new Set(pend.filter(o => o.status === 'paid').map(o => d10(o.phone)));
    const first = n => { const f = String(n || '').trim().split(/\s+/)[0] || 'there'; return f.charAt(0).toUpperCase() + f.slice(1).toLowerCase(); };
    const items = [];
    pend.filter(o => o.at > since && d10(o.phone).length === 10 && (o.status === 'expired' || (o.status === 'pending' && o.kind !== 'card' && now - o.at > 2 * 3600e3))).forEach(o => {
      const ph = d10(o.phone); if (paid.has(ph)) return;
      const couch = (o.items || []).length === 1 ? 'the ' + o.items[0].title : 'your couches';
      items.push({ id: 'o' + o.ref, kind: 'unpaid', at: o.at, name: o.customer || '', phone: ph, what: pendTitles(o), total: o.total, detail: o.status === 'expired' ? 'card checkout' : (o.payment || 'pay later'),
        text: `Hey ${first(o.customer)}, it's Billy from Billy's Couches. Looks like your order for ${couch} didn't go through. Want me to send a new checkout link, or is Venmo/Zelle easier?` }); });
    ab.filter(a => a.at > since && !paid.has(a.phone)).forEach(a => {
      const couch = a.couches.length === 1 ? 'the ' + a.couches[0].name : 'those couches';
      items.push({ id: a.id, kind: 'abandoned', at: a.at, name: a.name, phone: a.phone, what: a.couches.map(c => c.name).join(' + '), total: a.total, detail: /deliver/i.test(a.orderType) ? 'delivery ' + a.zip : 'pickup',
        text: `Hey ${first(a.name)}, it's Billy from Billy's Couches. Saw you were looking at ${couch}. Any questions I can answer? Happy to hold it for you or set up a time to come sit on it.` }); });
    const seen = new Set();   // same person on both lists: keep the unpaid order (it comes first)
    const out = items.filter(x => { if (seen.has(x.phone)) return false; seen.add(x.phone); return true; }).filter(x => !(st[x.id] || {}).hidden)
      .map(x => ({ ...x, texted: (st[x.id] || {}).texted || null })).sort((a, b) => b.at - a.at);
    res.json({ ok: true, items: out });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/followups/mark', async (req, res) => {
  try { const b = req.body || {}, id = clean(b.id, 80), st = (await kget(FU_KEY, {})) || {}; if (!id) return res.status(400).json({ error: 'id' });
    st[id] = { ...(st[id] || {}), ...(b.hide ? { hidden: Date.now() } : { texted: Date.now() }) };
    Object.keys(st).forEach(k => { const t = st[k].hidden || st[k].texted || 0; if (Date.now() - t > 30 * 864e5) delete st[k]; });
    await kset(FU_KEY, st); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/pending/ack', async (req, res) => {
  try { const pend = await getPending(), o = pend.find(x => x.ref === String(req.body.ref || '')); if (o) { o.ack = true; await setPending(pend); } res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
// Every 5 minutes: unpaid card checkouts go back on the website after 30 minutes; manual payments get one nudge at 24 hours.
async function pendingSweep() {
  const pend = await getPending(), now = Date.now(); let dirty = false, list = null;
  for (const o of pend) {
    if (o.status !== 'pending') continue;
    if (o.kind === 'card' && now - o.at > CARD_HOLD_MS) {
      list = list || await getDrops(); releaseDrops(list, o.ref); o.status = 'expired'; o.doneAt = now; dirty = true;
    } else if (o.kind !== 'card' && !o.nudged && now - o.at > NUDGE_MS) {
      o.nudged = now; dirty = true;
      await textAlert(`⏰ ${o.customer || 'A customer'} still hasn't paid for ${pendTitles(o)} (${money(o.total)}, ${o.payment || 'pay later'}). It's been held off the site for 24 hrs. Mark Paid or Release in HQ.`).catch(() => {});
    }
  }
  if (list) { await setDrops(list); dropsAt = now; recentCache.at = 0; }
  if (dirty) await setPending(pend);
}
setInterval(() => pendingSweep().catch(e => console.log('Pending sweep failed', e.message)), 5 * 60 * 1000);
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
// Holding: free for 5 days after purchase, then $20 a day. Orders placed before this went live keep the old free hold.
const HOLD_FREE_DAYS = 5, HOLD_RATE = 20, HOLD_START = Date.parse('2026-11-08T12:00:00-06:00');
const dayDiff = (a, b) => Math.round((Date.parse(a + 'T12:00:00Z') - Date.parse(b + 'T12:00:00Z')) / 864e5);
function holdInfo(o) {
  if (o.noHold || !o.created || o.created < HOLD_START) return { applies: false };
  const freeUntil = ctYmd(new Date(o.created + HOLD_FREE_DAYS * 864e5));
  return { applies: true, freeUntil, rate: HOLD_RATE, freeDays: HOLD_FREE_DAYS,
    freeLabel: new Date(freeUntil + 'T12:00:00Z').toLocaleDateString('en-US', { weekday: 'long', month: 'short', day: 'numeric', timeZone: 'UTC' }) };
}
const holdDaysFor = (o, date) => { const h = holdInfo(o); return h.applies ? Math.max(0, dayDiff(date, h.freeUntil)) : 0; };
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
// 30-day check-in: a text from Billy 30 days after the booked delivery / pick up date. Sent once, 10am-6pm Central. CHECKIN=off in Railway turns it off.
async function sendText(phone, text) {
  const user = (process.env.TEXTMAGIC_USERNAME || '').trim(), key = (process.env.TEXTMAGIC_API_KEY || '').trim();
  let d = String(phone || '').replace(/\D/g, ''); if (d.length === 10) d = '1' + d;
  if (!user || !key || d.length !== 11) return false;
  const r = await fetch('https://rest.textmagic.com/api/v2/messages', { method: 'POST', headers: { 'X-TM-Username': user, 'X-TM-Key': key, 'Content-Type': 'application/json' }, body: JSON.stringify({ text, phones: d }) });
  if (!r.ok) { console.error('TextMagic', r.status, await r.text()); return false; }
  return true;
}
async function checkinTexts() {
  if (process.env.CHECKIN === 'off') return;
  const hr = Number(new Date().toLocaleString('en-US', { timeZone: 'America/Chicago', hour: 'numeric', hour12: false }));
  if (hr < 10 || hr >= 18) return;
  const today = new Date().toLocaleDateString('en-CA', { timeZone: 'America/Chicago' }), m = await getSched(); let changed = false;
  for (const o of Object.values(m)) {
    const b = o.booking; if (!b || !b.date || o.checkinSent) continue;
    const due = new Date(b.date + 'T12:00:00'); due.setDate(due.getDate() + 30); const dueStr = due.toLocaleDateString('en-CA');
    if (dueStr > today) continue;
    if ((Date.parse(today) - Date.parse(dueStr)) / 864e5 > 14) { o.checkinSent = 'skipped-old'; changed = true; continue; }   // never blast old orders
    const first = String(o.name || '').trim().split(/\s+/)[0] || 'there', name = first.charAt(0).toUpperCase() + first.slice(1).toLowerCase();
    const ok = await sendText(b.phone || o.phone, `Hi ${name}, it's Billy with Billy's Couches. Just wanted to check in and see how the couch has been! If there are any issues, don't hesitate to reach out.`);
    if (ok) { o.checkinSent = new Date().toISOString(); changed = true; }
  }
  if (changed) await setSched(m);
}
setInterval(() => checkinTexts().catch(e => console.log('Check-in texts failed', e.message)), 60 * 60 * 1000);
// No-show text: put "(No show)" in a showing's title on the calendar and HQ texts that customer (checks every 5 min,
// 9am-8pm CT, once per showing). Only showings from the last 2 days count. NOSHOW_TEXT=off turns it off.
async function noShowTexts() {
  if ((process.env.NOSHOW_TEXT || '').toLowerCase() === 'off' || !cache.data) return;
  const rows = (cache.data.showings || []).filter(r => /\(\s*no[\s-]?show/i.test(r[1] || '') && String(r[3] || '').replace(/\D/g, '').length >= 10);
  const sent = (await kget('bcd:noShowSent', null)) || null, now = Date.now(), key = r => r[0] + '|' + String(r[3]).replace(/\D/g, '').slice(-10);
  if (!sent) { await kset('bcd:noShowSent', rows.map(key)); return; }   // first run: don't text anyone already marked before this was turned on
  const hr = Number(new Date().toLocaleString('en-US', { timeZone: 'America/Chicago', hour: 'numeric', hour12: false }));
  if (hr < 9 || hr >= 20) return;
  const today = new Date().toLocaleDateString('en-CA', { timeZone: 'America/Chicago' }); let changed = false;
  for (const r of rows) {
    const k = key(r), t = Date.parse(r[0]); if (sent.includes(k) || !t || t > now || now - t > 2 * 864e5) continue;
    const raw = String(r[1] || '').replace(/\(.*?\)/g, '').replace(/^\s*showing\s*(for)?\s*/i, '').trim().split(/\s+/)[0] || '';
    const name = raw && /^[a-z'-]+$/i.test(raw) ? raw.charAt(0).toUpperCase() + raw.slice(1).toLowerCase() : 'there';
    const when = new Date(t).toLocaleDateString('en-CA', { timeZone: 'America/Chicago' }) === today ? 'today' : 'yesterday';
    const ok = await sendText(r[3], `Hi ${name}, it's Billy with Billy's Couches. Looks like we missed you at the showroom ${when}, no worries! Want to pick another time to come check them out? You can grab a new time here: billyscouches.com/visitshowroom`);
    sent.push(k); changed = true; if (!ok) console.log('No-show text failed for', k);
  }
  if (changed) await kset('bcd:noShowSent', sent.slice(-500));
}
setInterval(() => noShowTexts().catch(e => console.log('No-show texts failed', e.message)), 5 * 60 * 1000);
setTimeout(() => noShowTexts().catch(() => {}), 90 * 1000);
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
  // A customer link can be opened further out (o.until, set from HQ) than the normal booking window.
  const own = skipToken && sched[skipToken], lastDay = own && own.until ? Math.max(cfg.maxDays || 14, dayDiff(own.until, ctYmd(new Date()))) : (cfg.maxDays || 14);
  for (let i = 0; i <= lastDay; i++) {
    const ymd = ctYmd(new Date(now + i * 864e5)); if (blocked.has(ymd)) continue;
    const dow = new Date(ymd + 'T12:00:00Z').getUTCDay(), d = conf[dow]; if (!d || !d.on) continue;
    // Pick ups: the windows are open hours, split into 30-minute times (slotMins in the settings).
    const step = kind === 'pickup' ? Number((cfg.pickup || {}).slotMins) || 30 : 0;
    const wins = step ? (d.win || []).flatMap(w => { const p = parseWin(w); if (!p) return []; const out = []; for (let t = p[0]; t + step <= p[1]; t += step) { const a = t, b = t + step, f = m => Math.floor(m / 60) + (m % 60 ? ':' + String(m % 60).padStart(2, '0') : ''); out.push(f(a) + '-' + f(b)); } return out; }) : (d.win || []);
    const slots = wins.map(w => { const p = parseWin(w); if (!p) return null; const s = ctAt(ymd, p[0]).getTime(), e = ctAt(ymd, p[1]).getTime();
      if (s - now < (cfg.noticeHours || 0) * 3600e3) return null;
      // HQ can open one full window for one customer (o.allow: ['2026-11-24|16-18']) without opening it for everyone.
      const used = busy.filter(b => b.s < e && b.e > s).length, left = own && (own.allow || []).includes(ymd + '|' + w) ? Math.max(1, (d.cap || 1) - used) : Math.max(0, (d.cap || 1) - used);
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
    // Sizing tool lead bought? Mark it so the leads sheet shows which signups turned into sales.
    const ph = m[token].phone; if (ph.length === 10) kget('bcd:fitLeads', []).then(async L => { const l = (L || []).find(x => x.phone === ph && !x.bought); if (l) { l.bought = new Date().toISOString(); await kset('bcd:fitLeads', L); } }).catch(() => {});
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/s/:token', (req, res) => res.sendFile(path.join(__dirname, 'schedule.html')));
// Employee Check-in (replaces the Jotform): public form at /checkin, answers saved in bcd:checkins, shown on the Employees tab.
app.get('/checkin', (req, res) => res.set('Cache-Control', 'no-cache').sendFile(path.join(__dirname, 'checkin.html')));
app.post('/public/checkin', async (req, res) => {
  try {
    const b = req.body || {};
    const tx = (k, n = 1500) => String(b[k] || '').trim().slice(0, n);
    const sc = k => { const n = parseInt(b[k], 10); return n >= 1 && n <= 5 ? n : null; };
    const first = tx('first', 40), last = tx('last', 40);
    if (!first) return res.status(400).json({ error: 'Please enter your name.' });
    const s = { pay: sc('pay'), work: sc('work'), train: sc('train'), supp: sc('supp'), stay: sc('stay') };
    if (Object.values(s).some(x => x == null)) return res.status(400).json({ error: 'Please answer every 1-5 question.' });
    const e = { id: crypto.randomBytes(6).toString('hex'), at: Date.now(), first, last, ...s, timeTask: tx('timeTask'), change: tx('change'), overall: tx('overall'), problems: tx('problems'), stress: tx('stress') };
    const list = (await kget('bcd:checkins', [])) || [];
    list.unshift(e);
    await kset('bcd:checkins', list.slice(0, 1000));
    res.json({ ok: true });
  } catch (e) { console.error('checkin failed', e.message); res.status(500).json({ error: 'Something went wrong. Please text Billy.' }); }
});
app.post('/api/checkins/hide', async (req, res) => {
  try { const list = (await kget('bcd:checkins', [])) || [], e = list.find(x => x.id === String(req.body.id || '')); if (!e) return res.status(404).json({ error: 'Not found' }); e.hidden = req.body.hidden !== false; await kset('bcd:checkins', list); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/checkins', async (req, res) => {
  try { res.json({ ok: true, checkins: (await kget('bcd:checkins', [])) || [] }); } catch (e) { res.status(500).json({ error: e.message }); }
});
// One link for everyone (the old Jotform points here): type your phone, we text you your own scheduling link.
// Never shows order details on the page, so a stranger typing someone's number learns nothing.
const findHits = new Map();
app.get('/schedule', (req, res) => res.set('Cache-Control', 'no-store').send(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Schedule your delivery · Billy's Couches</title><style>body{margin:0;background:#f6f2ee;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;color:#2b1d16}
.w{max-width:440px;margin:0 auto;padding:40px 20px}img{height:52px}h1{font-size:26px;margin:22px 0 8px}p{color:#6b5d55;line-height:1.5;margin:0 0 18px}
input{width:100%;box-sizing:border-box;font:inherit;font-size:20px;padding:14px;border:2px solid #e0d5ca;border-radius:14px;background:#fff}
button{width:100%;margin-top:12px;font:inherit;font-size:17px;font-weight:700;padding:15px;border:0;border-radius:999px;background:#b0524c;color:#fff;cursor:pointer}
button:disabled{opacity:.6}.ok{background:#e3efe6;color:#2e6b45;border-radius:14px;padding:14px;margin-top:14px;display:none;line-height:1.5}a{color:#b0524c}</style></head><body><div class="w">
<img src="/logo.png" alt="Billy's Couches"><h1>Schedule your delivery or pick up</h1><p>Type the phone number you used when you bought your couch. We'll text you your own link to pick a time.</p>
<form id="f"><input id="ph" type="tel" inputmode="tel" autocomplete="tel" placeholder="(314) 555-1234" required><button id="b">Text me my link</button></form>
<div class="ok" id="ok"></div><p style="margin-top:22px;font-size:14px">Questions? Text Billy at <a href="sms:+13148997503">(314) 899-7503</a></p></div>
<script>document.getElementById('f').onsubmit=async function(e){e.preventDefault();var b=document.getElementById('b'),ok=document.getElementById('ok');b.disabled=true;
try{var r=await fetch('/public/sched-find',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({phone:document.getElementById('ph').value})});var j=await r.json();ok.textContent=j.msg||j.error||'Done.';}
catch(x){ok.textContent='Something went wrong. Text Billy at (314) 899-7503.';}ok.style.display='block';b.disabled=false;};</script></body></html>`));
app.post('/public/sched-find', async (req, res) => {
  try {
    const ip = clientIp(req), now = Date.now(), h = (findHits.get(ip) || []).filter(x => now - x < 3600e3);
    if (h.length >= 6) return res.status(429).json({ error: 'Too many tries. Text Billy at (314) 899-7503.' }); h.push(now); findHits.set(ip, h);
    const phone = String((req.body || {}).phone || '').replace(/\D/g, '').replace(/^1(\d{10})$/, '$1');
    if (phone.length !== 10) return res.status(400).json({ error: 'Add your 10-digit phone number.' });
    const m = await getSched(), mine = Object.values(m).filter(o => o.phone === phone).sort((a, b) => (b.created || 0) - (a.created || 0));
    const o = mine.find(x => !x.booking) || mine[0];
    if (o) await sendText(phone, `Hi ${o.name.split(/\s+/)[0]}! Here's your link to pick your ${o.type === 'pickup' ? 'pick up' : 'delivery'} time: ${schedLink(o.token)}`).catch(() => false);
    else textAlert(`Someone tried to schedule from the old link with ${phone}, but there's no order under that number. Send them a link from HQ > Scheduling.`).catch(() => {});
    res.json({ ok: true, msg: o ? 'Done! We just texted your scheduling link. Tap it to pick your time.' : "We couldn't find an order under that number yet. Billy will text you your link shortly, or text him at (314) 899-7503." });
  } catch (e) { res.status(500).json({ error: 'Something went wrong. Text Billy at (314) 899-7503.' }); }
});
// Customers can move their own booking until 24 hours before the window starts; after that they text Billy.
const MOVE_LOCK_HRS = 24;
const moveLocked = o => { const b = o.booking; if (!b || !b.date) return false; const w = parseWin(b.win); if (!w) return false; return ctAt(b.date, w[0]).getTime() - Date.now() < MOVE_LOCK_HRS * 3600e3; };
const schedPublic = (o, days) => ({ name: o.name, first: o.name.split(/\s+/)[0], phone: o.phone, type: o.type, couches: o.couches, addons: o.addons, zip: o.zip,
  booking: o.booking ? { date: o.booking.date, win: o.booking.win, label: o.booking.label, address: o.booking.address, city: o.booking.city, zip: o.booking.zip, room: o.booking.room, notes: o.booking.notes, extras: o.booking.extras || [], locked: moveLocked(o) } : null,
  upsells: SCHED_ADDONS.filter(a => !(a.deliveryOnly && o.type !== 'delivery') && !o.addons.some(x => a.match.test(x)) && !((o.booking && o.booking.extras) || []).some(x => a.match.test(x))).map(({ id, label, price, pitch }) => ({ id, label, price, pitch })),
  days, taxRate: SCHED_TAX, feeRate: SCHED_FEE, hold: { ...holdInfo(o), paidDays: o.holdPaidDays || 0 } });
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
// ---------- Customer Database tab (Google Sheet) ----------
// Every scheduled delivery/pickup is added as a row. The order proxy has the Google
// login, so HQ hands it the rows. Needs SIGN_FEED_KEY in HQ = the proxy's SIGN_FEED_KEY.
function custRow(o) {
  const b = o.booking || {}, isDel = o.type === 'delivery';
  return { at: b.at || o.created || Date.now(), name: o.name, email: b.email || '', phone: fmtPhone(b.phone || o.phone || ''),
    street: isDel ? b.address || '' : '', city: isDel ? b.city || '' : '', state: isDel ? 'MO' : '', zip: isDel ? b.zip || '' : '',
    couch: o.couches.map(c => c.title).join(' + ') };
}
async function pushCustomers(rows) {
  if (!rows.length) return;
  const key = process.env.SIGN_FEED_KEY; if (!key) throw new Error('Set SIGN_FEED_KEY in HQ (same value as the proxy)');
  const r = await fetch(SCHED_PROXY + '/api/customer', { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-sign-key': key }, body: JSON.stringify({ rows }) });
  const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.error || 'proxy ' + r.status);
}
// One-time: add everyone who already booked on the new scheduling form.
setTimeout(async () => {
  try { if (await kget('bcd:custBackfill', null)) return;
    const rows = Object.values(await getSched()).filter(o => o.booking && o.booking.date).sort((a, b) => (a.booking.at || 0) - (b.booking.at || 0)).map(custRow);
    await pushCustomers(rows); await kset('bcd:custBackfill', { at: Date.now(), n: rows.length }); console.log('Customer Database backfill:', rows.length);
  } catch (e) { console.log('Customer Database backfill waiting:', e.message); }
}, 20000);
app.post('/public/sched/:token', async (req, res) => {
  try {
    const m = await getSched(), o = m[String(req.params.token)]; if (!o) return res.status(404).json({ error: 'This link has expired. Text us at (314) 899-7503.' });
    const b = req.body || {}, date = clean(b.date, 10), win = clean(b.win, 12);
    if (moveLocked(o)) return res.status(409).json({ error: 'Your time is less than 24 hours away, so it can\'t be moved online. Text Billy at (314) 899-7503.' });
    const days = await openSlots(o.type, o.token), day = days.find(d => d.date === date), slot = day && day.slots.find(s => s.win === win);
    if (!slot || slot.left < 1) return res.status(409).json({ error: 'That time just filled up. Please pick another.', days });
    const isDel = o.type === 'delivery', address = clean(b.address, 120), city = clean(b.city, 60), zip = clean(b.zip, 10).replace(/[^\d]/g, '');
    if (isDel && (!address || !city || zip.length !== 5)) return res.status(400).json({ error: 'Add your full address and ZIP code.' });
    const phone = String(b.phone || o.phone || '').replace(/\D/g, '').slice(-10) || o.phone;
    const email = clean(b.email, 160).toLowerCase();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
    const offered = schedPublic(o, []).upsells, extrasNew = offered.filter(a => (b.extras || []).includes(a.id));
    const prev = o.booking || {}, w = parseWin(win), start = ctAt(date, w[0]), end = ctAt(date, w[1]);
    const extras = [...(prev.extras || []), ...extrasNew.map(a => a.label)];
    const room = clean(b.room, 80), notes = clean(b.notes, 300), couch = o.couches.map(c => c.title).join(' + ');
    const allAdds = [...o.addons, ...extras];
    const holdDays = holdDaysFor(o, date), holdNew = Math.max(0, holdDays - (o.holdPaidDays || 0)), holdFee = holdNew * HOLD_RATE;
    const desc = [`Phone Number:`, fmtPhone(phone), `Address:`, isDel ? `${address}, ${city}, MO, ${zip}` : 'Pickup at warehouse', `Pick up or Delivery? :`, isDel ? 'Delivery' : 'Pick up', '',
      `Couch: ${couch}`, `Add-ons: ${allAdds.length ? allAdds.join(', ') : 'None'}`, room ? `Room: ${room}` : '', notes ? `Notes: ${notes}` : '',
      extrasNew.length ? `Added when scheduling: ${extrasNew.map(a => a.label).join(', ')} (paid by card link)` : '',
      holdDays ? `Holding fee: ${holdDays} day${holdDays > 1 ? 's' : ''} past the free ${HOLD_FREE_DAYS} ($${holdDays * HOLD_RATE})${holdFee ? ' - paid by card link' : ''}` : '',
      ...(o.couches || []).filter(c => c && c.photo).map((c, i, all) => all.length > 1 ? `Photo ${i + 1}: ${c.photo}` : `Photo: ${c.photo}`)].filter(x => x !== '').join('\n');
    const row = [new Date().toLocaleDateString('en-US', { timeZone: 'America/Chicago' }), o.name, fmtPhone(phone), isDel ? address : '', isDel ? city : '', isDel ? zip : '', isDel ? 'Delivery' : 'Pickup', couch, allAdds.join(', '), `${date} ${winLabel(win)}`, o.from || 'Order app'];
    const j = await sheetsBook({ eventId: prev.eventId || '', title: `${isDel ? 'Delivery' : 'Pick up'} for ${o.name}`, start: start.toISOString(), end: end.toISOString(),
      location: isDel ? `${address}, ${city}, MO ${zip}` : '126 E Orleans St, Pacific, MO 63069', desc, photo: (o.couches[0] && o.couches[0].photo) || '', photoName: (couch || 'couch').replace(/[^\w -]/g, '').slice(0, 60) + '.jpg', row: JSON.stringify(row) });
    // Card link for anything they added now (couch + tax + 3% card fee), made by the order proxy like the team app does.
    let payUrl = '', due = 0;
    if (extrasNew.length || holdFee) {
      const sub = extrasNew.reduce((a, x) => a + x.price, 0), tax = Math.round(sub * SCHED_TAX) / 100; due = Math.round((sub + tax + holdFee) * (1 + SCHED_FEE) * 100) / 100;
      try { const r = await fetch(SCHED_PROXY + '/create-stripe-link', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ customerName: o.name, orderType: [extrasNew.length ? 'Add-ons: ' + extrasNew.map(a => a.label).join(', ') : '', holdFee ? `Holding fee (${holdNew} day${holdNew > 1 ? 's' : ''} x $${HOLD_RATE})` : ''].filter(Boolean).join(' + '), totalCents: Math.round(due * 100), totalDisplay: '$' + due.toFixed(2), redirectUrl: schedLink(o.token) + '?paid=1' }) });
        const d = await r.json(); payUrl = d.url || ''; } catch (e) { console.log('Add-on pay link failed', e.message); }
    }
    o.booking = { date, win, label: `${day.label} · ${slot.label}`, address, city, zip, room, notes, phone, email, why: clean(b.why, 300) || prev.why || '', extras, eventId: j.eventId || prev.eventId || '', at: Date.now(), moved: !!prev.date, photoAttached: !!j.attached };
    if (extrasNew.length || holdFee) o.extraDue = (o.extraDue || 0) + due;
    if (holdFee) o.holdPaidDays = holdDays;
    m[o.token] = o; await setSched(m);
    cache.at = 0;   // so the next HQ load re-reads the calendar
    if (!prev.date) pushCustomers([custRow(o)]).catch(e => console.log('Customer Database add failed', e.message));
    textAlert(`${prev.date ? 'RESCHEDULED' : 'BOOKED'}: ${holdDays ? '[HOLD ' + holdDays + 'd = $' + holdDays * HOLD_RATE + '] ' : ''}${isDel ? 'Delivery' : 'Pickup'} ${o.booking.label}\n${o.name} ${fmtPhone(phone)}\n${couch}${allAdds.length ? '\nAdd-ons: ' + allAdds.join(', ') : ''}${extrasNew.length ? `\nNEW ADD-ONS: ${extrasNew.map(a => a.label).join(', ')} ($${due.toFixed(2)} link sent)` : ''}${isDel ? '\n' + address + ', ' + city : ''}`).catch(() => {});
    // Confirmation text to the customer with their link (so they can find it to reschedule).
    { const cf = o.name.split(/\s+/)[0], what = isDel ? 'delivery' : 'pick up';
      sendText(phone, prev.date ? `Hi ${cf}, your ${what} is moved to ${o.booking.label}. Need to change it again? Use your link up to 24 hrs before: ${schedLink(o.token)} - Billy's Couches`
        : `Hi ${cf}, you're booked! ${isDel ? 'Delivery' : 'Pick up'}: ${o.booking.label}. Need to reschedule? Use your link up to 24 hrs before: ${schedLink(o.token)} - Billy's Couches`).catch(() => {}); }
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
    .map(o => ({ token: o.token, name: o.name, phone: o.phone, type: o.type, couch: o.couches.map(c => c.title).join(' + '), photo: (o.couches[0] || {}).photo || '', addons: [...o.addons, ...((o.booking || {}).extras || [])], created: o.created, booking: o.booking || null, link: schedLink(o.token), extraDue: o.extraDue || 0, until: o.until || null, noHold: !!o.noHold }));
    res.json({ ok: true, list, cfg: await slotCfg(), defaults: SLOT_DEFAULT }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
// HQ: let one customer book further out (through `until`) and/or skip the holding fee.
app.post('/api/sched/extend', async (req, res) => {
  try { const b = req.body || {}, m = await getSched(), o = m[String(b.token || '')]; if (!o) return res.status(404).json({ error: 'not found' });
    if (/^\d{4}-\d{2}-\d{2}$/.test(b.until || '')) o.until = b.until; else if (b.until === null) delete o.until;
    if (b.noHold !== undefined) o.noHold = !!b.noHold;
    if (Array.isArray(b.allow)) o.allow = b.allow.filter(x => /^\d{4}-\d{2}-\d{2}\|\d{1,2}(:\d{2})?-\d{1,2}(:\d{2})?$/.test(x)).slice(0, 10);
    await setSched(m); res.json({ ok: true, token: o.token, until: o.until || null, noHold: !!o.noHold, url: schedLink(o.token) }); }
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
// ---------- Brand New: reserve-before-it-lands page (hq.billyscouches.com/brand-new) ----------
// Countdown to BN_LAUNCH, $100 Stripe deposit holds one of the 4 units, then the page flips to a normal shop.
const BN_LAUNCH = Date.parse(process.env.BN_LAUNCH || '2026-12-04T06:00:00Z'); // Dec 4, 12:00 AM Central
const BN_DEPOSIT = 100;
const BN_PRODUCTS = [
  { id: 'harmont', name: 'Harmont 5-Piece Sectional', brand: 'Behold Home', color: 'Camel', tagline: 'Ottoman + pillows included · deepest seats · plush reversible cushions', price: 2486, launch: 2286, units: 4,
    photos: ['h2', 'h3', 'h4', 'h5'], note: 'Matching ottoman and throw pillows included.',
    pieces: [{ name: 'Corner wedge', w: 45, d: 45 }, { name: 'Armless', w: 38, d: 45, qty: 2 }, { name: 'Left arm', w: 41, d: 45, side: 'L' }, { name: 'Right arm', w: 41, d: 45, side: 'R' }, { name: 'Ottoman', w: 43, d: 43 }],
    blurb: "Deep seats and high backs that feel genuinely comfortable without losing the support to keep you there all day. Plush reversible seat and back cushions hold their shape long after the new-couch feeling wears off.",
    specs: [['Overall size', 'About 124" x 124" corner'], ['Depth', '45"'], ['Back height', '37" (top of back cushion)'], ['Seat height', '19"'], ['Arm height', '26"'],
      ['Fabric', 'Camel, a light warm beige'], ['Cushions', 'Deep, plush, reversible seat and back cushions'], ['Pieces', 'Left-arm, right-arm, 2 armless, a corner wedge + matching ottoman'], ['Ottoman', 'Included, same fabric, 43" x 43" x 19" tall'], ['Throw pillows', 'Included'],
      ['Modular', 'Yes, every piece moves separately'], ['Legs', 'Removable, 1" tall']] },
  { id: 'ryker', name: 'Ryker 5-Piece Sectional', brand: 'Behold Home', color: 'Stone', tagline: 'Ottoman + pillows included · performance fabric · washable covers', price: 2964, launch: 2764, units: 4,
    photos: ['r5', 'r3', 'r7', 'r4', 'r6', 'r8'], fitPhoto: 'r3', note: 'Matching ottoman and throw pillows included.',
    pieces: [{ name: 'Corner wedge', w: 44, d: 44 }, { name: 'Armless', w: 37, d: 44, qty: 2 }, { name: 'Left arm', w: 42, d: 44, side: 'L' }, { name: 'Right arm', w: 42, d: 44, side: 'R' }, { name: 'Ottoman', w: 43, d: 43 }],
    blurb: 'A deep, sink-in corner sectional with a gel-infused cushion topper and performance fabric you can actually live on. Fully modular, so it fits your room your way.',
    specs: [['Overall size', '123" x 123" corner'], ['Depth', '44"'], ['Back height', '36" (top of back cushion)'], ['Seat height', '20"'], ['Arm height', '26"'],
      ['Fabric', 'Stone performance fabric, removable and washable covers'], ['Cushions', '2.0 density foam with a gel-infused topper'], ['Pieces', 'Left-arm, right-arm, 2 armless, a corner wedge + matching ottoman'], ['Ottoman', 'Included, same fabric, 43" x 43" x 19" tall'], ['Throw pillows', 'Included'],
      ['Modular', 'Yes, every piece moves separately'], ['Legs', 'Removable, 1" tall']] }
];
const BN_KEY = 'bcd:brandNew';
const bnGet = () => kget(BN_KEY, { res: [] });
const bnLive = () => Date.now() >= BN_LAUNCH;
const bnCount = (st, id) => (st.res || []).filter(r => r.item === id && (r.status === 'paid' || r.status === 'landed' || r.status === 'done')).length;
const bnPhoto = f => /^https?:/.test(f) ? f : '/public/bn/' + f;
app.get('/brand-new', (req, res) => res.sendFile(path.join(__dirname, 'brandnew.html')));
app.get('/public/bn/:f', (req, res) => { const f = req.params.f; if (!BN_PRODUCTS.some(p => p.photos.includes(f) || p.fitPhoto === f)) return res.sendStatus(404);
  res.set('Cache-Control', 'public, max-age=86400').set('Access-Control-Allow-Origin', '*').sendFile((/^[hr]\d+$/.test(f) && fs.existsSync(path.join(__dirname, 'bn', 'x', f + '.jpg')) ? path.join(__dirname, 'bn', 'x', f + '.jpg') : path.join(__dirname, 'bn', f, 'image.png'))); });
app.get('/public/brand-new', async (req, res) => {
  dropCors(res);
  try { const st = await bnGet(), live = bnLive();
    res.set('Cache-Control', 'no-store').json({ ok: true, now: Date.now(), launchAt: BN_LAUNCH, live, deposit: BN_DEPOSIT, deliveryFee: deliveryFee(), fitUrl: FIT_BASE ? FIT_BASE + '/' : PUBLIC_BASE + '/fit',
      products: BN_PRODUCTS.map(p => { const taken = bnCount(st, p.id); return { ...p, photos: p.photos.map(bnPhoto), crop: Object.fromEntries(Object.entries(p.crop || {}).map(([k, v]) => ['/public/bn/' + k, v])), reserved: taken, left: Math.max(0, p.units - taken), now: live ? p.price : p.launch }; }) });
  } catch (e) { res.status(500).json({ error: 'unavailable' }); }
});
const bnHits = new Map();
app.post('/public/brand-new/reserve', async (req, res) => {
  dropCors(res);
  try {
    const b = req.body || {}, ip = clientIp(req), now = Date.now();
    const h = (bnHits.get(ip) || []).filter(t => now - t < 3600e3); if (h.length >= 8) return res.status(429).json({ error: 'Too many tries. Text Billy at (314) 899-7503.' }); h.push(now); bnHits.set(ip, h);
    const p = BN_PRODUCTS.find(x => x.id === b.item); if (!p) return res.status(400).json({ error: 'Pick a sectional.' });
    const name = String(b.name || '').trim().slice(0, 80), email = String(b.email || '').trim().toLowerCase().slice(0, 160), phone = String(b.phone || '').replace(/\D/g, '').replace(/^1(\d{10})$/, '$1');
    if (name.length < 2) return res.status(400).json({ error: 'Add your full name.' });
    if (phone.length !== 10) return res.status(400).json({ error: 'Add a 10-digit phone number.' });
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: 'Add a valid email.' });
    if (!b.agree) return res.status(400).json({ error: 'Tick the box to show you understand how the deposit works.' });
    const st = await bnGet(); if (bnCount(st, p.id) >= p.units) return res.status(409).json({ error: `All ${p.units} ${p.name.split(' ')[0]} sectionals are reserved. Text Billy to get on the waitlist.` });
    const live = bnLive(), total = live ? p.price : p.launch, rid = crypto.randomBytes(9).toString('hex');
    const r = await fetch(SCHED_PROXY + '/create-stripe-link', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ customerName: name,
      orderType: `$${BN_DEPOSIT} deposit to reserve: ${p.name} (${p.color}). $${(total - BN_DEPOSIT).toLocaleString()} due when it arrives`, totalCents: BN_DEPOSIT * 100, totalDisplay: '$' + BN_DEPOSIT,
      redirectUrl: `https://hq.billyscouches.com/brand-new?bnr=${rid}&sid={CHECKOUT_SESSION_ID}` }) });
    const j = await r.json().catch(() => ({}));
    if (!j.url) return res.status(502).json({ error: 'Payment link failed. Text Billy at (314) 899-7503.' });
    st.res = (st.res || []).concat({ id: rid, item: p.id, name, phone, email, price: total, at: now, status: 'pending' }).slice(-400);
    await kset(BN_KEY, st);
    res.json({ ok: true, url: j.url });
  } catch (e) { console.log('[brand-new] reserve failed', e.message); res.status(500).json({ error: 'Something went wrong. Text Billy at (314) 899-7503.' }); }
});
// After Stripe: confirm the deposit really went through (asks the proxy, which holds the Stripe key), then text both sides.
app.post('/public/brand-new/confirm', async (req, res) => {
  dropCors(res);
  try {
    const { bnr, sid } = req.body || {}; const st = await bnGet(), r = (st.res || []).find(x => x.id === bnr);
    if (!r) return res.status(404).json({ error: 'Reservation not found. Text Billy at (314) 899-7503.' });
    const p = BN_PRODUCTS.find(x => x.id === r.item) || {};
    if (r.status !== 'pending') return res.json({ ok: true, item: r.item, name: r.name, price: r.price });
    if (!/^cs_[A-Za-z0-9_]+$/.test(String(sid || ''))) return res.status(400).json({ error: 'Missing payment info. Text Billy at (314) 899-7503.' });
    const v = await fetch(SCHED_PROXY + '/stripe-session', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id: sid }) }).then(x => x.json()).catch(() => ({}));
    if (!v.paid || v.amount < BN_DEPOSIT * 100) return res.status(402).json({ error: "We couldn't confirm your deposit yet. Refresh in a minute, or text Billy at (314) 899-7503." });
    if ((st.res || []).some(x => x.sid === sid)) return res.json({ ok: true, item: r.item, name: r.name, price: r.price });
    r.status = 'paid'; r.sid = sid; r.paidAt = Date.now(); await kset(BN_KEY, st);
    const first = r.name.split(/\s+/)[0], left = Math.max(0, (p.units || 4) - bnCount(st, r.item));
    sendText(r.phone, `Hey ${first}, this is Billy with Billy's Couches! Your ${p.name || 'sectional'} (${p.color || ''}) is reserved. $${BN_DEPOSIT} deposit received, $${(r.price - BN_DEPOSIT).toLocaleString()} due when it arrives. Estimated arrival is Dec 4, and I'll text you the day it lands.`).catch(() => {});
    textAlert(`New deposit: ${r.name} reserved a ${p.name} ($${BN_DEPOSIT}). ${left} left. ${r.phone}`).catch(() => {});
    res.json({ ok: true, item: r.item, name: r.name, price: r.price });
  } catch (e) { console.log('[brand-new] confirm failed', e.message); res.status(500).json({ error: 'Something went wrong. Text Billy at (314) 899-7503.' }); }
});
app.options(['/public/brand-new/reserve', '/public/brand-new/confirm'], (req, res) => { dropCors(res); res.setHeader('Access-Control-Allow-Headers', 'Content-Type'); res.sendStatus(204); });
// HQ (Drops tab): see reservations, mark landed / done / refunded, and text everyone "it landed".
app.get('/api/brand-new', async (req, res) => { const st = await bnGet(); res.json({ ok: true, launchAt: BN_LAUNCH, products: BN_PRODUCTS.map(p => ({ id: p.id, name: p.name, color: p.color, units: p.units, reserved: bnCount(st, p.id) })), res: (st.res || []).filter(r => r.status !== 'pending').sort((a, b) => (b.paidAt || 0) - (a.paidAt || 0)) }); });
app.post('/api/brand-new/status', async (req, res) => { const { id, status } = req.body || {}; if (!['paid', 'landed', 'done', 'refunded'].includes(status)) return res.status(400).json({ error: 'bad status' });
  const st = await bnGet(), r = (st.res || []).find(x => x.id === id); if (!r) return res.status(404).json({ error: 'not found' }); r.status = status; await kset(BN_KEY, st); res.json({ ok: true }); });
app.post('/api/brand-new/landed', async (req, res) => {
  const st = await bnGet(); let n = 0;
  for (const r of (st.res || []).filter(x => x.status === 'paid')) { const p = BN_PRODUCTS.find(x => x.id === r.item) || {};
    const ok = await sendText(r.phone, `Hey ${r.name.split(/\s+/)[0]}, your ${(p.name || 'sectional').replace(' 5-Piece Sectional', '')} just landed! Want to pick it up or have us deliver? Reply here and I'll get you on the schedule. -Billy`).catch(() => false);
    if (ok) { r.status = 'landed'; r.landedAt = Date.now(); n++; } }
  await kset(BN_KEY, st); res.json({ ok: true, texted: n });
});

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
    if (typeof req.body.callScript === 'string') cur.callScript = req.body.callScript.slice(0, 30000);
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

// ---------- HQ work log (replaces the Jotform Work Log) ----------
// The team opens hq.billyscouches.com/log?k=<TEAM_PAY_KEY> on their phone. Name, start/end, and counts. Goes straight to Payroll.
const logKeyOk = k => { const key = (process.env.TEAM_PAY_KEY || '').trim(); return !key || k === key; };
app.get('/log', (req, res) => res.set('Cache-Control', 'no-cache').set('X-Robots-Tag', 'noindex').sendFile(path.join(__dirname, 'worklog.html')));
app.get('/public/worklog/team', (req, res) => { if (!logKeyOk(req.query.k)) return res.status(401).json({ error: 'This link is missing its code. Ask Billy for the work log link.' }); res.json({ ok: true, team: TEAM, today: ctYmd(new Date()) }); });
app.post('/public/worklog', async (req, res) => {
  try {
    const b = req.body || {}; if (!logKeyOk(b.k)) return res.status(401).json({ error: 'This link is missing its code. Ask Billy for the work log link.' });
    const name = TEAM.find(n => n.toLowerCase() === String(b.name || '').toLowerCase()); if (!name) return res.status(400).json({ error: 'Tap your name.' });
    const date = /^\d{4}-\d{2}-\d{2}$/.test(b.date || '') ? b.date : ctYmd(new Date());
    const tm = v => { const m = String(v || '').match(/^(\d{1,2}):(\d{2})$/); return m ? (+m[1]) * 60 + (+m[2]) : null; };
    const a = tm(b.start), z = tm(b.end); if (a == null || z == null) return res.status(400).json({ error: 'Add your start and end time.' });
    const hours = Math.round(((z - a + (z <= a ? 1440 : 0)) / 60) * 100) / 100; if (hours > 16) return res.status(400).json({ error: 'That shift is over 16 hours. Check your start and end time.' });
    const c = k => Math.max(0, Math.min(50, parseInt(b[k], 10) || 0));
    const e = { id: 'hq' + crypto.randomBytes(5).toString('hex'), at: new Date().toISOString(), name, date, start: b.start, end: b.end, hours,
      shows: c('shows'), sold: Math.min(c('sold'), c('shows') || c('sold')), deep: c('deep'), spot: c('spot'), pickups: c('pickups'), deliveries: c('deliveries'), tip: Math.max(0, Math.min(2000, Math.round((parseFloat(b.tip) || 0) * 100) / 100)) };
    const list = (await kget(HQLOG_KEY, [])) || []; list.push(e); await kset(HQLOG_KEY, list.slice(-5000));
    // Their week so far (same math as Payroll: hours x rate + $20 per showing sold + $20 once deep cleans hit 4).
    const log = await workLog(false), W = weekBounds(0), rates = { ...DEFAULT_RATES, ...((await kget(KEYS.rates, {})) || {}) }, k = name.toLowerCase();
    const mineW = (log.entries || []).filter(x => x.date >= W.mon && x.date <= W.sun && String(x.name || '').trim().split(/\s+/)[0].toLowerCase().replace(/^gunarr$/, 'gunnarr') === k);
    const sum = f => mineW.reduce((t, x) => t + (x[f] || 0), 0), hrs = Math.round(sum('hours') * 100) / 100, deep = sum('deep'), sold = sum('sold');
    res.json({ ok: true, entry: e, week: { hours: hrs, showBonus: sold * 20, deep, deepToGo: Math.max(0, 4 - deep), cleanBonus: deep >= 4 ? 20 : 0, est: Math.round((hrs * (rates[k] || 0) + sold * 20 + (deep >= 4 ? 20 : 0)) * 100) / 100 } });
    pushAll('Work log', `${name}: ${hours} hrs${e.sold ? ' · ' + e.sold + ' sold' : ''}`, '/', 'wl-' + e.id).catch(() => {});
  } catch (err) { res.status(500).json({ error: 'Could not save. Try again.' }); }
});
// HQ: remove a mistaken shift from the HQ work log
app.post('/api/worklog/delete', async (req, res) => {
  const id = String((req.body || {}).id || ''); const list = (await kget(HQLOG_KEY, [])) || [];
  if (list.some(e => e.id === id)) await kset(HQLOG_KEY, list.filter(e => e.id !== id));
  else if (id) { const h = (await kget('bcd:wlHidden', [])) || []; if (!h.includes(id)) h.push(id); await kset('bcd:wlHidden', h.slice(-500)); wl.at = 0; }   // old-form (Jotform) entries: hide, never delete
  res.json({ ok: true });
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
// ===================================================================
// DAILY JOB BOARD (hq.billyscouches.com/jobs)
// HQ builds tomorrow's job board from the Billy's Couches calendar and spreads hours evenly:
// each spot goes to whoever (1) has no red "Unavailable" block at that time, (2) can do that job,
// (3) is furthest below their weekly hours target (hours from the work log). Ties go to whoever
// worked least in the last 2 weeks. At 7pm Billy gets a text/Telegram to approve; nothing posts on its own.
// Telegram posting turns on when TG_BOT_TOKEN + TG_TEAM_CHAT (+ TG_BILLY_CHAT for the 7pm DM) are in Railway.
// ===================================================================
const JB_KEY = 'bcd:jobBoard';
const JB_TEAM = {
  Zach: { full: 'Zach Pierce', target: 22, can: ['drive', 'host', 'warehouse'] },
  Luke: { full: 'Luke Peters', target: 10, can: ['help', 'truck', 'warehouse'] },
  Joey: { full: 'Joey Menendez', target: 10, can: ['help', 'truck', 'warehouse'] },
  Collin: { full: 'Collin Comer', target: 10, can: ['clean', 'help'] },
  Finley: { full: 'Finley Lotzin', target: 12, can: ['clean', 'help'] },
  Gunnarr: { full: 'Gunnarr Caldwell', target: 10, can: ['help', 'clean'] },
};
const JB_ROLES = { drive: 'Driver', help: 'Helper', host: 'Host', clean: 'Cleaner', truck: 'Truckload Help', warehouse: 'Warehouse' };
const JB_MANUAL = { clean: { label: 'CLEANINGS', icon: '🧽', role: 'clean' }, truck: { label: 'TRUCKLOAD', icon: '🚛', role: 'truck' }, warehouse: { label: 'WAREHOUSE WORK', icon: '🏭', role: 'warehouse' } };
async function jbState() { const s = (await kget(JB_KEY, {})) || {}; s.team = s.team || {}; s.jobs = s.jobs || {}; s.boards = s.boards || {}; s.helpers = s.helpers || 1; return s; }
const jbTeam = s => Object.keys(JB_TEAM).map(n => ({ name: n, ...JB_TEAM[n], ...(s.team[n] || {}) }));
const jbMin = ms => { const p = ctParts(new Date(ms)); return +p.hour * 60 + +p.minute; };
const jbTime = ms => { const m = jbMin(ms), h = Math.floor(m / 60), mm = m % 60; return (h % 12 || 12) + (mm ? ':' + String(mm).padStart(2, '0') : '') + (h < 12 ? 'am' : 'pm'); };
const jbMon = ymd => { const t = new Date(ymd + 'T12:00:00Z'); t.setUTCDate(t.getUTCDate() - ((t.getUTCDay() + 6) % 7)); return t.toISOString().slice(0, 10); };
const jbAdd = (ymd, n) => { const t = new Date(ymd + 'T12:00:00Z'); t.setUTCDate(t.getUTCDate() + n); return t.toISOString().slice(0, 10); };
const jbWho = (entryName, n) => lc(entryName).split(/\s+/)[0].replace(/[^a-z]/g, '') === lc(n) || (lc(n) === 'gunnarr' && /^gunnar/.test(lc(entryName)));

// The jobs on one day: delivery run (from the calendar), pickups outside the run, showings, plus jobs Billy adds.
async function jbJobs(date, s) {
  const g = await google(false).catch(() => ({}));
  const on = iso => ctYmd(new Date(iso)) === date, isPick = t => /pick\s*-?\s*up/i.test(t || '');
  const rows = (g.deliveries || []).filter(r => on(r[0]) && !/cancel/i.test(r[2] || ''));
  const dels = rows.filter(r => !isPick(r[2])), picks = rows.filter(r => isPick(r[2]));
  const jobs = [];
  let run = null;
  if (dels.length) {
    run = { id: 'run', kind: 'run', start: Math.min(...dels.map(r => Date.parse(r[0]))) - 30 * 60e3, end: Math.max(...dels.map(r => Date.parse(r[1]))), count: dels.length,
      slots: ['drive', ...Array(Math.max(0, Number(s.helpers) || 1)).fill('help')] };
    run.availFrom = run.start + 60 * 60e3;   // helpers can join up to 30 min after the first delivery starts
    jobs.push(run);
  }
  const loose = picks;   // "Pick up" on the calendar = a customer picking up at the warehouse (its own job, not part of the run)
  if (loose.length) jobs.push({ id: 'pick', kind: 'pick', start: Math.min(...loose.map(r => Date.parse(r[0]))) - 15 * 60e3, end: Math.max(...loose.map(r => Date.parse(r[1]))), count: loose.length, slots: ['warehouse'] });
  const shows = (g.showings || []).filter(r => on(r[0]) && !/cancel|no.?show/i.test(r[1] || ''));
  if (shows.length) jobs.push({ id: 'show', kind: 'show', start: Math.min(...shows.map(r => Date.parse(r[0]))), end: Math.max(...shows.map(r => Date.parse(r[0]))) + 20 * 60e3, count: shows.length, slots: ['host'] });
  (s.jobs[date] || []).forEach(j => {
    const [h, m] = String(j.time || '16:00').split(':').map(Number), st = ctAt(date, h * 60 + (m || 0)).getTime();
    jobs.push({ id: j.id, kind: j.kind, manual: true, start: st, end: st + (Number(j.hours) || 2) * 3600e3, count: Number(j.count) || 1, note: j.note || '', slots: Array(Math.max(1, Number(j.people) || 1)).fill(JB_MANUAL[j.kind] ? JB_MANUAL[j.kind].role : j.kind) });
  });
  jobs.sort((a, b) => a.start - b.start);
  return { jobs, pickups: picks.length, unavail: g.unavail || [] };
}

// Hours this week per person: logged hours, plus approved-board hours on days they haven't logged yet.
async function jbHours(date, s) {
  const mon = jbMon(date), log = await workLog(false).catch(() => ({ entries: [] })), out = {}, missing = [];
  const today = ctYmd(new Date()), from14 = jbAdd(date, -14);
  for (const p of jbTeam(s)) {
    const mine = (log.entries || []).filter(e => jbWho(e.name, p.name));
    const loggedDays = new Set(mine.map(e => e.date));
    let hrs = mine.filter(e => e.date >= mon && e.date < date).reduce((a, e) => a + (Number(e.hours) || 0), 0), planned = 0, recent = mine.filter(e => e.date >= from14 && e.date < date).reduce((a, e) => a + (Number(e.hours) || 0), 0);
    Object.entries(s.boards).forEach(([d, b]) => {
      if (!b.posted || !b.assign || d >= date || loggedDays.has(d)) return;
      const h = b.assign.filter(a => a.name === p.name).reduce((x, a) => x + a.hours, 0); if (!h) return;
      if (d >= mon) planned += h; if (d >= from14) recent += h;
      if (d < today) missing.push({ name: p.name, date: d });
    });
    out[p.name] = { logged: Math.round(hrs * 10) / 10, planned: Math.round(planned * 10) / 10, total: hrs + planned, recent };
  }
  return { hours: out, missing, mon };
}

async function jbBuild(date) {
  const s = await jbState(), team = jbTeam(s).filter(p => !p.off), { jobs, pickups, unavail } = await jbJobs(date, s), { hours, missing, mon } = await jbHours(date, s);
  const board = s.boards[date] || {}, pick = board.pick || {}, busy = {}, add = {};
  const blocked = (n, a, b) => unavail.some(([st, en, title]) => new RegExp('\\b' + n + '\\b', 'i').test(title || '') && Date.parse(st) < b && Date.parse(en) > a);
  // Team availability app: once someone confirms a week, they're only scheduled inside the times they said they CAN work.
  // Anyone who hasn't confirmed is off the board (from AV_START). Before that, unconfirmed people fall back to the calendar.
  const av = await avState(), avConf = n => !!((av.people[n] || {}).confirmed || {})[jbMon(date)];
  const avBlocked = (n, a, b) => avConf(n) ? !avFree(av.people[n], date).some(([x, y]) => x <= a && y >= b) : avNeeds(date);
  const blocked2 = (n, a, b) => blocked(n, a, b) || avBlocked(n, a, b);
  // Showing form settings: host order, and days Billy is away (then a team host covers showings and customer pickups).
  const shc = (await shfState()).cfg, billyIn = !shc.billyAway.includes(date);
  const why = {};
  for (const j of jobs) {
    j.people = j.slots.map((role, i) => {
      const key = j.id + ':' + i, hrs = (j.end - j.start) / 3600e3;
      const free = team.filter(p => (p.can.includes(role) || (role === 'host' && shc.hosts.includes(p.name))) && !blocked2(p.name, j.availFrom || j.start, j.end) && !(busy[p.name] || []).some(([a, b]) => a < j.end && b > j.start));
      const score = p => ((hours[p.name].total + (add[p.name] || 0)) / Math.max(1, p.target));
      free.sort((a, b) => score(a) - score(b) || hours[a.name].recent - hours[b.name].recent || a.name.localeCompare(b.name));
      if (role === 'host') free.sort((a, b) => (shc.hosts.indexOf(a.name) + 1 || 99) - (shc.hosts.indexOf(b.name) + 1 || 99));
      // Fixed defaults: Zach always drives, Billy hosts showings and does loose warehouse pickups (swap still overrides).
      const fixed = role === 'drive' ? 'Zach' : (role === 'host' || j.kind === 'pick') ? (billyIn ? 'Billy' : '') : '';
      let name = Object.prototype.hasOwnProperty.call(pick, key) ? pick[key] : (fixed || (free[0] ? free[0].name : ''));
      if (name && name !== 'Billy') { (busy[name] = busy[name] || []).push([j.start, j.end]); add[name] = (add[name] || 0) + hrs; }
      return { key, role, label: j.kind === 'pick' ? 'Host' : (JB_ROLES[role] || role), name, hours: hrs, auto: !Object.prototype.hasOwnProperty.call(pick, key), options: [...new Set([fixed, ...free.map(p => p.name), ...(role === 'host' || j.kind === 'pick' ? ['Billy'] : [])].filter(Boolean))] };
    });
  }
  const full = n => n === 'Billy' ? 'Billy' : n ? ((jbTeam(s).find(p => p.name === n) || {}).full || n) : '';
  const d = new Date(date + 'T12:00:00Z'), line = '__________________________';
  const L = [`📋 Billy's Couches — Daily Job Board`, `📅 ${d.getUTCMonth() + 1}/${d.getUTCDate()}/${String(d.getUTCFullYear()).slice(2)}`, line];
  const run = jobs.find(j => j.kind === 'run'), pk = jobs.find(j => j.kind === 'pick'), sh = jobs.find(j => j.kind === 'show');
  L.push(`🚚 DELIVERIES: ${run ? run.count : ''}`, `📦 PICKUPS:`);
  if (run) { run.people.forEach(x => L.push(`👤 ${x.label}: ${full(x.name)}`)); L.push(`⏰ Start Time: ${jbTime(run.start)}`); }
  if (!run) L.push('👤 Driver:', '⏰ Start Time:');
  if (pk) { L.push(line, `🙋 CUSTOMER PICKUPS: ${pk.count}`); pk.people.forEach(x => L.push(`👤 Host: ${full(x.name)}`)); L.push(`⏰ Pickup Time: ${jbTime(pk.start + 15 * 60e3)}`); }
  L.push(line, `🏠 WAREHOUSE SHOWINGS: ${sh ? sh.count : ''}`);
  if (sh) { L.push(`👤 Host: ${full(sh.people[0].name)}`, `⏰ Start Time: ${jbTime(sh.start)}`); } else L.push('👤 Host:', '⏰ Start Time:');
  Object.entries(JB_MANUAL).forEach(([k, m]) => {
    const list = jobs.filter(j => j.kind === k);
    if (!list.length && k !== 'clean') return;
    L.push(line, `${m.icon} ${m.label}: ${list.reduce((a, j) => a + j.count, 0) || ''}`);
    if (!list.length) L.push(`👤 ${JB_ROLES[m.role]}:`, '⏰ Start Time:');
    list.forEach(j => { j.people.forEach(x => L.push(`👤 ${x.label}: ${full(x.name)}`)); L.push(`⏰ Start Time: ${jbTime(j.start)}` + (j.note ? `\n📝 ${j.note}` : '')); });
  });
  const assign = jobs.flatMap(j => j.people.filter(x => x.name && x.name !== 'Billy').map(x => ({ name: x.name, hours: Math.round(x.hours * 100) / 100, job: j.id })));
  const weekTeam = jbTeam(s).map(p => ({ name: p.name, full: p.full, target: p.target, can: p.can, off: !!p.off, logged: hours[p.name].logged, planned: hours[p.name].planned, tomorrow: Math.round((add[p.name] || 0) * 10) / 10 }));
  return { ok: true, date, mon, text: L.join('\n'), jobs, assign, team: weekTeam, missing, helpers: s.helpers, posted: board.posted || null, manual: s.jobs[date] || [], tg: !!(TG() && jbChat(s)), tgToken: !!TG(), tgCode: TG() && !jbChat(s) ? await jbCode(s) : '' };
}

const TG = () => (process.env.TG_BOT_TOKEN || '').trim();
// The team group is linked by typing /connect <code> in it (code shows on the job board), or TG_TEAM_CHAT in Railway.
const jbChat = s => String(process.env.TG_TEAM_CHAT || s.tgChat || '');
async function jbCode(s) { if (!s.tgCode) { s.tgCode = crypto.randomBytes(3).toString('hex'); await kset(JB_KEY, s); } return s.tgCode; }
async function tgCall(method, body) {
  const r = await fetch(`https://api.telegram.org/bot${TG()}/${method}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const j = await r.json().catch(() => ({})); if (!j.ok) throw new Error('Telegram: ' + (j.description || r.status)); return j.result;
}
async function jbPost(date) {
  const b = await jbBuild(date), s = await jbState();
  if (TG() && jbChat(s)) await tgCall('sendMessage', { chat_id: jbChat(s), text: b.text });
  s.boards[date] = { ...(s.boards[date] || {}), posted: Date.now(), assign: b.assign, text: b.text };
  await kset(JB_KEY, s);
  return b;
}
const jbTomorrow = () => jbAdd(ctYmd(new Date()), 1);
const jbDate = q => /^\d{4}-\d{2}-\d{2}$/.test(q || '') ? q : jbTomorrow();

app.get('/jobs', (req, res) => res.set('Cache-Control', 'no-cache').sendFile(path.join(__dirname, authed(req) ? 'jobs.html' : 'login.html')));
app.get('/api/jobboard', async (req, res) => { try { res.json(await jbBuild(jbDate(req.query.date))); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/jobboard/pick', async (req, res) => {
  try { const b = req.body || {}, date = jbDate(b.date), s = await jbState(); s.boards[date] = s.boards[date] || {}; const p = s.boards[date].pick = s.boards[date].pick || {};
    if (b.auto) delete p[b.key]; else p[String(b.key)] = clean(b.name, 30); await kset(JB_KEY, s); res.json(await jbBuild(date)); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/jobboard/job', async (req, res) => {
  try { const b = req.body || {}, date = jbDate(b.date), s = await jbState(), list = s.jobs[date] = s.jobs[date] || [];
    if (b.remove) s.jobs[date] = list.filter(j => j.id !== b.remove);
    else { if (!JB_MANUAL[b.kind]) return res.status(400).json({ error: 'Pick a job type' }); if (!/^\d{1,2}:\d{2}$/.test(b.time || '')) return res.status(400).json({ error: 'Pick a start time' });
      list.push({ id: 'j' + Date.now().toString(36), kind: b.kind, time: b.time, hours: Math.min(12, Math.max(0.5, Number(b.hours) || 2)), people: Math.min(4, Math.max(1, Number(b.people) || 1)), count: Math.max(1, Number(b.count) || 1), note: clean(b.note, 120) }); }
    await kset(JB_KEY, s); res.json(await jbBuild(date)); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/jobboard/settings', async (req, res) => {
  try { const b = req.body || {}, s = await jbState();
    if (b.helpers != null) s.helpers = Math.min(3, Math.max(0, Number(b.helpers) || 0));
    if (b.name && JB_TEAM[b.name]) { const t = s.team[b.name] = s.team[b.name] || {};
      if (b.target != null) t.target = Math.min(40, Math.max(0, Number(b.target) || 0));
      if (Array.isArray(b.can)) t.can = b.can.filter(r => JB_ROLES[r]);
      if (b.off != null) t.off = !!b.off; }
    await kset(JB_KEY, s); res.json(await jbBuild(jbDate(b.date))); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/jobboard/post', async (req, res) => { try { res.json({ ...(await jbPost(jbDate((req.body || {}).date))), justPosted: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

// ===================== TEAM AVAILABILITY =====================
// Each team member gets a private link (/a/<token>) to mark when they CAN work, Mon-Sun, with exact times and an
// optional weekly repeat. Blocks = available windows; a day with none = not available. Everyone must confirm every week. Until a person confirms a week, the job board treats them
// as unavailable that week (starting AV_START). Billy gets a text/Telegram on every save. Red calendar events still count.
const AV_KEY = 'bcd:avail';
const AV_START = '2026-11-30';   // first week the "no reply = unavailable" rule applies
async function avState() { const a = (await kget(AV_KEY, {})) || {}; a.people = a.people || {}; return a; }
function avPerson(a, name) {
  const p = a.people[name] = a.people[name] || {};
  if (!p.token) p.token = crypto.randomBytes(9).toString('base64url');
  p.blocks = p.blocks || []; p.confirmed = p.confirmed || {}; return p;
}
const avHM = v => { const m = String(v || '').match(/^(\d{1,2}):(\d{2})$/); if (!m || +m[1] > 23 || +m[2] > 59) return null; return +m[1] * 60 + +m[2]; };
const avFmt = min => { const h = Math.floor(min / 60), m = min % 60; return (h % 12 || 12) + (m ? ':' + String(m).padStart(2, '0') : '') + (h < 12 ? 'a' : 'p'); };
const avDow = ymd => new Date(ymd + 'T12:00:00Z').getUTCDay();
const AV_DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
// Blocks that apply on a date: one-offs for that date, plus weekly repeats (unless skipped that date).
const avOn = (p, ymd) => (p.blocks || []).filter(b => b.date ? b.date === ymd : (b.dow === avDow(ymd) && ymd >= (b.from || '') && (!b.until || ymd <= b.until) && !(b.skip || []).includes(ymd)));
const avLabel = b => b.allDay ? 'all day' : `${avFmt(b.s)}–${avFmt(b.e)}`;
// Available windows (ms) for a person on a date, for the job board.
function avFree(p, ymd) { return avOn(p, ymd).map(b => b.allDay ? [ctAt(ymd, 0).getTime(), ctAt(ymd, 24 * 60 - 1).getTime()] : [ctAt(ymd, b.s).getTime(), ctAt(ymd, b.e).getTime()]); }
const avNeeds = ymd => jbMon(ymd) >= AV_START;
const avTeam = async () => jbTeam(await jbState()).filter(p => !p.off);
function avSummary(p, mon) {
  const out = [];
  for (let i = 0; i < 7; i++) { const d = jbAdd(mon, i), bl = avOn(p, d); if (bl.length) out.push(AV_DAYS[avDow(d)] + ' ' + bl.map(b => avLabel(b) + (b.dow != null ? ' ↻' : '')).join(', ')); }
  return out.length ? 'can work ' + out.join(' · ') : 'not available all week';
}
async function avNotify(text) {
  try { if (TG() && process.env.TG_BILLY_CHAT) return await tgCall('sendMessage', { chat_id: process.env.TG_BILLY_CHAT, text }); } catch (e) {}
  return textAlert(text).catch(() => {});
}
app.get('/a/:token', (req, res) => res.set('Cache-Control', 'no-cache').set('X-Robots-Tag', 'noindex').sendFile(path.join(__dirname, 'avail.html')));
async function avFind(token) { const a = await avState(); const name = Object.keys(a.people).find(n => a.people[n].token === token); return name ? { a, name, p: avPerson(a, name) } : null; }
app.get('/public/avail/:token', async (req, res) => {
  try {
    const f = await avFind(String(req.params.token)); if (!f) return res.status(404).json({ error: 'This link is no longer active. Ask Billy for a new one.' });
    const today = ctYmd(new Date()), mon = /^\d{4}-\d{2}-\d{2}$/.test(req.query.week || '') ? jbMon(req.query.week) : jbMon(jbAdd(today, 1));
    const days = []; for (let i = 0; i < 7; i++) { const d = jbAdd(mon, i); days.push({ date: d, dow: avDow(d), past: d < today, blocks: avOn(f.p, d).map(b => ({ id: b.id, allDay: !!b.allDay, start: b.allDay ? '' : avFmt(b.s), s: b.s, e: b.e, repeat: b.dow != null })) }); }
    res.json({ name: f.name, week: mon, thisWeek: jbMon(today), days, confirmed: f.p.confirmed[mon] || null });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// Save one week. Body: { week, days: [{ date, blocks: [{ id?, allDay, s, e, repeat, scope }] }] }
// scope on an existing repeat: 'week' = change just this week (skip the repeat that date), 'all' = change the repeat itself.
const avHits = new Map();
app.post('/public/avail/:token', async (req, res) => {
  try {
    const ip = String(req.headers['x-forwarded-for'] || req.ip || '').split(',')[0], n = (avHits.get(ip) || 0) + 1; avHits.set(ip, n); if (n > 120) return res.status(429).json({ error: 'Too many saves. Try again later.' });
    const f = await avFind(String(req.params.token)); if (!f) return res.status(404).json({ error: 'This link is no longer active.' });
    const b = req.body || {}, mon = jbMon(String(b.week || '')), today = ctYmd(new Date()); if (!/^\d{4}-\d{2}-\d{2}$/.test(mon)) return res.status(400).json({ error: 'Bad week' });
    const p = f.p, before = avSummary(p, mon), dates = new Set(); for (let i = 0; i < 7; i++) dates.add(jbAdd(mon, i));
    for (const day of (Array.isArray(b.days) ? b.days : [])) {
      const d = String(day.date || ''); if (!dates.has(d) || d < today) continue;
      const wanted = (Array.isArray(day.blocks) ? day.blocks : []).slice(0, 8).map(x => ({ id: clean(x.id, 20), allDay: !!x.allDay, s: avHM(x.start), e: avHM(x.end), repeat: !!x.repeat, scope: x.scope === 'all' ? 'all' : 'week' }))
        .filter(x => x.allDay || (x.s != null && x.e != null && x.e > x.s));
      const keepIds = new Set(wanted.map(x => x.id).filter(Boolean));
      // Existing blocks on this date that were removed
      // Removed blocks: a one-off just goes; a weekly repeat is skipped for this date unless they chose "every week".
      const allGone = new Set((Array.isArray(day.removeAll) ? day.removeAll : []).map(String));
      for (const old of avOn(p, d)) {
        if (keepIds.has(old.id)) continue;
        if (old.date || allGone.has(old.id)) p.blocks = p.blocks.filter(x => x !== old);
        else (old.skip = old.skip || []).push(d);
      }
      for (const x of wanted) {
        const old = x.id && p.blocks.find(y => y.id === x.id);
        const vals = { allDay: x.allDay, s: x.allDay ? null : x.s, e: x.allDay ? null : x.e };
        if (old) {
          if (old.dow != null) {
            const same = old.allDay === vals.allDay && old.s === vals.s && old.e === vals.e;
            if (!x.repeat) { (old.skip = old.skip || []).push(d); old.until = d; p.blocks.push({ id: crypto.randomBytes(5).toString('hex'), date: d, ...vals }); }   // repeat turned off: ends here
            else if (!same && x.scope === 'all') Object.assign(old, vals);
            else if (!same) { (old.skip = old.skip || []).push(d); p.blocks.push({ id: crypto.randomBytes(5).toString('hex'), date: d, ...vals }); }
          } else if (x.repeat) { p.blocks = p.blocks.filter(y => y !== old); p.blocks.push({ id: crypto.randomBytes(5).toString('hex'), dow: avDow(d), from: d, ...vals }); }
          else Object.assign(old, vals);
        } else p.blocks.push(x.repeat ? { id: crypto.randomBytes(5).toString('hex'), dow: avDow(d), from: d, ...vals } : { id: crypto.randomBytes(5).toString('hex'), date: d, ...vals });
      }
    }
    p.blocks = p.blocks.filter(x => x.date ? x.date >= jbAdd(today, -14) : true).slice(-200);
    p.confirmed[mon] = Date.now(); p.updated = Date.now();
    await kset(AV_KEY, f.a);
    const after = avSummary(p, mon), wk = `${+mon.slice(5, 7)}/${+mon.slice(8)}`;
    // Changing tomorrow (or today) after the 7pm board went out: flag it.
    const s = await jbState(), tom = jbTomorrow(), late = before === after ? [] : [today, tom].filter(d => dates.has(d) && (s.boards[d] || {}).notified);
    avNotify(`🗓 ${f.name} ${before === after ? 'confirmed' : 'updated'} availability (week of ${wk}): ${after}` + (late.length ? `\n⚠️ This changes ${late.includes(today) ? 'today' : 'tomorrow'}'s job board. Check it: ${PUBLIC_BASE}/jobs?date=${late[late.length - 1]}` : ''));
    res.json({ ok: true, confirmed: p.confirmed[mon] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// Team tab: everyone's week (app blocks + red calendar events), who hasn't confirmed, and link/phone management.
app.get('/api/avail', async (req, res) => {
  try {
    const a = await avState(), team = await avTeam(), today = ctYmd(new Date());
    const mon = /^\d{4}-\d{2}-\d{2}$/.test(req.query.week || '') ? jbMon(req.query.week) : jbMon(today);
    let cal = []; try { cal = (await google(false)).unavail || []; } catch (e) {}
    const people = team.map(t => {
      const p = avPerson(a, t.name), days = [];
      for (let i = 0; i < 7; i++) {
        const d = jbAdd(mon, i), dayStart = ctAt(d, 0).getTime(), dayEnd = ctAt(d, 24 * 60 - 1).getTime();
        const items = avOn(p, d).map(b => ({ allDay: !!b.allDay, s: b.s, e: b.e, label: avLabel(b), repeat: b.dow != null, src: 'app' }));
        cal.filter(([st, en, title]) => new RegExp('\\b' + t.name + '\\b', 'i').test(title || '') && Date.parse(st) < dayEnd && Date.parse(en) > dayStart).forEach(([st, en, , allDay]) => {
          if (allDay || (Date.parse(st) <= dayStart && Date.parse(en) >= dayEnd)) items.push({ allDay: true, label: 'all day', src: 'cal' });
          else { const s = Math.max(0, jbMin(Math.max(Date.parse(st), dayStart))), e = Math.min(1439, jbMin(Math.min(Date.parse(en), dayEnd))); items.push({ allDay: false, s, e, label: `${avFmt(s)}–${avFmt(e)}`, src: 'cal' }); }
        });
        days.push({ date: d, items });
      }
      return { name: t.name, full: t.full, phone: p.phone || '', link: `${PUBLIC_BASE}/a/${p.token}`, confirmed: p.confirmed[mon] || null, required: avNeeds(mon), days };
    });
    await kset(AV_KEY, a);   // saves any newly created tokens
    res.json({ week: mon, thisWeek: jbMon(today), start: AV_START, people });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/avail/person', async (req, res) => {
  try {
    const b = req.body || {}, a = await avState(), team = await avTeam(); if (!team.some(t => t.name === b.name)) return res.status(400).json({ error: 'Unknown team member' });
    const p = avPerson(a, b.name);
    if (b.phone != null) { const d = String(b.phone).replace(/\D/g, ''); p.phone = d.length === 10 ? d : d.length === 11 && d[0] === '1' ? d.slice(1) : ''; }
    if (b.newLink) p.token = crypto.randomBytes(9).toString('base64url');
    if (b.sendLink) { if (!p.phone) return res.status(400).json({ error: 'Add their phone first' }); await sendText(p.phone, `Hey ${b.name}, it's Billy. Mark when you CAN work so you get put on the job board (takes a minute): ${PUBLIC_BASE}/a/${p.token}`); p.lastSent = Date.now(); }
    await kset(AV_KEY, a); res.json({ ok: true, phone: p.phone || '', link: `${PUBLIC_BASE}/a/${p.token}` });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// ===================== TEAM UPDATES =====================
// Billy posts a change (sale, policy, drop schedule). Urgent ones are texted to the whole team right away with a
// personal "Got it" link (/u/<their availability token>, no login). Every update also shows at the top of the weekly
// availability form until they check "I read these". HQ shows who has confirmed. Updates are hidden, never deleted.
const TU_KEY = 'bcd:teamUpdates';
const tuList = async () => (await kget(TU_KEY, [])) || [];
const tuOpen = (list, name) => list.filter(u => !u.hidden && Date.now() - u.at < 45 * 864e5 && !(u.seen || {})[name]);
const tuText = (u, p) => `📣 Billy's Couches update:\n${u.text}\n\nTap to confirm you got it: ${PUBLIC_BASE}/u/${p.token}`;
async function tuSend(u, names) {
  const a = await avState(); let sent = 0; const noPhone = [];
  for (const n of names) { const p = avPerson(a, n); if (!p.phone) { noPhone.push(n); continue; }
    try { await sendText(p.phone, tuText(u, p)); sent++; } catch (e) { console.log('team update text failed', n, e.message); } }
  await kset(AV_KEY, a); return { sent, noPhone };
}
app.get('/api/team-updates', async (req, res) => {
  try { const list = await tuList(), team = (await avTeam()).map(t => t.name);
    res.json({ ok: true, team, updates: list.filter(u => !u.hidden).slice(0, 15) }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/team-updates', async (req, res) => {
  try { const b = req.body || {}, text = String(b.text || '').trim().slice(0, 600); if (!text) return res.status(400).json({ error: 'Type the update first' });
    const list = await tuList(), u = { id: crypto.randomBytes(5).toString('hex'), text, at: Date.now(), urgent: !!b.urgent, seen: {} };
    list.unshift(u); await kset(TU_KEY, list.slice(0, 100));
    const r = u.urgent ? await tuSend(u, (await avTeam()).map(t => t.name)) : { sent: 0, noPhone: [] };
    res.json({ ok: true, update: u, ...r });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/team-updates/nudge', async (req, res) => {
  try { const list = await tuList(), u = list.find(x => x.id === String((req.body || {}).id || '')); if (!u) return res.status(404).json({ error: 'Not found' });
    const left = (await avTeam()).map(t => t.name).filter(n => !(u.seen || {})[n]), r = await tuSend(u, left);
    u.nudged = Date.now(); await kset(TU_KEY, list); res.json({ ok: true, ...r });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/team-updates/hide', async (req, res) => {
  try { const list = await tuList(), u = list.find(x => x.id === String((req.body || {}).id || '')); if (u) { u.hidden = Date.now(); await kset(TU_KEY, list); } res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/u/:token', (req, res) => res.set('Cache-Control', 'no-cache').set('X-Robots-Tag', 'noindex').sendFile(path.join(__dirname, 'updates.html')));
app.get('/public/updates/:token', async (req, res) => {
  try { const f = await avFind(String(req.params.token)); if (!f) return res.status(404).json({ error: 'This link is no longer active. Ask Billy for a new one.' });
    const list = await tuList(), open = tuOpen(list, f.name), pick = u => ({ id: u.id, text: u.text, at: u.at });
    res.json({ name: f.name, open: open.map(pick), recent: list.filter(u => !u.hidden && !open.includes(u)).slice(0, 5).map(pick) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/public/updates/:token', async (req, res) => {
  try { const f = await avFind(String(req.params.token)); if (!f) return res.status(404).json({ error: 'This link is no longer active.' });
    const ids = new Set((Array.isArray((req.body || {}).ids) ? req.body.ids : []).map(String)), list = await tuList(), now = Date.now();
    list.forEach(u => { if (ids.has(u.id)) { u.seen = u.seen || {}; if (!u.seen[f.name]) u.seen[f.name] = now; } });
    await kset(TU_KEY, list); res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// ===================== END TEAM UPDATES =====================
// Sunday 6pm: everyone gets their link for next week. Monday noon: one reminder to anyone who hasn't confirmed this week.
setInterval(async () => {
  try {
    if (process.env.AVAIL_TEXTS === 'off') return;
    const p = ctParts(new Date()), today = ctYmd(new Date()), dow = avDow(today), hr = +p.hour;
    const kind = dow === 0 && hr >= 18 && hr < 21 ? 'sun' : dow === 1 && hr >= 12 && hr < 15 ? 'mon' : ''; if (!kind) return;
    const mon = kind === 'sun' ? jbAdd(today, 1) : today, a = await avState(), team = await avTeam(); let changed = false;
    for (const t of team) {
      const per = avPerson(a, t.name); per.sent = per.sent || {}; const key = kind + ':' + mon;
      if (per.sent[key] || !per.phone) continue; if (kind === 'mon' && per.confirmed[mon]) continue;
      const link = `${PUBLIC_BASE}/a/${per.token}`;
      const msg = kind === 'sun' ? `Hey ${t.name}, mark when you CAN work this week (Mon–Sun) and tap confirm, even if nothing changed: ${link}` : `Reminder ${t.name}: you're off the job board until you confirm this week's availability: ${link}`;
      if (await sendText(per.phone, msg)) { per.sent[key] = Date.now(); changed = true; }
    }
    if (changed) await kset(AV_KEY, a);
  } catch (e) { console.log('[avail] weekly texts failed:', e.message); }
}, 10 * 60 * 1000);
// 7pm Central: tell Billy tomorrow's board is ready (Telegram DM with a Post button if set up, otherwise a text).
setInterval(async () => {
  try {
    const p = ctParts(new Date()); if (+p.hour < 19 || +p.hour >= 22 || process.env.JOBBOARD === 'off') return;
    const date = jbTomorrow(), s = await jbState(); if ((s.boards[date] || {}).notified || (s.boards[date] || {}).posted) return;
    s.boards[date] = { ...(s.boards[date] || {}), notified: Date.now() }; await kset(JB_KEY, s);
    const b = await jbBuild(date), link = `${PUBLIC_BASE}/jobs?date=${date}`;
    if (TG() && process.env.TG_BILLY_CHAT) await tgCall('sendMessage', { chat_id: process.env.TG_BILLY_CHAT, text: `Tomorrow's job board is ready:\n\n${b.text}`, reply_markup: { inline_keyboard: [[{ text: '✅ Post to team', callback_data: 'jbpost:' + date }, { text: '🔁 Swap someone', url: link }]] } });
    else await textAlert(`Tomorrow's job board is ready. Tap to check it and post it to the team: ${link}`);
  } catch (e) { console.log('[job board] 7pm notice failed:', e.message); }
}, 10 * 60 * 1000);
// Telegram "Post to team" button (only Billy's chat can press it).
const TG_HOOK = () => crypto.createHash('sha256').update('tg:' + TG()).digest('hex').slice(0, 24);
app.post('/public/tg/:hook', async (req, res) => {
  res.json({ ok: true });
  try {
    if (!TG() || req.params.hook !== TG_HOOK()) return;
    const msg = (req.body || {}).message, cm = msg && String(msg.text || '').match(/^\/connect(?:@\w+)?\s+([a-f0-9]{6})\b/i);
    if (cm) { const s = await jbState(); if (s.tgCode && cm[1].toLowerCase() === s.tgCode) { s.tgChat = String(msg.chat.id); s.tgChatName = clean(msg.chat.title || '', 80); delete s.tgCode; await kset(JB_KEY, s); await tgCall('sendMessage', { chat_id: msg.chat.id, text: "✅ Connected. Billy's daily job board will post here." }); } return; }
    const cb = (req.body || {}).callback_query; if (!cb || !/^jbpost:\d{4}-\d{2}-\d{2}$/.test(cb.data || '')) return;
    if (String(cb.from && cb.from.id) !== String(process.env.TG_BILLY_CHAT || '')) return tgCall('answerCallbackQuery', { callback_query_id: cb.id, text: 'Only Billy can post this.' });
    const date = cb.data.slice(7), s = await jbState();
    if ((s.boards[date] || {}).posted) return tgCall('answerCallbackQuery', { callback_query_id: cb.id, text: 'Already posted.' });
    await jbPost(date);
    await tgCall('answerCallbackQuery', { callback_query_id: cb.id, text: 'Posted to the team ✅' });
    await tgCall('editMessageReplyMarkup', { chat_id: cb.message.chat.id, message_id: cb.message.message_id, reply_markup: { inline_keyboard: [[{ text: '✅ Posted', callback_data: 'noop' }]] } });
  } catch (e) { console.log('[job board] telegram button failed:', e.message); }
});
if (TG()) setTimeout(() => tgCall('setWebhook', { url: `${PUBLIC_BASE}/public/tg/${TG_HOOK()}`, allowed_updates: ['callback_query', 'message'] }).then(() => console.log('[job board] Telegram button ready')).catch(e => console.log('[job board]', e.message)), 20000);

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

// ===================== SHOWINGS: in-house showing form (replaces the Jotform "Warehouse Showing") =====================
// Customers book at /showing (embedded on billyscouches.com/visitshowroom). Open times = the weekly hours, or the
// special hours set for a date, minus closed dates and times already booked. Nobody is assigned here: hosts are
// assigned the day before on the job board / work log. Each booking becomes a "Showing for <name>" event on the
// Billy's Couches calendar in the same format Jotform used, so the job board, no-show texts and warm leads keep working.
const SHF_KEY = 'bcd:showForm';
const SHF_DEFAULT = { hosts: ['Finley', 'Collin', 'Gunnarr', 'Luke', 'Zach'], billyAway: [], closed: [], special: {}, slot: 20, notice: 7, days: 3,
  hours: { 0: [840, 1260], 1: [540, 1260], 2: [540, 1260], 3: [540, 1260], 4: [540, 1260], 5: [540, 1260], 6: [540, 1260] } };
const SHF_SOON = ['ASAP', '1-3 weeks', '1-3 months'];
const SHF_SRC = ['Facebook Marketplace', 'Craigslist', 'Facebook or Instagram Ad', 'TikTok', 'Google Search', 'Google Maps', 'Someone referred me', 'Other'];
async function shfState() { const s = (await kget(SHF_KEY, {})) || {}; s.cfg = { ...SHF_DEFAULT, ...(s.cfg || {}) }; s.book = s.book || {}; return s; }
const shfHm = m => { const h = Math.floor(m / 60), mm = m % 60; return `${h % 12 || 12}:${String(mm).padStart(2, '0')} ${h < 12 ? 'AM' : 'PM'}`; };
const shfDay = ymd => new Date(ymd + 'T12:00:00Z').toLocaleDateString('en-US', { weekday: 'long', month: 'short', day: 'numeric', timeZone: 'UTC' });
const shfCap = w => String(w || '').trim().split(/\s+/).map(x => x ? x[0].toUpperCase() + x.slice(1) : '').join(' ');
const shfEsc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const shfRange = (lo, hi) => shfHm(lo).replace(':00', '').replace(' ', '').toLowerCase() + '-' + shfHm(hi).replace(':00', '').replace(' ', '').toLowerCase();
async function shfDays(s, onlyDate) {
  const cfg = s.cfg, g = await google(false).catch(() => ({})), today = ctYmd(new Date()), now = Date.now();
  const shows = (g.showings || []).filter(r => !/cancel/i.test(r[1] || '')).map(r => Date.parse(r[0]));
  Object.values(s.book).forEach(b => { if (!shows.some(t => Math.abs(t - b.start) < 60e3)) shows.push(b.start); });   // booked here but not on the calendar copy yet
  const out = [];
  for (let i = 0; i < cfg.days; i++) {
    const date = jbAdd(today, i); if (onlyDate && date !== onlyDate) continue;
    const dow = new Date(date + 'T12:00:00Z').getUTCDay(), hrs = (cfg.special || {})[date] || cfg.hours[dow], day = { date, label: shfDay(date), slots: [] };
    out.push(day);
    if (!hrs || cfg.closed.includes(date)) continue;
    for (let m = hrs[0]; m + cfg.slot <= hrs[1]; m += cfg.slot) {
      const a = ctAt(date, m).getTime(), b = a + cfg.slot * 60e3;
      if (a - now < cfg.notice * 3600e3 || shows.some(t => t >= a && t < b)) continue;
      day.slots.push({ min: m, label: shfHm(m) });
    }
  }
  return out;
}
app.get('/showing', (req, res) => res.set('Cache-Control', 'no-cache').sendFile(path.join(__dirname, 'showing.html')));
app.get('/public/showing', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const s = await shfState(), days = await shfDays(s), drops = await getDrops().catch(() => []);
    const couches = drops.filter(d => (d.status === 'live' || d.status === 'emailed') && (d.photos || []).length).sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0)).slice(0, 40)
      .map(d => ({ id: d.id, title: d.title, price: d.price, photo: dropPhotoUrl(d.photos[0]) }));
    res.json({ ok: true, days: days.map(d => ({ date: d.date, label: d.label, slots: d.slots.map(x => ({ min: x.min, label: x.label })) })), couches, soon: SHF_SOON, sources: SHF_SRC });
  } catch (e) { console.log('Showing slots failed', e.message); res.status(500).json({ error: 'Could not load times. Text Billy at (314) 899-7503.' }); }
});
const shfHits = new Map();
app.post('/public/showing', async (req, res) => {
  try {
    const ip = clientIp(req), n = (shfHits.get(ip) || 0) + 1; shfHits.set(ip, n); setTimeout(() => shfHits.delete(ip), 3600e3);
    if (n > 15) return res.status(429).json({ error: 'Too many tries. Text Billy at (314) 899-7503.' });
    const b = req.body || {}, first = shfCap(clean(b.first, 40)), last = shfCap(clean(b.last, 40)), phone = String(b.phone || '').replace(/\D/g, '').replace(/^1(?=\d{10}$)/, '');
    if (!first || !last) return res.status(400).json({ error: 'Add your first and last name.' });
    if (phone.length !== 10) return res.status(400).json({ error: 'Enter a 10-digit cell number.' });
    const soon = SHF_SOON.includes(b.soon) ? b.soon : '', src = SHF_SRC.includes(b.source) ? b.source : '';
    if (!soon || !src) return res.status(400).json({ error: 'Answer both questions.' });
    const date = clean(b.date, 10), min = Number(b.min);
    const s = await shfState(), day = (await shfDays(s, date))[0], slot = day && day.slots.find(x => x.min === min);
    if (!slot) return res.status(409).json({ error: 'That time was just taken. Please pick another.' });
    const start = ctAt(date, min), end = new Date(start.getTime() + s.cfg.slot * 60e3), name = `${first} ${last}`;
    const couch = (await getDrops().catch(() => [])).find(d => d.id === b.couch);
    const utm = {}; ['fbcamp', 'fbsource', 'utm_adset', 'utm_ad', 'utm_source', 'utm_campaign'].forEach(k => { if (b[k]) utm[k] = clean(b[k], 120); });
    const P = (k, v) => `<p><strong>${k}</strong></p><p>${shfEsc(v)}</p>`;
    const desc = P('Name:', name) + P('Phone Number:', fmtPhone(phone)) + P('How soon do you need a couch? :', soon) + (couch ? P('Coming to see:', couch.title) : '')
      + P('How did you find us? :', src) + (Object.keys(utm).length ? P('Ad:', Object.entries(utm).map(([k, v]) => k + ' ' + v).join(' · ')) : '') + '<p>Booked on the HQ showing form</p>';
    const j = await sheetsBook({ title: `Showing for ${name}`, start: start.toISOString(), end: end.toISOString(), location: '126 E Orleans St, Pacific, MO 63069', desc });
    const id = crypto.randomBytes(6).toString('hex');
    s.book[id] = { id, name, phone, soon, source: src, couch: couch ? couch.title : '', start: start.getTime(), eventId: j.eventId || '', created: Date.now(), utm };
    Object.keys(s.book).forEach(k => { if (s.book[k].start < Date.now() - 45 * 864e5) delete s.book[k]; });
    await kset(SHF_KEY, s); refreshGoogle().catch(() => {});
    const when = `${shfDay(date)} at ${slot.label}`;
    sendText(phone, `Hi ${first}! You're booked to see couches ${when} at our showroom, 126 E Orleans St, Pacific. Can't make it? Text Billy at (314) 899-7503. - Billy's Couches`).catch(() => {});
    pushAll('New showing', `${name} · ${when}${couch ? ' · ' + couch.title : ''}`, '/?tab=sched', 'showing').catch(() => {});   // HQ app notification only, no text
    res.json({ ok: true, when, first, couch: couch ? couch.title : '' });
  } catch (e) { console.log('Showing booking failed', e.message); res.status(500).json({ error: 'Could not book that time. Text Billy at (314) 899-7503.' }); }
});
// HQ: showing form settings + the next few days.
app.get('/api/showform', async (req, res) => {
  try { const s = await shfState(), c = s.cfg, sp = c.special || {}, g = await google(false).catch(() => ({})), today = ctYmd(new Date());
    const shows = (g.showings || []).filter(r => !/cancel/i.test(r[1] || '')).map(r => ctYmd(new Date(r[0])));
    const next7 = []; for (let i = 0; i < 7; i++) { const d = jbAdd(today, i), h = sp[d] || c.hours[new Date(d + 'T12:00:00Z').getUTCDay()];
      next7.push({ date: d, label: shfDay(d), hours: c.closed.includes(d) || !h ? 'Closed' : shfRange(h[0], h[1]), special: !!sp[d] || c.closed.includes(d), booked: shows.filter(x => x === d).length }); }
    res.json({ ok: true, hours: c.hours, closed: c.closed.filter(d => d >= today).sort(), special: Object.keys(sp).filter(d => d >= today).sort().map(d => ({ date: d, range: shfRange(sp[d][0], sp[d][1]) })), next7 }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
// Special hours, typed like "2026-11-24 3:40pm-5:20pm, 2026-11-25 10am-12:40pm".
const shfMin = (h, m, ap) => (Number(h) % 12 + (/p/i.test(ap) ? 12 : 0)) * 60 + Number(m || 0);
app.post('/api/showform/cfg', async (req, res) => {
  try { const b = req.body || {}, s = await shfState(), c = s.cfg, today = ctYmd(new Date());
    if (b.closed !== undefined) c.closed = String(b.closed || '').split(/[\s,]+/).filter(x => /^\d{4}-\d{2}-\d{2}$/.test(x)).slice(0, 60);
    if (b.special !== undefined) { const sp = {}, re = /(\d{4}-\d{2}-\d{2})\s+(\d{1,2})(?::(\d{2}))?\s*(am|pm)\s*-\s*(\d{1,2})(?::(\d{2}))?\s*(am|pm)/gi; let m;
      while ((m = re.exec(String(b.special)))) { const lo = shfMin(m[2], m[3], m[4]), hi = shfMin(m[5], m[6], m[7]); if (hi > lo && m[1] >= today) sp[m[1]] = [lo, hi]; }
      if (String(b.special).trim() && !Object.keys(sp).length) return res.status(400).json({ error: 'Type it like 2026-11-24 3:40pm-5:20pm' });
      c.special = sp; }
    s.cfg = c; await kset(SHF_KEY, s); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
// ===================== END SHOWINGS =====================
app.listen(CFG.PORT, () => console.log('Billy\'s Couches dashboard on ' + CFG.PORT));

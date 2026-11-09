// Billy's Couches HQ — Signature form feed  (repo: billys-couches-dashboard)
// THIS FILE: sign-feed.js, a NEW file at the root of the dashboard repo, next to server.js.
//
// Pulls "bought it today and I'm taking it now" buyers from the new Signature &
// Agreement form (running on the proxy at /sign) so they show up on the
// Thank You Cards tab and get added to the Customers sheet, the same way the
// old Jotform signature form did.
//
// Railway variables on the DASHBOARD service:
//   SIGN_FEED_KEY   same value as SIGN_FEED_KEY on the proxy service (required)
//   SIGN_FEED_URL   optional; defaults to the proxy's /api/sign/cards

const FEED_URL = process.env.SIGN_FEED_URL
  || 'https://billys-couches-proxy-production.up.railway.app/api/sign/cards';

module.exports = async function signFeedCards() {
  const key = process.env.SIGN_FEED_KEY || '';
  if (!key) return [];
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 10000);
    const r = await fetch(FEED_URL, { headers: { 'x-sign-key': key }, signal: ctrl.signal });
    clearTimeout(t);
    if (!r.ok) { console.log('Sign feed failed:', r.status); return []; }
    const j = await r.json();
    return (j.cards || []).map((c) => ({
      id: 'sf-' + c.id,
      form: 'sign',
      name: c.name || '',
      phone: c.phone || '',
      line1: c.line1 || '',
      line2: c.line2 || '',
      type: 'Pick up today',
      date: c.submitted || '',
      submitted: c.submitted || '',
    }));
  } catch (e) {
    console.log('Sign feed error:', e.message);
    return [];
  }
};

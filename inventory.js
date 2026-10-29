/* Billy's Couches - Current Inventory page, built live from Billy's HQ (Drops tab).
   Squarespace: on /currentinventory add ONE Code Block with:
     <div id="bc-inventory"></div>
     <script src="https://hq.billyscouches.com/public/inventory.js" defer></script>
   Couches appear when you tap "Go live" in HQ and disappear when you mark them Sold. */
(function () {
  var FEED = 'https://hq.billyscouches.com/public/inventory';
  var ORDER_URL = 'https://order.billyscouches.com/';
  var SHOWING_URL = '/warehouseshowing';
  var PHONE = '+13148997503';
  var TAX = 0.0968, FEE = 0.06;
  var GRADE = {
    A: ['Like New', 'Open-box or barely used. No visible wear.', '#2e7d4f'],
    B: ['Excellent', 'Light use. Any small flaws are listed below.', '#2f5d8a'],
    C: ['Good', 'Visible wear, priced to match. Flaws listed below.', '#b7791f']
  };

  var root = document.getElementById('bc-inventory');
  if (!root) { root = document.createElement('div'); root.id = 'bc-inventory'; (document.currentScript && document.currentScript.parentNode || document.body).appendChild(root); }

  var css = ''
    + '#bc-inventory{--red:#a74d4a;--ink:#1f1a17;--mut:#6b5d54;--cream:#efe9e2;--line:#e7ded4;font-family:inherit;color:var(--ink);max-width:1180px;margin:0 auto;padding:0 0 40px}'
    + '#bc-inventory *{box-sizing:border-box}'
    + '.bci-top{display:flex;flex-wrap:wrap;gap:8px 16px;align-items:center;justify-content:center;font-size:14px;color:var(--mut);margin:6px 0 28px;text-align:center}'
    + '.bci-top b{color:var(--ink)}'
    + '.bci-item{padding:0 0 56px;margin:0 0 56px;border-bottom:1px solid var(--line)}'
    + '.bci-item:last-child{border-bottom:0}'
    + '.bci-gal{position:relative;max-width:820px;margin:0 auto 28px;aspect-ratio:4/3;background:#f4efe9;border-radius:6px;overflow:hidden;touch-action:pan-y}'
    + '.bci-track{display:flex;height:100%;transition:transform .35s ease}'
    + '.bci-track img{flex:0 0 100%;width:100%;height:100%;object-fit:cover;display:block;user-select:none;-webkit-user-drag:none}'
    + '.bci-arr{position:absolute;top:50%;transform:translateY(-50%);width:42px;height:42px;border-radius:50%;border:0;background:rgba(255,255,255,.88);color:var(--ink);font-size:22px;line-height:42px;text-align:center;cursor:pointer;box-shadow:0 2px 10px rgba(0,0,0,.15);padding:0}'
    + '.bci-arr.l{left:12px}.bci-arr.r{right:12px}'
    + '.bci-dots{position:absolute;left:0;right:0;bottom:12px;display:flex;justify-content:center;gap:6px}'
    + '.bci-dots i{width:8px;height:8px;border-radius:50%;background:rgba(255,255,255,.6);box-shadow:0 0 2px rgba(0,0,0,.4)}.bci-dots i.on{background:#fff}'
    + '.bci-body{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.4fr);grid-template-areas:"info btns" "acc btns";gap:0 48px;max-width:1100px;margin:0 auto;align-items:start}'
    + '.bci-left{grid-area:info}.bci-right{grid-area:btns}.bci-accw{grid-area:acc}'
    + '.bci-title{font-size:22px;font-weight:400;line-height:1.5;margin:0 0 6px;font-family:inherit;color:var(--ink);letter-spacing:0}'
    + '.bci-price{font-size:22px;font-weight:700;margin:0 0 6px}.bci-price s{color:var(--red);font-weight:400;margin-left:8px;font-size:19px}'
    + '.bci-grade{display:flex;align-items:center;gap:10px;margin:8px 0 2px;max-width:440px}'
    + '.bci-badge{flex:0 0 auto;display:inline-flex;align-items:center;gap:6px;font-size:13px;font-weight:700;padding:6px 12px;border-radius:999px;color:#fff;line-height:1}.bci-badge b{font-size:15px}'
    + '.bci-gtxt{font-size:13px;color:var(--mut);line-height:1.35}'
    + '.bci-q{background:none;border:0;padding:0;font:inherit;font-size:12px;font-weight:600;color:#b0524c;text-decoration:underline;text-underline-offset:2px;cursor:pointer;white-space:nowrap}'
    + '.bci-k{background:var(--cream);border-radius:12px;padding:12px 14px;margin-top:10px;max-width:440px}'
    + '.bci-del{display:none;align-items:center;gap:8px;font-size:13px;font-weight:600;color:#2e5c3e;margin:0 0 6px}.bci-del .dot{width:8px;height:8px;border-radius:50%;background:#22a15a;flex-shrink:0}'
    + '.bci-km{display:flex;align-items:center;gap:12px}.bci-ki{flex:1;min-width:0}.bci-kr{font-size:14px;line-height:1.35}'
    + '.bci-kf{font-size:11px;color:#8a7f75;margin-top:3px;line-height:1.3}'
    + '.bci-kb{flex:0 0 auto;background:#b0524c;font-size:12px;font-weight:600;line-height:1;padding:7px 12px;border-radius:999px;white-space:nowrap;color:#fff!important;text-decoration:none!important}'
    + '.bci-acc{margin-top:26px;max-width:440px;border-top:1px solid #222}'
    + '.bci-acc details{border-bottom:1px solid #222}'
    + '.bci-acc summary{list-style:none;cursor:pointer;display:flex;justify-content:space-between;align-items:center;padding:18px 0;font-size:22px;color:var(--red)}'
    + '.bci-acc summary::-webkit-details-marker{display:none}.bci-acc summary:after{content:"+";color:#222;font-size:22px;font-weight:300}.bci-acc details[open] summary:after{content:"\\2013"}'
    + '.bci-acc .in{padding:0 0 18px;font-size:14.5px;line-height:1.6}.bci-acc .in p{margin:0 0 10px}.bci-acc .in ul{margin:0;padding-left:18px}'
    + '.bci-acc .in a{color:var(--red)}'
    + '.bci-btn{display:flex;align-items:center;justify-content:center;width:100%;min-height:60px;border-radius:300px;font-size:16px;text-decoration:none!important;margin:0 0 12px;transition:opacity .15s}'
    + '.bci-btn:hover{opacity:.9}.bci-buy{background:var(--red);color:#fff!important}.bci-show{border:1.5px solid var(--red);color:var(--red)!important;background:transparent}'
    + '.bci-ft{text-align:center;font-size:14px;line-height:1.4;margin-top:6px}.bci-ft span{display:block;color:#777;font-size:13px;margin-bottom:2px}'
    + '.bci-ft a{color:#b0524c!important;font-weight:600;text-decoration:underline;text-underline-offset:3px}'
    + '.bci-ft svg{display:inline-block;width:16px;height:16px;vertical-align:-3px;margin-right:5px}'
    + '.bci-empty{text-align:center;padding:60px 16px;color:var(--mut);font-size:16px}.bci-empty a{color:var(--red)}'
    + '.bci-gm{position:fixed;inset:0;z-index:99999;background:rgba(20,12,8,.55);display:none;align-items:center;justify-content:center;padding:16px}.bci-gm.open{display:flex}'
    + '.bci-gmb{background:#fff;border-radius:18px;max-width:440px;width:100%;padding:24px 22px 20px;position:relative;color:#222;box-shadow:0 20px 50px rgba(0,0,0,.25)}'
    + '.bci-gmb h3{font-size:20px;margin:0 0 4px}.bci-gmb .sub{font-size:13px;color:var(--mut);margin:0 0 14px;line-height:1.45}'
    + '.bci-gmx{position:absolute;top:10px;right:12px;background:none;border:0;font-size:26px;line-height:1;color:#8a7f75;cursor:pointer}'
    + '.bci-gmr{display:flex;gap:12px;align-items:flex-start;padding:10px 0;border-top:1px solid #eee5db}'
    + '.bci-gmr span{flex:0 0 auto;color:#fff;font-size:12px;font-weight:700;padding:5px 10px;border-radius:999px;min-width:66px;text-align:center}'
    + '.bci-gmr p{margin:0;font-size:13px;line-height:1.45;color:#3d3833}.bci-gmf{font-size:12px;color:#8a7f75;margin:10px 0 0}'
    + '@media (max-width:767px){.bci-body{grid-template-columns:1fr;grid-template-areas:"info" "btns" "acc";gap:0}.bci-right{margin-top:16px}.bci-item{padding-bottom:40px;margin-bottom:40px}.bci-gal{margin-bottom:18px;border-radius:0}'
    + '.bci-acc{margin-top:18px}.bci-acc summary{font-size:19px;padding:15px 0}.bci-btn{min-height:54px}.bci-arr{width:36px;height:36px;line-height:36px;font-size:19px}}';
  var st = document.createElement('style'); st.textContent = css; document.head.appendChild(st);

  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function money(n) { return '$' + Math.round(n).toLocaleString('en-US'); }
  function img(u, w) { return /images\.squarespace-cdn\.com/.test(u) ? u + '?format=' + w + 'w' : u; }

  var gm = document.createElement('div');
  gm.className = 'bci-gm';
  gm.innerHTML = '<div class="bci-gmb" role="dialog" aria-label="How we grade couches"><button type="button" class="bci-gmx" aria-label="Close">&times;</button>'
    + '<h3>How we grade every couch</h3><p class="sub">Every couch is inspected and cleaned before it hits the floor, then graded honestly so there are no surprises.</p>'
    + ['A', 'B', 'C'].map(function (g) { return '<div class="bci-gmr"><span style="background:' + GRADE[g][2] + '">Grade ' + g + '</span><p><b>' + GRADE[g][0] + '.</b> ' + GRADE[g][1] + '</p></div>'; }).join('')
    + '<p class="bci-gmf">Want a closer look? Come sit on it or text Billy at (314) 899-7503 for more photos.</p></div>';
  document.body.appendChild(gm);
  document.addEventListener('click', function (e) {
    if (e.target.closest && e.target.closest('.bci-q')) { e.preventDefault(); gm.classList.add('open'); }
    else if (e.target === gm || (e.target.closest && e.target.closest('.bci-gmx'))) gm.classList.remove('open');
  });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') gm.classList.remove('open'); });

  function item(c, fee) {
    var per = Math.ceil(c.price * (1 + TAX) * (1 + FEE) / 4);
    var g = GRADE[c.grade];
    var photos = (c.photos || []).length ? c.photos : [];
    var msg = 'Hi Billy, can I get a video tour of the ' + c.title + '? (A quick video or a live FaceTime works.)';
    var details = '<p>Delivery Pricing<br>&bull; Delivery within 40 miles of Pacific, MO: $' + fee + '<br>Further out? <a href="/contact">Contact Billy</a> for a quote.</p>'
      + '<p>Delivery pricing may increase for recliners, sleepers, or specialty deliveries.</p>'
      + (c.details.length ? '<p>' + c.details.map(esc).join('<br>') + '</p>' : '')
      + (g ? '<p>Condition: Grade ' + c.grade + ' &ndash; ' + g[0] + '</p>' : '');
    return '<article class="bci-item" id="couch-' + esc(c.id) + '">'
      + (photos.length ? '<div class="bci-gal" data-n="' + photos.length + '"><div class="bci-track">'
        + photos.map(function (u, i) { return '<img src="' + esc(img(u, 1500)) + '" srcset="' + esc(img(u, 750)) + ' 750w, ' + esc(img(u, 1500)) + ' 1500w" sizes="(max-width:767px) 100vw, 820px" alt="' + esc(c.title) + (i ? ' photo ' + (i + 1) : '') + '"' + (i ? ' loading="lazy"' : '') + '>'; }).join('')
        + '</div>' + (photos.length > 1 ? '<button class="bci-arr l" aria-label="Previous photo">&#8249;</button><button class="bci-arr r" aria-label="Next photo">&#8250;</button><div class="bci-dots">' + photos.map(function (_, i) { return '<i' + (i ? '' : ' class="on"') + '></i>'; }).join('') + '</div>' : '')
        + '</div>' : '')
      + '<div class="bci-body"><div class="bci-left">'
      + '<h2 class="bci-title">' + esc(c.title) + '</h2>'
      + '<div class="bci-price">' + money(c.price) + (c.retail > c.price ? '<s>' + money(c.retail) + '</s>' : '') + '</div>'
      + (g ? '<div class="bci-grade"><span class="bci-badge" style="background:' + g[2] + '">Grade <b>' + c.grade + '</b> &middot; ' + g[0] + '</span><span class="bci-gtxt">' + g[1] + ' <button type="button" class="bci-q">What do grades mean?</button></span></div>' : '')
      + '<div class="bci-k"><div class="bci-del"></div><div class="bci-km"><div class="bci-ki"><div class="bci-kr">Or 4 payments of <b>$' + per + '</b></div><div class="bci-kf">Incl. tax + 6% fee. Subject to approval.</div></div>'
      + '<a class="bci-kb" href="' + ORDER_URL + '">Pay with Klarna</a></div></div>'
      + '</div><div class="bci-accw"><div class="bci-acc"><details><summary>Details</summary><div class="in">' + details + '</div></details>'
      + '<details><summary>Imperfections</summary><div class="in">' + (c.imperfections.length ? (c.imperfections.length > 1 ? '<ul>' + c.imperfections.map(function (x) { return '<li>' + esc(x) + '</li>'; }).join('') + '</ul>' : '<p>' + esc(c.imperfections[0]) + '</p>') : '<p>None</p>') + '</div></details>'
      + '<details><summary>Dimensions</summary><div class="in"><p>' + (esc(c.dimensions) || 'Ask Billy for exact measurements.') + '</p></div></details></div>'
      + '</div><div class="bci-right">'
      + '<a class="bci-btn bci-buy" href="' + ORDER_URL + '">Buy Now</a>'
      + '<a class="bci-btn bci-show" href="' + SHOWING_URL + '">Schedule a Showing</a>'
      + '<div class="bci-ft"><span>Can\'t make it in?</span><a href="sms:' + PHONE + '?&body=' + encodeURIComponent(msg) + '"><svg viewBox="0 0 24 24" fill="none" stroke="#b0524c" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="6" width="14" height="12" rx="2"/><path d="M16 10l6-3v10l-6-3z"/></svg>Request a video tour</a></div>'
      + '</div></div></article>';
  }

  function slider(gal) {
    var n = +gal.getAttribute('data-n'); if (n < 2) return;
    var tr = gal.querySelector('.bci-track'), dots = gal.querySelectorAll('.bci-dots i'), i = 0, x0 = null;
    function go(k) { i = (k + n) % n; tr.style.transform = 'translateX(' + (-100 * i) + '%)'; for (var d = 0; d < dots.length; d++) dots[d].className = d === i ? 'on' : ''; }
    gal.querySelector('.l').onclick = function () { go(i - 1); };
    gal.querySelector('.r').onclick = function () { go(i + 1); };
    gal.addEventListener('touchstart', function (e) { x0 = e.touches[0].clientX; }, { passive: true });
    gal.addEventListener('touchend', function (e) { if (x0 == null) return; var dx = e.changedTouches[0].clientX - x0; if (Math.abs(dx) > 40) go(i + (dx < 0 ? 1 : -1)); x0 = null; });
  }

  root.innerHTML = '<div class="bci-empty">Loading couches&hellip;</div>';
  fetch(FEED, { cache: 'no-store' }).then(function (r) { return r.json(); }).then(function (d) {
    var list = (d && d.couches) || [], fee = d.deliveryFee || 150;
    var upd = d.updated ? new Date(d.updated).toLocaleDateString('en-US', { month: 'numeric', day: 'numeric', year: '2-digit' }) : '';
    if (!list.length) { root.innerHTML = '<div class="bci-empty">Everything sold! New couches drop to the First Dibs list first. <a href="/firstdibs">Join First Dibs</a></div>'; return; }
    root.innerHTML = '<div class="bci-top"><span><b>' + list.length + '</b> couches available</span>' + (upd ? '<span>Last updated: ' + upd + '</span>' : '') + '<span>Sales tax applicable.</span></div>'
      + list.map(function (c) { return item(c, fee); }).join('');
    Array.prototype.forEach.call(root.querySelectorAll('.bci-gal'), slider);
    if (location.hash) { var t = document.getElementById(location.hash.slice(1)); if (t) t.scrollIntoView(); }
    fetch('https://order.billyscouches.com/api/delivery-status').then(function (r) { return r.json(); }).then(function (s) {
      if (!s || !s.nextDate) return;
      var when = s.daysOut === 0 ? 'today' : s.daysOut === 1 ? 'tomorrow' : s.dayName.slice(0, 3) + ', ' + s.dateLabel;
      Array.prototype.forEach.call(root.querySelectorAll('.bci-del'), function (el) { el.innerHTML = '<span class="dot"></span>Delivered as soon as ' + when; el.style.display = 'flex'; });
    }).catch(function () {});
  }).catch(function () {
    root.innerHTML = '<div class="bci-empty">Couldn\'t load the inventory right now. Text Billy at <a href="sms:' + PHONE + '">(314) 899-7503</a> for what\'s available.</div>';
  });
})();

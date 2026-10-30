// Billy's Couches – "Just sold" pop-ups. Served from Billy's HQ; edit here, no Squarespace changes needed.
(function(){
  if (document.getElementById('bc-sold')) return;
  var st = document.createElement('style'); st.textContent = "#bc-sold{box-sizing:border-box;position:fixed;left:16px;bottom:16px;z-index:9999;max-width:340px;width:calc(100% - 32px);\n    display:flex;gap:12px;align-items:center;background:#fff;color:#1A1716;border:2px solid #1A1716;border-radius:16px;\n    padding:12px 38px 12px 12px;box-shadow:0 12px 30px rgba(0,0,0,.18);font-family:inherit;line-height:1.3;\n    transform:translateY(140%);opacity:0;transition:transform .45s cubic-bezier(.2,.9,.3,1.2),opacity .3s;pointer-events:none}\n  #bc-sold.on{transform:none;opacity:1;pointer-events:auto}\n  #bc-sold .ic{flex:none;width:56px;height:56px;overflow:hidden;border-radius:12px;background:#A5504A;color:#fff;display:flex;align-items:center;justify-content:center;font-size:22px}\n  #bc-sold .ic img{width:100%;height:100%;object-fit:cover;display:block}\n  #bc-sold .t1{font-size:12px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;color:#A5504A}\n  #bc-sold .t2{font-size:15px;font-weight:700;margin:2px 0}\n  #bc-sold .t3{font-size:12.5px;color:#6B625C}\n  #bc-sold .t3 a{color:#A5504A;font-weight:700;text-decoration:underline}\n  #bc-sold .x{position:absolute;top:6px;right:8px;border:0;background:none;font-size:20px;line-height:1;color:#6B625C;cursor:pointer;padding:4px}\n  @media (max-width:640px){#bc-sold{left:10px;bottom:10px;width:calc(100% - 20px);max-width:none}}"; document.head.appendChild(st);
  var w = document.createElement('div'); w.innerHTML = "<div id=\"bc-sold\" role=\"status\" aria-live=\"polite\">\n  <div class=\"ic\" id=\"bc-sold-i\">&#128715;</div>\n  <div><div class=\"t1\" id=\"bc-sold-h\">Just sold</div><div class=\"t2\" id=\"bc-sold-t\"></div><div class=\"t3\" id=\"bc-sold-s\"></div></div>\n  <button class=\"x\" id=\"bc-sold-x\" aria-label=\"Close\">&times;</button>\n</div>"; document.body.appendChild(w.firstElementChild);
})();
(function(){
  var FEED = 'https://hq.billyscouches.com/public/recent-sales';
  // Pages to show on ('/' = home). Remove any you don't want.
  var SHOW_ON = ['/', '/currentinventory', '/firstdibs', '/visitshowroom', '/ways-to-pay', '/cart', '/ourstory'];
  var FIRST_DELAY = 6000, SHOW_FOR = 6000, GAP = 8000, MAX_PER_PAGE = 7;

  var path = location.pathname.replace(/\/$/, '') || '/';
  var ok = SHOW_ON.some(function(p){ return p === '/' ? path === '/' : path.indexOf(p) === 0; });
  var box = document.getElementById('bc-sold'); if (!ok || !box) return;
  try { if (sessionStorage.getItem('bcSoldOff')) return; } catch (e) {}

  function daysAgo(s){ var t = new Date(); t.setHours(0,0,0,0); var d = new Date(s.at); d.setHours(0,0,0,0); return Math.round((t - d) / 864e5); }
  function ago(s){
    var ms = Date.now() - Date.parse(s.at), h = ms / 36e5, d = Math.floor(ms / 864e5);
    if (s.exact) { if (h < 1) return Math.max(1, Math.round(ms / 6e4)) + ' min ago'; if (h < 24) return Math.round(h) + (Math.round(h) === 1 ? ' hour ago' : ' hours ago'); }
    var today = new Date(); today.setHours(0,0,0,0); var day = new Date(s.at); day.setHours(0,0,0,0);
    var n = Math.round((today - day) / 864e5); return n <= 0 ? 'today' : n === 1 ? 'yesterday' : n + ' days ago';
  }
  fetch(FEED, { cache: 'no-store' }).then(function(r){ return r.json(); }).then(function(d){
    var list = (d && d.sales) || []; if (!list.length) return;
    var BASE = FEED.replace(/\/public\/recent-sales.*$/, '');
    // newest sale first; keep going where the last page left off, but start over when a new sale comes in
    var i = 0, shown = 0, timer, sig = list[0].at;
    try { if (sessionStorage.getItem('bcSoldSig') === sig) i = +sessionStorage.getItem('bcSoldIdx') || 0; else { sessionStorage.setItem('bcSoldSig', sig); sessionStorage.setItem('bcSoldIdx', 0); } } catch (e) {}
    // Sit above any sticky bottom bar (like the mobile Shop Now / Visit Showroom buttons).
    // Sit above any bar pinned to the bottom (like the mobile Shop Now / Visit Showroom bar),
    // even one that's still hidden and slides in when you scroll.
    function lift(){
      var vh = window.innerHeight, vw = window.innerWidth, need = 0;
      var els = document.body.getElementsByTagName('*');
      for (var k = 0; k < els.length; k++) {
        var el = els[k]; if (el === box || box.contains(el)) continue;
        var cs = getComputedStyle(el); if (cs.position !== 'fixed' || cs.display === 'none' || cs.visibility === 'hidden' || cs.bottom === 'auto') continue;
        var h = el.offsetHeight, bot = parseFloat(cs.bottom) || 0;
        if (h > 0 && h < vh * 0.4 && el.offsetWidth > vw * 0.5 && bot < 60) need = Math.max(need, h + bot);
      }
      box.style.bottom = (need ? need + 10 : (vw <= 640 ? 10 : 16)) + 'px';
    }
    function show(){
      if (shown >= MAX_PER_PAGE) return;
      var s = list[i % list.length]; i++; shown++;
      try { sessionStorage.setItem('bcSoldIdx', i % list.length); } catch (e) {}
      document.getElementById('bc-sold-h').textContent = daysAgo(s) <= 1 ? 'Just sold' : 'Sold';
      document.getElementById('bc-sold-t').textContent = s.title;
      var ic = document.getElementById('bc-sold-i');
      if (s.photo) { ic.innerHTML = ''; var im = new Image(); im.alt = ''; im.src = /^https?:/.test(s.photo) ? s.photo : BASE + s.photo; ic.appendChild(im); } else ic.innerHTML = '&#128715;';
      document.getElementById('bc-sold-s').innerHTML = (s.who ? s.who.replace(/[<>&]/g, '') + ' bought it ' : 'Sold ') + ago(s) + ' &middot; <a href="/currentinventory">See what&rsquo;s left</a>';
      lift(); box.classList.add('on');
      timer = setTimeout(function(){ box.classList.remove('on'); timer = setTimeout(show, GAP); }, SHOW_FOR);
    }
    document.getElementById('bc-sold-x').onclick = function(){ clearTimeout(timer); box.classList.remove('on'); try { sessionStorage.setItem('bcSoldOff', '1'); } catch (e) {} };
    setTimeout(show, FIRST_DELAY);
  }).catch(function(){});
})();
// Floor previews on /firstdibs (#fdGrid) and /visitshowroom (#bcLiveGrid): filled from Billy's HQ inventory
// (the Current Inventory page is now built by HQ, so the old page-scraping code finds nothing).
(function(){
  var grids = [['fdGrid', 4], ['bcLiveGrid', 12]].map(function(g){ return [document.getElementById(g[0]), g[1], g[0]]; }).filter(function(g){ return g[0]; });
  if (!grids.length) return;
  function esc(s){ return String(s == null ? '' : s).replace(/[&<>"]/g, function(c){ return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }
  function money(n){ return '$' + Math.round(n).toLocaleString('en-US'); }
  function img(u, w){ return /images\.squarespace-cdn\.com/.test(u) ? u + '?format=' + w + 'w' : u; }
  fetch('https://hq.billyscouches.com/public/inventory', { cache: 'no-store' }).then(function(r){ return r.json(); }).then(function(d){
    var list = (d && d.couches) || []; if (!list.length) return;
    grids.forEach(function(g){
      var el = g[0], fd = g[2] === 'fdGrid', items = list.slice(0, g[1]);
      var html = items.map(function(c){
        var t = esc(c.title), ph = (c.photos || [])[0], pr = money(c.price) + (c.retail > c.price ? '<s>' + money(c.retail) + '</s>' : '');
        return fd
          ? '<a class="fd-card" href="/currentinventory#couch-' + esc(c.id) + '"><div class="im">' + (ph ? '<img loading="lazy" src="' + esc(img(ph, 500)) + '" alt="' + t + '">' : '') + '</div><div class="bd"><p class="t">' + t + '</p><div class="pr">' + pr + '</div></div></a>'
          : '<a class="bc-live-card" href="/currentinventory#couch-' + esc(c.id) + '"><div class="bc-live-img">' + (ph ? '<img loading="lazy" src="' + esc(img(ph, 750)) + '" alt="' + t + '">' : '') + '</div><div class="bc-live-body"><p class="bc-live-t">' + t + '</p><div class="bc-live-p">' + pr + '</div><span class="bc-live-cta">Book a time to sit on it &rarr;</span></div></a>';
      }).join('');
      var card = fd ? '.fd-card' : '.bc-live-card';
      function fill(){ if (!el.querySelector(card)) el.innerHTML = html; }
      fill(); setTimeout(fill, 1500); setTimeout(fill, 4000);   // the page's old script may overwrite it with "See everything..."
    });
  }).catch(function(){});
})();
// Any other page whose old "on the floor" preview gave up ("See everything on our Current Inventory page"):
// swap that message for live couch cards from HQ. Works on pages we don't know the grid id for (e.g. the showing thank-you page).
(function(){
  var RX = /^see everything (on the floor )?on our current inventory page\.?$/i;
  function esc(s){ return String(s == null ? '' : s).replace(/[&<>"]/g, function(c){ return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }
  function money(n){ return '$' + Math.round(n).toLocaleString('en-US'); }
  function img(u){ return /images\.squarespace-cdn\.com/.test(u) ? u + '?format=500w' : u; }
  var list = null, css = false;
  function addCss(){ if (css) return; css = true; var st = document.createElement('style');
    st.textContent = '.bcf-grid{display:grid!important;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:14px;width:100%;grid-column:1/-1;margin:0}'
      + '.bcf-card{display:block;background:#fff;border:1px solid #e8e0d6;border-radius:14px;overflow:hidden;text-decoration:none!important;color:#1f1a17!important;transition:transform .15s}.bcf-card:hover{transform:translateY(-2px)}'
      + '.bcf-card .im{aspect-ratio:4/3;background:#f2ede7}.bcf-card img{width:100%;height:100%;object-fit:cover;display:block}'
      + '.bcf-card .bd{padding:10px 12px 12px}.bcf-card .t{margin:0 0 4px!important;font-size:14px!important;line-height:1.35!important;font-weight:600;letter-spacing:0;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}'
      + '.bcf-card .p{font-size:15px!important;font-weight:700;line-height:1.3}.bcf-card s{color:#b0524c;font-weight:400;margin-left:6px;font-size:13px}'
      + '@media(max-width:640px){.bcf-grid{grid-template-columns:1fr 1fr;gap:10px}.bcf-card .t{font-size:13px!important}.bcf-card .bd{padding:8px 10px 10px}}';
    document.head.appendChild(st); }
  function scan(){
    if (!list || !list.length) return;
    var els = document.querySelectorAll('div,p,span');
    for (var i = 0; i < els.length; i++) {
      var el = els[i]; if (el.children.length > 2 || el.querySelector('div,p,span') || !RX.test((el.textContent || '').replace(/\s+/g, ' ').trim())) continue;
      var box = el.parentElement; if (!box || box.querySelector('.bcf-card, .fd-card, .bc-live-card')) continue;
      addCss(); box.style.display = 'block'; box.style.width = '100%';
      box.innerHTML = '<div class="bcf-grid">' + list.slice(0, 8).map(function(c){ var ph = (c.photos || [])[0];
        return '<a class="bcf-card" href="/currentinventory#couch-' + esc(c.id) + '"><div class="im">' + (ph ? '<img loading="lazy" src="' + esc(img(ph)) + '" alt="' + esc(c.title) + '">' : '') + '</div>'
          + '<div class="bd"><div class="t">' + esc(c.title) + '</div><div class="p">' + money(c.price) + (c.retail > c.price ? '<s>' + money(c.retail) + '</s>' : '') + '</div></div></a>'; }).join('') + '</div>';
    }
  }
  fetch('https://hq.billyscouches.com/public/inventory', { cache: 'no-store' }).then(function(r){ return r.json(); }).then(function(d){
    list = (d && d.couches) || []; scan(); setTimeout(scan, 1500); setTimeout(scan, 4000); setTimeout(scan, 8000);
    // also catch the message whenever the page's own script writes it
    var t, mo = new MutationObserver(function(){ clearTimeout(t); t = setTimeout(scan, 200); });
    mo.observe(document.body, { childList: true, subtree: true }); setTimeout(function(){ mo.disconnect(); }, 20000);
  }).catch(function(){});
})();

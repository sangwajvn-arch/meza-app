/* Meza — offline helper. Loaded in the <head> of every page.
   1. Registers the service worker (so pages open without internet).
   2. Shows a banner when the internet is gone, and when it comes back.
   3. Tells the user when a button press did NOT reach the server.            */
(function () {
    'use strict';
    if (window.__mezaPwa) return;
    window.__mezaPwa = true;

    // ---- 1. Installable app that reopens the same page ---------------------
    try {
        var link = document.querySelector('link[rel="manifest"]');
        if (!link) {
            link = document.createElement('link');
            link.rel = 'manifest';
            document.head.appendChild(link);
        }
        link.href = '/manifest.webmanifest?start=' + encodeURIComponent(location.pathname + location.search);
    } catch (e) { /* not important */ }

    // ---- 2. Service worker --------------------------------------------------
    var secure = location.protocol === 'https:' || location.hostname === 'localhost' || location.hostname === '127.0.0.1';
    if ('serviceWorker' in navigator && secure) {
        window.addEventListener('load', function () {
            navigator.serviceWorker.register('/sw.js').catch(function () { /* offline mode simply stays off */ });
        });
    }

    // ---- Owner dashboard on a phone: keep the chosen tab in view ----
    document.addEventListener('DOMContentLoaded', function () {
        var nav = document.querySelector('.sidebar nav');
        if (!nav || !window.MutationObserver) return;
        var follow = function () {
            var active = nav.querySelector('.nav-item.active');
            if (active && active.scrollIntoView && window.innerWidth <= 900) active.scrollIntoView({ inline: 'center', block: 'nearest', behavior: 'smooth' });
        };
        new MutationObserver(follow).observe(nav, { attributes: true, subtree: true, attributeFilter: ['class'] });
        follow();
    });

    // ---- 3. Banner + toast --------------------------------------------------
    var css = '' +
        '#meza-net{position:fixed;left:0;right:0;top:0;z-index:2147483000;padding:calc(env(safe-area-inset-top,0px) + 7px) 12px 7px;' +
        'font:700 12px/1.35 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;text-align:center;color:#FAF6EE;background:#A8371E;' +
        'transform:translateY(-110%);transition:transform .25s ease;pointer-events:none}' +
        '#meza-net.show{transform:none}#meza-net.on{background:#25381F}' +
        '#meza-toast{position:fixed;left:12px;right:12px;bottom:calc(env(safe-area-inset-bottom,0px) + 84px);z-index:2147483001;margin:0 auto;max-width:420px;' +
        'padding:13px 16px;border-radius:12px;background:#1A1712;color:#FAF6EE;font:700 13px/1.4 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;' +
        'text-align:center;box-shadow:0 10px 30px rgba(0,0,0,.3)}';
    function addStyle() {
        if (document.getElementById('meza-net-style')) return;
        var style = document.createElement('style');
        style.id = 'meza-net-style';
        style.textContent = css;
        (document.head || document.documentElement).appendChild(style);
    }

    var bar = null, hideTimer = null, offline = false, probeTimer = null, toastTimer = null, lastToast = 0;

    function showBar(text, online) {
        addStyle();
        if (!bar) {
            bar = document.createElement('div');
            bar.id = 'meza-net';
            bar.setAttribute('role', 'status');
            bar.setAttribute('aria-live', 'polite');
            (document.body || document.documentElement).appendChild(bar);
        }
        bar.textContent = text;
        bar.className = online ? 'on' : '';
        void bar.offsetWidth;                       // let the slide-in animation run
        bar.classList.add('show');
        clearTimeout(hideTimer);
    }
    function hideBar() { if (bar) bar.classList.remove('show'); }

    function toast(message) {
        var now = Date.now();
        if (now - lastToast < 3500) return;          // never spam
        lastToast = now;
        addStyle();
        var old = document.getElementById('meza-toast');
        if (old) old.remove();
        var box = document.createElement('div');
        box.id = 'meza-toast';
        box.setAttribute('role', 'alert');
        box.textContent = message;
        (document.body || document.documentElement).appendChild(box);
        clearTimeout(toastTimer);
        toastTimer = setTimeout(function () { box.remove(); }, 5000);
    }

    var realFetch = window.fetch ? window.fetch.bind(window) : null;

    function setOffline(state) {
        if (state === offline) return;
        offline = state;
        if (offline) {
            var show = function () { showBar('You are offline. Showing saved pages. Orders and payments need internet.', false); };
            if (document.body) show(); else document.addEventListener('DOMContentLoaded', show);
            startProbe();
        } else {
            showBar('Back online', true);
            hideTimer = setTimeout(hideBar, 2500);
            stopProbe();
            try { window.dispatchEvent(new Event('meza:online')); } catch (e) { /* old browser */ }
        }
    }

    // While offline, quietly check every 6 seconds whether the internet is back.
    function startProbe() {
        if (probeTimer || !realFetch) return;
        probeTimer = setInterval(function () {
            realFetch('/health', { cache: 'no-store' }).then(function (r) { if (r && r.ok) setOffline(false); }).catch(function () { /* still offline */ });
        }, 6000);
    }
    function stopProbe() { clearInterval(probeTimer); probeTimer = null; }

    window.addEventListener('offline', function () { setOffline(true); });
    window.addEventListener('online', function () {
        if (!realFetch) return;
        realFetch('/health', { cache: 'no-store' }).then(function (r) { if (r && r.ok) setOffline(false); }).catch(function () { /* wifi up, internet not yet */ });
    });
    if (navigator.onLine === false) setOffline(true);

    // Watch every request the page makes. A failure means "no internet".
    if (realFetch) {
        window.fetch = function (input, init) {
            var method = String((init && init.method) || (input && input.method) || 'GET').toUpperCase();
            return realFetch(input, init).then(function (response) {
                var fromSavedCopy = response && response.headers && response.headers.get('X-Meza-Offline');
                setOffline(!!fromSavedCopy);
                return response;
            }, function (error) {
                setOffline(true);
                if (method !== 'GET') toast('No internet. That did not go through. Please try again when you are back online.');
                throw error;
            });
        };
    }
})();

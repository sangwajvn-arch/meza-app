/* Meza service worker.
   - Pages, styles and scripts are saved so the app opens with no internet.
   - The public menu and restaurant name are saved so customers can still browse.
   - Orders, payments, staff and owner data are NEVER saved: they always go to the server.
   Change VERSION whenever you want every phone to refresh its saved files. */
'use strict';

const VERSION = 'meza-v1';
const SHELL = VERSION + '-shell';
const PAGES = VERSION + '-pages';
const DATA = VERSION + '-data';
const ASSETS = VERSION + '-assets';
const IMAGES = VERSION + '-images';
const KEEP = [SHELL, PAGES, DATA, ASSETS, IMAGES];

const SHELL_FILES = ['/offline.html', '/style.css', '/mobile.css', '/pwa.js', '/icon-192.png', '/icon-512.png', '/apple-touch-icon.png'];
const PAGE_FILES = [
    '/', '/index.html', '/login.html', '/register.html', '/forgot-password.html', '/reset-password.html',
    '/staff-login.html', '/waitress.html', '/kitchen.html', '/cashier.html', '/admin.html', '/super-admin.html'
];

self.addEventListener('install', event => {
    event.waitUntil((async () => {
        const shell = await caches.open(SHELL);
        const pages = await caches.open(PAGES);
        // One missing file must never stop the install, so add them one by one.
        await Promise.all(SHELL_FILES.map(f => shell.add(f).catch(() => {})));
        await Promise.all(PAGE_FILES.map(f => pages.add(new Request(f, { cache: 'reload' })).catch(() => {})));
        await self.skipWaiting();
    })());
});

self.addEventListener('activate', event => {
    event.waitUntil((async () => {
        const names = await caches.keys();
        await Promise.all(names.filter(n => !KEEP.includes(n)).map(n => caches.delete(n)));
        await self.clients.claim();
    })());
});

function timeout(ms) { return new Promise(resolve => setTimeout(() => resolve(null), ms)); }

function withHeader(response, name, value) {
    const headers = new Headers(response.headers);
    headers.set(name, value);
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

async function trim(cache, max) {
    const keys = await cache.keys();
    for (let i = 0; i < keys.length - max; i++) await cache.delete(keys[i]);
}

// ---- Page loads: network first, saved copy if the network is slow or gone ----
async function handleNavigation(event) {
    const req = event.request;
    const url = new URL(req.url);
    const key = url.origin + url.pathname;                 // one saved copy per page, whatever the ?query
    const cache = await caches.open(PAGES);

    const network = fetch(req).then(res => {
        const type = res.headers.get('content-type') || '';
        if (res.ok && res.type === 'basic' && type.includes('text/html')) cache.put(key, res.clone());
        return res;
    });
    network.catch(() => {});                               // the failure is handled below; this just keeps the console quiet
    const saved = await cache.match(key);

    if (!saved) {
        try { return await network; }
        catch (e) { return (await caches.match('/offline.html')) || Response.error(); }
    }
    try {
        // Slow connection? After 3.5 seconds show the saved copy instead of a blank screen.
        const winner = await Promise.race([network, timeout(3500)]);
        if (winner) return winner;
        event.waitUntil(network.catch(() => {}));
        return saved;
    } catch (e) {
        return saved;
    }
}

// ---- Public data (menu, restaurant name): network first, saved copy offline ----
async function handleData(event) {
    const req = event.request;
    const cache = await caches.open(DATA);
    const network = fetch(req).then(res => {
        const cc = res.headers.get('Cache-Control') || '';
        if (res.ok && !cc.includes('no-store')) cache.put(req, res.clone());
        return res;
    });
    network.catch(() => {});
    const saved = await cache.match(req);

    if (!saved) {
        try { return await network; }
        catch (e) {
            return new Response(JSON.stringify({ error: 'You are offline.' }), {
                status: 503, headers: { 'Content-Type': 'application/json', 'X-Meza-Offline': '1' }
            });
        }
    }
    try {
        const winner = await Promise.race([network, timeout(4000)]);
        if (winner) return winner;
        event.waitUntil(network.catch(() => {}));
        return withHeader(saved, 'X-Meza-Offline', '1');
    } catch (e) {
        return withHeader(saved, 'X-Meza-Offline', '1');
    }
}

// ---- Files that rarely change: show the saved copy now, refresh it quietly ----
async function staleWhileRevalidate(event, cacheName, max) {
    const req = event.request;
    const cache = await caches.open(cacheName);
    const saved = await cache.match(req);
    const update = fetch(req).then(async res => {
        if (res && (res.ok || res.type === 'opaque')) {
            await cache.put(req, res.clone());
            if (max) await trim(cache, max);
        }
        return res;
    }).catch(() => null);
    if (saved) { event.waitUntil(update); return saved; }
    return (await update) || Response.error();
}

self.addEventListener('fetch', event => {
    const req = event.request;
    if (req.method !== 'GET') return;                      // orders, payments, logins: always live
    const url = new URL(req.url);

    if (req.mode === 'navigate') { event.respondWith(handleNavigation(event)); return; }

    if (url.origin === self.location.origin) {
        if (url.pathname === '/menu' || /^\/restaurants\/\d+$/.test(url.pathname)) {
            event.respondWith(handleData(event));
            return;
        }
        if (url.pathname !== '/sw.js' && /\.(css|js|png|svg|jpe?g|webp|ico|woff2?|ttf)$/i.test(url.pathname)) {
            event.respondWith(staleWhileRevalidate(event, ASSETS));
        }
        return;                                            // every other request goes straight to the server
    }

    if (url.hostname === 'fonts.googleapis.com' || url.hostname === 'fonts.gstatic.com') {
        event.respondWith(staleWhileRevalidate(event, ASSETS));
    } else if (req.destination === 'image') {
        event.respondWith(staleWhileRevalidate(event, IMAGES, 40));   // dish photos, at most 40 kept
    }
});

// Meza: make every page phone-friendly and offline-ready.
//
// How to use (from your project folder, the one that contains server.js):
//     node add-mobile.js
// It is safe to run again at any time. It never deletes anything.
//
// It edits every .html file inside your "public" folder:
//   - adds the phone viewport tag (without it phones show a tiny desktop page)
//   - adds the offline helper script and the phone stylesheet
//   - fixes the customer page so it can follow its order status (index.html only)

const fs = require('fs');
const path = require('path');

const publicDir = path.resolve(process.argv[2] || (fs.existsSync('public') ? 'public' : '.'));
if (!fs.existsSync(publicDir)) {
    console.error('Cannot find the folder: ' + publicDir);
    process.exit(1);
}

const NEEDED = ['mobile.css', 'pwa.js', 'sw.js', 'offline.html', 'icon-192.png', 'icon-512.png', 'apple-touch-icon.png'];
const missing = NEEDED.filter(f => !fs.existsSync(path.join(publicDir, f)));
if (missing.length) {
    console.error('\nThese files must be copied into ' + publicDir + ' first:\n  ' + missing.join('\n  '));
    console.error('\nCopy them there, then run this again.');
    process.exit(1);
}

const HEAD_START = '<!-- meza-mobile -->';
const HEAD_END = '<!-- /meza-mobile -->';
const CSS_TAG = '<link rel="stylesheet" href="/mobile.css"> <!-- meza-mobile-css -->';

const headBlock = [
    HEAD_START,
    '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">',
    '<meta name="theme-color" content="#1A1712">',
    '<meta name="mobile-web-app-capable" content="yes">',
    '<meta name="apple-mobile-web-app-capable" content="yes">',
    '<meta name="apple-mobile-web-app-title" content="Meza">',
    '<link rel="apple-touch-icon" href="/apple-touch-icon.png">',
    '<script src="/pwa.js"></script>',
    HEAD_END
].join('\n    ');

// Customer page: the old code asked for the staff-only order list, which the secured server refuses.
const OLD_STATUS = /fetch\(\s*'\/orders\?restaurant='\s*\+\s*restaurantId\s*\)\s*\.then\(\s*response\s*=>\s*response\.json\(\)\s*\)\s*\.then\(\s*orders\s*=>\s*\{\s*const\s+order\s*=\s*orders\.find\(\s*o\s*=>\s*o\.id\s*===\s*currentOrderId\s*\)\s*;\s*if\s*\(\s*!order\s*\)\s*return\s*;/;
const NEW_STATUS = "fetch('/orders/' + currentOrderId + '/status')\n            .then(response => response.json())\n            .then(order => {\n                if (!order || order.error) return;";

let changed = 0;
for (const file of fs.readdirSync(publicDir).filter(f => f.toLowerCase().endsWith('.html')).sort()) {
    if (file === 'offline.html') continue;
    const full = path.join(publicDir, file);
    let html = fs.readFileSync(full, 'utf8');
    const original = html;
    const notes = [];

    // 1. remove any older copy of our block, and any other viewport tag, so there is exactly one of each
    html = html.replace(new RegExp(HEAD_START + '[\\s\\S]*?' + HEAD_END + '\\s*', 'g'), '');
    html = html.replace(/\s*<link rel="stylesheet" href="\/mobile\.css"> <!-- meza-mobile-css -->/g, '');
    html = html.replace(/[ \t]*<meta\s+name=["']viewport["'][^>]*>\s*\n?/gi, '');

    // 2. add the block right after <head>, and the phone stylesheet last (so it wins over the page's own CSS)
    if (!/<head[^>]*>/i.test(html) || !/<\/head>/i.test(html)) {
        console.log('  skipped  ' + file + ' (no <head> found)');
        continue;
    }
    html = html.replace(/<head([^>]*)>/i, (m) => m + '\n    ' + headBlock);
    html = html.replace(/<\/head>/i, '    ' + CSS_TAG + '\n</head>');
    notes.push('phone + offline tags');

    // 3. customer page order-status fix
    if (/watchOrderStatus/.test(html) && OLD_STATUS.test(html)) {
        html = html.replace(OLD_STATUS, NEW_STATUS);
        notes.push('order-status fix applied');
    } else if (/watchOrderStatus/.test(html) && /fetch\(\s*'\/orders\?restaurant='/.test(html)) {
        notes.push('!! order-status code looks different: change it by hand (see the chat)');
    }

    if (html !== original) {
        fs.writeFileSync(full, html, 'utf8');
        changed++;
        console.log('  updated  ' + file + '  (' + notes.join(', ') + ')');
    } else {
        console.log('  ok       ' + file + '  (already up to date)');
    }
}

console.log('\nDone. ' + changed + ' page(s) changed in ' + publicDir + '.');
console.log('Next: save your work (git add, commit, push) so Render deploys it.');

const db = require('./db');

const restaurants = db.prepare('SELECT * FROM restaurants ORDER BY id ASC').all();

// Pass 1: move everything to temporary negative IDs to avoid collisions
restaurants.forEach(r => {
    const tempId = -r.id;
    db.prepare('UPDATE restaurants SET id = ? WHERE id = ?').run(tempId, r.id);
    db.prepare('UPDATE menu_items SET restaurant_id = ? WHERE restaurant_id = ?').run(tempId, r.id);
    db.prepare('UPDATE orders SET restaurant_id = ? WHERE restaurant_id = ?').run(tempId, r.id);
    db.prepare('UPDATE messages SET restaurant_id = ? WHERE restaurant_id = ?').run(tempId, r.id);
});

// Pass 2: assign clean sequential IDs (1, 2, 3...)
restaurants.forEach((r, index) => {
    const oldTempId = -r.id;
    const newId = index + 1;
    db.prepare('UPDATE restaurants SET id = ? WHERE id = ?').run(newId, oldTempId);
    db.prepare('UPDATE menu_items SET restaurant_id = ? WHERE restaurant_id = ?').run(newId, oldTempId);
    db.prepare('UPDATE orders SET restaurant_id = ? WHERE restaurant_id = ?').run(newId, oldTempId);
    db.prepare('UPDATE messages SET restaurant_id = ? WHERE restaurant_id = ?').run(newId, oldTempId);
    console.log(`${r.name}: ${r.id} → ${newId}`);
});

// Make sure future new restaurants continue after the last renumbered one
db.prepare("UPDATE sqlite_sequence SET seq = ? WHERE name = 'restaurants'").run(restaurants.length);

console.log('Done renumbering.');
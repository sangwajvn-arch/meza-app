const db = require('./db');

const args = process.argv.slice(2);
const command = args[0];


const relatedTables = [
  'owners',
  'menu_items',
  'orders',
  'messages',
  'staff',
  'inventory_items',
  'venue_areas',
  'venue_tables',
  'vendors',
  'venue_contacts',
  'venue_settings'
];

function getRestaurantSummary(restaurant) {
  const counts = {};

  for (const table of relatedTables) {
    counts[table] = db
      .prepare(`SELECT COUNT(*) AS total FROM ${table} WHERE restaurant_id = ?`)
      .get(restaurant.id).total;
  }

  return {
    id: restaurant.id,
    name: restaurant.name,
    ...counts
  };
}

function listRestaurants() {
  const restaurants = db
    .prepare('SELECT id, name FROM restaurants ORDER BY id')
    .all();

  if (!restaurants.length) {
    console.log('No restaurants found.');
    return;
  }

  console.table(restaurants.map(getRestaurantSummary));
}

function deleteRestaurant(id) {
  const restaurant = db
    .prepare('SELECT id, name FROM restaurants WHERE id = ?')
    .get(id);

  if (!restaurant) {
    console.log(`Restaurant ID ${id} does not exist.`);
    return;
  }

  const removeRestaurant = db.transaction(() => {
    for (const table of relatedTables) {
      db.prepare(`DELETE FROM ${table} WHERE restaurant_id = ?`).run(id);
    }

    db.prepare('DELETE FROM restaurants WHERE id = ?').run(id);
  });

  removeRestaurant();

  console.log(`Deleted "${restaurant.name}" (ID ${id}) and its linked data.`);
}

if (command === '--list') {
  listRestaurants();
} else if (command === '--delete') {
  const ids = args.slice(1).map(Number).filter(Number.isInteger);

  if (!ids.length) {
    console.log('Use: node fix.js --delete 4');
    process.exit(1);
  }

  ids.forEach(deleteRestaurant);
} else {
  console.log(`
Restaurant cleanup tool

List restaurants:
  node fix.js --list

Delete one restaurant:
  node fix.js --delete 4

Delete multiple restaurants:
  node fix.js --delete 4 5
  `);
}
function renameRestaurant(id, newName) {
  const restaurant = db
    .prepare('SELECT id, name FROM restaurants WHERE id = ?')
    .get(id);

  if (!restaurant) {
    console.log(`Restaurant ID ${id} does not exist.`);
    return;
  }

  if (!newName || !newName.trim()) {
    console.log('Enter a new restaurant name.');
    return;
  }

  db.prepare('UPDATE restaurants SET name = ? WHERE id = ?')
    .run(newName.trim(), id);

  console.log(
    `Renamed "${restaurant.name}" to "${newName.trim()}" (ID ${id}).`
  );
}
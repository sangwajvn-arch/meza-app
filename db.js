const Database = require('better-sqlite3');
const db = new Database('meza.db');

db.exec(`
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY,
        restaurant_id INTEGER,
        table_number TEXT,
        items TEXT,
        status TEXT
    )
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS restaurants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT
    )
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS menu_items (
        id TEXT,
        restaurant_id INTEGER,
        name TEXT,
        description TEXT,
        price INTEGER,
        image_url TEXT,
        PRIMARY KEY (id, restaurant_id)
    )
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY,
        restaurant_id INTEGER,
        table_number TEXT,
        text TEXT
    )
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS owners (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        restaurant_id INTEGER,
        full_name TEXT,
        email TEXT UNIQUE,
        password_hash TEXT
    )
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS staff (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        restaurant_id INTEGER,
        full_name TEXT,
        role TEXT,
        pin TEXT,
        active INTEGER DEFAULT 1
    )
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS ingredients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        restaurant_id INTEGER,
        name TEXT,
        unit TEXT,
        quantity_in_stock REAL DEFAULT 0,
        low_stock_at REAL DEFAULT 0
    )
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS recipe_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        restaurant_id INTEGER,
        menu_item_id TEXT,
        ingredient_id INTEGER,
        quantity_required REAL
    )
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        restaurant_id INTEGER,
        table_number TEXT,
        type TEXT,
        status TEXT DEFAULT 'open'
    )
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_id INTEGER,
        token TEXT,
        expires_at INTEGER
    )
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS order_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        restaurant_id INTEGER,
        order_id INTEGER,
        action TEXT,
        actor_type TEXT,
        actor_id INTEGER,
        actor_name TEXT,
        created_at INTEGER
    )
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS expenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        restaurant_id INTEGER,
        expense_date TEXT,
        category TEXT,
        description TEXT,
        amount REAL
    )
`);
db.exec(`
    CREATE TABLE IF NOT EXISTS used_transaction_ids (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        restaurant_id INTEGER,
        transaction_id TEXT,
        order_id INTEGER,
        UNIQUE(restaurant_id, transaction_id)
    )
`);

try { db.exec("ALTER TABLE menu_items ADD COLUMN category TEXT DEFAULT 'Other'"); } catch (e) {}
try { db.exec("ALTER TABLE menu_items ADD COLUMN name_rw TEXT DEFAULT ''"); } catch (e) {}
try { db.exec("ALTER TABLE menu_items ADD COLUMN description_rw TEXT DEFAULT ''"); } catch (e) {}
try { db.exec("ALTER TABLE menu_items ADD COLUMN name_fr TEXT DEFAULT ''"); } catch (e) {}
try { db.exec("ALTER TABLE menu_items ADD COLUMN description_fr TEXT DEFAULT ''"); } catch (e) {}
try { db.exec("ALTER TABLE menu_items ADD COLUMN prep_time_minutes INTEGER DEFAULT 0"); } catch (e) {}
try { db.exec("ALTER TABLE restaurants ADD COLUMN number_of_tables INTEGER DEFAULT 0"); } catch (e) {}
try { db.exec("ALTER TABLE restaurants ADD COLUMN momo_number TEXT DEFAULT ''"); } catch (e) {}
try { db.exec("ALTER TABLE restaurants ADD COLUMN airtel_number TEXT DEFAULT ''"); } catch (e) {}
try { db.exec("ALTER TABLE restaurants ADD COLUMN urubuto_code TEXT DEFAULT ''"); } catch (e) {}
try { db.exec("ALTER TABLE orders ADD COLUMN paid INTEGER DEFAULT 0"); } catch (e) {}
try { db.exec("ALTER TABLE orders ADD COLUMN payment_method TEXT DEFAULT ''"); } catch (e) {}
try { db.exec("ALTER TABLE orders ADD COLUMN payment_status TEXT DEFAULT 'unpaid'"); } catch (e) {}
try { db.exec("ALTER TABLE orders ADD COLUMN void_reason TEXT DEFAULT ''"); } catch (e) {}
try { db.exec("ALTER TABLE orders ADD COLUMN created_at INTEGER DEFAULT 0"); } catch (e) {}
try { db.exec("ALTER TABLE orders ADD COLUMN total REAL DEFAULT 0"); } catch (e) {}
try { db.exec("ALTER TABLE orders ADD COLUMN cost REAL DEFAULT 0"); } catch (e) {}
try { db.exec("ALTER TABLE ingredients ADD COLUMN cost_per_unit REAL DEFAULT 0"); } catch (e) {}
try { db.exec("ALTER TABLE orders ADD COLUMN sms_text TEXT DEFAULT ''");} catch (e) {}
try { db.exec("ALTER TABLE orders ADD COLUMN sms_amount REAL DEFAULT 0");} catch (e) {}
try { db.exec("ALTER TABLE orders ADD COLUMN sms_transaction_id TEXT DEFAULT ''");} catch (e) {}
try { db.exec("ALTER TABLE orders ADD COLUMN sms_verified INTEGER DEFAULT 0")} catch (e) {}

const existingRestaurant = db.prepare('SELECT COUNT(*) as count FROM restaurants').get();
let restaurantId;

if (existingRestaurant.count === 0) {
    const result = db.prepare('INSERT INTO restaurants (name) VALUES (?)').run("TEN Points Cafe");
    restaurantId = result.lastInsertRowid;
} else {
    restaurantId = db.prepare('SELECT id FROM restaurants LIMIT 1').get().id;
}

const existing = db.prepare('SELECT COUNT(*) as count FROM menu_items').get();
if (existing.count === 0) {
    const insert = db.prepare('INSERT INTO menu_items (id, restaurant_id, name, description, price, image_url, category) VALUES (?, ?, ?, ?, ?, ?, ?)');
    insert.run('goat', restaurantId, 'Goat Brochettes', 'Grilled goat meat skewers served with fried plantain', 3500, '', 'Grilled Food');
    insert.run('chicken', restaurantId, 'Chicken Brochettes', 'Charcoal grilled, onion and pepper', 3800, '', 'Grilled Food');
}

module.exports = db;

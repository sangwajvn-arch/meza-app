const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const QRCode = require('qrcode');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const db = require('./db');
const app = express();
const PORT = 3000;

app.use(express.static(__dirname));
app.use(express.json());
app.use(session({
    secret: 'change-this-to-something-random-later',
    resave: false,
    saveUninitialized: false
}));

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'youraddress@gmail.com',
        pass: 'your-16-char-app-password'
    }
});

const PLAN_LIMITS = {
    'Free': 5, 'Starter': 15, 'Standard': 25, 'Business': 40,
    'Premium': 60, 'Professional': 100, 'Enterprise': Infinity
};

function requireOwner(req, res, restaurantId) {
    if (!req.session.ownerId || req.session.restaurantId != restaurantId) {
        res.status(403).send({ error: 'Not authorized.' });
        return false;
    }
    return true;
}

// AUTH

app.post('/register', async (req, res) => {
    const { venueName, phone, fullName, email, password } = req.body;
    try {
        const restaurantResult = db.prepare('INSERT INTO restaurants (name) VALUES (?)').run(venueName);
        const restaurantId = restaurantResult.lastInsertRowid;
        const passwordHash = await bcrypt.hash(password, 10);
        db.prepare('INSERT INTO owners (restaurant_id, full_name, email, password_hash) VALUES (?, ?, ?, ?)')
          .run(restaurantId, fullName, email, passwordHash);
        req.session.ownerId = db.prepare('SELECT id FROM owners WHERE email = ?').get(email).id;
        req.session.restaurantId = restaurantId;
        res.send({ status: 'created', restaurantId });
    } catch (error) {
        res.status(400).send({ error: 'That email is already registered.' });
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const owner = db.prepare('SELECT * FROM owners WHERE email = ?').get(email);
    if (!owner) return res.status(401).send({ error: 'Incorrect email or password.' });
    const match = await bcrypt.compare(password, owner.password_hash);
    if (!match) return res.status(401).send({ error: 'Incorrect email or password.' });
    req.session.ownerId = owner.id;
    req.session.restaurantId = owner.restaurant_id;
    res.send({ status: 'logged in', restaurantId: owner.restaurant_id });
});

app.post('/logout', (req, res) => {
    req.session.destroy(() => res.send({ status: 'logged out' }));
});

app.get('/me', (req, res) => {
    if (!req.session.ownerId) return res.status(401).send({ error: 'Not logged in' });
    res.send({ ownerId: req.session.ownerId, restaurantId: req.session.restaurantId });
});

app.get('/admin/me', (req, res) => {
    if (!req.session.ownerId) return res.status(401).send({ error: 'Not logged in' });
    res.send({ restaurantId: req.session.restaurantId, role: 'owner' });
});

app.post('/staff-login', (req, res) => {
    const { restaurant_id, pin } = req.body;
    if (!pin) return res.status(401).send({ error: 'Incorrect PIN.' });
    const member = db.prepare('SELECT * FROM staff WHERE restaurant_id = ? AND pin = ? AND active = 1').get(restaurant_id, pin);
    if (!member) return res.status(401).send({ error: 'Incorrect PIN.' });
    req.session.staffId = member.id;
    req.session.staffRole = member.role;
    req.session.staffRestaurantId = restaurant_id;
    res.send({ role: member.role, name: member.full_name });
});

app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    const owner = db.prepare('SELECT * FROM owners WHERE email = ?').get(email);
    if (owner) {
        const token = crypto.randomBytes(32).toString('hex');
        const expiresAt = Date.now() + 15 * 60 * 1000;
        db.prepare('INSERT INTO password_reset_tokens (owner_id, token, expires_at) VALUES (?, ?, ?)').run(owner.id, token, expiresAt);
        const resetUrl = `${req.protocol}://${req.get('host')}/reset-password.html?token=${token}`;
        try {
            await transporter.sendMail({
                from: '"Meza" <youraddress@gmail.com>',
                to: email,
                subject: 'Reset your Meza password',
                html: `
                <div style="font-family: Arial, sans-serif; background:#FAF6EE; padding:40px 20px;">
                  <div style="max-width:420px; margin:0 auto; text-align:center;">
                    <div style="width:48px; height:48px; background:#A8371E; border-radius:12px; margin:0 auto 16px; display:flex; align-items:center; justify-content:center;">
                      <span style="color:#FAF6EE; font-size:24px; font-weight:800; line-height:48px;">M</span>
                    </div>
                    <h2 style="color:#1A1712; margin:0 0 4px;">Meza</h2>
                    <p style="color:#6B6455; font-size:13px; margin:0 0 28px;">Reset your account password</p>
                    <div style="background:#fff; border:1px solid #E7E0D2; border-radius:12px; padding:28px; text-align:left;">
                      <p style="color:#1A1712; font-size:15px;">Hi ${owner.full_name},</p>
                      <p style="color:#1A1712; font-size:15px;">We received a request to reset the password on your Meza account. Click the button below to choose a new one.</p>
                      <p style="color:#6B6455; font-size:13px;">This link expires in <strong>15 minutes</strong> and can only be used once.</p>
                      <div style="text-align:center; margin:24px 0;">
                        <a href="${resetUrl}" style="background:#A8371E; color:#FAF6EE; text-decoration:none; padding:14px 28px; border-radius:26px; font-weight:700; display:inline-block;">Reset my password</a>
                      </div>
                      <p style="color:#6B6455; font-size:12px;">Or copy this link: <a href="${resetUrl}" style="color:#A8371E;">${resetUrl}</a></p>
                      <p style="color:#6B6455; font-size:12px;">If you didn't request this, you can safely ignore this email.</p>
                    </div>
                    <p style="color:#6B6455; font-size:11px; margin-top:24px;">Meza · Restaurant ordering platform</p>
                  </div>
                </div>
                `
            });
        } catch (error) { console.error('Email send failed:', error); }
    }
    res.send({ status: 'sent' });
});

app.post('/reset-password', async (req, res) => {
    const { token, password } = req.body;
    const record = db.prepare('SELECT * FROM password_reset_tokens WHERE token = ?').get(token);
    if (!record || record.expires_at < Date.now()) {
        return res.status(400).send({ error: 'This reset link is invalid or has expired.' });
    }
    const passwordHash = await bcrypt.hash(password, 10);
    db.prepare('UPDATE owners SET password_hash = ? WHERE id = ?').run(passwordHash, record.owner_id);
    db.prepare('DELETE FROM password_reset_tokens WHERE id = ?').run(record.id);
    res.send({ status: 'reset' });
});

// STAFF

app.get('/staff', (req, res) => {
    const restaurantId = req.query.restaurant;
    if (!requireOwner(req, res, restaurantId)) return;
    res.json(db.prepare('SELECT * FROM staff WHERE restaurant_id = ?').all(restaurantId));
});

app.post('/staff', (req, res) => {
    const { restaurant_id, full_name, role, pin } = req.body;
    if (!requireOwner(req, res, restaurant_id)) return;
    db.prepare('INSERT INTO staff (restaurant_id, full_name, role, pin, active) VALUES (?, ?, ?, ?, 1)')
      .run(restaurant_id, full_name, role, pin);
    res.send({ status: 'added' });
});

app.put('/staff/:id', (req, res) => {
    const { restaurant_id, full_name, role, pin, active } = req.body;
    if (!requireOwner(req, res, restaurant_id)) return;
    const current = db.prepare('SELECT * FROM staff WHERE id = ?').get(req.params.id);
    if (!current) return res.status(404).send({ error: 'Staff member not found.' });
    db.prepare('UPDATE staff SET full_name = ?, role = ?, pin = ?, active = ? WHERE id = ?')
      .run(
          full_name !== undefined ? full_name : current.full_name,
          role !== undefined ? role : current.role,
          pin !== undefined ? pin : current.pin,
          active !== undefined ? (active ? 1 : 0) : current.active,
          req.params.id
      );
    res.send({ status: 'updated' });
});

// ORDERS

app.post('/orders', (req, res) => {
    const { restaurant_id, table } = req.body;
    const items = JSON.stringify(req.body.items);
    const stmt = db.prepare('INSERT INTO orders (restaurant_id, table_number, items, status, paid) VALUES (?, ?, ?, ?, 0)');
    const result = stmt.run(restaurant_id, table, items, 'awaiting_payment');
    res.send({ status: 'awaiting_payment', orderId: result.lastInsertRowid });
});

app.get('/orders', (req, res) => {
    const restaurantId = req.query.restaurant;
    const rows = db.prepare('SELECT * FROM orders WHERE restaurant_id = ?').all(restaurantId);
    const orders = rows.map(row => ({
        id: row.id,
        table: row.table_number,
        items: JSON.parse(row.items),
        status: row.status,
        paid: !!row.paid,
        payment_method: row.payment_method
    }));
    res.json(orders);
});

app.post('/orders/:id/claim-payment', (req, res) => {
    const { payment_method } = req.body;
    db.prepare('UPDATE orders SET status = ?, payment_method = ? WHERE id = ?')
      .run('awaiting_confirmation', payment_method, req.params.id);
    res.send({ status: 'awaiting_confirmation' });
});

app.post('/orders/:id/confirm-payment', (req, res) => {
    db.prepare('UPDATE orders SET status = ?, paid = 1 WHERE id = ?').run('pending', req.params.id);
    res.send({ status: 'confirmed' });
});

app.post('/orders/:id/reject-payment', (req, res) => {
    db.prepare('UPDATE orders SET status = ? WHERE id = ?').run('rejected', req.params.id);
    res.send({ status: 'rejected' });
});

app.post('/orders/:id/approve', (req, res) => {
    const orderId = Number(req.params.id);
    const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId);
    if (!order) return res.status(404).send({ error: 'Order not found.' });

    const items = JSON.parse(order.items);
    const needed = {};

    for (let dishId in items) {
        const qtyOrdered = items[dishId];
        const recipe = db.prepare('SELECT * FROM recipe_items WHERE menu_item_id = ? AND restaurant_id = ?').all(dishId, order.restaurant_id);
        recipe.forEach(r => {
            needed[r.ingredient_id] = (needed[r.ingredient_id] || 0) + (r.quantity_required * qtyOrdered);
        });
    }

    for (let ingredientId in needed) {
        const ingredient = db.prepare('SELECT * FROM ingredients WHERE id = ?').get(ingredientId);
        if (!ingredient || ingredient.quantity_in_stock < needed[ingredientId]) {
            return res.status(400).send({ error: `Not enough ${ingredient ? ingredient.name : 'an ingredient'} in stock to approve this order.` });
        }
    }

    for (let ingredientId in needed) {
        db.prepare('UPDATE ingredients SET quantity_in_stock = quantity_in_stock - ? WHERE id = ?')
          .run(needed[ingredientId], ingredientId);
    }

    db.prepare('UPDATE orders SET status = ? WHERE id = ?').run('approved', orderId);
    res.send({ status: 'approved' });
});

app.post('/orders/:id/ready', (req, res) => {
    db.prepare('UPDATE orders SET status = ? WHERE id = ?').run('ready', req.params.id);
    res.send({ status: 'ready' });
});

app.post('/orders/:id/done', (req, res) => {
    db.prepare('UPDATE orders SET status = ? WHERE id = ?').run('done', req.params.id);
    res.send({ status: 'done' });
});

app.post('/orders/:id/reject', (req, res) => {
    db.prepare('UPDATE orders SET status = ? WHERE id = ?').run('rejected', req.params.id);
    res.send({ status: 'rejected' });
});

app.post('/orders/:id/void', (req, res) => {
    db.prepare('UPDATE orders SET status = ? WHERE id = ?').run('void', req.params.id);
    res.send({ status: 'void' });
});

app.post('/orders/:id/pay', (req, res) => {
    const { payment_method } = req.body;
    db.prepare('UPDATE orders SET paid = 1, payment_method = ? WHERE id = ?').run(payment_method || 'cash', req.params.id);
    res.send({ status: 'paid' });
});

// DASHBOARD

app.get('/dashboard', (req, res) => {
    const restaurantId = req.query.restaurant;
    const orders = db.prepare('SELECT * FROM orders WHERE restaurant_id = ?').all(restaurantId);
    const menu = db.prepare('SELECT * FROM menu_items WHERE restaurant_id = ?').all(restaurantId);
    const priceMap = {};
    menu.forEach(item => { priceMap[item.id] = item.price; });

    const counts = { awaiting_payment: 0, awaiting_confirmation: 0, pending: 0, approved: 0, ready: 0, done: 0, rejected: 0, void: 0 };
    let revenue = 0;

    orders.forEach(order => {
        counts[order.status] = (counts[order.status] || 0) + 1;
        if (order.paid) {
            const items = JSON.parse(order.items);
            for (let id in items) revenue += (priceMap[id] || 0) * items[id];
        }
    });

    const openOrders = counts.pending + counts.approved + counts.ready;
    res.send({ openOrders, counts, revenue, lowStock: 0 });
});

// MENU

app.get('/menu', (req, res) => {
    res.json(db.prepare('SELECT * FROM menu_items WHERE restaurant_id = ?').all(req.query.restaurant));
});

app.get('/menu/:id/recipe', (req, res) => {
    res.json(db.prepare('SELECT * FROM recipe_items WHERE menu_item_id = ? AND restaurant_id = ?').all(req.params.id, req.query.restaurant));
});

app.post('/menu', (req, res) => {
    const id = req.body.id.trim();
    const { name, description, price, image_url, restaurant_id, category, name_rw, description_rw, name_fr, description_fr, prep_time_minutes, recipe } = req.body;
    try {
        const insert = db.prepare('INSERT INTO menu_items (id, restaurant_id, name, description, price, image_url, category, name_rw, description_rw, name_fr, description_fr, prep_time_minutes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
        insert.run(id, restaurant_id, name, description, price, image_url, category, name_rw || '', description_rw || '', name_fr || '', description_fr || '', prep_time_minutes || 0);
        if (Array.isArray(recipe)) {
            const insertRecipe = db.prepare('INSERT INTO recipe_items (restaurant_id, menu_item_id, ingredient_id, quantity_required) VALUES (?, ?, ?, ?)');
            recipe.forEach(r => { if (r.ingredient_id && r.quantity > 0) insertRecipe.run(restaurant_id, id, r.ingredient_id, r.quantity); });
        }
        res.send({ status: 'added' });
    } catch (error) {
        res.status(400).send({ error: 'A dish with that ID already exists for this restaurant.' });
    }
});

app.delete('/menu/:id', (req, res) => {
    db.prepare('DELETE FROM menu_items WHERE id = ? AND restaurant_id = ?').run(req.params.id, req.query.restaurant);
    db.prepare('DELETE FROM recipe_items WHERE menu_item_id = ? AND restaurant_id = ?').run(req.params.id, req.query.restaurant);
    res.send({ status: 'deleted' });
});

app.put('/menu/:id', (req, res) => {
    const id = req.params.id;
    const restaurantId = req.query.restaurant;
    const { name, description, price, image_url, category, name_rw, description_rw, name_fr, description_fr, prep_time_minutes, recipe } = req.body;
    db.prepare('UPDATE menu_items SET name = ?, description = ?, price = ?, image_url = ?, category = ?, name_rw = ?, description_rw = ?, name_fr = ?, description_fr = ?, prep_time_minutes = ? WHERE id = ? AND restaurant_id = ?')
      .run(name, description, price, image_url, category, name_rw || '', description_rw || '', name_fr || '', description_fr || '', prep_time_minutes || 0, id, restaurantId);
    db.prepare('DELETE FROM recipe_items WHERE menu_item_id = ? AND restaurant_id = ?').run(id, restaurantId);
    if (Array.isArray(recipe)) {
        const insertRecipe = db.prepare('INSERT INTO recipe_items (restaurant_id, menu_item_id, ingredient_id, quantity_required) VALUES (?, ?, ?, ?)');
        recipe.forEach(r => { if (r.ingredient_id && r.quantity > 0) insertRecipe.run(restaurantId, id, r.ingredient_id, r.quantity); });
    }
    res.send({ status: 'updated' });
});

// INGREDIENTS

app.get('/ingredients', (req, res) => {
    res.json(db.prepare('SELECT * FROM ingredients WHERE restaurant_id = ?').all(req.query.restaurant));
});

app.post('/ingredients', (req, res) => {
    const { restaurant_id, name, unit, quantity_in_stock, low_stock_at } = req.body;
    db.prepare('INSERT INTO ingredients (restaurant_id, name, unit, quantity_in_stock, low_stock_at) VALUES (?, ?, ?, ?, ?)')
      .run(restaurant_id, name, unit, quantity_in_stock, low_stock_at);
    res.send({ status: 'added' });
});

app.put('/ingredients/:id', (req, res) => {
    const { name, unit, quantity_in_stock, low_stock_at } = req.body;
    db.prepare('UPDATE ingredients SET name = ?, unit = ?, quantity_in_stock = ?, low_stock_at = ? WHERE id = ?')
      .run(name, unit, quantity_in_stock, low_stock_at, req.params.id);
    res.send({ status: 'updated' });
});

app.delete('/ingredients/:id', (req, res) => {
    db.prepare('DELETE FROM ingredients WHERE id = ?').run(req.params.id);
    res.send({ status: 'deleted' });
});

// RESTAURANTS

app.get('/restaurants', (req, res) => {
    res.json(db.prepare('SELECT * FROM restaurants').all());
});

app.get('/restaurants/:id', (req, res) => {
    res.json(db.prepare('SELECT * FROM restaurants WHERE id = ?').get(req.params.id));
});

app.post('/restaurants', async (req, res) => {
    const { name, fullName, email, password } = req.body;
    try {
        const result = db.prepare('INSERT INTO restaurants (name) VALUES (?)').run(name);
        const restaurantId = result.lastInsertRowid;
        const passwordHash = await bcrypt.hash(password, 10);
        db.prepare('INSERT INTO owners (restaurant_id, full_name, email, password_hash) VALUES (?, ?, ?, ?)')
          .run(restaurantId, fullName, email, passwordHash);
        res.send({ id: restaurantId, name });
    } catch (error) {
        res.status(400).send({ error: 'That email is already registered, or something went wrong.' });
    }
});

app.put('/restaurants/:id', (req, res) => {
    db.prepare('UPDATE restaurants SET name = ? WHERE id = ?').run(req.body.name, req.params.id);
    res.send({ status: 'updated' });
});

app.put('/restaurants/:id/tables', (req, res) => {
    if (!requireOwner(req, res, req.params.id)) return;
    const restaurant = db.prepare('SELECT * FROM restaurants WHERE id = ?').get(req.params.id);
    const plan = restaurant.plan || 'Free';
    const limit = PLAN_LIMITS[plan] ?? 5;
    const requested = req.body.number_of_tables;
    if (requested > limit) {
        return res.status(400).send({ error: `Your ${plan} plan allows up to ${limit} QR codes. Upgrade your plan to add more tables.` });
    }
    db.prepare('UPDATE restaurants SET number_of_tables = ? WHERE id = ?').run(requested, req.params.id);
    res.send({ status: 'updated' });
});

app.put('/restaurants/:id/plan', (req, res) => {
    if (!requireOwner(req, res, req.params.id)) return;
    const { plan } = req.body;
    if (!PLAN_LIMITS.hasOwnProperty(plan)) return res.status(400).send({ error: 'Unknown plan.' });
    db.prepare('UPDATE restaurants SET plan = ? WHERE id = ?').run(plan, req.params.id);
    res.send({ status: 'updated', plan });
});

app.put('/restaurants/:id/payment-details', (req, res) => {
    if (!requireOwner(req, res, req.params.id)) return;
    const { momo_number, airtel_number, urubuto_code } = req.body;
    db.prepare('UPDATE restaurants SET momo_number = ?, airtel_number = ?, urubuto_code = ? WHERE id = ?')
      .run(momo_number, airtel_number, urubuto_code, req.params.id);
    res.send({ status: 'updated' });
});

app.delete('/restaurants/:id', (req, res) => {
    const id = req.params.id;
    db.prepare('DELETE FROM restaurants WHERE id = ?').run(id);
    db.prepare('DELETE FROM menu_items WHERE restaurant_id = ?').run(id);
    db.prepare('DELETE FROM orders WHERE restaurant_id = ?').run(id);
    db.prepare('DELETE FROM owners WHERE restaurant_id = ?').run(id);
    db.prepare('DELETE FROM staff WHERE restaurant_id = ?').run(id);
    db.prepare('DELETE FROM ingredients WHERE restaurant_id = ?').run(id);
    db.prepare('DELETE FROM recipe_items WHERE restaurant_id = ?').run(id);
    db.prepare('DELETE FROM messages WHERE restaurant_id = ?').run(id);
    db.prepare('DELETE FROM requests WHERE restaurant_id = ?').run(id);
    res.send({ status: 'deleted' });
});

// QR CODES

app.get('/qr', async (req, res) => {
    const restaurantId = req.query.restaurant;
    const table = req.query.table;
    const baseUrl = req.protocol + '://' + req.get('host');
    const url = `${baseUrl}/?restaurant=${restaurantId}&table=${table}`;
    try {
        const dataUrl = await QRCode.toDataURL(url);
        res.send({ url, dataUrl });
    } catch (error) {
        res.status(500).send({ error: 'Could not generate QR code.' });
    }
});

// MESSAGES

app.post('/messages', (req, res) => {
    const { restaurant_id, table, text } = req.body;
    db.prepare('INSERT INTO messages (restaurant_id, table_number, text) VALUES (?, ?, ?)').run(restaurant_id, table, text);
    res.send({ status: 'sent' });
});

app.get('/messages', (req, res) => {
    res.json(db.prepare('SELECT * FROM messages WHERE restaurant_id = ? AND table_number = ?').all(req.query.restaurant, req.query.table));
});

app.delete('/messages/:id', (req, res) => {
    db.prepare('DELETE FROM messages WHERE id = ?').run(req.params.id);
    res.send({ status: 'deleted' });
});

// TABLE REQUESTS

app.post('/requests', (req, res) => {
    const { restaurant_id, table, type } = req.body;
    db.prepare('INSERT INTO requests (restaurant_id, table_number, type, status) VALUES (?, ?, ?, ?)').run(restaurant_id, table, type, 'open');
    res.send({ status: 'sent' });
});

app.get('/requests', (req, res) => {
    res.json(db.prepare("SELECT * FROM requests WHERE restaurant_id = ? AND status = 'open'").all(req.query.restaurant));
});

app.post('/requests/:id/resolve', (req, res) => {
    db.prepare("UPDATE requests SET status = 'resolved' WHERE id = ?").run(req.params.id);
    res.send({ status: 'resolved' });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log('Server is running at http://localhost:' + PORT);
});

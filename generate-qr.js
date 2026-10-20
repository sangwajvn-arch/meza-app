const QRCode = require('qrcode');
const fs = require('fs');
const db = require('./db');

const baseUrl = 'http://192.168.1.68:3000';
const numberOfTables = 5;

const restaurants = db.prepare('SELECT * FROM restaurants').all();

restaurants.forEach(restaurant => {
    const folder = `qr-codes/restaurant-${restaurant.id}`;
    if (!fs.existsSync(folder)) {
        fs.mkdirSync(folder, { recursive: true });
    }

    for (let i = 1; i <= numberOfTables; i++) {
        const url = `${baseUrl}/?restaurant=${restaurant.id}&table=${i}`;
        QRCode.toFile(`${folder}/table-${i}.png`, url, (err) => {
            if (err) console.error(err);
            else console.log(`Created QR code for ${restaurant.name}, table ${i}`);
        });
    }
});
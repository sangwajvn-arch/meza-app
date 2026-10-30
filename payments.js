const db = require('./db');
const crypto = require('crypto');

function createPaymentAttempt({
    restaurantId,
    orderId,
    provider,
    phone
}) {
    // Check the payment provider
    if (!['mtn', 'airtel'].includes(provider)) {
        throw new Error('Unsupported payment provider');
    }

    // Validate the Rwandan phone number
    if (!/^\+2507\d{8}$/.test(phone)) {
        throw new Error(
            'Enter a valid Rwandan phone number (+2507XXXXXXXX)'
        );
    }

    // Find the order
    const order = db.prepare(`
        SELECT id, restaurant_id, total, paid
        FROM orders
        WHERE id = ? AND restaurant_id = ?
    `).get(orderId, restaurantId);

    if (!order) {
        throw new Error('Order not found');
    }

    if (order.paid) {
        throw new Error('Order is already paid');
    }

    if (!Number.isFinite(order.total) || order.total <= 0) {
        throw new Error('Invalid order amount');
    }

    // Generate a unique payment reference
    const reference = crypto.randomUUID();

    // Save the payment attempt
    const result = db.prepare(`
        INSERT INTO payment_transactions (
            restaurant_id,
            order_id,
            provider,
            amount,
            currency,
            payer_phone,
            provider_reference,
            status
        )
        VALUES (?, ?, ?, ?, 'RWF', ?, ?, 'pending')
    `).run(
        restaurantId,
        orderId,
        provider,
        order.total,
        phone,
        reference
    );

    return {
        transactionId: result.lastInsertRowid,
        reference,
        amount: order.total,
        currency: 'RWF',
        provider,
        status: 'pending'
    };
}

module.exports = {
    createPaymentAttempt
};
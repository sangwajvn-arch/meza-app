async function requestPayment({
    restaurantId,
    orderId,
    amount,
    phone
}) {
    throw new Error(
        'Airtel payments are not connected yet.'
    );
}

module.exports = {
    requestPayment
};
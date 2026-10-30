async function requestPayment({
    restaurantId,
    orderId,
    amount,
    phone
}) {
    throw new Error(
        'MTN payments are not connected yet.'
    );
}

module.exports = {
    requestPayment
};

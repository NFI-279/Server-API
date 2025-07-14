const express = require('express');
const router = express.Router();
const pool = require('../config/database');
const authenticateToken = require('../middleware/authenticate');

router.post('/sync', authenticateToken, async (req, res) => {

    const userId = req.user.userId;

    console.log(`Sync request received for authenticated user ID: ${userId}`);

    let client;
    try {
        client = await pool.connect();

        const query = 'SELECT license.product_id, license.duration, activation.activated_at, activation.license_id, product.name, product.latest_version, product.patch_note FROM license INNER JOIN activation ON activation.license_id = license.id INNER JOIN product ON  license.product_id = product.id WHERE license.user_id = $1';
        const result = await client.query(query, [userId]);

        if (result.rows.length === 0){
            console.log('No licenses have been found')
            return res.json({ subscriptions: [] });
        }

        const subscriptionsForClient = result.rows.map(sub => {
            const activationDate = new Date(sub.activated_at);
            const expirationDate = new Date(activationDate);
            expirationDate.setDate(activationDate.getDate() + sub.duration);

            const today = new Date();
            const timeDiff = expirationDate.getTime() - today.getTime();
            const daysRemaining = Math.max(0, Math.ceil(timeDiff / (1000 * 3600 * 24))); // Ensure it doesn't go below 0

            return {
                product_name: sub.name,
                latest_version: sub.latest_version,
                patch_note: sub.patch_note,
                days_remaining: daysRemaining
            };
        });

        return res.json({ subscriptions: subscriptionsForClient });
    } catch (error) {
        console.error(`Error during sync for user ${userId}:`, error);
        return res.status(500).json({ error: 'An internal server error occurred.' });
    } finally {
        if (client) {
            client.release();
        }
    }
});

module.exports = router;
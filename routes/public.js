const express = require('express');
const router = express.Router();
const pool = require('../config/database.js');
const { hashCache, validateInputs, activationLimiter, versionCheckLimiter } = require('../config/security');
const jwt = require('jsonwebtoken');
const semver = require('semver');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const validateHandshake = require('../middleware/validateHandshake.js')
const { generateHandshake, PURPOSE_AWAITING_SYNC, PURPOSE_AWAITING_ACTIVATION } = require('../config/handshake');
const { getClientIp } = require('../config/network');
const verifySignature = require('../middleware/verifySignature');
const verifyUserAgent = require('../middleware/verifyUserAgent');

router.get(`/version-check`, versionCheckLimiter, verifyUserAgent, async (req, res) => {
    const { version: client_version, checksum: client_checksum, intent } = req.query;
    const client_ip = getClientIp(req);

    let purpose;

    if (!client_version || !client_checksum || !intent) {
        return res.status(400).json({ error: 'Version, checksum and intent parameters are required.' });
    }

    let client;
    try {
        client = await pool.connect();
        const getLoaderInformation = 'SELECT latest_version, download_url, checksum FROM product WHERE name = $1';
        const result = await client.query(getLoaderInformation, ['loader']);


        if (result.rows.length === 0)
            return res.status(404).json({ error: 'Loader entry not found in the database' });

        const loader_version = result.rows[0].latest_version;
        const loader_url = result.rows[0].download_url;
        const loader_checksum = result.rows[0].checksum;

        if (!semver.valid(client_version))
            return res.status(400).json({ error: 'Invalid version format.' });
            
        if (semver.gt(client_version, loader_version))
            return res.status(409).json({ error: 'Client version is ahead of server. Please use the official loader.' });
        if (semver.lt(client_version, loader_version)) 
            return res.json({
                status: 'update_required',
                latest_version: loader_version,
                download_url: loader_url
            });

        if (client_checksum !== loader_checksum)
            return res.status(403).json({ error: 'File integrity check failed. Please re-download the application.' });

        if(intent == 'sync')
            purpose = PURPOSE_AWAITING_SYNC;
        else if(intent == 'activate')
            purpose = PURPOSE_AWAITING_ACTIVATION;
        else
            return res.status(400).json({ error: 'Invalid request intent'});

        const plainTextToken = await generateHandshake(client_ip, purpose);
        console.log(`Generated '${purpose}' token for IP ${client_ip}`);
        return res.json({ handshake_token: plainTextToken });

    } catch (error) {
        console.error("Error in /version-check:", error);
        return res.status(500).json({ error: "An internal server error occurred." });
    } finally {
        if (client) client.release();
    }
});


router.post(`/activate`, activationLimiter,  verifyUserAgent, validateHandshake(PURPOSE_AWAITING_ACTIVATION), verifySignature, async (req, res) => {
    const { license, hwid} = req.body;
    let client;

    try {
        if (!validateInputs(hwid, license))
            return res.status(400).json({ error: 'Bad request. The HWID or License are incorrect.' });

        client = await pool.connect();
        await client.query('BEGIN');
        const findLicenseQuery = 'SELECT * FROM license WHERE key = $1 FOR UPDATE';
        const result = await client.query(findLicenseQuery, [license]);

        if (result.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(403).json({ error: 'There is no valid license with this key.' });
        }

        const foundLicense = result.rows[0];

        if (foundLicense.user_id == null) {
            await client.query('ROLLBACK');
            return res.status(403).json({ error: 'This license key has not been assigned to an account.' });
        }

        if (foundLicense.status !== 'fresh') {
            await client.query('ROLLBACK');
            return res.status(403).json({ error: 'This license has already been used or is not active.' });
        }

        const checkForExistingQuery = 'SELECT l.id FROM license l JOIN activation a ON l.id = a.license_id WHERE l.user_id = $1 AND l.product_id = $2 AND l.status = $3';
        const existingResult = await client.query(checkForExistingQuery, [foundLicense.user_id, foundLicense.product_id, 'used']);

         if (existingResult.rows.length > 0) { // The user already has an active license for this product
            await client.query('ROLLBACK');
            return res.status(403).json({ 
                error: 'You already have an active subscription for this product. To extend it, please use the renewal option on our website.' 
            });
        }

        const updateQuery = 'UPDATE license SET status = $1 WHERE key = $2';
        await client.query(updateQuery, ['used', license]);
        const activationQuery = 'INSERT INTO activation (hwid, license_id, activated_at) VALUES ($1, $2, CURRENT_DATE) RETURNING id';
        const activationResult = await client.query(activationQuery, [hwid, foundLicense.id]);
        const newActivationId = activationResult.rows[0].id;
        const tokenPayload = {
            userId: foundLicense.user_id,
            activationId: newActivationId,
            hwid: hwid
        };
        const sessionToken = jwt.sign(tokenPayload, process.env.JWT_SECRET, { expiresIn: '14d' });
        await client.query('COMMIT');

        const syncQuery = 'SELECT p.name, p.latest_version, p.patch_note, l.duration, a.activated_at FROM license l JOIN activation a ON a.license_id = l.id JOIN product p ON l.product_id = p.id WHERE l.user_id = $1';
        const syncResult = await client.query(syncQuery, [foundLicense.user_id]);

        const subscriptionsForClient = syncResult.rows.map(sub => {
            const activationDate = new Date(sub.activated_at);
            const expirationDate = new Date(activationDate);
            expirationDate.setDate(activationDate.getDate() + sub.duration);
            const today = new Date();
            const timeDiff = expirationDate.getTime() - today.getTime();
            const daysRemaining = Math.max(0, Math.ceil(timeDiff / (1000 * 3600 * 24)));

            return {
                product_name: sub.name,
                latest_version: sub.latest_version,
                patch_note: sub.patch_note,
                days_remaining: daysRemaining
            };
        });
        return res.json({
            status: 'success',
            message: 'License activated successfully!',
            token: sessionToken,
            subscriptions: subscriptionsForClient // Include the initial subscription data
        });

    } catch (error) {
        if (client) await client.query('ROLLBACK');
        console.error("Something went wrong with the activation process:", error);
        return res.status(500).json({ error: "An internal server error occurred." });
    } finally {
        if (client) client.release();
    }
});

module.exports = router;

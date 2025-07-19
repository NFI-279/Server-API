const express = require('express');
const router = express.Router();
const pool = require('../config/database.js');
const { hashCache, validateInputs, activationLimiter, versionCheckLimiter } = require('../config/security');
const jwt = require('jsonwebtoken');
const semver = require('semver');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const validateHandshake = require('../middleware/validateHandshake.js')

router.get(`/version-check`, versionCheckLimiter, async (req, res) => {
    const client_version = req.query.version;
    const client_checksum = req.query.checksum;
    const client_ip = req.ip;

    if (!client_version || !client_checksum) {
        return res.status(400).json({ error: 'Version and checksum parameters are required.' });
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

        const randomSecret = crypto.randomBytes(16).toString('hex');
        const hashedSecret = await bcrypt.hash(randomSecret, 10);
        const expirationTime = Date.now() + (1 * 60 * 1000);
        const PURPOSE_TOKEN = 'version-check';

        hashCache.set(client_ip, { hash: hashedSecret, expires: expirationTime, purpose: PURPOSE_TOKEN });
        console.log(`Generated secret for IP ${client_ip}`);
        return res.json({
           // status: 'ok',
            handshake_token: randomSecret,
        });
    } catch (error) {
        console.error("Error in /version-check:", error);
        return res.status(500).json({ error: "An internal server error occurred." });
    } finally {
        if (client) client.release();
    }
});


router.post(`/activate`, activationLimiter, validateHandshake('version-check'), async (req, res) => {
    const { license, hwid} = req.body;
    const client_ip = req.ip;
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

        console.log(`Transaction successful for license: ${license}`);
        return res.json({
            status: 'success',
            message: 'License activated successfully!',
            token: sessionToken
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
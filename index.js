require('dotenv').config(); 

const express = require("express");
const { Pool } = require('pg');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const semver = require('semver');
const app = express();
const PORT = process.env.PORT || 4000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false // Required for Supabase connections
  }
});

const activationLimiter = rateLimit({ // Used to rate limit against potential brute-force attacks
    windowMs: 60 * 60 * 1000, // 1 hour window
    max: 10, // Max 10 requests per hour from a single IP
    message: { error: 'Too many activation attempts from this IP, please try again after an hour.' },
    standardHeaders: true,
    legacyHeaders: false,
});

const versionCheckLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Allow 100 requests per 15 minutes from one IP
    message: { error: 'Too many requests. Please try again later.' }
});

function validateInputs(hwid, license){ // Function used for Input Validation against server crashes
    if(typeof license != "string" || typeof hwid != "string" || license.length != 50 || hwid.length != 16)
        return false;
    return true;
}

app.use(express.json());

app.post(`/api/activate`, activationLimiter, async (req, res) => {
    const { license, hwid } = req.body;
    let client;

    if(!validateInputs(hwid, license))
        return res.status(400).json({error: 'Bad request. The HWID or License are incorrect.'});

    try {
        client = await pool.connect();
        console.log("Successfully connected to the database.");

        const findLicenseQuery = 'SELECT * FROM license WHERE key = $1 FOR UPDATE'; // Lock the row to avoid having two users try to activate the same key at the same time
        const result = await client.query(findLicenseQuery, [license]);

        if (result.rows.length === 0) {
            return res.status(403).json({ error: 'There is no valid license with this key.' });
        }

        const foundLicense = result.rows[0];
        if (foundLicense.status !== 'fresh') {
            return res.status(403).json({ error: 'This license has already been used or is not active.' });
        }

        try {
            await client.query('BEGIN'); 

            const updateQuery = 'UPDATE license SET status = $1 WHERE key = $2'; // Update our license
            await client.query(updateQuery, ['used', license]);

            const activationQuery = 'INSERT INTO activation (hwid, license_id, activated_at) VALUES ($1, $2, CURRENT_DATE) RETURNING id'; // Create the new record in activation table for the license key

            const activationResult = await client.query(activationQuery, [hwid, foundLicense.id]);

            const newActivationId = activationResult.rows[0].id;

            const tokenPayload = {
                userId: foundLicense.user_id,
                activationId: newActivationId,
                hwid: hwid // Lock the token to this HWID
            };

            const sessionToken = jwt.sign(
                tokenPayload,
                process.env.JWT_SECRET,
                { expiresIn: '14d' }  // Token valid for 14 days
            );

            await client.query('COMMIT'); // If both queries executed without errors THEN commit

            console.log(`Transaction successful for license: ${license}`);
            return res.json({
                status: 'success',
                message: 'License activated successfully!',
                token: sessionToken
            });

        } catch (transactionError) {
            await client.query('ROLLBACK'); // One of the queries failed, ROLLBACK
            throw transactionError; 
        }

    } catch (error) {
        console.error("Something went wrong with the activation process:", error);
        return res.status(500).json({ error: "An internal server error occurred." });

    } finally {
        if (client) {
            client.release();
            console.log("Database connection released");
        }
    }
});

app.get(`/api/version-check`, versionCheckLimiter, async(req, res) =>{
    const client_version = req.query.version;
    let client;
    try{
        client = await pool.connect();
        const getLoaderInformation = 'SELECT latest_version, download_url FROM product WHERE name = $1';
        const result = await client.query(getLoaderInformation, ['loader']);

        if(result.rows.length === 0)
            return res.status(404).json({ error: 'Loader entry not found in the database'});    

        const loader_version = result.rows[0].latest_version;
        const loader_url = result.rows[0].download_url;

        if (!semver.valid(client_version))
            return res.status(400).json({ error: 'Invalid version format.' });
        if (semver.gt(client_version, loader_version)) { // Client's version is GREATER THAN the server's latest version which is a problem
            return res.status(409).json({ error: 'Client version is ahead of server. Please use the official loader.' });
        } else if (semver.lt(client_version, loader_version)) { // Client's version is LESS THAN the server's latest version which means update is required
            return res.json({
                status: 'update_required',
                latest_version: loader_version,
                download_url: loader_url
            });
        } else { // Client and server version match
            return res.json({ status: 'ok' });
        }

    } catch (error) {
        console.error("Something went wrong", error);

    } finally {
        if (client) {
            client.release();
            console.log("Database connection released");
        }
    }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
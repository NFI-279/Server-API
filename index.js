require('dotenv').config(); 

const express = require("express");
const { Pool } = require('pg');
const app = express();
const PORT = process.env.PORT || 4000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false // Required for Supabase connections
  }
});

app.use(express.json());

app.post(`/api/activate`, async (req, res) => {
    const { license, hwid } = req.body;
    let client;

    try {
        client = await pool.connect();
        console.log("Successfully connected to the database.");

        const findLicenseQuery = 'SELECT * FROM license WHERE key = $1';
        const result = await client.query(findLicenseQuery, [license]);

        if (result.rows.length === 0) {
            return res.status(403).json({ error: 'There is no valid license with this key.' });
        }

        const foundLicense = result.rows[0];
        if (foundLicense.status !== 'idle') {
            return res.status(403).json({ error: 'This license has already been used or is not active.' });
        }

        try {
            await client.query('BEGIN'); 

            const updateQuery = 'UPDATE license SET status = $1 WHERE key = $2'; // Update our license
            await client.query(updateQuery, ['used', license]);

            const activationQuery = 'INSERT INTO activation (hwid, license_id, activated_at) VALUES ($1, $2, CURRENT_DATE)'; // Create the new record in activation table for the license key
            await client.query(activationQuery, [hwid, foundLicense.id]);

            await client.query('COMMIT'); // If both queries executed without errors THEN commit

            console.log(`Transaction successful for license: ${license}`);
            return res.json({ status: 'success', message: 'License activated successfully!' });

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

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
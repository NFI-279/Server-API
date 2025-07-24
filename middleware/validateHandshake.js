const { hashCache } = require('../config/security');
const bcrypt = require('bcrypt'); 

function validateHandshake(expectedPurpose){
   return async function (req, res, next) {
        const handshake_token = req.body.handshake_token;
        const client_ip = req.ip;

        try{
            if(!handshake_token)
                return res.status(403).json({ error: 'Forbidden: Handshake token is missing.' });

            const cachedData = hashCache.get(client_ip);

            if (!cachedData) {
                return res.status(403).json({ error: 'Forbidden: No active handshake session found. Please restart.' });
            }

            if (Date.now() > cachedData.expires) {
                hashCache.delete(client_ip); // Clean up the expired entry
                return res.status(403).json({ error: 'Forbidden: Handshake session has expired. Please restart.' });
            }

             if (expectedPurpose !== cachedData.purpose) {
                hashCache.delete(client_ip); 
                return res.status(403).json({ error: 'Forbidden: Handshake purpose mismatch.' });
            }

            const isMatch = await bcrypt.compare(handshake_token, cachedData.hash);

            if (!isMatch)
                return res.status(403).json({ error: 'Invalid activation token.' });
            else {
                hashCache.delete(client_ip);
                next();
            }
        } catch (error) {
            console.error("Error in validateHandshake middleware:", error);
            return res.status(500).json({ error: "An internal server error occurred." });
        }
    }
}

module.exports = validateHandshake;
const { hashCache } = require('../config/security');
const bcrypt = require('bcrypt'); 

function validateHandshake(expectedPurpose){
   return async function (req, res, next) {
        const handshake_token = req.body.handshake_token;
        const client_ip = req.ip;

        try{
            if(!handshake_token)
                return res.status(403).json({ error: 'Something went wrong.' });

            const cachedData = hashCache.get(client_ip);

            if (!cachedData || Date.now() > cachedData.expires || expectedPurpose != cachedData.purpose)
                return res.status(403).json({ error: 'Something went wrong.' });

            const isMatch = await bcrypt.compare(handshake_token, cachedData.hash);

            if (!isMatch)
                return res.status(403).json({ error: 'Invalid activation token.' });
            else {
                hashCache.delete(client_ip);
                next();
            }
        } catch (error) {
            return res.status(500).json({ error: "An internal server error occurred." });
        }
    }
}

module.exports = validateHandshake;
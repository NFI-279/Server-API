const crypto = require('crypto');

function verifySignature(req, res, next) {
    const signatureFromHeader = req.get('X-Signature');

    if (!signatureFromHeader) {
        return res.status(403).json({ error: 'Forbidden: Missing request signature' });
    }

    if (!req.body || Object.keys(req.body).length === 0) {
        return res.status(400).json({ error: 'Bad Request: Missing request body.' });
    }

    try {
        const secret = process.env.API_SHARED_SECRET;
        if (!secret) {
            console.error("CRITICAL: API_SHARED_SECRET is not set");
            return res.status(500).json({ error: 'Internal Server Error.' });
        }

        const keys = Object.keys(req.body);
        keys.sort();
        const string_to_hash = keys.map(key => req.body[key]).join('');


        const expectedSignature = crypto
            .createHash('sha256')
            .update(string_to_hash + secret)
            .digest('hex');
        
        const signaturesMatch = crypto.timingSafeEqual(
            Buffer.from(signatureFromHeader, 'hex'),
            Buffer.from(expectedSignature, 'hex')
        );

        if (signaturesMatch) {
            return next();
        } else {
            console.log("Signature Mismatch!");
            console.log("Client sent:", signatureFromHeader);
            console.log("Server expected:", expectedSignature);
            console.log("Server used this raw body:", req.rawBody);
            return res.status(403).json({ error: 'Forbidden: Invalid request signature' });
        }
    } catch (error) {
        return res.status(400).json({ error: 'Bad Request: Invalid signature format' });
    }
}


module.exports = verifySignature;



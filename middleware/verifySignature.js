const crypto = require('crypto');

function verifySignature(req, res, next) {
    const signatureFromHeader = req.get('X-Signature');

    if (!signatureFromHeader) {
        return res.status(403).json({ error: 'Forbidden: Missing request signature' });
    }

    if (!req.rawBody) {
        console.error("Error: rawBody is not available");
        return res.status(500).json({ error: 'Internal Server Error' });
    }

    try {
        const secret = process.env.API_SHARED_SECRET;
        if (!secret) {
            console.error("CRITICAL: API_SHARED_SECRET is not set");
            return res.status(500).json({ error: 'Internal Server Error.' });
        }

        const string_to_hash = req.rawBody + secret;
        const expectedSignature = crypto
            .createHash('sha256')
            .update(string_to_hash)
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


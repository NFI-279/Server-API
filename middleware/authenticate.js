const jwt = require('jsonwebtoken');

function authenticateToken(req, res, next) {
    // Get the token from the "Authorization: Bearer <TOKEN>" header
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) {
        return res.status(401).json({ error: 'Unauthorized: No token provided.' });
    }

    try {
        const decodedPayload = jwt.verify(token, process.env.JWT_SECRET);

        const { hwid } = req.body;
        if (decodedPayload.hwid !== hwid) {
            return res.status(403).json({ error: 'Forbidden: Hardware ID mismatch.' });
        }

        req.user = decodedPayload;
        
        next();

    } catch (error) {
        console.error("Authentication Error:", error.message);
        return res.status(403).json({ error: 'Forbidden: Token is invalid or has expired.' });
    }
}

module.exports = authenticateToken;
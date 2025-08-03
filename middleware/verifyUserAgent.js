function verifyUserAgent(req, res, next) {
    const userAgent = req.get('User-Agent');
    const expectedAgent = 'MyLoader';

    if (userAgent && userAgent === expectedAgent)
        return next();

    return res.status(403).json({ error: 'Forbidden' });
}

module.exports = verifyUserAgent;
function getClientIp(req) {
    const forwardedFor = req.headers['x-forwarded-for'];

    if (forwardedFor)
        return forwardedFor.split(',')[0].trim();

    // for local development
    return req.ip;
}

module.exports = {
    getClientIp
};

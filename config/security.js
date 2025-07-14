const rateLimit = require('express-rate-limit');

const activationCache = new Map();

const activationLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 10,
    message: { error: 'Too many activation attempts from this IP, please try again after an hour.' },
    standardHeaders: true,
    legacyHeaders: false,
});

const versionCheckLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    message: { error: 'Too many requests. Please try again later.' }
});

function validateInputs(hwid, license){
    if(typeof license !== 'string' || typeof hwid !== 'string' || license.length != 50 || hwid.length != 16)
        return false;
    return true;
}

module.exports = {
    activationCache,
    activationLimiter,
    versionCheckLimiter,
    validateInputs
};
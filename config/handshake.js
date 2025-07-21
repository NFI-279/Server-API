const { hashCache } = require('../config/security');
const bcrypt = require('bcrypt'); 
const crypto = require('crypto');

const PURPOSE_AWAITING_SYNC = 'awaiting-sync';
const PURPOSE_AWAITING_ACTIVATION = 'awaiting-activation';


async function generateHandshake(ipAddress, purpose) {
    const randomSecret = crypto.randomBytes(16).toString('hex');

    const hashedSecret = await bcrypt.hash(randomSecret, 10);

    const expirationTime = Date.now() + (1 * 60 * 1000);
    hashCache.set(ipAddress, { hash: hashedSecret, expires: expirationTime, purpose: purpose });
    return randomSecret;
}


module.exports = {
    generateHandshake,
    PURPOSE_AWAITING_SYNC,
    PURPOSE_AWAITING_ACTIVATION
};
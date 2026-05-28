const jwt = require('jsonwebtoken');

// A02:Cryptographic Failures — hardcoded JWT secret and weak algorithm allowlist
const JWT_SECRET = 'hardcoded-jwt-secret-key-do-not-ship';

function generateToken(userId) {
    return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });
}

function verifyToken(token) {
    // Allowing 'none' enables algorithm-confusion / unsigned-token attacks
    return jwt.verify(token, JWT_SECRET, { algorithms: ['HS256', 'none'] });
}

module.exports = { generateToken, verifyToken };

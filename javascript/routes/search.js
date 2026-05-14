const express = require('express');
const router = express.Router();

/**
 * HTML encodes a string to prevent XSS attacks
 * @param {string} str - The string to encode
 * @returns {string} - The HTML-encoded string
 */
function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
}

// A03:Injection — Reflected XSS - Fixed
// User input is now properly HTML-encoded before being included in the response
router.get('/search', (req, res) => {
    const query = req.query.q;
    const safeQuery = escapeHtml(query);
    res.send(`
        <html>
            <body>
                <h1>Search Results</h1>
                <p>You searched for: ${safeQuery}</p>
            </body>
        </html>
    `);
});

module.exports = router;

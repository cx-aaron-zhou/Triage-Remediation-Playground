const express = require('express');
const router = express.Router();

// A03:Injection — Reflected XSS
// User input is interpolated directly into the HTML response with no encoding
router.get('/search', (req, res) => {
    const query = req.query.q;
    res.send(`
        <html>
            <body>
                <h1>Search Results</h1>
                <p>You searched for: ${query}</p>
            </body>
        </html>
    `);
});

module.exports = router;

const express = require('express');
const http = require('http');
const router = express.Router();

// A10:Server-Side Request Forgery — user-supplied URL passed directly to server-side HTTP request
router.get('/fetch', (req, res) => {
    const url = req.query.url;
    http.get(url, (response) => {
        let data = '';
        response.on('data', (chunk) => { data += chunk; });
        response.on('end', () => res.send(data));
    }).on('error', (err) => res.status(500).send(err.message));
});

module.exports = router;

const express = require('express');
const http = require('http');
const { URL } = require('url');
const router = express.Router();

// SSRF protection: Validate and sanitize URLs before making requests
function isUrlSafe(urlString) {
    try {
        const url = new URL(urlString);

        // Only allow HTTP and HTTPS protocols
        if (!['http:', 'https:'].includes(url.protocol)) {
            return false;
        }

        // Block common internal/private IP ranges and localhost
        const hostname = url.hostname.toLowerCase();

        // Block localhost and loopback addresses
        if (hostname === 'localhost' ||
            hostname === '127.0.0.1' ||
            hostname.startsWith('127.') ||
            hostname === '0.0.0.0' ||
            hostname === '::1' ||
            hostname === '0:0:0:0:0:0:0:1') {
            return false;
        }

        // Block private IP ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
        if (hostname.startsWith('10.') ||
            hostname.startsWith('192.168.') ||
            /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(hostname)) {
            return false;
        }

        // Block link-local addresses (169.254.x.x)
        if (hostname.startsWith('169.254.')) {
            return false;
        }

        // Block metadata service endpoints (common in cloud environments)
        if (hostname === '169.254.169.254') {
            return false;
        }

        return true;
    } catch (err) {
        // Invalid URL format
        return false;
    }
}

// A10:Server-Side Request Forgery — Now protected with URL validation
router.get('/fetch', (req, res) => {
    const url = req.query.url;

    // Validate URL before making request
    if (!url || !isUrlSafe(url)) {
        return res.status(400).send('Invalid or unsafe URL provided');
    }

    http.get(url, (response) => {
        let data = '';
        response.on('data', (chunk) => { data += chunk; });
        response.on('end', () => res.send(data));
    }).on('error', (err) => res.status(500).send('Error fetching URL'));
});

module.exports = router;

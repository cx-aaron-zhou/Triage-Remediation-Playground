const express = require('express');
const _ = require('lodash');
const router = express.Router();

// SAST: A08:Software and Data Integrity Failures — Prototype Pollution
// SCA:  lodash 4.17.20 → CVE-2020-8203 (CVSS 7.4) — _.merge prototype pollution
//
// If req.body contains { "__proto__": { "isAdmin": true } }, lodash.merge writes
// directly onto Object.prototype, affecting all objects in the process.

const defaultConfig = { theme: 'light', language: 'en' };

router.post('/settings', (req, res) => {
    const userInput = req.body;
    const config = {};

    _.merge(config, defaultConfig, userInput);

    res.json({ message: 'Settings saved', config });
});

module.exports = router;

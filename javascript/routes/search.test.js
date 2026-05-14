const request = require('supertest');
const express = require('express');
const searchRouter = require('./search');

// Create a test app
const app = express();
app.use('/', searchRouter);

describe('Search Route - XSS Protection Tests', () => {
    describe('GET /search', () => {
        test('should return 200 status for valid request', async () => {
            const response = await request(app)
                .get('/search?q=test');
            expect(response.status).toBe(200);
            expect(response.text).toContain('Search Results');
        });

        test('should display search query for safe input', async () => {
            const response = await request(app)
                .get('/search?q=hello+world');
            expect(response.text).toContain('You searched for: hello world');
        });

        test('should escape HTML special characters to prevent XSS', async () => {
            const response = await request(app)
                .get('/search?q=<script>alert("xss")</script>');

            // Should contain encoded version, not raw script tag
            expect(response.text).toContain('&lt;script&gt;');
            expect(response.text).toContain('&lt;/script&gt;');
            // Should NOT contain unencoded script tags
            expect(response.text).not.toContain('<script>alert');
        });

        test('should escape ampersands correctly', async () => {
            const response = await request(app)
                .get('/search?q=Tom&Jerry');

            // Ampersands should be encoded
            expect(response.text).toContain('Tom&amp;Jerry');
        });

        test('should escape less-than and greater-than symbols', async () => {
            const response = await request(app)
                .get('/search?q=1<2>0');

            expect(response.text).toContain('1&lt;2&gt;0');
        });

        test('should escape double quotes to prevent attribute injection', async () => {
            const response = await request(app)
                .get('/search?q=test"onload="alert(1)');

            // Quotes should be encoded
            expect(response.text).toContain('&quot;');
            expect(response.text).not.toContain('onload="alert(1)"');
        });

        test('should escape single quotes to prevent attribute injection', async () => {
            const response = await request(app)
                .get('/search?q=test\'onload=\'alert(1)');

            // Single quotes should be encoded
            expect(response.text).toContain('&#x27;');
        });

        test('should escape forward slashes to prevent context breaking', async () => {
            const response = await request(app)
                .get('/search?q=</script><script>alert(1)</script>');

            // Forward slashes should be encoded
            expect(response.text).toContain('&#x2F;');
            // Should not contain unencoded closing script tag
            expect(response.text).not.toContain('</script><script>');
        });

        test('should handle XSS via IMG tag with onerror', async () => {
            const response = await request(app)
                .get('/search?q=<img src=x onerror=alert(1)>');

            // Should encode the entire tag
            expect(response.text).toContain('&lt;img');
            expect(response.text).toContain('&gt;');
            expect(response.text).not.toContain('<img src=x');
        });

        test('should handle XSS via event handlers', async () => {
            const response = await request(app)
                .get('/search?q=<div onmouseover="alert(1)">hover</div>');

            // Should encode angle brackets and quotes
            expect(response.text).toContain('&lt;div');
            expect(response.text).toContain('&quot;');
            expect(response.text).not.toContain('onmouseover="alert');
        });

        test('should handle XSS via SVG elements', async () => {
            const response = await request(app)
                .get('/search?q=<svg onload=alert(1)>');

            expect(response.text).toContain('&lt;svg');
            expect(response.text).toContain('&gt;');
            expect(response.text).not.toContain('<svg onload=');
        });

        test('should handle XSS via javascript: protocol', async () => {
            const response = await request(app)
                .get('/search?q=<a href="javascript:alert(1)">click</a>');

            expect(response.text).toContain('&lt;a');
            expect(response.text).toContain('&quot;');
            expect(response.text).not.toContain('javascript:alert');
        });

        test('should handle empty query parameter', async () => {
            const response = await request(app)
                .get('/search?q=');

            expect(response.status).toBe(200);
            expect(response.text).toContain('You searched for:');
        });

        test('should handle missing query parameter', async () => {
            const response = await request(app)
                .get('/search');

            expect(response.status).toBe(200);
            expect(response.text).toContain('Search Results');
        });

        test('should handle special characters combination attack', async () => {
            const response = await request(app)
                .get('/search?q="><script>alert(String.fromCharCode(88,83,83))</script>');

            // All special characters should be encoded
            expect(response.text).toContain('&quot;&gt;&lt;script&gt;');
            expect(response.text).not.toContain('"><script>');
        });

        test('should handle encoded attack attempts', async () => {
            const response = await request(app)
                .get('/search?q=%3Cscript%3Ealert(1)%3C/script%3E');

            // Express automatically decodes URL encoding, so our function should encode the result
            expect(response.text).toContain('&lt;script&gt;');
            expect(response.text).not.toContain('<script>');
        });

        test('should handle nested HTML tags', async () => {
            const response = await request(app)
                .get('/search?q=<div><span><script>alert(1)</script></span></div>');

            expect(response.text).toContain('&lt;div&gt;&lt;span&gt;&lt;script&gt;');
            expect(response.text).not.toContain('<div><span><script>');
        });

        test('should preserve legitimate search content after encoding', async () => {
            const response = await request(app)
                .get('/search?q=How+to+use+3<5+in+math');

            // Should show encoded version but still be readable
            expect(response.text).toContain('How to use 3&lt;5 in math');
            expect(response.status).toBe(200);
        });

        test('should handle unicode characters safely', async () => {
            const response = await request(app)
                .get('/search?q=测试<script>alert(1)</script>');

            // Unicode should pass through, but script tags should be encoded
            expect(response.text).toContain('测试');
            expect(response.text).toContain('&lt;script&gt;');
        });

        test('should handle data URI XSS attempt', async () => {
            const response = await request(app)
                .get('/search?q=<img src="data:text/html,<script>alert(1)</script>">');

            expect(response.text).toContain('&lt;img');
            expect(response.text).toContain('&quot;');
            expect(response.text).not.toContain('<img src="data:');
        });
    });

    describe('HTML Escaping Function Behavior', () => {
        // These tests verify the escapeHtml function works correctly
        // even though it's not exported, we test it indirectly through the route

        test('should handle null and undefined values gracefully', async () => {
            const response = await request(app).get('/search');
            expect(response.status).toBe(200);
            // Should not crash and should handle undefined query parameter
        });

        test('should maintain proper HTML structure after encoding', async () => {
            const response = await request(app)
                .get('/search?q=test<script>');

            // Response should still be valid HTML
            expect(response.text).toContain('<html>');
            expect(response.text).toContain('</html>');
            expect(response.text).toContain('<body>');
            expect(response.text).toContain('</body>');
        });
    });

    describe('Regression Tests', () => {
        test('should not break normal functionality for safe queries', async () => {
            const testQueries = [
                'javascript programming',
                'node.js tutorial',
                'how to cook pasta',
                'weather forecast',
                'movie reviews'
            ];

            for (const query of testQueries) {
                const response = await request(app)
                    .get(`/search?q=${encodeURIComponent(query)}`);

                expect(response.status).toBe(200);
                expect(response.text).toContain('Search Results');
                expect(response.text).toContain(query);
            }
        });

        test('should handle long query strings safely', async () => {
            const longQuery = 'a'.repeat(1000) + '<script>alert(1)</script>';
            const response = await request(app)
                .get(`/search?q=${encodeURIComponent(longQuery)}`);

            expect(response.status).toBe(200);
            expect(response.text).toContain('&lt;script&gt;');
            expect(response.text).not.toContain('<script>alert');
        });
    });
});

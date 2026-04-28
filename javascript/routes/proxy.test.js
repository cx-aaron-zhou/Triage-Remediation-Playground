const express = require('express');
const request = require('supertest');
const { expect } = require('chai');
const proxyRouter = require('./proxy');

describe('Proxy Route SSRF Protection', function() {
    let app;

    beforeEach(function() {
        // Create a fresh Express app for each test
        app = express();
        app.use('/proxy', proxyRouter);
    });

    describe('SSRF Attack Prevention', function() {
        // Test blocking localhost access
        it('should block requests to localhost', function(done) {
            request(app)
                .get('/proxy/fetch?url=http://localhost:3000')
                .expect(400)
                .end((err, res) => {
                    if (err) return done(err);
                    expect(res.text).to.equal('Invalid or unsafe URL provided');
                    done();
                });
        });

        it('should block requests to 127.0.0.1', function(done) {
            request(app)
                .get('/proxy/fetch?url=http://127.0.0.1:3000')
                .expect(400)
                .end((err, res) => {
                    if (err) return done(err);
                    expect(res.text).to.equal('Invalid or unsafe URL provided');
                    done();
                });
        });

        it('should block requests to 127.x.x.x loopback range', function(done) {
            request(app)
                .get('/proxy/fetch?url=http://127.0.0.2:8080')
                .expect(400)
                .end((err, res) => {
                    if (err) return done(err);
                    expect(res.text).to.equal('Invalid or unsafe URL provided');
                    done();
                });
        });

        it('should block requests to 0.0.0.0', function(done) {
            request(app)
                .get('/proxy/fetch?url=http://0.0.0.0:3000')
                .expect(400)
                .end((err, res) => {
                    if (err) return done(err);
                    expect(res.text).to.equal('Invalid or unsafe URL provided');
                    done();
                });
        });

        it('should block requests to IPv6 localhost (::1)', function(done) {
            request(app)
                .get('/proxy/fetch?url=http://[::1]:3000')
                .expect(400)
                .end((err, res) => {
                    if (err) return done(err);
                    expect(res.text).to.equal('Invalid or unsafe URL provided');
                    done();
                });
        });

        // Test blocking private IP ranges
        it('should block requests to 10.x.x.x private network', function(done) {
            request(app)
                .get('/proxy/fetch?url=http://10.0.0.1')
                .expect(400)
                .end((err, res) => {
                    if (err) return done(err);
                    expect(res.text).to.equal('Invalid or unsafe URL provided');
                    done();
                });
        });

        it('should block requests to 192.168.x.x private network', function(done) {
            request(app)
                .get('/proxy/fetch?url=http://192.168.1.1')
                .expect(400)
                .end((err, res) => {
                    if (err) return done(err);
                    expect(res.text).to.equal('Invalid or unsafe URL provided');
                    done();
                });
        });

        it('should block requests to 172.16.x.x private network', function(done) {
            request(app)
                .get('/proxy/fetch?url=http://172.16.0.1')
                .expect(400)
                .end((err, res) => {
                    if (err) return done(err);
                    expect(res.text).to.equal('Invalid or unsafe URL provided');
                    done();
                });
        });

        it('should block requests to 172.31.x.x private network', function(done) {
            request(app)
                .get('/proxy/fetch?url=http://172.31.255.255')
                .expect(400)
                .end((err, res) => {
                    if (err) return done(err);
                    expect(res.text).to.equal('Invalid or unsafe URL provided');
                    done();
                });
        });

        it('should block requests to link-local addresses (169.254.x.x)', function(done) {
            request(app)
                .get('/proxy/fetch?url=http://169.254.1.1')
                .expect(400)
                .end((err, res) => {
                    if (err) return done(err);
                    expect(res.text).to.equal('Invalid or unsafe URL provided');
                    done();
                });
        });

        it('should block requests to cloud metadata service (169.254.169.254)', function(done) {
            request(app)
                .get('/proxy/fetch?url=http://169.254.169.254/latest/meta-data/')
                .expect(400)
                .end((err, res) => {
                    if (err) return done(err);
                    expect(res.text).to.equal('Invalid or unsafe URL provided');
                    done();
                });
        });

        // Test blocking dangerous protocols
        it('should block file:// protocol', function(done) {
            request(app)
                .get('/proxy/fetch?url=file:///etc/passwd')
                .expect(400)
                .end((err, res) => {
                    if (err) return done(err);
                    expect(res.text).to.equal('Invalid or unsafe URL provided');
                    done();
                });
        });

        it('should block ftp:// protocol', function(done) {
            request(app)
                .get('/proxy/fetch?url=ftp://example.com')
                .expect(400)
                .end((err, res) => {
                    if (err) return done(err);
                    expect(res.text).to.equal('Invalid or unsafe URL provided');
                    done();
                });
        });

        it('should block gopher:// protocol', function(done) {
            request(app)
                .get('/proxy/fetch?url=gopher://example.com')
                .expect(400)
                .end((err, res) => {
                    if (err) return done(err);
                    expect(res.text).to.equal('Invalid or unsafe URL provided');
                    done();
                });
        });

        // Test invalid/malformed URLs
        it('should reject missing URL parameter', function(done) {
            request(app)
                .get('/proxy/fetch')
                .expect(400)
                .end((err, res) => {
                    if (err) return done(err);
                    expect(res.text).to.equal('Invalid or unsafe URL provided');
                    done();
                });
        });

        it('should reject empty URL parameter', function(done) {
            request(app)
                .get('/proxy/fetch?url=')
                .expect(400)
                .end((err, res) => {
                    if (err) return done(err);
                    expect(res.text).to.equal('Invalid or unsafe URL provided');
                    done();
                });
        });

        it('should reject malformed URLs', function(done) {
            request(app)
                .get('/proxy/fetch?url=not-a-valid-url')
                .expect(400)
                .end((err, res) => {
                    if (err) return done(err);
                    expect(res.text).to.equal('Invalid or unsafe URL provided');
                    done();
                });
        });

        it('should reject URLs without protocol', function(done) {
            request(app)
                .get('/proxy/fetch?url=example.com')
                .expect(400)
                .end((err, res) => {
                    if (err) return done(err);
                    expect(res.text).to.equal('Invalid or unsafe URL provided');
                    done();
                });
        });
    });

    describe('Legitimate URL Handling', function() {
        // Note: These tests demonstrate the validation logic allows legitimate URLs
        // In a real environment, you would mock the http.get calls to avoid actual external requests

        it('should allow requests to legitimate HTTP URLs', function(done) {
            // This test would make an actual HTTP request in a real scenario
            // In production tests, you should mock http.get
            request(app)
                .get('/proxy/fetch?url=http://example.com')
                .end((err, res) => {
                    if (err) return done(err);
                    // Should not return 400 (validation should pass)
                    expect(res.status).to.not.equal(400);
                    done();
                });
        });

        it('should allow requests to legitimate HTTPS URLs', function(done) {
            // This test would make an actual HTTPS request in a real scenario
            // In production tests, you should mock http.get
            request(app)
                .get('/proxy/fetch?url=https://example.com')
                .end((err, res) => {
                    if (err) return done(err);
                    // Should not return 400 (validation should pass)
                    expect(res.status).to.not.equal(400);
                    done();
                });
        });
    });

    describe('Error Handling', function() {
        it('should not expose internal error details', function(done) {
            // Test with a URL that will fail to connect (non-existent domain)
            request(app)
                .get('/proxy/fetch?url=http://this-domain-does-not-exist-12345.com')
                .end((err, res) => {
                    if (err) return done(err);
                    // Should return 500 with generic error message
                    if (res.status === 500) {
                        expect(res.text).to.equal('Error fetching URL');
                        // Ensure no stack traces or internal details are exposed
                        expect(res.text).to.not.include('Error:');
                        expect(res.text).to.not.include('at ');
                        expect(res.text).to.not.include('/javascript/');
                    }
                    done();
                });
        });
    });

    describe('Edge Cases and Bypass Attempts', function() {
        it('should handle uppercase LOCALHOST', function(done) {
            request(app)
                .get('/proxy/fetch?url=http://LOCALHOST:3000')
                .expect(400)
                .end((err, res) => {
                    if (err) return done(err);
                    expect(res.text).to.equal('Invalid or unsafe URL provided');
                    done();
                });
        });

        it('should handle mixed case hostnames', function(done) {
            request(app)
                .get('/proxy/fetch?url=http://LocalHost:3000')
                .expect(400)
                .end((err, res) => {
                    if (err) return done(err);
                    expect(res.text).to.equal('Invalid or unsafe URL provided');
                    done();
                });
        });

        it('should block URL with port specification on localhost', function(done) {
            request(app)
                .get('/proxy/fetch?url=http://localhost:8080/admin')
                .expect(400)
                .end((err, res) => {
                    if (err) return done(err);
                    expect(res.text).to.equal('Invalid or unsafe URL provided');
                    done();
                });
        });

        it('should block URL with path on private IP', function(done) {
            request(app)
                .get('/proxy/fetch?url=http://192.168.1.1/admin/config')
                .expect(400)
                .end((err, res) => {
                    if (err) return done(err);
                    expect(res.text).to.equal('Invalid or unsafe URL provided');
                    done();
                });
        });

        it('should block URL with query parameters on private IP', function(done) {
            request(app)
                .get('/proxy/fetch?url=http://10.0.0.1/api?secret=token')
                .expect(400)
                .end((err, res) => {
                    if (err) return done(err);
                    expect(res.text).to.equal('Invalid or unsafe URL provided');
                    done();
                });
        });
    });
});

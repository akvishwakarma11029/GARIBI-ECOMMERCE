const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const novuService = require('./novu-service');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('.')); // Serve static files from current directory

// Logging middleware
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
    next();
});

// ==================== NOTIFICATION ENDPOINTS ====================

/**
 * POST /api/notify/login-success
 * Send login success notification
 */
app.post('/api/notify/login-success', async (req, res) => {
    try {
        const { email, name, loginTime } = req.body;

        if (!email || !name) {
            return res.status(400).json({
                success: false,
                error: 'Email and name are required'
            });
        }

        const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        const result = await novuService.sendLoginSuccess(email, name, loginTime, ipAddress);

        res.json(result);
    } catch (error) {
        console.error('Error in login-success endpoint:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/notify/failed-login
 * Send failed login alert
 */
app.post('/api/notify/failed-login', async (req, res) => {
    try {
        const { email, attemptCount } = req.body;

        if (!email) {
            return res.status(400).json({
                success: false,
                error: 'Email is required'
            });
        }

        // Get user name from database
        const dbPath = path.join(__dirname, 'documentation', 'customer_database.json');
        const users = JSON.parse(fs.readFileSync(dbPath, 'utf8'));
        const user = users.find(u => u.email === email);

        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }

        const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        const result = await novuService.sendFailedLoginAlert(
            email,
            user.name,
            attemptCount || 1,
            ipAddress
        );

        res.json(result);
    } catch (error) {
        console.error('Error in failed-login endpoint:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/notify/2fa-code
 * Send 2FA verification code
 */
app.post('/api/notify/2fa-code', async (req, res) => {
    try {
        const { email, name, code } = req.body;

        if (!email || !name || !code) {
            return res.status(400).json({
                success: false,
                error: 'Email, name, and code are required'
            });
        }

        const result = await novuService.send2FACode(email, name, code);
        res.json(result);
    } catch (error) {
        console.error('Error in 2fa-code endpoint:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/notify/password-reset
 * Send password reset code
 */
app.post('/api/notify/password-reset', async (req, res) => {
    try {
        const { email, resetCode } = req.body;

        if (!email || !resetCode) {
            return res.status(400).json({
                success: false,
                error: 'Email and reset code are required'
            });
        }

        // Get user name from database
        const dbPath = path.join(__dirname, 'documentation', 'customer_database.json');
        const users = JSON.parse(fs.readFileSync(dbPath, 'utf8'));
        const user = users.find(u => u.email === email);

        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }

        const result = await novuService.sendPasswordReset(email, user.name, resetCode);
        res.json(result);
    } catch (error) {
        console.error('Error in password-reset endpoint:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/notify/account-locked
 * Send account locked alert
 */
app.post('/api/notify/account-locked', async (req, res) => {
    try {
        const { email, reason } = req.body;

        if (!email) {
            return res.status(400).json({
                success: false,
                error: 'Email is required'
            });
        }

        // Get user name from database
        const dbPath = path.join(__dirname, 'documentation', 'customer_database.json');
        const users = JSON.parse(fs.readFileSync(dbPath, 'utf8'));
        const user = users.find(u => u.email === email);

        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }

        const result = await novuService.sendAccountLockedAlert(
            email,
            user.name,
            reason || 'Multiple failed login attempts'
        );

        res.json(result);
    } catch (error) {
        console.error('Error in account-locked endpoint:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/notify/subscribe
 * Subscribe new user to Novu
 */
app.post('/api/notify/subscribe', async (req, res) => {
    try {
        const { email, name } = req.body;

        if (!email || !name) {
            return res.status(400).json({
                success: false,
                error: 'Email and name are required'
            });
        }

        const result = await novuService.subscribeUser(email, name);
        res.json(result);
    } catch (error) {
        console.error('Error in subscribe endpoint:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * DELETE /api/notify/unsubscribe/:email
 * Unsubscribe user from Novu
 */
app.delete('/api/notify/unsubscribe/:email', async (req, res) => {
    try {
        const { email } = req.params;

        if (!email) {
            return res.status(400).json({
                success: false,
                error: 'Email is required'
            });
        }

        const result = await novuService.unsubscribeUser(email);
        res.json(result);
    } catch (error) {
        console.error('Error in unsubscribe endpoint:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ==================== HEALTH CHECK ====================

app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        service: 'GARIBI Novu Notification Server',
        timestamp: new Date().toISOString()
    });
});

// ==================== ERROR HANDLING ====================

app.use((req, res) => {
    res.status(404).json({
        success: false,
        error: 'Endpoint not found'
    });
});

app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({
        success: false,
        error: 'Internal server error'
    });
});

// ==================== START SERVER ====================

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`
╔═══════════════════════════════════════════════════════╗
║                                                       ║
║   🚀 GARIBI Novu Notification Server                 ║
║                                                       ║
║   Status: Running                                     ║
║   Port: ${PORT}                                          ║
║   Time: ${new Date().toLocaleString('en-IN')}     ║
║                                                       ║
║   Endpoints:                                          ║
║   • POST /api/notify/login-success                    ║
║   • POST /api/notify/failed-login                     ║
║   • POST /api/notify/2fa-code                         ║
║   • POST /api/notify/password-reset                   ║
║   • POST /api/notify/account-locked                   ║
║   • POST /api/notify/subscribe                        ║
║   • DELETE /api/notify/unsubscribe/:email             ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝
    `);
});

module.exports = app;

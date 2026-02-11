const { Novu } = require('@novu/node');
require('dotenv').config();

const novu = new Novu(process.env.NOVU_API_KEY);

class NovuNotificationService {

    /**
     * Send Login Success Notification
     * Triggered when user successfully logs in
     */
    async sendLoginSuccess(userEmail, userName, loginTime, ipAddress = 'Unknown') {
        try {
            await novu.trigger('login-success', {
                to: {
                    subscriberId: userEmail,
                    email: userEmail,
                },
                payload: {
                    userName: userName,
                    loginTime: loginTime,
                    ipAddress: ipAddress,
                    deviceInfo: 'Web Browser'
                }
            });
            console.log(`✅ Login success email sent to ${userEmail}`);
            return { success: true };
        } catch (error) {
            console.error('❌ Error sending login notification:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Send Failed Login Alert
     * Triggered after multiple wrong password attempts
     */
    async sendFailedLoginAlert(userEmail, userName, attemptCount, ipAddress = 'Unknown') {
        try {
            await novu.trigger('failed-login-alert', {
                to: {
                    subscriberId: userEmail,
                    email: userEmail,
                },
                payload: {
                    userName: userName,
                    attemptCount: attemptCount,
                    ipAddress: ipAddress,
                    timestamp: new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
                    actionRequired: attemptCount >= 3
                        ? 'Account will be locked after next failed attempt'
                        : 'Please verify your credentials'
                }
            });
            console.log(`⚠️ Failed login alert sent to ${userEmail} (${attemptCount} attempts)`);
            return { success: true };
        } catch (error) {
            console.error('❌ Error sending failed login alert:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Send 2FA Code
     * Sends one-time password for two-factor authentication
     */
    async send2FACode(userEmail, userName, code) {
        try {
            await novu.trigger('2fa-code', {
                to: {
                    subscriberId: userEmail,
                    email: userEmail,
                },
                payload: {
                    userName: userName,
                    code: code,
                    expiryTime: '10 minutes',
                    timestamp: new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })
                }
            });
            console.log(`🔐 2FA code sent to ${userEmail}: ${code}`);
            return { success: true };
        } catch (error) {
            console.error('❌ Error sending 2FA code:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Send Password Reset Code
     * Triggered when user requests forgot password
     */
    async sendPasswordReset(userEmail, userName, resetCode) {
        try {
            await novu.trigger('password-reset', {
                to: {
                    subscriberId: userEmail,
                    email: userEmail,
                },
                payload: {
                    userName: userName,
                    resetCode: resetCode,
                    expiryTime: '15 minutes',
                    timestamp: new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })
                }
            });
            console.log(`🔑 Password reset email sent to ${userEmail}`);
            return { success: true };
        } catch (error) {
            console.error('❌ Error sending password reset:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Send Account Locked Alert
     * Triggered when account is locked due to suspicious activity
     */
    async sendAccountLockedAlert(userEmail, userName, reason = 'Multiple failed login attempts') {
        try {
            await novu.trigger('account-locked', {
                to: {
                    subscriberId: userEmail,
                    email: userEmail,
                },
                payload: {
                    userName: userName,
                    reason: reason,
                    timestamp: new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
                    supportContact: '+91 7984974394',
                    supportEmail: 'admin@garibi.com'
                }
            });
            console.log(`🔒 Account locked alert sent to ${userEmail}`);
            return { success: true };
        } catch (error) {
            console.error('❌ Error sending account locked alert:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Subscribe a new user to Novu
     * Called during user registration
     */
    async subscribeUser(userEmail, userName) {
        try {
            const nameParts = userName.split(' ');
            await novu.subscribers.identify(userEmail, {
                email: userEmail,
                firstName: nameParts[0] || userName,
                lastName: nameParts.slice(1).join(' ') || '',
            });
            console.log(`👤 User ${userEmail} subscribed to Novu`);
            return { success: true };
        } catch (error) {
            console.error('❌ Error subscribing user:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Unsubscribe user from Novu
     * Called when user deletes account
     */
    async unsubscribeUser(userEmail) {
        try {
            await novu.subscribers.delete(userEmail);
            console.log(`🗑️ User ${userEmail} unsubscribed from Novu`);
            return { success: true };
        } catch (error) {
            console.error('❌ Error unsubscribing user:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Send custom notification
     * For any other notification needs
     */
    async sendCustomNotification(userEmail, workflowId, payload) {
        try {
            await novu.trigger(workflowId, {
                to: {
                    subscriberId: userEmail,
                    email: userEmail,
                },
                payload: payload
            });
            console.log(`📧 Custom notification sent to ${userEmail} (${workflowId})`);
            return { success: true };
        } catch (error) {
            console.error('❌ Error sending custom notification:', error);
            return { success: false, error: error.message };
        }
    }
}

// Export singleton instance
module.exports = new NovuNotificationService();

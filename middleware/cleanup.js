const Token = require('../models/Token');
const Session = require('../models/Session');

/**
 * Cleanup expired tokens and sessions
 */
async function cleanupExpiredData() {
    try {
        console.log('Running cleanup for expired data...');
        
        // Cleanup expired tokens
        const expiredTokens = await Token.cleanupExpiredTokens();
        if (expiredTokens > 0) {
            console.log(`Marked ${expiredTokens} tokens as expired`);
        }
        
        // Cleanup expired sessions
        const expiredSessions = await Session.cleanupExpiredSessions();
        if (expiredSessions > 0) {
            console.log(`Marked ${expiredSessions} sessions as expired`);
        }
        
    } catch (error) {
        console.error('Error during cleanup:', error);
    }
}

/**
 * Auto-delete expired tokens if enabled
 */
async function autoDeleteExpiredTokens() {
    try {
        const deletedCount = await Token.deleteExpiredTokens();
        if (deletedCount > 0) {
            console.log(`Auto-deleted ${deletedCount} expired tokens`);
        }
        return deletedCount;
    } catch (error) {
        console.error('Error auto-deleting expired tokens:', error);
        return 0;
    }
}

module.exports = {
    cleanupExpiredData,
    autoDeleteExpiredTokens
};


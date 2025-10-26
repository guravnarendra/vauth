const Token = require('../models/Token');
const Session = require('../models/Session');
const firebaseTokenManager = require('../utils/firebaseTokenManager');

/**
 * Cleanup expired tokens and sessions
 */
async function cleanupExpiredData() {
  try {
    console.log('Running cleanup for expired data...');
    
    // Cleanup expired tokens in Firebase
    const expiredTokens = await firebaseTokenManager.cleanupExpiredTokens();
    if (expiredTokens > 0) {
      console.log(`Marked ${expiredTokens} tokens as expired in Firebase`);
    }

    // Cleanup expired sessions in MongoDB
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
    const deletedCount = await firebaseTokenManager.deleteExpiredTokens();
    if (deletedCount > 0) {
      console.log(`Auto-deleted ${deletedCount} expired tokens from Firebase`);
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
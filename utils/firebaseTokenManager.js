const { db } = require('../config/firebase');
const crypto = require('crypto');

class FirebaseTokenManager {
  constructor() {
    this.tokensRef = db.ref('tokens');
    this.io = null;
  }

  // Set up real-time listeners
  setupRealTimeListeners(io) {
    this.io = io;
    
    console.log('🔥 Firebase real-time listeners initialized');

    // Listen for token changes in Firebase
    this.tokensRef.on('child_changed', (snapshot) => {
      const token = snapshot.val();
      const tokenId = snapshot.key;
      
      console.log(`🔄 Token ${tokenId} status changed to: ${token.status}`);
      
      // Emit real-time update to admin dashboard
      if (this.io) {
        this.io.to('admin').emit('token-status-update', {
          tokenId,
          newStatus: token.status,
          device_id: token.device_id,
          timestamp: new Date()
        });
      }
    });

    // Listen for new tokens
    this.tokensRef.on('child_added', (snapshot) => {
      const token = snapshot.val();
      const tokenId = snapshot.key;
      
      console.log(`🆕 New token created: ${tokenId} for device: ${token.device_id}`);
      
      // Emit new token to admin dashboard
      if (this.io) {
        this.io.to('admin').emit('token-added', {
          tokenId,
          token: {
            _id: tokenId,
            ...token,
            timeRemaining: this.calculateTimeRemaining(token)
          },
          timestamp: new Date()
        });
      }
    });

    // Listen for token deletions
    this.tokensRef.on('child_removed', (snapshot) => {
      const tokenId = snapshot.key;
      
      console.log(`🗑️ Token deleted: ${tokenId}`);
      
      // Emit token deletion to admin dashboard
      if (this.io) {
        this.io.to('admin').emit('token-deleted', {
          tokenId,
          timestamp: new Date()
        });
      }
    });
  }

  // Generate token hash (same as MongoDB version)
  generateTokenHash(device_id, plain_token) {
    return crypto.createHash('sha512').update(device_id + plain_token).digest('hex');
  }

  // Generate random 6-character token
  generateRandomToken() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let token = '';
    for (let i = 0; i < 6; i++) {
      token += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return token;
  }

  // Create new token in Firebase
  async createToken(device_id, expirySeconds = 300) {
    try {
      const plain_token = this.generateRandomToken();
      const token_hash = this.generateTokenHash(device_id, plain_token);
      
      const expires_at = new Date(Date.now() + (expirySeconds * 1000));
      const created_at = new Date();

      const tokenData = {
        device_id,
        token_hash,
        status: 'ACTIVE',
        created_at: created_at.toISOString(),
        expires_at: expires_at.toISOString(),
        used_at: null
      };

      // Store in Firebase
      const tokenRef = this.tokensRef.push();
      await tokenRef.set(tokenData);

      console.log(`✅ Token created in Firebase: ${tokenRef.key} for device: ${device_id}`);

      // Set up auto-expiry in Firebase
      this.setupTokenExpiry(tokenRef.key, expires_at);

      return {
        token: {
          _id: tokenRef.key,
          ...tokenData
        },
        plain_token
      };

    } catch (error) {
      console.error('❌ Firebase token creation error:', error);
      throw error;
    }
  }

  // Set up Firebase rules for auto-expiry
  setupTokenExpiry(tokenId, expires_at) {
    const expiresIn = expires_at.getTime() - Date.now();
    
    if (expiresIn > 0) {
      setTimeout(async () => {
        try {
          await this.tokensRef.child(tokenId).update({
            status: 'EXPIRED'
          });
          console.log(`⏰ Token ${tokenId} auto-expired in Firebase`);
        } catch (error) {
          console.error('❌ Error auto-expiring token in Firebase:', error);
        }
      }, expiresIn);
    }
  }

  // Verify token
  async verifyToken(device_id, plain_token) {
    try {
      const token_hash = this.generateTokenHash(device_id, plain_token);
      
      // Query Firebase for matching token
      const snapshot = await this.tokensRef
        .orderByChild('token_hash')
        .equalTo(token_hash)
        .once('value');

      if (!snapshot.exists()) {
        console.log(`❌ Token verification failed: TOKEN_NOT_FOUND for device: ${device_id}`);
        return { valid: false, reason: 'TOKEN_NOT_FOUND' };
      }

      let token = null;
      let tokenId = null;

      snapshot.forEach((childSnapshot) => {
        token = childSnapshot.val();
        tokenId = childSnapshot.key;
        
        // Check if token belongs to the correct device
        if (token.device_id !== device_id) {
          token = null;
          return;
        }
      });

      if (!token) {
        console.log(`❌ Token verification failed: TOKEN_NOT_FOUND for device: ${device_id}`);
        return { valid: false, reason: 'TOKEN_NOT_FOUND' };
      }

      if (token.status !== 'ACTIVE') {
        console.log(`❌ Token verification failed: TOKEN_INACTIVE for device: ${device_id}`);
        return { valid: false, reason: 'TOKEN_INACTIVE' };
      }

      const expiresAt = new Date(token.expires_at);
      if (expiresAt < new Date()) {
        // Mark as expired
        await this.tokensRef.child(tokenId).update({
          status: 'EXPIRED'
        });
        console.log(`❌ Token verification failed: TOKEN_EXPIRED for device: ${device_id}`);
        return { valid: false, reason: 'TOKEN_EXPIRED' };
      }

      // Mark as used
      await this.tokensRef.child(tokenId).update({
        status: 'USED',
        used_at: new Date().toISOString()
      });

      console.log(`✅ Token verified successfully for device: ${device_id}`);

      return { 
        valid: true, 
        token: {
          _id: tokenId,
          ...token,
          status: 'USED',
          used_at: new Date().toISOString()
        }
      };

    } catch (error) {
      console.error('❌ Firebase token verification error:', error);
      return { valid: false, reason: 'VERIFICATION_ERROR' };
    }
  }

  // Get all tokens
  async getAllTokens() {
    try {
      const snapshot = await this.tokensRef.once('value');
      if (!snapshot.exists()) {
        console.log('ℹ️  No tokens found in Firebase');
        return [];
      }

      const tokens = [];
      snapshot.forEach((childSnapshot) => {
        const token = childSnapshot.val();
        tokens.push({
          _id: childSnapshot.key,
          ...token,
          timeRemaining: this.calculateTimeRemaining(token)
        });
      });

      console.log(`📊 Retrieved ${tokens.length} tokens from Firebase`);
      return tokens;
    } catch (error) {
      console.error('❌ Error getting tokens from Firebase:', error);
      return [];
    }
  }

  // Calculate time remaining
  calculateTimeRemaining(token) {
    if (token.status !== 'ACTIVE') return 0;
    
    const now = new Date();
    const expiresAt = new Date(token.expires_at);
    
    // Handle invalid dates
    if (isNaN(expiresAt.getTime())) {
      return 0;
    }
    
    const remaining = Math.max(0, expiresAt - now);
    return Math.floor(remaining / 1000);
  }

  // Delete token
  async deleteToken(tokenId) {
    try {
      await this.tokensRef.child(tokenId).remove();
      console.log(`✅ Token deleted from Firebase: ${tokenId}`);
      return true;
    } catch (error) {
      console.error('❌ Error deleting token from Firebase:', error);
      return false;
    }
  }

  // Cleanup expired tokens
  async cleanupExpiredTokens() {
    try {
      const snapshot = await this.tokensRef
        .orderByChild('status')
        .equalTo('ACTIVE')
        .once('value');

      let expiredCount = 0;
      const updates = {};

      snapshot.forEach((childSnapshot) => {
        const token = childSnapshot.val();
        const expiresAt = new Date(token.expires_at);
        
        if (expiresAt < new Date()) {
          updates[childSnapshot.key] = {
            ...token,
            status: 'EXPIRED'
          };
          expiredCount++;
        }
      });

      if (expiredCount > 0) {
        await this.tokensRef.update(updates);
        console.log(`🔄 Marked ${expiredCount} tokens as expired in Firebase`);
      }

      return expiredCount;
    } catch (error) {
      console.error('❌ Error cleaning up expired tokens in Firebase:', error);
      return 0;
    }
  }

  // Delete expired tokens
  async deleteExpiredTokens() {
    try {
      const snapshot = await this.tokensRef
        .orderByChild('status')
        .equalTo('EXPIRED')
        .once('value');

      let deletedCount = 0;
      const updates = {};

      snapshot.forEach((childSnapshot) => {
        updates[childSnapshot.key] = null;
        deletedCount++;
      });

      if (deletedCount > 0) {
        await this.tokensRef.update(updates);
        console.log(`🗑️  Deleted ${deletedCount} expired tokens from Firebase`);
      }

      return deletedCount;
    } catch (error) {
      console.error('❌ Error deleting expired tokens from Firebase:', error);
      return 0;
    }
  }

  // Get token by ID
  async getTokenById(tokenId) {
    try {
      const snapshot = await this.tokensRef.child(tokenId).once('value');
      if (!snapshot.exists()) {
        return null;
      }
      
      const token = snapshot.val();
      return {
        _id: tokenId,
        ...token,
        timeRemaining: this.calculateTimeRemaining(token)
      };
    } catch (error) {
      console.error('❌ Error getting token by ID from Firebase:', error);
      return null;
    }
  }
}

module.exports = new FirebaseTokenManager();
const mongoose = require('mongoose');
const crypto = require('crypto');
const firebaseTokenManager = require('../utils/firebaseTokenManager');

const tokenSchema = new mongoose.Schema({
  device_id: {
    type: String,
    required: true,
    trim: true
  },
  token_hash: {
    type: String,
    required: true,
    unique: true
  },
  status: {
    type: String,
    enum: ['ACTIVE', 'USED', 'EXPIRED'],
    default: 'ACTIVE'
  },
  created_at: {
    type: Date,
    default: Date.now
  },
  expires_at: {
    type: Date,
    required: true
  },
  used_at: {
    type: Date,
    default: null
  }
});

// Indexes for performance
tokenSchema.index({ device_id: 1 }, { name: "token_device_id_index" });
tokenSchema.index({ token_hash: 1 }, { name: "token_hash_index" });
tokenSchema.index({ status: 1 }, { name: "token_status_index" });
tokenSchema.index({ expires_at: 1 }, { name: "token_expires_at_index" });
tokenSchema.index({ created_at: -1 }, { name: "token_created_at_index" });

// Static method to generate token hash
tokenSchema.statics.generateTokenHash = function(device_id, plain_token) {
  return crypto.createHash('sha512').update(device_id + plain_token).digest('hex');
};

// Static method to generate random 6-character token
tokenSchema.statics.generateRandomToken = function() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let token = '';
  for (let i = 0; i < 6; i++) {
    token += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return token;
};

// Static method to create new token (now uses Firebase)
tokenSchema.statics.createToken = async function(device_id, expirySeconds = 300) {
  return await firebaseTokenManager.createToken(device_id, expirySeconds);
};

// Static method to verify token (now uses Firebase)
tokenSchema.statics.verifyToken = async function(device_id, plain_token) {
  return await firebaseTokenManager.verifyToken(device_id, plain_token);
};

// Static method to get all tokens (FIXED - returns array directly)
tokenSchema.statics.find = async function(query = {}) {
  try {
    const tokens = await firebaseTokenManager.getAllTokens();
    
    // Apply basic filtering
    let filteredTokens = tokens;
    
    if (query.status) {
      filteredTokens = tokens.filter(token => token.status === query.status);
    }
    
    // Return the array directly - the calling code will handle sorting
    return filteredTokens;
  } catch (error) {
    console.error('Error in Token.find:', error);
    return [];
  }
};

// Static method to cleanup expired tokens (now uses Firebase)
tokenSchema.statics.cleanupExpiredTokens = async function() {
  return await firebaseTokenManager.cleanupExpiredTokens();
};

// Static method to delete expired tokens (now uses Firebase)
tokenSchema.statics.deleteExpiredTokens = async function() {
  return await firebaseTokenManager.deleteExpiredTokens();
};

// Static method to find by ID and delete (now uses Firebase)
tokenSchema.statics.findByIdAndDelete = async function(tokenId) {
  const success = await firebaseTokenManager.deleteToken(tokenId);
  return success ? { _id: tokenId } : null;
};

// Static method to count documents (now uses Firebase)
tokenSchema.statics.countDocuments = async function(query = {}) {
  const tokens = await firebaseTokenManager.getAllTokens();
  
  if (query.status) {
    return tokens.filter(token => token.status === query.status).length;
  }
  
  return tokens.length;
};

// Virtual for time remaining
tokenSchema.virtual('timeRemaining').get(function() {
  if (this.status !== 'ACTIVE') return 0;
  const now = new Date();
  const remaining = Math.max(0, new Date(this.expires_at) - now);
  return Math.floor(remaining / 1000);
});

module.exports = mongoose.model('Token', tokenSchema);
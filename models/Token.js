const mongoose = require('mongoose');
const crypto = require('crypto');

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

// Indexes for performance - specify names to avoid conflicts
tokenSchema.index({ device_id: 1 }, { name: "token_device_id_index" });
tokenSchema.index({ token_hash: 1 }, { name: "token_hash_index" });
tokenSchema.index({ status: 1 }, { name: "token_status_index" });
tokenSchema.index({ expires_at: 1 }, { name: "token_expires_at_index" });
tokenSchema.index({ created_at: -1 }, { name: "token_created_at_index" });

// ... rest of the Token model code remains the same
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

// Static method to create new token
tokenSchema.statics.createToken = async function(device_id, expirySeconds = 300) {
  const plain_token = this.generateRandomToken();
  const token_hash = this.generateTokenHash(device_id, plain_token);
  const expires_at = new Date(Date.now() + (expirySeconds * 1000));

  const token = await this.create({
    device_id,
    token_hash,
    expires_at
  });

  return {
    token: token,
    plain_token: plain_token
  };
};

// Static method to verify token
tokenSchema.statics.verifyToken = async function(device_id, plain_token) {
  const token_hash = this.generateTokenHash(device_id, plain_token);
  const token = await this.findOne({
    device_id,
    token_hash,
    status: 'ACTIVE'
  });

  if (!token) {
    return { valid: false, reason: 'TOKEN_NOT_FOUND' };
  }

  if (token.expires_at < new Date()) {
    // Mark as expired
    token.status = 'EXPIRED';
    await token.save();
    return { valid: false, reason: 'TOKEN_EXPIRED' };
  }

  // Mark as used
  token.status = 'USED';
  token.used_at = new Date();
  await token.save();

  return { valid: true, token: token };
};

// Static method to cleanup expired tokens
tokenSchema.statics.cleanupExpiredTokens = async function() {
  const result = await this.updateMany(
    {
      status: 'ACTIVE',
      expires_at: { $lt: new Date() }
    },
    {
      $set: { status: 'EXPIRED' }
    }
  );
  return result.modifiedCount;
};

// Static method to delete expired tokens
tokenSchema.statics.deleteExpiredTokens = async function() {
  const result = await this.deleteMany({
    status: 'EXPIRED'
  });
  return result.deletedCount;
};

// Virtual for time remaining
tokenSchema.virtual('timeRemaining').get(function() {
  if (this.status !== 'ACTIVE') return 0;
  const now = new Date();
  const remaining = Math.max(0, this.expires_at - now);
  return Math.floor(remaining / 1000); // Return seconds
});

module.exports = mongoose.model('Token', tokenSchema);
const mongoose = require('mongoose');

const sessionSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    trim: true
  },
  device_id: {
    type: String,
    required: true,
    trim: true
  },
  ip: {
    type: String,
    required: true
  },
  started_at: {
    type: Date,
    default: Date.now
  },
  expires_at: {
    type: Date,
    required: true
  },
  status: {
    type: String,
    enum: ['ACTIVE', 'FORCED_LOGOUT', 'EXPIRED'],
    default: 'ACTIVE'
  }
});

// Indexes for performance - specify names to avoid conflicts
sessionSchema.index({ username: 1 }, { name: "session_username_index" });
sessionSchema.index({ device_id: 1 }, { name: "session_device_id_index" });
sessionSchema.index({ status: 1 }, { name: "session_status_index" });
sessionSchema.index({ expires_at: 1 }, { name: "session_expires_at_index" });
sessionSchema.index({ started_at: -1 }, { name: "session_started_at_index" });

// ... rest of the Session model code remains the same
// Static method to create new session
sessionSchema.statics.createSession = async function(username, device_id, ip, expiryMinutes = 10) {
  const expires_at = new Date(Date.now() + (expiryMinutes * 60 * 1000));
  
  // End any existing active sessions for this user
  await this.updateMany(
    { username, status: 'ACTIVE' },
    { $set: { status: 'EXPIRED' } }
  );

  return await this.create({
    username,
    device_id,
    ip,
    expires_at
  });
};

// Static method to validate session
sessionSchema.statics.validateSession = async function(sessionId) {
  const session = await this.findById(sessionId);
  if (!session) {
    return { valid: false, reason: 'SESSION_NOT_FOUND' };
  }

  if (session.status !== 'ACTIVE') {
    return { valid: false, reason: 'SESSION_INACTIVE' };
  }

  if (session.expires_at < new Date()) {
    // Mark as expired
    session.status = 'EXPIRED';
    await session.save();
    return { valid: false, reason: 'SESSION_EXPIRED' };
  }

  return { valid: true, session: session };
};

// Static method to force logout
sessionSchema.statics.forceLogout = async function(sessionId) {
  const session = await this.findById(sessionId);
  if (session && session.status === 'ACTIVE') {
    session.status = 'FORCED_LOGOUT';
    await session.save();
    return true;
  }
  return false;
};

// Static method to cleanup expired sessions
sessionSchema.statics.cleanupExpiredSessions = async function() {
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

// Static method to get active sessions
sessionSchema.statics.getActiveSessions = async function() {
  return await this.find({
    status: 'ACTIVE',
    expires_at: { $gt: new Date() }
  }).sort({ started_at: -1 });
};

// Virtual for time remaining
sessionSchema.virtual('timeRemaining').get(function() {
  if (this.status !== 'ACTIVE') return 0;
  const now = new Date();
  const remaining = Math.max(0, this.expires_at - now);
  return Math.floor(remaining / 1000); // Return seconds
});

// Virtual for session duration
sessionSchema.virtual('duration').get(function() {
  const now = new Date();
  const duration = now - this.started_at;
  return Math.floor(duration / 1000); // Return seconds
});

module.exports = mongoose.model('Session', sessionSchema);
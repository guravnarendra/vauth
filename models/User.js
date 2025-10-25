const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const { encrypt, decrypt } = require('../utils/encryption');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 50
  },
  password_hash: {
    type: String,
    required: true
  },
  vauth_device_ID: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  // Encrypted PII fields
  name_enc: {
    type: String,
    required: true
  },
  email_enc: {
    type: String,
    required: true
  },
  mobile_enc: {
    type: String,
    required: true
  },
  operating_country_enc: {
    type: String,
    required: true
  },
  created_at: {
    type: Date,
    default: Date.now
  }
});

// Indexes for performance - specify names to avoid conflicts
userSchema.index({ username: 1 }, { name: "username_index" });
userSchema.index({ vauth_device_ID: 1 }, { name: "vauth_device_id_index" });
userSchema.index({ created_at: -1 }, { name: "created_at_index" });

// Static method to hash password
userSchema.statics.hashPassword = async function(password) {
  const saltRounds = 12;
  return await bcrypt.hash(password, saltRounds);
};

// Instance method to verify password
userSchema.methods.verifyPassword = async function(password) {
  return await bcrypt.compare(password, this.password_hash);
};

// Static method to create user with encrypted PII
userSchema.statics.createUser = async function(userData) {
  const { name, email, mobile, operating_country, username, password, vauth_device_ID } = userData;

  // Hash password
  const password_hash = await this.hashPassword(password);

  // Encrypt PII data
  const name_enc = encrypt(name);
  const email_enc = encrypt(email);
  const mobile_enc = encrypt(mobile);
  const operating_country_enc = encrypt(operating_country);

  return await this.create({
    username,
    password_hash,
    vauth_device_ID,
    name_enc,
    email_enc,
    mobile_enc,
    operating_country_enc
  });
};

// Instance method to get decrypted user data
userSchema.methods.getDecryptedData = function() {
  return {
    username: this.username,
    vauth_device_ID: this.vauth_device_ID,
    name: decrypt(this.name_enc),
    email: decrypt(this.email_enc),
    mobile: decrypt(this.mobile_enc),
    operating_country: decrypt(this.operating_country_enc),
    created_at: this.created_at
  };
};

// Virtual for getting decrypted name (for display purposes)
userSchema.virtual('name').get(function() {
  return decrypt(this.name_enc);
});

module.exports = mongoose.model('User', userSchema);
// utils/encryption.js
const crypto = require('crypto');

const algorithm = 'aes-256-cbc';
const rawKey = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
const secretKey = crypto.createHash('sha256').update(rawKey).digest();
const ivLength = 16;

function encrypt(text) {
  try {
    const iv = crypto.randomBytes(ivLength);
    const cipher = crypto.createCipheriv(algorithm, secretKey, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
  } catch (err) {
    console.error('Encryption error:', err);
    throw new Error('Failed to encrypt data');
  }
}

function decrypt(text) {
  try {
    const [ivHex, encryptedData] = text.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv(algorithm, secretKey, iv);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (err) {
    console.error('Decryption error:', err);
    throw new Error('Failed to decrypt data');
  }
}

module.exports = { encrypt, decrypt };

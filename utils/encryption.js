const crypto = require('crypto');
require('dotenv').config();

const ALGORITHM = 'aes-256-gcm';
const KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'utf8').slice(0, 32); // Ensure 32 bytes

/**
 * Encrypt text using AES-256-GCM
 * @param {string} text - Text to encrypt
 * @returns {string} - Encrypted text with IV and auth tag (base64 encoded)
 */
function encrypt(text) {
    try {
        if (!text) return '';
        
        const iv = crypto.randomBytes(16); // 128-bit IV
        const cipher = crypto.createCipher('aes-256-cbc', KEY); // Use CBC instead of GCM for compatibility
        
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        // Combine IV and encrypted data
        const combined = Buffer.concat([
            iv,
            Buffer.from(encrypted, 'hex')
        ]);
        
        return combined.toString('base64');
    } catch (error) {
        console.error('Encryption error:', error);
        throw new Error('Failed to encrypt data');
    }
}

/**
 * Decrypt text using AES-256-CBC
 * @param {string} encryptedData - Encrypted text (base64 encoded)
 * @returns {string} - Decrypted text
 */
function decrypt(encryptedData) {
    try {
        if (!encryptedData) return '';
        
        const combined = Buffer.from(encryptedData, 'base64');
        
        // Extract IV and encrypted data
        const iv = combined.slice(0, 16);
        const encrypted = combined.slice(16);
        
        const decipher = crypto.createDecipher('aes-256-cbc', KEY);
        
        let decrypted = decipher.update(encrypted, null, 'utf8');
        decrypted += decipher.final('utf8');
        
        return decrypted;
    } catch (error) {
        console.error('Decryption error:', error);
        throw new Error('Failed to decrypt data');
    }
}

/**
 * Generate a random encryption key
 * @returns {string} - Random 32-byte key in hex format
 */
function generateKey() {
    return crypto.randomBytes(32).toString('hex');
}

module.exports = {
    encrypt,
    decrypt,
    generateKey
};


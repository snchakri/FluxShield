const crypto = require('crypto');

const DEFAULT_AAD = 'waf-v1';

function getMasterKey() {
  const keyBase64 = process.env.APP_LAYER_MASTER_KEY_B64;
  if (!keyBase64) {
    const fallback = crypto.createHash('sha256').update('twilight-dev-master-key').digest();
    return fallback;
  }

  const decoded = Buffer.from(keyBase64, 'base64');
  if (decoded.length !== 32) {
    throw new Error('APP_LAYER_MASTER_KEY_B64 must decode to 32 bytes');
  }
  return decoded;
}

function encryptUtf8(plaintext, aad = DEFAULT_AAD) {
  const masterKey = getMasterKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', masterKey, iv);
  cipher.setAAD(Buffer.from(aad, 'utf8'));

  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    nonce_b64: iv.toString('base64'),
    ciphertext_b64: Buffer.concat([encrypted, authTag]).toString('base64'),
    aad_b64: Buffer.from(aad, 'utf8').toString('base64'),
    algo: 'aes-256-gcm-app-layer',
  };
}

function decryptUtf8(blob) {
  if (!blob || !blob.nonce_b64 || !blob.ciphertext_b64 || !blob.aad_b64) {
    throw new Error('invalid encrypted payload');
  }

  const masterKey = getMasterKey();
  const iv = Buffer.from(blob.nonce_b64, 'base64');
  const cipherAndTag = Buffer.from(blob.ciphertext_b64, 'base64');

  if (cipherAndTag.length < 17) {
    throw new Error('invalid encrypted payload');
  }

  const authTag = cipherAndTag.subarray(cipherAndTag.length - 16);
  const ciphertext = cipherAndTag.subarray(0, cipherAndTag.length - 16);
  const aad = Buffer.from(blob.aad_b64, 'base64');

  const decipher = crypto.createDecipheriv('aes-256-gcm', masterKey, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted.toString('utf8');
}

module.exports = {
  encryptUtf8,
  decryptUtf8,
};

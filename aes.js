const crypto = require("crypto");

function aesEncrypt(text, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-ctr", key, iv);

  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");

  const result = Buffer.concat([iv, Buffer.from(encrypted, "hex")]);

  return result.toString("hex");
}

function aesDecrypt(encrypted, key) {
  const encryptedBuffer = Buffer.from(encrypted, "hex");
  const iv = encryptedBuffer.slice(0, 16);
  const content = encryptedBuffer.slice(16);

  const decipher = crypto.createDecipheriv("aes-256-ctr", key, iv);

  let decrypted = decipher.update(content, "hex", "utf8");
  decrypted += decipher.final("utf8");

  return decrypted;
}

function deriveKey(passphrase, salt) {
  return crypto.pbkdf2Sync(passphrase, salt, 100000, 32, "sha256");
}

module.exports = {
  aesEncrypt,
  aesDecrypt,
  deriveKey,
};

/***
 *
 * For Web Browsers Access
 *
 */

/*

async function aesDecrypt(encrypted, passphrase, salt) {
    // Convert data to byte arrays
    const encryptedBytes = hexToBytes(encrypted);
    const iv = encryptedBytes.slice(0, 16);
    const content = encryptedBytes.slice(16);
    const passphraseBytes = new TextEncoder().encode(passphrase);
    const saltBytes = new TextEncoder().encode(salt);

    // Import the passphrase as a PBKDF2 key
    const baseKey = await window.crypto.subtle.importKey(
        'raw', passphraseBytes, 'PBKDF2', false, ['deriveBits']
    );

    // Derive a 256-bit AES key from the passphrase
    const aesKeyBits = await window.crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: saltBytes, iterations: 100000, hash: 'SHA-256' },
        baseKey, 256
    );

    // Import the AES key bits into a CryptoKey object
    const aesKey = await window.crypto.subtle.importKey(
        'raw', aesKeyBits, { name: 'AES-CTR', length: 256 }, false, ['decrypt']
    );

    // Decrypt the content
    const decryptedBytes = await window.crypto.subtle.decrypt(
        { name: 'AES-CTR', counter: iv, length: 128 },
        aesKey, content
    );

    // Convert decrypted bytes to string
    return new TextDecoder().decode(decryptedBytes);
}

function hexToBytes(hex) {
    return new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}


e.g.

aesDecrypt(encrypted, passphrase, salt).then(decrypted => {
    console.log(decrypted);
}).catch(error => {
    console.error(error);
});

*/

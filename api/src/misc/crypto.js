import { createHmac, createCipheriv, createDecipheriv, randomBytes } from "crypto";
import crypto from 'crypto';

const algorithm = 'aes256';

// Use a fixed key and IV for consistency
const secretKey = crypto.scryptSync('my_secret_password', 'salt', 32); // Use scrypt to derive a key from a password
const iv = Buffer.alloc(16, 0); // Fixed IV (should ideally be random and unique for each encryption)

// Encrypt function
export const encrypt = (text) => {
    const cipher = crypto.createCipheriv(algorithm, secretKey, iv);
    let encrypted = cipher.update(text, 'utf8', 'base64');
    encrypted += cipher.final('base64');

    const encryptedString = `${iv.toString('base64')}:${encrypted}`;
    return encodeURIComponent(encryptedString); // URL-encode the result
};

// Decrypt function
export const decrypt = (encryptedText) => {
    try {
        const decodedText = decodeURIComponent(encryptedText);
        const [ivBase64, encryptedData] = decodedText.split(':');

        // Convert fixed IV to Buffer
        const decipher = crypto.createDecipheriv(algorithm, secretKey, Buffer.from(ivBase64, 'base64'));
        let decrypted = decipher.update(encryptedData, 'base64', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;

    } catch (error) {
        console.error("Decryption failed:", error.message);
        return null; // Or you could throw an error or return a custom message
    }
};

export function generateSalt() {
    return randomBytes(64).toString('hex');
}

export function generateHmac(str, salt) {
    return createHmac("sha256", salt).update(str).digest("base64url");
}

export function encryptStream(plaintext, iv, secret) {
    const buff = Buffer.from(JSON.stringify(plaintext));
    const key = Buffer.from(secret, "base64url");
    const cipher = createCipheriv(algorithm, key, Buffer.from(iv, "base64url"));

    return Buffer.concat([ cipher.update(buff), cipher.final() ])
}

export function decryptStream(ciphertext, iv, secret) {
    const buff = Buffer.from(ciphertext);
    const key = Buffer.from(secret, "base64url");
    const decipher = createDecipheriv(algorithm, key, Buffer.from(iv, "base64url"));

    return Buffer.concat([ decipher.update(buff), decipher.final() ])
}

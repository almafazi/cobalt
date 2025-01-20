// Import library crypto-js
import CryptoJS from 'crypto-js';
// Fungsi untuk encrypt
export const encrypt_string = (text, key, ttlInSeconds) => {// Tambahkan timestamp (waktu saat ini) ke dalam teks
    const timestamp = Date.now();
    const textWithTimestamp = `${timestamp}_*_${ttlInSeconds}_*_${text}`;

    // Enkripsi menggunakan AES dengan key yang diberikan
    const encrypted = CryptoJS.AES.encrypt(textWithTimestamp, key).toString();
    // Encode hasil enkripsi ke Base64 agar aman untuk URL
    return encodeURIComponent(CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(encrypted)));
}

// Fungsi untuk decrypt
export const decrypt_string = (encryptedText, key) => {

    // Decode dari Base64
    const decoded = CryptoJS.enc.Base64.parse(decodeURIComponent(encryptedText)).toString(CryptoJS.enc.Utf8);
    // Dekripsi menggunakan AES dengan key yang diberikan
    const decryptedWithTimestamp = CryptoJS.AES.decrypt(decoded, key).toString(CryptoJS.enc.Utf8);

    // Pisahkan timestamp, TTL, dan teks asli
    const [timestamp, ttlInSeconds, text] = decryptedWithTimestamp.split("_*_");

    // Hitung waktu kedaluwarsa
    const expirationTime = parseInt(timestamp) + parseInt(ttlInSeconds) * 1000; // Konversi ke milidetik
    const currentTime = Date.now();

    // Periksa apakah data sudah kedaluwarsa
    if (currentTime > expirationTime) {
        throw new Error("Link expired and cannot be decrypted.");

    }

    // Jika belum kedaluwarsa, kembalikan teks asli
    return text;
}
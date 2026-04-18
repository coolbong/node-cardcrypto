/**
 * Created by coolbong on 2015. 5. 30..
 */

var ut = require('./util');
var crypto = require('crypto');

/**
 * SEED ECB encryption.
 *
 * No automatic padding is applied.
 *
 * @param {string | Buffer} key 16 bytes (128-bit) SEED key
 * @param {string | Buffer} msg Data to encrypt. Length must be a multiple of 16 bytes
 * @returns {string} Hexadecimal string of the SEED encrypted data
 */
function seed_ecb_encrypt(key, msg) {

    msg = ut.toBuffer(msg);
    key = ut.toBuffer(key);

    if (key.length !== 16) {
        throw Error('key length is invalid. must set to be 16');
    }

    if (msg.length % 16 !== 0) {
        throw Error('Invalid message length, must set to be multiple 16');
    }

    var cipher = crypto.createCipheriv('seed-ecb', key, '');
    cipher.setAutoPadding(false);
    return ut.toHexString(cipher.update(msg));
}

/**
 * SEED ECB decryption.
 *
 * No automatic padding is applied.
 *
 * @param {string | Buffer} key 16 bytes (128-bit) SEED key
 * @param {string | Buffer} msg Data to decrypt. Length must be a multiple of 16 bytes
 * @returns {string} Hexadecimal string of the SEED decrypted data
 */
function seed_ecb_decrypt(key, msg) {

    msg = ut.toBuffer(msg);
    key = ut.toBuffer(key);

    if (key.length !== 16) {
        throw Error('key length is invalid. must set to be 16');
    }

    if (msg.length % 16 !== 0) {
        throw Error('Invalid message length, must set to be multiple 16');
    }

    var decipher = crypto.createDecipheriv('seed-ecb', key, '');
    decipher.setAutoPadding(false);
    return ut.toHexString(decipher.update(msg));
}

/**
 * SEED CBC encryption.
 *
 * No automatic padding is applied.
 *
 * @param {string | Buffer} key 16 bytes (128-bit) SEED key
 * @param {string | Buffer} msg Data to encrypt. Length must be a multiple of 16 bytes
 * @param {string | Buffer} [iv] Initialization Vector (16 bytes). Default is zero-filled Buffer
 * @returns {string} Hexadecimal string of the SEED encrypted data
 */
function seed_cbc_encrypt(key, msg, iv) {

    msg = ut.toBuffer(msg);
    key = ut.toBuffer(key);

    if (key.length !== 16) {
        throw Error('key length is invalid. must set to be 16');
    }

    if (msg.length % 16 !== 0) {
        throw Error('Invalid message length, must set to be multiple 16');
    }
    
    if(iv === undefined){
        iv = Buffer.alloc(16);
        iv.fill(0);
    } else {
        iv = ut.toBuffer(iv);
    }

    if(iv.length !== 16) {
        throw Error('Invalid initialize vector length, must set to 16');
    }

    var cipher = crypto.createCipheriv('seed-cbc', key, iv);
    cipher.setAutoPadding(false);
    return ut.toHexString(cipher.update(msg));
}

/**
 * SEED CBC decryption.
 *
 * No automatic padding is applied.
 *
 * @param {string | Buffer} key 16 bytes (128-bit) SEED key
 * @param {string | Buffer} msg Data to decrypt. Length must be a multiple of 16 bytes
 * @param {string | Buffer} [iv] Initialization Vector (16 bytes). Default is zero-filled Buffer
 * @returns {string} Hexadecimal string of the SEED decrypted data
 */
function seed_cbc_decrypt(key, msg, iv) {
    msg = ut.toBuffer(msg);
    key = ut.toBuffer(key);

    if (key.length !== 16) {
        throw Error('key length is invalid. must set to be 16');
    }

    if (msg.length % 16 !== 0) {
        throw Error('Invalid message length, must set to be multiple 16');
    }

    if(iv === undefined){
        iv = Buffer.alloc(16);
        iv.fill(0);
    } else {
        iv = ut.toBuffer(iv);
    }

    if(iv.length !== 16) {
        throw Error('Invalid initialize vector length, must set to 16');
    }
    var decipher = crypto.createDecipheriv('seed-cbc', key, iv);
    decipher.setAutoPadding(false);
    return ut.toHexString(decipher.update(msg));
}

module.exports = {
    ecb_encrypt: seed_ecb_encrypt,
    ecb_decrypt: seed_ecb_decrypt,
    cbc_encrypt: seed_cbc_encrypt,
    cbc_decrypt: seed_cbc_decrypt
};
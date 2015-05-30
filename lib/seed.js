/**
 * Created by coolbong on 2015. 5. 30..
 */

var crypto = require('crypto');

/**
 *
 * SEED ECB encryption.
 *
 *
 * no padding.
 *
 * @param {Buffer} key 16 byte
 * @param {Buffer} message multiple 16 bytes
 * @returns {Buffer} SEED encrypted data
 */
function seed_ecb_encrypt(key, message) {
    var cipher = crypto.createCipheriv('seed-ecb', key, '');
    cipher.setAutoPadding(false);
    return cipher.update(message);
}

/**
 *
 * SEED CBC decryption.
 *
 *
 * no padding
 *
 * @param {Buffer} key 16 byte
 * @param {Buffer} message multiple 16 bytes
 * @returns {Buffer} SEED decrypt data
 */
function seed_ecb_decrypt(key, message) {
    var decipher = crypto.createDecipheriv('seed-ecb', key, '');
    decipher.setAutoPadding(false);
    return decipher.update(message);
}

/**
 *
 * SEED CBC encryption.
 *
 * no padding.
 *
 * @param {Buffer} key 16 byte
 * @param {Buffer} message multiple 16 bytes
 * @param {Buffer} iv initialize vector
 * @returns {Buffer} SEED encrypted data
 */
function seed_cbc_encrypt(key, message, iv) {
    if(iv === undefined){
        iv = new Buffer(16);
        iv.fill(0);
    }
    var cipher = crypto.createCipheriv('seed-cbc', key, iv);
    cipher.setAutoPadding(false);
    return cipher.update(message);
}

/**
 *
 * SEED CBC decryption.
 *
 *
 * no padding
 *
 * @param {Buffer} key 16 byte
 * @param {Buffer} message multiple 16 bytes
 * @param {Buffer} iv initialize vector
 * @returns {Buffer} SEED decrypt data
 */
function seed_cbc_decrypt(key, message, iv) {
    if(iv === undefined){
        iv = new Buffer(16);
        iv.fill(0);
    }
    var decipher = crypto.createDecipheriv('seed-cbc', key, iv);
    decipher.setAutoPadding(false);
    return decipher.update(message);
}

module.exports = {
    ecb_encrypt: seed_ecb_encrypt,
    ecb_decrypt: seed_ecb_decrypt,
    cbc_encrypt: seed_cbc_encrypt,
    cbc_decrypt: seed_cbc_decrypt
};
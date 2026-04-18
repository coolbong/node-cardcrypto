/**
 * Created by coolbong on 2015. 5. 30..
 */

var ut = require('./util');
var crypto = require('crypto');

/**
 * AES ECB encryption.
 *
 * No automatic padding is applied.
 *
 * @param {string | Buffer} key 16 bytes (AES-128), 24 bytes (AES-192), or 32 bytes (AES-256)
 * @param {string | Buffer} msg Data to encrypt. Length must be a multiple of 16 bytes
 * @returns {string} Hexadecimal string of the AES encrypted data
 */
function aes_ecb_encrypt(key, msg) {
    var cipherType;
    msg = ut.toBuffer(msg);
    key = ut.toBuffer(key);

    if( key.length === 16) {
        //128 bit key aes ecb mode
        cipherType = 'aes-128-ecb';
    } else if( key.length === 24) {
        //192 bit key aes ecb mode
        cipherType = 'aes-192-ecb';
    } else if (key.length === 32) {
        //256 bit key aes ecb mode
        cipherType = 'aes-256-ecb';
    } else {
        throw Error('key length is invalid. must set to be 16, 24, 32');
    }

    if (msg.length % 16 !== 0) {
        throw Error('Invalid message length, must set to be multiple 16');
    }

    var cipher = crypto.createCipheriv(cipherType, key, '');
    cipher.setAutoPadding(false);
    return ut.toHexString(cipher.update(msg));
}

/**
 * AES ECB decryption.
 *
 * No automatic padding is applied.
 *
 * @param {string | Buffer} key 16 bytes (AES-128), 24 bytes (AES-192), or 32 bytes (AES-256)
 * @param {string | Buffer} msg Data to decrypt. Length must be a multiple of 16 bytes
 * @returns {string} Hexadecimal string of the AES decrypted data
 */
function aes_ecb_decrypt(key, msg) {
    var cipherType;

    msg = ut.toBuffer(msg);
    key = ut.toBuffer(key);

    if( key.length === 16) {
        //128 bit key aes ecb mode
        cipherType = 'aes-128-ecb';
    } else if( key.length === 24) {
        //192 bit key aes ecb mode
        cipherType = 'aes-192-ecb';
    } else if (key.length === 32) {
        //256 bit key aes ecb mode
        cipherType = 'aes-256-ecb';
    } else {
        throw Error('key length is invalid. must set to be 16, 24, 32');
    }

    if (msg.length % 16 !== 0) {
        throw Error('Invalid message length, must set to be multiple 16');
    }

    var decipher = crypto.createDecipheriv(cipherType, key, '');
    decipher.setAutoPadding(false);
    return ut.toHexString(decipher.update(msg));
}

/**
 * AES CBC encryption.
 *
 * No automatic padding is applied.
 *
 * @param {string | Buffer} key 16 bytes (AES-128), 24 bytes (AES-192), or 32 bytes (AES-256)
 * @param {string | Buffer} msg Data to encrypt. Length must be a multiple of 16 bytes
 * @param {string | Buffer} [iv] Initialization Vector (16 bytes). Default is zero-filled Buffer
 * @returns {string} Hexadecimal string of the AES encrypted data
 */
function aes_cbc_encrypt(key, msg, iv) {
    var cipherType;

    msg = ut.toBuffer(msg);
    key = ut.toBuffer(key);

    if( key.length === 16) {
        //128 bit key aes cbc mode
        cipherType = 'aes-128-cbc';
    } else if( key.length === 24) {
        //192 bit key aes cbc mode
        cipherType = 'aes-192-cbc';
    } else if (key.length === 32) {
        //256 bit key aes cbc mode
        cipherType = 'aes-256-cbc';
    } else {
        throw Error('key length is invalid. must set to be 16, 24, 32');
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

    var cipher = crypto.createCipheriv(cipherType, key, iv);
    cipher.setAutoPadding(false);
    return ut.toHexString(cipher.update(msg));
}

/**
 * AES CBC decryption.
 *
 * No automatic padding is applied.
 *
 * @param {string | Buffer} key 16 bytes (AES-128), 24 bytes (AES-192), or 32 bytes (AES-256)
 * @param {string | Buffer} msg Data to decrypt. Length must be a multiple of 16 bytes
 * @param {string | Buffer} [iv] Initialization Vector (16 bytes). Default is zero-filled Buffer
 * @returns {string} Hexadecimal string of the AES decrypted data
 */
function aes_cbc_decrypt(key, msg, iv) {
    var cipherType;

    msg = ut.toBuffer(msg);
    key = ut.toBuffer(key);

    if( key.length === 16) {
        //128 bit key aes cbc mode
        cipherType = 'aes-128-cbc';
    } else if( key.length === 24) {
        //192 bit key aes cbc mode
        cipherType = 'aes-192-cbc';
    } else if (key.length === 32) {
        //256 bit key aes cbc mode
        cipherType = 'aes-256-cbc';
    } else {
        throw Error('key length is invalid. must set to be 16, 24, 32');
    }

    if (msg.length % 16 !== 0) {
        throw Error('Invalid message length, must set to be multiple 16');
    }

    if(iv === undefined){
        iv = new Buffer(16);
        iv.fill(0);
    } else {
        iv = ut.toBuffer(iv);
    }

    if(iv.length !== 16) {
        throw Error('Invalid initialize vector length, must set to 16');
    }

    var decipher = crypto.createDecipheriv(cipherType, key, iv);
    decipher.setAutoPadding(false);
    return ut.toHexString(decipher.update(msg));
}

/**
 * AES CTR encryption.
 *
 * No automatic padding is applied.
 *
 * @param {string | Buffer} key 16 bytes (AES-128), 24 bytes (AES-192), or 32 bytes (AES-256)
 * @param {string | Buffer} msg Data to encrypt. Length must be a multiple of 16 bytes
 * @param {string | Buffer} [iv] Initialization Vector (16 bytes). Default is zero-filled Buffer
 * @returns {string} Hexadecimal string of the AES encrypted data
 */
function aes_ctr_encrypt(key, msg, iv) {
    var cipherType;
    msg = ut.toBuffer(msg);
    key = ut.toBuffer(key);

    if( key.length === 16) {
        //128 bit key aes ctr mode
        cipherType = 'aes-128-ctr';
    } else if( key.length === 24) {
        //192 bit key aes ctr mode
        cipherType = 'aes-192-ctr';
    } else if (key.length === 32) {
        //256 bit key aes ctr mode
        cipherType = 'aes-256-ctr'
    } else {
        throw Error('key length is invalid. must set to be 16, 24, 32');
    }

    if (msg.length % 16 !== 0) {
        throw Error('Invalid message length, must set to be multiple 16');
    }

    if(iv === undefined){
        iv = new Buffer(16);
        iv.fill(0);
    } else {
        iv = ut.toBuffer(iv);
    }

    if(iv.length !== 16) {
        throw Error('Invalid initialize vector length, must set to 16');
    }

    var cipher = crypto.createCipheriv(cipherType, key, iv);
    cipher.setAutoPadding(false);
    return ut.toHexString(cipher.update(msg));
}

/**
 * AES CTR decryption.
 *
 * No automatic padding is applied.
 *
 * @param {string | Buffer} key 16 bytes (AES-128), 24 bytes (AES-192), or 32 bytes (AES-256)
 * @param {string | Buffer} msg Data to decrypt. Length must be a multiple of 16 bytes
 * @param {string | Buffer} [iv] Initialization Vector (16 bytes). Default is zero-filled Buffer
 * @returns {string} Hexadecimal string of the AES decrypted data
 */
function aes_ctr_decrypt(key, msg, iv) {
    var cipherType;

    msg = ut.toBuffer(msg);
    key = ut.toBuffer(key);

    if( key.length === 16) {
        //128 bit key aes ctr mode
        cipherType = 'aes-128-ctr';
    } else if( key.length === 24) {
        //192 bit key aes ctr mode
        cipherType = 'aes-192-ctr';
    } else if (key.length === 32) {
        //256 bit key aes ctr mode
        cipherType = 'aes-256-ctr';
    } else {
        throw Error('key length is invalid. must set to be 16, 24, 32');
    }

    if (msg.length % 16 !== 0) {
        throw Error('Invalid message length, must set to be multiple 16');
    }

    if(iv === undefined){
        iv = new Buffer(16);
        iv.fill(0);
    } else {
        iv = ut.toBuffer(iv);
    }

    if(iv.length !== 16) {
        throw Error('Invalid initialize vector length, must set to 16');
    }

    var decipher = crypto.createDecipheriv(cipherType, key, iv);
    decipher.setAutoPadding(false);
    return ut.toHexString(decipher.update(msg));
}

module.exports = {
    ecb_encrypt: aes_ecb_encrypt,
    ecb_decrypt: aes_ecb_decrypt,
    cbc_encrypt: aes_cbc_encrypt,
    cbc_decrypt: aes_cbc_decrypt,
    ctr_encrypt: aes_ctr_encrypt,
    ctr_decrypt: aes_ctr_decrypt
};
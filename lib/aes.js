/**
 * Created by coolbong on 2015. 5. 30..
 */

var crypto = require('crypto');

/**
 *
 * AES ECB encryption.
 *
 *
 * no padding
 *
 * @param {Buffer} key 16 byte(128it), 24 byte(192bit), 32 byte(256bit)
 * @param {Buffer} message multiple 16 bytes
 * @returns {Buffer} AES encrypted data
 */
function aes_ecb_encrypt(key, message) {
    var cipherType = '';
    if( key.length == 16) {
        //128 bit key aes ecb mode
        cipherType = 'aes-128-ecb';
    } else if( key.length == 24) {
        //192 bit key aes ecb mode
        cipherType = 'aes-192-ecb';
    } else if (key.length == 32) {
        //256 bit key aes ecb mode
        cipherType = 'aes-256-ecb';
    } else {
        console.log('key length is invalid. must set to be 16, 24, 32');
        return null;
    }

    var cipher = crypto.createCipheriv(cipherType, key, '');
    cipher.setAutoPadding(false);
    return cipher.update(message);
}

/**
 *
 * AES ECB decryption.
 *
 *
 * no padding
 *
 * @param {Buffer} key 16 byte(128it), 24 byte(192bit), 32 byte(256bit)
 * @param {Buffer} message multiple 16 bytes
 * @returns {Buffer} AES decrypt data
 */
function aes_ecb_decrypt(key, message) {
    var cipherType = '';
    if( key.length == 16) {
        //128 bit key aes ecb mode
        cipherType = 'aes-128-ecb';
    } else if( key.length == 24) {
        //192 bit key aes ecb mode
        cipherType = 'aes-192-ecb';
    } else if (key.length == 32) {
        //256 bit key aes ecb mode
        cipherType = 'aes-256-ecb';
    } else {
        console.log('key length is invalid. must set to be 16, 24, 32');
        return null;
    }
    var decipher = crypto.createDecipheriv(cipherType, key, '');
    decipher.setAutoPadding(false);
    return decipher.update(message);
}

/**
 *
 * AES CBC encryption.
 *
 *
 * no padding
 *
 * @param {Buffer} key 16 byte(128it), 24 byte(192bit), 32 byte(256bit)
 * @param {Buffer} message multiple 16 bytes
 * @param {Buffer} [iv] initialize vector
 * @returns {Buffer} AES encrypted data
 */
function aes_cbc_encrypt(key, message, iv) {
    var cipherType = '';
    if( key.length == 16) {
        //128 bit key aes cbc mode
        cipherType = 'aes-128-cbc';
    } else if( key.length == 24) {
        //192 bit key aes cbc mode
        cipherType = 'aes-192-cbc';
    } else if (key.length == 32) {
        //256 bit key aes cbc mode
        cipherType = 'aes-256-cbc';
    } else {
        console.log('key length is invalid. must set to be 16, 24, 32');
        return null;
    }

    if(iv === undefined){
        iv = new Buffer(16);
        iv.fill(0);
    }

    var cipher = crypto.createCipheriv(cipherType, key, iv);
    cipher.setAutoPadding(false);
    return cipher.update(message);
}

/**
 *
 * AES CBC decryption.
 *
 *
 * no padding
 *
 * @param {Buffer} key 16 byte(128it), 24 byte(192bit), 32 byte(256bit)
 * @param {Buffer} message multiple 16 bytes
 * @param {Buffer} [iv] initialize vector
 * @returns {Buffer} AES decrypt data
 */
function aes_cbc_decrypt(key, message, iv) {
    var cipherType = '';
    if( key.length == 16) {
        //128 bit key aes ecb mode
        cipherType = 'aes-128-cbc';
    } else if( key.length == 24) {
        //192 bit key aes cbc mode
        cipherType = 'aes-192-cbc';
    } else if (key.length == 32) {
        //256 bit key aes cbc mode
        cipherType = 'aes-256-cbc';
    } else {
        console.log('key length is invalid. must set to be 16, 24, 32');
        return null;
    }
    if(iv === undefined){
        iv = new Buffer(16);
        iv.fill(0);
    }
    var decipher = crypto.createDecipheriv(cipherType, key, iv);
    decipher.setAutoPadding(false);
    return decipher.update(message);
}

/**
 *
 * AES CTR encryption.
 *
 *
 * no padding
 *
 * @param {Buffer} key 16 byte(128it), 24 byte(192bit), 32 byte(256bit)
 * @param {Buffer} message multiple 16 bytes
 * @param {Buffer} [iv] initialize vector
 * @returns {Buffer} AES encrypted data
 */
function aes_ctr_encrypt(key, message, iv) {
    var cipherType = '';
    if( key.length == 16) {
        //128 bit key aes ctr mode
        cipherType = 'aes-128-ctr';
    } else if( key.length == 24) {
        //192 bit key aes ctr mode
        cipherType = 'aes-192-ctr';
    } else if (key.length == 32) {
        //256 bit key aes ctr mode
        cipherType = 'aes-256-ctr'
    } else {
        console.log('key length is invalid. must set to be 16, 24, 32');
        return null;
    }

    var cipher = crypto.createCipheriv(cipherType, key, iv);
    cipher.setAutoPadding(false);
    return cipher.update(message);
}

/**
 *
 * AES CBC decryption.
 *
 *
 * no padding
 *
 * @param {Buffer} key 16 byte(128it), 24 byte(192bit), 32 byte(256bit)
 * @param {Buffer} message multiple 16 bytes
 * @param {Buffer} [iv] initialize vector
 * @returns {Buffer} AES decrypt data
 */
function aes_ctr_decrypt(key, message, iv) {
    var cipherType = '';
    if( key.length == 16) {
        //128 bit key aes ctr mode
        cipherType = 'aes-128-ctr';
    } else if( key.length == 24) {
        //192 bit key aes ctr mode
        cipherType = 'aes-192-ctr';
    } else if (key.length == 32) {
        //256 bit key aes ctr mode
        cipherType = 'aes-256-ctr';
    } else {
        console.log('key length is invalid. must set to be 16, 24. 32');
        return null;
    }

    var decipher = crypto.createDecipheriv(cipherType, key, iv);
    decipher.setAutoPadding(false);
    return decipher.update(message);
}

module.exports = {
    ecb_encrypt: aes_ecb_encrypt,
    ecb_decrypt: aes_ecb_decrypt,
    cbc_encrypt: aes_cbc_encrypt,
    cbc_decrypt: aes_cbc_decrypt,
    ctr_encrypt: aes_ctr_encrypt,
    ctr_decrypt: aes_ctr_decrypt
};
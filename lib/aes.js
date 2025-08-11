/**
 * Created by coolbong on 2015. 5. 30..
 */

var ut = require('./util');
var crypto = require('crypto');

/**
 *
 * AES ECB encryption.
 *
 *
 * no padding
 *
 * @param {string | Buffer} key 16 byte(128it), 24 byte(192bit), 32 byte(256bit)
 * @param {string | Buffer} msg multiple 16 bytes
 * @returns {string} AES encrypted data
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
 *
 * AES ECB decryption.
 *
 *
 * no padding
 *
 * @param {string | Buffer} key 16 byte(128it), 24 byte(192bit), 32 byte(256bit)
 * @param {string | Buffer} msg multiple 16 bytes
 * @returns {string} AES decrypt data
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
 *
 * AES CBC encryption.
 *
 *
 * no padding
 *
 * @param {string | Buffer} key 16 byte(128it), 24 byte(192bit), 32 byte(256bit)
 * @param {string | Buffer} msg multiple 16 bytes
 * @param {string | Buffer} [iv] initialize vector
 * @returns {string} AES encrypted data
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
 *
 * AES CBC decryption.
 *
 *
 * no padding
 *
 * @param {string | Buffer} key 16 byte(128it), 24 byte(192bit), 32 byte(256bit)
 * @param {string | Buffer} msg multiple 16 bytes
 * @param {string | Buffer} [iv] initialize vector
 * @returns {string} AES decrypt data
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
 *
 * AES CTR encryption.
 *
 *
 * no padding
 *
 * @param {string | Buffer} key 16 byte(128it), 24 byte(192bit), 32 byte(256bit)
 * @param {string | Buffer} msg multiple 16 bytes
 * @param {string | Buffer} [iv] initialize vector
 * @returns {string} AES encrypted data
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
 *
 * AES CBC decryption.
 *
 *
 * no padding
 *
 * @param {string | Buffer} key 16 byte(128it), 24 byte(192bit), 32 byte(256bit)
 * @param {string | Buffer} msg multiple 16 bytes
 * @param {string | Buffer} [iv] initialize vector
 * @returns {string} AES decrypt data
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
/**
 * Created by coolbong on 2015. 5. 30..
 */

var ut = require('./util');
var crypto = require('crypto');


/**
 *
 * DES ECB encryption.
 *
 * 1 key: DES
 * 2 key: TDES
 * 3 key: TDES
 *
 * no padding
 *
 * @param {string | Buffer} key 8 byte(1 key), 16 byte(2key), 24 byte(3key)
 * @param {string | Buffer} msg multiple 8 bytes
 * @returns {string} des encrypted data
 */
function des_ecb_encrypt(key, msg) {
    var cipherType = '';

    msg = ut.toBuffer(msg);
    key = ut.toBuffer(key);

    if( key.length === 8) {
        //one key des ecb
        cipherType = 'des-ecb';
    } else if( key.length === 16) {
        // Two key triple des ecb
        cipherType = 'des-ede';
    } else if (key.length === 24) {
        //Three key triple des ecb
        cipherType = 'des-ede3'
    } else {
        throw Error('key length is invalid. must set to be 8, 16, 24');
    }

    if (msg.length % 8 != 0) {
        throw Error('Invalid message length, must set to be multiple 8');
    }

    var cipher = crypto.createCipheriv(cipherType, key, '');
    cipher.setAutoPadding(false);
    return ut.toHexString(cipher.update(msg));
}

/**
 *
 * DES ECB decryption.
 *
 * 1 key: DES
 * 2 key: TDES
 * 3 key: TDES
 *
 * no padding
 *
 * @param {string|Buffer} key 8 byte(1 key), 16 byte(2key), 24 byte(3key)
 * @param {string|Buffer} msg multiple 8 bytes
 * @returns {string} DES decrypted data
 */
function des_ecb_decrypt(key, msg) {
    var cipherType = '';

    msg = ut.toBuffer(msg);
    key = ut.toBuffer(key);

    if (key.length === 8) {
        //one key des ecb
        cipherType = 'des-ecb';
    } else if (key.length === 16) {
        // Two key triple des ecb
        cipherType = 'des-ede';
    } else if (key.length === 24) {
        //Three key triple des ecb
        cipherType = 'des-ede3'
    } else {
        throw Error('key length is invalid. must set to be 8, 16, 24');
    }

    if (msg.length % 8 != 0) {
        throw Error('Invalid message length, must set to be multiple 8');
    }

    var decipher = crypto.createDecipheriv(cipherType, key, '');
    decipher.setAutoPadding(false);
    return ut.toHexString(decipher.update(msg));
}

/**
 *
 * DES CBC encryption.
 *
 * 1 key: DES
 * 2 key: TDES
 * 3 key: TDES
 *
 * no padding
 *
 * @param {string|Buffer} key 8 byte(1 key), 16 byte(2key), 24 byte(3key)
 * @param {string|Buffer} msg multiple 8 bytes
 * @param {string|Buffer} [iv] initialize vector
 * @returns {string} DES encrypted data
 */
function des_cbc_encrypt(key, msg, iv) {
    var cipherType;

    msg = ut.toBuffer(msg);
    key = ut.toBuffer(key);

    if( key.length === 8) {
        //one key des cbc
        cipherType = 'des-cbc';
    } else if( key.length === 16) {
        // Two key triple des cbc
        cipherType = 'des-ede-cbc';
    } else if (key.length === 24) {
        //Three key triple des cbc
        cipherType = 'des-ede3-cbc'
    } else {
        throw Error('key length is invalid. must set to be 8, 16, 24');
    }

    if (msg.length % 8 !== 0) {
        throw Error('Invalid message length, must set to be multiple 8');
    }

    if (iv === undefined) {
        iv = new Buffer(8);
        iv.fill(0);
    } else {
        iv = ut.toBuffer(iv);
    }

    if(iv.length !== 8) {
        throw Error('Invalid initialize vector length, must set to 8');
    }

    var cipher = crypto.createCipheriv(cipherType, key, iv);
    cipher.setAutoPadding(false);
    return ut.toHexString(cipher.update(msg));
}

/**
 *
 * DES CBC decryption.
 *
 * 1 key: DES
 * 2 key: TDES
 * 3 key: TDES
 *
 * no padding
 *
 * @param {string | Buffer} key 8 byte(1 key), 16 byte(2key), 24 byte(3key)
 * @param {string | Buffer} msg multiple 8 bytes
 * @param {string | Buffer} [iv] initialize vector
 * @returns {string} DES decrypted data
 */
function des_cbc_decrypt(key, msg, iv) {
    var cipherType;

    msg = ut.toBuffer(msg);
    key = ut.toBuffer(key);

    if( key.length === 8) {
        //one key des cbc
        cipherType = 'des-cbc';
    } else if( key.length === 16) {
        // Two key triple des cbc
        cipherType = 'des-ede-cbc';
    } else if (key.length === 24) {
        //Three key triple des cbc
        cipherType = 'des-ede3-cbc'
    } else {
        throw Error('key length is invalid. must set to be 8, 16, 24');
    }

    if (msg.length % 8 !== 0) {
        throw Error('Invalid message length, must set to be multiple 8');
    }

    if (iv === undefined) {
        iv = new Buffer(8);
        iv.fill(0);
    } else {
        iv = ut.toBuffer(iv);
    }

    if(iv.length !== 8) {
        throw Error('Invalid initialize vector length, must set to 8');
    }

    var decipher = crypto.createDecipheriv(cipherType, key, iv);
    decipher.setAutoPadding(false);
    return ut.toHexString(decipher.update(msg));
}

module.exports = {
    ecb_encrypt: des_ecb_encrypt,
    ecb_decrypt: des_ecb_decrypt,
    cbc_encrypt: des_cbc_encrypt,
    cbc_decrypt: des_cbc_decrypt
};
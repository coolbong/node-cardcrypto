/**
 * Created by coolbong on 2015. 5. 30..
 */


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
 * @param {Buffer} key 8 byte(1 key), 16 byte(2key), 24 byte(3key)
 * @param {Buffer} message multiple 8 bytes
 * @returns {Buffer} des encrypted data
 */
function des_ecb_encrypt(key, message) {
    var cipherType = '';
    if( key.length == 8) {
        //one key des ecb
        cipherType = 'des-ecb';
    } else if( key.length == 16) {
        // Two key triple des ecb
        cipherType = 'des-ede';
    } else if (key.length == 24) {
        //Three key triple des ecb
        cipherType = 'des-ede3'
    } else {
        console.log('key length is invalid. must set to be 8, 16, 24');
        return null;
    }

    var cipher = crypto.createCipheriv(cipherType, key, '');
    cipher.setAutoPadding(false);

    return cipher.update(message);
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
 * @param {Buffer} key 8 byte(1 key), 16 byte(2key), 24 byte(3key)
 * @param {Buffer} message multiple 8 bytes
 * @returns {Buffer} DES decrypted data
 */
function des_ecb_decrypt(key, message) {
    var cipherType = '';
    if (key.length == 8) {
        //one key des ecb
        cipherType = 'des-ecb';
    } else if (key.length == 16) {
        // Two key triple des ecb
        cipherType = 'des-ede';
    } else if (key.length == 24) {
        //Three key triple des ecb
        cipherType = 'des-ede3'
    } else {
        console.log('key length is invalid. must set to be 8, 16, 24');
        return null;
    }
    var decipher = crypto.createDecipheriv(cipherType, key, '');
    decipher.setAutoPadding(false);
    return decipher.update(message);
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
 * @param {Buffer} key 8 byte(1 key), 16 byte(2key), 24 byte(3key)
 * @param {Buffer} message multiple 8 bytes
 * @param {Buffer} [iv] initialize vector
 * @returns {Buffer} DES encrypted data
 */
function des_cbc_encrypt(key, message, iv) {
    var cipherType = '';
    if( key.length == 8) {
        //one key des cbc
        cipherType = 'des-cbc';
    } else if( key.length == 16) {
        // Two key triple des cbc
        cipherType = 'des-ede-cbc';
    } else if (key.length == 24) {
        //Three key triple des cbc
        cipherType = 'des-ede3-cbc'
    } else {
        console.log('key length is invalid. must set to be 8, 16, 24');
        return null;
    }

    if(iv === undefined) {
        iv = new Buffer(8);
        iv.fill(0);
    }

    var cipher = crypto.createCipheriv(cipherType, key, iv);
    cipher.setAutoPadding(false);
    return cipher.update(message);
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
 * @param {Buffer} key 8 byte(1 key), 16 byte(2key), 24 byte(3key)
 * @param {Buffer} message multiple 8 bytes
 * @param {Buffer} [iv] initialize vector
 * @returns {Buffer} DES decrypted data
 */
function des_cbc_decrypt(key, message, iv) {
    var cipherType = '';
    if( key.length == 8) {
        //one key des cbc
        cipherType = 'des-cbc';
    } else if( key.length == 16) {
        // Two key triple des cbc
        cipherType = 'des-ede-cbc';
    } else if (key.length == 24) {
        //Three key triple des cbc
        cipherType = 'des-ede3-cbc'
    } else {
        console.log('key length is invalid. must set to be 8, 16, 24');
        return null;
    }

    if(iv === undefined){
        iv = new Buffer(8);
        iv.fill(0);
    }

    var decipher = crypto.createDecipheriv(cipherType, key, iv);
    decipher.setAutoPadding(false);
    return decipher.update(message);
}

module.exports = {
    ecb_encrypt: des_ecb_encrypt,
    ecb_decrypt: des_ecb_decrypt,
    cbc_encrypt: des_cbc_encrypt,
    cbc_decrypt: des_cbc_decrypt
};
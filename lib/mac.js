/**
 * Created by coolbong on 2015. 5. 31..
 */

var crypto  = require('crypto');
var des     = require('./des');
var aes     = require('./aes');
var padding = require('./padding');
var ut      = require('./util');
var xor     = require('./bitwise').xor;

/**
 * HMAC
 *
 * https://en.wikipedia.org/wiki/Hash-based_message_authentication_code
 *
 * @param {string} type 'sha1', 'sha256', 'md5'
 * @param {string | Buffer} key 'key'
 * @param {string | Buffer} msg
 * @returns {string}
 */
function hmac(type, key, msg) {
    key = ut.toBuffer(key);
    msg = ut.toBuffer(msg);
    var ret = crypto.createHmac(type, key).update(msg).digest();
    return ut.toHexString(ret);
}

/**
 *
 * @param {string | Buffer} key
 * @param {string | Buffer} msg
 * @returns {string}
 */
function hmac_sha1(key, msg) {
    key = ut.toBuffer(key);
    msg = ut.toBuffer(msg);
    var ret = crypto.createHmac('sha1', key).update(msg).digest();
    return ut.toHexString(ret);
}


/**
 *
 * @param {string | Buffer} key
 * @param {string | Buffer} msg
 * @returns {string}
 */
function hmac_sha256(key, msg) {
    key = ut.toBuffer(key);
    msg = ut.toBuffer(msg);
    var ret = crypto.createHmac('sha256', key).update(msg).digest();
    return ut.toHexString(ret);
}

/**
 *
 * @param {string | Buffer} key
 * @param {string | Buffer} msg
 * @returns {string}
 */
function hmac_md5(key, msg) {
    key = ut.toBuffer(key);
    msg = ut.toBuffer(msg);
    var ret = crypto.createHmac('md5', key).update(msg).digest();
    return ut.toHexString(ret);
}

/**
 * Full Triple Des MAC
 * FIPS PUB 113 Computer Data Authentication is a (now obsolete) U.S. government standard that specified the CBC-MAC algorithm using DES as the block cipher.
 * The CBC-MAC algorithm is equivalent to ISO/IEC 9797-1 MAC Algorithm 1.
 * http://en.wikipedia.org/wiki/CBC-MAC
 * http://www.freesoft.org/CIE/RFC/1510/83.htm
 *
 * @param {string | Buffer} key 16 bytes(2 key) or 24 byte(3 key)
 * @param {string | Buffer} msg
 * @param {string | Buffer} [iv] initialize vector
 * @param {string | number} [len] output length
 * @return {string} des mac (default 4 bytes)
 */
function des_mac(key, msg, iv, len) {

    key = ut.toBuffer(key);
    msg = ut.toBuffer(msg);

    len = len || 4;

    var padded = padding.des_padding(msg);
    var result = des.cbc_encrypt(key, padded, iv);

    result = ut.toBuffer(result);
    var mac = result.slice(result.length-len, result.length);

    return ut.toHexString(mac);
}

/**
 * Full Triple Des MAC
 * FIPS PUB 113 Computer Data Authentication is a (now obsolete) U.S. government standard that specified the CBC-MAC algorithm using DES as the block cipher.
 * The CBC-MAC algorithm is equivalent to ISO/IEC 9797-1 MAC Algorithm 3 with method 2(padding) no truncation.
 *
 * Single DES Plus Final Triple DES with the C-MAC
 * This is also known as the Retail MAC. It is as defined in [ISO 9797-1] as MAC Algorithm 2 with output
 * transformation 2, without truncation, and with DES taking the place of the block cipher.
 *
 * http://en.wikipedia.org/wiki/CBC-MAC
 * http://www.freesoft.org/CIE/RFC/1510/83.htm
 *
 * @param {string | Buffer} key 16 byte (2 key)
 * @param {string | Buffer} msg
 * @return {string} mac
 */
function des_mac_algorithm2(key, msg) {

    key = ut.toBuffer(key);
    msg = ut.toBuffer(msg);

    if(key.length !== 16) {
        throw Error('key length is invalid. must set to be 16 byte (2 key)');
    }

    var key1 = key.slice(0, 8);
    var key2 = key.slice(8, 16);
    var padded = padding.des_padding(msg);
    var encryptedData = des.cbc_encrypt(key1, padded);

    // get last block cipher
    encryptedData = ut.toBuffer(encryptedData);
    var hq = encryptedData.slice(encryptedData.length-8, encryptedData.length);

    // transformation 2
    //step 1. E(k', Hq)
    return des.cbc_encrypt(key2, hq);
}


/**
 * Full Triple Des MAC
 * FIPS PUB 113 Computer Data Authentication is a (now obsolete) U.S. government standard that specified the CBC-MAC algorithm using DES as the block cipher.
 * The CBC-MAC algorithm is equivalent to ISO/IEC 9797-1 MAC Algorithm 3 with method 2(padding) no truncation.
 *
 * Single DES Plus Final Triple DES with the C-MAC
 * This is also known as the Retail MAC. It is as defined in [ISO 9797-1] as MAC Algorithm 3 with output
 * transformation 3, without truncation, and with DES taking the place of the block cipher.
 *
 * http://en.wikipedia.org/wiki/CBC-MAC
 * http://www.freesoft.org/CIE/RFC/1510/83.htm
 *
 * @param {string | Buffer} key
 * @param {string | Buffer} data
 * @return {string}
 */
function des_mac_algorithm3(key, data) {

    key = ut.toBuffer(key);
    data = ut.toBuffer(data);

    if(key.length !== 16) {
        throw Error('key length have to be 16 bytes 2key data');
    }

    var key1 = key.slice(0, 8);
    var key2 = key.slice(8, 16);
    var padded = padding.des_padding(data);
    var encryptedData = des.cbc_encrypt(key1, padded);

    // get last block cipher

    //console.log(encryptedData);
    encryptedData = ut.toBuffer(encryptedData);

    var hq = encryptedData.slice(encryptedData.length-8, encryptedData.length);

    // transformation 3
    //step 1. D(k', Hq)
    //step 2. E(K, step 1's result)
    var output = des.cbc_decrypt(key2, hq);
    return des.cbc_encrypt(key1, output);
}


module.exports = {
    hmac: hmac,
    hmac_sha1: hmac_sha1,
    hmac_sha256: hmac_sha256,
    hmac_md5: hmac_md5,
    des_mac: des_mac,
    des_mac_algorithm2: des_mac_algorithm2,
    des_mac_algorithm3: des_mac_algorithm3,
    des_mac_emv: des_mac_algorithm3
};
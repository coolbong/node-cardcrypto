/**
 * Created by coolbong on 2015. 5. 30..
 */

var ut = require('./util');

/**
 * ISO 9797-1 padding method 1.
 *
 * also called 00 padding
 * http://en.wikipedia.org/wiki/ISO/IEC_9797-1
 *
 * @param {string|Buffer} buff source data
 * @param {number} [block_size] optional, default value 8
 * @returns {string} padding data
 */
function ISO9797Method1(buff, block_size) {
    block_size = block_size || 8;
    buff = ut.toBuffer(buff);
    var pad_len = block_size - (buff.length % block_size);

    if(pad_len == block_size) {
        return ut.toHexString(buff);
    }
    var pad = Buffer.alloc(pad_len);
    pad.fill(0);

    return ut.toHexString(Buffer.concat([buff, pad]));
}

/**
 * ISO 9797-1 padding method 2.
 *
 * also called 80 padding
 * http://en.wikipedia.org/wiki/ISO/IEC_9797-1
 *
 * @param {string|Buffer} buff source data
 * @param {number} [block_size] optional, default value 8
 * @returns {string} padding data
 */
function ISO9797Method2(buff, block_size) {
    block_size = block_size || 8;
    buff = ut.toBuffer(buff);
    var pad_len = block_size - (buff.length % block_size);

    var pad = Buffer.alloc(pad_len);
    pad.fill(0);
    pad[0] = 0x80;

    return ut.toHexString(Buffer.concat([buff, pad]));
}

//TODO ISO9797Method 3

/**
 * ISO9797 method 2 (80 padding).
 * block size 8 bytes.
 *
 * @param {string | Buffer} data
 * @return {string}
 */
function des_padding(data) {
    return ISO9797Method2(data, 8);
}

/**
 * ISO9797 method 2 (80 padding).
 * block size 8 bytes.
 *
 * @param {string | Buffer} data
 * @return {string}
 */
function aes_padding(data) {
    return ISO9797Method2(data, 16);
}


/**
 * PKCS #5 padding
 *
 * https://www.ietf.org/rfc/rfc2898.txt
 * 6.1.1.4 padding string 8-(||M|| mod 8)
 *
 * @param {string | Buffer} buff
 * @returns {string}
 */
function pkcs5_padding(buff) {
    return pkcs7_padding(buff, 8);
}

/**
 * PKCS #7 padding
 *
 * https://www.ietf.org/rfc/rfc2315.txt
 * 10.3.2 padding string  k - (l mod k)
 *
 * @param {string | Buffer} buff
 * @param {number} [block_size] optional, default value 8
 * @returns {string}
 */
function pkcs7_padding(buff, block_size) {
    block_size = block_size || 8;
    buff = ut.toBuffer(buff);

    var pad_len = block_size - (buff.length % block_size);

    var pad = Buffer.alloc(pad_len);
    pad.fill(pad.length);
    return ut.toHexString(Buffer.concat([buff, pad]));
}

module.exports = {
    ISO9797Method1: ISO9797Method1,
    ISO9797Method2: ISO9797Method2,
    padding00: ISO9797Method1,
    padding80: ISO9797Method2,
    des_padding: des_padding,
    aes_padding: aes_padding,
    pkcs5_padding: pkcs5_padding,
    pkcs7_padding: pkcs7_padding
};
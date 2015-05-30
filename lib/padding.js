/**
 * Created by coolbong on 2015. 5. 30..
 */


/**
 * ISO 9797-1 padding method 1.
 *
 * also called 00 padding
 * http://en.wikipedia.org/wiki/ISO/IEC_9797-1
 *
 * @param {Buffer} buff source data
 * @param {number} block_size optional, default value 8
 * @returns {Buffer} padding data
 */
function ISO9797Method1(buff, block_size) {
    block_size = block_size || 8;

    var padd_len = block_size - (buff.length % block_size);
    if(padd_len == block_size) {
        return new Buffer(buff);
    }
    var pad = new Buffer(padd_len);
    pad.fill(0);

    return Buffer.concat([buff, pad]);
}

/**
 * ISO 9797-1 padding method 2.
 *
 * also called 80 padding
 * http://en.wikipedia.org/wiki/ISO/IEC_9797-1
 *
 * @param {Buffer} buff source data
 * @param {number} block_size optional, default value 8
 * @returns {Buffer} padding data
 */
function ISO9797Method2(buff, block_size) {
    block_size = block_size || 8;
    var padd_len = block_size - (buff.length % block_size);

    var pad = new Buffer(padd_len);
    pad.fill(0);
    pad[0] = 0x80;

    return Buffer.concat([buff, pad]);
}

//TODO ISO9797Method 3

/**
 * ISO9797 method 2 (80 padding).
 * block size 8 bytes.
 *
 * @param {Buffer} data
 * @return {Buffer}
 */
function des_padding(data) {
    return ISO9797Method2(data, 8);
}

/**
 * ISO9797 method 2 (80 padding).
 * block size 8 bytes.
 *
 * @param {Buffer} data
 * @return {Buffer}
 */
function aes_padding(data) {
    return ISO9797Method2(data, 16);
}

module.exports = {
    ISO9797Method_1: ISO9797Method1,
    ISO9797Method_2: ISO9797Method2,
    padding00: ISO9797Method1,
    padding80: ISO9797Method2,
    des_padding: des_padding,
    aes_padding: aes_padding
};
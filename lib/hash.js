/**
 * Created by coolbong on 2015. 5. 30..
 */

var crypto = require('crypto');

/**
 * HASH.
 *
 * md5 output size: 128 bit (16 byte)
 * sha1 output size: 160 bit (20 byte)
 * sha256 output size: 256 bit (32 byte)
 *
 * @param {String} 'md5', 'sha1', 'sha256'
 * @param {Buffer} message
 * @returns {Buffer} hash buffer
 */
function digest(/* Buffer */hash, /* Buffer */message) {
    return crypto.createHash(hash).update(message).digest();
}

module.exports = {
    digest: digest
};
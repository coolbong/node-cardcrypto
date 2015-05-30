/**
 * Created by coolbong on 2015. 5. 30..
 */

var crypto = require('crypto');

/**
 * HASH.
 *
 *
 *
 * @param {String} hash md5, SHA_1
 * @param {Buffer} message
 * @returns {Buffer} hash buffer
 */
function digest(/* Buffer */hash, /* Buffer */message) {
    return crypto.createHash(hash).update(message).digest();
}

module.exports = {
    digest: digest
};
/**
 * Created by coolbong on 2015. 5. 30..
 */

var ut = require('./util');
var crypto = require('crypto');

/**
 * HASH.
 *
 * md5 output size: 128 bit (16 byte)
 * sha1 output size: 160 bit (20 byte)
 * sha256 output size: 256 bit (32 byte)
 *
 * @param {String} 'md5', 'sha1', 'sha256'
 * @param {string | Buffer} msg
 * @returns {string} hash buffer
 */
function digest(/* String */hash, /* Buffer | string */msg) {
    msg = ut.toBuffer(msg);
    return ut.toHexString(crypto.createHash(hash).update(msg).digest());
}


/**
 *
 * HASH.
 * sha1 output size: 160 bit (20 byte)
 *
 * @param {string | Buffer} msg
 * @returns {string}
 */
function sha1(msg) {
    msg = ut.toBuffer(msg);
    return ut.toHexString(crypto.createHash('sha1').update(msg).digest());
}

/**
 *
 * HASH.
 * md5 output size: 128 bit (16 byte)
 *
 * @param {string | Buffer} msg
 * @returns {string}
 */
function md5(msg) {
    msg = ut.toBuffer(msg);
    return ut.toHexString(crypto.createHash('md5').update(msg).digest());
}


module.exports = {
    md5: md5,
    sha1: sha1,
    digest: digest
};
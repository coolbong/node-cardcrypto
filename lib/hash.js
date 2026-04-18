/**
 * Created by coolbong on 2015. 5. 30..
 */

var ut = require('./util');
var crypto = require('crypto');

/**
 * Dynamic Hashing Function
 *
 * Supports generating hashes for varous algorithms.
 * md5 output size: 128 bit (16 bytes)
 * sha1 output size: 160 bit (20 bytes)
 * sha256 output size: 256 bit (32 bytes)
 *
 * @param {string} hash Hashing algorithm to use (e.g., 'md5', 'sha1', 'sha256')
 * @param {string | Buffer} msg The data to be hashed
 * @returns {string} Hexadecimal string of the final hash digest
 */
function digest(/* String */hash, /* Buffer | string */msg) {
    msg = ut.toBuffer(msg);
    return ut.toHexString(crypto.createHash(hash).update(msg).digest());
}


/**
 * SHA1 Hash
 *
 * Generates a SHA1 hash digest.
 * Output size: 160 bits (20 bytes)
 *
 * @param {string | Buffer} msg The data to be hashed
 * @returns {string} Hexadecimal string of the SHA1 hash digest
 */
function sha1(msg) {
    msg = ut.toBuffer(msg);
    return ut.toHexString(crypto.createHash('sha1').update(msg).digest());
}

/**
 * MD5 Hash
 *
 * Generates an MD5 hash digest.
 * Output size: 128 bits (16 bytes)
 *
 * @param {string | Buffer} msg The data to be hashed
 * @returns {string} Hexadecimal string of the MD5 hash digest
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
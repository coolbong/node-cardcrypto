/**
 * Created by coolbong on 2015. 5. 31..
 */

var ut = require('./util');
var crypto = require('crypto');


/**
 * Random
 *
 * @param {number} length
 * @returns {string} random bytes
 */
function random(/*number*/length) {
    return ut.toHexString(crypto.randomBytes(length));
}

/**
 * Pseudo Random.
 *
 * @param {number} length
 * @returns {Buffer} random bytes
 */
function pseudoRandom(/*number*/ length) {
    return crypto.pseudoRandomBytes(length);
}

module.exports = {
    random: random,
    pseudoRandom: pseudoRandom
};
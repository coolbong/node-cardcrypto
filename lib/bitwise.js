/**
 * Created by coolbong on 2015. 5. 31..
 */

var ut = require('./util');

/**
 *
 * @param {string|Buffer} arr1
 * @param {string|Buffer} arr2
 * @returns {string}
 */
function xor(arr1, arr2) {
    arr1 = ut.toBuffer(arr1);
    arr2 = ut.toBuffer(arr2);

    var ret = [];
    var len = (arr1.length > arr2.length) ? (arr2.length) : (arr1.length);
    for (var i = 0; i < len; i++) {
        ret[i] = arr1[i] ^ arr2[i];
    }

    var result = new Buffer(ret);
    return result.toString('hex').toUpperCase();
}

module.exports = {
    xor: xor
};
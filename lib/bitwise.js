/**
 * Created by coolbong on 2015. 5. 31..
 */


/**
 *
 * @param {Buffer} arr1
 * @param {Buffer} arr2
 * @returns {Buffer}
 */
function xor(arr1, arr2) {
    var ret = [];
    var len = (arr1.length > arr2.length) ? (arr2.length) : (arr1.length);
    for (var i = 0; i < len; i++) {
        ret[i] = arr1[i] ^ arr2[i];
    }

    return new Buffer(ret);
}

module.exports = {
    xor: xor
};
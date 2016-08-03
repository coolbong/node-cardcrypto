/**
 * Created by coolbong on 2015-06-02.
 */
var RSA = require('node-jsbnrsa');

var encrypt = function(modulus, exponent, text) {
    var rsa = new RSA();
    rsa.setPublic(modulus, exponent);
    return rsa.encrypt(text);
};

var decrypt = function(modulus, exponent, encryptedMsg) {
    var rsa = new RSA();
    rsa.setPrivate(modulus, exponent);
    return rsa.decrypt(encryptedMsg);
};

var decryptCrt = function(p, q, dp, dq, qInv, encryptedMsg) {
    var rsa = new RSA();
    rsa.setPrivateCrt(p, q, dp, dq, qInv);
    return rsa.decrypt(encryptedMsg);
};

var getCaPublicKey = function(rid, index) {
    var caKeys = require('../keys/CAKey');
    var strRid = rid;
    if (Buffer.isBuffer(rid)) {
        strRid = rid.toString('hex').toUpperCase();
    }
    return caKeys[strRid][index];
};

module.exports = {
    RSA: RSA,
    encrypt: encrypt,
    decrypt: decrypt,
    decryptCrt: decryptCrt,
    getCaPublicKey: getCaPublicKey
};
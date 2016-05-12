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

var getCaPublickKeyLength = function(rid, caPublicKeyCertificate) {
    var caKeys = require('../keys/CAKey');
    var strRid = rid;

    if (Buffer.isBuffer(rid)) {
        strRid = rid.toString('hex').toUpperCase();
    }
    var keys = caKeys[rid];
    for(var keyIndex in keys) {
        //console.log(tag + ': ' + TLV.getTagName(tag) + ' : ' + records[tag].toHexString());
    }
};

module.exports = {
    RSA: RSA,
    encrypt: encrypt,
    decrypt: decrypt,
    decryptCrt: decryptCrt,
    getCaPublicKey: getCaPublicKey
};


var caPublicKeyInfo = {
    "E": "03",
    "index": "F3",
    "rid": "A000000004",
    "M": "98F0C770F23864C2E766DF02D1E833DFF4FFE92D696E1642F0A88C5694C6479D16DB1537BFE29E4FDC6E6E8AFD1B0EB7EA0124723C333179BF19E93F10658B2F776E829E87DAEDA9C94A8B3382199A350C077977C97AFF08FD11310AC950A72C3CA5002EF513FCCC286E646E3C5387535D509514B3B326E1234F9CB48C36DDD44B416D23654034A66F403BA511C5EFA3",
    "keyLength": 1152,
    "sha1": "A69AC7603DAF566E972DEDC2CB433E07E8B01A9A"
};


function rsa_test() {
    //TAG_90 from SFI 3 record 2
    var issuerPublicKeyCertificate = new Buffer('21EC0FC6E1810DFEEA26545127494B40F5F12FA8670877C4B47516BBCD67EDF5F0652B437B4D3E4E83999E7B8245E2A18A7968E7C3E1C16B5609036E65E0F4AF2C4383AF19F1679DD59726C5D315B21967F5A3E526E645724B61F4C8ABCE98BEB8DF1FD64237DBE356B1F96C73EBA3206AAA4C818518E58E17F0E4265A0A5D7E2196E983C6DA78FC5C73F64E6F3AFF5A', 'hex');
    var caPublickey = new RSA();

    var modulus = new Buffer(caPublicKeyInfo.M, 'hex');
    var exponent = new Buffer(caPublicKeyInfo.E, 'hex');
    caPublickey.setPublic(modulus, exponent);
    

    var issuerPublicKey = caPublickey.encrypt(issuerPublicKeyCertificate);

    console.log('issuer certificate:')
    console.log(issuerPublicKey.toString('hex').toUpperCase());
}

function get_test() {
    var caPublicKey = getCaPublicKey('A000000004', 'F3');
    console.log(caPublicKey);
}

function main() {
    rsa_test();
    get_test();

}

//main();
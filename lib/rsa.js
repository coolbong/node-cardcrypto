/**
 * Created by coolbong on 2015-06-02.
 */
var RSA = require('node-jsbnrsa');

var public_encrypt = function(modulus, exponent, text) {
    var m;
    var e;
    var input;

    if (Buffer.isBuffer(modulus)) {
        m = modulus.toString('hex');
    } else {
        m = modulus;
    }

    if (Buffer.isBuffer(exponent)) {
        e = exponent.toString('hex');
    } else {
        e = exponent;
    }

    if (Buffer.isBuffer(text)) {
        input = text.toString('hex');
    } else {
        input = text;
    }

    var rsa = new RSA();
    rsa.setPublic(m, e);
    var result = rsa.encrypt(input);

    return new Buffer(result, 'hex');
/*
    var rsa = new RSA();
    rsa.setPublic(modulus, exponent);
    var result = rsa.encrypt(text);
    return new Buffer(result, 'hex');
    //console.log(result.toUpperCase());
*/
};

var encrypt = function(modulus, exponent, text) {

    var n;
    var e;
    var t;

    if (Buffer.isBuffer(modulus)) {
        n = modulus;
    } else {
        n = new Buffer(modulus, 'hex');
    }

    if (Buffer.isBuffer(exponent)) {
        e = exponent;
    } else {
        e = new Buffer(exponent, 'hex');
    }

    if (Buffer.isBuffer(text)) {
        t = text;
    } else {
        t = new Buffer(text, 'hex');
    }

    var rsa = new RSA();
    rsa.setPublic(n, e);
    var ret = rsa.encrypt(t);

    return new Buffer(ret, 'hex');
};

var decrypt = function(modulus, exponent, cipher) {
    var n;
    var d;
    var c;

    if (Buffer.isBuffer(modulus)) {
        n = modulus;
    } else {
        n = new Buffer(modulus, 'hex');
    }

    if (Buffer.isBuffer(exponent)) {
        d = exponent;
    } else {
        d = new Buffer(exponent, 'hex');
    }

    if (Buffer.isBuffer(cipher)) {
        c = cipher;
    } else {
        c = new Buffer(cipher, 'hex');
    }

    var rsa = new RSA();
    rsa.setPrivate(n, d);
    var ret = rsa.decrypt(c);

    return new Buffer(ret, 'hex');

};


module.exports = {
    public_encrypt: public_encrypt,
    encrypt: encrypt,
    decrypt: decrypt
};


var caPublicKeyInfo = {
    "E": "03",
    "index": "F3",
    "rid": "A000000004",
    "M": "98F0C770F23864C2E766DF02D1E833DFF4FFE92D696E1642F0A88C5694C6479D16DB1537BFE29E4FDC6E6E8AFD1B0EB7EA0124723C333179BF19E93F10658B2F776E829E87DAEDA9C94A8B3382199A350C077977C97AFF08FD11310AC950A72C3CA5002EF513FCCC286E646E3C5387535D509514B3B326E1234F9CB48C36DDD44B416D23654034A66F403BA511C5EFA3",
    "keyLength": 1152,
    "sha1": "A69AC7603DAF566E972DEDC2CB433E07E8B01A9A"
};


function main() {
    //TAG_90 from SFI 3 record 2
    var issuerPublicKeyCertificate = '21EC0FC6E1810DFEEA26545127494B40F5F12FA8670877C4B47516BBCD67EDF5F0652B437B4D3E4E83999E7B8245E2A18A7968E7C3E1C16B5609036E65E0F4AF2C4383AF19F1679DD59726C5D315B21967F5A3E526E645724B61F4C8ABCE98BEB8DF1FD64237DBE356B1F96C73EBA3206AAA4C818518E58E17F0E4265A0A5D7E2196E983C6DA78FC5C73F64E6F3AFF5A'.toBuffer();
    //var issuerPublicKeyCertificate = '914315BDA0CCFC820718C0225A278C2964B9668C697A4C00451C75A10180B0BD3E2601BDD30D3319DC4006E911E271B7C6AAEE28FA65312BB1F680489CDC9CD311980E156F5841B7C6B0EFE3BD3DAA1C4D9DE235644F461C79DF0336A8C570CA69BAC1EA1570C590178AAC7532934839660F4C8F3B74023DBCD75E655240952AA1E4CB4ECF322749B51B72865B1B28C1000E542E562FF20E0F9FCA28C930831F8FDC06FC7B05E162CB37570E41C65D14'.toBuffer();
    var caPublickey = new RSA();

    var modulus = caPublicKeyInfo.M.toBuffer();
    var exponent = caPublicKeyInfo.E.toBuffer();
    caPublickey.setPublic(modulus, exponent);
    //caPublickey.setOptions({});
    //var data = caPublickey.decrypt(issuerPublicKeyCertificate, false);

    var issuerPublicKey = caPublickey.encrypt(issuerPublicKeyCertificate);

    console.log(issuerPublicKey.toUpperCase());

    public_encrypt(modulus, exponent, issuerPublicKeyCertificate);
}

//main();
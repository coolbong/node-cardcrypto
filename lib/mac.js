/**
 * Created by coolbong on 2015. 5. 31..
 */

var crypto  = require('crypto');
var des     = require('./des');
var aes     = require('./aes');
var padding = require('./padding');

/**
 *
 * @param {String} type 'sha1', 'sha256', 'md5'
 * @param {Buffer} key 'key'
 * @param {Buffer} data
 * @returns {Buffer}
 */
function hmac(type, key, data) {
    return crypto.createHmac(type, key).update(data).digest();
}

/**
 *
 * @param {Buffer} key
 * @param {Buffer} data
 */
function hmac_sha1(key, data) {
    return crypto.createHmac('sha1', key).update(data).digest();
}


/**
 * Full Triple Des MAC
 * FIPS PUB 113 Computer Data Authentication is a (now obsolete) U.S. government standard that specified the CBC-MAC algorithm using DES as the block cipher.
 * The CBC-MAC algorithm is equivalent to ISO/IEC 9797-1 MAC Algorithm 1.
 * http://en.wikipedia.org/wiki/CBC-MAC
 * http://www.freesoft.org/CIE/RFC/1510/83.htm
 *
 * @param {Buffer} key 16 bytes(2 key) or 24 byte(3 key)
 * @param {Buffer} message
 * @param {Buffer} [iv] initialize vector
 * @param {number} [len] output length
 * @return {Buffer} des mac (default 4 bytes)
 */
function des_mac(key, message, iv, len) {
    if(iv === undefined) {
        iv = new Buffer(8);
        iv.fill(0);
    }
    len = len || 8;

    var padded = padding.des_padding(message);
    var result = des.cbc_encrypt(key, padded, iv);
    return result.slice(result.length-len, result.length);
}

/**
 * Full Triple Des MAC
 * FIPS PUB 113 Computer Data Authentication is a (now obsolete) U.S. government standard that specified the CBC-MAC algorithm using DES as the block cipher.
 * The CBC-MAC algorithm is equivalent to ISO/IEC 9797-1 MAC Algorithm 3 with method 2(padding) no truncation.
 *
 * Single DES Plus Final Triple DES with the C-MAC
 * This is also known as the Retail MAC. It is as defined in [ISO 9797-1] as MAC Algorithm 2 with output
 * transformation 2, without truncation, and with DES taking the place of the block cipher.
 *
 * http://en.wikipedia.org/wiki/CBC-MAC
 * http://www.freesoft.org/CIE/RFC/1510/83.htm
 *
 * @param {Buffer} key
 * @param {Buffer} data
 * @return {Buffer}
 */
function des_mac_algorithm2(key, data) {
    if(key.length != 16) {
        console.log('key length have to be 16 bytes 2key data');
    }

    var key1 = key.slice(0, 8);
    var key2 = key.slice(8, 16);
    var padded = padding.des_padding(data);
    var encryptedData = des.cbc_encrypt(key1, padded);

    // get last block cipher
    var hq = encryptedData.slice(encryptedData.length-8, encryptedData.length);

    // transformation 2
    //step 1. E(k', Hq)
    return des.cbc_encrypt(key2, hq);
}


/**
 * Full Triple Des MAC
 * FIPS PUB 113 Computer Data Authentication is a (now obsolete) U.S. government standard that specified the CBC-MAC algorithm using DES as the block cipher.
 * The CBC-MAC algorithm is equivalent to ISO/IEC 9797-1 MAC Algorithm 3 with method 2(padding) no truncation.
 *
 * Single DES Plus Final Triple DES with the C-MAC
 * This is also known as the Retail MAC. It is as defined in [ISO 9797-1] as MAC Algorithm 3 with output
 * transformation 3, without truncation, and with DES taking the place of the block cipher.
 *
 * http://en.wikipedia.org/wiki/CBC-MAC
 * http://www.freesoft.org/CIE/RFC/1510/83.htm
 *
 * @param {Buffer} key
 * @param {Buffer} data
 * @return {Buffer}
 */
function des_mac_algorithm3(key, data) {
    if(key.length != 16) {
        console.log('key length have to be 16 bytes 2key data');
    }

    var key1 = key.slice(0, 8);
    var key2 = key.slice(8, 16);
    var padded = padding.des_padding(data);
    var encryptedData = des.cbc_encrypt(key1, padded);

    // get last block cipher
    var hq = encryptedData.slice(encryptedData.length-8, encryptedData.length);

    // transformation 3
    //step 1. D(k', Hq)
    //step 2. E(K, step 1's result)
    var output = des.cbc_decrypt(key2, hq);
    return des.cbc_encrypt(key1, output);
}

/**
 * http://en.wikipedia.org/wiki/CMAC
 * https://code.google.com/p/impacket/source/browse/trunk/impacket/crypto.py?r=707
 *
 * @param {Buffer} key
 * @param {Buffer} data
 */
function aes_mac(key, data) {
    //http://en.wikipedia.org/wiki/CMAC
    data = padding.aes_padding(data);
    var result = aes.cbc_encrypt(key, data);
    return result.slice(result.length-16, result.length);
}


/**
 *
 * @param key
 * @param data
 * @returns {Buffer}
 */
function aes_cmac(key, data) {
    //RFC 4493 The AES-CMAC algorithm http://www.ietf.org/rfc/rfc4493.txt
    //NIST SP 800-38B The CMAC Mode for Authentication http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf
    if (!(this instanceof aes_cmac)) {
        return new aes_cmac(key, data);
    }

    var const_Bsize = 16;
    var const_zero = new Buffer(16);
    const_zero.fill(0);

    //Step 1. [K1, K2] = generate_subkey(key)
    var keys = this.generate_subkey(key);
    var K1 = keys['K1'];
    var K2 = keys['K2'];

    //Step 2. n = ceil(len/const_Bsize)
    var M = data; //new Buffer(data.length).fill(0);
    var len = M.length;
    var n = Math.ceil(len/const_Bsize);

    //Step 3. if n = 0
    //        then  n = 1; falg = false;
    //        else
    //            if len mod const_Bsize == 0
    //            then flag = true
    //            else flag = false
    var flag; // complete block flag
    if ( n == 0 ){
        n = 1;
        flag = false;
    } else {
        if( len % const_Bsize == 0) {
            flag = true;
        } else {
            //n += 1;
            flag = false
        }
    }

    //Step 4. if flag is true
    //        then M_last = M_n xor K1;
    //        else M_last = aes_padding(M_n) xor K2;
    var offset = (n-1) * const_Bsize;
    var M_n = M.slice(offset);

    var M_last;
    if (flag == true) {
        M_last = xor(M_n, K1);
    } else {
        M_last = xor(padding.aes_padding(M_n), K2);
    }

    //Step 5. X = const_zero
    var X= const_zero;

    var Y;

    //Step 6. for (i=1 i<n-1; i++)
    //            Y = X xor M_i
    //            X = aes-128(K, Y)
    //        Y = M_last xor X
    //        T = AES-128(K, Y)
    var M_i;
    for(var i=0; i<n-1; i++) {
        M_i = M.slice(i * const_Bsize);
        Y = xor(X, M_i);
        X = aes.cbc_encrypt(key, Y);
    }
    Y = xor(M_last, X);
    //Step 7. return T
    return aes.cbc_encrypt(key, Y);
}

aes_cmac.prototype.MSB = function(buf) {
    var tmp ;
    if(buf instanceof Buffer || buf instanceof Array) {
        tmp = buf[0];
    } else {
        tmp = buf;
    }
    return  (tmp & 0x80) ? 1 : 0;
};

aes_cmac.prototype.shift_left_1 = function(buf) {
    var len = buf.length;
    var ret = new Buffer(len);

    for(var i=0; i< len; i++) {
        ret[i]  = buf[i] << 1;
        if( i+1 < buf.length && (this.MSB(buf[i+1]) != 0)) {
            ret[i] |= 0x01;
        }
    }
    return ret;
};



aes_cmac.prototype.generate_subkey = function(K) {

    var const_zero = new Buffer(16);
    const_zero.fill(0);
    var const_Rb = 0x87;
    //var const_zero = new Buffer('00000000000000000000000000000000', 'hex');
    //var const_Rb   = new Buffer('00000000000000000000000000000087', 'hex');

    //Step 1. L = aes-128(K, consta_zero)
    var L = aes.cbc_encrypt(K, const_zero);

    //Step 2. if MSB(L) == 0
    //        then K1 = L << 1
    //        else K1 = (L << 1) XOR const Rb
    var K1 = this.shift_left_1(L);
    if(this.MSB(L) == 1) {
        K1[K1.length-1] ^= const_Rb;
    }

    //Step 3. if MSB(K1) == 0
    //        then K2 = K1 << 1
    //        else K2 = (K1 << 1) XOR const Rb
    var K2 = this.shift_left_1(K1);
    if(this.MSB(K1) == 1) {
        K2[K2.length-1] ^= const_Rb;
    }

    //Step 4. return k1, k2
    return {
        K1: K1,
        K2: K2
    };
};

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
    hmac: hmac,
    hmac_sha1: hmac_sha1,
    des_mac: des_mac,
    des_mac_algorithm2: des_mac_algorithm2,
    des_mac_algorithm3: des_mac_algorithm3,
    des_mac_emv: des_mac_algorithm3,
    aes_mac: aes_mac,
    aes_cmac: aes_cmac
};
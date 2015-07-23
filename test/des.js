/**
 * Created by coolbong on 2015. 5. 31..
 */

var des  = require('../lib/des');
var xor  = require('../lib/bitwise').xor;
var assert = require('assert');

var key1 = new Buffer('7CA110454A1A6E57', 'hex');
var key2 = new Buffer('0131D9619DC1376E', 'hex');
var key3 = new Buffer('9DC1376E0131D961', 'hex');

//7CA110454A1A6E570131D9619DC1376E9DC1376E0131D961
var plain;
var cipher;
var result;
var iv;

// Create three single DES keys, a double DES key and a triple DES key
var deskey1 = key1;
var deskey2 = key2;
var deskey3 = key3;

var des2key = Buffer.concat([key1, key2]);
var des3key = Buffer.concat([key1, key2, key3]);


exports.des = {
    'single des ecb mode' : {
        'single DES ECB Encrypt' : function() {
            // Single DES ECB encrypt
            plain = new Buffer('01A1D6D039776742', 'hex');
            cipher = new Buffer('690F5B0D9A26939B', 'hex');
            result = des.ecb_encrypt(deskey1, plain);
            //console.log('result: ' + result.toString('hex').toUpperCase());
            assert(result.toString('hex') ==  cipher.toString('hex'));
        },
        'single DES ECB Decrypt' : function() {
            // Single DES ECB decrypt
            plain = new Buffer('01A1D6D039776742', 'hex');
            result = des.ecb_decrypt(deskey1, cipher);

            assert(result.toString('hex') == plain.toString('hex'));
        },
        'single block' : function() {
            var key = new Buffer('4041424344454647', 'hex');
            var text = new Buffer('ABCDEFGH', 'ascii');
            var cipher = new Buffer('9DF73E6786F342CD', 'hex');

            var result = des.ecb_encrypt(key, text);
            assert(result.toString('hex') == cipher.toString('hex'));
        },
        'multiple block' : function() {
            var key = new Buffer('4041424344454647', 'hex');
            var text = new Buffer('ABCDEFGHabcdefgh', 'ascii');
            var cipher = new Buffer('9DF73E6786F342CDAC43F7565CCE42ED', 'hex');

            var result = des.ecb_encrypt(key, text);
            //console.log(result.toString('hex').toUpperCase());
            assert(result.toString('hex') == cipher.toString('hex'));
        }
    },
    'two key triple des ecb mode' : {
        'single block 1': function () {
            plain = new Buffer('01A1D6D039776742', 'hex');
            cipher = plain;
            cipher = des.ecb_encrypt(deskey1, cipher);
            cipher = des.ecb_decrypt(deskey2, cipher);
            cipher = des.ecb_encrypt(deskey1, cipher);

            result = des.ecb_encrypt(des2key, plain);
            assert(result.toString('hex') == cipher.toString('hex'));

            cipher = new Buffer('B76FAB4FBDBDB767', 'hex');
            assert(result.toString('hex') == cipher.toString('hex'));
        },
        'single block 2' : function () {
            var key = new Buffer('505152535455565758595A5B5C5D5E5F', 'hex');
            var key1 = new Buffer('5051525354555657', 'hex');
            var key2 = new Buffer('58595A5B5C5D5E5F', 'hex');
            plain = new Buffer('20141027', 'ascii');
            //console.log(plain.toString('hex'));
            cipher = plain;

            cipher = des.ecb_encrypt(key1, cipher);
            cipher = des.ecb_decrypt(key2, cipher);
            cipher = des.ecb_encrypt(key1, cipher);

            result = des.ecb_encrypt(key, plain);

            assert(result.toString('hex') ==  cipher.toString('hex'));

            cipher = new Buffer('6281A3389E1204EA', 'hex');
            assert(result.toString('hex') ==  cipher.toString('hex'));
        },
        'single block 3' : function() {
            var key = new Buffer('404142434445464748494A4B4C4D4E4F', 'hex');
            var text = new Buffer('01A1D6D039776742', 'hex');
            var cipher = new Buffer('245D11F97B8463ED', 'hex');

            var result = des.ecb_encrypt(key, text);
            assert(result.toString('hex') == cipher.toString('hex'));
        },
        'multiple block: 2 block' : function() {
            var key = new Buffer('404142434445464748494A4B4C4D4E4F', 'hex');
            var text = new Buffer('0101005A000000000000000000000000', 'hex');
            var cipher = new Buffer('6280A1DD2F7E930153F8C39D105381B0', 'hex');

            var result = des.ecb_encrypt(key, text);
            //assert(result.toString('hex') == cipher.toString('hex'));
        }

    },
    'three key triple des ecb mode' : function() {
        plain = new Buffer('01A1D6D039776742', 'hex');
        cipher = plain;
        cipher = des.ecb_encrypt(deskey1, cipher);
        cipher = des.ecb_decrypt(deskey2, cipher);
        cipher = des.ecb_encrypt(deskey3, cipher);

        result = des.ecb_encrypt(des3key, plain);
        assert(result.toString('hex') ==  cipher.toString('hex'));
    },
    'single des cbc encrypt 1' : function() {
        // Single DES CBC encrypt
        plain = new Buffer('01A1D6D0397767423977674201A1D6D0', 'hex');
        iv = new Buffer('59D9839733B8455D', 'hex');

        cipher = new Buffer('3A5A2EEFE27ACE7B038F50F35BD7678E', 'hex');

        result = des.cbc_encrypt(deskey1, plain, iv);
        assert(result.toString('hex') == cipher.toString('hex'));
    },
    'single des cbc encrypt 2' : function() {
        plain = new Buffer('00010203040506070809800000000000', 'hex');

        iv = new Buffer('0000000000000000', 'hex');
        key1 = new Buffer('4041424344454647', 'hex');

        result = des.cbc_encrypt(key1, plain, iv);
        //console.log(result.toString('hex').toUpperCase());
    },
    'single des cbc encrypt 3' : function() {
        // Single DES CBC encrypt
        plain = new Buffer('01A1D6D0397767423977674201A1D6D0', 'hex');
        iv = new Buffer('59D9839733B8455D', 'hex');
        var v;

        v = plain.slice(0, 8);
        v = xor(v, iv);
        v = des.ecb_encrypt(deskey1, v);
        cipher = v;

        v = plain.slice(8, 16);
        v = xor(cipher, v);
        v = des.ecb_encrypt(deskey1, v);

        cipher = Buffer.concat([cipher, v]);

        result = des.cbc_encrypt(deskey1, plain, iv);
        assert(result.toString('hex') == cipher.toString('hex'));
        //console.log(result.toString('hex').toUpperCase());

        result = des.cbc_decrypt(deskey1, cipher, iv);
        assert(result.toString('hex') == plain.toString('hex'));
    },
    'single des cbc decrypt': function() {
        plain = new Buffer('01A1D6D0397767423977674201A1D6D0', 'hex');
        iv = new Buffer('59D9839733B8455D', 'hex');

    }

};
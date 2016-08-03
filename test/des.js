/**
 * Created by coolbong on 2015. 5. 31..
 */

var des  = require('../lib/des');
var xor  = require('../lib/bitwise').xor;
var assert = require('assert');

var key1 = '7CA110454A1A6E57';
var key2 = '0131D9619DC1376E';
var key3 = '9DC1376E0131D961';

//7CA110454A1A6E570131D9619DC1376E9DC1376E0131D961
var plain;
var cipher;
var result;

// Create three single DES keys, a double DES key and a triple DES key
var deskey1 = key1;
var deskey2 = key2;
var deskey3 = key3;

var des2key = key1 + key2;
var des3key = key1 + key2 +  key3;


exports.des = {
    'single des ecb mode' : {
        'single DES ECB Encrypt' : function() {
            // Single DES ECB encrypt
            plain = '01A1D6D039776742';
            cipher = '690F5B0D9A26939B';
            result = des.ecb_encrypt(deskey1, plain);
            assert(result === cipher);
        },
        'single DES ECB Decrypt' : function() {
            // Single DES ECB decrypt
            plain = '01A1D6D039776742';
            result = des.ecb_decrypt(deskey1, cipher);

            assert(result === plain);
        },
        'single block' : function() {
            var key = '4041424344454647';
            var plain = new Buffer('ABCDEFGH', 'ascii');
            plain = plain.toString('hex');
            var cipher = '9DF73E6786F342CD';

            var result = des.ecb_encrypt(key, plain);
            assert(result === cipher);
        },
        'multiple block' : function() {
            var key = '4041424344454647';
            var plain = new Buffer('ABCDEFGHabcdefgh', 'ascii');
            plain = plain.toString('hex');

            var cipher = '9DF73E6786F342CDAC43F7565CCE42ED';

            var result = des.ecb_encrypt(key, plain);
            assert(result === cipher);
        }
    },
    'two key triple des ecb mode' : {
        'single block 1': function () {
            var plain = '01A1D6D039776742';
            cipher = plain;
            cipher = des.ecb_encrypt(deskey1, cipher);
            cipher = des.ecb_decrypt(deskey2, cipher);
            cipher = des.ecb_encrypt(deskey1, cipher);

            result = des.ecb_encrypt(des2key, plain);
            assert(result === cipher);

            cipher = 'B76FAB4FBDBDB767';
            assert(result === cipher);
        },
        'single block 2' : function () {
            var key = '505152535455565758595A5B5C5D5E5F';
            var key1 = '5051525354555657';
            var key2 = '58595A5B5C5D5E5F';
            var plain = new Buffer('20141027', 'ascii');
            plain = plain.toString('hex');

            cipher = plain;

            cipher = des.ecb_encrypt(key1, cipher);
            cipher = des.ecb_decrypt(key2, cipher);
            cipher = des.ecb_encrypt(key1, cipher);

            result = des.ecb_encrypt(key, plain);

            assert(result === cipher);

            cipher = '6281A3389E1204EA';
            assert(result === cipher);
        },
        'single block 3' : function() {
            var key = '404142434445464748494A4B4C4D4E4F';
            var text = '01A1D6D039776742';
            var cipher = '245D11F97B8463ED';

            var result = des.ecb_encrypt(key, text);
            assert(result === cipher);
        },
        'multiple block: 2 block' : function() {
            var key    = '404142434445464748494A4B4C4D4E4F';
            var text   = '0101005A000000000000000000000000';
            var cipher = '6280A1DD2F7E93018BAF473F2F8FD094';

            var result = des.ecb_encrypt(key, text);
            assert(result === cipher);
        }

    },
    'three key triple des ecb mode' :  {
        'single block 1': function() {
            var plain = '01A1D6D039776742';
            cipher = plain;
            cipher = des.ecb_encrypt(deskey1, cipher);
            cipher = des.ecb_decrypt(deskey2, cipher);
            cipher = des.ecb_encrypt(deskey3, cipher);

            var result = des.ecb_encrypt(des3key, plain);
            assert(result === cipher);
        },
        'single block 2' : function() {
            var key = '505152535455565758595A5B5C5D5E5F4041424344454647';
            var key1 = '5051525354555657';
            var key2 = '58595A5B5C5D5E5F';
            var key3 = '4041424344454647';
            var plain = '0102030405060708';
            cipher = plain;

            cipher = des.ecb_encrypt(key1, cipher);
            cipher = des.ecb_decrypt(key2, cipher);
            cipher = des.ecb_encrypt(key3, cipher);

            result = des.ecb_encrypt(key, plain);
            assert(result === cipher);
        },
        'single block 3' : function() {
            var key = '404142434445464748494A4B4C4D4E4F5051525354555657';
            var text = '01A1D6D039776742';
            var cipher = '22AB55A538375963';

            var result = des.ecb_encrypt(key, text);
            assert(result === cipher);
        },
        'multiple block 1: 2 block' : function() {
            var key = '404142434445464748494A4B4C4D4E4F5051525354555657';
            var text = '0101005A000000000000000000000000';
            var cipher = '805619622A69C6F3B4692BCB67460309';

            var result = des.ecb_encrypt(key, text);
            assert(result === cipher);
        }

    },

    'single des cbc encrypt' : {
        'single block 1': function() {

        },
        'single block 2': function () {
            var key = '4041424344454647';
            var text = new Buffer('ABCDEFGH', 'ascii');
            text = text.toString('hex');
            var iv = '0000000000000000';

            var cipher = '9DF73E6786F342CD';

            var result = des.cbc_encrypt(key, text, iv);
            assert(result === cipher);
        },
        'single block 3': function () {

        },
        'multiple block 1: 2 block' : function() {
            var key = '404142434445464748494A4B4C4D4E4F';
            var text = '0101005A000000000000000000000000';
            var iv = '0000000000000000';
            var cipher = '6280A1DD2F7E930153F8C39D105381B0';

            var result = des.cbc_encrypt(key, text, iv);
            assert(result === cipher);
        },

        'multiple block 1: 2 block without iv' : function() {
            var key = '404142434445464748494A4B4C4D4E4F';
            var text = '0101005A000000000000000000000000';
            var cipher = '6280A1DD2F7E930153F8C39D105381B0';

            var result = des.cbc_encrypt(key, text);
            assert(result === cipher);
        },
        'multiple block 2: 2 block' : function() {
            var plain = '01A1D6D0397767423977674201A1D6D0';
            var iv = '59D9839733B8455D';
            var cipher = '3A5A2EEFE27ACE7B038F50F35BD7678E';

            result = des.cbc_encrypt(deskey1, plain, iv);
            assert(result == cipher);
        }
    }
    ,
    'single des cbc encrypt 2' : function() {
        //plain = new Buffer('00010203040506070809800000000000', 'hex');
        var plain = '00 00 00 00 00 00 00 00';

        var iv = '0000000000000000';
        var key1 = '4041424344454647';
        var cipher = '4FB92328C50AEAD3';

        result = des.cbc_encrypt(key1, plain, iv);
        //console.log(result.toString('hex').toUpperCase());

        assert(result === cipher);
    },
    'single des cbc encrypt 3' : function() {
        // Single DES CBC encrypt

        var plain1 = '01A1D6D039776742';
        var plain2 = '3977674201A1D6D0';
        var plain = plain1 + plain2;
        var iv = '59D9839733B8455D';
        var v;

        v = plain1;
        v = xor(v, iv);
        v = des.ecb_encrypt(deskey1, v);
        cipher = v;

        v = plain2;
        v = xor(cipher, v);
        v = des.ecb_encrypt(deskey1, v);

        //cipher = Buffer.concat([cipher, v]);
        cipher = cipher + v;

        result = des.cbc_encrypt(deskey1, plain, iv);
        assert(result === cipher);
        //console.log(result.toString('hex').toUpperCase());

        result = des.cbc_decrypt(deskey1, cipher, iv);
        assert(result === plain);
    },
    'single des cbc decrypt': function() {

    }

};
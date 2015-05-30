/**
 * Created by coolbong on 2015. 5. 31..
 */

var aes  = require('../lib/aes');
var assert = require('assert');




exports.aes = {
    'AES ECB' : {
        'aes ecb 128bit': function () {

            var key = new Buffer('000102030405060708090A0B0C0D0E0F', 'hex');
            var plain = new Buffer('00112233445566778899AABBCCDDEEFF', 'hex');
            var cipher = new Buffer('69C4E0D86A7B0430D8CDB78070B4C55A', 'hex');

            var result = aes.ecb_encrypt(key, plain);
            assert(result.toString('hex') == cipher.toString('hex'));

            result = aes.ecb_decrypt(key, cipher);
            assert(result.toString('hex') == plain.toString('hex'));
        },
        'aes ecb 192bit': function () {
            var key = new Buffer('000102030405060708090A0B0C0D0E0F1011121314151617', 'hex');
            var plain = new Buffer('00112233445566778899AABBCCDDEEFF', 'hex');
            var cipher = new Buffer('DDA97CA4864CDFE06EAF70A0EC0D7191', 'hex');

            var result = aes.ecb_encrypt(key, plain);
            assert(result.toString('hex') == cipher.toString('hex'));

            result = aes.ecb_decrypt(key, cipher);
            assert(result.toString('hex') == plain.toString('hex'));
        },
        'aes ecb 256bit':  function() {
            var key = new Buffer('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F', 'hex');
            var plain = new Buffer('00112233445566778899AABBCCDDEEFF', 'hex');
            var cipher = new Buffer('8EA2B7CA516745BFEAFC49904B496089', 'hex');

            var result = aes.ecb_encrypt(key, plain);
            assert(result.toString('hex') == cipher.toString('hex'));

            result = aes.ecb_decrypt(key, cipher);
            assert(result.toString('hex') == plain.toString('hex'));
        }
    },
    'AES CBC' :  function() {
        var key = new Buffer('AB94FDECF2674FDFB9B391F85D7F76F2', 'hex');
        var plain = new Buffer('781723860C06C2264608F919887022120B795240CB7049B01C19B33E32804F0B', 'hex');
        var cipher = new Buffer('0E5C908F68BA1B2C2DCAFD5D8D6B23E5CC262CBBE26BBD4478580C8DF7EC8D48', 'hex');

        var result = aes.cbc_encrypt(key, plain);
        assert(result.toString('hex') == cipher.toString('hex'));
    },

    'AES CRT' : function() {
        var key = new Buffer('2B7E151628AED2A6ABF7158809CF4F3C', 'hex');
        var plain = new Buffer('6BC1BEE22E409F96E93D7E117393172A', 'hex');
        var cipher = new Buffer('874D6191B620E3261BEF6864990DB6CE', 'hex');
        var iv = new Buffer('F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF', 'hex');

        var result = aes.ctr_encrypt(key, plain, iv);
        assert(result.toString('hex') == cipher.toString('hex'));

        result = aes.ctr_decrypt(key, cipher, iv);
        assert(result.toString('hex') == plain.toString('hex'));

        // Decrypt and encrypt same in CTR mode
        result = aes.ctr_encrypt(key, cipher, iv);
        assert(result.toString('hex') == plain.toString('hex'));
    }
};
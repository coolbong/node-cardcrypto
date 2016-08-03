/**
 * Created by coolbong on 2015. 5. 31..
 */

var aes  = require('../lib/aes');
var assert = require('assert');




exports.aes = {
    'AES ECB' : {
        'aes ecb 128bit': function () {

            var key = '000102030405060708090A0B0C0D0E0F';
            var plain = '00112233445566778899AABBCCDDEEFF';
            var cipher = '69C4E0D86A7B0430D8CDB78070B4C55A';

            var result = aes.ecb_encrypt(key, plain);
            assert(result === cipher);

            result = aes.ecb_decrypt(key, cipher);
            assert(result === plain);
        },
        'aes ecb 192bit': function () {
            var key = '000102030405060708090A0B0C0D0E0F1011121314151617';
            var plain = '00112233445566778899AABBCCDDEEFF';
            var cipher = 'DDA97CA4864CDFE06EAF70A0EC0D7191';

            var result = aes.ecb_encrypt(key, plain);
            assert(result === cipher);

            result = aes.ecb_decrypt(key, cipher);
            assert(result === plain);
        },
        'aes ecb 256bit':  function() {
            var key = '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F';
            var plain = '00112233445566778899AABBCCDDEEFF';
            var cipher = '8EA2B7CA516745BFEAFC49904B496089';

            var result = aes.ecb_encrypt(key, plain);
            assert(result === cipher);

            result = aes.ecb_decrypt(key, cipher);
            assert(result === plain);
        }
    },
    'AES CBC' :  function() {
        var key = 'AB94FDECF2674FDFB9B391F85D7F76F2';
        var plain = '781723860C06C2264608F919887022120B795240CB7049B01C19B33E32804F0B';
        var cipher = '0E5C908F68BA1B2C2DCAFD5D8D6B23E5CC262CBBE26BBD4478580C8DF7EC8D48';

        var result = aes.cbc_encrypt(key, plain);
        assert(result === cipher);
    },

    'AES CRT' : function() {
        var key = '2B7E151628AED2A6ABF7158809CF4F3C';
        var plain = '6BC1BEE22E409F96E93D7E117393172A';
        var cipher = '874D6191B620E3261BEF6864990DB6CE';
        var iv = 'F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF';

        var result = aes.ctr_encrypt(key, plain, iv);
        assert(result === cipher);

        result = aes.ctr_decrypt(key, cipher, iv);
        assert(result === plain);

        // Decrypt and encrypt same in CTR mode
        result = aes.ctr_encrypt(key, cipher, iv);
        assert(result === plain);
    }
};
/**
 * Created by coolbong on 2014-12-29.
 */

var seed  = require('../lib/seed');
var padding = require('../lib/padding');
var assert = require('assert');

var key;
var message;
var answer;
var result;
var iv;

exports.seed = {
    'seed': {
        'seed ecb encrypt': function () {
            message = '000102030405060708090A0B0C0D0E0F';
            answer  = '5EBAC6E0054E166819AFF1CC6D346CDB';
            key     = '00000000000000000000000000000000';

            result = seed.ecb_encrypt(key, message);
            assert(answer === result);
        },
        'seed ecb decrypt' : function() {
            message = '5EBAC6E0054E166819AFF1CC6D346CDB';
            answer  = '000102030405060708090A0B0C0D0E0F';
            key     = '00000000000000000000000000000000';
            result = seed.ecb_decrypt(key, message);

            assert(answer === result);
        },
        'seed cbc encrypt': function() {
            message = '000102030405060708090A0B0C0D0E0F';
            iv      = '268D66A735A81A816FBAD9FA36162501';
            key     = '88E34F8F081779F1E9F394370AD40589';

            answer = '75DDA4B065FF86427D448C5403D35A07';
            result = seed.cbc_encrypt(key, message, iv);

            assert(answer === result);
        },
        'seed cbc decrypt' : function() {
            message = '75DDA4B065FF86427D448C5403D35A07';
            iv      = '268D66A735A81A816FBAD9FA36162501';
            key     = '88E34F8F081779F1E9F394370AD40589';

            answer = '000102030405060708090A0B0C0D0E0F';

            result = seed.cbc_decrypt(key, message, iv);
            assert(answer === result);
        },
        'seed ecb encrypt with 80 padding': function() {
            message = '12340000010000';
            key     = '404142434445464748494A4B4C4D4E4F';

            answer = '6C71E60DEF884C34C810904297B44F3C';
            message = padding.ISO9797Method2(message, 16);
            result = seed.ecb_encrypt(key, message);

            assert(answer === result);

        },
        'seed cbc encrypt with 80 padding' : function() {
            message = '12340000010000';
            key     = '404142434445464748494A4B4C4D4E4F';

            answer = '6C71E60DEF884C34C810904297B44F3C';
            message = padding.ISO9797Method2(message, 16);
            result = seed.cbc_encrypt(key, message);

            assert(answer === result);
        }
    }
};


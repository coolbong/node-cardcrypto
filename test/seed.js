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
            message = new Buffer('000102030405060708090A0B0C0D0E0F', 'hex');
            answer  = new Buffer('5EBAC6E0054E166819AFF1CC6D346CDB', 'hex');
            key     = new Buffer('00000000000000000000000000000000', 'hex');

            result = seed.ecb_encrypt(key, message);
            assert(answer.toString('hex') == result.toString('hex'));
        },
        'seed ecb decrypt' : function() {
            message = new Buffer('5EBAC6E0054E166819AFF1CC6D346CDB', 'hex');
            answer  = new Buffer('000102030405060708090A0B0C0D0E0F', 'hex');
            key     = new Buffer('00000000000000000000000000000000', 'hex');
            result = seed.ecb_decrypt(key, message);

            assert(answer.toString('hex') == result.toString('hex'));
        },
        'seed cbc encrypt': function() {
            message = new Buffer('000102030405060708090A0B0C0D0E0F', 'hex');
            iv      = new Buffer('268D66A735A81A816FBAD9FA36162501', 'hex');
            key     = new Buffer('88E34F8F081779F1E9F394370AD40589', 'hex');

            answer = new Buffer('75DDA4B065FF86427D448C5403D35A07', 'hex');
            result = seed.cbc_encrypt(key, message, iv);

            assert(answer.toString('hex') == result.toString('hex'));
        },
        'seed cbc decrypt' : function() {
            message = new Buffer('75DDA4B065FF86427D448C5403D35A07', 'hex');
            iv      = new Buffer('268D66A735A81A816FBAD9FA36162501', 'hex');
            key     = new Buffer('88E34F8F081779F1E9F394370AD40589', 'hex');

            answer = new Buffer('000102030405060708090A0B0C0D0E0F', 'hex');

            result = seed.cbc_decrypt(key, message, iv);
            assert(answer.toString('hex') == result.toString('hex'));
        },
        'seed ecb encrypt with 80 padding': function() {
            /*
             40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F
             12 34 00 00 01 00 00 80 00 00 00 00 00 00 00 00
             6C 71 E6 0D EF 88 4C 34 C8 10 90 42 97 B4 4F 3C
             12 34 00 00 01 00 00 80 00 00 00 00 00 00 00 00
             */

            message = new Buffer('12340000010000', 'hex');
            key     = new Buffer('404142434445464748494A4B4C4D4E4F', 'hex');

            answer = new Buffer('6C71E60DEF884C34C810904297B44F3C', 'hex');
            message = padding.ISO9797Method2(message, 16);
            result = seed.ecb_encrypt(key, message);

            //console.log('seed ecb: ' + result.toString('hex').toUpperCase());
            assert(answer.toString('hex') == result.toString('hex'));

        },
        'seed cbc encrypt with 80 padding' : function() {
            message = new Buffer('12340000010000', 'hex');
            key     = new Buffer('404142434445464748494A4B4C4D4E4F', 'hex');

            answer = new Buffer('6C71E60DEF884C34C810904297B44F3C', 'hex');
            message = padding.ISO9797Method2(message, 16);
            result = seed.cbc_encrypt(key, message);

            //console.log('seed cbc: ' + result.toString('hex').toUpperCase());
            assert(answer.toString('hex') == result.toString('hex'));
        }
    }
};


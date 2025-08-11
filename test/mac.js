/**
 * Created by coolbong on 2015. 5. 31..
 */

var mac = require('../lib/mac');
var des = require('../lib/des');
var padding = require('../lib/padding');

var assert = require('assert');

exports.mac = {


    'des mac algorithm 3' : function() {
        var text = '84820000105565124D57758ED6';
        var key = '81511A453242319321F22FE2C4D206EC';

        var answer = '1CAB9A384188C9B9';
        var result = mac.des_mac_algorithm3(key,  text);

        assert(answer === result);
    },
    'des mac emv' : function() {
        var text = '84DA00C50B 0002 F84327D38D6549AE 000008';
        var key = '876C6B3D4211C448FB00485B5761995D';
        var answer = 'B0AA8344E3B8018A';
        var result = mac.des_mac_emv(key, text);

        assert(answer === result);
    },
    'hmac' : function() {
        var msg = Buffer.from('The quick brown fox jumps over the lazy dog', 'ascii');
        var key = Buffer.from('key', 'ascii');
        var result;

        result = mac.hmac_sha1(key, msg);
        assert(result === 'DE7C9B85B8B78AA6BC8A7A36F70A90701C9DB4D9');

        result = mac.hmac_sha256(key, msg);
        assert(result === 'F7BC83F430538424B13298E6AA6FB143EF4D59A14946175997479DBC2D1A3CD8');

        result = mac.hmac_md5(key, msg);
        assert(result === '80070713463E7749B90C2DC24911E275');
    },

    'hmac sha1' : function() {
        var key;
        var message;
        message = '';
        key = '';
        var result = mac.hmac_sha1(key, message);
        var answer = 'FBDB1D1B18AA6C08324B7D64B71FB76370690E1D';
        assert(answer === result);
    }

/*
    'des mac': function () {
        //test 1
        var key = new Buffer('21F347F04A223FEFEAC7857E057EA42A', 'hex');
        var plain = new Buffer('8482000010CA5225B746F24411', 'hex');
        var desmac = new Buffer('D75C127C2959176C', 'hex');

        var result = mac.des_mac(key, plain, null, 8);
        assert(result.toString('hex') == desmac.toString('hex'));

        key = new Buffer('404142434445464748494A4B4C4D4E4F', 'hex');
        plain = new Buffer('00010203040506074041424344454647', 'hex');
        var iv = new Buffer('0000000000000000', 'hex');

        //test 2
        var plain_padd = padding.des_padding(plain);
        var cipher = des.cbc_encrypt(key, plain_padd, iv);
        cipher = cipher.slice(cipher.length - 8, cipher.length);

        result = mac.des_mac(key, plain, null, 8);
        assert(result.toString('hex') == cipher.toString('hex'));

        // test 3
        key = new Buffer('404142434445464748494A4B4C4D4E4F', 'hex');
        var host_challenge = new Buffer('0001020304050607', 'hex');
        var card_challege = new Buffer('08090A0B0C0D0E0F', 'hex');

        cipher = new Buffer('D0AEF0167D590E74', 'hex');
        plain = Buffer.concat([host_challenge, card_challege]);

        result = mac.des_mac(key, plain, null, 8);
        assert(result.toString('hex') == cipher.toString('hex'));
    },
    'AES CMAC': function () {
        var key = new Buffer('2B7E151628AED2A6ABF7158809CF4F3C', 'hex');
        var plain = new Buffer('6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411', 'hex');
        var cipher = new Buffer('DFA66747DE9AE63030CA32611497C827', 'hex');

        var result = mac.aes_cmac(key, plain);

        assert(result.toString('hex') == cipher.toString('hex'));

        key = new Buffer('404142434445464748494A4B4C4D4E4F', 'hex');
        plain = new Buffer('000000000000000000000006000080010000000000000000B53CA38AD92EEFE5', 'hex');

        cipher = new Buffer('ADFC43E1BFD7F3048987695748F56D99', 'hex');
        result = mac.aes_cmac(key, plain);

        assert(result.toString('hex') == cipher.toString('hex'));
    }
*/
};
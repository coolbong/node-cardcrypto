/**
 * Created by coolbong on 2015. 5. 31..
 */

var mac = require('../lib/mac');
var des = require('../lib/des');
var xor = require('../lib/bitwise').xor;
var padding = require('../lib/padding');

var assert = require('assert');

exports.mac = {
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
    ' Retail MAC': function () {

        var plain = new Buffer('Hello World !!!!', 'ascii');
        var iv = new Buffer('0000000000000000', 'hex');

        var result = mac.des_mac_emv(des2key, plain);


        var block1 = plain.slice(0, 8);
        var block2 = plain.slice(plain.length - 8, plain.length);


        var cipher = des.cbc_encrypt(deskey1, plain, iv);
        cipher = xor(cipher, block2);
        cipher = des.ecb_encrypt(des2key, cipher);
        //FIXME check this assert mac api changed padding is default
        //assert(result.toString('hex') == cipher.toString('hex'));

        cipher = des.ecb_encrypt(deskey1, block1);
        cipher = xor(cipher, block2);

        cipher = des.ecb_encrypt(deskey1, cipher);
        cipher = des.ecb_decrypt(deskey2, cipher);
        cipher = des.ecb_encrypt(deskey1, cipher);

        //FIXME check this assert mac api changed padding is default
        //assert(result.toString('hex') == cipher.toString('hex'));

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
    },
    'hmac sha1' : function() {
        var key;
        var message = new Buffer('I love cupcakes', 'ascii');
        key = new Buffer('abcdefg', 'ascii');
        //message = new Buffer('', 'hex');
        //key = new Buffer('', 'hex');
        var result = crypto.hmac_sha1(key, message);
        var answer = new Buffer('fbdb1d1b18aa6c08324b7d64b71fb76370690e1d', 'hex');
        //console.log(result.toString('hex').toUpperCase());
        //console.log(answer.toString('hex').toUpperCase());
        //assert(answer.toString('hex') === result.toString('hex'));

        message = new Buffer('Marry', 'ascii');
        key = new Buffer('abcdefghijklmnopqrstuvwxyz', 'ascii');
        result = crypto.hmac_sha1(key, message);
        //console.log(result.toString('hex').toUpperCase())

        message = new Buffer('0000000002D1A394','hex');
        key = new Buffer('123400000100003251010B22F2BFF2','hex');
        result = crypto.hmac_sha1(key, message);
        //console.log(result.toString('hex').toUpperCase());

        key = new Buffer('0000000002D1A394','hex');
        message = new Buffer('123400000100003251010B22F2BFF2','hex');
        result = crypto.hmac_sha1(key, message);
        //console.log(result.toString('hex').toUpperCase());

        //key:123400000100003251010B22F2BFF2
        //text:0000000002D1A394
        //result:7B975C79D3625022C978FADBACB7C5183CB83E1B
    }
*/
};
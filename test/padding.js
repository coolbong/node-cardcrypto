/**
 * Created by coolbong on 2015. 5. 31..
 */

var padding  = require('../lib/padding');
var assert = require('assert');


exports.padding = {
    'ISO9797Method1' : function() {
        var buffer = Buffer.from('Now is the time for all ', 'ascii');
        var result = padding.ISO9797Method1(buffer, 8);
        assert.equal(result.toString('hex').toUpperCase(), '4E6F77206973207468652074696D6520666F7220616C6C20');
    },
    'ISO9797Method2' : function() {
        var input = 'CAFEBABECAFEBA'; // 7 byte length
        var result = padding.ISO9797Method2(input);
        var answer = 'CAFEBABECAFEBA80';
        assert.equal(result, answer);
    },
    'pkcs5_padding 01' : function() {
        var input = 'CAFEBABECAFEBA'; // 7 byte length
        var result = padding.pkcs5_padding(input);
        var answer = 'CAFEBABECAFEBA01';
        assert.equal(result, answer);
    },
    'pkcs5_padding 02' : function() {
        var input = 'CAFEBABECAFE'; // 6 byte length
        var result = padding.pkcs5_padding(input);
        var answer = 'CAFEBABECAFE0202';
        assert.equal(result, answer);
    },
    'pkcs5_padding 08' : function() {
        var input = 'CAFEBABECAFEBABE'; // 8 byte length
        var result = padding.pkcs5_padding(input);
        var answer = 'CAFEBABECAFEBABE0808080808080808';
        assert.equal(result, answer);
    },
    'pkcs7_padding 01' : function() {
        var input = 'CAFEBABECAFEBABE'; // 8 byte length
        var result = padding.pkcs7_padding(input, 8);
        var answer = 'CAFEBABECAFEBABE0808080808080808';
        assert.equal(result, answer);
    },
    'pkcs7_padding 02' : function() {
        var input = 'CAFEBABECAFE';
        var result = padding.pkcs7_padding(input, 16);
        var answer = 'CAFEBABECAFE0A0A0A0A0A0A0A0A0A0A';
        assert.equal(result, answer);
    },
};

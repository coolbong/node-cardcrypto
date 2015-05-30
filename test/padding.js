/**
 * Created by coolbong on 2015. 5. 31..
 */

var padding  = require('../lib/padding');
var assert = require('assert');


exports.padding = {
    'ISO9797Method1' : function() {
        var buffer = new Buffer('Now is the time for all ', 'ascii');
        var result = padding.ISO9797Method1(buffer, 8);
        assert.equal(result.toString('hex').toUpperCase(), '4E6F77206973207468652074696D6520666F7220616C6C20');
    },
    'ISO9797Method2' : function() {
        //var buffer = new Buffer('Now is the time for all ', 'ascii');
        //var result = padding.ISO9797Method2(buffer, 8);
        //assert.equal(result.toString('hex').toUpperCase(), '4E6F77206973207468652074696D6520666F7220616C6C20');
    }
};

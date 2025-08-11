/**
 * Created by coolbong on 2016-07-21.
 */

function strip(str) {
    str = str || '';
    return str.replace(/\s+/g, '');
}


/**
 * convert to hex string
 *
 * @param {number | Buffer | string} hex string
 * @returns {string}
 */
function toHexString(data) {
    if (Buffer.isBuffer(data)) {
        return data.toString('hex').toUpperCase();
    } else if (typeof data === 'string') {
        return data; // fixme ascii string
    } else if (typeof data === 'number') {
        //number
        var h = data.toString(16).toUpperCase();
        if ((h.length & 1) == 1) {
            h = '0' + h;
        }
        return h;
    } else {
        return '';
    }
}


/**
 *  convert to Uint8Array array(Buffer)
 *
 * @param {string | Buffer | number }data
 * @returns {Buffer}
 */
function toBuffer(data) {
    if (Buffer.isBuffer(data)) {
        return data;
    } else if (typeof data === 'string') {
        data = strip(data);
        return Buffer.from(data, 'hex');
    } else if (typeof data == 'number') {
        var h = data.toString(16).toUpperCase();
        if ((h.length & 1) == 1) {
            h = '0' + h;
        }
        return Buffer.from(h, 'hex');
    } else {
        return Buffer.alloc(0);
    }
}

module.exports = {
    strip: strip,
    toHexString: toHexString,
    toBuffer: toBuffer
};
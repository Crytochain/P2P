var Hex = require('crypto-js/enc-hex');
var sha3 = require('crypto-js/sha3');
var BigNumber = require('bignumber.js');
var BN = require('bn.js');
var _ = require('underscore');
var secp256k1 = require('secp256k1');
var Buffer = require('safe-buffer').Buffer;
var numberToBN = require('number-to-bn');
var RLP = require("../utils/rlp");
var Hash = require("../utils/hash");


exports.sha3 = function (value, options) {
    if (options && options.encoding === 'hex') {
        if (value.length > 2 && value.substr(0, 2) === '0x') {
            value = value.substr(2);
        }
        value = Hex.parse(value);
    }
    let sha = sha3(value, {
        outputLength: 256
    }).toString()
    return '0x' + sha;
}

/**
 * Auto converts any given value into it's hex representation.
 *
 * And even stringifys objects before.
 *
 * @method toHex
 * @param {String|Number|BigNumber|Object}
 * @return {String}
 */
exports.toHex = function (val) {
    /*jshint maxcomplexity: 8 */
    if (isBoolean(val))
        return fromDecimal(+val);

    if (isBigNumber(val))
        return fromDecimal(val);

    if (typeof val === 'object')
        return fromUtf8(JSON.stringify(val));

    // if its a negative number, pass it through fromDecimal
    if (isString(val)) {
        if (val.indexOf('-0x') === 0)
            return fromDecimal(val);
        else if (val.indexOf('0x') === 0)
            return val;
        else if (!isFinite(val)) {

            return fromUtf8(val, 1);
        }

    }

    return fromDecimal(val);
};

/* 
 * A simple signTransaction function to sign
 * the input TX with private key.
 * Input:
 * tx - a JSON format object contains the input TX info
 * privateKey - a string format of the private key
 * Output:
 * rawTransaction - HEX String, can be used with 
 * 
 * 
 */
exports.signTransaction = function (tx, privateKey) {

    if (tx.chainId < 1) {
        return new Error('"Chain ID" is invalid');
    }

    if (!tx.gas && !tx.gasLimit) {
        return new Error('"gas" is missing');
    }

    if (tx.nonce < 0 ||
        tx.gasLimit < 0 ||
        tx.gasPrice < 0 ||
        tx.chainId < 0) {
        return new Error('Gas, gasPrice, nonce or chainId is lower than 0');
    }
    //Sharding Flag can be 0, 1, 2
    //If input has not sharding flag, set it to 0 as global TX.
    if (tx.shardingFlag == undefined) {
        tx.shardingFlag = 0;
    }
    try {
        //Make sure all the number fields are in HEX format
        var transaction = tx;
        transaction.to = tx.to || '0x'; //Can be zero, for contract creation
        transaction.data = tx.data || '0x'; //can be zero for general TXs
        transaction.value = tx.value || '0x'; //can be zero for contract call
        transaction.chainId = numberToHex(tx.chainId);
        transaction.shardingFlag = numberToHex(tx.shardingFlag);
        transaction.systemContract = '0x0'; //System contract flag, always = 0
        transaction.via = tx.via || '0x'; //vnode subchain address

        //Encode the TX for signature
        //   type txdata struct {
        // AccountNonce uint64          `json:"nonce"    gencodec:"required"`
        // SystemContract uint64          `json:"syscnt" gencodec:"required"`
        // Price        *big.Int        `json:"gasPrice" gencodec:"required"`
        // GasLimit     *big.Int        `json:"gas"      gencodec:"required"`
        //   // nil means contract creation
        // Amount       *big.Int        `json:"value"    gencodec:"required"`
        // Payload      []byte          `json:"input"    gencodec:"required"`
        // ShardingFlag uint64 `json:"shardingFlag" gencodec:"required"`
        // Via            *common.Address `json:"to"       rlp:"nil"`

        // // Signature values
        // V *big.Int `json:"v" gencodec:"required"`
        // R *big.Int `json:"r" gencodec:"required"`
        // S *big.Int `json:"s" gencodec:"required"`

        var rlpEncoded = RLP.encode([
            fromNat(transaction.nonce),
            fromNat(transaction.systemContract),
            fromNat(transaction.gasPrice),
            fromNat(transaction.gasLimit),
            transaction.to.toLowerCase(),
            fromNat(transaction.value),
            transaction.data,
            fromNat(transaction.shardingFlag),
            // transaction.via.toLowerCase()]);
            transaction.via.toLowerCase(),
            fromNat(transaction.chainId),
            "0x",
            "0x"
        ]);

        var hash = Hash.keccak256(rlpEncoded);

        var vPos = 9;
        //Sign the hash with the private key to produce the
        //V, R, S
        var newsign = ecsign(hash, stripHexPrefix(privateKey));

        var rawTx = RLP.decode(rlpEncoded).slice(0, vPos + 3);

        //Replace the V field with chainID info
        var newV = newsign.v + 8 + transaction.chainId * 2;

        rawTx[vPos] = (makeEven(trimLeadingZero(bufferToHex(newV))));
        rawTx[vPos + 1] = (makeEven(trimLeadingZero(bufferToHex(newsign.r))));
        rawTx[vPos + 2] = (makeEven(trimLeadingZero(bufferToHex(newsign.s))));
        var rawTransaction = RLP.encode(rawTx);


    } catch (e) {

        return e;
    }

    return rawTransaction;
};

/**
 * ECDSA sign
 * @param {Buffer} msgHash
 * @param {Buffer} privateKey
 * @return {Object}
 */
var ecsign = function ecsign(msgHash, privateKeyStr) {
    //Convert the input string to Buffer
    if (typeof msgHash === 'string') {
        if (isHexString(msgHash)) {
            msgHash = Buffer.from(makeEven(stripHexPrefix(msgHash)), 'hex')
        }
    }

    var privateKey = new Buffer.from(privateKeyStr, 'hex');

    var sig = secp256k1.sign(msgHash, privateKey)

    var ret = {}
    ret.r = sig.signature.slice(0, 32)
    ret.s = sig.signature.slice(32, 64)
    ret.v = sig.recovery + 27

    return ret
}

var makeEven = function (hex) {
    if (hex.length % 2 === 1) {
        hex = hex.replace('0x', '0x0');
    }
    return hex;
};

/**
 * Converts a `Buffer` into a hex `String`
 * @param {Buffer} buf
 * @return {String}
 */
var bufferToHex = function bufferToHex(buf) {
    buf = toBuffer(buf)
    return '0x' + buf.toString('hex')
}

/**
* Attempts to turn a value into a `Buffer`. As input it supports `Buffer`, `String`, `Number`, null/undefined, `BN` and other objects with a `toArray()` method.
* @param {*} v the value
*/
var toBuffer = function toBuffer(v) {
    if (!Buffer.isBuffer(v)) {
        if (Array.isArray(v)) {
            v = Buffer.from(v)
        } else if (typeof v === 'string') {
            if (isHexString(v)) {
                v = Buffer.from(padToEven(stripHexPrefix(v)), 'hex')
            } else {
                v = Buffer.from(v)
            }
        } else if (typeof v === 'number') {
            v = intToBuffer(v)
        } else if (v === null || v === undefined) {
            v = Buffer.allocUnsafe(0)
        } else if (v.toArray) {
            // converts a BN to a Buffer
            v = Buffer.from(v.toArray())
        } else {
            throw new Error('invalid type')
        }
    }
    return v
}

/*
 * Transfer an integer to buffer
 */
var intToBuffer = function intToBuffer(i) {
    var hex = intToHex(i)
    return new Buffer.from(hex, 'hex')
}

/*
* RLP usage, conver the input integer to HEX value.
*/
var intToHex = function intToHex(i) {
    var hex = i.toString(16)
    if (hex.length % 2) {
        hex = '0' + hex
    }

    return hex
}

//To fix an error of 2 leading 0s
var trimLeadingZero = function (hex) {
    while (hex && hex.startsWith('0x00')) {
        hex = '0x' + hex.slice(4);
    }
    return hex;
};

/**
 * Removes 0x from a given String
 * @param {String} value
 * @return {String} output
 */
var stripHexPrefix = function stripHexPrefix(str) {
    if (typeof str !== 'string') {
        return str;
    }
    return isHexPrefixed(str) ? str.slice(2) : str;
}

/**
 * Check if string is HEX, requires a 0x in front
 *
 * @method isHexStrict
 * @param {String} hex to be checked
 * @returns {Boolean}
 */
var isHexStrict = function (hex) {
    return ((_.isString(hex) || _.isNumber(hex)) && /^(-)?0x[0-9a-f]*$/i.test(hex));
};

/**
 * Takes an input and transforms it into an BN
 *
 * @method toBN
 * @param {Number|String|BN} number, string, HEX string or BN
 * @return {BN} BN
 */
var toBN = function (number) {
    try {
        return numberToBN.apply(null, arguments);
    } catch (e) {
        throw new Error(e + ' Given value: "' + number + '"');
    }
};

var isHexPrefixed = function isHexPrefixed(str) {
    return str.slice(0, 2) === '0x';
}

var isHexString = function isHexString(value, length) {
    if (typeof value !== 'string' || !value.match(/^0x[0-9A-Fa-f]*$/)) {
        return false;
    }

    if (length && value.length !== 2 + 2 * length) {
        return false;
    }

    return true;
}
/**
 * Converts value to it's hex representation
 *
 * @method fromDecimal
 * @param {String|Number|BigNumber}
 * @return {String}
 */
var fromDecimal = function (value) {
    var number = toBigNumber(value);
    var result = number.toString(16);

    return number.isLessThan(0) ? '-0x' + result.substr(1) : '0x' + result;
};

var toBigNumber = function (number) {
    /*jshint maxcomplexity:5 */
    number = number || 0;
    if (isBigNumber(number))
        return number;

    if (isString(number) && (number.indexOf('0x') === 0 || number.indexOf('-0x') === 0)) {
        return new BigNumber(number.toLowerCase().replace('0x', ''), 16);
    }

    return new BigNumber(number.toString(10), 10);
};

/**
 * Should be called to get hex representation (prefixed by 0x) of utf8 string
 *
 * @method fromUtf8
 * @param {String} string
 * @param {Number} optional padding
 * @returns {String} hex representation of input string
 */
var fromUtf8 = function (str, allowZero) {
    str = utf8.encode(str);
    var hex = "";
    for (var i = 0; i < str.length; i++) {
        var code = str.charCodeAt(i);
        if (code === 0) {
            if (allowZero) {
                hex += '00';
            } else {
                break;
            }
        } else {
            var n = code.toString(16);
            hex += n.length < 2 ? '0' + n : n;
        }
    }

    return "0x" + hex;
};

/**
 * Converts value to it's hex representation
 *
 * @method numberToHex
 * @param {String|Number|BN} value
 * @return {String}
 */
var numberToHex = function (value) {
    if (_.isNull(value) || _.isUndefined(value)) {
        return value;
    }

    if (!isFinite(value) && !isHexStrict(value)) {
        throw new Error('Given input "' + value + '" is not a number.');
    }

    var number = toBN(value);
    var result = number.toString(16);

    return number.lt(new BN(0)) ? '-0x' + result.substr(1) : '0x' + result;
};

/**
 * Returns true if object is BigNumber, otherwise false
 *
 * @method isBigNumber
 * @param {Object}
 * @return {Boolean}
 */
var isBigNumber = function (object) {
    return object instanceof BigNumber ||
        (object && object.constructor && object.constructor.name === 'BigNumber');
};

/**
 * Returns true if object is string, otherwise false
 *
 * @method isString
 * @param {Object}
 * @return {Boolean}
 */
var isString = function (object) {
    return typeof object === 'string' ||
        (object && object.constructor && object.constructor.name === 'String');
};

/**
 * Check if string is HEX, requires a 0x in front
 *
 * @method isHexStrict
 * @param {String} hex to be checked
 * @returns {Boolean}
 */
var isHexStrict = function (hex) {
    return ((_.isString(hex) || _.isNumber(hex)) && /^(-)?0x[0-9a-f]*$/i.test(hex));
};

/**
 * Returns true if object is function, otherwise false
 *
 * @method isFunction
 * @param {Object}
 * @return {Boolean}
 */
var isFunction = function (object) {
    return typeof object === 'function';
};

/**
 * Returns true if object is Objet, otherwise false
 *
 * @method isObject
 * @param {Object}
 * @return {Boolean}
 */
var isObject = function (object) {
    return object !== null && !(Array.isArray(object)) && typeof object === 'object';
};

/**
 * Returns true if object is boolean, otherwise false
 *
 * @method isBoolean
 * @param {Object}
 * @return {Boolean}
 */
var isBoolean = function (object) {
    return typeof object === 'boolean';
};

var fromNat = function fromNat(bn) {
    return bn === "0x0" ? "0x" : bn.length % 2 === 0 ? bn : "0x0" + bn.slice(2);
};
var { randomBytes } = require('crypto');
var BN = require("bn.js");
exports.BN = BN;
var createKeccakHash = require('keccak');
var secp256k1 = require('secp256k1');
exports.secp256k1 = secp256k1;
var assert = require('assert');
var Buffer = require('safe-buffer').Buffer;

function assert(val, msg) {
    if (!val) {
        throw new Error(msg || 'Assertion failed');
    }
}

/**
 * Attempts to turn a value into a `Buffer`. As input it supports `Buffer`, `String`, `Number`, null/undefined, `BN` and other objects with a `toArray()` method.
 * @param v the value
 */
exports.toBuffer = function (v) {
    if (!Buffer.isBuffer(v)) {
        if (Array.isArray(v)) {
            v = Buffer.from(v);
        }
        else if (typeof v === 'string') {
            if (exports.isHexString(v)) {
                v = Buffer.from(exports.padToEven(exports.stripHexPrefix(v)), 'hex');
            }
            else {
                v = Buffer.from(v);
            }
        }
        else if (typeof v === 'number') {
            v = exports.intToBuffer(v);
        }
        else if (v === null || v === undefined) {
            v = Buffer.allocUnsafe(0);
        }
        else if (BN.isBN(v)) {
            v = v.toArrayLike(Buffer);
        }
        else if (v.toArray) {
            // converts a BN to a Buffer
            v = Buffer.from(v.toArray());
        }
        else {
            throw new Error('invalid type');
        }
    }
    return v;
};
/**
 * Converts a `Buffer` into a hex `String`.
 * @param buf `Buffer` object to convert
 */
exports.bufferToHex = function (buf) {
    buf = exports.toBuffer(buf);
    return '0x' + buf.toString('hex');
};
/**
 * Creates Keccak hash of the input
 * @param a The input data (Buffer|Array|String|Number)
 * @param bits The Keccak width
 */
exports.keccak = function (a, bits) {
    if (bits === void 0) { bits = 256; }
    a = exports.toBuffer(a);
    if (!bits)
        bits = 256;
    return createKeccakHash("keccak" + bits)
        .update(a)
        .digest();
};
/**
 * Checks if the private key satisfies the rules of the curve secp256k1.
 */
exports.isValidPrivate = function (privateKey) {
    return secp256k1.privateKeyVerify(privateKey);
};
/**
 * Checks if the public key satisfies the rules of the curve secp256k1
 * and the requirements of Liberum.
 * @param publicKey The two points of an uncompressed key, unless sanitize is enabled
 * @param sanitize Accept public keys in other formats
 */
exports.isValidPublic = function (publicKey, sanitize) {
    if (sanitize === void 0) { sanitize = false; }
    if (publicKey.length === 64) {
        // Convert to SEC1 for secp256k1
        return secp256k1.publicKeyVerify(Buffer.concat([Buffer.from([4]), publicKey]));
    }
    if (!sanitize) {
        return false;
    }
    return secp256k1.publicKeyVerify(publicKey);
};
/**
 * Returns the liberum address of a given public key.
 * Accepts "Liberum public keys" and SEC1 encoded keys.
 * @param pubKey The two points of an uncompressed key, unless sanitize is enabled
 * @param sanitize Accept public keys in other formats
 */
exports.pubToAddress = function (pubKey, sanitize) {
    if (sanitize === void 0) { sanitize = false; }
    pubKey = exports.toBuffer(pubKey);
    if (sanitize && pubKey.length !== 64) {
        pubKey = secp256k1.publicKeyConvert(pubKey, false).slice(1);
    }
    assert(pubKey.length === 64);
    // Only take the lower 160bits of the hash
    return exports.keccak(pubKey).slice(-20);
};
exports.publicToAddress = exports.pubToAddress;
/**
 * Returns the liberum public key of a given private key.
 * @param privateKey A private key must be 256 bits wide
 */
exports.privateToPublic = function (privateKey) {
    privateKey = exports.toBuffer(privateKey);
    // skip the type flag and use the X, Y points
    return secp256k1.publicKeyCreate(privateKey, false).slice(1);
};
/**
 * Converts a public key to the Liberum format.
 */
exports.importPublic = function (publicKey) {
    publicKey = exports.toBuffer(publicKey);
    if (publicKey.length !== 64) {
        publicKey = secp256k1.publicKeyConvert(publicKey, false).slice(1);
    }
    return publicKey;
};
/**
 * Returns the liberum address of a given private key.
 * @param privateKey A private key must be 256 bits wide
 */
exports.privateToAddress = function (privateKey) {
    return exports.publicToAddress(exports.privateToPublic(privateKey));
};

var Wallet = function Wallet(priv, pub) {
    if (priv && pub) {
        throw new Error('Cannot supply both a private and a public key to the constructor');
    }

    if (priv && !exports.isValidPrivate(priv)) {
        throw new Error('Private key does not satisfy the curve requirements (ie. it is invalid)');
    }

    if (pub && !exports.isValidPublic(pub)) {
        throw new Error('Invalid public key');
    }

    this._privKey = priv;
    this._pubKey = pub;
};

Object.defineProperty(Wallet.prototype, 'privKey', {
    get: function get() {
        assert(this._privKey, 'This is a public key only wallet');
        return this._privKey;
    }
});

Object.defineProperty(Wallet.prototype, 'pubKey', {
    get: function get() {
        if (!this._pubKey) {
            this._pubKey = exports.privateToPublic(this.privKey);
        }
        return this._pubKey;
    }
});

Wallet.generate = function (icapDirect) {
    if (icapDirect) {
        var max = new exports.BN('088f924eeceeda7fe92e1f5b0fffffffffffffff', 16);
        while (true) {
            var privKey = randomBytes(32);
            if (new exports.BN(exports.privateToAddress(privKey)).lte(max)) {
                return new Wallet(privKey);
            }
        }
    } else {
        return new Wallet(randomBytes(32));
    }
};



Wallet.prototype.getPrivateKey = function () {
    return this.privKey;
};

Wallet.prototype.getPrivateKeyString = function () {
    return exports.bufferToHex(this.getPrivateKey());
};

Wallet.prototype.getAddress = function () {
    return exports.publicToAddress(this.pubKey);
};

Wallet.prototype.getAddressString = function () {
    return exports.bufferToHex(this.getAddress());
};

module.exports = Wallet;

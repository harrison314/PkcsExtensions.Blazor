var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
var PkcsExtensionsBlazor;
(function (PkcsExtensionsBlazor) {
    function toBase64(uint8Array) {
        return window.btoa(uint8Array.reduce(function (data, byte) { return data + String.fromCharCode(byte); }, ''));
    }
    function unpromise(inObj) {
        var acc = Promise.resolve(0);
        var outObj = {};
        var _loop_1 = function (key) {
            if (inObj[key] && typeof inObj[key].then === 'function') {
                acc = acc.then(function (_) { return inObj[key].then(function (t) { return outObj[key] = t; }); });
            }
            else {
                outObj[key] = inObj[key];
            }
        };
        for (var _i = 0, _a = Object.keys(inObj); _i < _a.length; _i++) {
            var key = _a[_i];
            _loop_1(key);
        }
        return acc.then(function (_) { return outObj; });
    }
    var getRandomValues = function (size) {
        var array = new Uint8Array(size);
        crypto.getRandomValues(array);
        return toBase64(array);
    };
    var generateKeyRsa = function (modulusLength, name) {
        if (name === void 0) { name = 'RSA-OAEP'; }
        return crypto.subtle.generateKey({
            name: name,
            modulusLength: modulusLength,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: { name: 'SHA-256' },
        }, true, ['encrypt', 'decrypt'])
            .then(function (t) { return crypto.subtle.exportKey('pkcs8', t.privateKey); })
            .then(function (buffer) { return toBase64(new Uint8Array(buffer)); });
    };
    var mapEcJwk = function (jwk) {
        return {
            kty: 'EC',
            crv: jwk.crv,
            d: jwk.d,
            x: jwk.x,
            y: jwk.y
        };
    };
    var sanilizeEcJwk = function (jwk) {
        if (jwk.d) {
            return {
                kty: 'EC',
                crv: jwk.crv,
                d: jwk.d,
                x: jwk.x,
                y: jwk.y,
                ext: true
            };
        }
        else {
            return {
                kty: 'EC',
                crv: jwk.crv,
                x: jwk.x,
                y: jwk.y,
                ext: true
            };
        }
    };
    var generateKeyEcdsa = function (namedCurve) {
        var ecdsaParams = {
            name: 'ECDSA',
            namedCurve: namedCurve
        };
        return crypto.subtle.generateKey(ecdsaParams, true, ['sign', 'verify'])
            .then(function (t) { return crypto.subtle.exportKey('jwk', t.privateKey); })
            .then(function (t) { return mapEcJwk(t); });
    };
    var sharedEphemeralDhmSecret = function (publicKey, bitsLegnht) {
        if (bitsLegnht === void 0) { bitsLegnht = 256; }
        var importParams = {
            name: 'ECDH',
            namedCurve: publicKey.crv
        };
        var publicKeyPromise = window.crypto.subtle.importKey('jwk', sanilizeEcJwk(publicKey), importParams, true, ['deriveBits']);
        var keyPairPromise = window.crypto.subtle.generateKey(importParams, true, ['deriveBits']);
        return unpromise({
            otherPublicKey: publicKeyPromise,
            ephemeralKeyPair: keyPairPromise
        }).then(function (material) {
            var bits = window.crypto.subtle.deriveBits({
                name: 'ECDH',
                public: material.otherPublicKey,
            }, material.ephemeralKeyPair.privateKey, bitsLegnht)
                .then(function (t) { return new Uint8Array(t); });
            var exportedPublicKey = window.crypto.subtle.exportKey('jwk', material.ephemeralKeyPair.publicKey);
            return unpromise({ publicJwk: exportedPublicKey, bits: bits })
                .then(function (t) { return (__assign(__assign({}, mapEcJwk(t.publicJwk)), { derivedBits: toBase64(t.bits) })); });
        });
    };
    var sharedDhmSecret = function (privateKey, publicKey, bitsLegnht) {
        if (bitsLegnht === void 0) { bitsLegnht = 256; }
        var importParams = {
            name: 'ECDH',
            namedCurve: publicKey.crv
        };
        var publicKeyPromise = window.crypto.subtle.importKey('jwk', sanilizeEcJwk(publicKey), importParams, true, ['deriveBits']);
        var privateKeyPromise = window.crypto.subtle.importKey('jwk', sanilizeEcJwk(privateKey), importParams, true, ['deriveBits']);
        return unpromise({
            publicKey: publicKeyPromise,
            privateKey: privateKeyPromise
        }).then(function (material) {
            return window.crypto.subtle.deriveBits({
                name: 'ECDH',
                public: material.publicKey,
            }, material.privateKey, bitsLegnht)
                .then(function (t) { return toBase64(new Uint8Array(t)); });
        });
    };
    function Load() {
        window['PkcsExtensionsBlazor_getRandomValues'] = getRandomValues;
        window['PkcsExtensionsBlazor_generateKeyRsa'] = generateKeyRsa;
        window['PkcsExtensionsBlazor_generateKeyEcdsa'] = generateKeyEcdsa;
        window['PkcsExtensionsBlazor_sharedEphemeralDhmSecret'] = sharedEphemeralDhmSecret;
        window['PkcsExtensionsBlazor_sharedDhmSecret'] = sharedDhmSecret;
    }
    PkcsExtensionsBlazor.Load = Load;
})(PkcsExtensionsBlazor || (PkcsExtensionsBlazor = {}));
PkcsExtensionsBlazor.Load();

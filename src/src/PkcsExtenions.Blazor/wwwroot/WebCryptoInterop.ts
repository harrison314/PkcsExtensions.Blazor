
namespace PkcsExtensionsBlazor {

    // For Browser support see https://diafygi.github.io/webcrypto-examples/

    interface EcDsaPrivateKeyData {
        kty: 'EC';
        crv: 'P-256' | 'P-384' | 'P-521';
        d: string;
        x: string;
        y: string;
    }

    type Unpromised<T> = {
        [P in keyof T]: T[P] extends PromiseLike<infer K> ? K : T[P];
    }

    // Typescript polyfill
    declare class Promise {
        static resolve(p: any): any;
    }

    /**
     * Convert Uint8Array to Base64 string.
     * @param uint8Array
     */
    function toBase64(uint8Array: Uint8Array): string {
        return window.btoa(uint8Array.reduce((data, byte) => data + String.fromCharCode(byte), ''));
    }


    function unpromise<T extends object>(inObj: T): PromiseLike<Unpromised<T>> {
        let acc = Promise.resolve(0)
        let outObj: Partial<Unpromised<T>> = {};

        for (let key of Object.keys(inObj)) {
            if (inObj[key] && typeof inObj[key].then === 'function') {
                acc = acc.then(_ => inObj[key].then(t => outObj[key] = t));
            }
            else {
                outObj[key] = inObj[key];
            }
        }

        return acc.then(_ => outObj);
    }

    /**
     * Generate random bytes with size as Base64 string.
     * @param size The size of random bytes.
     * @returns Random bytes as Base64 string.
     */
    const getRandomValues = function (size: number): string {
        let array = new Uint8Array(size);
        crypto.getRandomValues(array);
        return toBase64(array);
    };

    const generateKeyRsa = function (modulusLength: number, name = 'RSA-OAEP'): PromiseLike<string> {
        return crypto.subtle.generateKey({
            name: name,
            modulusLength: modulusLength,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: { name: 'SHA-256' },
        }, true, ['encrypt', 'decrypt'])
            .then(t => crypto.subtle.exportKey('pkcs8', t.privateKey))
            .then(buffer => toBase64(new Uint8Array(buffer)));
    };

    const mapEcJwk = function (jwk: JsonWebKey): EcDsaPrivateKeyData {
        return {
            kty: 'EC',
            crv: jwk.crv as any,
            d: jwk.d,
            x: jwk.x,
            y: jwk.y
        };
    };

    const sanilizeEcJwk = function (jwk: JsonWebKey): JsonWebKey {
        if (jwk.d) {
            return {
                kty: 'EC',
                crv: jwk.crv,
                d: jwk.d,
                x: jwk.x,
                y: jwk.y,
                ext: true
            };
        } else {
            return {
                kty: 'EC',
                crv: jwk.crv,
                x: jwk.x,
                y: jwk.y,
                ext: true
            };
        }
    }

    const generateKeyEcdsa = function (namedCurve: string): PromiseLike<EcDsaPrivateKeyData> {
        let ecdsaParams = {
            name: 'ECDSA',
            namedCurve: namedCurve
        };

        return crypto.subtle.generateKey(ecdsaParams, true, ['sign', 'verify'])
            .then(t => crypto.subtle.exportKey('jwk', t.privateKey))
            .then(t => mapEcJwk(t));
    };


    const sharedEphemeralDhmSecret = function (publicKey: JsonWebKey, bitsLegnht = 256): PromiseLike<EcDsaPrivateKeyData & { derivedBits: string }> {

        let importParams = {
            name: 'ECDH',
            namedCurve: publicKey.crv
        };

        let publicKeyPromise = window.crypto.subtle.importKey('jwk', sanilizeEcJwk(publicKey), importParams, true, ['deriveBits']);
        let keyPairPromise = window.crypto.subtle.generateKey(importParams, true, ['deriveBits']);

        return unpromise({
            otherPublicKey: publicKeyPromise,
            ephemeralKeyPair: keyPairPromise
        }).then(material => {
            let bits = window.crypto.subtle.deriveBits({
                name: 'ECDH',
                public: material.otherPublicKey,
            }, material.ephemeralKeyPair.privateKey, bitsLegnht)
                .then(t => new Uint8Array(t));

            let exportedPublicKey = window.crypto.subtle.exportKey('jwk', material.ephemeralKeyPair.publicKey);

            return unpromise({ publicJwk: exportedPublicKey, bits: bits })
                .then(t => ({
                    ...mapEcJwk(t.publicJwk),
                    derivedBits: toBase64(t.bits)
                }));
        });
    }

    const sharedDhmSecret = function (privateKey: JsonWebKey, publicKey: JsonWebKey, bitsLegnht = 256): PromiseLike<string> {

        let importParams = {
            name: 'ECDH',
            namedCurve: publicKey.crv
        };

        let publicKeyPromise = window.crypto.subtle.importKey('jwk', sanilizeEcJwk(publicKey), importParams, true, ['deriveBits']);
        let privateKeyPromise = window.crypto.subtle.importKey('jwk', sanilizeEcJwk(privateKey), importParams, true, ['deriveBits']);

        return unpromise({
            publicKey: publicKeyPromise,
            privateKey: privateKeyPromise
        }).then(material => {
            return window.crypto.subtle.deriveBits({
                name: 'ECDH',
                public: material.publicKey,
            }, material.privateKey, bitsLegnht)
                .then(t => toBase64(new Uint8Array(t)));
        });
    }

    export function Load(): void {
        window['PkcsExtensionsBlazor_getRandomValues'] = getRandomValues;
        window['PkcsExtensionsBlazor_generateKeyRsa'] = generateKeyRsa;
        window['PkcsExtensionsBlazor_generateKeyEcdsa'] = generateKeyEcdsa;
        window['PkcsExtensionsBlazor_sharedEphemeralDhmSecret'] = sharedEphemeralDhmSecret;
        window['PkcsExtensionsBlazor_sharedDhmSecret'] = sharedDhmSecret;
    }
}

PkcsExtensionsBlazor.Load();



using Microsoft.JSInterop;
using PkcsExtensions.Blazor.Jwk;
using PkcsExtensions.Blazor.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PkcsExtensions.Blazor.WebCrypto
{
    public class WebCryptoProvider : IWebCryptoProvider
    {
        private readonly IJSRuntime jsRuntime;

        public WebCryptoProvider(IJSRuntime jsRuntime)
        {
            this.jsRuntime = jsRuntime ?? throw new ArgumentNullException(nameof(jsRuntime));
        }

        public async ValueTask<byte[]> GetRandomBytes(int count, CancellationToken cancellationToken = default)
        {
            if (count < 0) throw new ArgumentOutOfRangeException(nameof(count));

            if (count == 0)
            {
                return Array.Empty<byte>();
            }

            string base64RandomData = await this.jsRuntime.InvokeAsync<string>("PkcsExtensionsBlazor_getRandomValues",
                cancellationToken: cancellationToken,
                args: new object[] { count });

            return Convert.FromBase64String(base64RandomData);
        }

        public async ValueTask<RSA> GenerateRsaKeyPair(int keySize, CancellationToken cancellationToken = default)
        {
            if (keySize <= 0 || keySize % 1024 != 0)
            {
                throw new ArgumentException("Invalid RSA key size.", nameof(keySize));
            }

            string b64Pkcs8 = await this.jsRuntime.InvokeAsync<string>("PkcsExtensionsBlazor_generateKeyRsa",
                cancellationToken: cancellationToken,
                args: new object[] { keySize });

            RSA rsa = RSA.Create();
            try
            {
                rsa.ManagedImportPkcs8PrivateKey(Convert.FromBase64String(b64Pkcs8));
                return rsa;
            }
            catch
            {
                rsa.Dispose();
                throw;
            }
        }

        public async ValueTask<JsonWebKey> GenerateECDsaJwkKeyPair(WebCryptoCurveName curveName, CancellationToken cancellationToken = default)
        {
            string namedCurve = this.TranslateToCurveName(curveName);

            Dictionary<string, string> jwkFields = await this.jsRuntime.InvokeAsync<Dictionary<string, string>>("PkcsExtensionsBlazor_generateKeyEcdsa",
                cancellationToken: cancellationToken,
                args: new object[] { namedCurve });

            return this.ConvertToWebKey(jwkFields);
        }

        public async ValueTask<byte[]> DeriveBytesPbkdf2(byte[] password, byte[] salt, int iterations, WebCryptoHashAlgorithm hashAlgorithm, int ouputSize, CancellationToken cancellationToken = default)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (salt == null) throw new ArgumentNullException(nameof(salt));

            if (salt.Length == 0) throw new ArgumentOutOfRangeException("salt size is less than zero");

            string hash = this.TraslnalteToHashName(hashAlgorithm);
            return await this.jsRuntime.InvokeAsync<byte[]>("PkcsExtensionsBlazor_generateKeyEcdsa",
                 cancellationToken: cancellationToken,
                 args: new object[] { hash, password, salt, iterations, ouputSize * 8 });
        }

        public async ValueTask<byte[]> ComputeHmac(WebCryptoHashAlgorithm hashAlgorithm, byte[] key, byte[] data, CancellationToken cancellationToken = default)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (data == null) throw new ArgumentNullException(nameof(data));


            string hash = this.TraslnalteToHashName(hashAlgorithm);
            return await this.jsRuntime.InvokeAsync<byte[]>("PkcsExtensionsBlazor_hmac",
                 cancellationToken: cancellationToken,
                 args: new object[] { hash, key, data });
        }

        private string TranslateToCurveName(WebCryptoCurveName curveName)
        {
            return curveName switch
            {
                WebCryptoCurveName.NistP256 => "P-256",
                WebCryptoCurveName.NistP384 => "P-384",
                WebCryptoCurveName.NistP521 => "P-521",
                _ => throw new NotImplementedException()
            };
        }

        private string TraslnalteToHashName(WebCryptoHashAlgorithm hashAlgorithm)
        {
            return hashAlgorithm switch
            {
                WebCryptoHashAlgorithm.SHA1 => "SHA-1",
                WebCryptoHashAlgorithm.SHA256 => "SHA-256",
                WebCryptoHashAlgorithm.SHA384 => "SHA-384",
                WebCryptoHashAlgorithm.SHA512 => "SHA-512",
                _ => throw new NotImplementedException()
            };
        }

        private JsonWebKey ConvertToWebKey(Dictionary<string, string> rawJwk)
        {
            JsonWebKey webKey = new JsonWebKey()
            {
                Kty = "EC",
                CurveName = rawJwk["crv"],
                D = Base64Url.EncodeFromString(rawJwk["d"]),
                X = Base64Url.EncodeFromString(rawJwk["x"]),
                Y = Base64Url.EncodeFromString(rawJwk["y"])
            };

            webKey.KeyOps = new List<string>()
            {
                JsonWebKeyOperation.Sign,
                JsonWebKeyOperation.Verify,
                JsonWebKeyOperation.DeriveBits
            };

            return webKey;
        }
    }
}

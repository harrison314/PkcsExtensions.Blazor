using Microsoft.JSInterop;
using PkcsExtenions.Blazor.Jwk;
using PkcsExtenions.Blazor.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PkcsExtenions.Blazor.WebCrypto
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

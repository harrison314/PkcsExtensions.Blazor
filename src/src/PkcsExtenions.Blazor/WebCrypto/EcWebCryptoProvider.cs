using Microsoft.JSInterop;
using PkcsExtenions.Blazor.Jwk;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PkcsExtenions.Blazor.WebCrypto
{
    public class EcWebCryptoProvider : IEcWebCryptoProvider
    {
        private readonly IJSRuntime jsRuntime;

        public EcWebCryptoProvider(IJSRuntime jsRuntime)
        {
            this.jsRuntime = jsRuntime ?? throw new ArgumentNullException(nameof(jsRuntime));
        }

        public async ValueTask<byte[]> GetSharedDhmSecret(JsonWebKey privateKey, JsonWebKey otherPublicKey, CancellationToken cancellationToken = default)
        {
            if (privateKey == null) throw new ArgumentNullException(nameof(privateKey));
            if (!privateKey.HasPrivateKey()) throw new ArgumentException("privateKey must by private key.");
            if (!string.Equals("EC", privateKey.Kty, StringComparison.Ordinal)) throw new ArgumentException("otherPublicKey must by EC key");

            if (otherPublicKey == null) throw new ArgumentNullException(nameof(otherPublicKey));
            if (otherPublicKey.HasPrivateKey()) throw new ArgumentException("otherPublicKey must by public key.");
            if (!string.Equals("EC", otherPublicKey.Kty, StringComparison.Ordinal)) throw new ArgumentException("otherPublicKey must by EC key");

            JsonWebKeyProxy privateKeyProxy = new JsonWebKeyProxy(privateKey);
            JsonWebKeyProxy otherPublicKeyProxy = new JsonWebKeyProxy(otherPublicKey);
            int lenght = this.ToDhmLen(otherPublicKey);

            string sharedSeecritBase64 = await this.jsRuntime.InvokeAsync<string>("PkcsExtensionsBlazor_sharedDhmSecret",
                cancellationToken: cancellationToken,
                args: new object[] { privateKeyProxy, otherPublicKeyProxy, lenght });

            return Convert.FromBase64String(sharedSeecritBase64);
        }

        public async ValueTask<EcdhEphemeralBundle> GetSharedEphemeralDhmSecret(JsonWebKey otherPublicKey, CancellationToken cancellationToken = default)
        {
            if (otherPublicKey == null) throw new ArgumentNullException(nameof(otherPublicKey));
            if (otherPublicKey.HasPrivateKey()) throw new ArgumentException("otherPublicKey must by public key.");
            if (!string.Equals("EC", otherPublicKey.Kty, StringComparison.Ordinal)) throw new ArgumentException("otherPublicKey must by EC key");

            JsonWebKeyProxy otherPublicKeyProxy = new JsonWebKeyProxy(otherPublicKey);
            int lenght = this.ToDhmLen(otherPublicKey);

            Dictionary<string, string> jwkFields = await this.jsRuntime.InvokeAsync<Dictionary<string, string>>("PkcsExtensionsBlazor_sharedEphemeralDhmSecret",
                cancellationToken: cancellationToken,
                args: new object[] { otherPublicKeyProxy, lenght });

            return new EcdhEphemeralBundle()
            {
                EphemeralDhmPublicKey = this.ConvertToWebKey(jwkFields),
                SharedSecret = Convert.FromBase64String(jwkFields["derivedBits"])
            };
        }

        public int ToDhmLen(JsonWebKey jsonWebKey)
        {
            return jsonWebKey.CurveName switch
            {
                "P-256" => 256,
                "P-384" => 384,
                "P-521" => 528,
                _ => throw new NotSupportedException($"Curve {jsonWebKey.CurveName} is not supported.")
            };
        }

        private JsonWebKey ConvertToWebKey(Dictionary<string, string> rawJwk)
        {
            JsonWebKey webKey = new JsonWebKey()
            {
                Kty = "EC",
                CurveName = rawJwk["crv"],
                X = Base64Url.EncodeFromString(rawJwk["x"]),
                Y = Base64Url.EncodeFromString(rawJwk["y"])
            };

            webKey.KeyOps = new List<string>()
            {
                JsonWebKeyOperation.DeriveBits
            };

            return webKey;
        }
    }
}

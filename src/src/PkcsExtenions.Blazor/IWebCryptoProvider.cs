using PkcsExtenions.Blazor.Jwk;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PkcsExtenions.Blazor
{
    public interface IWebCryptoProvider
    {
        ValueTask<byte[]> GetRandomBytes(int count, CancellationToken cancellationToken = default);

        ValueTask<RSA> GenerateRsaKeyPair(int keySize, CancellationToken cancellationToken = default);

        ValueTask<JsonWebKey> GenerateECDsaJwkKeyPair(WebCryptoCurveName curveName, CancellationToken cancellationToken = default);
    }
}

using PkcsExtensions.Blazor.Jwk;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PkcsExtensions.Blazor
{
    public interface IWebCryptoProvider
    {
        ValueTask<byte[]> GetRandomBytes(int count, CancellationToken cancellationToken = default);

        ValueTask<RSA> GenerateRsaKeyPair(int keySize, CancellationToken cancellationToken = default);

        ValueTask<JsonWebKey> GenerateECDsaJwkKeyPair(WebCryptoCurveName curveName, CancellationToken cancellationToken = default);

        ValueTask<byte[]> DeriveBytesPbkdf2(byte[] password, byte[] salt, int iterations, WebCryptoHashAlgorithm hashAlgorithm, int ouputSize, CancellationToken cancellationToken = default);

        ValueTask<byte[]> ComputeHmac(WebCryptoHashAlgorithm hashAlgorithm, byte[] key, byte[] data, CancellationToken cancellationToken = default);
    }
}

using PkcsExtenions.Blazor.Jwk;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PkcsExtenions.Blazor
{
    public interface IEcWebCryptoProvider
    {
        ValueTask<EcdhEphemeralBundle> GetSharedEphemeralDhmSecret(JsonWebKey otherPublicKey, CancellationToken cancellationToken = default);

        ValueTask<byte[]> GetSharedDhmSecret(JsonWebKey privateKey, JsonWebKey otherPublicKey, CancellationToken cancellationToken = default);
    }
}

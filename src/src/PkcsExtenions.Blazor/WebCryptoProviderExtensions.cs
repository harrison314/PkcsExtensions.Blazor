using PkcsExtenions.Algorithms;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PkcsExtenions.Blazor
{
    public static class WebCryptoProviderExtensions
    {
        public static async ValueTask<IRandomGenerator> CreateRandomGeneratorWithSeed(this IWebCryptoProvider webCryptoProvider, CancellationToken canselationToken = default)
        {
            DigestRandomGenerator generator = new DigestRandomGenerator(HashAlgorithmName.SHA1);
            generator.GenerateSeed(null);
            byte[] seedData = await webCryptoProvider.GetRandomBytes(generator.HashSize / 8, canselationToken);
            generator.AddSeedMaterial(seedData);

            return generator;
        }
    }
}

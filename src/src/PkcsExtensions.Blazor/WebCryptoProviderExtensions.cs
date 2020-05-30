using PkcsExtensions.Algorithms;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PkcsExtensions.Blazor
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

        public static async Task<byte[]> GetNonZeroBytes(this IWebCryptoProvider webCryptoProvider, int count, CancellationToken cancellationToken = default)
        {
            if (count < 0) throw new ArgumentOutOfRangeException(nameof(count));

            if (count == 0)
            {
                return Array.Empty<byte>();
            }

            byte[] buffer = await webCryptoProvider.GetRandomBytes(count, cancellationToken);
            for (; ; )
            {
                int zeroCount = 0;
                for (int i = 0; i < buffer.Length; i++)
                {
                    if (buffer[i] == 0)
                    {
                        zeroCount++;
                    }
                }

                if (zeroCount == 0)
                {
                    break;
                }

                else
                {
                    byte[] additionalSource = await webCryptoProvider.GetRandomBytes(zeroCount, cancellationToken);
                    int j = 0;
                    for (int i = 0; i < buffer.Length; i++)
                    {
                        if (buffer[i] == 0)
                        {
                            buffer[i] = additionalSource[j];
                            j++;
                        }
                    }
                }
            }

            return buffer;
        }
    }
}

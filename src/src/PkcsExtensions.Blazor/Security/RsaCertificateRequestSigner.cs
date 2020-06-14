using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace PkcsExtensions.Blazor.Security
{
    public delegate ValueTask<byte[]> RsaCertificateRequestSigner(byte[] hash, HashAlgorithmName usedHash);
}

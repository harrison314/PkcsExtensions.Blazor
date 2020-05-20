using PkcsExtenions.ASN1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace PkcsExtenions.Blazor.ASN1
{
    internal class SubjectPublicKeyInfo : IAsn1Node
    {
        public AlgorithmIdentifier Algorithm
        {
            get;
        }

        public ReadOnlyMemory<byte> PublicKey
        {
            get;
        }

        public SubjectPublicKeyInfo(AsnReader asnReader)
        {
            if (asnReader == null) throw new ArgumentNullException(nameof(asnReader));

            AsnReader pski = asnReader.ReadSequence();
            this.Algorithm = new AlgorithmIdentifier(pski);
            if (!pski.TryGetPrimitiveBitStringValue(out _, out ReadOnlyMemory<byte> publicKeyBytes))
            {
                throw new CryptographicException("Corrupted ASN1");
            }

            this.PublicKey = publicKeyBytes;
        }

        public SubjectPublicKeyInfo(RSAParameters parameters)
        {
            this.Algorithm = new AlgorithmIdentifier("1.2.840.113549.1.1.1");
            this.PublicKey = PkcsRsaConvertor.RsaParamsToPublicKey(parameters);
        }

        public void Write(AsnWriter asnWriter)
        {
            if (asnWriter == null) throw new ArgumentNullException(nameof(asnWriter));

            asnWriter.PushSequence();
            this.Algorithm.Write(asnWriter);
            asnWriter.WriteBitString(this.PublicKey.Span);
            asnWriter.PopSequence();
        }
    }
}

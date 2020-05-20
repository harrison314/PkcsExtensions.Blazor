using PkcsExtenions.ASN1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace PkcsExtenions.Blazor.ASN1
{
    internal class PrivateKeyInfo : IAsn1Node
    {
        public int Version
        {
            get;
            protected set;
        }

        public AlgorithmIdentifier Algorithm
        {
            get;
            protected set;
        }

        public ReadOnlyMemory<byte> PrivateKey
        {
            get;
            protected set;
        }

        public PrivateKeyInfo(AsnReader asnReader)
        {
            if (asnReader == null) throw new ArgumentNullException(nameof(asnReader));

            AsnReader pski = asnReader.ReadSequence();
            pski.TryReadInt32(out int version);
            this.Version = version;

            this.Algorithm = new AlgorithmIdentifier(pski);
            if (!pski.TryGetPrimitiveOctetStringBytes(out ReadOnlyMemory<byte> publicKeyBytes))
            {
                throw new CryptographicException("Corrupted ASN1");
            }

            this.PrivateKey = publicKeyBytes;
        }

        public PrivateKeyInfo(RSAParameters parameters)
        {
            this.Algorithm = new AlgorithmIdentifier("1.2.840.113549.1.1.1");
            this.PrivateKey = PkcsRsaConvertor.RsaParamsToPrivateKey(parameters);
        }

        public void Write(AsnWriter asnWriter)
        {
            if (asnWriter == null) throw new ArgumentNullException(nameof(asnWriter));

            asnWriter.PushSequence();
            asnWriter.WriteInteger(this.Version);
            this.Algorithm.Write(asnWriter);
            asnWriter.WriteOctetString(this.PrivateKey.Span);

            //asnWriter.WriteNull(new Asn1Tag(TagClass.ContextSpecific, 0, true));

            asnWriter.PopSequence();
        }
    }
}

using PkcsExtensions.ASN1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PkcsExtensions.Blazor.ASN1
{
    internal class CertificationRequest : IAsn1Node
    {
        public CertificationRequestInfo CertificationRequestInfo
        {
            get;
            set;
        }

        public AlgorithmIdentifier SignatureAlgorithm
        {
            get;
            set;
        }

        public Memory<byte> Signature
        {
            get;
            set;
        }

        public CertificationRequest()
        {

        }

        public void Write(AsnWriter asnWriter)
        {
            asnWriter.PushSequence();
            this.CertificationRequestInfo.Write(asnWriter);
            this.SignatureAlgorithm.Write(asnWriter);
            asnWriter.WriteBitString(this.Signature.Span);
            asnWriter.PopSequence();
        }
    }
}

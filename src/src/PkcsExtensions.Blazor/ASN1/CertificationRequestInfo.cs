using PkcsExtensions.ASN1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PkcsExtensions.Blazor.ASN1
{
    // https://tools.ietf.org/html/rfc2986

    internal class CertificationRequestInfo : IAsn1Node
    {
        public int Version
        {
            get;
            set;
        }

        public X509Name Name
        {
            get;
            set;
        }

        public SubjectPublicKeyInfo SubjectPKInfo
        {
            get;
            set;
        }

        public IEnumerable<IAsn1Node> Attributes
        {
            get;
            set;
        }

        public CertificationRequestInfo(X509Name name, SubjectPublicKeyInfo spki, IEnumerable<IAsn1Node> attributes)
        {
            this.Version = 0;
            this.Name = name;
            this.SubjectPKInfo = spki;
            this.Attributes = attributes;
        }

        public void Write(AsnWriter asnWriter)
        {
            asnWriter.PushSequence();
            asnWriter.WriteInteger((long)this.Version);
            this.Name.Write(asnWriter);
            this.SubjectPKInfo.Write(asnWriter);

            asnWriter.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 0, true));
            if (this.Attributes != null)
            {
                foreach (IAsn1Node attribute in this.Attributes)
                {
                    attribute.Write(asnWriter);
                }
            }
            asnWriter.PopSetOf();

            asnWriter.PopSequence();
        }
    }
}

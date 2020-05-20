using PkcsExtenions.ASN1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PkcsExtenions.Blazor.ASN1
{
    internal class AsnNull: IAsn1Node
    {
        public AsnNull()
        {

        }

        public AsnNull(AsnReader asnReader)
        {
            if (asnReader == null) throw new ArgumentNullException(nameof(asnReader));

            asnReader.ReadNull();
        }

        public void Write(AsnWriter asnWriter)
        {
            if (asnWriter == null) throw new ArgumentNullException(nameof(asnWriter));

            asnWriter.WriteNull();
        }
    }
}

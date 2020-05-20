using PkcsExtenions.ASN1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PkcsExtenions.Blazor.ASN1
{
    internal interface IAsn1Node
    {
        void Write(AsnWriter asnWriter);
    }
}

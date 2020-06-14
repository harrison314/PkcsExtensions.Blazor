using PkcsExtensions.ASN1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PkcsExtensions.Blazor.ASN1
{
    public interface IAsn1Node
    {
        void Write(AsnWriter asnWriter);
    }
}

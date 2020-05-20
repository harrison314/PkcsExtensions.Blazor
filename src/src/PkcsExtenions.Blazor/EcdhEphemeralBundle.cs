using PkcsExtenions.Blazor.Jwk;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PkcsExtenions.Blazor
{
    public class EcdhEphemeralBundle
    {
        public byte[] SharedSecret
        {
            get;
            internal set;
        }

        public JsonWebKey EphemeralDhmPublicKey
        {
            get;
            internal set;
        }

        internal EcdhEphemeralBundle()
        {

        }
    } 
}

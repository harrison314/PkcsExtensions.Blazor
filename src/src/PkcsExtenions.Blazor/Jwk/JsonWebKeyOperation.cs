using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PkcsExtenions.Blazor.Jwk
{
    public static class JsonWebKeyOperation
    {
        public const string Encrypt = "encrypt";

        public const string Decrypt = "decrypt";

        public const string Sign = "sign";

        public const string Verify = "verify";

        public const string Wrap = "wrapKey";

        public const string Unwrap = "unwrapKey";

        public const string DeriveBits = "deriveBits";
    }
}

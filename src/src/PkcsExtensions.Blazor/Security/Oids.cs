using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PkcsExtensions.Blazor.Security
{
    internal static class Oids
    {
        public const string Sha1WithRsaEncryption = "1.2.840.113549.1.1.5";
        public const string Sha256WithRsaEncryption = "1.2.840.113549.1.1.11";
        public const string Sha384WithRsaEncryption = "1.2.840.113549.1.1.12";
        public const string Sha512WithRsaEncryption = "1.2.840.113549.1.1.13";
    }
}

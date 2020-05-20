using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PkcsExtenions.Blazor.Jwk
{
    internal static class Base64Url
    {
        public static string EncodeToString(byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            StringBuilder sb = new StringBuilder(Convert.ToBase64String(data));
            sb.Replace('/', '_');
            sb.Replace('+', '-');

            while (sb.Length > 0 && sb[sb.Length - 1] == '=')
            {
                sb.Length--;
            }

            return sb.ToString();
        }

        public static byte[] EncodeFromString(string base64Url)
        {
            if (base64Url == null) throw new ArgumentNullException(nameof(base64Url));

            StringBuilder sb = new StringBuilder(base64Url);
            sb.Replace("_", "/");
            sb.Replace("-", "+");

            switch (sb.Length % 4)
            {
                case 0:
                    break;

                case 2:
                    sb.Append("==");
                    break;

                case 3:
                    sb.Append('=');
                    break;

                default:
                    throw new ArgumentOutOfRangeException(nameof(base64Url), "Illegal base64url string!");
            }

            string base64 = sb.ToString();
            return Convert.FromBase64String(base64);
        }
    }
}

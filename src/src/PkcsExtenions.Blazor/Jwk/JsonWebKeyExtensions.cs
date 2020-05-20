using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PkcsExtenions.Blazor.Jwk
{
    public static class JsonWebKeyExtensions
    {
        public static JsonWebKey AsPublicKey(this JsonWebKey jsonWebKey)
        {
            if (!jsonWebKey.HasPrivateKey())
            {
                return jsonWebKey;
            }
            else
            {
                JsonWebKey other = new JsonWebKey(jsonWebKey);
                switch (other.Kty)
                {
                    case "EC":
                    case "EC-HSM":
                        other.D = null;
                        break;
                    case "RSA":
                    case "RSA-HSM":
                        other.D = null;
                        other.DP = null;
                        other.DQ = null;
                        other.QI = null;
                        other.P = null;
                        other.Q = null;
                        break;
                    default:
                        throw new InvalidOperationException($"Key type {other.Kty} is not asymetric key.");
                }

                return other;
            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace PkcsExtenions.Blazor.Jwk
{
    public class JsonWebKey
    {
        // public IDictionary<string, object> ExtensionData
        // {
        //     get;
        //     set;
        // }

        public string Kid
        {
            get;
            set;
        }

        public string Kty
        {
            get;
            set;
        }

        public IList<string> KeyOps
        {
            get;
            set;
        }

        public byte[] N
        {
            get;
            set;
        }

        public byte[] E
        {
            get;
            set;
        }

        public byte[] DP
        {
            get;
            set;
        }

        public byte[] DQ
        {
            get;
            set;
        }

        public byte[] QI
        {
            get;
            set;
        }

        public byte[] P
        {
            get;
            set;
        }

        public byte[] Q
        {
            get;
            set;
        }

        public string CurveName
        {
            get;
            set;
        }

        public byte[] X
        {
            get;
            set;
        }

        public byte[] Y
        {
            get;
            set;
        }

        public byte[] D
        {
            get;
            set;
        }

        public byte[] K
        {
            get;
            set;
        }

        public byte[] T
        {
            get;
            set;
        }

        public JsonWebKey()
        {

        }

        public JsonWebKey(JsonWebKey other)
        {
            if (other == null) throw new ArgumentNullException(nameof(other));

            this.CurveName = other.CurveName;
            this.D = other.D;
            this.DP = other.DP;
            this.DQ = other.DQ;
            this.E = other.E;
            this.K = other.K;
            this.KeyOps = other.KeyOps;
            this.Kid = other.Kid;
            this.Kty = other.Kty;
            this.N = other.N;
            this.P = other.P;
            this.Q = other.Q;
            this.QI = other.QI;
            this.T = other.T;
            this.X = other.X;
            this.Y = other.Y;
        }

        public JsonWebKey(Aes aesProvider)
        {
            if (aesProvider == null) throw new ArgumentNullException(nameof(aesProvider));

            this.Kty = "oct";
            this.K = aesProvider.Key;
        }

        public JsonWebKey(RSAParameters rsaParameters)
        {
            this.Kty = "RSA";
            this.E = rsaParameters.Exponent;
            this.N = rsaParameters.Modulus;
            this.D = rsaParameters.D;
            this.DP = rsaParameters.DP;
            this.DQ = rsaParameters.DQ;
            this.QI = rsaParameters.InverseQ;
            this.P = rsaParameters.P;
            this.Q = rsaParameters.Q;
        }

        public JsonWebKey(ECParameters ecParameters)
        {
            if (!ecParameters.Curve.IsNamed)
            {
                throw new ArgumentException("ecParameters can not cotians named curve");
            }

            this.Kty = "EC";
            this.CurveName = ecParameters.Curve.Oid?.Value switch
            {
                "1.2.840.10045.3.1.7" => "P-256",
                "1.3.132.0.34" => "P-384",
                "1.3.132.0.35" => "P-521",
                _ => throw new NotSupportedException($"Not support curve with OID {ecParameters.Curve.Oid?.Value}")
            };

            this.KeyOps = new List<string>();
            if (ecParameters.D != null)
            {
                this.KeyOps.Add("sign");
            }


            this.D = ecParameters.D;
            this.X = ecParameters.Q.X;
            this.Y = ecParameters.Q.Y;
        }

        public bool HasPrivateKey()
        {
            switch (this.Kty)
            {
                case "oct":
                    return this.K != null;
                case "EC":
                case "EC-HSM":
                    return this.D != null;
                case "RSA":
                case "RSA-HSM":
                    if (this.D != null && this.DP != null && this.DQ != null && this.QI != null && this.P != null)
                    {
                        return this.Q != null;
                    }
                    return false;
                default:
                    return false;
            }
        }

        public Aes ToAes()
        {
            if (!this.Kty.Equals("oct"))
            {
                throw new InvalidOperationException("key is not an octet key");
            }
            if (this.K == null)
            {
                throw new InvalidOperationException("key does not contain a value");
            }
            Aes aes = Aes.Create();
            if (aes != null)
            {
                aes.Key = this.K;
            }
            return aes;
        }

        public RSAParameters ToRSAParameters(bool includePrivateParameters = false)
        {
            if (this.Kty != "RSA" && this.Kty != "RSA-HSM")
            {
                throw new InvalidOperationException("JsonWebKey is not a RSA key");
            }
            JsonWebKey.VerifyNonZero("N", this.N);
            JsonWebKey.VerifyNonZero("E", this.E);
            RSAParameters rSAParameters = default(RSAParameters);
            rSAParameters.Modulus = JsonWebKey.RemoveLeadingZeros(this.N);
            rSAParameters.Exponent = JsonWebKey.ForceLength("E", this.E, 4);
            if (includePrivateParameters)
            {
                int num = rSAParameters.Modulus.Length * 8;
                rSAParameters.D = JsonWebKey.ForceLength("D", this.D, num / 8);
                rSAParameters.DP = JsonWebKey.ForceLength("DP", this.DP, num / 16);
                rSAParameters.DQ = JsonWebKey.ForceLength("DQ", this.DQ, num / 16);
                rSAParameters.InverseQ = JsonWebKey.ForceLength("QI", this.QI, num / 16);
                rSAParameters.P = JsonWebKey.ForceLength("P", this.P, num / 16);
                rSAParameters.Q = JsonWebKey.ForceLength("Q", this.Q, num / 16);
            }

            return rSAParameters;
        }

        public ECParameters ToECParameters(bool includePrivateParameters = false)
        {
            if (this.Kty != "EC" && this.Kty != "EC-HSM")
            {
                throw new InvalidOperationException("JsonWebKey is not a RSA key");
            }

            ECParameters ecParameters = new ECParameters();
            ecParameters.Curve = this.CurveName switch
            {
                "P-256" => ECCurve.NamedCurves.nistP256,
                "P-384" => ECCurve.NamedCurves.nistP384,
                "P-521" => ECCurve.NamedCurves.nistP521,
                _ => throw new NotSupportedException()
            };

            if (includePrivateParameters)
            {
                ecParameters.D = this.D;
            }

            ecParameters.Q.X = this.X;
            ecParameters.Q.Y = this.Y;

            ecParameters.Validate();
            return ecParameters;
        }

        private static void VerifyNonZero(string name, byte[] value)
        {
            if (value != null)
            {
                for (int i = 0; i < value.Length; i++)
                {
                    if (value[i] != 0)
                    {
                        return;
                    }
                }
            }
            throw new ArgumentException(string.Format("Value of \"{0}\" must be non-zero.", name));
        }

        private static byte[] RemoveLeadingZeros(byte[] value)
        {
            if (value != null && value.Length > 1 && value[0] == 0)
            {
                for (int i = 1; i < value.Length; i++)
                {
                    if (value[i] != 0)
                    {
                        byte[] array = new byte[value.Length - i];
                        Array.Copy(value, i, array, 0, array.Length);
                        return array;
                    }
                }
                return new byte[1];
            }
            return value;
        }

        private static byte[] ForceLength(string name, byte[] value, int requiredLength)
        {
            if (value != null && value.Length != 0)
            {
                if (value.Length == requiredLength)
                {
                    return value;
                }
                if (value.Length < requiredLength)
                {
                    byte[] array = new byte[requiredLength];
                    Array.Copy(value, 0, array, requiredLength - value.Length, value.Length);
                    return array;
                }
                int num = value.Length - requiredLength;
                for (int i = 0; i < num; i++)
                {
                    if (value[i] != 0)
                    {
                        throw new ArgumentException(string.Format("Invalid length of \"{0}\": expected at most {1} bytes, found {2} bytes.", name, requiredLength, value.Length - i));
                    }
                }
                byte[] array2 = new byte[requiredLength];
                Array.Copy(value, value.Length - requiredLength, array2, 0, requiredLength);
                return array2;
            }
            throw new ArgumentException(string.Format("Value of \"{0}\" is null or empty.", name));
        }

        public override string ToString()
        {
            return this.ToString(false);
        }

        public string ToString(bool intended)
        {
            JsonWebKeyProxy proxy = new JsonWebKeyProxy(this);
            return JsonSerializer.Serialize(proxy, typeof(JsonWebKeyProxy), new JsonSerializerOptions()
            {
                IgnoreNullValues = true,
                WriteIndented = intended
            });
        }

        public static JsonWebKey Parse(string jsonText)
        {
            if (jsonText == null) throw new ArgumentNullException(nameof(jsonText));

            JsonWebKeyProxy proxy = JsonSerializer.Deserialize<JsonWebKeyProxy>(jsonText, new JsonSerializerOptions()
            {
                IgnoreNullValues = true
            });
            JsonWebKey jsonWebKey = new JsonWebKey();
            jsonWebKey.AplyProxy(proxy);

            return jsonWebKey;
        }

        internal void AplyProxy(JsonWebKeyProxy proxy)
        {
            if (proxy == null)
            {
                throw new ArgumentNullException(nameof(proxy));
            }

            this.CurveName = proxy.CurveName;
            this.D = this.TryEncode(proxy.D);
            this.DP = this.TryEncode(proxy.DP);
            this.DQ = this.TryEncode(proxy.DQ);
            this.E = this.TryEncode(proxy.E);
            // this.ExtensionData = proxy.ExtensionData;
            this.K = this.TryEncode(proxy.K);
            this.KeyOps = proxy.KeyOps;
            this.Kid = proxy.Kid;
            this.Kty = proxy.Kty;
            this.N = this.TryEncode(proxy.N);
            this.P = this.TryEncode(proxy.P);
            this.Q = this.TryEncode(proxy.Q);
            this.QI = this.TryEncode(proxy.QI);
            this.T = this.TryEncode(proxy.T);
            this.X = this.TryEncode(proxy.X);
            this.Y = this.TryEncode(proxy.Y);
        }

        private byte[] TryEncode(string value)
        {
            return string.IsNullOrEmpty(value) ? null : Base64Url.EncodeFromString(value);
        }
    }
}

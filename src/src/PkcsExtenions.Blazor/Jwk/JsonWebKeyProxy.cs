using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace PkcsExtenions.Blazor.Jwk
{
    public class JsonWebKeyProxy
    {

        internal const string Property_Kid = "kid";

        internal const string Property_Kty = "kty";

        internal const string Property_KeyOps = "key_ops";

        internal const string Property_D = "d";

        internal const string Property_DP = "dp";

        internal const string Property_DQ = "dq";

        internal const string Property_E = "e";

        internal const string Property_QI = "qi";

        internal const string Property_N = "n";

        internal const string Property_P = "p";

        internal const string Property_Q = "q";

        internal const string Property_Crv = "crv";

        internal const string Property_X = "x";

        internal const string Property_Y = "y";

        internal const string Property_K = "k";

        internal const string Property_T = "key_hsm";

        //[JsonExtensionData]
        //public IDictionary<string, object> ExtensionData
        //{
        //    get;
        //    set;
        //}

        [JsonPropertyName(Property_Kid)]
        public string Kid
        {
            get;
            set;
        }

        [JsonPropertyName(Property_Kty)]
        public string Kty
        {
            get;
            set;
        }

        [JsonPropertyName(Property_KeyOps)]
        public IList<string> KeyOps
        {
            get;
            set;
        }

        [JsonPropertyName(Property_N)]
        public string N
        {
            get;
            set;
        }

        [JsonPropertyName(Property_E)]
        public string E
        {
            get;
            set;
        }

        [JsonPropertyName(Property_DP)]
        public string DP
        {
            get;
            set;
        }

        [JsonPropertyName(Property_DQ)]
        public string DQ
        {
            get;
            set;
        }

        [JsonPropertyName(Property_QI)]
        public string QI
        {
            get;
            set;
        }

        [JsonPropertyName(Property_P)]
        public string P
        {
            get;
            set;
        }

        [JsonPropertyName(Property_Q)]
        public string Q
        {
            get;
            set;
        }

        [JsonPropertyName(Property_Crv)]
        public string CurveName
        {
            get;
            set;
        }

        [JsonPropertyName(Property_X)]
        public string X
        {
            get;
            set;
        }

        [JsonPropertyName(Property_Y)]
        public string Y
        {
            get;
            set;
        }

        [JsonPropertyName(Property_D)]
        public string D
        {
            get;
            set;
        }

        [JsonPropertyName(Property_K)]
        public string K
        {
            get;
            set;
        }

        [JsonPropertyName(Property_T)]
        public string T
        {
            get;
            set;
        }

        public JsonWebKeyProxy()
        {

        }

        internal JsonWebKeyProxy(JsonWebKey jsonWebKey)
        {
            if (jsonWebKey == null)
            {
                throw new ArgumentNullException(nameof(jsonWebKey));
            }

            this.CurveName = jsonWebKey.CurveName;
            this.D = this.TryEncode(jsonWebKey.D);
            this.DP = this.TryEncode(jsonWebKey.DP);
            this.DQ = this.TryEncode(jsonWebKey.DQ);
            this.E = this.TryEncode(jsonWebKey.E);
            //this.ExtensionData = jsonWebKey.ExtensionData;
            this.K = this.TryEncode(jsonWebKey.K);
            this.KeyOps = jsonWebKey.KeyOps;
            this.Kid = jsonWebKey.Kid;
            this.Kty = jsonWebKey.Kty;
            this.N = this.TryEncode(jsonWebKey.N);
            this.P = this.TryEncode(jsonWebKey.P);
            this.Q = this.TryEncode(jsonWebKey.Q);
            this.QI = this.TryEncode(jsonWebKey.QI);
            this.T = this.TryEncode(jsonWebKey.T);
            this.X = this.TryEncode(jsonWebKey.X);
            this.Y = this.TryEncode(jsonWebKey.Y);
        }

        private string TryEncode(byte[] data)
        {
            if (data is null)
            {
                return null;
            }
            else
            {
                return Base64Url.EncodeToString(data);
            }
        }
    }
}

using PkcsExtenions.ASN1;
using PkcsExtenions.Blazor.ASN1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace PkcsExtenions.Blazor.ASN1
{
    internal static class PkcsRsaConvertor
    {
        public static RSAParameters PrivateKeyToRsaParams(ReadOnlyMemory<byte> data)
        {
            RSAParameters rsaParams = new RSAParameters();

            AsnReader octedReader = new AsnReader(data, AsnEncodingRules.DER);
            AsnReader sequenceReader = octedReader.ReadSequence();
            sequenceReader.GetIntegerBytes().ToArray();
            rsaParams.Modulus = ToPositiveInteger(sequenceReader.GetIntegerBytes().Span);
            rsaParams.Exponent = ToPositiveInteger(sequenceReader.GetIntegerBytes().Span);
            rsaParams.D = ToPositiveInteger(sequenceReader.GetIntegerBytes().Span);
            rsaParams.P = ToPositiveInteger(sequenceReader.GetIntegerBytes().Span);
            rsaParams.Q = ToPositiveInteger(sequenceReader.GetIntegerBytes().Span);
            rsaParams.DP = ToPositiveInteger(sequenceReader.GetIntegerBytes().Span);
            rsaParams.DQ = ToPositiveInteger(sequenceReader.GetIntegerBytes().Span);
            rsaParams.InverseQ = ToPositiveInteger(sequenceReader.GetIntegerBytes().Span);

            return rsaParams;
        }

        public static RSAParameters PublicKeyToRsaParams(ReadOnlyMemory<byte> data)
        {
            RSAParameters rsaParams = new RSAParameters();

            AsnReader octedReader = new AsnReader(data, AsnEncodingRules.DER);
            AsnReader sequenceReader = octedReader.ReadSequence();
            rsaParams.Modulus = ToPositiveInteger(sequenceReader.GetIntegerBytes().Span);
            rsaParams.Exponent = ToPositiveInteger(sequenceReader.GetIntegerBytes().Span);

            return rsaParams;
        }

        public static byte[] RsaParamsToPrivateKey(RSAParameters rsaParams)
        {
            using AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);
            writer.PushSequence();

            writer.WriteInteger(0);
            writer.WriteInteger(rsaParams.Modulus, true);
            writer.WriteInteger(rsaParams.Exponent, true);
            writer.WriteInteger(rsaParams.D, true);
            writer.WriteInteger(rsaParams.P, true);
            writer.WriteInteger(rsaParams.Q, true);
            writer.WriteInteger(rsaParams.DP, true);
            writer.WriteInteger(rsaParams.DQ, true);
            writer.WriteInteger(rsaParams.InverseQ, true);

            writer.PopSequence();

            return writer.Encode();
        }

        public static byte[] RsaParamsToPublicKey(RSAParameters rsaParams)
        {
            using AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);
            writer.PushSequence();

            writer.WriteInteger(rsaParams.Modulus, true);
            writer.WriteInteger(rsaParams.Exponent, true);

            writer.PopSequence();

            return writer.Encode();
        }

        private static byte[] ToPositiveInteger(ReadOnlySpan<byte> data)
        {
            int start = 0;
            for (int i = 0; i < data.Length; i++)
            {
                if (data[i] == 0)
                {
                    start++;
                }
                else
                {
                    break;
                }
            }

            return data.Slice(start).ToArray();
        }
    }
}

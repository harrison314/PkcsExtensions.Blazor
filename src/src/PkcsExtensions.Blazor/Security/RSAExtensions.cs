using PkcsExtensions.ASN1;
using PkcsExtensions.Blazor.ASN1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace PkcsExtensions.Blazor.Security
{
    public static class RSAExtensions
    {
        public static void ManagedImportPkcs8PrivateKey(this RSA rsa, ReadOnlyMemory<byte> privateKeyInfoBytes)
        {
            AsnReader reader = new AsnReader(privateKeyInfoBytes, AsnEncodingRules.DER);
            PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(reader);

            RSAParameters parameters = PkcsRsaConvertor.PrivateKeyToRsaParams(privateKeyInfo.PrivateKey);
            rsa.ImportParameters(parameters);
        }

        public static byte[] ManagedExportPkcs8PrivateKey(this RSA rsa)
        {
            PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(rsa.ExportParameters(true));
            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);
            privateKeyInfo.Write(writer);

            return writer.Encode();
        }

        public static byte[] ManagedExportPkcs8PrivateKey(this RSA rsa, AsnFormat format)
        {
            return format switch
            {
                AsnFormat.Der => rsa.ManagedExportPkcs8PrivateKey(),
                AsnFormat.Pem => PemFormater.ToPemBytes(rsa.ManagedExportPkcs8PrivateKey(), "RSA PRIVATE KEY"),
                _ => throw new NotImplementedException()
            };
        }

        public static void ManagedImportSubjectPublicKeyInfo(this RSA rsa, ReadOnlyMemory<byte> publicSubjectKeyInfoBytes)
        {
            AsnReader reader = new AsnReader(publicSubjectKeyInfoBytes, AsnEncodingRules.DER);
            SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(reader);

            RSAParameters parameters = PkcsRsaConvertor.PublicKeyToRsaParams(subjectPublicKeyInfo.PublicKey);
            rsa.ImportParameters(parameters);
        }

        public static byte[] ManagedExportSubjectPublicKeyInfo(this RSA rsa)
        {
            SubjectPublicKeyInfo privateKeyInfo = new SubjectPublicKeyInfo(rsa.ExportParameters(false));
            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);
            privateKeyInfo.Write(writer);

            return writer.Encode();
        }

        public static byte[] ManagedExportSubjectPublicKeyInfo(this RSA rsa, AsnFormat format)
        {
            return format switch
            {
                AsnFormat.Der => rsa.ManagedExportSubjectPublicKeyInfo(),
                AsnFormat.Pem => PemFormater.ToPemBytes(rsa.ManagedExportSubjectPublicKeyInfo(), "PUBLIC KEY"),
                _ => throw new NotImplementedException()
            };
        }
    }
}

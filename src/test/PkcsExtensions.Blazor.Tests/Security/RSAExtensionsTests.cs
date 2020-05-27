using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using PkcsExtensions.Blazor.Security;

namespace PkcsExtensions.Blazor.Tests.Security
{
    [TestClass]
    public class RSAExtensionsTests
    {
        [TestMethod]
        public void ManagedImportPkcs8PrivateKey()
        {
            using RSA rsa = RSA.Create(2048);
            byte[] exported = rsa.ExportPkcs8PrivateKey();

            using RSA rsaWithPrivate = RSA.Create();
            rsaWithPrivate.ManagedImportPkcs8PrivateKey(exported);

            this.CheckRsa(rsaWithPrivate, rsa);
        }

        [TestMethod]
        public void ManagedExportPkcs8PrivateKey()
        {
            using RSA rsa = RSA.Create(2048);
            byte[] exported = rsa.ManagedExportPkcs8PrivateKey();

            using RSA rsaWithPrivate = RSA.Create();
            rsaWithPrivate.ImportPkcs8PrivateKey(exported, out _);

            this.CheckRsa(rsaWithPrivate, rsa);
        }

        [DataTestMethod]
        [DataRow(AsnFormat.Der)]
        [DataRow(AsnFormat.Pem)]
        public void ManagedExportPkcs8PrivateKey2(AsnFormat format)
        {
            using RSA rsa = RSA.Create(2048);
            byte[] exported = rsa.ManagedExportPkcs8PrivateKey(format);
            ReadOnlySpan<byte> exportedDer = PemFormater.FromDerOrPem(exported);
            
            using RSA rsaWithPrivate = RSA.Create();
            rsaWithPrivate.ImportPkcs8PrivateKey(exportedDer, out _);

            this.CheckRsa(rsaWithPrivate, rsa);

            this.CheckFormat(format, exported);
        }

        [TestMethod]
        public void ManagedImportSubjectPublicKeyInfo()
        {
            using RSA rsa = RSA.Create(2048);
            byte[] exported = rsa.ExportSubjectPublicKeyInfo();

            using RSA rsaWithPublicKey = RSA.Create();
            rsaWithPublicKey.ManagedImportSubjectPublicKeyInfo(exported);

            this.CheckRsa(rsa, rsaWithPublicKey);
        }

        [TestMethod]
        public void ManagedExportSubjectPublicKeyInfo()
        {
            using RSA rsa = RSA.Create(2048);
            byte[] exported = rsa.ManagedExportSubjectPublicKeyInfo();

            using RSA rsaWithPublicKey = RSA.Create();
            rsaWithPublicKey.ImportSubjectPublicKeyInfo(exported, out _);

            this.CheckRsa(rsa, rsaWithPublicKey);
        }


        [DataTestMethod]
        [DataRow(AsnFormat.Der)]
        [DataRow(AsnFormat.Pem)]
        public void ManagedExportSubjectPublicKeyInfo(AsnFormat format)
        {
            using RSA rsa = RSA.Create(2048);
            byte[] exported = rsa.ManagedExportSubjectPublicKeyInfo(format);
            ReadOnlySpan<byte> exportedDer = PemFormater.FromDerOrPem(exported);

            using RSA rsaWithPrivate = RSA.Create();
            rsaWithPrivate.ImportSubjectPublicKeyInfo(exportedDer, out _);

            this.CheckRsa(rsaWithPrivate, rsa);

            this.CheckFormat(format, exported);
        }

        private void CheckRsa(RSA signer, RSA verifier)
        {
            byte[] hash = HexConvertor.GetBytes("540fb8eb12db464515e45d587376526532e0472f3bbd242a8f86c16c51614ce0");
            byte[] signature = signer.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            bool isValid = verifier.VerifyHash(hash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            Assert.IsTrue(isValid, "Signer and verifier has diferent keys.");
        }

        private void CheckFormat(AsnFormat format, byte[] data)
        {
            byte[] pemStart = Encoding.ASCII.GetBytes("-----BEGIN ");
            if (format == AsnFormat.Der)
            {
                if (this.StatWith(data, pemStart))
                {
                    Assert.Fail("Excepted data format is {0} but is not match to {1}", format, Convert.ToBase64String(data));
                }
            }

            if (format == AsnFormat.Pem)
            {
                if (!this.StatWith(data, pemStart))
                {
                    Assert.Fail("Excepted data format is {0} but is not match to {1}", format, Convert.ToBase64String(data));
                }
            }
        }

        private bool StatWith(byte[] data, byte[] start)
        {
            if (data.Length < start.Length)
            {
                return false;
            }
            else
            {
                for (int i = 0; i < start.Length; i++)
                {
                    if (data[i] != start[i])
                    {
                        return false;
                    }
                }

                return true;
            }
        }
    }
}

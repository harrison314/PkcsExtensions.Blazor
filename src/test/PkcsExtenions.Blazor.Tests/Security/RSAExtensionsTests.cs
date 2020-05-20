using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using PkcsExtenions.Blazor.Security;

namespace PkcsExtenions.Blazor.Tests.Security
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

        private void CheckRsa(RSA signer, RSA verifier)
        {
            byte[] hash = HexConvertor.GetBytes("540fb8eb12db464515e45d587376526532e0472f3bbd242a8f86c16c51614ce0");
            byte[] signature = signer.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            bool isValid = signer.VerifyHash(hash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            Assert.IsTrue(isValid, "Signer and verifier has diferent keys.");
        }
    }
}

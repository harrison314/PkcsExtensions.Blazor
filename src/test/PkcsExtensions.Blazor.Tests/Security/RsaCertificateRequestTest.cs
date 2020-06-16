using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Pkcs;
using PkcsExtensions.ASN1;
using PkcsExtensions.Blazor.ASN1;
using PkcsExtensions.Blazor.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace PkcsExtensions.Blazor.Tests.Security
{
    [TestClass]
    public class RsaCertificateRequestTest
    {
        [TestMethod]
        public void X509NameEncode()
        {
            X509Name name = new X509Name();
            name.Add(X509NameOids.CommonName, "Test");
            name.Add(X509NameOids.CountryName, "SK");
            name.Add(X509NameOids.SerialNumber, "SK-123456789");

            using AsnWriter asnWriter = new AsnWriter(AsnEncodingRules.DER);
            name.Write(asnWriter);

            Assert.IsNotNull(asnWriter.Encode());
        }

        [TestMethod]
        public async Task CreateRequest()
        {
            X509Name name = new X509Name();
            name.Add(X509NameOids.CommonName, "Test");
            name.Add(X509NameOids.CountryName, "SK");
            name.Add(X509NameOids.SerialNumber, "SK-123456789");

            using RSA rsa = RSA.Create(2048);

            RsaCertificateRequest request = new RsaCertificateRequest(name, rsa);

            byte[] requestData = await request.Generate(AsnFormat.Der);

            Pkcs10CertificationRequest pkcs10 = new Pkcs10CertificationRequest(requestData);

            Assert.IsNotNull(pkcs10.GetPublicKey());
            Assert.IsNotNull(pkcs10.GetSignatureOctets());
            Assert.IsTrue(pkcs10.Verify(), "Signature is not verified.");
        }

        [TestMethod]
        public async Task CreateRequestWithAttribute()
        {
            X509Name name = new X509Name();
            name.Add(X509NameOids.CommonName, "Test");
            name.Add(X509NameOids.CountryName, "SK");
            name.Add(X509NameOids.SerialNumber, "SK-123456789");

            using RSA rsa = RSA.Create(2048);

            RsaCertificateRequest request = new RsaCertificateRequest(name,
                rsa,
                new IAsn1Node[]{
                    new CustomAttribute("test test test")
            });

            byte[] requestData = await request.Generate(AsnFormat.Der);

            Pkcs10CertificationRequest pkcs10 = new Pkcs10CertificationRequest(requestData);

            Assert.IsNotNull(pkcs10.GetPublicKey());
            Assert.IsNotNull(pkcs10.GetSignatureOctets());
            Assert.IsTrue(pkcs10.Verify(), "Signature is not verified.");
        }

        class CustomAttribute : IAsn1Node
        {
            private readonly string name;

            public CustomAttribute(string name)
            {
                this.name = name;
            }

            public void Write(AsnWriter asnWriter)
            {
                asnWriter.PushSequence();
                asnWriter.WriteObjectIdentifier("1.4.5.8.6.9.5.4.2.1.1");
                asnWriter.PushSetOf();
                asnWriter.PushSequence();
                asnWriter.WriteCharacterString(UniversalTagNumber.PrintableString, this.name);
                asnWriter.PopSequence();
                asnWriter.PopSetOf();
                asnWriter.PopSequence();
            }
        }
    }
}

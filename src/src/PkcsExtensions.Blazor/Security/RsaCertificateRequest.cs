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

    public class RsaCertificateRequest
    {
        private readonly CertificationRequestInfo certificationRequestInfo;
        private readonly RsaCertificateRequestSigner signer;

        public HashAlgorithmName SignatureHash
        {
            get;
            set;
        }

        public RsaCertificateRequest(X509Name x509Name, RSA rsa, IEnumerable<IAsn1Node> attributes = null)
            : this(x509Name, rsa, (hash, hashName) => new ValueTask<byte[]>(rsa.SignHash(hash, hashName, RSASignaturePadding.Pkcs1)), attributes)
        {

        }

        public RsaCertificateRequest(X509Name x509Name, RSA rsa, RsaCertificateRequestSigner signer, IEnumerable<IAsn1Node> attributes = null)
        {
            if (x509Name == null) throw new ArgumentNullException(nameof(x509Name));
            if (rsa == null) throw new ArgumentNullException(nameof(rsa));
            if (signer == null) throw new ArgumentNullException(nameof(signer));

            this.SignatureHash = HashAlgorithmName.SHA256;
            SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(rsa.ExportParameters(false));
            this.certificationRequestInfo = new CertificationRequestInfo(x509Name, subjectPublicKeyInfo, attributes);
            this.signer = signer;
        }

        public async ValueTask<byte[]> Generate(AsnFormat format)
        {
            byte[] sha256 = this.CreateHash();

            CertificationRequest request = new CertificationRequest();

            request.CertificationRequestInfo = this.certificationRequestInfo;
            request.Signature = await this.signer.Invoke(sha256, HashAlgorithmName.SHA256).ConfigureAwait(false);
            request.SignatureAlgorithm = new AlgorithmIdentifier(this.GetHashALgorithmRsaEncryptionOid());

            using AsnWriter asnWriter = new AsnWriter(AsnEncodingRules.DER);
            request.Write(asnWriter);
            byte[] derRequest = asnWriter.Encode();

            return format switch
            {
                AsnFormat.Der => derRequest,
                AsnFormat.Pem => PemFormater.ToPemBytes(derRequest, "CERTIFICATE REQUEST"),
                _ => throw new NotImplementedException()
            };
        }

        private byte[] CreateHash()
        {
            using AsnWriter asnWriter = new AsnWriter(AsnEncodingRules.DER);
            this.certificationRequestInfo.Write(asnWriter);

            using HashAlgorithm hashAlgorithm = HashAlgorithmConvertor.ToHashAlgorithm(this.SignatureHash);
            return hashAlgorithm.ComputeHash(asnWriter.Encode());
        }

        private string GetHashALgorithmRsaEncryptionOid()
        {
            if (HashAlgorithmName.SHA256.Equals(this.SignatureHash))
            {
                return Oids.Sha256WithRsaEncryption;
            }

            if (HashAlgorithmName.SHA384.Equals(this.SignatureHash))
            {
                return Oids.Sha384WithRsaEncryption;
            }

            if (HashAlgorithmName.SHA512.Equals(this.SignatureHash))
            {
                return Oids.Sha512WithRsaEncryption;
            }

            throw new NotSupportedException($"Hash algorithm {this.SignatureHash} is not supported.");
        }
    }
}

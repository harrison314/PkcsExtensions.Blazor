using Microsoft.JSInterop;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using PkcsExtenions.Blazor.WebCrypto;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace PkcsExtenions.Blazor.Tests
{
    [TestClass]
    public class WebCryptoProviderTests
    {
        [DataTestMethod]
        [DataRow(12, @"sTD9nS5NCKscng1G")]
        [DataRow(49, @"Zzf48MmU6YM9BQaZ21BX4UoOVRa52MxjheVMlVUx6fp/TQVnVcldqFczMCa4lC6+iQ==")]
        [DataRow(256, @"AKDxyngsUyhhfUqqq7gNtzMp6kEE6P2Hkci2ydKGgQ7I7SxgC4xI8Ok6bk1naWsZwrC4oEFRQFxZG14Bj9rlVmwFitkmXeXM6/mtT/G7bGquI+W6XWq20kGZWMtkGeauAkn67sYs051w00SZqXAlwm9Ix1iHh7eL/KG36sFiAOAQQUMc5HoEk71ieQ9n/u98Bam+c9i8WDhUkGB11+jPAU5ZU+LeK3OYZDWcgwI4HmrwF/2AjuhjOGqHs2czkZdCJtBXLBdZpbAmtRbZX1e+EnfObH/lowXDgZRvLjtQ4epeXy+xdhDnKEoGt+g3KCJOXErll3p/keVhGMCTgIshmw==")]
        public async Task GetRandomBytes(int count, string browserResult)
        {
            Mock<IJSRuntime> jsRuntimeMock = new Mock<IJSRuntime>(MockBehavior.Strict);
            jsRuntimeMock.Setup(t => t.InvokeAsync<string>("PkcsExtensionsBlazor_getRandomValues",
                It.IsAny<CancellationToken>(),
                It.Is<object[]>(q => (int)q[0] == count)))
                .ReturnsAsync(browserResult)
                .Verifiable();

            WebCryptoProvider provider = new WebCryptoProvider(jsRuntimeMock.Object);

            byte[] randomData = await provider.GetRandomBytes(count);

            Assert.AreEqual(count, randomData.Length);
            jsRuntimeMock.Verify();
        }

        [DataTestMethod]
        [DataRow(2048, @"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDfDLNX4i8u/OffMmlGE69igsZD00s1L7dmdIk15hGFlzzMIHd1bNgF7tYqt1XzKxY50ma0HYTQgtwPZDsMFOnbUpAzbe9WEXCQWIbahsAQ+J5w4Z5+Fn3MKWFia3aswjQtmBGDKoZmOO7CQikrn7WPV/av333x6bZtNcSZypdl4RFJ1ixYlLtUs52PHAFTk7oqwC3A7lUtd3EbJBEKfg/B0x/n8f7SHQ6/3R/b7vpCVu0wPyM50p84AuOKJNpnRVcwgQbVhSSWrJCz4ms6+NPYAnrx3kUdg6z+yqZ2DvMMrghC9ql4CpVumCjUFIYBbwA9Fi3fzSuxy2W4Zv1z76gvAgMBAAECggEALPsyNcBy9H5jQnM3oL66iVrHIgl76sNvMHXC8AAwO2knBSFtBdzH6dZjEWU8q5feWRXRyXQEg0pIl8AGWmbjTGwnkX+Tmx9UPH/l3i77j9CbnzcYz+O4RdJ4hbEXUzqs7B71NSb/yKClob5W8Cm6oyhBovEmxID13atQtRUSmCQ9cB0YtlSB8cwzgO68k2RxwyPCZ3iEWbxQgsBzqS7N9NUf/QAaQayyl5ZC1LfDMsCQc1UAg2MwMZ4o73eWhOVyFKYXjgZi4Lfhy5XIV9bXr/zQOy9fRKjZeoxvCFmegtZXxkISXYAj3129Uw49mw+MNhRVuNKQo9YbGlCSvDV6EQKBgQD5l80bW2FT+eeehBwmq9lU+pPVrd4oThSpoyrJkJRzJaJ2YQnvo+g0kChZLCyYa1mAhU+nGHZBAaNAuKde6bw04W9ZW0wijcAJO4k23coHVS/pL7brl4ra/wPHiPF+lx8yJ9LWQFcB4iYaivTzuRYKXw4mdjVdcI07Bc4d7sSw8QKBgQDkxnhFdoxBzPCZZdHF/DVyudpSc+nRJuy8O6DKUO1HlYQBAgdExWrIOaBVPQzK6R1rWkLxPehrVFdkphKNVIfYrErOAbIZhMTZm6rqySVk9D3w83KaHG8H9Jop9YTBoQlAOJqx15a6RMGJKVYaj+ppgIrgFEYCD6RS66C+9sHrHwKBgQDI+X3TkHI/b1Qc5N3SGcBHV/ngLj9bjvu+WL9kTIHschpuXdblWsLoSEfk/dfu50nLXgz0TJMz5wCwZb+HgofkwL2rYwNcM221QXZMcqxx2RtaFeyhqYXKr1s4uUFToJYjCcQQdwBYaOQrrUZuVdO0iDPZrodr9OwT4anFmnRQ0QKBgAlQOx040kTrfu//wSZ6OgLNpiGtLluhZgnTs5wI51/+qj0QRBN8pfg4wFo3/glUrCnupsMDbi7QZC5oxGCUjGM5wGHal9GKIilpuO+N+MO/XbYtcwDrH2oHfy8uG5V2ZNYEd+e9ixlSKz7WO/cg3L4myYCN0rvKvznQ9d5QVVypAoGABW8qQaN0HGQvqFfeN6jvUCMmuaJGMnHY+T+OPoatLTAAZ2HxoTcgCV2jcu6R7i0z3Ru5DTCnmu3a9J5OaFyzAEzJcUXxmZDIofi9RbGj2WA4ezNalJeAftMkgZ4I2Fzi5eikk4BEfD+FOqatBH7Socke/x9SCl2gmOj8iFo5/FE=", DisplayName = "RSA2048 Firefox")]
        [DataRow(2048, @"MIIEywIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCb9YCI7Nkdl52hyx17u1gGMKI/aVSR8SoISNgGIgiEovX33IwqMEyGlqg+iukR8yJTob9r2c8CNmYCjmahf/SBKzHnrWK9EwbAowX1Z1jVANAAz+MI5ZktZ4vSu1LNsuGW121sqhejTN59kc4CPHxx84JNdPmovvzj6yJQKhug6Zb4eg4k23js1Bji1TWmmoIFED0bO8mL+teXhS8QBfL1LFs9dzEOszK+AO9Gmu1BT3tchmwX2UCST9xi6DiS+w88sqU3bT0N0j5C0ExsdXVcc92DBEJPFk2qons3iBDoqMbeTn0odzuHiJAjS3Zin7pVLl+78rAN8pjiEPO7s2U1AgMBAAECggEAHjSlSV++CUo1IIHrWuyE9uXydp+a3o0729Dn7gAncDDzvKa9iupB2AtT2JEk5PIXIuV/4o6T1lTc2v/jhsH2hBHun3VoW0BVHXg1jjsO7Go03wNkcHOvgCi+3vii5+4OXR2qNtKWs20O5nkX0j0OyS8lfIT8WZ9r8WS4B5iwMzDdQnY8j+aDReZbG35hGINzp6d2TmeE0h2F2LDIlHfhdNWxY6rF4t7FQBAU6hoBU0s7cv+dAtRohjlNXu82OPXdcQ12DenS5VZGAAyUTd35zDrFZgfW02navk6sJwCCDAKFSaIk6Oipx+2eXPEczrtP36dg9vTO3ekFDPYKLsMu3QKBgQDGD8z62PC37/alG4ftx5hpG9jJm3W9lYUgaHYCXXopdvn7jJBUsbYKmQw/3sb95t0zRMsaNWVXPmkfB8IA1U9euOagtA78MvkTjRmIeWYn3OKmkC/mPs3jN/biO1QHXgRYOoPAYVNtj7oo7rJXYmTD2ovKP4piixmt57wfQ+b8SwKBgQDJlMPDuopN22mvMsAWs8ad4WOKX3y6tflRAWKGpPFwNlpskk2B/rUnCdeu5c1zxjdVgArdV2wUMYRyM/2DrBT2I3QZvj4mFoDsI+xydZXVgt0JMKQ4VwVFecLiEAQDzaGFm9Y4+Zw8zXwHWl1ECJkOqXD6FIYI7GRS8oY4Tnc0fwKBgGcMfYfeK5BoB5nr8xMiEAhP9sEeY2oaS0OLVirw28iLIJFilw2Z0K8+5gKtNDeSUHCGUG34bhuwWx1L+gJY+Yy9AzGFvW42TyV++lPpZd9Dq6Ehz+oprxGTYp5eY9/ZaMVG3JnRiYitiRwW5S9WADtuj+DQon2XBetXcKeLurh1AoGAbGFTr9SHr7ycYdoDdTFLRG9+OVOFmE1msqrv8jyUoyRWEbHHgnETrN2Z3Sso/2o/LfUd4kuyjFjjQRO65iSLUJtXPNAQUiIfRtc5tYCLArTNareAU9pVtzj0Et9RiUnx4ggbcZ6i5f4FBV8MbhvBTyTC3XJTblDKz94dVAC8DrkCgYBZ0NZxicaXk/s6YyGHmKhvvPdh1mdbTyaEKrqmw0azYdrG852rgG8dSIpmho+ubAyYOUZz0THE0DVTJwA3RABGF1AgcA1JhUVIc5NxNKbZ+JBl67KSid/Bfp997JaXryKBIr99CBGrDgcWFPMtxpB05bQk/Q49N6K5+IJ4RTJ6eKANMAsGA1UdDzEEAwIAgA==", DisplayName = "RSA2048 Edge")]
        public async Task GenerateRsaKeyPair(int keySize, string browserResult)
        {
            Mock<IJSRuntime> jsRuntimeMock = new Mock<IJSRuntime>(MockBehavior.Strict);
            jsRuntimeMock.Setup(t => t.InvokeAsync<string>("PkcsExtensionsBlazor_generateKeyRsa",
                It.IsAny<CancellationToken>(),
                It.Is<object[]>(q => (int)q[0] == keySize)))
                .ReturnsAsync(browserResult)
                .Verifiable();

            WebCryptoProvider provider = new WebCryptoProvider(jsRuntimeMock.Object);

            using RSA rsa = await provider.GenerateRsaKeyPair(keySize);

            byte[] hash = this.GenerateRandomData(32);
            byte[] signature = rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            bool verification = rsa.VerifyHash(hash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            Assert.IsTrue(verification, "Signature has not verified.");
        }

        [DataTestMethod]
        [DataRow(WebCryptoCurveName.NistP256, "P-256", @"qg77h9zqz5_57RIIDEBbTDsO2M78GqWMcOAAhtpgLYw", @"Tp7phbE16SZg-xp0VwMdjpOunZUsTokWdO45wwegL5Y", @"IHlXwjcxgxMegAGoLHu4SuJKJUhRGyl1x_iaLrBjxXo", DisplayName = "NistP256 in Firefox")]
        [DataRow(WebCryptoCurveName.NistP384, "P-384", @"JNdFlIjnweNwRKvbF8C2L2X3HzW2H8J6-Qq01d4gSyer5y2P2PxwqB-YRlmNOHvB", @"cbB7sE4QDBYnjW_g5Irbo4gUH6FjywA7tXiBZLumD0oUA6A6gnfNyr3mu75b-E-6", @"lCoyMrO4qDqUVGjh_had1HLMXGJS-yP4qpbui_w8XmgbGaKTNYzxyhDIx63ZhdGo", DisplayName = "NistP384 in Firefox")]
        [DataRow(WebCryptoCurveName.NistP521, "P-521", @"AUV4TS78ggLdRKXzlFFoVeE1y2lZuXRBLPR01VG4c-C0uTjTNNxwWvQX9TYQXonC2TS2n9rCD7VEbm9dKIulThIu", @"ANw6E_mpyFffjkNBTlWKBbZ_pKc9xrA3NmS3bEov9EixPMtVW5NDHZnkzICwiEpjlOX1lMmxuzSsENJU3LEcISvg", @"AHfkTRBfejeBbBbv31Fk1LNVpf3JtlArLJfslrhUiCgu-w1FEpXW6FknC6CqNLB-CA6P6p8SflGLUJLYk178MV2J", DisplayName = "NistP521 in Edge")]
        public async Task GenerateECDsaJwkKeyPair(WebCryptoCurveName curveName, string browserCurveName, string d, string x, string y)
        {
            Mock<IJSRuntime> jsRuntimeMock = new Mock<IJSRuntime>(MockBehavior.Strict);
            jsRuntimeMock.Setup(t => t.InvokeAsync<Dictionary<string, string>>("PkcsExtensionsBlazor_generateKeyEcdsa",
                It.IsAny<CancellationToken>(),
                It.Is<object[]>(q => (string)q[0] == browserCurveName)))
                .ReturnsAsync(new Dictionary<string, string>()
                {
                    {"kty", "EC" },
                    {"crv", browserCurveName },
                    {"d", d },
                    {"x", x },
                    {"y", y },
                })
                .Verifiable();

            WebCryptoProvider provider = new WebCryptoProvider(jsRuntimeMock.Object);

            Jwk.JsonWebKey jwk = await provider.GenerateECDsaJwkKeyPair(curveName);

            // .Net Core testing
            ECDsa ecdsa = ECDsa.Create(jwk.ToECParameters(true));
            byte[] hash = this.GenerateRandomData(32);
            byte[] signature = ecdsa.SignHash(hash);
            ecdsa.VerifyHash(hash, signature);
        }

        private byte[] GenerateRandomData(int size)
        {
            Random random = new Random(4871);
            byte[] data = new byte[size];
            random.NextBytes(data);

            return data;
        }
    }
}

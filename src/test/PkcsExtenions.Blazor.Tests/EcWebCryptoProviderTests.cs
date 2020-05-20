using Microsoft.JSInterop;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using PkcsExtenions.Blazor.Jwk;
using PkcsExtenions.Blazor.WebCrypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PkcsExtenions.Blazor.Tests
{
    [TestClass]
    public class EcWebCryptoProviderTests
    {
        [TestMethod]
        public async Task GetSharedDhmSecret()
        {
            Mock<IJSRuntime> jsRuntimeMock = new Mock<IJSRuntime>(MockBehavior.Strict);
            jsRuntimeMock.Setup(t => t.InvokeAsync<string>("PkcsExtensionsBlazor_sharedDhmSecret",
                It.IsAny<CancellationToken>(),
                It.IsNotNull<object[]>()))
                .ReturnsAsync("77XO/NCfjLD2dApcU90/84pj5hb9evvtpty286SXDXo=")
                .Verifiable();

            EcWebCryptoProvider ecWebCryptoProvider = new EcWebCryptoProvider(jsRuntimeMock.Object);

            JsonWebKey privateKey = this.GeneratePrivateEcKey();
            JsonWebKey publicKey = this.GeneratePrivateEcKey().AsPublicKey();

            byte[] data = await ecWebCryptoProvider.GetSharedDhmSecret(privateKey, publicKey);

            Assert.IsNotNull(data);
            jsRuntimeMock.VerifyAll();
        }

        [TestMethod]
        public async Task GetSharedEphemeralDhmSecret()
        {
            Mock<IJSRuntime> jsRuntimeMock = new Mock<IJSRuntime>(MockBehavior.Strict);
            jsRuntimeMock.Setup(t => t.InvokeAsync<Dictionary<string, string>>("PkcsExtensionsBlazor_sharedEphemeralDhmSecret",
                It.IsAny<CancellationToken>(),
                It.IsNotNull<object[]>()))
                .ReturnsAsync(()=> new Dictionary<string, string>
                {
                    {"kty", "EC" },
                    {"crv", "P-256" },
                    {"x",  "Tp7phbE16SZg-xp0VwMdjpOunZUsTokWdO45wwegL5Y" },
                    {"y", "IHlXwjcxgxMegAGoLHu4SuJKJUhRGyl1x_iaLrBjxXo" },
                    {"derivedBits", "77XO/NCfjLD2dApcU90/84pj5hb9evvtpty286SXDXo=" }
                })
                .Verifiable();

            EcWebCryptoProvider ecWebCryptoProvider = new EcWebCryptoProvider(jsRuntimeMock.Object);

            JsonWebKey publicKey = this.GeneratePrivateEcKey().AsPublicKey();

            EcdhEphemeralBundle bundle = await ecWebCryptoProvider.GetSharedEphemeralDhmSecret(publicKey);

            Assert.IsNotNull(bundle.EphemeralDhmPublicKey);
            Assert.IsNotNull(bundle.SharedSecret);
            jsRuntimeMock.VerifyAll();
        }

        private JsonWebKey GeneratePrivateEcKey()
        {
            using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            return new JsonWebKey(ecdsa.ExportParameters(true));
        }
    }
}

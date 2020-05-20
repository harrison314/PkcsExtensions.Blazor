using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using System;
using System.Threading.Tasks;

namespace PkcsExtenions.Blazor.Tests
{
    [TestClass]
    public class WebCryptoProviderExtensionsTests
    {
        [TestMethod]
        public async Task CreateRandomGeneratorWithSeed()
        {
            Random random = new Random(42);
            byte[] randomData = new byte[20];
            random.NextBytes(randomData);

            Mock<IWebCryptoProvider> providerMock = new Mock<IWebCryptoProvider>(MockBehavior.Strict);
            providerMock.Setup(t => t.GetRandomBytes(20, default))
                .ReturnsAsync(randomData)
                .Verifiable();

            using Algorithms.IRandomGenerator generator = await providerMock.Object.CreateRandomGeneratorWithSeed(default);

            Assert.IsNotNull(generator);

            generator.NextBytes(new byte[50]);
        }
    }
}

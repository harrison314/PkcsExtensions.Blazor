using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using System;
using System.Threading.Tasks;

namespace PkcsExtensions.Blazor.Tests
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

        [TestMethod]
        public async Task GetNonZeroBytes()
        {
            byte[] result = new byte[20];
            Array.Fill<byte>(result, 42);
            result[3] = result[7] = result[13] = result[17] = 0;

            Mock<IWebCryptoProvider> providerMock = new Mock<IWebCryptoProvider>(MockBehavior.Strict);
            providerMock.Setup(t => t.GetRandomBytes(20, default))
                .ReturnsAsync(result)
                .Verifiable();

            providerMock.Setup(t => t.GetRandomBytes(4, default))
                .ReturnsAsync(new byte[] { 87, 0, 76, 7 })
                .Verifiable();

            providerMock.Setup(t => t.GetRandomBytes(1, default))
                .ReturnsAsync(new byte[] { 8 })
                .Verifiable();

            byte[] nonZeroBytes = await providerMock.Object.GetNonZeroBytes(20);
            Assert.IsNotNull(result);
            CollectionAssert.DoesNotContain(nonZeroBytes,(byte) 0);
        }
    }
}

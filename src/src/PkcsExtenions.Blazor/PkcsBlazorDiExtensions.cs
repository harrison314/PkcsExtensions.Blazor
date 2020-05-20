using PkcsExtenions.Blazor;
using PkcsExtenions.Blazor.WebCrypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class PkcsBlazorDiExtensions
    {
        /// <summary>
        /// Register <see cref="IWebCryptoProvider"/> to dependency injection.
        /// Must add '_content/PkcsExtenions.Blazor/WebCryptoInterop.js' to index.html.
        /// </summary>
        /// <param name="serviceCollection"></param>
        /// <returns></returns>
        public static IServiceCollection AddWebCryptoProvider(this IServiceCollection serviceCollection)
        {
            serviceCollection.AddTransient<IWebCryptoProvider, WebCryptoProvider>();
            serviceCollection.AddTransient<IEcWebCryptoProvider, EcWebCryptoProvider>();

            return serviceCollection;
        }
    }
}

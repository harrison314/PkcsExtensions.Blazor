# PkcsExtensions.Blazor
 Add extensions for Blazor and light [WebCrypto](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) interop.

 ### Features
 - Namespace **PkcsExtensions.Blazor**:
   - `IWebCryptoProvider` - provide generate random numbers, generate RSA and ECDSA (as JsonWebKey) key pairs
   - `IEcWebCryptoProvider` - provide methods `GetSharedDhmSecret` for derive bytes using _Diffie Hellman Merkle_ and `GetSharedEphemeralDhmSecret` for ECIES scheme.
- Namespace **PkcsExtenions.Blazor.Jwk** - implementation of __JsonWebKey__
- Namespace **PkcsExtenions.Blazor.Security** - extensions for [System.Security.Cryptography](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography?view=netstandard-2.1)

### Usage
Install package `dotnet add package PkcsExtensions.Blazor` to Blazor WebAssebmly project.

Add to _index.html_:
```html
<script src="_content/PkcsExtenions.Blazor/WebCryptoInterop.js"></script>
```

And register services in _Main_ method:
```cs
    public class Program
    {
        public static async Task Main(string[] args)
        {
            var builder = WebAssemblyHostBuilder.CreateDefault(args);
            builder.RootComponents.Add<App>("app");
            builder.Services.AddSingleton(new HttpClient { BaseAddress = new Uri(builder.HostEnvironment.BaseAddress) });
            
            builder.Services.AddWebCryptoProvider();

            WebAssemblyHost host = builder.Build();
            await host.RunAsync();
        }
    }
```

### Recommendations
- Avoid use WebCyrpto for hashing, HMAC-ing, encryption, because their implementations has differs between browsers and operating systems. Use _.Net_ implementation.
- Hint: Consider using high performance elliptic curves [Curve25519](https://en.wikipedia.org/wiki/Curve25519),
[Ed25519](https://en.wikipedia.org/wiki/EdDSA#Ed25519) or similar. Use full managed implementation e.g. [Chaos.NaCl library](https://github.com/CodesInChaos/Chaos.NaCl).

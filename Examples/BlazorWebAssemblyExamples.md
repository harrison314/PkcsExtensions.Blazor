# PkcsExtensions.Blazor examples
Examples using WebCrypto interop.

## Generate random byte array
```cs
@inject PkcsExtensions.Blazor.IWebCryptoProvider wcProvider

<div>
    <p>@dataAsBase64</p>
</div>
<div>
    <button @onclick="GenerateRandom">Generate</button>
</div>

@code {

    private string dataAsBase64 = string.Empty;

    private async Task GenerateRandom()
    {
        byte[] data = await this.wcProvider.GetRandomBytes(32);
        this.dataAsBase64 = Convert.ToBase64String(data);
    }
}
```

## Generate RSA keys
```cs
@using System.Security.Cryptography
@using PkcsExtensions
@using PkcsExtensions.Blazor.Security
@inject PkcsExtensions.Blazor.IWebCryptoProvider wcProvider

<pre>@data</pre>

<div>
    <button @onclick="GenerateRsa">Generate</button>
</div>

@code {

    private string data = string.Empty;

    private async Task GenerateRsa()
    {
        using RSA rsaKey = await wcProvider.GenerateRsaKeyPair(2048);
        this.data = Encoding.ASCII.GetString(rsaKey.ManagedExportSubjectPublicKeyInfo(AsnFormat.Pem));
    }
}
```

## Generate EC keys as JWK
```cs
@using System.Security.Cryptography
@using PkcsExtensions
@using PkcsExtensions.Blazor.Jwk
@using PkcsExtensions.Blazor
@inject IWebCryptoProvider wcProvider

<div>
    <p>@data</p>
</div>
<div>
    <button @onclick="GenerateEc">Generate</button>
</div>

@code {

    private string data = string.Empty;

    private async Task GenerateEc()
    {
        JsonWebKey privateEcKey = await wcProvider.GenerateECDsaJwkKeyPair(WebCryptoCurveName.NistP256);
        this.data = privateEcKey.AsPublicKey().ToString();
    }
}
```

## Key exange using EC DHM
```cs
@using System.Security.Cryptography
@using PkcsExtensions
@using PkcsExtensions.Blazor.Jwk
@using PkcsExtensions.Blazor
@inject IWebCryptoProvider wcProvider
@inject IEcWebCryptoProvider ecProvider

<div>
    <p>Alice: @aliceSecret</p>
    <p>Bob: @bobSecret</p>
</div>
<div>
    <button @onclick="Generate">Generate</button>
</div>

@code {

    private string aliceSecret = string.Empty;
    private string bobSecret = string.Empty;

    private async Task Generate()
    {
        JsonWebKey alicePrivateKey = await wcProvider.GenerateECDsaJwkKeyPair(WebCryptoCurveName.NistP521);
        JsonWebKey alicePublicKey = alicePrivateKey.AsPublicKey();

        JsonWebKey bobPrivateKey = await wcProvider.GenerateECDsaJwkKeyPair(WebCryptoCurveName.NistP521);
        JsonWebKey bobPublicKey = bobPrivateKey.AsPublicKey();
        
        byte[] aliceSeecretBytes = await ecProvider.GetSharedDhmSecret(alicePrivateKey, bobPublicKey);
        byte[] bobSecretBytes = await ecProvider.GetSharedDhmSecret(bobPrivateKey, alicePublicKey);

        this.aliceSecret = Convert.ToBase64String(aliceSeecretBytes);
        this.bobSecret = Convert.ToBase64String(bobSecretBytes);
    }
}
```

## Using ECIES scheme
```cs
@using System.Security.Cryptography
@using PkcsExtensions
@using PkcsExtensions.Blazor.Jwk
@using PkcsExtensions.Blazor
@inject IWebCryptoProvider wcProvider
@inject IEcWebCryptoProvider ecProvider

    <div>
        <p>Ephemeral Public Key: @ephemeralPublicKey</p>
        <p>Shared Seecrit Key: @sharedSeecrit</p>
    </div>
<div>
    <button @onclick="Generate">Generate</button>
</div>

@code {

    private string aplicePublicKey = "{ \"kty\": \"EC\", \"key_ops\": [ \"deriveBits\" ], \"crv\": \"P-256\", \"x\": \"rpFupz6ubMRIzuj5NCY2nUTXc1Yd-X_KJQVrj5QYW0M\", \"y\": \"hqmJCq-tP5dYNloX2gB2bDOHUKfLk_vlbjXrYhHzGjs\" }";
    private string ephemeralPublicKey = string.Empty;
    private string sharedSeecrit = string.Empty;

    public async Task Generate()
    {
        JsonWebKey aplicePublicJwk = JsonWebKey.Parse(this.aplicePublicKey);

        EcdhEphemeralBundle bundle = await ecProvider.GetSharedEphemeralDhmSecret(aplicePublicJwk);

        this.ephemeralPublicKey = bundle.EphemeralDhmPublicKey.ToString();
        this.sharedSeecrit = Convert.ToBase64String(bundle.SharedSecret);
    }
}
```
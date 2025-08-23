# Knowledge Base

## Negotiate authentication

A negotiated, single sign on type of authentication that is the Windows implementation of [Simple and Protected GSSAPI Negotiation Mechanism (SPNEGO)](https://learn.microsoft.com/en-us/windows/win32/winrm/windows-remote-management-glossary). SPNEGO negotiation determines whether authentication is handled by Kerberos or NTLM. Kerberos is the preferred mechanism. Negotiate authentication on Windows-based systems is also called Windows Integrated Authentication.

Reference:

- https://learn.microsoft.com/en-us/windows/win32/winrm/windows-remote-management-glossary#:~:text=A%20negotiated%2C%20single,Windows%20Integrated%20Authentication
- https://learn.microsoft.com/en-us/windows/win32/winrm/authentication-for-remote-connections#negotiate-authentication

## WinRM - Types of Authentication

1. Basic Authentication
2. Digest Authentication
3. Kerberos Authentication
4. Negotiate Authentication
5. NTLM Authentication
6. Certificate Authentication
7. CredSSP Authentication

Reference: https://learn.microsoft.com/en-us/windows/win32/winrm/authentication-for-remote-connections

Enable Auth

```powershell
Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value $true
```

## Configure WinRM HTTPS with self-signed certificate

```powershell
# https://gist.github.com/gregjhogan/dbe0bfa277d450c049e0bbdac6142eed
$cert = New-SelfSignedCertificate -CertstoreLocation Cert:\LocalMachine\My -DnsName $env:COMPUTERNAME
Enable-PSRemoting -SkipNetworkProfileCheck -Force
New-Item -Path WSMan:\LocalHost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $cert.Thumbprint –Force

New-NetFirewallRule -DisplayName "Windows Remote Management (HTTPS-In)" -Name "Windows Remote Management (HTTPS-In)" -Profile Any -LocalPort 5986 -Protocol TCP
```

Reference: https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management

- **Get the current WinRM configuration**

```powershell
winrm get winrm/config
```

- **Enumerate WinRM listeners**

```powershell
winrm enumerate winrm/config/listener
```

## Configure WinRM Certificate Authentication

Certificate authentication is a method of authenticating to a remote computer using a certificate. The certificate must be installed on the remote computer and the client must have access to the private key of the certificate.

**Enable Certificate Authentication**

```powershell
Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value $true
```

**Generate a certificate using PowerShell**

```powershell
# Set the username to the name of the user the certificate will be mapped to
$username = 'local-user'

$clientParams = @{
    CertStoreLocation = 'Cert:\CurrentUser\My'
    NotAfter          = (Get-Date).AddYears(1)
    Provider          = 'Microsoft Software Key Storage Provider'
    Subject           = "CN=$username"
    TextExtension     = @("2.5.29.37={text}1.3.6.1.5.5.7.3.2","2.5.29.17={text}upn=$username@localhost")
    Type              = 'Custom'
}
$cert = New-SelfSignedCertificate @clientParams
$certKeyName = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey(
    $cert).Key.UniqueName

# Exports the public cert.pem and key cert.pfx
Set-Content -Path "cert.pem" -Value @(
    "-----BEGIN CERTIFICATE-----"
    [Convert]::ToBase64String($cert.RawData) -replace ".{64}", "$&`n"
    "-----END CERTIFICATE-----"
)
$certPfxBytes = $cert.Export('Pfx', '')
[System.IO.File]::WriteAllBytes("$pwd\cert.pfx", $certPfxBytes)

# Removes the private key and cert from the store after exporting
$keyPath = [System.IO.Path]::Combine($env:AppData, 'Microsoft', 'Crypto', 'Keys', $certKeyName)
Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($cert.Thumbprint)" -Force
Remove-Item -LiteralPath $keyPath -Force
```

We now have `cert.pem` and `cert.pfx` files.

**Import Certificate to the Certificate Store**

```powershell
$store = Get-Item -LiteralPath Cert:\LocalMachine\Root
$store.Open('ReadWrite')
$store.Add($cert)
$store.Dispose()
```

**Mapping Certificate to a Local Account**

```powershell
# Will prompt for the password of the user.
$credential = Get-Credential local-user

$certChain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
[void]$certChain.Build($cert)
$caThumbprint = $certChain.ChainElements.Certificate[-1].Thumbprint

$certMapping = @{
    Path       = 'WSMan:\localhost\ClientCertificate'
    Subject    = $cert.GetNameInfo('UpnName', $false)
    Issuer     = $caThumbprint
    Credential = $credential
    Force      = $true
}
New-Item @certMapping
```

**Convert to PEM format**

```bash
openssl pkcs12 \
    -in cert.pfx \
    -nocerts \
    -nodes \
    -passin pass: |
    sed -ne '/-BEGIN PRIVATE KEY-/,/-END PRIVATE KEY-/p' > priv-key.pem
```

User `local-user` can now auth using private key `priv_key.pem` and public key `cert.pem`.

Reference: https://docs.ansible.com/ansible/latest/os_guide/windows_winrm_certificate.html

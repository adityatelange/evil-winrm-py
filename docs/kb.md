# Knowledge Base

## Negotiate authentication

A negotiated, single sign on type of authentication that is the Windows implementation of [Simple and Protected GSSAPI Negotiation Mechanism (SPNEGO)](https://learn.microsoft.com/en-us/windows/win32/winrm/windows-remote-management-glossary). SPNEGO negotiation determines whether authentication is handled by Kerberos or NTLM. Kerberos is the preferred mechanism. Negotiate authentication on Windows-based systems is also called Windows Integrated Authentication.

Read more:

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


# SecretManagement.CyberArk

A [SecretManagement](https://github.com/powershell/secretmanagement) extension for [CyberArk](https://www.cyberark.com/). It supports connecting to the Vault by either the REST API, Credential Provider, or Central Credential Provider.

The [psPAS](https://github.com/pspete/psPAS) or [CredentialRetriever](https://github.com/pspete/CredentialRetriever) module is used to communicate with the Vault.

## Prerequisities

- The [psPAS](https://github.com/pspete/psPAS) Powershell module
- The [CredentialRetriever](https://github.com/pspete/CredentialRetriever) Powershell module
- The [SecretManagement](https://github.com/powershell/secretmanagement) Powershell module

## Installation

From PowerShell Gallery

```powershell
Install-Module SecretManagement.CyberArk
```

## Registration

Once installed, it must be registered as an extension for `SecretManagement`. Depending on how you want to connect to the Vault, you will need to provide the appropriate parameters.

### Credential Provider

Specify `CredentialProvider` as the `ConnectionType`, the `AppID` to authenticate as, and optionally a `ClientPath` to the Credential Provider executable (otherwise it will use the existing `ClientPath` previously set via `Set-AIMConfiguration`.)

```powershell
$VaultParameters = @{
    ConnectionType = 'CredentialProvider'
    AppID          = 'windowsScript'
    ClientPath     = 'C:\Path\To\CLIPasswordSDK.exe'
}

Register-SecretVault -Name CyberArk -ModuleName SecretManagement.CyberArk -VaultParameters $VaultParameters
```

### Central Credential Provider

Specify `CentralCredentialProvider` as the `ConnectionType`, the `AppID` to authenticate as, and the `URL` for the Central Credential Provider. Optionally, parameters such as `SkipCertificateCheck`, `UseDefaultCredentials`, `Credential`, `CertificateThumbPrint`, and `Certificate` can be specified.

```powershell
$VaultParameters = @{
    ConnectionType       = 'CentralCredentialProvider'
    AppID                = 'windowsScript'
    URL                  = 'https://comp01.contoso.com'
    SkipCertificateCheck = $true
}

Register-SecretVault -Name CyberArk -ModuleName SecretManagement.CyberArk -VaultParameters $VaultParameters
```

### REST API

Specify `REST` as the `ConnectionType` and an existing `PASSession` will be used.

```powershell
$VaultParameters = @{
    ConnectionType = 'REST'
}

Register-SecretVault -Name CyberArk -ModuleName SecretManagement.CyberArk -VaultParameters $VaultParameters
```

## Usage

You use the typical `SecretManagement` commands such as `Get-Secret` and `Set-Secret`.

### Examples

To retrieve the password for an account named `localAdmin01`:

```powershell
Get-Secret -Name localAdmin01 -VaultName CyberArk
```

or

```powershell
Get-PASAccount -search localAdmin01 -safeName Windows | Get-Secret -VaultName CyberArk
```

Note: If multiple results are returned from CyberArk the first one is provided.

To retrieve the password for an account named `linuxAdmin01` where policy requires a reason:

```powershell
Get-Secret -Name localAdmin01 -AdditionalParameters @{Reason = 'To do things' } -VaultName CyberArk
```

To create a new credential in the Vault use:

```powershell
$Secret = ConvertTo-SecureString 'verySecret!' -AsPlainText -Force

$NewCredentialProperties = @{
    platformId = 'WindowsDomainAccount'
    safeName   = 'Windows'
    address    = 'iosharp.lab'
    userName   = 'localAdmin10'
}

Set-Secret -VaultName CyberArk -Secret $Secret -AdditionalParameters $NewCredentialProperties
```

Note: The value passed to the `Name` argument will be used as the `name` property for the account in CyberArk. If you want CyberArk to generate the name for the account automatically, do not use the `Name` argument. This is not supported for the `CentralCredentialProvider` and `CredentialProvider` connection types.

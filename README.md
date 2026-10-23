# SecretManagement.CyberArk

A [SecretManagement](https://github.com/powershell/secretmanagement) extension for [CyberArk](https://www.cyberark.com/). It supports connecting to the Vault by either the REST API, Credential Provider, or Central Credential Provider.

The [psPAS](https://github.com/pspete/psPAS) module (REST) or [CredentialRetriever](https://github.com/pspete/CredentialRetriever) module (Credential Provider and Central Credential Provider) is used to communicate with the Vault.

## Prerequisites

All three modules are declared as `RequiredModules` and are installed with the extension from PowerShell Gallery:

- [psPAS](https://github.com/pspete/psPAS) >= 7.0.242
- [CredentialRetriever](https://github.com/pspete/CredentialRetriever) >= 4.0.0
- [Microsoft.PowerShell.SecretManagement](https://github.com/powershell/secretmanagement) >= 1.1.2

## Installation

From PowerShell Gallery

```powershell
Install-Module SecretManagement.CyberArk
```

## Registration

Once installed, it must be registered as an extension for `SecretManagement`. Depending on how you want to connect to the Vault, you will need to provide the appropriate parameters.

All options are read from the `VaultParameters` given at registration. `Get-Secret`, `Set-Secret`, `Remove-Secret`, `Get-SecretInfo` and `Test-SecretVault` have no per-call extension parameters (there is no `-AdditionalParameters`); to change an option, re-register the vault. `VaultParameters` are stored as plaintext JSON in your SecretManagement registry, so use only simple values (strings, numbers, booleans): never put passwords, `PSCredential`, `SecureString` or certificate objects in them.

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

Specify `CentralCredentialProvider` as the `ConnectionType`, the `AppID` to authenticate as, and the `URL` for the Central Credential Provider.

Only these vault parameters are passed to `Get-CCPCredential`; any other key is ignored with a warning naming it:

`AppID`, `URL`, `SkipCertificateCheck`, `UseDefaultCredentials`, `CertificateThumbPrint`, `WebServiceName`, `ConnectionTimeout`, `Method`, `FailRequestOnPasswordChange`

`Credential` and `Certificate` objects cannot be used because they cannot be persisted; use `CertificateThumbPrint` for certificate authentication.

```powershell
$VaultParameters = @{
    ConnectionType = 'CentralCredentialProvider'
    AppID          = 'windowsScript'
    URL            = 'https://comp01.contoso.com'
}

Register-SecretVault -Name CyberArk -ModuleName SecretManagement.CyberArk -VaultParameters $VaultParameters
```

> **Warning:** `SkipCertificateCheck = $true` disables TLS certificate validation, so the connection can be intercepted. Use it in lab environments only.

### REST API

Specify `REST` as the `ConnectionType`. An existing `PASSession` (created with `New-PASSession`) is used; commands write the error 'Failed to get PASSession. Run New-PASSession again.' if there is no active session.

```powershell
$VaultParameters = @{
    ConnectionType = 'REST'
}

Register-SecretVault -Name CyberArk -ModuleName SecretManagement.CyberArk -VaultParameters $VaultParameters
```

Optional REST vault parameters:

- `Get-Secret`: `safeName` (limits the account search), and the password retrieval options `Reason`, `TicketingSystem`, `TicketId`, `Version`, `ActionType`, `isUse`, `Machine`. They apply to every `Get-Secret` call on that vault, e.g. register a dedicated vault with `Reason = 'To do things'` if policy requires a reason.
- `Set-Secret`: `SafeName` and `PlatformId` (required), `userName` and `address`.

## Usage

You use the typical `SecretManagement` commands such as `Get-Secret` and `Set-Secret`.

### Get-Secret

```powershell
Get-Secret -Name localAdmin01 -VaultName CyberArk
```

or

```powershell
Get-PASAccount -search localAdmin01 -safeName Windows | Get-Secret -VaultName CyberArk
```

- **Return type:** a `PSCredential` for all connection types (user name plus password). Callers that previously expected a `SecureString` from Credential Provider or Central Credential Provider should use `.Password` or `.GetNetworkCredential().Password`.
- **REST name matching:** only accounts whose `name` exactly matches (case-insensitive) are used; substring-only hits count as not found. If several accounts match, one error states the count and name and nothing is returned. Passing a `PASAccount` object bypasses the name check.
- **Not found:** the extension returns `$null`, which SecretManagement reports as "The secret ... was not found".

### Set-Secret

REST only. `SafeName` and `PlatformId` come from the vault's `VaultParameters` (see above); `userName` and `address` are optional there too.

```powershell
Register-SecretVault -Name CyberArkWindows -ModuleName SecretManagement.CyberArk -VaultParameters @{
    ConnectionType = 'REST'
    SafeName       = 'Windows'
    PlatformId     = 'WindowsDomainAccount'
    address        = 'iosharp.lab'
    userName       = 'localAdmin10'
}

$Secret = ConvertTo-SecureString 'verySecret!' -AsPlainText -Force
Set-Secret -VaultName CyberArkWindows -Secret $Secret
```

The value passed to `-Name` is used as the `name` property of the account in CyberArk. Omit `-Name` to have CyberArk generate the name.

### Remove-Secret

REST only. Deletes the single account whose `name` exactly matches `-Name` (case-insensitive). With zero or multiple exact matches it writes an error and deletes nothing; substring matches are ignored.

### Get-SecretInfo

Returns `PSCredential`-typed entries with a fixed metadata allowlist (string, int or DateTime values only; secrets are never included).

| ConnectionType | Wildcards in `-Name` | Metadata |
|---|---|---|
| `REST` | Supported (`-like`); a plain name matches exactly | `id`, `name`, `userName`, `address`, `safeName`, `platformId`, `secretType`, `createdTime` (UTC `DateTime`) |
| `CredentialProvider`, `CentralCredentialProvider` | Not supported: they cannot enumerate, so a wildcard (including the default `*`) returns nothing; give the exact object name | `Name`, `UserName`, `Address`, `Safe`, `Folder`, `PolicyID`, `DeviceType` |

### Test-SecretVault

Checks the vault per `ConnectionType`, without calling the Credential Provider services:

- `REST`: an active `PASSession` with a populated `BaseURI`.
- `CredentialProvider`: `AppID` is set and `Get-AIMCredential` is available.
- `CentralCredentialProvider`: `AppID` and `URL` are set and `Get-CCPCredential` is available.

A missing requirement (or an unknown `ConnectionType`) writes an error naming it and returns `$false`.

### Errors

Failures are written as normal PowerShell errors with the real message (SecretManagement would otherwise replace a thrown message with a generic "Unable to ..."). Use `-ErrorAction Stop` to make them terminating. Unsupported operations (`Set-Secret`/`Remove-Secret` on Credential Provider types) also write errors.

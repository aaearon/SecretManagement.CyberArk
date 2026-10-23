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

`SafeName` is optional: when set, every lookup on that vault is scoped to that safe (passed to `Get-AIMCredential` as `-Safe`). The secret name you request is passed to `Get-AIMCredential` as `-UserName` (not as the object name). Without `SafeName` the lookup is by that UserName only, so it must be unique across the safes `AppID` can see.

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

`ConnectionType` and `Verbose` are ignored silently (SecretManagement adds them); other unknown keys produce the warning. Switch parameters (`SkipCertificateCheck`, `UseDefaultCredentials`, `FailRequestOnPasswordChange`) are passed only when true; a false value is omitted, because `Get-CCPCredential` treats a bound `UseDefaultCredentials` as enabled.

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

- `Get-Secret`: `safeName` (scopes `Get-Secret`, `Get-SecretInfo` and `Remove-Secret` to that safe; matches in other safes are treated as not found), and the password retrieval options `Reason`, `TicketingSystem`, `TicketId`, `Version`, `ActionType`, `isUse`, `Machine`. They apply to every `Get-Secret` call on that vault, e.g. register a dedicated vault with `Reason = 'To do things'` if policy requires a reason.
- `Set-Secret`: optional defaults `SafeName`, `PlatformId`, `userName` and `address`; `-Metadata` on each call overrides them (see Set-Secret below).

## Usage

You use the typical `SecretManagement` commands such as `Get-Secret` and `Set-Secret`.

### Get-Secret

```powershell
Get-Secret -Name localAdmin01 -VaultName CyberArk
```

Pipeline input is not forwarded to the extension: SecretManagement's `Get-Secret` binds piped values to `-Name` (an object is converted to a string), and has no `-PASAccount` parameter. Pipe names only, for example `'localAdmin01' | Get-Secret -Vault CyberArk`.

- **Return type:** a `PSCredential` for all connection types (user name plus password). Callers that previously expected a `SecureString` from Credential Provider or Central Credential Provider should use `.Password` or `.GetNetworkCredential().Password`.
- **REST name matching:** only accounts whose `name` exactly matches (case-insensitive) are used; substring-only hits count as not found. If several accounts match, one error states the count and name and nothing is returned.
- **Not found:** the extension returns `$null`, which SecretManagement reports as "The secret ... was not found".

### Set-Secret

REST only. `-Secret` may be a `SecureString`, a string or a `PSCredential` (its password is used, and its user name unless `userName` comes from `-Metadata` or the vault parameters). Pass the target as `-Metadata`; keys are case-insensitive. `SafeName` and `PlatformId` are required, `address` and `userName` optional. Any `VaultParameters` with the same names act as defaults: a non-empty Metadata value wins per key, otherwise the vault parameter is used. Other Metadata keys are ignored. If `SafeName` or `PlatformId` is missing from both, an error is written and nothing is created.

```powershell
$Secret = ConvertTo-SecureString 'verySecret!' -AsPlainText -Force
Set-Secret -Vault CyberArk -Name localAdmin10 -Secret $Secret -Metadata @{
    SafeName   = 'Windows'
    PlatformId = 'WindowsDomainAccount'
    address    = 'iosharp.lab'
    userName   = 'localAdmin10'
}
```

One vault can therefore serve any safe/platform. To avoid repeating values, register defaults (`SafeName`, `PlatformId`, `address`, `userName`) in the `VaultParameters` and override per call with `-Metadata`.

The value passed to `-Name` is used as the `name` property of the account in CyberArk. Omit `-Name` to have CyberArk generate the name.

### Remove-Secret

REST only. Deletes the single account whose `name` exactly matches `-Name` (case-insensitive). With zero or multiple exact matches it writes an error and deletes nothing; substring matches are ignored.

### Get-SecretInfo

Returns `PSCredential`-typed entries with a fixed metadata allowlist (string, int or DateTime values only; secrets are never included).

| ConnectionType | Wildcards in `-Name` | Metadata |
|---|---|---|
| `REST` | Supported (`-like`, including `[a-z]` classes and `` `* `` escapes); a plain name matches exactly | `id`, `name`, `userName`, `address`, `safeName`, `platformId`, `secretType`, `createdTime` (UTC `DateTime`) |
| `CredentialProvider`, `CentralCredentialProvider` | Not supported: they cannot enumerate, so a wildcard (including the default `*`) returns nothing; give the exact name (for `CredentialProvider` the account `UserName`, for `CentralCredentialProvider` the object name) | `Name`, `UserName`, `Address`, `Safe`, `Folder`, `PolicyID`, `DeviceType` (for `CredentialProvider` the entry name is the `UserName` you looked up, so it can be passed back to `Get-Secret`) |

### Test-SecretVault

Checks the vault per `ConnectionType`, without calling the Credential Provider services:

- `REST`: an active `PASSession` with a populated `BaseURI`.
- `CredentialProvider`: `AppID` is set and `Get-AIMCredential` is available.
- `CentralCredentialProvider`: `AppID` and `URL` are set and `Get-CCPCredential` is available.

A missing requirement (or an unknown `ConnectionType`) writes an error naming it and returns `$false`.

### Errors

Failures are written as normal PowerShell errors with the real message (SecretManagement would otherwise replace a thrown message with a generic "Unable to ..."). Use `-ErrorAction Stop` to make them terminating. Unsupported operations (`Set-Secret`/`Remove-Secret` on Credential Provider types) also write errors.

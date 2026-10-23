# Changelog

All notable changes to this project are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2.0.0] - unreleased

### Breaking changes

- `Get-Secret` for `CredentialProvider` and `CentralCredentialProvider` now returns a `PSCredential` instead of a `SecureString`. Use `.Password`, or `.GetNetworkCredential().Password` for plaintext.
- `Get-SecretInfo` reports `SecretType` `PSCredential` for the Credential Provider types.
- REST `Get-Secret` and `Get-SecretInfo` match account names exactly instead of by substring. Use wildcards with `Get-SecretInfo` (for example `-Name 'web*'`) if you relied on substring matching.
- REST `Get-Secret` by name with several exact matches now returns nothing and writes an error (it used to return the first). Use a unique name, `safeName`, or set the `safeName` vault parameter.
- `Get-Secret -AdditionalParameters @{...}` per-call options never worked through the public cmdlet and are documented as removed; options come from the registered `VaultParameters`. Re-register the vault with the options you need.
- `CentralCredentialProvider` vault parameters are an allowlist; `Credential`, `Certificate` and any other key are ignored with a warning. Use `CertificateThumbPrint` instead of `Certificate`/`Credential`.
- `Get-SecretInfo` metadata is a fixed allowlist (see README); other properties are no longer included.
- `Get-SecretInfo` with a wildcard (including the default `*`) on the Credential Provider types returns nothing; specify the exact object name.
- The extension's `Get-Secret` and `Invoke-GetAIMCredential` `-SafeName` function parameter was removed. This only affects direct callers of the extension functions; use the `SafeName` vault parameter.
- Failures are written with `Write-Error` rather than thrown, and `Test-SecretVault` returns `$false`. Use `-ErrorAction Stop` to get terminating errors.
- Minimum dependency versions: psPAS 7.0.242, CredentialRetriever 4.0.0, Microsoft.PowerShell.SecretManagement 1.1.2.

### Added

- `Set-Secret` (REST) accepts `-Metadata` with `SafeName`, `PlatformId`, `address` and `userName` (case-insensitive keys). Metadata overrides the vault parameters per key, so one vault can write to any safe/platform; other keys are ignored.
- `Test-SecretVault` checks per `ConnectionType`: REST needs an active session; `CredentialProvider` needs `AppID` and `Get-AIMCredential`; `CentralCredentialProvider` needs `AppID`, `URL` and `Get-CCPCredential`.
- `Get-SecretInfo` wildcard filtering for REST, and metadata including `createdTime` (UTC `DateTime`); `UserName` is always requested from the Credential Provider and included.
- New `CentralCredentialProvider` vault parameters: `WebServiceName`, `ConnectionTimeout`, `Method`, `FailRequestOnPasswordChange`.
- Pester integration test driving the public SecretManagement cmdlets in a child process with a temporary registry.
- Pester coverage for vault parameter handling, error surfacing, name matching and metadata.
- Static compatibility audit against psPAS 8.2.0 (no code changes required; not exercised against a live CyberArk).

### Changed

- Contract functions use the `AdditionalParameters` that SecretManagement supplies (the registered `VaultParameters`) instead of re-reading the vault registry.
- `Remove-Secret` deletes only a single exact name match, by account id; zero or multiple matches write an error and delete nothing.
- REST password retrieval failures surface the underlying reason instead of reporting "not found".
- An empty psPAS session (no `New-PASSession`) is treated as no session.
- `ModuleVersion` is 2.0.0 and `CompanyName` is set in the manifests.

### Fixed

- REST `Get-Secret` lookups and `Get-CCPCredential`/`Get-AIMCredential`/`Add-PASAccount` failures no longer escape as terminating errors; they are written with the exception message.
- Provider results without a `UserName` or with an empty password write an error naming the missing field instead of failing in `ToCredential()`.
- `CentralCredentialProvider` switch vault parameters set to false (notably `UseDefaultCredentials`) are no longer passed, which previously enabled OS credentials.
- The `safeName` vault parameter now also scopes `Remove-Secret` and REST `Get-SecretInfo`, and is enforced client-side for `Get-Secret`.
- `Set-Secret` accepts a `PSCredential` (as returned by `Get-Secret`) or a string as well as a `SecureString`.
- `CredentialProvider` `Get-SecretInfo` reports the looked-up `UserName` as the entry name so it round-trips into `Get-Secret`.
- REST `Get-SecretInfo` wildcard filters with `[` classes or backtick escapes no longer miss matches; `createdTime` in milliseconds is converted and invalid values are dropped.
- Errors from `Get-Secret`, `Get-SecretInfo`, `Set-Secret`, `Remove-Secret` and `Test-SecretVault` reach the caller with their real message instead of SecretManagement's generic "Unable to ...".
- Unsupported operations, unknown `ConnectionType` and missing `SafeName`/`PlatformId` on `Set-Secret` write errors instead of throwing.
- `CredentialProvider` vaults accept an optional `SafeName` vault parameter, passed to `Get-AIMCredential` as `-Safe`. Previously it could not be supplied through SecretManagement and was never passed on, and the check for it never fired.

### Security

- `Remove-Secret` can no longer delete an account on a substring match.
- `Credential`/`Certificate` objects are no longer accepted as vault parameters (they cannot be persisted; `VaultParameters` are stored as plaintext JSON). The README warns that `SkipCertificateCheck = $true` disables TLS validation.
- Metadata never includes secret values.
- Publishing uses `Publish-Module` without `-Verbose` instead of a third-party action; actions are pinned by commit SHA and workflow permissions are `contents: read`.

### CI

- Pester failures now fail the build (`Run.Exit`); Pester is pinned to 5.2 through 5.99; `windows-2019` is dropped.
- The matrix runs psPAS 7.0.242 and latest on ubuntu and windows; the psPAS version is verified after install.
- `publish.yml` runs the Pester workflow first and publishes only from tags.

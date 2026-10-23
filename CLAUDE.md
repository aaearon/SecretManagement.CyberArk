# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

PowerShell (`pwsh`) module; no build step and no PSScriptAnalyzer config. Pester tests live in `SecretManagement.CyberArk/Tests/`.

```powershell
# Dependencies (as in CI)
Install-Module psPAS, CredentialRetriever, Microsoft.PowerShell.SecretManagement, Pester
Import-Module Microsoft.PowerShell.SecretManagement -Force

# All tests (CI: .github/workflows/pester.yml, ubuntu + windows)
Invoke-Pester ./SecretManagement.CyberArk/Tests/*.Tests.ps1 -Passthru
# Single test file / single test
Invoke-Pester ./SecretManagement.CyberArk/Tests/Get-Secret.Tests.ps1
Invoke-Pester ./SecretManagement.CyberArk/Tests/Get-Secret.Tests.ps1 -FullNameFilter '*REST*'

# Try locally
Import-Module ./SecretManagement.CyberArk -Force
Register-SecretVault -Name CyberArk -ModuleName ./SecretManagement.CyberArk -VaultParameters @{ConnectionType='REST'}
```

`.devcontainer/` provides a pwsh container with SecretManagement, Pester and psPAS preinstalled (not CredentialRetriever; install it manually).

## Architecture

- `SecretManagement.CyberArk/SecretManagement.CyberArk.psd1` is the parent manifest: no root module, only `NestedModules` pointing at the `.Extension` manifest, plus `RequiredModules` (psPAS, CredentialRetriever, SecretManagement >= 1.0.0).
- `SecretManagement.CyberArk.Extension/*.psm1` is the whole implementation (single file). The manifest exports exactly the SecretManagement contract: `Get-Secret`, `Get-SecretInfo`, `Set-Secret`, `Remove-Secret`, `Test-SecretVault`. Adding a function that must be visible requires updating `FunctionsToExport`.
- Each contract function reads `(Get-SecretVault -Name $VaultName).VaultParameters` and `switch`es on `ConnectionType`; unknown types throw. Types:
  - `REST`: psPAS (`Get-PASAccount`, `Get-PASAccountPassword`, `Add-PASAccount`, ...) using an existing session; `Test-PASSession` throws if there is no `PASSession`. Only REST supports `Set-Secret`/`Remove-Secret`.
  - `CredentialProvider`: `Invoke-GetAIMCredential` wraps CredentialRetriever `Get-AIMCredential` (AppID, optional `ClientPath` applied via `Set-AIMConfiguration`; `SafeName` required, `RequiredProps` via AdditionalParameters).
  - `CentralCredentialProvider`: `Invoke-GetCCPCredential` copies all VaultParameters, removes `ConnectionType`, adds `Object = $Name`, and splats them into `Get-CCPCredential`. So any extra registered parameter (URL, AppID, SkipCertificateCheck, Credential, Certificate, ...) passes straight through; don't hardcode a list.
- Tests dot-import the Extension `.psd1` directly (not the parent) and mock psPAS/CredentialRetriever cmdlets; each registers a `CyberArk.Test` vault with the relevant `ConnectionType`.
- Versions are duplicated in both `.psd1` files (`ModuleVersion`); bump both on release.

## Release

`.github/workflows/publish.yml` publishes `SecretManagement.CyberArk/` to PowerShell Gallery (`PS_GALLERY_KEY` secret) when a GitHub release is published (or manually dispatched). Nothing is gated on tests in that workflow.

## README essentials

Registration is `Register-SecretVault -Name CyberArk -ModuleName SecretManagement.CyberArk -VaultParameters $VaultParameters`, with `ConnectionType` one of `REST`, `CredentialProvider` (`AppID`, optional `ClientPath`), `CentralCredentialProvider` (`AppID`, `URL`, optional `SkipCertificateCheck`, `UseDefaultCredentials`, `Credential`, `CertificateThumbPrint`, `Certificate`). `Get-Secret -AdditionalParameters @{Reason=...}` for policy reasons; multiple matches return the first. `Set-Secret` takes `platformId`, `safeName`, `address`, `userName` in `-AdditionalParameters`; omitting `-Name` lets CyberArk auto-name (REST only). Update README when changing registration parameters.

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

PowerShell (`pwsh`) module; no build step and no PSScriptAnalyzer config. Pester tests live in `SecretManagement.CyberArk/Tests/`.

```powershell
# Dependencies (as in CI; Pester must be 5.2-5.99)
Install-Module psPAS, CredentialRetriever, Microsoft.PowerShell.SecretManagement
Install-Module Pester -MinimumVersion 5.2.0 -MaximumVersion 5.99.99
Import-Module Microsoft.PowerShell.SecretManagement -Force

# All tests (same as CI)
$c = New-PesterConfiguration; $c.Run.Path = './SecretManagement.CyberArk/Tests'; $c.Run.Exit = $true; Invoke-Pester -Configuration $c
# Single file / single test: set $c.Run.Path = './SecretManagement.CyberArk/Tests/Get-Secret.Tests.ps1'; add $c.Filter.FullName = '*REST*'

# Try locally
Import-Module ./SecretManagement.CyberArk -Force
Register-SecretVault -Name CyberArk -ModuleName ./SecretManagement.CyberArk -VaultParameters @{ConnectionType='REST'}
```

CI (`.github/workflows/pester.yml`) tests psPAS 7.0.242 and latest on ubuntu and windows; failures fail the build. `pwsh` is blocked inside Claude Code agent worktrees: run tests from the main checkout. `.devcontainer/` has pwsh with SecretManagement, Pester and psPAS (install CredentialRetriever manually).

## SecretManagement conventions (normative)

- Contract functions never `throw`: SecretManagement replaces thrown messages with a generic "Unable to ...". Use `Write-Error` then `return` (`return $false` from `Test-SecretVault`).
- `$AdditionalParameters` IS the registered VaultParameters (plus `Verbose`). The public cmdlets have no per-call parameters. Do not re-read `Get-SecretVault`.
- `Get-Secret` returns `$null` for not found; return exactly one of byte[], string, SecureString, PSCredential, Hashtable (we return PSCredential).
- `Get-SecretInfo` metadata values: string, int or DateTime only, copied via allowlists. It must implement wildcard matching itself (`$Filter`, empty means `*`).
- VaultParameters persist as plaintext JSON: primitives only, no PSCredential/SecureString/certificate objects or secrets.
- Never put secret values in messages or verbose output.

## Architecture

- `SecretManagement.CyberArk/SecretManagement.CyberArk.psd1` is the parent manifest: no root module, `NestedModules` points at the `.Extension` manifest; `RequiredModules` are psPAS >= 7.0.242, CredentialRetriever >= 4.0.0, SecretManagement >= 1.1.2.
- `SecretManagement.CyberArk.Extension/*.psm1` is the whole implementation. The manifest exports exactly `Get-Secret`, `Get-SecretInfo`, `Set-Secret`, `Remove-Secret`, `Test-SecretVault`; new visible functions need `FunctionsToExport`.
- Each contract function switches on `$AdditionalParameters.ConnectionType`; unknown types write an error. All types return `PSCredential` from `Get-Secret`.
  - `REST`: psPAS using an existing session. `Test-PASSession` requires `(Get-PASSession).BaseURI`. Name lookups are exact, case-insensitive (`Get-PASAccount -search` then `-eq`); multiple matches are an error. Only REST supports `Set-Secret` (SafeName/PlatformId/address/userName come from `-Metadata` first, VaultParameters as fallback; keys case-insensitive; SafeName+PlatformId required) and `Remove-Secret` (single exact match only).
  - `CredentialProvider`: `Invoke-GetAIMCredential` wraps `Get-AIMCredential` (`ClientPath` via `Set-AIMConfiguration`; `UserName` always in `RequiredProps`; optional vault parameter `SafeName` is passed as `-Safe`, `Get-AIMCredential` has no `-SafeName`).
  - `CentralCredentialProvider`: `Invoke-GetCCPCredential` passes only the allowlist (AppID, URL, SkipCertificateCheck, UseDefaultCredentials, CertificateThumbPrint, WebServiceName, ConnectionTimeout, Method, FailRequestOnPasswordChange); other keys are dropped with a warning (ConnectionType/Verbose silently).
  - `Test-SecretVault` checks per type (REST: session; CP: AppID + `Get-AIMCredential`; CCP: AppID + URL + `Get-CCPCredential`).
  - `Get-SecretInfo` wildcards: REST `-like`; CP/CCP return nothing for wildcards.
- Tests dot-import the Extension `.psd1` (not the parent), mock psPAS/CredentialRetriever cmdlets (`Get-PASSession` mocked with a `BaseURI`) and pass `-AdditionalParameters` to the extension functions. Each file unregisters `CyberArk.Test` before registering and in `AfterAll`.

## Release

Bump `ModuleVersion` in both `.psd1` files and add a `CHANGELOG.md` entry. `publish.yml` (on release published or manual dispatch) first runs `pester.yml` via `workflow_call`, then publishes only from tags with `Publish-Module` (`PS_GALLERY_KEY` secret; no third-party action). Actions are pinned by commit SHA.

## README

Update README.md (CRLF line endings: preserve them) and CHANGELOG.md when changing registration parameters or user-visible behaviour.

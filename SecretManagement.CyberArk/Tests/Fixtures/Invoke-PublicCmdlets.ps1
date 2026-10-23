# Runs inside a child pwsh whose HOME/XDG_* point at a temporary directory (see PublicCmdlets.Tests.ps1).
# Registers vaults with the real SecretManagement cmdlets, calls the public cmdlets and emits one JSON document.
param ([Parameter(Mandatory)] [string] $TestsRoot)

$ErrorActionPreference = 'Continue'
Import-Module Microsoft.PowerShell.SecretManagement
$SM = 'Microsoft.PowerShell.SecretManagement'
$Out = [ordered]@{ RegistryUnderTemp = $false }

Register-SecretVault -Name 'CyberArk.PublicTest' -ModuleName "$TestsRoot/../../SecretManagement.CyberArk" -VaultParameters @{ConnectionType = 'REST'; PlatformId = 'VPlat'}
Register-SecretVault -Name 'Echo.PublicTest' -ModuleName "$TestsRoot/Fixtures/EchoVault" -VaultParameters @{ConnectionType = 'REST'}
$Out.RegistryUnderTemp = @(Get-ChildItem -LiteralPath $env:PUBLICTEST_HOME -Recurse -File -Filter 'vaultinfo*' -Force -ErrorAction SilentlyContinue).Count -gt 0

$Secret = ConvertTo-SecureString 'pw' -AsPlainText -Force
$null = & "$SM\Set-Secret" -Vault 'CyberArk.PublicTest' -Name n -Secret $Secret -Metadata @{SafeName = 'MetaSafe'} -ErrorAction SilentlyContinue -ErrorVariable E1
$Out.SetWithMetadata = "$E1"
$null = & "$SM\Set-Secret" -Vault 'CyberArk.PublicTest' -Name n -Secret $Secret -Metadata @{} -ErrorAction SilentlyContinue -ErrorVariable E2
$Out.SetWithoutSafe = "$E2"

[PSCustomObject]@{ Id = '5'; name = 'acct' } | & "$SM\Get-Secret" -Vault 'Echo.PublicTest' | Out-Null
$Out.PublicGetSecretHasPASAccount = (Get-Command "$SM\Get-Secret").Parameters.ContainsKey('PASAccount')
$Out.Echo = @(Get-Content -LiteralPath $env:ECHOVAULT_LOG | ConvertFrom-Json)

Unregister-SecretVault -Name 'CyberArk.PublicTest'
Unregister-SecretVault -Name 'Echo.PublicTest'
$Out | ConvertTo-Json -Depth 5 -Compress

# Test fixture: records what SecretManagement hands the extension functions, so tests can assert it.
# The record file path comes from the ECHOVAULT_LOG environment variable.
function Write-Echo { param($Function, $Bound) @{ Function = $Function; Bound = @($Bound.Keys); Name = "$($Bound.Name)" } | ConvertTo-Json -Compress | Add-Content -LiteralPath $env:ECHOVAULT_LOG }
function Get-Secret { [CmdletBinding()] param([string] $Name, [string] $VaultName, [hashtable] $AdditionalParameters, [Parameter(ValueFromPipeline)] [object] $PASAccount) Write-Echo 'Get-Secret' $PSBoundParameters; [pscredential]::new('u', (ConvertTo-SecureString 'p' -AsPlainText -Force)) }
function Get-SecretInfo { param($Filter, $VaultName, $AdditionalParameters) }
function Set-Secret { param($Name, $Secret, $VaultName, $AdditionalParameters, $Metadata) Write-Echo 'Set-Secret' $PSBoundParameters }
function Remove-Secret { param($Name, $VaultName, $AdditionalParameters) }
function Test-SecretVault { param($VaultName, $AdditionalParameters) $true }

using namespace System.Collections.ObjectModel
using namespace System.Collections.Generic
function Get-Secret {
    [CmdletBinding()]
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    $results = Get-PASAccount -search "$Name"

    if ($results.Count -gt 1) {
        Write-Warning "Multiple matches found with name $Name. Returning the first match."
        $Account = $results[0]
    } else {
        $Account = $results
    }

    if ($AdditionalParameters.Reason) {
        $AccountSecret = Get-PASAccountPassword -AccountID $Account.Id -Reason $AdditionalParameters.Reason
    } else {
        $AccountSecret = Get-PASAccountPassword -AccountID $Account.Id
    }
    $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Account.userName, $AccountSecret.ToSecureString()
    return $Credential
}

function Get-SecretInfo {
    [CmdletBinding()]
    param (
        [string] $Filter,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    $results = Get-PASAccount -search "$Filter"

    if ($results.Count -gt 1) {
        Write-Warning "Multiple matches found with name $Name. Returning the first match."
        $Account = $results[0]
    } else {
        $Account = $results
    }

    $Metadata = [Ordered]@{}
    $Account.psobject.properties | ForEach-Object { $Metadata[$PSItem.Name] = $PSItem.Value } | ConvertTo-ReadOnlyDictionary

    return @(,[Microsoft.PowerShell.SecretManagement.SecretInformation]::new(
        "$($Account.name)",        # Name of secret
        [Microsoft.PowerShell.SecretManagement.SecretType]::PSCredential,      # Secret data type [Microsoft.PowerShell.SecretManagement.SecretType]
        $VaultName))    # Name of vault
}

function Remove-Secret
{
    [CmdletBinding()]
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    $results = Get-PASAccount -search "$Name"

    if ($results.Count -gt 1) {
        Write-Error "Multiple matches found with name $Name. Not deleting anything."
    }

    $results | Remove-PASAccount
    return $?
}

function Set-Secret {
    [CmdletBinding()]
    param (
        [string] $Name,
        [object] $Secret,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    return $true
    
}

function Test-SecretVault
{
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $VaultName,
        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable] $AdditionalParameters
    )
    Write-Host $AdditionalParameters.hi
    return Get-PASSession
}


function ConvertTo-ReadOnlyDictionary {
    <#
        .SYNOPSIS
        Converts a hashtable to a ReadOnlyDictionary[String,Object]. Needed for SecretInformation
        https://github.com/PowerShell/SecretManagement/issues/108#issue-821736250
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)][hashtable]$hashtable
    )
    process {
        $dictionary = [Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
        $hashtable.GetEnumerator().foreach{
            $dictionary[$_.Name] = $_.Value
        }
        [ReadOnlyDictionary[string,object]]::new($dictionary)
    }
}
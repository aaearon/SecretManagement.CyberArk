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

    $AccountSecret = Get-PASAccountPassword -AccountID $Account.Id
    return New-Object System.Management.Automation.PSCredential ($Account.userName, $AccountSecret.ToSecureString)
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

    return @(,[Microsoft.PowerShell.SecretManagement.SecretInformation]::new(
        "$Account.name",        # Name of secret
        [Microsoft.PowerShell.SecretManagement.SecretType]::PSCredential,      # Secret data type [Microsoft.PowerShell.SecretManagement.SecretType]
        $VaultName,    # Name of vault
        $Account))    # Optional Metadata parameter
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

    Add-PASAccount -secret 
    return $?
    
}
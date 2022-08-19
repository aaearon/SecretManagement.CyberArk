function Get-Secret {
    [CmdletBinding()]
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters,
        [Parameter(ValueFromPipeline = $true)]
        [object] $PASAccount
    )

    $VaultParameters = (Get-SecretVault -Name $VaultName).VaultParameters

    switch ($VaultParameters.ConnectionType) {
        'CredentialProvider' {

        }
        'CentralCredentialProvider' {

        }

        'REST' {
            Test-PASSession

            if ($PASAccount) {
                $Account = Get-PASAccount -id $PASAccount.Id
            } else {
                $GetPASAccountParameters = @{
                    search = $Name
                }
                if ($AdditionalParameters.safeName) { $GetPASAccountParameters.Add('safeName', $AdditionalParameters.safeName) }

                $results = Get-PASAccount @GetPASAccountParameters

                if ($results.Count -gt 1) {
                    Write-Warning "Multiple matches found with name $Name. Returning the first match."
                    $Account = $results[0]
                } else {
                    $Account = $results
                }
            }

            $GetPASAccountPasswordParameters = @{
                AccountId = $Account.Id
            }
            if ($AdditionalParameters.Reason) { $GetPASAccountPasswordParameters.Add('Reason', $AdditionalParameters.Reason) }
            if ($AdditionalParameters.TicketingSystem) { $GetPASAccountPasswordParameters.Add('TicketingSystem', $AdditionalParameters.TicketingSystem) }
            if ($AdditionalParameters.TicketId) { $GetPASAccountPasswordParameters.Add('TicketId', $AdditionalParameters.TicketId) }
            if ($AdditionalParameters.Version) { $GetPASAccountPasswordParameters.Add('Version', $AdditionalParameters.Version) }
            if ($AdditionalParameters.ActionType) { $GetPASAccountPasswordParameters.Add('ActionType', $AdditionalParameters.ActionType) }
            if ($AdditionalParameters.isUse) { $GetPASAccountPasswordParameters.Add('isUse', $AdditionalParameters.isUse) }
            if ($AdditionalParameters.Machine) { $GetPASAccountPasswordParameters.Add('Machine', $AdditionalParameters.Machine) }

            try {
                $AccountSecret = Get-PASAccountPassword @GetPASAccountPasswordParameters
                $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Account.userName, $AccountSecret.ToSecureString()
            } catch {
                $Credential = $null
            }
        }

        default {
            throw "ConnectionType $($VaultParameters.ConnectionType) is not supported"
        }
    }

    return $Credential
}

function Get-SecretInfo {
    [CmdletBinding()]
    param (
        [string] $Filter,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    $VaultParameters = (Get-SecretVault -Name $VaultName).VaultParameters

    switch ($VaultParameters.ConnectionType) {
        'CredentialProvider' { }
        'CentralCredentialProvider' { }
        'REST' {
            Test-PASSession

            $results = Get-PASAccount -search "$Filter"
        }
        Default {
            throw "ConnectionType $($VaultParameters.ConnectionType) is not supported"
        }
    }

    $Secrets = New-Object System.Collections.Generic.List[System.Object]

    foreach ($Account in $results) {
        $Metadata = [Ordered]@{}
        $Account.psobject.properties | ForEach-Object { $Metadata[$PSItem.Name] = $PSItem.Value }

        $SecretInfo = [Microsoft.PowerShell.SecretManagement.SecretInformation]::new(
            "$($Account.name)", # Name of secret
            [Microsoft.PowerShell.SecretManagement.SecretType]::PSCredential, # Secret data type [Microsoft.PowerShell.SecretManagement.SecretType]
            $VaultName, # Name of vault
            $Metadata)  # Optional Metadata parameter)

        $Secrets.Add($SecretInfo)
    }

    return $Secrets
}

function Remove-Secret {
    [CmdletBinding()]
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    $VaultParameters = (Get-SecretVault -Name $VaultName).VaultParameters

    switch ($VaultParameters.ConnectionType) {
        'CredentialProvider' {
            throw 'Remove-Secret is not supported for Credential Provider'
        }
        'CentralCredentialProvider' {
            throw 'Remove-Secret is not supported for Central Credential Provider'
        }
        'REST' {
            Test-PASSession

            $results = Get-PASAccount -search "$Name"

            if ($results.Count -gt 1) {
                Write-Error "Multiple matches found with name $Name. Not deleting anything."
            } else {
                $results | Remove-PASAccount
            }
        }
        Default {
            throw "ConnectionType $($VaultParameters.ConnectionType) is not supported"
        }
    }
}

function Set-Secret {
    [CmdletBinding()]
    param (
        [string] $Name,
        [object] $Secret,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    $VaultParameters = (Get-SecretVault -Name $VaultName).VaultParameters

    switch ($VaultParameters.ConnectionType) {
        'CredentialProvider' {
            throw 'Set-Secret is not supported for Credential Provider'
        }
        'CentralCredentialProvider' {
            throw 'Set-Secret is not supported for Central Credential Provider'
        }
        'REST' {
            if ($null -eq $AdditionalParameters.SafeName -or $null -eq $AdditionalParameters.PlatformId) {
                throw 'SafeName and PlatformId are required keys in $AdditionalParameters'
            }

            Test-PASSession

            $AddPASAccountParameters = @{
                SafeName   = $AdditionalParameters.SafeName
                PlatformId = $AdditionalParameters.PlatformId
            }
            if ($Name) { $AddPASAccountParameters.Add('name', $Name) }
            if ($AdditionalParameters.userName) { $AddPASAccountParameters.Add('userName', $AdditionalParameters.userName) }
            if ($AdditionalParameters.address) { $AddPASAccountParameters.Add('address', $AdditionalParameters.address) }
            if ($Secret) { $AddPASAccountParameters.Add('secret', $Secret) }

            Add-PASAccount @AddPASAccountParameters
        }
        Default {
            throw "ConnectionType $($VaultParameters.ConnectionType) is not supported"
        }
    }
}

function Test-SecretVault {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $VaultName,
        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable] $AdditionalParameters
    )

    Test-PASSession
    return $true
}

function Test-PASSession {
    try {
        $null = Get-PASSession
    } catch {
        throw 'Failed to get PASSession. Run New-PASSession again.'
    }

}
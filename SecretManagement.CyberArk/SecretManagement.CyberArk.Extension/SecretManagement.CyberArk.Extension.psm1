function Get-Secret {
    [CmdletBinding()]
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters,
        [Parameter(ValueFromPipeline = $true)]
        [object] $PASAccount,
        [string] $SafeName
    )

    $VaultParameters = (Get-SecretVault -Name $VaultName).VaultParameters

    switch ($VaultParameters.ConnectionType) {
        'CredentialProvider' {
            if ($null -eq $SafeName) { throw 'SafeName is required for the Credential Provider type' }
            $Credential = Invoke-GetAIMCredential -Name $Name -VaultName $VaultName -AdditionalParameters $AdditionalParameters
            if ($null -ne $Credential) { $Credential = $Credential.ToSecureString() }
        }
        'CentralCredentialProvider' {
            $Credential = Invoke-GetCCPCredential -Name $Name -VaultName $VaultName -AdditionalParameters $AdditionalParameters
            if ($null -ne $Credential) { $Credential = $Credential.ToSecureString() }
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

                $results = @(Get-PASAccount @GetPASAccountParameters | Where-Object { $_.name -eq $Name })

                if ($results.Count -eq 0) {
                    return $null
                }
                if ($results.Count -gt 1) {
                    $message = "Found $($results.Count) accounts named '$Name'. Use a unique name or the PASAccount parameter."
                    Write-Warning $message
                    throw $message
                }
                $Account = $results[0]
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
        'CredentialProvider' {
            $SecretDataType = [Microsoft.PowerShell.SecretManagement.SecretType]::SecureString
            $results = Invoke-GetAIMCredential -Name $Filter -VaultName $VaultName -AdditionalParameters $AdditionalParameters
            $results = $results | Select-Object -Property * -ExcludeProperty Password
        }
        'CentralCredentialProvider' {
            $SecretDataType = [Microsoft.PowerShell.SecretManagement.SecretType]::SecureString
            $results = Invoke-GetCCPCredential -Name $Filter -VaultName $VaultName -AdditionalParameters $AdditionalParameters
            $results = $results | Select-Object -Property * -ExcludeProperty Content
        }
        'REST' {
            $SecretDataType = [Microsoft.PowerShell.SecretManagement.SecretType]::PSCredential
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
            $SecretDataType, # Secret data type [Microsoft.PowerShell.SecretManagement.SecretType]
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

            $results = @(Get-PASAccount -search "$Name" | Where-Object { $PSItem.name -eq $Name })

            if ($results.Count -eq 0) {
                throw "No account found with name $Name. Not deleting anything."
            } elseif ($results.Count -gt 1) {
                throw "Multiple accounts found with name $Name. Not deleting anything."
            }

            Remove-PASAccount -id $results[0].Id
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

    $VaultParameters = (Get-SecretVault -Name $VaultName).VaultParameters

    switch ($VaultParameters.ConnectionType) {
        'CredentialProvider' {
            if (-not $VaultParameters.AppID) { Write-Error 'CredentialProvider vault parameter AppID is missing'; return $false }
            if (-not (Get-Command -Name Get-AIMCredential -ErrorAction SilentlyContinue)) { Write-Error 'Get-AIMCredential command not found'; return $false }
            return $true
        }
        'CentralCredentialProvider' {
            if (-not $VaultParameters.AppID) { Write-Error 'CentralCredentialProvider vault parameter AppID is missing'; return $false }
            if (-not $VaultParameters.URL) { Write-Error 'CentralCredentialProvider vault parameter URL is missing'; return $false }
            if (-not (Get-Command -Name Get-CCPCredential -ErrorAction SilentlyContinue)) { Write-Error 'Get-CCPCredential command not found'; return $false }
            return $true
        }
        'REST' {
            Test-PASSession
            return $true
        }
        Default {
            Write-Error "ConnectionType $($VaultParameters.ConnectionType) is not supported"
            return $false
        }
    }
}

function Test-PASSession {
    try {
        if (-not (Get-PASSession).BaseURI) { throw 'No active session' }
    } catch {
        throw 'Failed to get PASSession. Run New-PASSession again.'
    }

}

function Invoke-GetCCPCredential {
    [CmdletBinding()]
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    if ($null -ne $VaultName) {
        $VaultParameters = (Get-SecretVault -Name $VaultName).VaultParameters
    }
    else {
        $VaultParameters = (Get-SecretVault).VaultParameters
    }
    if ($null -eq $VaultParameters) {
        throw "No vault parameters!"
    }

    $GetCCPCredentialParameters = [System.Collections.Hashtable]::new($VaultParameters)
    $GetCCPCredentialParameters.Remove("ConnectionType")
    $GetCCPCredentialParameters.Add("Object", $Name)

    $Credential = Get-CCPCredential @GetCCPCredentialParameters
    return $Credential
}

function Invoke-GetAIMCredential {
    [CmdletBinding()]
    param (
        [string] $Name,
        [string] $SafeName,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    $VaultParameters = (Get-SecretVault -Name $VaultName).VaultParameters

    if ($VaultParameters.ClientPath) { Set-AIMConfiguration -ClientPath $VaultParameters.ClientPath }

    $GetAIMCredentialParameters = @{
        AppID    = $VaultParameters.AppID
        UserName = $Name
    }
    if ($SafeName) { $GetAIMCredentialParameters.Add('SafeName', $SafeName) }
    if ($AdditionalParameters.RequiredProps) { $GetAIMCredentialParameters.Add('RequiredProps', $AdditionalParameters.RequiredProps) }

    $Credential = Get-AIMCredential @GetAIMCredentialParameters
    return $Credential
}
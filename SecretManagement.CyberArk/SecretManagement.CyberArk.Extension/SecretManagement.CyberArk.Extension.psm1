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

    switch ($AdditionalParameters.ConnectionType) {
        'CredentialProvider' {
            if ($null -eq $SafeName) { Write-Error 'SafeName is required for the Credential Provider type'; return }
            $Credential = Invoke-GetAIMCredential -Name $Name -AdditionalParameters $AdditionalParameters
            if ($null -ne $Credential) { $Credential = $Credential.ToCredential() }
        }
        'CentralCredentialProvider' {
            $Credential = Invoke-GetCCPCredential -Name $Name -AdditionalParameters $AdditionalParameters
            if ($null -ne $Credential) { $Credential = $Credential.ToCredential() }
        }

        'REST' {
            if (-not (Test-PASSession)) { return }

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
                    Write-Error $message
                    return
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
                Write-Error "Failed to retrieve the password for account '$Name': $($_.Exception.Message)"
                return
            }
        }

        default {
            Write-Error "ConnectionType $($AdditionalParameters.ConnectionType) is not supported"
            return
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

    switch ($AdditionalParameters.ConnectionType) {
        'CredentialProvider' {
            $SecretDataType = [Microsoft.PowerShell.SecretManagement.SecretType]::PSCredential
            $results = Invoke-GetAIMCredential -Name $Filter -AdditionalParameters $AdditionalParameters
            $results = $results | Select-Object -Property * -ExcludeProperty Password
        }
        'CentralCredentialProvider' {
            $SecretDataType = [Microsoft.PowerShell.SecretManagement.SecretType]::PSCredential
            $results = Invoke-GetCCPCredential -Name $Filter -AdditionalParameters $AdditionalParameters
            $results = $results | Select-Object -Property * -ExcludeProperty Content
        }
        'REST' {
            $SecretDataType = [Microsoft.PowerShell.SecretManagement.SecretType]::PSCredential
            if (-not (Test-PASSession)) { return }

            $results = Get-PASAccount -search "$Filter"
        }
        Default {
            Write-Error "ConnectionType $($AdditionalParameters.ConnectionType) is not supported"
            return
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

    switch ($AdditionalParameters.ConnectionType) {
        'CredentialProvider' {
            Write-Error 'Remove-Secret is not supported for Credential Provider'
            return
        }
        'CentralCredentialProvider' {
            Write-Error 'Remove-Secret is not supported for Central Credential Provider'
            return
        }
        'REST' {
            if (-not (Test-PASSession)) { return }

            $results = @(Get-PASAccount -search "$Name" | Where-Object { $PSItem.name -eq $Name })

            if ($results.Count -eq 0) {
                Write-Error "No account found with name $Name. Not deleting anything."
                return
            } elseif ($results.Count -gt 1) {
                Write-Error "Multiple accounts found with name $Name. Not deleting anything."
                return
            }

            Remove-PASAccount -id $results[0].Id
        }
        Default {
            Write-Error "ConnectionType $($AdditionalParameters.ConnectionType) is not supported"
            return
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

    switch ($AdditionalParameters.ConnectionType) {
        'CredentialProvider' {
            Write-Error 'Set-Secret is not supported for Credential Provider'
            return
        }
        'CentralCredentialProvider' {
            Write-Error 'Set-Secret is not supported for Central Credential Provider'
            return
        }
        'REST' {
            if ($null -eq $AdditionalParameters.SafeName -or $null -eq $AdditionalParameters.PlatformId) {
                Write-Error 'SafeName and PlatformId are required keys in $AdditionalParameters'
                return
            }

            if (-not (Test-PASSession)) { return }

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
            Write-Error "ConnectionType $($AdditionalParameters.ConnectionType) is not supported"
            return
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

    switch ($AdditionalParameters.ConnectionType) {
        'CredentialProvider' {
            if (-not $AdditionalParameters.AppID) { Write-Error 'CredentialProvider vault parameter AppID is missing'; return $false }
            if (-not (Get-Command -Name Get-AIMCredential -ErrorAction SilentlyContinue)) { Write-Error 'Get-AIMCredential command not found'; return $false }
            return $true
        }
        'CentralCredentialProvider' {
            if (-not $AdditionalParameters.AppID) { Write-Error 'CentralCredentialProvider vault parameter AppID is missing'; return $false }
            if (-not $AdditionalParameters.URL) { Write-Error 'CentralCredentialProvider vault parameter URL is missing'; return $false }
            if (-not (Get-Command -Name Get-CCPCredential -ErrorAction SilentlyContinue)) { Write-Error 'Get-CCPCredential command not found'; return $false }
            return $true
        }
        'REST' {
            return (Test-PASSession)
        }
        Default {
            Write-Error "ConnectionType $($AdditionalParameters.ConnectionType) is not supported"
            return $false
        }
    }
}

function Test-PASSession {
    try {
        if (-not (Get-PASSession).BaseURI) { throw 'No active session' }
    } catch {
        Write-Error 'Failed to get PASSession. Run New-PASSession again.'
        return $false
    }
    return $true
}

function Invoke-GetCCPCredential {
    [CmdletBinding()]
    param (
        [string] $Name,
        [hashtable] $AdditionalParameters
    )

    # Vault-level, JSON-persistable Get-CCPCredential connection settings (CredentialRetriever 4.0.0).
    # Credential/Certificate cannot survive VaultParameters persistence; Safe/Folder/UserName/Address/Database/
    # PolicyID/Query/QueryFormat/Reason identify a secret; AsCredential/AsSecureString would change the return type.
    $AllowedKeys = @(
        'AppID', 'URL', 'SkipCertificateCheck', 'UseDefaultCredentials', 'CertificateThumbPrint',
        'WebServiceName', 'ConnectionTimeout', 'Method', 'FailRequestOnPasswordChange'
    )
    $SilentKeys = @('ConnectionType', 'Verbose')

    $GetCCPCredentialParameters = @{}
    $IgnoredKeys = @()
    foreach ($Key in $AdditionalParameters.Keys) {
        if ($Key -in $AllowedKeys) {
            $GetCCPCredentialParameters[($AllowedKeys | Where-Object { $_ -eq $Key })] = $AdditionalParameters[$Key]
        } elseif ($Key -notin $SilentKeys) {
            $IgnoredKeys += $Key
        }
    }
    if ($IgnoredKeys) {
        Write-Warning "Ignoring unsupported vault parameter(s) for CentralCredentialProvider: $($IgnoredKeys -join ', ')"
    }
    $GetCCPCredentialParameters.Add('Object', $Name)

    $Credential = Get-CCPCredential @GetCCPCredentialParameters
    return $Credential
}

function Invoke-GetAIMCredential {
    [CmdletBinding()]
    param (
        [string] $Name,
        [string] $SafeName,
        [hashtable] $AdditionalParameters
    )

    if ($AdditionalParameters.ClientPath) { Set-AIMConfiguration -ClientPath $AdditionalParameters.ClientPath }

    $GetAIMCredentialParameters = @{
        AppID    = $AdditionalParameters.AppID
        UserName = $Name
    }
    if ($SafeName) { $GetAIMCredentialParameters.Add('SafeName', $SafeName) }
    # UserName is always requested so a PSCredential can be built
    $RequiredProps = @($AdditionalParameters.RequiredProps) + 'UserName' | Where-Object { $_ } | Select-Object -Unique
    $GetAIMCredentialParameters.Add('RequiredProps', $RequiredProps)

    $Credential = Get-AIMCredential @GetAIMCredentialParameters
    return $Credential
}
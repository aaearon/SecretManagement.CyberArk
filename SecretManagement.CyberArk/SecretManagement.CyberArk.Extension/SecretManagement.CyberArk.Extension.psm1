function Get-Secret {
    [CmdletBinding()]
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters,
        [Parameter(ValueFromPipeline = $true)]
        [object] $PASAccount
    )

    switch ($AdditionalParameters.ConnectionType) {
        'CredentialProvider' {
            $Credential = Invoke-GetAIMCredential -Name $Name -AdditionalParameters $AdditionalParameters
            if ($null -ne $Credential) {
                $Credential = ConvertTo-ProviderCredential -Result $Credential -SecretProperty 'Password' -Name $Name
                if ($null -eq $Credential) { return }
            }
        }
        'CentralCredentialProvider' {
            $Credential = Invoke-GetCCPCredential -Name $Name -AdditionalParameters $AdditionalParameters
            if ($null -ne $Credential) {
                $Credential = ConvertTo-ProviderCredential -Result $Credential -SecretProperty 'Content' -Name $Name
                if ($null -eq $Credential) { return }
            }
        }

        'REST' {
            if (-not (Test-PASSession)) { return }

            if ($PASAccount) {
                $Account = Get-PASAccount -id $PASAccount.Id
            } else {
                $GetPASAccountParameters = @{
                    search = $Name
                }
                $VaultSafe = Get-CaseInsensitiveValue -Table $AdditionalParameters -Key 'safeName'
                if ($VaultSafe) { $GetPASAccountParameters.Add('safeName', $VaultSafe) }

                try {
                    $results = @(Get-PASAccount @GetPASAccountParameters | Where-Object { $_.name -eq $Name } | Select-AccountInVaultSafe -SafeName $VaultSafe)
                } catch {
                    Write-Error "Failed to look up account '$Name': $($_.Exception.Message)"
                    return
                }

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

function ConvertTo-ProviderCredential {
    # Validates a Get-AIMCredential/Get-CCPCredential result and converts it. Never reports secret values.
    param ($Result, [string] $SecretProperty, [string] $Name)

    if ([string]::IsNullOrEmpty("$($Result.UserName)")) {
        Write-Error "The provider returned no UserName for '$Name'; cannot build a credential."
        return
    }
    if ([string]::IsNullOrEmpty("$($Result.$SecretProperty)")) {
        Write-Error "The provider returned an empty $SecretProperty for '$Name'; cannot build a credential."
        return
    }
    try {
        return $Result.ToCredential()
    } catch {
        Write-Error "Failed to build a credential for '$Name': $($_.Exception.Message)"
        return
    }
}

function Get-SecretInfo {
    [CmdletBinding()]
    param (
        [string] $Filter,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    if ([string]::IsNullOrEmpty($Filter)) { $Filter = '*' }
    $VerboseOn = [bool]$AdditionalParameters.Verbose

    # Non-secret, useful fields only. Anything else (secrets, nested objects) is never copied into metadata.
    $ProviderKeys = @('Name', 'UserName', 'Address', 'Safe', 'Folder', 'PolicyID', 'DeviceType')
    $RestKeys = @('id', 'name', 'userName', 'address', 'safeName', 'platformId', 'secretType', 'createdTime')
    $SecretDataType = [Microsoft.PowerShell.SecretManagement.SecretType]::PSCredential

    switch ($AdditionalParameters.ConnectionType) {
        { $_ -in 'CredentialProvider', 'CentralCredentialProvider' } {
            if ([WildcardPattern]::ContainsWildcardCharacters($Filter)) {
                Write-Verbose "$($AdditionalParameters.ConnectionType) cannot enumerate secrets, so wildcard filter '$Filter' returns nothing. Specify the exact object name." -Verbose:$VerboseOn
                return
            }
            $Keys = $ProviderKeys
            if ($_ -eq 'CredentialProvider') {
                $results = Invoke-GetAIMCredential -Name $Filter -AdditionalParameters $AdditionalParameters
            } else {
                $results = Invoke-GetCCPCredential -Name $Filter -AdditionalParameters $AdditionalParameters
            }
        }
        'REST' {
            if (-not (Test-PASSession)) { return }
            $Keys = $RestKeys

            # Search with the longest non-wildcard fragment, then apply the real wildcard match locally.
            $SearchText = [regex]::Split($Filter, '[*?\[\]]') | Sort-Object -Property Length -Descending | Select-Object -First 1
            $GetPASAccountParameters = @{}
            if ($SearchText) { $GetPASAccountParameters.search = $SearchText }
            $VaultSafe = Get-CaseInsensitiveValue -Table $AdditionalParameters -Key 'safeName'
            if ($VaultSafe) { $GetPASAccountParameters.safeName = $VaultSafe }
            $results = Get-PASAccount @GetPASAccountParameters | Where-Object { $_.name -like $Filter } | Select-AccountInVaultSafe -SafeName $VaultSafe
        }
        Default {
            Write-Error "ConnectionType $($AdditionalParameters.ConnectionType) is not supported"
            return
        }
    }

    $Secrets = New-Object System.Collections.Generic.List[System.Object]

    foreach ($Account in $results) {
        $Metadata = [Ordered]@{}
        foreach ($Key in $Keys) {
            $Property = $Account.psobject.Properties[$Key]
            if ($null -eq $Property) { continue }
            $Value = ConvertTo-SecretMetadataValue -Key $Key -Value $Property.Value
            if ($null -ne $Value) { $Metadata[$Key] = $Value }
        }

        $SecretName = if ($Account.name) { "$($Account.name)" } else { $Filter }
        $SecretInfo = [Microsoft.PowerShell.SecretManagement.SecretInformation]::new(
            $SecretName, # Name of secret
            $SecretDataType, # Secret data type [Microsoft.PowerShell.SecretManagement.SecretType]
            $VaultName, # Name of vault
            $Metadata)  # Optional Metadata parameter)

        $Secrets.Add($SecretInfo)
    }

    return $Secrets
}

function ConvertTo-SecretMetadataValue {
    # SecretManagement metadata supports string, int and DateTime only.
    param ([string] $Key, $Value)

    if ($null -eq $Value) { return $null }
    if ($Key -eq 'createdTime' -and $Value -is [ValueType] -and $Value -isnot [datetime]) {
        # psPAS leaves REST times as Unix epoch seconds
        return [DateTimeOffset]::FromUnixTimeSeconds([long]$Value).UtcDateTime
    }
    if ($Value -is [string] -or $Value -is [datetime]) { return $Value }
    if ($Value -is [int]) { return $Value }
    if ($Value -is [long] -or $Value -is [int16] -or $Value -is [byte]) {
        if ($Value -ge [int]::MinValue -and $Value -le [int]::MaxValue) { return [int]$Value }
        return "$Value"
    }
    return $null
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

            $GetPASAccountParameters = @{ search = "$Name" }
            $VaultSafe = Get-CaseInsensitiveValue -Table $AdditionalParameters -Key 'safeName'
            if ($VaultSafe) { $GetPASAccountParameters.safeName = $VaultSafe }
            $results = @(Get-PASAccount @GetPASAccountParameters | Where-Object { $PSItem.name -eq $Name } | Select-AccountInVaultSafe -SafeName $VaultSafe)

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
        [hashtable] $AdditionalParameters,
        [hashtable] $Metadata
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
            $Known = 'SafeName', 'PlatformId', 'address', 'userName'
            $Resolved = @{}
            foreach ($Key in $Known) {
                $Value = Get-CaseInsensitiveValue -Table $Metadata -Key $Key
                if ($null -eq $Value) { $Value = Get-CaseInsensitiveValue -Table $AdditionalParameters -Key $Key }
                if ($null -ne $Value) { $Resolved[$Key] = $Value }
            }

            $Unknown = @($Metadata.Keys | Where-Object { $_ -notin $Known })
            if ($Unknown) {
                Write-Verbose "Ignoring unsupported Metadata keys: $($Unknown -join ', ')" -Verbose:($AdditionalParameters.Verbose -eq $true -or $VerbosePreference -eq 'Continue')
            }

            $Missing = @('SafeName', 'PlatformId' | Where-Object { -not $Resolved.ContainsKey($_) })
            if ($Missing) {
                Write-Error "SafeName and PlatformId are required (via -Metadata or VaultParameters); missing: $($Missing -join ', ')"
                return
            }

            # psPAS -secret takes a SecureString; accept what SecretManagement hands over (PSCredential from Get-Secret, string)
            $SecretValue = $Secret
            if ($Secret -is [pscredential]) {
                $SecretValue = $Secret.Password
                if (-not $Resolved.ContainsKey('userName') -and -not [string]::IsNullOrEmpty($Secret.UserName)) { $Resolved['userName'] = $Secret.UserName }
            } elseif ($Secret -is [string]) {
                $SecretValue = ConvertTo-SecureString -String $Secret -AsPlainText -Force
            } elseif ($null -ne $Secret -and $Secret -isnot [securestring]) {
                Write-Error "Set-Secret: unsupported secret type $($Secret.GetType().FullName) for REST; use a SecureString, string or PSCredential"
                return
            }

            if (-not (Test-PASSession)) { return }

            $AddPASAccountParameters = @{
                SafeName   = $Resolved.SafeName
                PlatformId = $Resolved.PlatformId
            }
            if ($Name) { $AddPASAccountParameters.Add('name', $Name) }
            if ($Resolved.ContainsKey('userName')) { $AddPASAccountParameters.Add('userName', $Resolved.userName) }
            if ($Resolved.ContainsKey('address')) { $AddPASAccountParameters.Add('address', $Resolved.address) }
            if ($SecretValue) { $AddPASAccountParameters.Add('secret', $SecretValue) }

            Add-PASAccount @AddPASAccountParameters
        }
        Default {
            Write-Error "ConnectionType $($AdditionalParameters.ConnectionType) is not supported"
            return
        }
    }
}

function Select-AccountInVaultSafe {
    # Enforces the vault's SafeName scope client-side too, so it holds even if the server-side filter does not.
    param ([Parameter(ValueFromPipeline)] $Account, [string] $SafeName)
    process {
        if ([string]::IsNullOrEmpty($SafeName) -or $Account.safeName -ieq $SafeName) { $Account }
    }
}

function Get-CaseInsensitiveValue {
    # Returns the first non-empty value whose key equals $Key ignoring case, else $null.
    param ([hashtable] $Table, [string] $Key)
    foreach ($K in $Table.Keys) {
        if ($K -ieq $Key -and -not [string]::IsNullOrEmpty("$($Table[$K])")) { return $Table[$K] }
    }
    return $null
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
    # Get-CCPCredential acts on a switch being bound, even as $false (UseDefaultCredentials would send OS credentials),
    # so switches are passed only when truthy.
    $SwitchKeys = @('SkipCertificateCheck', 'UseDefaultCredentials', 'FailRequestOnPasswordChange')

    $GetCCPCredentialParameters = @{}
    $IgnoredKeys = @()
    foreach ($Key in $AdditionalParameters.Keys) {
        if ($Key -in $AllowedKeys) {
            $CanonicalKey = $AllowedKeys | Where-Object { $_ -eq $Key }
            $Value = $AdditionalParameters[$Key]
            if ($CanonicalKey -in $SwitchKeys) {
                $Parsed = $false
                if ($Value -is [string] -and [bool]::TryParse($Value, [ref]$Parsed)) { $Value = $Parsed }
                if (-not $Value) { continue }
                $Value = $true
            }
            $GetCCPCredentialParameters[$CanonicalKey] = $Value
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
        [hashtable] $AdditionalParameters
    )

    if ($AdditionalParameters.ClientPath) { Set-AIMConfiguration -ClientPath $AdditionalParameters.ClientPath }

    $GetAIMCredentialParameters = @{
        AppID    = $AdditionalParameters.AppID
        UserName = $Name
    }
    # Optional vault-level scope; Get-AIMCredential's parameter is named Safe
    if ($AdditionalParameters.SafeName) { $GetAIMCredentialParameters.Add('Safe', $AdditionalParameters.SafeName) }
    # UserName is always requested so a PSCredential can be built
    $RequiredProps = @($AdditionalParameters.RequiredProps) + 'UserName' | Where-Object { $_ } | Select-Object -Unique
    $GetAIMCredentialParameters.Add('RequiredProps', $RequiredProps)

    $Credential = Get-AIMCredential @GetAIMCredentialParameters
    return $Credential
}
BeforeAll {
    Get-Module 'SecretManagement.CyberArk' | Remove-Module -Force
    Get-Module 'Microsoft.Powershell.SecretManagement' | Remove-Module -Force

    Import-Module Microsoft.PowerShell.SecretManagement
    $ExtensionModule = Import-Module "$PSScriptRoot/../SecretManagement.CyberArk.Extension/*.psd1" -Force -PassThru
    $VaultName = 'CyberArk.Test'

    Mock Get-PASAccount -MockWith {
        return [PSCustomObject]@{
            name     = 'localAdmin01'
            userName = 'localAdmin01'
            Id       = '1'
            safeName = 'LocalAdministrators'
        }
    } -ModuleName $ExtensionModule.Name
}

AfterAll {
    Remove-Module $ExtensionModule -Force
}
Describe 'Get-SecretInfo' {
    Context 'when connection type is REST' {
        BeforeAll {


            $VaultParams = @{ConnectionType = 'REST' }
            Mock Get-PASSession -MockWith { [PSCustomObject]@{ BaseURI = 'https://pvwa' } } -ModuleName $ExtensionModule.Name
        }

        It 'returns information on a secret' {
            $SecretInfo = Get-SecretInfo -Filter 'localAdmin01' -VaultName $VaultName -AdditionalParameters $VaultParams
            $SecretInfo | Should -Not -BeNullOrEmpty
            $SecretInfo | Should -BeOfType [Microsoft.PowerShell.SecretManagement.SecretInformation]
            $SecretInfo.Name | Should -Be 'localAdmin01'
            $SecretInfo.Metadata.userName | Should -Be 'localAdmin01'
            $SecretInfo.Metadata.id | Should -Be '1'
            $SecretInfo.Metadata.safeName | Should -Be 'LocalAdministrators'
        }

        It 'returns only allowed metadata keys with allowed types' {
            Mock Get-PASAccount -MockWith {
                [PSCustomObject]@{
                    id = '7'; name = 'acct'; userName = 'u'; address = 'host'; safeName = 'S'; platformId = 'P'; secretType = 'password'
                    createdTime = 1700000000; secret = 'sekrit'; Password = 'sekrit'; Content = 'sekrit'
                    platformAccountProperties = @{ a = 'b' }; secretManagement = @{ automaticManagementEnabled = $true }
                    remoteMachinesAccess = @{ x = 'y' }; empty = $null
                }
            } -ModuleName $ExtensionModule.Name
            $Info = Get-SecretInfo -Filter 'acct' -VaultName $VaultName -AdditionalParameters $VaultParams
            ($Info.Metadata.Keys | Sort-Object) | Should -Be @('address', 'createdTime', 'id', 'name', 'platformId', 'safeName', 'secretType', 'userName')
            $Info.Metadata['createdTime'] | Should -BeOfType [datetime]
            $Info.Metadata['createdTime'] | Should -Be ([datetime]::new(2023, 11, 14, 22, 13, 20, [DateTimeKind]::Utc))
            $Info.Metadata['id'] | Should -BeOfType [string]
            "$($Info.Metadata.Values)" | Should -Not -BeLike '*sekrit*'
        }

        It 'scopes results to the vault safeName' {
            Mock Get-PASAccount -MockWith {
                @(
                    [PSCustomObject]@{ id = '1'; name = 'acctA'; safeName = 'SafeA' },
                    [PSCustomObject]@{ id = '2'; name = 'acctB'; safeName = 'SafeB' }
                )
            } -ModuleName $ExtensionModule.Name
            $Info = @(Get-SecretInfo -Filter '*' -VaultName $VaultName -AdditionalParameters ($VaultParams + @{ SafeName = 'safea' }))
            $Info.Name | Should -Be 'acctA'
            Should -Invoke -CommandName Get-PASAccount -ModuleName $ExtensionModule.Name -Times 1 -Exactly -ParameterFilter { $safeName -eq 'safea' }
        }

        It 'converts createdTime given in milliseconds' {
            Mock Get-PASAccount -MockWith { [PSCustomObject]@{ id = '7'; name = 'acct'; createdTime = 1700000000000 } } -ModuleName $ExtensionModule.Name
            $Info = Get-SecretInfo -Filter 'acct' -VaultName $VaultName -AdditionalParameters $VaultParams
            $Info.Metadata['createdTime'] | Should -Be ([datetime]::new(2023, 11, 14, 22, 13, 20, [DateTimeKind]::Utc))
        }

        It 'drops an out-of-range or invalid createdTime without throwing' -ForEach @(
            @{ Value = 9000000000000000000L }, @{ Value = -9000000000000000000L }, @{ Value = [double]::MaxValue }, @{ Value = 'not-a-time' }, @{ Value = $true }
        ) {
            $global:CreatedTimeValue = $Value
            Mock Get-PASAccount -MockWith { [PSCustomObject]@{ id = '7'; name = 'acct'; createdTime = $global:CreatedTimeValue } } -ModuleName $ExtensionModule.Name
            $Info = Get-SecretInfo -Filter 'acct' -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction Stop
            $Info.Name | Should -Be 'acct'
            $Info.Metadata.Keys | Should -Not -Contain 'createdTime'
        }

        Context 'wildcard filtering' {
            BeforeEach {
                Mock Get-PASAccount -MockWith {
                    @(
                        [PSCustomObject]@{ id = '1'; name = 'localAdmin01' },
                        [PSCustomObject]@{ id = '2'; name = 'localAdmin02' },
                        [PSCustomObject]@{ id = '3'; name = 'domainAdmin' }
                    )
                } -ModuleName $ExtensionModule.Name
            }

            It 'searches with the non-wildcard text and filters results with -like' {
                $Info = @(Get-SecretInfo -Filter 'local*01' -VaultName $VaultName -AdditionalParameters $VaultParams)
                $Info.Name | Should -Be 'localAdmin01'
                Should -Invoke -CommandName Get-PASAccount -ModuleName $ExtensionModule.Name -Times 1 -Exactly -ParameterFilter { $search -eq 'local' }
            }

            It 'returns everything and does not search for *' {
                $Info = @(Get-SecretInfo -Filter '*' -VaultName $VaultName -AdditionalParameters $VaultParams)
                $Info.Count | Should -Be 3
                Should -Invoke -CommandName Get-PASAccount -ModuleName $ExtensionModule.Name -Times 1 -Exactly -ParameterFilter { -not $PesterBoundParameters.ContainsKey('search') }
            }

            It 'treats an empty filter as *' {
                @(Get-SecretInfo -Filter '' -VaultName $VaultName -AdditionalParameters $VaultParams).Count | Should -Be 3
            }

            It 'matches an exact name only' {
                $Info = @(Get-SecretInfo -Filter 'localAdmin0' -VaultName $VaultName -AdditionalParameters $VaultParams)
                $Info | Should -BeNullOrEmpty
            }

            It 'does not prefilter with -search when the filter has a [ character class, and still matches' {
                Mock Get-PASAccount -MockWith ([scriptblock]::Create('$global:PASBound = @($PesterBoundParameters.Keys); @([PSCustomObject]@{ id = "1"; name = "abz" }, [PSCustomObject]@{ id = "2"; name = "bc" })')) -ModuleName $ExtensionModule.Name
                $Info = @(Get-SecretInfo -Filter 'a[bc]z' -VaultName $VaultName -AdditionalParameters $VaultParams)
                $Info.Name | Should -Be 'abz'
                $global:PASBound | Should -Not -Contain 'search'
            }

            It 'does not prefilter with -search when the filter has an escaped wildcard, and matches it literally' {
                Mock Get-PASAccount -MockWith ([scriptblock]::Create('$global:PASBound = @($PesterBoundParameters.Keys); @([PSCustomObject]@{ id = "1"; name = "foo*bar" }, [PSCustomObject]@{ id = "2"; name = "fooXbar" })')) -ModuleName $ExtensionModule.Name
                $Info = @(Get-SecretInfo -Filter 'foo`*bar' -VaultName $VaultName -AdditionalParameters $VaultParams)
                $Info.Name | Should -Be 'foo*bar'
                $global:PASBound | Should -Not -Contain 'search'
            }

            It 'supports ? wildcards' {
                @(Get-SecretInfo -Filter 'localAdmin0?' -VaultName $VaultName -AdditionalParameters $VaultParams).Count | Should -Be 2
            }
        }

    }
    Context 'when connection type is Central Credential Provder' {
        BeforeAll {
            $VaultParams = @{ConnectionType = 'CentralCredentialProvider'; AppID = 'banana'; URL = 'https://banana.com' }
        }

        It 'invokes Get-CCPCredential' {
            Mock Get-CCPCredential -MockWith {
                [PSCustomObject]@{ UserName = 'svc-ccp'; Content = 'ccp-pass'; Address = 'host1'; Name = 'admin' }
            } -ModuleName $ExtensionModule.Name
            $Info = Get-SecretInfo -Filter 'admin' -VaultName $VaultName -AdditionalParameters $VaultParams
            Should -Invoke -CommandName Get-CCPCredential -ModuleName $ExtensionModule.Name
            $Info.Type | Should -Be 'PSCredential'
            $Info.Name | Should -Be 'admin'
            $Info.Metadata.Keys | Should -Not -Contain 'Content'
        }

        It 'writes an error with the exception message when Get-CCPCredential throws' {
            Mock Get-CCPCredential -MockWith { throw 'ccp exploded' } -ModuleName $ExtensionModule.Name
            $Info = Get-SecretInfo -Filter 'admin' -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction SilentlyContinue -ErrorVariable Err
            $Info | Should -BeNullOrEmpty
            "$Err" | Should -BeLike '*admin*ccp exploded*'
        }

        It 'returns only allowed metadata keys with allowed types' {
            Mock Get-CCPCredential -MockWith {
                [PSCustomObject]@{ Content = 'sekrit'; Name = 'admin'; UserName = 'svc'; Address = 'host'; Safe = 'S'; Folder = 'Root'; PolicyID = 'Pol'; DeviceType = 'Operating System'
                    PasswordChangeInProcess = $false; Extra = @{ a = 'b' }; Missing = $null }
            } -ModuleName $ExtensionModule.Name
            $Info = Get-SecretInfo -Filter 'admin' -VaultName $VaultName -AdditionalParameters $VaultParams
            ($Info.Metadata.Keys | Sort-Object) | Should -Be @('Address', 'DeviceType', 'Folder', 'Name', 'PolicyID', 'Safe', 'UserName')
            "$($Info.Metadata.Values)" | Should -Not -BeLike '*sekrit*'
        }

        It 'returns nothing without calling Get-CCPCredential when the filter has wildcards' -ForEach @('*', 'adm*', 'a?min', 'ad[a-z]in', '') {
            Mock Get-CCPCredential -MockWith { throw 'should not be called' } -ModuleName $ExtensionModule.Name
            $Verbose = Get-SecretInfo -Filter $_ -VaultName $VaultName -AdditionalParameters ($VaultParams + @{ Verbose = $true }) 4>&1
            @($Verbose | Where-Object { $_ -is [Microsoft.PowerShell.SecretManagement.SecretInformation] }) | Should -BeNullOrEmpty
            "$Verbose" | Should -BeLike '*wildcard*'
            Should -Invoke -CommandName Get-CCPCredential -ModuleName $ExtensionModule.Name -Times 0 -Exactly
        }

        It 'treats a filter without wildcards as the exact name' {
            Mock Get-CCPCredential -MockWith { [PSCustomObject]@{ Content = 'sekrit'; UserName = 'svc' } } -ModuleName $ExtensionModule.Name
            $Info = Get-SecretInfo -Filter 'myobject' -VaultName $VaultName -AdditionalParameters $VaultParams
            $Info.Name | Should -Be 'myobject'
        }

    }

    Context 'when connection type is Credential Provder' {
        BeforeAll {
            $VaultParams = @{ConnectionType = 'CredentialProvider'; AppID = 'banana' }
        }

        It 'invokes Get-AIMCredential' {
            Mock Get-AIMCredential -MockWith {
                [PSCustomObject]@{ UserName = 'svc-aim'; Password = 'aim-pass'; Address = 'host2'; Name = 'admin' }
            } -ModuleName $ExtensionModule.Name
            $Info = Get-SecretInfo -Filter 'admin' -VaultName $VaultName -AdditionalParameters $VaultParams
            Should -Invoke -CommandName Get-AIMCredential -ModuleName $ExtensionModule.Name
            $Info.Type | Should -Be 'PSCredential'
            $Info.Name | Should -Be 'admin'
            $Info.Metadata.Keys | Should -Not -Contain 'Password'
        }

        It 'writes an error with the exception message when Get-AIMCredential throws' {
            Mock Get-AIMCredential -MockWith { throw 'aim exploded' } -ModuleName $ExtensionModule.Name
            $Info = Get-SecretInfo -Filter 'admin' -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction SilentlyContinue -ErrorVariable Err
            $Info | Should -BeNullOrEmpty
            "$Err" | Should -BeLike '*admin*aim exploded*'
        }

        It 'reports the name it was looked up by (UserName) so the name round-trips into Get-Secret' {
            Mock Get-AIMCredential -MockWith {
                [PSCustomObject]@{ UserName = 'svc-aim'; Name = 'Operating System-WinDomain-host-svc-aim'; Password = 'x' }
            } -ModuleName $ExtensionModule.Name
            $Info = Get-SecretInfo -Filter 'svc-aim' -VaultName $VaultName -AdditionalParameters $VaultParams
            $Info.Name | Should -Be 'svc-aim'
            $null = Get-Secret -Name $Info.Name -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction SilentlyContinue
            Should -Invoke -CommandName Get-AIMCredential -ModuleName $ExtensionModule.Name -Times 2 -Exactly -ParameterFilter { $UserName -eq 'svc-aim' }
        }

        It 'passes the SafeName vault parameter to Get-AIMCredential as Safe' {
            Mock Get-AIMCredential -MockWith {
                [PSCustomObject]@{ UserName = 'svc-aim'; Name = 'admin' }
            } -ModuleName $ExtensionModule.Name
            $null = Get-SecretInfo -Filter 'admin' -VaultName $VaultName -AdditionalParameters ($VaultParams + @{SafeName = 'Windows' })
            Should -Invoke -CommandName Get-AIMCredential -ModuleName $ExtensionModule.Name -Times 1 -Exactly -ParameterFilter { $Safe -eq 'Windows' }
        }

        It 'returns only allowed metadata keys with allowed types' {
            Mock Get-AIMCredential -MockWith {
                [PSCustomObject]@{ Password = 'sekrit'; Name = 'admin'; UserName = 'svc'; Address = 'host'; Safe = 'S'; Folder = 'Root'; PolicyID = 'Pol'; DeviceType = 'Operating System'
                    PasswordChangeInProcess = $false; Extra = @{ a = 'b' }; Missing = $null }
            } -ModuleName $ExtensionModule.Name
            $Info = Get-SecretInfo -Filter 'admin' -VaultName $VaultName -AdditionalParameters $VaultParams
            ($Info.Metadata.Keys | Sort-Object) | Should -Be @('Address', 'DeviceType', 'Folder', 'Name', 'PolicyID', 'Safe', 'UserName')
            "$($Info.Metadata.Values)" | Should -Not -BeLike '*sekrit*'
        }

        It 'returns nothing without calling Get-AIMCredential when the filter has wildcards' -ForEach @('*', 'adm*', 'a?min', 'ad[a-z]in', '') {
            Mock Get-AIMCredential -MockWith { throw 'should not be called' } -ModuleName $ExtensionModule.Name
            $Verbose = Get-SecretInfo -Filter $_ -VaultName $VaultName -AdditionalParameters ($VaultParams + @{ Verbose = $true }) 4>&1
            @($Verbose | Where-Object { $_ -is [Microsoft.PowerShell.SecretManagement.SecretInformation] }) | Should -BeNullOrEmpty
            "$Verbose" | Should -BeLike '*wildcard*'
            Should -Invoke -CommandName Get-AIMCredential -ModuleName $ExtensionModule.Name -Times 0 -Exactly
        }

        It 'treats a filter without wildcards as the exact name' {
            Mock Get-AIMCredential -MockWith { [PSCustomObject]@{ Password = 'sekrit'; UserName = 'svc' } } -ModuleName $ExtensionModule.Name
            $Info = Get-SecretInfo -Filter 'myobject' -VaultName $VaultName -AdditionalParameters $VaultParams
            $Info.Name | Should -Be 'myobject'
        }

    }
}
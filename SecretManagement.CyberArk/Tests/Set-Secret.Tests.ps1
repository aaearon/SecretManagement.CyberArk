BeforeAll {
    Get-Module 'SecretManagement.CyberArk' | Remove-Module -Force
    Get-Module 'Microsoft.Powershell.SecretManagement' | Remove-Module -Force

    $ExtensionModule = Import-Module "$PSScriptRoot/../SecretManagement.CyberArk.Extension/*.psd1" -Force -PassThru
    $VaultName = 'CyberArk.Test'
}

AfterAll {
    Remove-Module $ExtensionModule -Force
}

Describe 'Set-Secret' {
    Context 'when connection method is REST' {
        BeforeAll {
            $VaultParams = @{ConnectionType = 'REST' }
            Mock Get-PASSession -MockWith { [PSCustomObject]@{ BaseURI = 'https://pvwa' } } -ModuleName $ExtensionModule.Name
        }

        It 'calls Add-PASAccount' {
            Mock Add-PASAccount -MockWith {} -ModuleName $ExtensionModule.Name

            Set-Secret -VaultName $VaultName -Name 'test' -AdditionalParameters ($VaultParams + @{PlatformId = 'Test'; SafeName = 'TestSafe' }) -Secret ('test' | ConvertTo-SecureString -AsPlainText -Force)
            Should -Invoke -CommandName Add-PASAccount -ModuleName $ExtensionModule.Name
        }

        It 'writes an error when SafeName and PlatformId are missing' {
            Mock Add-PASAccount -MockWith {} -ModuleName $ExtensionModule.Name

            Set-Secret -VaultName $VaultName -AdditionalParameters $VaultParams -Name 'test' -Secret ('test' | ConvertTo-SecureString -AsPlainText -Force) -ErrorAction SilentlyContinue -ErrorVariable Err
            "$Err" | Should -BeLike '*SafeName and PlatformId are required*'
            Should -Invoke -CommandName Add-PASAccount -ModuleName $ExtensionModule.Name -Times 0 -Exactly
        }

    }

    Context 'when connection method is REST and Metadata is supplied' {
        BeforeAll {
            Mock Get-PASSession -MockWith { [PSCustomObject]@{ BaseURI = 'https://pvwa' } } -ModuleName $ExtensionModule.Name
            $Plain = 'Zq9-UniqueSecretValue-81!'
            $Sec = ConvertTo-SecureString $Plain -AsPlainText -Force
            $Full = @{ SafeName = 'MSafe'; PlatformId = 'MPlat'; address = 'm.host'; userName = 'muser' }
        }

        BeforeEach {
            Mock Add-PASAccount -MockWith {} -ModuleName $ExtensionModule.Name
        }

        It 'takes all four values from Metadata when vault parameters lack them' {
            Set-Secret -Name 'n' -Secret $Sec -VaultName $VaultName -AdditionalParameters @{ConnectionType = 'REST' } -Metadata $Full
            Should -Invoke Add-PASAccount -ModuleName $ExtensionModule.Name -Times 1 -Exactly -ParameterFilter {
                $SafeName -eq 'MSafe' -and $platformID -eq 'MPlat' -and $address -eq 'm.host' -and $userName -eq 'muser' -and $name -eq 'n'
            }
        }

        It 'keeps working from vault parameters only' {
            $vp = @{ConnectionType = 'REST'; SafeName = 'VSafe'; PlatformId = 'VPlat'; address = 'v.host'; userName = 'vuser' }
            Set-Secret -Name 'n' -Secret $Sec -VaultName $VaultName -AdditionalParameters $vp -Metadata @{}
            Should -Invoke Add-PASAccount -ModuleName $ExtensionModule.Name -Times 1 -Exactly -ParameterFilter {
                $SafeName -eq 'VSafe' -and $platformID -eq 'VPlat' -and $address -eq 'v.host' -and $userName -eq 'vuser'
            }
        }

        It 'lets Metadata win per key over vault parameters' {
            $vp = @{ConnectionType = 'REST'; SafeName = 'VSafe'; PlatformId = 'VPlat'; address = 'v.host'; userName = 'vuser' }
            Set-Secret -Name 'n' -Secret $Sec -VaultName $VaultName -AdditionalParameters $vp -Metadata $Full
            Should -Invoke Add-PASAccount -ModuleName $ExtensionModule.Name -Times 1 -Exactly -ParameterFilter {
                $SafeName -eq 'MSafe' -and $platformID -eq 'MPlat' -and $address -eq 'm.host' -and $userName -eq 'muser'
            }
        }

        It 'mixes sources: SafeName from Metadata, PlatformId and userName from vault' {
            $vp = @{ConnectionType = 'REST'; SafeName = 'VSafe'; PlatformId = 'VPlat'; userName = 'vuser' }
            Set-Secret -Name 'n' -Secret $Sec -VaultName $VaultName -AdditionalParameters $vp -Metadata @{ SafeName = 'MSafe' }
            Should -Invoke Add-PASAccount -ModuleName $ExtensionModule.Name -Times 1 -Exactly -ParameterFilter {
                $SafeName -eq 'MSafe' -and $platformID -eq 'VPlat' -and $userName -eq 'vuser' -and -not $PesterBoundParameters.ContainsKey('address')
            }
        }

        It 'falls back to vault parameters when a Metadata value is empty' {
            $vp = @{ConnectionType = 'REST'; SafeName = 'VSafe'; PlatformId = 'VPlat' }
            Set-Secret -Name 'n' -Secret $Sec -VaultName $VaultName -AdditionalParameters $vp -Metadata @{ SafeName = '' }
            Should -Invoke Add-PASAccount -ModuleName $ExtensionModule.Name -Times 1 -Exactly -ParameterFilter { $SafeName -eq 'VSafe' }
        }

        It 'writes an error naming <Missing> and does not call Add-PASAccount' -ForEach @(
            @{ Meta = @{ PlatformId = 'P' }; Vp = @{ConnectionType = 'REST' }; Missing = 'SafeName' }
            @{ Meta = @{ SafeName = 'S' }; Vp = @{ConnectionType = 'REST' }; Missing = 'PlatformId' }
            @{ Meta = @{}; Vp = @{ConnectionType = 'REST' }; Missing = 'SafeName, PlatformId' }
        ) {
            Set-Secret -Name 'n' -Secret $Sec -VaultName $VaultName -AdditionalParameters $Vp -Metadata $Meta -ErrorAction SilentlyContinue -ErrorVariable Err
            "$Err" | Should -BeLike "*missing*$Missing*"
            Should -Invoke Add-PASAccount -ModuleName $ExtensionModule.Name -Times 0 -Exactly
        }

        It 'accepts case variants of keys in Metadata' -ForEach @('safename', 'SAFENAME', 'SafeName') {
            $m = @{ PLATFORMID = 'P'; ADDRESS = 'a'; USERNAME = 'u' }
            $m[$_] = 'CaseSafe'
            Set-Secret -Name 'n' -Secret $Sec -VaultName $VaultName -AdditionalParameters @{ConnectionType = 'REST' } -Metadata $m
            Should -Invoke Add-PASAccount -ModuleName $ExtensionModule.Name -Times 1 -Exactly -ParameterFilter {
                $SafeName -eq 'CaseSafe' -and $platformID -eq 'P' -and $address -eq 'a' -and $userName -eq 'u'
            }
        }

        It 'accepts case variants of keys in case-sensitive AdditionalParameters' -ForEach @('safename', 'SAFENAME', 'SafeName') {
            $vp = [System.Collections.Hashtable]::new([System.StringComparer]::Ordinal)
            $vp['ConnectionType'] = 'REST'; $vp['platformid'] = 'P'; $vp['ADDRESS'] = 'a'; $vp['USERNAME'] = 'u'
            $vp[$_] = 'CaseSafe'
            Set-Secret -Name 'n' -Secret $Sec -VaultName $VaultName -AdditionalParameters $vp -Metadata @{}
            Should -Invoke Add-PASAccount -ModuleName $ExtensionModule.Name -Times 1 -Exactly -ParameterFilter {
                $SafeName -eq 'CaseSafe' -and $platformID -eq 'P' -and $address -eq 'a' -and $userName -eq 'u'
            }
        }

        It 'ignores unknown Metadata keys, names them only as keys, and never leaks the secret' {
            $m = $Full + @{ Colour = 'blue'; Owner = 'bob' }
            $out = Set-Secret -Name 'n' -Secret $Sec -VaultName $VaultName -AdditionalParameters @{ConnectionType = 'REST'; Verbose = $true } -Metadata $m -Verbose -WarningAction Continue *>&1 | Out-String
            Should -Invoke Add-PASAccount -ModuleName $ExtensionModule.Name -Times 1 -Exactly -ParameterFilter {
                -not $PesterBoundParameters.ContainsKey('Colour') -and -not $PesterBoundParameters.ContainsKey('Owner') -and $SafeName -eq 'MSafe'
            }
            $out | Should -BeLike '*Colour*'
            $out | Should -BeLike '*Owner*'
            $out | Should -Not -BeLike '*blue*'
            $out | Should -Not -BeLike "*$Plain*"
        }

        It 'omits name when no Name is given' {
            Set-Secret -Secret $Sec -VaultName $VaultName -AdditionalParameters @{ConnectionType = 'REST' } -Metadata $Full
            Should -Invoke Add-PASAccount -ModuleName $ExtensionModule.Name -Times 1 -Exactly -ParameterFilter { -not $PesterBoundParameters.ContainsKey('name') }
        }

        It 'names unknown keys in verbose output on a direct -Verbose call' {
            $out = Set-Secret -Name 'n' -Secret $Sec -VaultName $VaultName -AdditionalParameters @{ConnectionType = 'REST' } -Metadata ($Full + @{ Bogus = 'x' }) -Verbose 4>&1 | Out-String
            $out | Should -BeLike '*Bogus*'
            $out | Should -Not -BeLike "*$Plain*"
        }

        It 'does not leak the secret in the missing-key error' {
            Set-Secret -Name 'n' -Secret $Sec -VaultName $VaultName -AdditionalParameters @{ConnectionType = 'REST' } -Metadata @{} -ErrorAction SilentlyContinue -ErrorVariable Err -WarningVariable Warn
            "$Err $Warn" | Should -Not -BeLike "*$Plain*"
        }

        Context 'secret types' {
            BeforeAll { $Base = @{ SafeName = 'S'; PlatformId = 'P' } }

            It 'converts a string secret to a SecureString' {
                Set-Secret -Name 'n' -Secret 'plain-pw' -VaultName $VaultName -AdditionalParameters @{ConnectionType = 'REST' } -Metadata $Base
                Should -Invoke Add-PASAccount -ModuleName $ExtensionModule.Name -Times 1 -Exactly -ParameterFilter {
                    $secret -is [securestring] -and [System.Net.NetworkCredential]::new('', $secret).Password -eq 'plain-pw'
                }
            }

            It 'passes a SecureString through' {
                Set-Secret -Name 'n' -Secret $Sec -VaultName $VaultName -AdditionalParameters @{ConnectionType = 'REST' } -Metadata $Base
                Should -Invoke Add-PASAccount -ModuleName $ExtensionModule.Name -Times 1 -Exactly -ParameterFilter {
                    $secret -is [securestring] -and [System.Net.NetworkCredential]::new('', $secret).Password -eq $Plain
                }
            }

            It 'uses the password of a PSCredential and its UserName when userName is not supplied' {
                $Cred = [pscredential]::new('cred-user', $Sec)
                Set-Secret -Name 'n' -Secret $Cred -VaultName $VaultName -AdditionalParameters @{ConnectionType = 'REST' } -Metadata $Base
                Should -Invoke Add-PASAccount -ModuleName $ExtensionModule.Name -Times 1 -Exactly -ParameterFilter {
                    $secret -is [securestring] -and [System.Net.NetworkCredential]::new('', $secret).Password -eq $Plain -and $userName -eq 'cred-user'
                }
            }

            It 'prefers a userName from Metadata over the PSCredential UserName' {
                $Cred = [pscredential]::new('cred-user', $Sec)
                Set-Secret -Name 'n' -Secret $Cred -VaultName $VaultName -AdditionalParameters @{ConnectionType = 'REST' } -Metadata ($Base + @{ userName = 'meta-user' })
                Should -Invoke Add-PASAccount -ModuleName $ExtensionModule.Name -Times 1 -Exactly -ParameterFilter { $userName -eq 'meta-user' }
            }

            It 'writes an error without calling Add-PASAccount for an unsupported secret type and never echoes the value' {
                Set-Secret -Name 'n' -Secret @{ pw = $Plain } -VaultName $VaultName -AdditionalParameters @{ConnectionType = 'REST' } -Metadata $Base -ErrorAction SilentlyContinue -ErrorVariable Err
                "$Err" | Should -BeLike '*secret type*'
                "$Err" | Should -Not -BeLike "*$Plain*"
                Should -Invoke Add-PASAccount -ModuleName $ExtensionModule.Name -Times 0 -Exactly
            }
        }

        It 'writes an error with the exception message and no secret when Add-PASAccount throws' {
            Mock Add-PASAccount -MockWith { throw 'safe is full' } -ModuleName $ExtensionModule.Name
            Set-Secret -Name 'n' -Secret $Sec -VaultName $VaultName -AdditionalParameters @{ConnectionType = 'REST' } -Metadata $Full -ErrorAction SilentlyContinue -ErrorVariable Err
            "$Err" | Should -BeLike '*n*safe is full*'
            "$Err" | Should -Not -BeLike "*$Plain*"
        }

        It 'works when called exactly as SecretManagement calls it' {
            $params = @{
                Name                 = 'n'
                Secret               = $Sec
                VaultName            = $VaultName
                AdditionalParameters = @{ConnectionType = 'REST'; Verbose = $false }
                Metadata             = $Full
            }
            Set-Secret @params
            Should -Invoke Add-PASAccount -ModuleName $ExtensionModule.Name -Times 1 -Exactly -ParameterFilter { $SafeName -eq 'MSafe' -and $secret }
        }

    }

    Context 'when connection type is Credential Provider' {
        It 'writes an error' {
            $VaultParams = @{ConnectionType = 'CredentialProvider' }
            Set-Secret -Name 'admin' -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction SilentlyContinue -ErrorVariable Err
            "$Err" | Should -BeLike '*Set-Secret is not supported for Credential Provider*'
        }
    }

    Context 'when connection type is Central Credential Provider' {
        It 'writes an error' {
            $VaultParams = @{ConnectionType = 'CentralCredentialProvider' }
            Set-Secret -Name 'admin' -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction SilentlyContinue -ErrorVariable Err
            "$Err" | Should -BeLike '*Set-Secret is not supported for Central Credential Provider*'
        }
    }
}

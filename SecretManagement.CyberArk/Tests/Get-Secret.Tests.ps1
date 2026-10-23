# Credit for most of this goes to https://github.com/JustinGrote/SecretManagement.KeePass/blob/main/SecretManagement.KeePass/Tests/Get-Secret.Tests.ps1
BeforeAll {
    Get-Module 'SecretManagement.CyberArk' | Remove-Module -Force
    Get-Module 'Microsoft.Powershell.SecretManagement' | Remove-Module -Force

    $ExtensionModule = Import-Module "$PSScriptRoot/../SecretManagement.CyberArk.Extension/*.psd1" -Force -PassThru
    $VaultName = 'CyberArk.Test'
}

AfterAll {
    Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Unregister-SecretVault
    Remove-Module $ExtensionModule -Force
}

Describe 'Get-Secret' {
    Context 'when connection type is REST' {
        BeforeAll {
            Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Unregister-SecretVault
            $VaultParams = @{ConnectionType = 'REST' }
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters $VaultParams
            Mock Get-PASSession -MockWith { [PSCustomObject]@{ BaseURI = 'https://pvwa' } } -ModuleName $ExtensionModule.Name
        }
        It 'should return a <PSType> for <SecretName>' {
            Mock Get-PASAccountPassword -MockWith {
                $Result = [PSCustomObject]@{
                    Password = 'fake'
                    userName = 'localAdmin01'
                }
                $Result | Add-Member -MemberType ScriptMethod -Name 'ToSecureString' -Value { $this | Select-Object -ExpandProperty Password | ConvertTo-SecureString -AsPlainText -Force }
                return $Result
            } -ModuleName $ExtensionModule.Name
            Mock Get-PASAccount -MockWith {
                return [PSCustomObject]@{
                    name     = 'localAdmin01'
                    userName = 'localAdmin01'
                    Id       = '1'
                }
            } -ModuleName $ExtensionModule.Name

            $Secret = Get-Secret -Name $SecretName -VaultName $VaultName -AdditionalParameters $VaultParams
            $Secret | Should -Not -BeNullOrEmpty
            $Secret | Should -BeOfType $PSType
        } -TestCases (
            @{SecretName = 'localAdmin01'; PSType = 'System.Management.Automation.PSCredential' }
        )
        Context 'when the search returns several accounts' {
            BeforeEach {
                Mock Get-PASAccountPassword -MockWith {
                    $Result = [PSCustomObject]@{ Password = 'fake'; userName = 'admin' }
                    $Result | Add-Member -MemberType ScriptMethod -Name 'ToSecureString' -Value { $this | Select-Object -ExpandProperty Password | ConvertTo-SecureString -AsPlainText -Force }
                    return $Result
                } -ModuleName $ExtensionModule.Name
            }

            It 'returns null and does not retrieve a password when only substring matches are found' {
                Mock Get-PASAccount -MockWith {
                    @(
                        [PSCustomObject]@{ name = 'localAdmin01'; userName = 'localAdmin01'; Id = '1' },
                        [PSCustomObject]@{ name = 'localAdmin02'; userName = 'localAdmin02'; Id = '2' }
                    )
                } -ModuleName $ExtensionModule.Name

                Get-Secret -Name 'admin' -VaultName $VaultName -AdditionalParameters $VaultParams | Should -BeNullOrEmpty
                Should -Invoke -CommandName Get-PASAccountPassword -ModuleName $ExtensionModule.Name -Times 0 -Exactly
            }

            It 'writes an error and does not retrieve a password when more than one exact match is found' {
                Mock Get-PASAccount -MockWith {
                    @(
                        [PSCustomObject]@{ name = 'admin'; userName = 'admin'; Id = '1' },
                        [PSCustomObject]@{ name = 'ADMIN'; userName = 'ADMIN'; Id = '2' }
                    )
                } -ModuleName $ExtensionModule.Name

                Get-Secret -Name 'admin' -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction SilentlyContinue -ErrorVariable Err -WarningAction SilentlyContinue -WarningVariable Warn | Should -BeNullOrEmpty
                "$Err" | Should -BeLike '*2*admin*'
                $Warn | Should -BeNullOrEmpty
                Should -Invoke -CommandName Get-PASAccountPassword -ModuleName $ExtensionModule.Name -Times 0 -Exactly
            }

            It 'returns the single exact match among substring matches' {
                Mock Get-PASAccount -MockWith {
                    @(
                        [PSCustomObject]@{ name = 'admin2'; userName = 'admin2'; Id = '1' },
                        [PSCustomObject]@{ name = 'ADMIN'; userName = 'admin'; Id = '2' },
                        [PSCustomObject]@{ name = 'localadmin'; userName = 'localadmin'; Id = '3' }
                    )
                } -ModuleName $ExtensionModule.Name

                Get-Secret -Name 'admin' -VaultName $VaultName -AdditionalParameters $VaultParams | Should -BeOfType System.Management.Automation.PSCredential
                Should -Invoke -CommandName Get-PASAccountPassword -ModuleName $ExtensionModule.Name -Times 1 -Exactly -ParameterFilter { $AccountId -eq '2' }
            }
        }

        It 'writes an error with the underlying message when retrieving the password fails' {
            Mock Get-PASAccount -MockWith { [PSCustomObject]@{ name = 'admin'; userName = 'admin'; Id = '1' } } -ModuleName $ExtensionModule.Name
            Mock Get-PASAccountPassword -MockWith { throw 'access denied by policy' } -ModuleName $ExtensionModule.Name

            Get-Secret -Name 'admin' -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction SilentlyContinue -ErrorVariable Err | Should -BeNullOrEmpty
            "$Err" | Should -BeLike '*admin*access denied by policy*'
        }

        It 'writes an error when there is no PASSession' {
            Mock Get-PASSession -MockWith { throw 'no session' } -ModuleName $ExtensionModule.Name
            Mock Get-PASAccount -MockWith {} -ModuleName $ExtensionModule.Name

            Get-Secret -Name 'admin' -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction SilentlyContinue -ErrorVariable Err | Should -BeNullOrEmpty
            "$Err" | Should -BeLike '*Failed to get PASSession*'
            Should -Invoke -CommandName Get-PASAccount -ModuleName $ExtensionModule.Name -Times 0 -Exactly
        }

        It 'should have a PASAccount parameter' {
            'PASAccount' | Should -BeIn ((Get-Command -Module $ExtensionModule.Name -Name 'Get-Secret').Parameters.Keys)
        }
        AfterAll {
            Unregister-SecretVault -Name $VaultName
        }
    }

    Context 'when connection type is unknown' {
        It 'writes an error' {
            Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Unregister-SecretVault
            $VaultParams = @{ConnectionType = 'Bogus' }
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters $VaultParams
            Get-Secret -Name 'admin' -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction SilentlyContinue -ErrorVariable Err | Should -BeNullOrEmpty
            "$Err" | Should -BeLike '*ConnectionType Bogus is not supported*'
            Unregister-SecretVault -Name $VaultName
        }
    }

    Context 'when connection type is Central Credential Provider' {


        BeforeAll {
            Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Unregister-SecretVault
            $VaultParams = @{ConnectionType = 'CentralCredentialProvider'; AppID = 'banana'; URL = 'https://banana.com' }
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters $VaultParams
        }

        It 'invokes Get-CCPCredential' {
            Mock Get-CCPCredential -MockWith {
                $Result = [PSCustomObject]@{ UserName = 'svc-ccp'; Content = 'ccp-pass'; Address = 'host1'; Name = 'admin' }
                $Result | Add-Member -MemberType ScriptMethod -Name 'ToSecureString' -Value { $this.Content | ConvertTo-SecureString -AsPlainText -Force }
                $Result | Add-Member -MemberType ScriptMethod -Name 'ToCredential' -Value { New-Object System.Management.Automation.PSCredential($this.UserName, $this.ToSecureString()) }
                return $Result
            } -ModuleName $ExtensionModule.Name
            $Secret = Get-Secret -Name 'admin' -VaultName $VaultName -AdditionalParameters $VaultParams
            Should -Invoke -CommandName Get-CCPCredential -ModuleName $ExtensionModule.Name
            $Secret | Should -BeOfType System.Management.Automation.PSCredential
            $Secret.UserName | Should -Be 'svc-ccp'
            $Secret.GetNetworkCredential().Password | Should -Be 'ccp-pass'
        }

        Context 'vault parameter allowlist' {
            BeforeEach {
                Mock Get-CCPCredential -MockWith {
                    $Result = [PSCustomObject]@{ UserName = 'svc-ccp'; Content = 'ccp-pass'; Name = 'admin' }
                    $Result | Add-Member -MemberType ScriptMethod -Name 'ToSecureString' -Value { $this.Content | ConvertTo-SecureString -AsPlainText -Force }
                    $Result | Add-Member -MemberType ScriptMethod -Name 'ToCredential' -Value { New-Object System.Management.Automation.PSCredential($this.UserName, $this.ToSecureString()) }
                    return $Result
                } -ModuleName $ExtensionModule.Name
            }

            It 'passes allowed connection settings and the object name' {
                $Params = @{
                    ConnectionType = 'CentralCredentialProvider'; AppID = 'banana'; URL = 'https://banana.com'
                    SkipCertificateCheck = $true; UseDefaultCredentials = $true; CertificateThumbPrint = 'ABC123'
                    WebServiceName = 'AIMWebService'; ConnectionTimeout = 30; Method = 'GET'; FailRequestOnPasswordChange = $true
                }
                $null = Get-Secret -Name 'admin' -VaultName $VaultName -AdditionalParameters $Params -WarningVariable Warn -WarningAction SilentlyContinue
                $Warn | Should -BeNullOrEmpty
                Should -Invoke -CommandName Get-CCPCredential -ModuleName $ExtensionModule.Name -Times 1 -Exactly -ParameterFilter {
                    $AppID -eq 'banana' -and $URL -eq 'https://banana.com' -and $SkipCertificateCheck -and $UseDefaultCredentials -and
                    $CertificateThumbPrint -eq 'ABC123' -and $WebServiceName -eq 'AIMWebService' -and $ConnectionTimeout -eq 30 -and
                    $Method -eq 'GET' -and $FailRequestOnPasswordChange -and $Object -eq 'admin'
                }
            }

            It 'ignores Verbose silently and warns about unknown keys, naming only the keys' {
                $Params = @{
                    ConnectionType = 'CentralCredentialProvider'; AppID = 'banana'; URL = 'https://banana.com'; Verbose = $false
                    Bogus = 'sekrit-value'; Safe = 'sekrit-safe'; AsCredential = $true
                }
                $null = Get-Secret -Name 'admin' -VaultName $VaultName -AdditionalParameters $Params -WarningVariable Warn -WarningAction SilentlyContinue
                "$Warn" | Should -BeLike '*Bogus*'
                "$Warn" | Should -BeLike '*Safe*'
                "$Warn" | Should -BeLike '*AsCredential*'
                "$Warn" | Should -Not -BeLike '*sekrit*'
                "$Warn" | Should -Not -BeLike '*ConnectionType*'
                "$Warn" | Should -Not -BeLike '*Verbose*'
                Should -Invoke -CommandName Get-CCPCredential -ModuleName $ExtensionModule.Name -Times 1 -Exactly -ParameterFilter {
                    -not $PSBoundParameters.ContainsKey('Bogus') -and -not $PSBoundParameters.ContainsKey('Safe') -and
                    -not $PSBoundParameters.ContainsKey('AsCredential') -and $AppID -eq 'banana'
                }
            }

            It 'does not pass Credential or Certificate and warns about them' {
                $Params = @{
                    ConnectionType = 'CentralCredentialProvider'; AppID = 'banana'; URL = 'https://banana.com'
                    Credential = @{ UserName = 'u' }; Certificate = @{ Subject = 'cn=x' }
                }
                $null = Get-Secret -Name 'admin' -VaultName $VaultName -AdditionalParameters $Params -WarningVariable Warn -WarningAction SilentlyContinue
                "$Warn" | Should -BeLike '*Credential*'
                "$Warn" | Should -BeLike '*Certificate*'
                Should -Invoke -CommandName Get-CCPCredential -ModuleName $ExtensionModule.Name -Times 1 -Exactly -ParameterFilter {
                    -not $PSBoundParameters.ContainsKey('Credential') -and -not $PSBoundParameters.ContainsKey('Certificate')
                }
            }
        }

        AfterAll {
            Unregister-SecretVault -Name $VaultName
        }
    }

    Context 'when connection type is Credential Provder' {
        BeforeAll {
            Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Unregister-SecretVault
            $VaultParams = @{ConnectionType = 'CredentialProvider'; AppID = 'banana' }
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters $VaultParams
        }

        It 'invokes Get-AIMCredential' {
            Mock Get-AIMCredential -MockWith {
                $Result = [PSCustomObject]@{ UserName = 'svc-aim'; Password = 'aim-pass'; Address = 'host2'; Name = 'windowsAdmin01' }
                $Result | Add-Member -MemberType ScriptMethod -Name 'ToSecureString' -Value { $this.Password | ConvertTo-SecureString -AsPlainText -Force }
                $Result | Add-Member -MemberType ScriptMethod -Name 'ToCredential' -Value { New-Object System.Management.Automation.PSCredential($this.UserName, $this.ToSecureString()) }
                return $Result
            } -ModuleName $ExtensionModule.Name
            $Secret = Get-Secret -Name 'windowsAdmin01' -SafeName 'Windows' -VaultName $VaultName -AdditionalParameters $VaultParams
            Should -Invoke -CommandName Get-AIMCredential -ModuleName $ExtensionModule.Name
            $Secret | Should -BeOfType System.Management.Automation.PSCredential
            $Secret.UserName | Should -Be 'svc-aim'
            $Secret.GetNetworkCredential().Password | Should -Be 'aim-pass'
        }

        It 'always requests UserName so a PSCredential can be built' {
            Mock Get-AIMCredential -MockWith {
                $Result = [PSCustomObject]@{ UserName = 'svc-aim'; Password = 'aim-pass'; Address = 'host2'; Name = 'windowsAdmin01' }
                $Result | Add-Member -MemberType ScriptMethod -Name 'ToSecureString' -Value { $this.Password | ConvertTo-SecureString -AsPlainText -Force }
                $Result | Add-Member -MemberType ScriptMethod -Name 'ToCredential' -Value { New-Object System.Management.Automation.PSCredential($this.UserName, $this.ToSecureString()) }
                return $Result
            } -ModuleName $ExtensionModule.Name
            $null = Get-Secret -Name 'windowsAdmin01' -SafeName 'Windows' -VaultName $VaultName -AdditionalParameters $VaultParams
            Should -Invoke -CommandName Get-AIMCredential -ModuleName $ExtensionModule.Name -ParameterFilter { $RequiredProps -contains 'UserName' }
        }

        AfterAll {
            Unregister-SecretVault -Name $VaultName
        }
    }
}
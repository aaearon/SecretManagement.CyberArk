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
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters @{ConnectionType = 'REST' }
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

            $Secret = Get-Secret -Name $SecretName -VaultName $VaultName
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

                Get-Secret -Name 'admin' -VaultName $VaultName | Should -BeNullOrEmpty
                Should -Invoke -CommandName Get-PASAccountPassword -ModuleName $ExtensionModule.Name -Times 0 -Exactly
            }

            It 'throws and does not retrieve a password when more than one exact match is found' {
                Mock Get-PASAccount -MockWith {
                    @(
                        [PSCustomObject]@{ name = 'admin'; userName = 'admin'; Id = '1' },
                        [PSCustomObject]@{ name = 'ADMIN'; userName = 'ADMIN'; Id = '2' }
                    )
                } -ModuleName $ExtensionModule.Name

                { Get-Secret -Name 'admin' -VaultName $VaultName -ErrorAction Stop } | Should -Throw '*2*admin*'
                try { Get-Secret -Name 'admin' -VaultName $VaultName -WarningVariable Warn } catch { }
                "$Warn" | Should -BeLike '*2*admin*'
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

                Get-Secret -Name 'admin' -VaultName $VaultName | Should -BeOfType System.Management.Automation.PSCredential
                Should -Invoke -CommandName Get-PASAccountPassword -ModuleName $ExtensionModule.Name -Times 1 -Exactly -ParameterFilter { $AccountId -eq '2' }
            }
        }

        It 'should have a PASAccount parameter' {
            'PASAccount' | Should -BeIn ((Get-Command -Module $ExtensionModule.Name -Name 'Get-Secret').Parameters.Keys)
        }
        AfterAll {
            Unregister-SecretVault -Name $VaultName
        }
    }

    Context 'when connection type is Central Credential Provider' {


        BeforeAll {
            Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Unregister-SecretVault
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters @{ConnectionType = 'CentralCredentialProvider'; AppID = 'banana'; URL = 'https://banana.com' }
        }

        It 'invokes Get-CCPCredential' {
            Mock Get-CCPCredential -MockWith {} -ModuleName $ExtensionModule.Name
            Get-Secret -Name 'admin' -VaultName $VaultName
            Should -Invoke -CommandName Get-CCPCredential -ModuleName $ExtensionModule.Name
        }

        AfterAll {
            Unregister-SecretVault -Name $VaultName
        }
    }

    Context 'when connection type is Credential Provder' {
        BeforeAll {
            Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Unregister-SecretVault
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters @{ConnectionType = 'CredentialProvider'; AppID = 'banana' }
        }

        It 'invokes Get-AIMCredential' {
            Mock Get-AIMCredential -MockWith {} -ModuleName $ExtensionModule.Name
            Get-Secret -Name 'windowsAdmin01' -SafeName 'Windows' -VaultName $VaultName
            Should -Invoke -CommandName Get-AIMCredential -ModuleName $ExtensionModule.Name
        }

        AfterAll {
            Unregister-SecretVault -Name $VaultName
        }
    }
}
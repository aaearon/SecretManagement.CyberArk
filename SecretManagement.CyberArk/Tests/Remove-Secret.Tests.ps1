BeforeAll {
    Get-Module 'SecretManagement.CyberArk' | Remove-Module -Force
    Get-Module 'Microsoft.Powershell.SecretManagement' | Remove-Module -Force

    $ExtensionModule = Import-Module "$PSScriptRoot/../SecretManagement.CyberArk.Extension/*.psd1" -Force -PassThru
    $VaultName = 'CyberArk.Test'

    Mock Get-PASAccount -MockWith {
        return [PSCustomObject]@{
            name     = 'localAdmin01'
            userName = 'localAdmin01'
            Id       = '1'
        }
    } -ModuleName $ExtensionModule.Name
}

AfterAll {
    Remove-Module $ExtensionModule -Force
}
Describe 'Remove-Secret' {
    Context 'when connection type is REST' {
        BeforeAll {
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters @{ConnectionType = 'REST' }
        }

        It 'throws and does not remove when only substring matches are found' {
            Mock Get-PASAccount -MockWith {
                @(
                    [PSCustomObject]@{ name = 'localAdmin01'; userName = 'localAdmin01'; Id = '1' },
                    [PSCustomObject]@{ name = 'localAdmin02'; userName = 'localAdmin02'; Id = '2' }
                )
            } -ModuleName $ExtensionModule.Name
            Mock Remove-PASAccount -MockWith {} -ModuleName $ExtensionModule.Name

            { Remove-Secret -Name 'admin' -VaultName $VaultName } | Should -Throw
            Should -Invoke -CommandName Remove-PASAccount -ModuleName $ExtensionModule.Name -Times 0 -Exactly
        }

        It 'throws and does not remove when no accounts are found' {
            Mock Get-PASAccount -MockWith { $null } -ModuleName $ExtensionModule.Name
            Mock Remove-PASAccount -MockWith {} -ModuleName $ExtensionModule.Name

            { Remove-Secret -Name 'localAdmin01' -VaultName $VaultName } | Should -Throw
            Should -Invoke -CommandName Remove-PASAccount -ModuleName $ExtensionModule.Name -Times 0 -Exactly
        }

        It 'throws and does not remove when more than one exact match is found' {
            Mock Get-PASAccount -MockWith {
                @(
                    [PSCustomObject]@{ name = 'localAdmin01'; userName = 'a'; Id = '1' },
                    [PSCustomObject]@{ name = 'localAdmin01'; userName = 'b'; Id = '2' }
                )
            } -ModuleName $ExtensionModule.Name
            Mock Remove-PASAccount -MockWith {} -ModuleName $ExtensionModule.Name

            { Remove-Secret -Name 'localAdmin01' -VaultName $VaultName } | Should -Throw
            Should -Invoke -CommandName Remove-PASAccount -ModuleName $ExtensionModule.Name -Times 0 -Exactly
        }

        It 'removes only the exactly matching account, ignoring case' {
            Mock Get-PASAccount -MockWith {
                @(
                    [PSCustomObject]@{ name = 'localAdmin01'; userName = 'localAdmin01'; Id = '1' },
                    [PSCustomObject]@{ name = 'localAdmin01-old'; userName = 'localAdmin01'; Id = '2' }
                )
            } -ModuleName $ExtensionModule.Name
            Mock Remove-PASAccount -MockWith {} -ModuleName $ExtensionModule.Name

            Remove-Secret -Name 'LOCALADMIN01' -VaultName $VaultName
            Should -Invoke -CommandName Remove-PASAccount -ModuleName $ExtensionModule.Name -Times 1 -Exactly -ParameterFilter { $id -eq '1' }
        }

        AfterAll {
            Unregister-SecretVault -Name $VaultName
        }
    }

    Context 'when connection type is Credential Provider' {
        It 'throws an error' {
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters @{ConnectionType = 'CredentialProvider' }
            { Remove-Secret -Name 'admin' -VaultName $VaultName } | Should -Throw 'Remove-Secret is not supported for Credential Provider'
            Unregister-SecretVault -Name $VaultName
        }
    }

    Context 'when connection type is Central Credential Provider' {
        It 'throws an error' {
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters @{ConnectionType = 'CentralCredentialProvider' }
            { Remove-Secret -Name 'admin' -VaultName $VaultName } | Should -Throw 'Remove-Secret is not supported for Central Credential Provider'
            Unregister-SecretVault -Name $VaultName
        }
    }
}
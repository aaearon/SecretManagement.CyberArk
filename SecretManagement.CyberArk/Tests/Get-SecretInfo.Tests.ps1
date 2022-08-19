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

            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters @{ConnectionType = 'REST' }
        }

        It 'returns information on a secret' {
            $SecretInfo = Get-SecretInfo -Filter 'localAdmin01' -VaultName $VaultName
            $SecretInfo | Should -Not -BeNullOrEmpty
            $SecretInfo | Should -BeOfType [Microsoft.PowerShell.SecretManagement.SecretInformation]
            $SecretInfo.Name | Should -Be 'localAdmin01'
            $SecretInfo.Metadata.userName | Should -Be 'localAdmin01'
            $SecretInfo.Metadata.Id | Should -Be '1'
            $SecretInfo.Metadata.safeName | Should -Be 'LocalAdministrators'
        }

        AfterAll {
            Unregister-SecretVault -Name $VaultName
        }
    }
    Context 'when connection type is Central Credential Provder' {
        BeforeAll {
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters @{ConnectionType = 'CentralCredentialProvider'; AppID = 'banana'; URL = 'https://banana.com' }
        }

        It 'invokes Get-CCPCredential' {
            Mock Get-CCPCredential -MockWith {} -ModuleName $ExtensionModule.Name
            Get-SecretInfo -Filter 'admin' -VaultName $VaultName
            Should -Invoke -CommandName Get-CCPCredential -ModuleName $ExtensionModule.Name
        }

        AfterAll {
            Unregister-SecretVault -Name $VaultName
        }
    }

    Context 'when connection type is Credential Provder' {
        BeforeAll {
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters @{ConnectionType = 'CredentialProvider'; AppID = 'banana' }
        }

        It 'invokes Get-AIMCredential' {
            Mock Get-AIMCredential -MockWith {} -ModuleName $ExtensionModule.Name
            Get-SecretInfo -Filter 'admin' -VaultName $VaultName
            Should -Invoke -CommandName Get-AIMCredential -ModuleName $ExtensionModule.Name
        }

        AfterAll {
            Unregister-SecretVault -Name $VaultName
        }
    }
}
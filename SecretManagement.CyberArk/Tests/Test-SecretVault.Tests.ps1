BeforeAll {
    Get-Module 'SecretManagement.CyberArk' | Remove-Module -Force
    Get-Module 'Microsoft.Powershell.SecretManagement' | Remove-Module -Force

    Import-Module Microsoft.PowerShell.SecretManagement
    $ExtensionModule = Import-Module "$PSScriptRoot/../SecretManagement.CyberArk.Extension/*.psd1" -Force -PassThru
    $VaultName = 'CyberArk.Test'
}

AfterAll {
    Remove-Module $ExtensionModule -Force
}
Describe 'Test-SecretVault' {
    Context 'when connection type is REST' {
        BeforeAll {
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters @{ConnectionType = 'REST' }
        }

        It 'returns true when a PASSession exists' {
            Mock Get-PASSession -MockWith { [PSCustomObject]@{} } -ModuleName $ExtensionModule.Name
            Test-SecretVault -VaultName $VaultName | Should -BeTrue
        }

        It 'throws when there is no PASSession' {
            Mock Get-PASSession -MockWith { throw 'no session' } -ModuleName $ExtensionModule.Name
            { Test-SecretVault -VaultName $VaultName } | Should -Throw '*Failed to get PASSession*'
        }

        AfterAll {
            Unregister-SecretVault -Name $VaultName
        }
    }

    Context 'when connection type is Credential Provider' {
        It 'returns true when AppID is set and Get-AIMCredential is available' {
            Mock Get-Command -MockWith { [PSCustomObject]@{ Name = 'Get-AIMCredential' } } -ModuleName $ExtensionModule.Name
            Mock Test-PASSession -MockWith {} -ModuleName $ExtensionModule.Name
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters @{ConnectionType = 'CredentialProvider'; AppID = 'App' }
            Test-SecretVault -VaultName $VaultName | Should -BeTrue
            Should -Invoke -CommandName Test-PASSession -ModuleName $ExtensionModule.Name -Times 0 -Exactly
            Unregister-SecretVault -Name $VaultName
        }

        It 'returns false when AppID is missing' {
            Mock Get-Command -MockWith { [PSCustomObject]@{ Name = 'Get-AIMCredential' } } -ModuleName $ExtensionModule.Name
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters @{ConnectionType = 'CredentialProvider' }
            Test-SecretVault -VaultName $VaultName -ErrorAction SilentlyContinue | Should -BeFalse
            Unregister-SecretVault -Name $VaultName
        }

        It 'returns false when Get-AIMCredential is unavailable' {
            Mock Get-Command -MockWith { $null } -ModuleName $ExtensionModule.Name
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters @{ConnectionType = 'CredentialProvider'; AppID = 'App' }
            Test-SecretVault -VaultName $VaultName -ErrorAction SilentlyContinue | Should -BeFalse
            Unregister-SecretVault -Name $VaultName
        }
    }

    Context 'when connection type is Central Credential Provider' {
        It 'returns true when AppID and URL are set and Get-CCPCredential is available' {
            Mock Get-Command -MockWith { [PSCustomObject]@{ Name = 'Get-CCPCredential' } } -ModuleName $ExtensionModule.Name
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters @{ConnectionType = 'CentralCredentialProvider'; AppID = 'App'; URL = 'https://ccp' }
            Test-SecretVault -VaultName $VaultName | Should -BeTrue
            Unregister-SecretVault -Name $VaultName
        }

        It 'returns false when URL is missing' {
            Mock Get-Command -MockWith { [PSCustomObject]@{ Name = 'Get-CCPCredential' } } -ModuleName $ExtensionModule.Name
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters @{ConnectionType = 'CentralCredentialProvider'; AppID = 'App' }
            Test-SecretVault -VaultName $VaultName -ErrorAction SilentlyContinue | Should -BeFalse
            Unregister-SecretVault -Name $VaultName
        }

        It 'returns false when Get-CCPCredential is unavailable' {
            Mock Get-Command -MockWith { $null } -ModuleName $ExtensionModule.Name
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters @{ConnectionType = 'CentralCredentialProvider'; AppID = 'App'; URL = 'https://ccp' }
            Test-SecretVault -VaultName $VaultName -ErrorAction SilentlyContinue | Should -BeFalse
            Unregister-SecretVault -Name $VaultName
        }
    }

    Context 'when connection type is unknown' {
        It 'returns false' {
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters @{ConnectionType = 'Bogus' }
            Test-SecretVault -VaultName $VaultName -ErrorAction SilentlyContinue | Should -BeFalse
            Unregister-SecretVault -Name $VaultName
        }
    }
}

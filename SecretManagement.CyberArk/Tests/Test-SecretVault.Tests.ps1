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
            $VaultParams = @{ConnectionType = 'REST' }
        }

        It 'returns true when a PASSession exists' {
            Mock Get-PASSession -MockWith { [PSCustomObject]@{ BaseURI = 'https://pvwa' } } -ModuleName $ExtensionModule.Name
            Test-SecretVault -VaultName $VaultName -AdditionalParameters $VaultParams | Should -BeTrue
        }

        It 'returns false with an error when Get-PASSession returns an empty session object' {
            Mock Get-PASSession -MockWith { [PSCustomObject]@{ BaseURI = $null } } -ModuleName $ExtensionModule.Name
            Test-SecretVault -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction SilentlyContinue -ErrorVariable Err | Should -BeFalse
            "$Err" | Should -BeLike '*Failed to get PASSession*'
        }

        It 'returns false with an error when there is no PASSession' {
            Mock Get-PASSession -MockWith { throw 'no session' } -ModuleName $ExtensionModule.Name
            Test-SecretVault -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction SilentlyContinue -ErrorVariable Err | Should -BeFalse
            "$Err" | Should -BeLike '*Failed to get PASSession*'
        }

    }

    Context 'when connection type is Credential Provider' {
        It 'returns true when AppID is set and Get-AIMCredential is available' {
            Mock Get-Command -MockWith { [PSCustomObject]@{ Name = 'Get-AIMCredential' } } -ModuleName $ExtensionModule.Name
            Mock Test-PASSession -MockWith {} -ModuleName $ExtensionModule.Name
            $VaultParams = @{ConnectionType = 'CredentialProvider'; AppID = 'App' }
            Test-SecretVault -VaultName $VaultName -AdditionalParameters $VaultParams | Should -BeTrue
            Should -Invoke -CommandName Test-PASSession -ModuleName $ExtensionModule.Name -Times 0 -Exactly
        }

        It 'returns false when AppID is missing' {
            Mock Get-Command -MockWith { [PSCustomObject]@{ Name = 'Get-AIMCredential' } } -ModuleName $ExtensionModule.Name
            $VaultParams = @{ConnectionType = 'CredentialProvider' }
            Test-SecretVault -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction SilentlyContinue -ErrorVariable Err | Should -BeFalse
            "$Err" | Should -BeLike '*AppID*'
        }

        It 'returns false when Get-AIMCredential is unavailable' {
            Mock Get-Command -MockWith { $null } -ModuleName $ExtensionModule.Name
            $VaultParams = @{ConnectionType = 'CredentialProvider'; AppID = 'App' }
            Test-SecretVault -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction SilentlyContinue -ErrorVariable Err | Should -BeFalse
            "$Err" | Should -BeLike '*Get-AIMCredential*'
        }
    }

    Context 'when connection type is Central Credential Provider' {
        It 'returns true when AppID and URL are set and Get-CCPCredential is available' {
            Mock Get-Command -MockWith { [PSCustomObject]@{ Name = 'Get-CCPCredential' } } -ModuleName $ExtensionModule.Name
            $VaultParams = @{ConnectionType = 'CentralCredentialProvider'; AppID = 'App'; URL = 'https://ccp' }
            Test-SecretVault -VaultName $VaultName -AdditionalParameters $VaultParams | Should -BeTrue
        }

        It 'returns false when URL is missing' {
            Mock Get-Command -MockWith { [PSCustomObject]@{ Name = 'Get-CCPCredential' } } -ModuleName $ExtensionModule.Name
            $VaultParams = @{ConnectionType = 'CentralCredentialProvider'; AppID = 'App' }
            Test-SecretVault -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction SilentlyContinue -ErrorVariable Err | Should -BeFalse
            "$Err" | Should -BeLike '*URL*'
        }

        It 'returns false when Get-CCPCredential is unavailable' {
            Mock Get-Command -MockWith { $null } -ModuleName $ExtensionModule.Name
            $VaultParams = @{ConnectionType = 'CentralCredentialProvider'; AppID = 'App'; URL = 'https://ccp' }
            Test-SecretVault -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction SilentlyContinue -ErrorVariable Err | Should -BeFalse
            "$Err" | Should -BeLike '*Get-CCPCredential*'
        }
    }

    Context 'when connection type is unknown' {
        It 'returns false' {
            $VaultParams = @{ConnectionType = 'Bogus' }
            Test-SecretVault -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction SilentlyContinue | Should -BeFalse
        }
    }
}

BeforeAll {
    Get-Module 'SecretManagement.CyberArk' | Remove-Module -Force
    Get-Module 'Microsoft.Powershell.SecretManagement' | Remove-Module -Force

    Import-Module Microsoft.PowerShell.SecretManagement
    $ExtensionModule = Import-Module "$PSScriptRoot/../SecretManagement.CyberArk.Extension/*.psd1" -Force -PassThru
    $VaultName = 'CyberArk.Test'
}

AfterAll {
    Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Unregister-SecretVault
    Remove-Module $ExtensionModule -Force
}
Describe 'Test-SecretVault' {
    Context 'when connection type is REST' {
        BeforeAll {
            Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Unregister-SecretVault
            $VaultParams = @{ConnectionType = 'REST' }
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters $VaultParams
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

        AfterAll {
            Unregister-SecretVault -Name $VaultName
        }
    }

    Context 'when connection type is Credential Provider' {
        It 'returns true when AppID is set and Get-AIMCredential is available' {
            Mock Get-Command -MockWith { [PSCustomObject]@{ Name = 'Get-AIMCredential' } } -ModuleName $ExtensionModule.Name
            Mock Test-PASSession -MockWith {} -ModuleName $ExtensionModule.Name
            Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Unregister-SecretVault
            $VaultParams = @{ConnectionType = 'CredentialProvider'; AppID = 'App' }
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters $VaultParams
            Test-SecretVault -VaultName $VaultName -AdditionalParameters $VaultParams | Should -BeTrue
            Should -Invoke -CommandName Test-PASSession -ModuleName $ExtensionModule.Name -Times 0 -Exactly
            Unregister-SecretVault -Name $VaultName
        }

        It 'returns false when AppID is missing' {
            Mock Get-Command -MockWith { [PSCustomObject]@{ Name = 'Get-AIMCredential' } } -ModuleName $ExtensionModule.Name
            Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Unregister-SecretVault
            $VaultParams = @{ConnectionType = 'CredentialProvider' }
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters $VaultParams
            Test-SecretVault -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction SilentlyContinue -ErrorVariable Err | Should -BeFalse
            "$Err" | Should -BeLike '*AppID*'
            Unregister-SecretVault -Name $VaultName
        }

        It 'returns false when Get-AIMCredential is unavailable' {
            Mock Get-Command -MockWith { $null } -ModuleName $ExtensionModule.Name
            Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Unregister-SecretVault
            $VaultParams = @{ConnectionType = 'CredentialProvider'; AppID = 'App' }
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters $VaultParams
            Test-SecretVault -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction SilentlyContinue -ErrorVariable Err | Should -BeFalse
            "$Err" | Should -BeLike '*Get-AIMCredential*'
            Unregister-SecretVault -Name $VaultName
        }
    }

    Context 'when connection type is Central Credential Provider' {
        It 'returns true when AppID and URL are set and Get-CCPCredential is available' {
            Mock Get-Command -MockWith { [PSCustomObject]@{ Name = 'Get-CCPCredential' } } -ModuleName $ExtensionModule.Name
            Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Unregister-SecretVault
            $VaultParams = @{ConnectionType = 'CentralCredentialProvider'; AppID = 'App'; URL = 'https://ccp' }
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters $VaultParams
            Test-SecretVault -VaultName $VaultName -AdditionalParameters $VaultParams | Should -BeTrue
            Unregister-SecretVault -Name $VaultName
        }

        It 'returns false when URL is missing' {
            Mock Get-Command -MockWith { [PSCustomObject]@{ Name = 'Get-CCPCredential' } } -ModuleName $ExtensionModule.Name
            Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Unregister-SecretVault
            $VaultParams = @{ConnectionType = 'CentralCredentialProvider'; AppID = 'App' }
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters $VaultParams
            Test-SecretVault -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction SilentlyContinue -ErrorVariable Err | Should -BeFalse
            "$Err" | Should -BeLike '*URL*'
            Unregister-SecretVault -Name $VaultName
        }

        It 'returns false when Get-CCPCredential is unavailable' {
            Mock Get-Command -MockWith { $null } -ModuleName $ExtensionModule.Name
            Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Unregister-SecretVault
            $VaultParams = @{ConnectionType = 'CentralCredentialProvider'; AppID = 'App'; URL = 'https://ccp' }
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters $VaultParams
            Test-SecretVault -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction SilentlyContinue -ErrorVariable Err | Should -BeFalse
            "$Err" | Should -BeLike '*Get-CCPCredential*'
            Unregister-SecretVault -Name $VaultName
        }
    }

    Context 'when connection type is unknown' {
        It 'returns false' {
            Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Unregister-SecretVault
            $VaultParams = @{ConnectionType = 'Bogus' }
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters $VaultParams
            Test-SecretVault -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction SilentlyContinue | Should -BeFalse
            Unregister-SecretVault -Name $VaultName
        }
    }
}

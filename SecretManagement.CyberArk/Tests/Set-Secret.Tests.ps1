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

Describe 'Set-Secret' {
    Context 'when connection method is REST' {
        BeforeAll {
            Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Unregister-SecretVault
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters @{ConnectionType = 'REST' }
            Mock Get-PASSession -MockWith { [PSCustomObject]@{ BaseURI = 'https://pvwa' } } -ModuleName $ExtensionModule.Name
        }

        It 'calls Add-PASAccount' {
            Mock Add-PASAccount -MockWith {} -ModuleName $ExtensionModule.Name

            Set-Secret -VaultName $VaultName -Name 'test' -AdditionalParameters @{PlatformId = 'Test'; SafeName = 'TestSafe' } -Secret ('test' | ConvertTo-SecureString -AsPlainText -Force)
            Should -Invoke -CommandName Add-PASAccount -ModuleName $ExtensionModule.Name
        }

        It 'writes an error when SafeName and PlatformId are missing' {
            Mock Add-PASAccount -MockWith {} -ModuleName $ExtensionModule.Name

            Set-Secret -VaultName $VaultName -Name 'test' -Secret ('test' | ConvertTo-SecureString -AsPlainText -Force) -ErrorAction SilentlyContinue -ErrorVariable Err
            "$Err" | Should -BeLike '*SafeName and PlatformId are required*'
            Should -Invoke -CommandName Add-PASAccount -ModuleName $ExtensionModule.Name -Times 0 -Exactly
        }

        AfterAll {
            Unregister-SecretVault -Name $VaultName
        }
    }

    Context 'when connection type is Credential Provider' {
        It 'writes an error' {
            Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Unregister-SecretVault
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters @{ConnectionType = 'CredentialProvider' }
            Set-Secret -Name 'admin' -VaultName $VaultName -ErrorAction SilentlyContinue -ErrorVariable Err
            "$Err" | Should -BeLike '*Set-Secret is not supported for Credential Provider*'
            Unregister-SecretVault -Name $VaultName
        }
    }

    Context 'when connection type is Central Credential Provider' {
        It 'writes an error' {
            Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Unregister-SecretVault
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters @{ConnectionType = 'CentralCredentialProvider' }
            Set-Secret -Name 'admin' -VaultName $VaultName -ErrorAction SilentlyContinue -ErrorVariable Err
            "$Err" | Should -BeLike '*Set-Secret is not supported for Central Credential Provider*'
            Unregister-SecretVault -Name $VaultName
        }
    }
}

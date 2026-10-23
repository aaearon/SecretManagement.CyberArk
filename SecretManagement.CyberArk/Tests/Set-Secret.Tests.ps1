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
            $VaultParams = @{ConnectionType = 'REST' }
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters $VaultParams
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

        AfterAll {
            Unregister-SecretVault -Name $VaultName
        }
    }

    Context 'when connection type is Credential Provider' {
        It 'writes an error' {
            Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Unregister-SecretVault
            $VaultParams = @{ConnectionType = 'CredentialProvider' }
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters $VaultParams
            Set-Secret -Name 'admin' -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction SilentlyContinue -ErrorVariable Err
            "$Err" | Should -BeLike '*Set-Secret is not supported for Credential Provider*'
            Unregister-SecretVault -Name $VaultName
        }
    }

    Context 'when connection type is Central Credential Provider' {
        It 'writes an error' {
            Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Unregister-SecretVault
            $VaultParams = @{ConnectionType = 'CentralCredentialProvider' }
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters $VaultParams
            Set-Secret -Name 'admin' -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction SilentlyContinue -ErrorVariable Err
            "$Err" | Should -BeLike '*Set-Secret is not supported for Central Credential Provider*'
            Unregister-SecretVault -Name $VaultName
        }
    }
}

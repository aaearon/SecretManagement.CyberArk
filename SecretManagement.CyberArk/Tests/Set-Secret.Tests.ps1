BeforeAll {
    Get-Module 'SecretManagement.CyberArk' | Remove-Module -Force
    Get-Module 'Microsoft.Powershell.SecretManagement' | Remove-Module -Force

    $ExtensionModule = Import-Module "$PSScriptRoot/../SecretManagement.CyberArk.Extension/*.psd1" -Force -PassThru
}

AfterAll {
    Remove-Module $ExtensionModule -Force
}

Describe 'Set-Secret' {
    Context 'when connection method is psPAS' {
        BeforeAll {
            $VaultName = 'CyberArk.Test'
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters @{ConnectionType = 'REST' }
        }

        It 'calls Add-PASAccount' {
            Mock Add-PASAccount -MockWith {} -ModuleName $ExtensionModule.Name

            Set-Secret -VaultName $VaultName -Name 'test' -AdditionalParameters @{PlatformId = 'Test'; SafeName = 'TestSafe'} -Secret ('test' | ConvertTo-SecureString -AsPlainText -Force)
            Should -Invoke -CommandName Add-PASAccount -ModuleName $ExtensionModule.Name
        }

        AfterAll {
            Unregister-SecretVault -Name $VaultName
        }
    }
}

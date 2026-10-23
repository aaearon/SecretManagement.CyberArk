BeforeAll {
    Get-Module 'SecretManagement.CyberArk' | Remove-Module -Force
    Get-Module 'Microsoft.Powershell.SecretManagement' | Remove-Module -Force

    Import-Module Microsoft.PowerShell.SecretManagement
    $ExtensionModule = Import-Module "$PSScriptRoot/../SecretManagement.CyberArk.Extension/*.psd1" -Force -PassThru
    $VaultName = 'CyberArk.Test'
    $VaultParams = @{ConnectionType = 'REST' }
    Mock Get-PASSession -MockWith { [PSCustomObject]@{ BaseURI = 'https://pvwa' } } -ModuleName $ExtensionModule.Name
    Mock Get-PASAccount -MockWith { $null } -ModuleName $ExtensionModule.Name
    Mock Add-PASAccount -MockWith {} -ModuleName $ExtensionModule.Name
    Mock Get-SecretVault -MockWith { throw 'registry lookup should not be used' } -ModuleName $ExtensionModule.Name
}

AfterAll {
    Remove-Module $ExtensionModule -Force
}

Describe 'Vault parameters come from AdditionalParameters' {
    It 'Get-Secret does not re-read the vault registry' {
        Get-Secret -Name 'x' -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction SilentlyContinue
        Should -Invoke -CommandName Get-SecretVault -ModuleName $ExtensionModule.Name -Times 0 -Exactly
    }
    It 'Get-SecretInfo does not re-read the vault registry' {
        Get-SecretInfo -Filter 'x' -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction SilentlyContinue
        Should -Invoke -CommandName Get-SecretVault -ModuleName $ExtensionModule.Name -Times 0 -Exactly
    }
    It 'Remove-Secret does not re-read the vault registry' {
        Remove-Secret -Name 'x' -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction SilentlyContinue
        Should -Invoke -CommandName Get-SecretVault -ModuleName $ExtensionModule.Name -Times 0 -Exactly
    }
    It 'Set-Secret does not re-read the vault registry' {
        Set-Secret -Name 'x' -Secret 'y' -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction SilentlyContinue
        Should -Invoke -CommandName Get-SecretVault -ModuleName $ExtensionModule.Name -Times 0 -Exactly
    }
    It 'Test-SecretVault does not re-read the vault registry' {
        Test-SecretVault -VaultName $VaultName -AdditionalParameters $VaultParams | Should -BeTrue
        Should -Invoke -CommandName Get-SecretVault -ModuleName $ExtensionModule.Name -Times 0 -Exactly
    }
}

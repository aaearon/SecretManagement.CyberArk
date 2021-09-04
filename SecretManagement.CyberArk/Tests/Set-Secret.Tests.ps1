BeforeAll {
    Get-Module 'SecretManagement.CyberArk' | Remove-Module -Force
    Get-Module 'Microsoft.Powershell.SecretManagement' | Remove-Module -Force

    $ExtensionModule = Import-Module "$PSScriptRoot/../SecretManagement.CyberArk.Extension/*.psd1" -Force -PassThru
}

AfterAll {
    Remove-Module $ExtensionModule -Force
}
Describe "Set-Secret" {
    It "calls Add-PASAccount" {
        Mock Add-PASAccount -MockWith {} -ModuleName $ExtensionModule.Name

        Set-Secret -name 'test' -platformId 'Test' -safeName 'TestSafe' -secret ('test' | ConvertTo-SecureString -AsPlainText -Force)
        Should -Invoke -CommandName Add-PASAccount -ModuleName $ExtensionModule.Name
    }

    It "should have a <Name> parameter" {
        $AllParameters = (Get-Command -Module $ExtensionModule.Name -Name 'Set-Secret').Parameters.Keys
        $Name | Should -BeIn $AllParameters
    } -TestCases @(
        @{Name = 'platformId' }
        @{Name = 'safeName' }
    )
}

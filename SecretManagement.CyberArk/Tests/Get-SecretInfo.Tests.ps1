BeforeAll {
    Get-Module 'SecretManagement.CyberArk' | Remove-Module -Force
    Get-Module 'Microsoft.Powershell.SecretManagement' | Remove-Module -Force

    Import-Module Microsoft.PowerShell.SecretManagement
    $ExtensionModule = Import-Module "$PSScriptRoot/../SecretManagement.CyberArk.Extension/*.psd1" -Force -PassThru

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
    It 'returns information on a secret' {
        $SecretInfo = Get-SecretInfo -Filter 'localAdmin01'
        $SecretInfo | Should -Not -BeNullOrEmpty
        $SecretInfo | Should -BeOfType [Microsoft.PowerShell.SecretManagement.SecretInformation]
        $SecretInfo.Name | Should -Be 'localAdmin01'
        $SecretInfo.Metadata.userName | Should -Be 'localAdmin01'
        $SecretInfo.Metadata.Id | Should -Be '1'
        $SecretInfo.Metadata.safeName | Should -Be 'LocalAdministrators'
    }
}
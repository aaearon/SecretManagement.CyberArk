Describe "Remove-Secret" {
    BeforeAll {
        Get-Module 'SecretManagement.CyberArk' | Remove-Module -Force
        Get-Module 'Microsoft.Powershell.SecretManagement' | Remove-Module -Force

        $ExtensionModule = Import-Module "$PSScriptRoot/../SecretManagement.CyberArk.Extension/*.psd1" -Force -PassThru

        Mock Get-PASAccount -MockWith {
            return [PSCustomObject]@{
                name     = 'localAdmin01'
                userName = 'localAdmin01'
                Id       = '1'
            }
        }
    }

    AfterAll {
        Remove-Module $ExtensionModule -Force
    }

    It "writes an error when more than one account is found" {
        Mock Get-PASAccount -MockWith {
            $Results = @(
                [PSCustomObject]@{
                    name     = 'localAdmin01'
                    userName = 'localAdmin01'
                    Id       = '1'
                },
                [PSCustomObject]@{
                    name     = 'localAdmin02'
                    userName = 'localAdmin02'
                    Id       = '2'
                }
            )
            return $Results
        }
        Mock Write-Error -MockWith {}

        Remove-Secret -name 'admin'
        Should -Invoke -CommandName Write-Error
    }

    It "removes a secret from the vault" {
        Mock Remove-PASAccount -MockWith {}

        Remove-Secret -name 'localAdmin01'
        Should -Invoke -CommandName Remove-PASAccount
    }
}
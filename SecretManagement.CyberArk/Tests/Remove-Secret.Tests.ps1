﻿BeforeAll {
    Get-Module 'SecretManagement.CyberArk' | Remove-Module -Force
    Get-Module 'Microsoft.Powershell.SecretManagement' | Remove-Module -Force

    $ExtensionModule = Import-Module "$PSScriptRoot/../SecretManagement.CyberArk.Extension/*.psd1" -Force -PassThru

    Mock Get-PASAccount -MockWith {
        return [PSCustomObject]@{
            name     = 'localAdmin01'
            userName = 'localAdmin01'
            Id       = '1'
        }
    } -ModuleName $ExtensionModule.Name
}

AfterAll {
    Remove-Module $ExtensionModule -Force
}
Describe 'Remove-Secret' {
    Context 'when connection type is REST' {
        BeforeAll {
            $VaultName = 'CyberArk.Test'
            Register-SecretVault -Name $VaultName -ModuleName SecretManagement.CyberArk -VaultParameters @{ConnectionType = 'REST' }
        }

        It 'writes an error when more than one account is found' {
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
            } -ModuleName $ExtensionModule.Name
            Mock Write-Error -MockWith {} -ModuleName $ExtensionModule.Name

            Remove-Secret -Name 'admin' -VaultName $VaultName
            Should -Invoke -CommandName Write-Error -ModuleName $ExtensionModule.Name
        }

        It 'removes a secret from the vault' {
            Mock Remove-PASAccount -MockWith {} -ModuleName $ExtensionModule.Name

            Remove-Secret -Name 'localAdmin01' -VaultName $VaultName
            Should -Invoke -CommandName Remove-PASAccount -ModuleName $ExtensionModule.Name
        }


        AfterAll {
            Unregister-SecretVault -Name $VaultName
        }
    }
}
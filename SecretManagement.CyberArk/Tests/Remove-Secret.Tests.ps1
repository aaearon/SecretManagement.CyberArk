BeforeAll {
    Get-Module 'SecretManagement.CyberArk' | Remove-Module -Force
    Get-Module 'Microsoft.Powershell.SecretManagement' | Remove-Module -Force

    $ExtensionModule = Import-Module "$PSScriptRoot/../SecretManagement.CyberArk.Extension/*.psd1" -Force -PassThru
    $VaultName = 'CyberArk.Test'

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
            $VaultParams = @{ConnectionType = 'REST' }
            Mock Get-PASSession -MockWith { [PSCustomObject]@{ BaseURI = 'https://pvwa' } } -ModuleName $ExtensionModule.Name
        }

        It 'writes an error with the exception message when the lookup throws' {
            Mock Get-PASAccount -MockWith { throw 'lookup exploded' } -ModuleName $ExtensionModule.Name
            Mock Remove-PASAccount -MockWith {} -ModuleName $ExtensionModule.Name
            Remove-Secret -Name 'admin' -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction SilentlyContinue -ErrorVariable Err
            "$Err" | Should -BeLike '*lookup exploded*'
            Should -Invoke -CommandName Remove-PASAccount -ModuleName $ExtensionModule.Name -Times 0 -Exactly
        }

        It 'writes an error with the exception message when removal throws' {
            Mock Get-PASAccount -MockWith { [PSCustomObject]@{ name = 'admin'; Id = '1' } } -ModuleName $ExtensionModule.Name
            Mock Remove-PASAccount -MockWith { throw 'delete denied' } -ModuleName $ExtensionModule.Name
            Remove-Secret -Name 'admin' -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction SilentlyContinue -ErrorVariable Err
            "$Err" | Should -BeLike '*delete denied*'
        }

        It 'errors and does not remove when only substring matches are found' {
            Mock Get-PASAccount -MockWith {
                @(
                    [PSCustomObject]@{ name = 'localAdmin01'; userName = 'localAdmin01'; Id = '1' },
                    [PSCustomObject]@{ name = 'localAdmin02'; userName = 'localAdmin02'; Id = '2' }
                )
            } -ModuleName $ExtensionModule.Name
            Mock Remove-PASAccount -MockWith {} -ModuleName $ExtensionModule.Name

            Remove-Secret -Name 'admin' -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction SilentlyContinue -ErrorVariable Err
            "$Err" | Should -BeLike '*Not deleting anything*'
            Should -Invoke -CommandName Remove-PASAccount -ModuleName $ExtensionModule.Name -Times 0 -Exactly
        }

        It 'errors and does not remove when no accounts are found' {
            Mock Get-PASAccount -MockWith { $null } -ModuleName $ExtensionModule.Name
            Mock Remove-PASAccount -MockWith {} -ModuleName $ExtensionModule.Name

            Remove-Secret -Name 'localAdmin01' -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction SilentlyContinue -ErrorVariable Err
            "$Err" | Should -BeLike '*No account found*Not deleting anything*'
            Should -Invoke -CommandName Remove-PASAccount -ModuleName $ExtensionModule.Name -Times 0 -Exactly
        }

        It 'errors and does not remove when more than one exact match is found' {
            Mock Get-PASAccount -MockWith {
                @(
                    [PSCustomObject]@{ name = 'localAdmin01'; userName = 'a'; Id = '1' },
                    [PSCustomObject]@{ name = 'localAdmin01'; userName = 'b'; Id = '2' }
                )
            } -ModuleName $ExtensionModule.Name
            Mock Remove-PASAccount -MockWith {} -ModuleName $ExtensionModule.Name

            Remove-Secret -Name 'localAdmin01' -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction SilentlyContinue -ErrorVariable Err
            "$Err" | Should -BeLike '*Multiple accounts*Not deleting anything*'
            Should -Invoke -CommandName Remove-PASAccount -ModuleName $ExtensionModule.Name -Times 0 -Exactly
        }

        It 'does not remove an exact-name match that lives in a different safe than the vault safeName' {
            Mock Get-PASAccount -MockWith {
                [PSCustomObject]@{ name = 'localAdmin01'; userName = 'u'; Id = '9'; safeName = 'SafeB' }
            } -ModuleName $ExtensionModule.Name
            Mock Remove-PASAccount -MockWith {} -ModuleName $ExtensionModule.Name

            Remove-Secret -Name 'localAdmin01' -VaultName $VaultName -AdditionalParameters ($VaultParams + @{ SafeName = 'SafeA' }) -ErrorAction SilentlyContinue -ErrorVariable Err
            "$Err" | Should -BeLike '*No account found*Not deleting anything*'
            Should -Invoke -CommandName Remove-PASAccount -ModuleName $ExtensionModule.Name -Times 0 -Exactly
        }

        It 'passes the vault safeName to Get-PASAccount and removes the match in that safe, ignoring case' {
            Mock Get-PASAccount -MockWith {
                @(
                    [PSCustomObject]@{ name = 'localAdmin01'; userName = 'u'; Id = '9'; safeName = 'SafeB' },
                    [PSCustomObject]@{ name = 'localAdmin01'; userName = 'u'; Id = '8'; safeName = 'safea' }
                )
            } -ModuleName $ExtensionModule.Name
            Mock Remove-PASAccount -MockWith {} -ModuleName $ExtensionModule.Name

            Remove-Secret -Name 'localAdmin01' -VaultName $VaultName -AdditionalParameters ($VaultParams + @{ SafeName = 'SafeA' })
            Should -Invoke -CommandName Get-PASAccount -ModuleName $ExtensionModule.Name -Times 1 -Exactly -ParameterFilter { $safeName -eq 'SafeA' }
            Should -Invoke -CommandName Remove-PASAccount -ModuleName $ExtensionModule.Name -Times 1 -Exactly -ParameterFilter { $id -eq '8' }
        }

        It 'removes only the exactly matching account, ignoring case' {
            Mock Get-PASAccount -MockWith {
                @(
                    [PSCustomObject]@{ name = 'localAdmin01'; userName = 'localAdmin01'; Id = '1' },
                    [PSCustomObject]@{ name = 'localAdmin01-old'; userName = 'localAdmin01'; Id = '2' }
                )
            } -ModuleName $ExtensionModule.Name
            Mock Remove-PASAccount -MockWith {} -ModuleName $ExtensionModule.Name

            Remove-Secret -Name 'LOCALADMIN01' -VaultName $VaultName -AdditionalParameters $VaultParams
            Should -Invoke -CommandName Remove-PASAccount -ModuleName $ExtensionModule.Name -Times 1 -Exactly -ParameterFilter { $id -eq '1' }
        }

    }

    Context 'when connection type is Credential Provider' {
        It 'writes an error' {
            $VaultParams = @{ConnectionType = 'CredentialProvider' }
            Remove-Secret -Name 'admin' -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction SilentlyContinue -ErrorVariable Err
            "$Err" | Should -BeLike '*Remove-Secret is not supported for Credential Provider*'
        }
    }

    Context 'when connection type is Central Credential Provider' {
        It 'writes an error' {
            $VaultParams = @{ConnectionType = 'CentralCredentialProvider' }
            Remove-Secret -Name 'admin' -VaultName $VaultName -AdditionalParameters $VaultParams -ErrorAction SilentlyContinue -ErrorVariable Err
            "$Err" | Should -BeLike '*Remove-Secret is not supported for Central Credential Provider*'
        }
    }
}
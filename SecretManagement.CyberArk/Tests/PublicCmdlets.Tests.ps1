# Drives the real public SecretManagement cmdlets in a child pwsh whose HOME/XDG_* point at a temporary directory,
# so the user's own SecretManagement registry is never touched (a child process is needed because SecretManagement
# fixes its registry path when first loaded). SecretManagement loads extensions in its own runspace, so Pester Mock
# cannot reach psPAS calls inside it; the CyberArk extension is checked through its observable errors, and pipeline
# binding through a fixture vault that records what it receives.
BeforeAll {
    $TempHome = Join-Path ([IO.Path]::GetTempPath()) ('smca-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $TempHome | Out-Null
    $Info = [Diagnostics.ProcessStartInfo]::new((Get-Process -Id $PID).Path)
    foreach ($Arg in '-NoProfile', '-File', "$PSScriptRoot/Fixtures/Invoke-PublicCmdlets.ps1", '-TestsRoot', $PSScriptRoot) { $Info.ArgumentList.Add($Arg) }
    foreach ($Name in 'HOME', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA', 'XDG_DATA_HOME', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME') { $Info.Environment[$Name] = $TempHome }
    $Info.Environment['PUBLICTEST_HOME'] = $TempHome
    $Info.Environment['ECHOVAULT_LOG'] = Join-Path $TempHome 'echo.jsonl'
    $Info.RedirectStandardOutput = $true
    $Info.RedirectStandardError = $true
    $Process = [Diagnostics.Process]::Start($Info)
    $Stdout = $Process.StandardOutput.ReadToEnd()
    $Stderr = $Process.StandardError.ReadToEnd()
    $Process.WaitForExit()
    Remove-Item -LiteralPath $TempHome -Recurse -Force -ErrorAction SilentlyContinue
    $Result = $Stdout.Trim().Split("`n")[-1] | ConvertFrom-Json
}

Describe 'Public SecretManagement cmdlets' {
    It 'ran with its registry under the temporary home' {
        $Result.RegistryUnderTemp | Should -BeTrue -Because $Stderr
    }

    It 'passes -Metadata and vault parameters from public Set-Secret to the CyberArk extension' {
        # SafeName only in Metadata, PlatformId only in the vault parameters: both resolved, so it reaches the session check
        $Result.SetWithMetadata | Should -BeLike '*Failed to get PASSession*'
        $Result.SetWithMetadata | Should -Not -BeLike '*missing*'
    }

    It 'reports what is missing when Metadata lacks SafeName and the vault has no default' {
        $Result.SetWithoutSafe | Should -BeLike '*missing: SafeName*'
    }

    It 'binds a piped object to -Name only; the extension PASAccount parameter is not reachable through public Get-Secret' {
        $Result.PublicGetSecretHasPASAccount | Should -BeFalse
        $Record = $Result.Echo | Where-Object Function -eq 'Get-Secret' | Select-Object -Last 1
        $Record.Bound | Should -Contain 'Name'
        $Record.Bound | Should -Not -Contain 'PASAccount'
        $Record.Name | Should -BeLike '*acct*'
    }
}

# Measure which of an agent's documented paths actually exist on this machine, on Windows.
# Read only, and names only.
#
# The companion to measure_layout.sh, and it exists separately for the reason the two
# collectors do: a single file with no modules, so it runs on a stock Windows PowerShell
# 5.1 without anything being installed first.
#
# Why this exists. A hundred and twenty-six catalogue entries rest on somebody else's
# reading of a closed-source product rather than on a vendor page, and the Windows
# spellings are the weakest of those: several were derived from a macOS layout rather than
# observed. A path that was derived wrongly is the worst defect this catalogue can carry,
# because a collection searches it, finds nothing, and an analyst concludes the agent was
# never used.
#
# What it takes, and what it refuses to take. Directory names, file names, sizes and
# modification times. Never the content of a file. Paths are printed with the profile
# directory replaced by a placeholder so the user name does not travel, but some file and
# directory names carry project names: read the output before sending it and delete
# whatever should not be shared. A gap recorded as a gap is worth more than a guess.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\measure_layout.ps1 > layout.txt
#   powershell -ExecutionPolicy Bypass -File scripts\measure_layout.ps1 -Family cursor > layout.txt

[CmdletBinding()]
param(
    [string] $Family = 'all',
    [int] $Depth = 4
)

$ErrorActionPreference = 'Continue'

$profileRoot = $env:USERPROFILE

function Shorten($text) {
    if (-not $text) { return $text }
    # A literal replacement rather than a regular expression: a profile path contains
    # backslashes, which a pattern would read as escapes.
    return $text.Replace($profileRoot, '%USERPROFILE%')
}

function Write-Section($name) {
    Write-Output ''
    Write-Output ("===== " + $name)
}

# One tree, to a bounded depth, names and metadata only. An absent path is reported rather
# than skipped, because telling a wrong path apart from an uninstalled product is the whole
# purpose of this measurement.
function Write-Tree($path) {
    if (-not (Test-Path -LiteralPath $path)) {
        Write-Output ("ABSENT   " + (Shorten $path))
        return
    }
    Write-Output ("PRESENT  " + (Shorten $path))
    $root = (Get-Item -LiteralPath $path -Force).FullName
    $rootDepth = ($root.TrimEnd('\').Split('\')).Count
    Get-ChildItem -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { (($_.FullName.Split('\')).Count - $rootDepth) -le $Depth } |
        Sort-Object FullName |
        ForEach-Object {
            if ($_.PSIsContainer) { $kind = 'd'; $size = '-' }
            else { $kind = 'f'; $size = $_.Length }
            Write-Output ("  {0} {1,10}  {2}" -f $kind, $size, (Shorten $_.FullName))
        }
}

function Write-Version($path) {
    if (Test-Path -LiteralPath $path) {
        $item = Get-Item -LiteralPath $path -Force
        Write-Output ("VERSION  {0} = {1}" -f (Shorten $path), $item.VersionInfo.ProductVersion)
    }
}

Write-Output ("host: " + [System.Environment]::OSVersion.VersionString)
Write-Output ("powershell: " + $PSVersionTable.PSVersion.ToString())
Write-Output ("depth: " + $Depth)
Write-Output ("taken: " + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))

if ($Family -eq 'all' -or $Family -eq 'cursor') {
    Write-Section 'cursor'
    Write-Version (Join-Path $env:LOCALAPPDATA 'Programs\cursor\Cursor.exe')
    @(
        (Join-Path $env:APPDATA 'Cursor'),
        (Join-Path $env:LOCALAPPDATA 'Programs\cursor'),
        (Join-Path $env:LOCALAPPDATA 'cursor-updater'),
        (Join-Path $env:LOCALAPPDATA 'cursor-agent'),
        (Join-Path $env:LOCALAPPDATA 'cursor-compile-cache'),
        (Join-Path $profileRoot '.cursor'),
        (Join-Path $profileRoot '.cursor-server')
    ) | ForEach-Object { Write-Tree $_ }
}

if ($Family -eq 'all' -or $Family -eq 'chatgpt_desktop') {
    Write-Section 'chatgpt_desktop'
    # The catalogue has one Windows path for this family and it is a store this product
    # ships through the packaged-application mechanism, so the package directory is found
    # by name rather than assumed: the identifier is part of what this measurement is for.
    @(
        (Join-Path $env:LOCALAPPDATA 'Packages'),
        (Join-Path $env:APPDATA 'ChatGPT'),
        (Join-Path $env:LOCALAPPDATA 'ChatGPT'),
        (Join-Path $profileRoot '.codex')
    ) | ForEach-Object { Write-Tree $_ }
    Write-Section 'chatgpt_desktop: packages found by name'
    $packages = Join-Path $env:LOCALAPPDATA 'Packages'
    if (Test-Path -LiteralPath $packages) {
        Get-ChildItem -LiteralPath $packages -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match 'OpenAI|ChatGPT' } |
            ForEach-Object { Write-Output (Shorten $_.FullName) }
    }
}

if ($Family -eq 'all' -or $Family -eq 'windsurf') {
    Write-Section 'windsurf'
    @(
        (Join-Path $env:APPDATA 'Windsurf'),
        (Join-Path $env:APPDATA 'Devin'),
        (Join-Path $profileRoot '.codeium'),
        (Join-Path $profileRoot '.windsurf'),
        (Join-Path $profileRoot '.devin')
    ) | ForEach-Object { Write-Tree $_ }
}

Write-Section 'done'
Write-Output 'Read this file before sending it. Delete any line you would rather not share.'

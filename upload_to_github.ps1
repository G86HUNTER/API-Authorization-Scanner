<#
.SYNOPSIS
    Automated upload helper to push the API Authorization Scanner to GitHub.

.DESCRIPTION
    Configures remote origin and pushes the 'main' branch to your GitHub repository.

.EXAMPLE
    .\upload_to_github.ps1
#>

[CmdletBinding()]
param(
    [string]$RepoUrl = "https://github.com/G86HUNTER/API-Authorization-Scanner.git",
    [string]$Branch = "main"
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  API Authorization Security Testing Framework" -ForegroundColor White
Write-Host "  GitHub Upload Assistant" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Target Remote: $RepoUrl" -ForegroundColor Yellow
Write-Host "Target Branch: $Branch" -ForegroundColor Yellow
Write-Host ""

# Ensure we are in the script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

# Check git status
git status --short

Write-Host "`nEnsuring remote origin is configured..." -ForegroundColor Green
git remote remove origin 2>$null
git remote add origin $RepoUrl
git branch -M $Branch

Write-Host "`nAttempting to push to GitHub..." -ForegroundColor Cyan
Write-Host "(A browser or credential prompt may appear if you are not currently signed in)`n" -ForegroundColor Gray

git push -u origin $Branch

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n[SUCCESS] Project uploaded successfully to:" -ForegroundColor Green
    Write-Host "  https://github.com/G86HUNTER/API-Authorization-Scanner" -ForegroundColor White -BackgroundColor DarkGreen
} else {
    Write-Host "`n[NOTICE] Push did not complete automatically." -ForegroundColor Yellow
    Write-Host "If the repository does not yet exist on GitHub:" -ForegroundColor White
    Write-Host "  1. Visit: https://github.com/new" -ForegroundColor Cyan
    Write-Host "  2. Repository name: API-Authorization-Scanner" -ForegroundColor Cyan
    Write-Host "  3. Click 'Create repository' (leave README unchecked)" -ForegroundColor Cyan
    Write-Host "  4. Re-run this script: .\upload_to_github.ps1" -ForegroundColor Cyan
}

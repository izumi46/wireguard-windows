$filePath = ".\version\version.go"
$code = Get-Content -Path $filePath -Raw
$versionPattern = 'Number = "(\d+\.\d+\.\d+)"'
$regexMatches = [regex]::Matches($code, $versionPattern)

$version = $regexMatches[0].Groups[1].Value
Write-Output "::set-output name=version::$version"

# Downloads WinDivert beside lagrelay.exe. Run from an elevated PowerShell if
# lagrelay.exe lives in a protected folder. The release zip already includes it.
$ErrorActionPreference = 'Stop'
$ver = '2.2.2'
$sha = '63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15'
$dir = if ($args.Count -gt 0) { $args[0] } else { Split-Path (Get-Command lagrelay.exe).Source }
$zip = Join-Path $env:TEMP "WinDivert-$ver-A.zip"
Invoke-WebRequest "https://github.com/basil00/WinDivert/releases/download/v$ver/WinDivert-$ver-A.zip" -OutFile $zip
if ((Get-FileHash $zip -Algorithm SHA256).Hash.ToLower() -ne $sha) { throw 'WinDivert download failed its checksum' }
$tmp = Join-Path $env:TEMP "WinDivert-$ver"
Expand-Archive $zip -DestinationPath $tmp -Force
Copy-Item "$tmp\WinDivert-$ver-A\x64\WinDivert.dll", "$tmp\WinDivert-$ver-A\x64\WinDivert64.sys" $dir
Write-Host "WinDivert installed in $dir"

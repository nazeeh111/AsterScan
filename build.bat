@ECHO OFF
REM Build AsterScan from source

setlocal enabledelayedexpansion

SET PACKAGE=%CD%\asterscan-package
SET PYI=pyinstaller

IF EXIST "%PACKAGE%" (
    ECHO Package directory already exists: %PACKAGE%
    exit /b 1
)
ECHO Compiling AsterScan ...
%PYI% asterscan.spec
if !errorlevel! neq 0 GOTO ERROR
ECHO Compiling AsterScan updater ...
%PYI% asterscan-updater.spec
if !errorlevel! neq 0 GOTO ERROR
ECHO Compiling AsterScan Studio ...
%PYI% asterscan-studio.spec
if !errorlevel! neq 0 GOTO ERROR

:: Copy Executables and other files to the package folder
mkdir "%PACKAGE%"
if !errorlevel! neq 0 GOTO ERROR
copy /Y ".\dist\asterscan.exe" "%PACKAGE%\"
if !errorlevel! neq 0 GOTO ERROR
copy /Y ".\dist\asterscan-updater.exe" "%PACKAGE%\"
if !errorlevel! neq 0 GOTO ERROR
copy /Y ".\dist\asterscan-studio.exe" "%PACKAGE%\"
if !errorlevel! neq 0 GOTO ERROR
mkdir "%PACKAGE%\tools"
if !errorlevel! neq 0 GOTO ERROR
copy /Y ".\tools\pe-sieve32.exe" "%PACKAGE%\tools\"
if !errorlevel! neq 0 GOTO ERROR
copy /Y ".\tools\pe-sieve64.exe" "%PACKAGE%\tools\"
if !errorlevel! neq 0 GOTO ERROR
copy /Y ".\LICENSE" "%PACKAGE%\"
if !errorlevel! neq 0 GOTO ERROR
copy /Y ".\README.md" "%PACKAGE%\"
if !errorlevel! neq 0 GOTO ERROR
xcopy ".\config" "%PACKAGE%\config\" /E /I /Y >NUL
if !errorlevel! neq 0 GOTO ERROR
xcopy ".\docs" "%PACKAGE%\docs\" /E /I /Y >NUL
if !errorlevel! neq 0 GOTO ERROR
mkdir "%PACKAGE%\.github"
if !errorlevel! neq 0 GOTO ERROR
xcopy ".\.github\assets" "%PACKAGE%\.github\assets\" /E /I /Y >NUL
if !errorlevel! neq 0 GOTO ERROR

ECHO Build complete: %PACKAGE%
GOTO END

:ERROR
ECHO An error occurred. Build interrupted.
exit /b 1

:END


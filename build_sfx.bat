@ECHO OFF
REM Build an AsterScan ZIP package

setlocal enabledelayedexpansion

SET PACKAGE=%CD%\asterscan-package
SET DIST=%CD%\dist
SET ZIPPER="c:\Program Files\7-Zip\7z.exe"

:: Version
set /p VER="Enter Version: "

:: Build AsterScan
CALL build.bat
if !errorlevel! neq 0 GOTO ERROR

:: Pack
%ZIPPER% a -tzip -mm=Deflate -mmt=off -mx5 -mfb=32 -mpass=1 -sccUTF-8 "%DIST%\asterscan_%VER%.zip" "%PACKAGE%"
if !errorlevel! neq 0 GOTO ERROR
GOTO END

:ERROR
ECHO An error occurred. Build interrupted.
exit /b 1

:END




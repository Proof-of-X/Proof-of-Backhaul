@echo off
setlocal enabledelayedexpansion

set dir=%0\..\

cd %dir%\..\bin

for /f "usebackq delims=" %%i in (`bin\run-challenger.exe -v`) do (
    set VERSION=%%i
)

if %VERSION% == "INVALID" (
    echo "Please use the official builds"
    exit
)

for /f "tokens=*" %%i in ('curl https://raw.githubusercontent.com/Proof-of-X/Proof-of-Backhaul/main/release/latest/version.txt ^| findstr "pob_challenger_client"') do (
  set line=%%i
  set line=!line:*pob_challenger_client=!
  set LATEST_VERSION=!line:~2,-1!
)

if NOT "!LATEST_VERSION!" == "" if NOT "!VERSION!" == "!LATEST_VERSION!" (
    echo "Download the latest version? [y/n]"
    set /p response=

    if "!response!" == "y" set TRUE=1
    if "!response!" == "Y" set TRUE=1
    echo "!TRUE!"
    if defined TRUE (
        echo "inside loop"
        set ARCHITECTURE=x64
        set OS=Windows_NT
        echo "ARCH:"!ARCHITECTURE!
        echo "OS:"!OS!
        set URL="https://github.com/Proof-of-X/Proof-of-Backhaul/raw/main/release/latest/!ARCHITECTURE!/!OS!/run-challenger.exe"
        @REM update URL to the raw.githubusercontent.com format later
        echo "URL:"!URL!
        curl -o latest-run-challenger.exe !URL!

        for /f %%i in ("latest-run-challenger.exe") do set size=%%~zi
        echo "size: "!size!
        if !size! == 0 (
            echo "Updating..."
            move latest-run-challenger.exe run-challenger.exe
        ) else (
            echo "Already at latest version"
        )
    )
)

endlocal

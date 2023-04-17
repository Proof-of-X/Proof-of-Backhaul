@echo off

set dir=%0\..\

cd %dir%\..\bin

..\run\update-pob-challenger.cmd

:loop
	run-pob-challenger.exe %*
	echo "================> Restarting ===================="
	timeout /t 1 /nobreak > NUL
goto loop 

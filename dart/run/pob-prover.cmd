@echo off

set dir=%0\..\

cd %dir%\..\bin

..\run\update-pob-prover.cmd

:loop
	run-pob-prover.exe %*
	echo "================> Restarting ===================="
	timeout /t 1 /nobreak > NUL
goto loop 

@echo off

set dir=%0\..\

cd dir\..\bin

:loop
	run-challenger.exe %* 
	echo "================> Restarting ===================="
	timeout /t 1 /nobreak > NUL
goto loop 

@echo off

set dir=%~dp0
cd %dir%

CALL .\build-pob.cmd
cd %dir%
CALL .\build-pol.cmd
cd %dir%
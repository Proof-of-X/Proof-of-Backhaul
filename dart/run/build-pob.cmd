@echo off

set dir_pob=%0\..\
cd %dir_pob%\..\src

mkdir ..\bin > NUL
mkdir ..\bin\pob > NUL

cd pob

echo final version = ''' > release.dart
git log -1 --format=%ct origin/main >> release.dart
echo '''.trim(); >> release.dart

dart compile exe run-prover.dart	-o ../../bin/pob/run-pob-prover.exe
dart compile exe run-challenger.dart	-o ../../bin/pob/run-pob-challenger.exe


@echo off

set dir_pol=%0\..\
cd %dir_pol%\..\src

mkdir ..\bin > NUL
mkdir ..\bin\pol > NUL

cd pol

echo final version = ''' > release.dart
git log -1 --format=%ct origin/main >> release.dart
echo '''.trim(); >> release.dart

dart compile exe run-prover.dart	-o ../../bin/pol/run-pol-prover.exe
dart compile exe run-challenger.dart	-o ../../bin/pol/run-pol-challenger.exe

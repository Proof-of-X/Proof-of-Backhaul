@echo off

set dir=%0\..\

cd %dir%\..\src

mkdir ..\bin > NUL

cd pob

echo const version = ''' > release.dart 
git log -1 --format=%%cd origin/main >> release.dart
echo '''; >> release.dart

dart compile exe run-prover.dart	-o ../../bin/run-pob-prover.exe
dart compile exe run-challenger.dart	-o ../../bin/run-pob-challenger.exe

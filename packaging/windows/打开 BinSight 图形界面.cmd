@echo off
setlocal
pushd "%~dp0"

if not exist "bin\binsight.exe" (
  echo BinSight executable was not found: "%~dp0bin\binsight.exe"
  echo Please extract the full release zip before running this launcher.
  pause
  exit /b 1
)

"%~dp0bin\binsight.exe" gui
set "code=%ERRORLEVEL%"

if not "%code%"=="0" (
  echo.
  echo BinSight GUI exited with code %code%.
  echo You can also run: bin\binsight.exe scan path\to\sample.exe
  pause
)

popd
exit /b %code%

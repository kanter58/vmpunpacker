@echo off
setlocal
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo vswhere.exe not found
  exit /b 1
)
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
  set "VSINSTALL=%%i"
)
if not defined VSINSTALL (
  echo MSVC build tools not found
  exit /b 1
)
call "%VSINSTALL%\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (
  echo failed to initialise the MSVC environment
  exit /b 1
)
cd /d "%~dp0"
cmake -S . -B build -A x64
if errorlevel 1 exit /b 1
cmake --build build --config Release
exit /b %errorlevel%

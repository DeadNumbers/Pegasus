rem @echo off
cls
rem MAKE_INSTALLERS.BAT <Release|Debug>
rem rebuilds all project elements and prepares both x32 and x64 exes for usage

rem Check param passed
goto build_%1
:build_
echo ERR: no param passed, expected <Release|Debug>
exit 255

:build_Release
:build_Debug

rebuild_core %1
rebuild_modules %1

echo Installers buildlog, mode %1 > installers_build.log

devenv ..\Pegasus.sln /Rebuild "%1|x32" /project InstallerExe >> installers_build.log

rem Check build result
if %ERRORLEVEL% NEQ 0 (
	echo ERROR rebuilding InstallerExe in mode %1 x32
	pause
	exit 255
)

devenv ..\Pegasus.sln /Rebuild "%1|x64" /project InstallerExe >> installers_build.log

rem Check build result
if %ERRORLEVEL% NEQ 0 (
	echo ERROR rebuilding InstallerExe in mode %1 x64
	pause
	exit 255
)
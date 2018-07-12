@echo off
rem postbuild_installer.bat
rem Checks output exe, cleans some build timestamp fields, etc
rem FOR MAIN INSTALLER EXE

echo Calling script [%0] for target [%1] 

rem check if param passed
if not exist %1 (
	echo ERR: target file not found
	exit 255
)

echo Post-parsing target
pushd
cd /d %~dp0
php -n -f fake_timestamps.php %1
popd
if NOT ERRORLEVEL 0 (
	echo ERR: fake_timestamps.php parse failure
	exit 255
)

echo Signing binary
signtool.exe sign /f tric.pfx /p 123 %1
if NOT ERRORLEVEL 0 (
	echo ERR: Sign failed
	exit 255
)


rem got here if all was ok
echo ----------------------- Postbuils script finished OK --------------------------
echo .
exit 0

@echo off
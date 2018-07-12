@echo off
rem prebuild_installer.bat <main project filename and path> <DEBUG|RELEASE>
rem Recrypt strings, regenerates resources

echo Calling script [%0] with param [%1] in mode [%2]

rem check if param passed
if not exist %1 (
	echo ERR: main source file not found
	exit 255
)

echo Calling macro parser/string encryption
rem goto script dir so php won't claim No input file specified
pushd
cd /d %~dp0
php -n -f recrypt_strings.php %1
popd

echo Preparing binpack resources
pushd
cd /d %~dp0
php -n -f make_binpack.php %2
popd
if not exist ..\inc\binpack.h (
	echo ERR: binpack not generated
	exit 255
)

rem got here if all was ok
echo ----------------------- Prebuild script finished OK --------------------------
echo .
exit 0
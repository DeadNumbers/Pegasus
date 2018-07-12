@echo off
echo This tool executes recrypt_strings.php script
echo Expected params:
echo param1 - main source file (%1)

if not exist %1 (
	echo ERR: source not found
	exit 255
)

rem set

rem goto script dir so php won't claim No input file specified
cd /d %~dp0
php -n -f recrypt_strings.php %1

@echo off
rem rebuild_project.bat 1<Release|Debug> 2<project_name> 3<x32|x64> 4<logfile_name> 5<filename_to_check_without_ext>
rem rebuilds a single project when all vars are set


if exist "..\binres\*.pdb" (
	del "..\binres\*.pdb" > nul
)
if exist "..\binres\*.lib" (
	del "..\binres\*.lib" > nul
)
if exist "..\binres\*.exp" (
del "..\binres\*.exp" > nul
)
if exist "..\binres\*.bsc" (
del "..\binres\*.bsc" > nul
)


if exist "..\binres\%5.%3" (
	attrib -R "..\binres\%5.%3"
	del "..\binres\%5.%3" > nul
)

echo Rebuilding %1 %2 %3 
echo Rebuilding %1 %2 %3 >> %4
devenv ..\Pegasus.sln /Rebuild "%1|%3" /project %2 >> %4

rem Check build result
if %ERRORLEVEL% NEQ 0 (
	echo ERROR rebuilding %2 in mode %1 %3
	pause
	exit 255
)

rem Extra check for output file exists
if not exist "..\binres\%5.%3" (
	echo ERROR: output file %5.%3 not found
	pause
	exit 254
)

if exist "..\binres\*.pdb" (
	del "..\binres\*.pdb" > nul
)
if exist "..\binres\*.lib" (
	del "..\binres\*.lib" > nul
)
if exist "..\binres\*.exp" (
del "..\binres\*.exp" > nul
)
if exist "..\binres\*.bsc" (
del "..\binres\*.bsc" > nul
)

rem Resolving build issue when new target may remove previous binary file
attrib +R "..\binres\%5.%3"

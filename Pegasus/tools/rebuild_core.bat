@echo off
cls
rem rebuild_core.bat <Release|Debug>
rem Performs rebuild of all core projects - shellcode, rse, idd, wdd, possibly some others later
rem essential for building binpack and resulting installer exe
rem NOTE: second essential part before preparing binpack is building all the modules needed into ./binres/ dir


echo Setuping VS2012 vars
call "%VS120COMNTOOLS%\vsvars32.bat"


goto build_%1
:build_
echo ERR: no param passed, expected <Release|Debug>
exit 255


:build_Release
:build_Debug

rem Wipe some temp files
rem del ..\binres\*.pdb

echo Core buildlog, mode %1 > core_build.log

echo Building CORE in %1 mode

call rebuild_project.bat %1 shellcode x32 core_build.log shellcode
call rebuild_project.bat %1 shellcode x64 core_build.log shellcode

call rebuild_project.bat %1 RemoteServiceExe x32 core_build.log rse
call rebuild_project.bat %1 RemoteServiceExe x64 core_build.log rse

call rebuild_project.bat %1 InstallDispatcherDll x32 core_build.log idd
call rebuild_project.bat %1 InstallDispatcherDll x64 core_build.log idd

call rebuild_project.bat %1 WorkDispatcherDll x32 core_build.log wdd
call rebuild_project.bat %1 WorkDispatcherDll x64 core_build.log wdd

rem Revore read only from all files 
attrib -R "..\binres\*.x32"
attrib -R "..\binres\*.x64"
@echo off
cls
rem rebuild_modules.bat <Release|Debug>
rem Performs rebuild of actual modules


echo Setuping VS2012 vars
call "%VS120COMNTOOLS%\vsvars32.bat"


goto build_%1
:build_
echo ERR: no param passed, expected <Release|Debug>
exit 255


:build_Release
:build_Debug

echo Modules buildlog, mode %1 > mods_build.log

echo Building MODULES in %1 mode



call rebuild_project.bat %1 mod_CmdExec x32 mods_build.log mod_CmdExec
call rebuild_project.bat %1 mod_CmdExec x64 mods_build.log mod_CmdExec

call rebuild_project.bat %1 mod_DomainReplication x32 mods_build.log mod_DomainReplication
call rebuild_project.bat %1 mod_DomainReplication x64 mods_build.log mod_DomainReplication

call rebuild_project.bat %1 mod_LogonPasswords x32 mods_build.log mod_LogonPasswords
call rebuild_project.bat %1 mod_LogonPasswords x64 mods_build.log mod_LogonPasswords

call rebuild_project.bat %1 mod_NetworkConnectivity x32 mods_build.log mod_NetworkConnectivity
call rebuild_project.bat %1 mod_NetworkConnectivity x64 mods_build.log mod_NetworkConnectivity

rem Revore read only from all files 
attrib -R "..\binres\*.x32"
attrib -R "..\binres\*.x64"

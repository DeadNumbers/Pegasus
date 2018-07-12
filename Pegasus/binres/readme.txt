This directory contains files to be incorporated into resulting binres pack.
Post-build script for installer routine searches for *.x32/*.x64 pairs here
For every found file, it searches for a corresponding .info.json file with params about a specified module
to be put into resulting structure.
Output is put into binpack.bin here and translated into ..\inc\binpack.h 
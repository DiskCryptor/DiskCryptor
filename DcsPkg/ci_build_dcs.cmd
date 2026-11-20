cd %~dp0..\..\edk2

mklink /J DcsPkg %~dp0
cd DcsPkg

call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat"

set NASM_PREFIX=%~dp0..\DCrypt\tools\nasm\
dir %NASM_PREFIX%

call setenv.bat

echo patching edk2
robocopy %~dp0..\DCrypt\tools\edk2 %~dp0..\..\edk2 /E /COPY:DAT /DCOPY:DAT /IS /IT /R:0 /W:0

call dcs_bld.bat %1

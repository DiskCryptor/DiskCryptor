cd %~dp0..\..\edk2

mklink /J DcsPkg %~dp0
cd DcsPkg

call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat"

set NASM_PREFIX=%~dp0..\DCrypt\tools\nasm\
dir %NASM_PREFIX%

REM an edk2 tree (cache) without the BaseTools C tools: build them first
if not exist "%~dp0..\..\edk2\BaseTools\Bin\Win32\GenFw.exe" (
  setlocal
  pushd "%~dp0..\..\edk2"
  call edksetup.bat Rebuild
  popd
  endlocal
)

call setenv.bat

echo patching edk2
robocopy %~dp0..\DCrypt\tools\edk2 %~dp0..\..\edk2 /E /COPY:DAT /DCOPY:DAT /IS /IT /R:0 /W:0

call dcs_bld.bat %1

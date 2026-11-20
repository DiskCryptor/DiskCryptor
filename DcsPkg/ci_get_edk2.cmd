cd %~dp0..\..

REM git clone --branch edk2-stable202511 --recurse-submodules https://github.com/tianocore/edk2.git
git clone --branch edk2-stable202511 --depth 1 --recurse-submodules --shallow-submodules https://github.com/tianocore/edk2.git
cd edk2

call edksetup.bat Rebuild
if not exist BaseTools\Bin\Win32\GenFw.exe (echo BaseTools build failed & exit /b 1)

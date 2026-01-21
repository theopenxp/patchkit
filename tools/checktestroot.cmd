@setlocal
@if "%_echo%"=="" echo off

echo Verifying that the Testroot Certificate is installed...
set __certinstalled=
for /f %%i in ('tfindcer -a"Microsoft Test Root Authority" -s root -S ^| findstr /c:"8D19CCCE DDAF2F4C BE90C892 7C08A1F8 4AE41BC5"') do (
    set __certinstalled=1
)

if defined __certinstalled goto :eof
echo TestRoot does NOT appear to be installed yet.  Installing now...

@rem Install testroot certificate.
certmgr -add %RazzleToolPath%\testroot.cer -r localMachine -s root

echo Check again to see if Testroot is installed...
set __certinstalled=
for /f %%i in ('tfindcer -a"Microsoft Test Root Authority" -s root -S ^| findstr /c:"8D19CCCE DDAF2F4C BE90C892 7C08A1F8 4AE41BC5"') do (
    set __certinstalled=1
)

if defined __certinstalled echo TestRoot installed successfully&&goto :eof
echo TestRoot still not installed.  You may have to do this manually.  Simply
echo log on as a local administrator and issue the following command:
echo
echo certmgr -r localMachine -add %RazzleToolPath%\testroot.cer -s root

endlocal

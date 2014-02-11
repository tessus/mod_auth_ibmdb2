@echo off

rem SCRIPT: makemod.bat
rem Builds the mod_auth_ibmdb2 module with Visual Studio C/C++ Compiler
rem Usage: makemod.bat

rem Set DB2PATH to where DB2 will be accessed.
rem Set APACHEPATH to where Apache2 is installed

rem Path settings

set DB2PATH=c:\sqllib
set APACHEPATH=C:\Apache

rem Compiler and Linker Settings

set CC=cl
set DEFS= /nologo /MT /W3 /EHsc
set OUT=mod_auth_ibmdb2.so
set LINKER=link -nologo

set APACHEINC=-I"%APACHEPATH%\include"
set DB2INC=-I"%DB2PATH%\include"

set INCLUDES=%APACHEINC% %DB2INC%

set MDEFS=-D_CONSOLE -D_MBCS -DWIN32 -DWINNT -Di386 

set DEFINES= %INCLUDES% %DEFS% %MDEFS%
set CFLAGS= %DEFINES%

set APACHE_LIB="%APACHEPATH%\lib"

set LIB=%APACHE_LIB%;%LIB%
set LIBS=kernel32.lib libhttpd.lib libapr.lib libaprutil.lib "%DB2PATH%\lib\db2cli.lib"


%CC% %CFLAGS% -c mod_auth_ibmdb2.c

%CC% %CFLAGS% -LD %LIBS% mod_auth_ibmdb2.obj -Fe%OUT%

copy %OUT% "%APACHEPATH%\modules"
@echo on

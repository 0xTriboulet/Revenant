NAME	  = revnt

CCX86 	  = i686-w64-mingw32-gcc
CCX64 	  = x86_64-w64-mingw32-gcc

CFLAGS	  =  -O0 masm=intel
CFLAGS	  += -e WinMain

INCLUDE	  += -I Include
LINKING	  += -l netapi32 -l ws2_32 -l wsock32 -l wtsapi32 -l crypt32 -l shlwapi -l ntdll -l user32 -l gdi32 -l iphlpapi -l winhttp
SOURCE 	  =  $(wildcard Source/*)


all:
	printf "\033[0;36m[*]\033[0m Building Revenant agent...\n"

	# TODO: remove exe. lasting is going to be Dll and Reflective Dll
	$(CCX64) $(SOURCE) $(INCLUDE) $(CFLAGS) $(LINKING) -m64 -o Bin/Revenant.exe

	printf "\033[0;36m[*]\033[0m Finished building Revenant payload\n"
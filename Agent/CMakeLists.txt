cmake_minimum_required(VERSION 3.23)
project(Revenant C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Ofast -s")

include_directories(Include)

add_executable(Agent
        Source/Command.c
        Source/Core.c
        Source/Package.c
        Source/Transport.c
        Source/Parser.c
        Source/Main.c
        Source/ObfuscateStrings.c Include/RevntStrings.h)

#set_target_properties(Agent PROPERTIES LINK_FLAGS "-mwindows -Wl,--subsystem,windows")
target_compile_options(Agent PRIVATE -masm=intel -Wno-implicit-function-declaration -Wno-multichar -Wno-incompatible-pointer-types -Wno-int-conversion)
target_link_libraries(Agent ws2_32 kernel32 user32 gdi32 winspool shell32 ole32 oleaut32 uuid comdlg32 iphlpapi winhttp)

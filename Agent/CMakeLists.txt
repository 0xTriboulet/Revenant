cmake_minimum_required(VERSION 3.23)
project(Revenant C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)

include_directories(Include)

set_source_files_properties(Source/Main.c PROPERTIES COMPILE_FLAGS "-Wincompatible-pointer-types -Wmultichar -masm=intel")

add_executable(Agent
        Source/Command.c
        Source/Core.c
        Source/Package.c
        Source/Transport.c
        Source/Parser.c
        Source/Main.c
        Include/Native.h
        Include/Poly.h)

target_link_libraries(Agent ws2_32 kernel32 user32 gdi32 winspool shell32 ole32 oleaut32 uuid comdlg32 iphlpapi winhttp)

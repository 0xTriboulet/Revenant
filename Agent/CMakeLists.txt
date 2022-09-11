cmake_minimum_required( VERSION 3.23 )
project( Talon C )

set( CMAKE_C_STANDARD 99 )
set( CMAKE_C_COMPILER x86_64-w64-mingw32-gcc )

include_directories( Include )

add_executable( Agent
    Source/Main.c
    Source/Command.c
    Source/Core.c
    Source/Package.c
    Source/Transport.c
    Source/Parser.c
)

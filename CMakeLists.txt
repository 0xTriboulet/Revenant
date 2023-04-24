set(ARCH_VARIABLE ${ARCH})

if(WIN32)
    # LAZY DEV ENVIRONMENT CMAKE
    # IF x64
    if(ARCH_VARIABLE STREQUAL "x64")
        cmake_minimum_required(VERSION 3.24)
        project(Revenant C)

        set(CMAKE_VERBOSE_MAKEFILE ON)

        set(CMAKE_C_STANDARD 99)
        set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
        set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)

        set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/Agent/Bin/x64)

        include_directories(${CMAKE_SOURCE_DIR}/Agent/Include)

        add_executable(Revenant Agent/Source/Main.c Agent/Source/Command.c Agent/Source/Core.c Agent/Source/Package.c Agent/Source/Parser.c Agent/Source/Transport.c Agent/Source/Obfuscation.c Agent/Source/Utilities.c Agent/Source/AntiDebug.c Agent/Source/Poly.c Agent/Source/Asm.c)
        target_compile_options(Revenant PRIVATE -s -O3 -masm=intel -fdata-sections -Wno-implicit-function-declaration -Wno-multichar -Wno-incompatible-pointer-types -Wno-int-conversion)
        target_link_options(Revenant PRIVATE -s -O3)
        target_link_libraries(Revenant ws2_32 kernel32 user32 gdi32 winspool shell32 ole32 oleaut32 uuid comdlg32 iphlpapi winhttp)

    else()
        cmake_minimum_required(VERSION 3.24)
        project(Revenant C)

        set(CMAKE_VERBOSE_MAKEFILE ON)

        set(CMAKE_C_STANDARD 99)

        set(CMAKE_C_COMPILER i686-w64-mingw32-gcc)  # Use the 32-bit compiler
        set(CMAKE_CXX_COMPILER i686-w64-mingw32-g++)
        set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/Agent/Bin/x86)

        include_directories(${CMAKE_SOURCE_DIR}/Agent/Include)

        add_executable(Revenant Agent/Source/Main.c Agent/Source/Command.c Agent/Source/Core.c Agent/Source/Package.c Agent/Source/Parser.c Agent/Source/Transport.c Agent/Source/Obfuscation.c Agent/Source/Utilities.c Agent/Source/AntiDebug.c Agent/Source/Poly.c Agent/Source/Asm.c)
        target_compile_options(Revenant PRIVATE -s -O3 -masm=intel -fdata-sections -Wno-implicit-function-declaration -Wno-multichar -Wno-incompatible-pointer-types -Wno-int-conversion)  # Use the 32-bit compiler options
        target_link_options(Revenant PRIVATE -s -O3)  # Use the 32-bit linker options
        target_link_libraries(Revenant ws2_32 kernel32 user32 gdi32 winspool shell32 ole32 oleaut32 uuid comdlg32 iphlpapi winhttp)


    endif()

else()
    # IF x64
    if(ARCH_VARIABLE STREQUAL "x64")
        cmake_minimum_required(VERSION 3.24)
        project(Revenant C)

        set(CMAKE_VERBOSE_MAKEFILE ON)

        set(CMAKE_C_STANDARD 99)

        set(CMAKE_C_COMPILER /usr/bin/x86_64-w64-mingw32-gcc)
        set(CMAKE_CXX_COMPILER /usr/bin/x86_64-w64-mingw32-g++)
        set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/Agent/Bin/x64)

        include_directories(${CMAKE_SOURCE_DIR}/Agent/Include)


        add_executable(Revenant Agent/Source/Main.c Agent/Source/Command.c Agent/Source/Core.c Agent/Source/Package.c Agent/Source/Parser.c Agent/Source/Transport.c Agent/Source/Obfuscation.c Agent/Source/Utilities.c Agent/Source/AntiDebug.c Agent/Source/Poly.c Agent/Source/Asm.c)
        target_compile_options(Revenant PRIVATE -s -O0 -masm=intel -mwindows -fdata-sections -Wno-implicit-function-declaration -Wno-multichar -Wno-incompatible-pointer-types -Wno-int-conversion)
        target_link_options(Revenant PRIVATE -mwindows -s -O3)
        target_link_libraries(Revenant ws2_32 kernel32 user32 gdi32 winspool shell32 ole32 oleaut32 uuid comdlg32 iphlpapi winhttp)

    else()
        cmake_minimum_required(VERSION 3.24)
        project(Revenant C)

        set(CMAKE_VERBOSE_MAKEFILE ON)

        set(CMAKE_C_STANDARD 99)

        set(CMAKE_C_COMPILER /usr/bin/i686-w64-mingw32-gcc)
        set(CMAKE_CXX_COMPILER /usr/bin/i686-w64-mingw32-g++)
        set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/Agent/Bin/x86)

        include_directories(${CMAKE_SOURCE_DIR}/Agent/Include)

        add_executable(Revenant Agent/Source/Main.c Agent/Source/Command.c Agent/Source/Core.c Agent/Source/Package.c Agent/Source/Parser.c Agent/Source/Transport.c Agent/Source/Obfuscation.c Agent/Source/Utilities.c Agent/Source/AntiDebug.c Agent/Source/Poly.c Agent/Source/Asm.c)
        target_compile_options(Revenant PRIVATE -s -O0 -masm=intel -mwindows -fdata-sections -Wno-implicit-function-declaration -Wno-multichar -Wno-incompatible-pointer-types -Wno-int-conversion)
        target_link_options(Revenant PRIVATE -mwindows -s -O3)
        target_link_libraries(Revenant ws2_32 kernel32 user32 gdi32 winspool shell32 ole32 oleaut32 uuid comdlg32 iphlpapi winhttp)

    endif()
endif()
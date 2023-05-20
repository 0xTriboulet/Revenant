set(ARCH_VARIABLE ${ARCH})
# LAZY DEV ENVIRONMENT CMAKE
# CMAKE FOR DEV AND DEPLOYMENT PURPOSES ONLY, YOU SHOULD NOT TOUCH THIS

# WINDOWS CMAKE
if(WIN32)

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
        target_compile_options(Revenant PRIVATE -O3 -fdata-sections -Wno-implicit-function-declaration -Wno-multichar -Wno-inline-asm -Wno-incompatible-pointer-types -Wno-int-conversion -Wno-pointer-sign)
        target_link_options(Revenant PRIVATE -O3 -s)
        target_link_libraries(Revenant ws2_32 kernel32 user32 gdi32 iphlpapi advapi32 winspool shell32 ole32 oleaut32 uuid comdlg32 winhttp)

    else()
        cmake_minimum_required(VERSION 3.24)
        project(Revenant C)

        set(CMAKE_VERBOSE_MAKEFILE OFF)

        set(CMAKE_C_STANDARD 99)

        set(CMAKE_C_COMPILER i686-w64-mingw32-gcc)  # Use the 32-bit compiler
        set(CMAKE_CXX_COMPILER i686-w64-mingw32-g++)
        set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/Agent/Bin/x86)

        include_directories(${CMAKE_SOURCE_DIR}/Agent/Include)

        add_executable(Revenant Agent/Source/Main.c Agent/Source/Command.c Agent/Source/Core.c Agent/Source/Package.c Agent/Source/Parser.c Agent/Source/Transport.c Agent/Source/Obfuscation.c Agent/Source/Utilities.c Agent/Source/AntiDebug.c Agent/Source/Poly.c Agent/Source/Asm.c)
        target_compile_options(Revenant PRIVATE -O3 -DNDEBUG -fdata-sections -Wno-implicit-function-declaration -Wno-multichar -Wno-inline-asm -Wno-incompatible-pointer-types -Wno-int-conversion -Wno-pointer-sign -Wreturn-local-addr)  # Use the 32-bit compiler options
        target_link_options(Revenant PRIVATE -s -O3)  # Use the 32-bit linker options
        target_link_libraries(Revenant ws2_32 kernel32 user32 gdi32 iphlpapi advapi32 winspool shell32 ole32 oleaut32 uuid comdlg32 winhttp)


    endif()
    # LINUX CMAKE BELOW
else()
    # IF x64
    if(ARCH_VARIABLE STREQUAL "x64")
        cmake_minimum_required(VERSION 3.24)
        project(Revenant C)

        set(CMAKE_VERBOSE_MAKEFILE ON)

        set(CMAKE_C_STANDARD 99)

        set(CMAKE_C_COMPILER ${CMAKE_SOURCE_DIR}/llvm-mingw/bin/x86_64-w64-mingw32-gcc)
        set(CMAKE_CXX_COMPILER ${CMAKE_SOURCE_DIR}/llvm-mingw/bin/x86_64-w64-mingw32-g++)
        set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/Agent/Bin/x64)

        include_directories(${CMAKE_SOURCE_DIR}/Agent/Include)


        add_executable(Revenant Agent/Source/Main.c Agent/Source/Command.c Agent/Source/Core.c Agent/Source/Package.c Agent/Source/Parser.c Agent/Source/Transport.c Agent/Source/Obfuscation.c Agent/Source/Utilities.c Agent/Source/AntiDebug.c Agent/Source/Poly.c Agent/Source/Asm.c)
        target_compile_options(Revenant PRIVATE -O3 -mwindows -DNDEBUG -fdata-sections -Wno-implicit-function-declaration -Wno-multichar -Wno-inline-asm -Wno-incompatible-pointer-types -Wno-int-conversion -Wno-pointer-sign -Wreturn-local-addr)
        target_link_options(Revenant PRIVATE -mwindows -s -O3)
        target_link_libraries(Revenant ws2_32 kernel32 user32 gdi32 iphlpapi advapi32 winspool shell32 ole32 oleaut32 uuid comdlg32 winhttp)

    else()
        cmake_minimum_required(VERSION 3.24)
        project(Revenant C)

        set(CMAKE_VERBOSE_MAKEFILE ON)

        set(CMAKE_C_STANDARD 99)

        set(CMAKE_C_COMPILER ${CMAKE_SOURCE_DIR}/llvm-mingw/bin/i686-w64-mingw32-gcc)
        set(CMAKE_CXX_COMPILER ${CMAKE_SOURCE_DIR}/llvm-mingw/bin/i686-w64-mingw32-g++)
        set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/Agent/Bin/x86)

        include_directories(${CMAKE_SOURCE_DIR}/Agent/Include)

        add_executable(Revenant Agent/Source/Main.c Agent/Source/Command.c Agent/Source/Core.c Agent/Source/Package.c Agent/Source/Parser.c Agent/Source/Transport.c Agent/Source/Obfuscation.c Agent/Source/Utilities.c Agent/Source/AntiDebug.c Agent/Source/Poly.c Agent/Source/Asm.c)
        target_compile_options(Revenant PRIVATE -O3 -mwindows -DNDEBUG -fdata-sections -Wno-implicit-function-declaration -Wno-multichar -Wno-inline-asm -Wno-incompatible-pointer-types -Wno-int-conversion -Wno-pointer-sign -Wreturn-local-addr)
        target_link_options(Revenant PRIVATE -mwindows -s -O3)
        target_link_libraries(Revenant ws2_32 kernel32 user32 gdi32 iphlpapi advapi32 winspool shell32 ole32 oleaut32 uuid comdlg32 winhttp)

    endif()
endif()

if(WIN32)
    # LAZY DEV ENVIRONMENT CMAKE
    cmake_minimum_required(VERSION 3.24)
    project(Revenant C)

    set(CMAKE_VERBOSE_MAKEFILE ON)

    set(CMAKE_C_STANDARD 17)
    set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
    set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)

    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/Agent/Bin)

    include_directories(${CMAKE_SOURCE_DIR}/Agent/Include)

    set(NASM_NAMES Agent/Source/Asm/ntdll)

    FOREACH(src ${NASM_NAMES})
        SET(NASM_SRC ${CMAKE_CURRENT_SOURCE_DIR}/${src}.asm)
        SET(NASM_OBJ ${CMAKE_CURRENT_BINARY_DIR}/../${src}.o)
        ADD_CUSTOM_COMMAND(
                OUTPUT ${NASM_OBJ}
                COMMAND nasm -f win64 -o ${NASM_OBJ} ${NASM_SRC}
                DEPENDS ${NASM_SRC}
                COMMENT "Assembling ${NASM_SRC}")
        SET(NASM_OBJECTS ${NASM_OBJECTS} ${NASM_OBJ})
    ENDFOREACH(src)

    add_executable(Revenant ${NASM_OBJECTS} Agent/Source/Main.c Agent/Source/Command.c Agent/Source/Core.c Agent/Source/Package.c Agent/Source/Parser.c Agent/Source/Transport.c Agent/Source/Obfuscation.c)
    target_compile_options(Revenant PRIVATE -masm=intel -fdata-sections -Wno-implicit-function-declaration -Wno-multichar -Wno-incompatible-pointer-types -Wno-int-conversion)
    target_link_options(Revenant PRIVATE -s -mwindows)
    target_link_libraries(Revenant ws2_32 kernel32 user32 gdi32 winspool shell32 ole32 oleaut32 uuid comdlg32 iphlpapi winhttp)
else()
    cmake_minimum_required(VERSION 3.24)
    project(Revenant C)

    set(CMAKE_VERBOSE_MAKEFILE ON)

    set(CMAKE_C_STANDARD 17)
    set(CMAKE_C_COMPILER /usr/bin/x86_64-w64-mingw32-gcc-win32)
    set(CMAKE_CXX_COMPILER /usr/bin/x86_64-w64-mingw32-g++-win32)

    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/Agent/Bin)

    include_directories(${CMAKE_SOURCE_DIR}/Agent/Include)

    set(NASM_NAMES Agent/Source/Asm/ntdll)

    FOREACH(src ${NASM_NAMES})
        SET(NASM_SRC ${CMAKE_CURRENT_SOURCE_DIR}/${src}.asm)
        SET(NASM_OBJ ${CMAKE_CURRENT_BINARY_DIR}/${src}.o)
        ADD_CUSTOM_COMMAND(
                OUTPUT ${NASM_OBJ}
                COMMAND nasm -f win64 -o ${NASM_OBJ} ${NASM_SRC}
                DEPENDS ${NASM_SRC}
                COMMENT "Assembling ${NASM_SRC}")
        SET(NASM_OBJECTS ${NASM_OBJECTS} ${NASM_OBJ} Agent/Include/Strings.h)
    ENDFOREACH(src)

    add_executable(Revenant ${NASM_OBJECTS} Agent/Source/Main.c Agent/Source/Command.c Agent/Source/Core.c Agent/Source/Package.c Agent/Source/Parser.c Agent/Source/Transport.c Agent/Source/Obfuscation.c)
    target_compile_options(Revenant PRIVATE -masm=intel -mwindows -fdata-sections -Wno-implicit-function-declaration -Wno-multichar -Wno-incompatible-pointer-types -Wno-int-conversion)
    target_link_options(Revenant PRIVATE -mwindows -s -Os)
    target_link_libraries(Revenant ws2_32 kernel32 user32 gdi32 winspool shell32 ole32 oleaut32 uuid comdlg32 iphlpapi winhttp)
endif()
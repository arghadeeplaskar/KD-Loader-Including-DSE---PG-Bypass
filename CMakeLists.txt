cmake_minimum_required(VERSION 3.22)

project(
    AgdlKernelBypass
    VERSION 1.0.0
    DESCRIPTION "Agdl High-Performance DSE & PatchGuard Orchestrator"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Export compile commands for IDE indexing and language servers
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Source and Header Definitions
set(AGDL_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")

set(AGDL_SOURCES
    src/Main.cpp
    src/Driver/AmdProtocol.cpp
    src/Driver/KernelMemoryProvider.cpp
    src/Scanning/SignatureScanner.cpp
    src/Kernel/KernelEnvironment.cpp
)

set(AGDL_HEADERS
    include/Common/Types.hpp
    include/Driver/AmdProtocol.hpp
    include/Driver/KernelMemoryProvider.hpp
    include/Scanning/SignatureScanner.hpp
    include/Kernel/KernelEnvironment.hpp
)

add_executable(${PROJECT_NAME} ${AGDL_SOURCES} ${AGDL_HEADERS})

target_include_directories(${PROJECT_NAME} PRIVATE
    ${AGDL_INCLUDE_DIR}
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    ntdll
    psapi
    advapi32
)

if (MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE
        /W4
        /permissive-
        /Zc:inline
        /Zc:preprocessor
        /utf-8
        /O2
        /GL
    )
    target_link_options(${PROJECT_NAME} PRIVATE
        /LTCG
        /SUBSYSTEM:CONSOLE
    )
else()
    target_compile_options(${PROJECT_NAME} PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -O3
    )
endif()

install(
    TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin
)
cmake_minimum_required(VERSION 3.4.1)
if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    project(redsocks C)
endif()

# Embedders can supply an existing libevent target (ProxyDroid does this).
if(TARGET event)
    set(REDSOCKS_EVENT_LIBRARY event)
else()
    find_path(REDSOCKS_EVENT_INCLUDE_DIR event.h)
    find_library(REDSOCKS_EVENT_LIBRARY NAMES event_core event)
    if(NOT REDSOCKS_EVENT_INCLUDE_DIR OR NOT REDSOCKS_EVENT_LIBRARY)
        message(FATAL_ERROR "libevent headers and library are required")
    endif()
endif()

if(ANDROID OR CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(USE_IPTABLES 1)
endif()
file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/generated")
configure_file(cmake/config.h.in generated/config.h)
set(REDSOCKS_VERSION_FILE "${CMAKE_CURRENT_BINARY_DIR}/generated/version.c")
add_custom_target(redsocks-version
    COMMAND "${CMAKE_COMMAND}"
        "-DREDSOCKS_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
        "-DREDSOCKS_VERSION_OUTPUT=${REDSOCKS_VERSION_FILE}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.cmake"
    BYPRODUCTS "${REDSOCKS_VERSION_FILE}"
    VERBATIM)

add_executable(redsocks
    parser.c main.c redsocks.c log.c http-connect.c tls-sni.c socks4.c
    socks5.c http-relay.c base.c base64.c md5.c http-auth.c utils.c
    redudp.c dnstc.c dnsu2t.c "${REDSOCKS_VERSION_FILE}")
add_dependencies(redsocks redsocks-version)
set_property(TARGET redsocks PROPERTY C_STANDARD 99)
target_compile_definitions(redsocks PRIVATE _GNU_SOURCE _DEFAULT_SOURCE _XOPEN_SOURCE=600)
target_compile_options(redsocks PRIVATE -Wall)
target_include_directories(redsocks PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/generated")
if(REDSOCKS_EVENT_INCLUDE_DIR)
    target_include_directories(redsocks PRIVATE "${REDSOCKS_EVENT_INCLUDE_DIR}")
endif()
target_link_libraries(redsocks ${REDSOCKS_EVENT_LIBRARY})

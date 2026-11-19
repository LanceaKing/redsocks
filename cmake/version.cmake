# ProxyDroid supplies a source identity helper; standalone builds use this Git repository.
if(REDSOCKS_SOURCE_INFO_SCRIPT)
    find_program(REDSOCKS_PYTHON NAMES python3 REQUIRED)
    execute_process(COMMAND "${REDSOCKS_PYTHON}"
        "${REDSOCKS_SOURCE_INFO_SCRIPT}" "${REDSOCKS_SOURCE_DIR}" --with-dependencies
        OUTPUT_VARIABLE REDSOCKS_REVISION OUTPUT_STRIP_TRAILING_WHITESPACE
        COMMAND_ERROR_IS_FATAL ANY)
else()
    set(REDSOCKS_REVISION "0.5-sni-archive")
    find_package(Git QUIET)
    if(GIT_FOUND)
        execute_process(COMMAND "${GIT_EXECUTABLE}" rev-parse --short=12 HEAD
            WORKING_DIRECTORY "${REDSOCKS_SOURCE_DIR}"
            OUTPUT_VARIABLE REVISION OUTPUT_STRIP_TRAILING_WHITESPACE
            RESULT_VARIABLE GIT_RESULT ERROR_QUIET)
        if(GIT_RESULT EQUAL 0)
            set(REDSOCKS_REVISION "git/${REVISION}")
            execute_process(COMMAND "${GIT_EXECUTABLE}" status --porcelain --untracked-files=all
                WORKING_DIRECTORY "${REDSOCKS_SOURCE_DIR}"
                OUTPUT_VARIABLE DIRTY OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
            if(DIRTY)
                string(APPEND REDSOCKS_REVISION "-dirty")
            endif()
        endif()
    endif()
endif()
set(CONTENT "/* Generated at build time. */\n#include \"version.h\"\nconst char *redsocks_version = \"redsocks.${REDSOCKS_REVISION}-http-connect-sni\";\n")
set(OLD_CONTENT "")
if(EXISTS "${REDSOCKS_VERSION_OUTPUT}")
    file(READ "${REDSOCKS_VERSION_OUTPUT}" OLD_CONTENT)
endif()
if(NOT CONTENT STREQUAL OLD_CONTENT)
    file(WRITE "${REDSOCKS_VERSION_OUTPUT}" "${CONTENT}")
endif()

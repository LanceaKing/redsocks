# Git also works when .git is a submodule file, rather than a directory.
find_package(Git QUIET)
set(REDSOCKS_REVISION "0.5-sni-archive")
if(GIT_FOUND)
    execute_process(COMMAND "${GIT_EXECUTABLE}" rev-parse --short=12 HEAD
        WORKING_DIRECTORY "${REDSOCKS_SOURCE_DIR}"
        OUTPUT_VARIABLE REVISION OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE GIT_RESULT ERROR_QUIET)
    if(GIT_RESULT EQUAL 0)
        set(REDSOCKS_REVISION "git/${REVISION}")
        execute_process(COMMAND "${GIT_EXECUTABLE}" status --porcelain --untracked-files=no
            WORKING_DIRECTORY "${REDSOCKS_SOURCE_DIR}"
            OUTPUT_VARIABLE DIRTY OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
        if(DIRTY)
            set(REDSOCKS_REVISION "${REDSOCKS_REVISION}-dirty")
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

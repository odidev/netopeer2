#include(CheckFunctionExists)

project(mpra C)

# set version
set(MPRA_VERSION 0.0.1)
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/mpra_version.h.in" "${PROJECT_BINARY_DIR}/mpra_version.h" ESCAPE_QUOTES @ONLY)
include_directories(${PROJECT_BINARY_DIR})

# source files
set(MPRA_SRC
    mpra.c)

# mpra target
add_executable(mpra ${MPRA_SRC} $<TARGET_OBJECTS:compat>)

# dependencies - sysrepo
find_package(Sysrepo REQUIRED)
target_link_libraries(mpra ${SYSREPO_LIBRARIES})
include_directories(${SYSREPO_INCLUDE_DIRS})
list(APPEND CMAKE_REQUIRED_INCLUDES ${SYSREPO_INCLUDE_DIRS})
list(APPEND CMAKE_REQUIRED_LIBRARIES ${SYSREPO_LIBRARIES})

# install binary
install(TARGETS mpra DESTINATION ${CMAKE_INSTALL_BINDIR})

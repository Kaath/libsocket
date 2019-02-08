cmake_minimum_required(VERSION 3.13.0)

set(LANGUAGE CXX)
set(OPT
    -Wall
    -Wextra
    -Werror
    -pedantic
    -std=c++17)

add_library(socket SHARED)
target_compile_options(socket PRIVATE ${OPT})
target_include_directories(socket PUBLIC includes)
add_subdirectory(src)
add_subdirectory(includes)

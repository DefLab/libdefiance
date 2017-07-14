cmake_minimum_required(VERSION 3.2)
project(libdefiance)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_STATIC_LIBRARY_PREFIX "")

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include_directories(deps)

set(CMAKE_CXX_STANDARD 11)

file(GLOB SOURCE_FILES *.cpp deps/libinjection/*.c)
add_library(libdefiance ${SOURCE_FILES})
cmake_minimum_required (VERSION 2.6)
project (ssock)

configure_file(
    ${CMAKE_SOURCE_DIR}/Makefile.in ${CMAKE_SOURCE_DIR}/Makefile)

include_directories(.)

add_executable(ssock_test 
    ssock_test.c
    ssock.h)

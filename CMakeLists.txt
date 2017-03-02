cmake_minimum_required (VERSION 2.6)
project (ssock)

configure_file(
    ${CMAKE_SOURCE_DIR}/Makefile.in ${CMAKE_SOURCE_DIR}/Makefile)

find_package(OpenSSL REQUIRED)

set (SSOCK_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR} ${OPENSSL_INCLUDE_DIR} CACHE STRING "net_includes")
set (SSOCK_LIBRARIES  ${OPENSSL_LIBRARIES} CACHE STRING "net_openssl")

include_directories(${SSOCK_INCLUDES})

add_executable(net_exemple
    net_exemple.c
    net.h)

target_link_libraries(net_exemple ${OPENSSL_LIBRARIES})

cmake_minimum_required (VERSION 2.6)
project (net)

configure_file(
    ${CMAKE_SOURCE_DIR}/Makefile.in ${CMAKE_SOURCE_DIR}/Makefile)

find_package(OpenSSL REQUIRED)

set (NET_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR} ${OPENSSL_INCLUDE_DIR} CACHE STRING "net_includes")
set (NET_LIBRARIES  ${OPENSSL_LIBRARIES} CACHE STRING "net_openssl")

include_directories(${NET_INCLUDES})

add_executable(net_httpclient
    net_httpclient.c
    net.h)

target_link_libraries(net_httpclient ${OPENSSL_LIBRARIES})

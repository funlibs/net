cmake_minimum_required (VERSION 2.6)
project (ssock)

configure_file(
    ${CMAKE_SOURCE_DIR}/Makefile.in ${CMAKE_SOURCE_DIR}/Makefile)

find_package(OpenSSL REQUIRED)

set (SSOCK_INCLUDES . ${OPENSSL_INCLUDE_DIR})
set (SSOCK_LIBRARIES ${OPENSSL_LIBRARIES})

include_directories(${SSOCK_INCLUDES})

add_executable(testssl
    testssl.c)

add_executable(ssock_test
    ssock_test.c
    ssock.h)

target_link_libraries(testssl ${OPENSSL_LIBRARIES})
target_link_libraries(ssock_test ${OPENSSL_LIBRARIES})

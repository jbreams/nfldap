cmake_minimum_required(VERSION 3.2.0)
project(nfldap)

find_package(PkgConfig REQUIRED)
find_package (Threads REQUIRED)

pkg_search_module(LIBMONGOCXX libmongocxx REQUIRED)
pkg_search_module(OPENSSL openssl REQURED)
pkg_search_module(YAMLCPP yaml-cpp REQURED)

add_executable(nfldap
    ber.cpp
    exceptions.cpp
    ldapproto.cpp
    loguru.cpp
    main.cpp
    mongobackend.cpp
    passwords.cpp
)
set_property(TARGET nfldap PROPERTY CXX_STANDARD 11)
set_property(TARGET nfldap PROPERTY CXX_STANDARD_REQUIRED ON)

target_link_libraries(nfldap
    ${OPENSSL_LIBRARIES}
    ${LIBMONGOCXX_LIBRARIES}
    ${YAMLCPP_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
    ${CMAKE_DL_LIBS}
)
target_include_directories(nfldap PUBLIC
    ${OPENSSL_INCLUDE_DIRS}
    ${YAMLCPP_INCLUDE_DIRS}
    ${LIBMONGOCXX_INCLUDE_DIRS}
)
target_compile_options(nfldap PUBLIC
    ${OPENSSL_CFLAGS_OTHER}
    ${YAMLCPP_CFLAGS_OTHER}
    ${LIBMONGOCXX_CFLAGS_OTHER}
)

add_executable(nfpasswd
    nfpasswd.cpp
    passwords.cpp
)
set_property(TARGET nfpasswd PROPERTY CXX_STANDARD 11)
set_property(TARGET nfpasswd PROPERTY CXX_STANDARD_REQUIRED ON)
target_link_libraries(nfpasswd
    ${OPENSSL_LIBRARIES}
)
target_include_directories(nfpasswd PUBLIC
    ${OPENSSL_INCLUDE_DIRS}
)
target_compile_options(nfpasswd PUBLIC
    ${OPENSSL_CFLAGS_OTHER}
)


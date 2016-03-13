cmake_minimum_required(VERSION 3.2.0)
project(nfldap)

find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)
find_package(Boost REQUIRED COMPONENTS regex)

set(Boost_USE_MULTITHREADED      ON)
set(Boost_USE_STATIC_RUNTIME    OFF)

pkg_search_module(LIBMONGOCXX libmongocxx REQUIRED)
pkg_search_module(LIBSODIUM libsodium REQURED)
pkg_search_module(YAMLCPP yaml-cpp REQURED)

add_library(MAIN_SOURCES OBJECT
    access.cpp
    ber.cpp
    exceptions.cpp
    filter.cpp
    ldapproto.cpp
    loguru.cpp
    mongobackend.cpp
    passwords.cpp
)
set_property(TARGET MAIN_SOURCES PROPERTY CXX_STANDARD 11)
set_property(TARGET MAIN_SOURCES PROPERTY CXX_STANDARD_REQUIRED ON)

target_include_directories(MAIN_SOURCES PUBLIC
    ${LIBSODIUM_INCLUDE_DIRS}
    ${YAMLCPP_INCLUDE_DIRS}
    ${Boost_INCLUDE_DIRS}
    ${LIBMONGOCXX_INCLUDE_DIRS}
)
target_compile_options(MAIN_SOURCES PUBLIC
    ${LIBSODIUM_CFLAGS_OTHER}
    ${YAMLCPP_CFLAGS_OTHER}
    ${LIBMONGOCXX_CFLAGS_OTHER}
)


add_executable(nfldap
    $<TARGET_OBJECTS:MAIN_SOURCES>
    main.cpp
)
set_property(TARGET nfldap PROPERTY CXX_STANDARD 11)
set_property(TARGET nfldap PROPERTY CXX_STANDARD_REQUIRED ON)

target_link_libraries(nfldap
    ${LIBSODIUM_LIBRARIES}
    ${LIBMONGOCXX_LIBRARIES}
    ${YAMLCPP_LIBRARIES}
    ${Boost_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
    ${CMAKE_DL_LIBS}
)
target_include_directories(nfldap PUBLIC
    ${LIBSODIUM_INCLUDE_DIRS}
    ${YAMLCPP_INCLUDE_DIRS}
    ${Boost_INCLUDE_DIRS}
    ${LIBMONGOCXX_INCLUDE_DIRS}
)
target_compile_options(nfldap PUBLIC
    ${LIBSODIUM_CFLAGS_OTHER}
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
    ${LIBSODIUM_LIBRARIES}
)
target_include_directories(nfpasswd PUBLIC
    ${LIBSODIUM_INCLUDE_DIRS}
)
target_compile_options(nfpasswd PUBLIC
    ${LIBSODIUM_CFLAGS_OTHER}
)

file(GLOB TEST_SOURCES *_test.cpp)

add_executable(unittests ${TEST_SOURCES} $<TARGET_OBJECTS:MAIN_SOURCES>)
set_property(TARGET unittests PROPERTY CXX_STANDARD 11)
set_property(TARGET unittests PROPERTY CXX_STANDARD_REQUIRED ON)
target_link_libraries(unittests
    ${LIBSODIUM_LIBRARIES}
    ${LIBMONGOCXX_LIBRARIES}
    ${YAMLCPP_LIBRARIES}
    ${Boost_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
    ${CMAKE_DL_LIBS}
)
target_include_directories(unittests PUBLIC
    ${LIBSODIUM_INCLUDE_DIRS}
    ${YAMLCPP_INCLUDE_DIRS}
    ${Boost_INCLUDE_DIRS}
    ${LIBMONGOCXX_INCLUDE_DIRS}
)
target_compile_options(unittests PUBLIC
    ${LIBSODIUM_CFLAGS_OTHER}
    ${YAMLCPP_CFLAGS_OTHER}
    ${LIBMONGOCXX_CFLAGS_OTHER}
)
enable_testing()
add_test(NAME unittests COMMAND unittests)

cmake_minimum_required(VERSION 3.2.0)
project(nfldap)

find_package(PkgConfig REQUIRED)
find_package (Threads REQUIRED)

pkg_search_module(LIBMONGOCXX libmongocxx REQUIRED)

add_executable(nfldap
    ber.cpp
    ldapproto.cpp
    mongobackend.cpp
    main.cpp
    exceptions.cpp
    loguru.cpp
)
set_property(TARGET nfldap PROPERTY CXX_STANDARD 11)
set_property(TARGET nfldap PROPERTY CXX_STANDARD_REQUIRED ON)

target_link_libraries(nfldap ${LIBMONGOCXX_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} ${CMAKE_DL_LIBS})
target_include_directories(nfldap PUBLIC ${LIBMONGOCXX_INCLUDE_DIRS})
target_compile_options(nfldap PUBLIC ${LIBMONGOCXX_CFLAGS_OTHER})

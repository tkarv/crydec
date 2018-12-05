cmake_minimum_required(VERSION 3.0)
project(crydec)
include(GNUInstallDirs)
set (CMAKE_CXX_STANDARD 11)

add_library(cryptopp STATIC IMPORTED)
set_target_properties(cryptopp PROPERTIES
  IMPORTED_LOCATION "/usr/local/lib/libcryptopp.a"
  INTERFACE_INCLUDE_DIRECTORIES "/usr/local/include/cryptopp"
)

add_executable( encrypt encrypt.cpp )
add_executable( decrypt decrypt.cpp )
target_link_libraries( encrypt cryptopp)
target_link_libraries( decrypt cryptopp)

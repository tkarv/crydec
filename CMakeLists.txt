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
add_executable( generate_rsa_keypair generate_rsa_keypair.cpp)
add_executable( sign_message_with_private_key sign_message_with_private_key.cpp )
add_executable( verify_signature verify_signature.cpp)
add_executable( generate_aes_key generate_aes_key.cpp)
target_link_libraries( encrypt cryptopp)
target_link_libraries( decrypt cryptopp)
target_link_libraries( generate_rsa_keypair cryptopp )
target_link_libraries( sign_message_with_private_key cryptopp)
target_link_libraries( verify_signature cryptopp)
target_link_libraries( generate_aes_key cryptopp)
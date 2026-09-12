cmake_minimum_required(VERSION 3.10)
project(ofp_extractor_cpp)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add tiny-AES-c and md5-c sources
set(THIRD_PARTY_SOURCES
    third_party/aes.c
    third_party/md5.c
    third_party/tinyxml2.cpp
)

# Compile options for tiny-AES-c to enable AES-128
add_definitions(-DAES128=1)

# Main executable
add_executable(ofp_extractor
    src/main.cpp
    ${THIRD_PARTY_SOURCES}
)

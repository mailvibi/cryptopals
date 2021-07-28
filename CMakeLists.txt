cmake_minimum_required(VERSION 3.16)
project(Cryptopals VERSION 1.0
        DESCRIPTION "Cryptopals Exercises in CXX"
        LANGUAGES CXX)

#add_executable(set1 src/common/cryptopals.cpp src/set1/set1.cpp)
#target_compile_features(set1 PUBLIC cxx_std_17)
#set_target_properties(set1 PROPERTIES CXX_EXTENSIONS OFF)
#target_include_directories(set1 PUBLIC src/set1)
#target_include_directories(set1 PUBLIC include)
#target_link_libraries(set1 crypto)
#target_include_directories(set1 PUBLIC include)

include_directories(include)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(common_lib src/lib/common_lib.cpp)
add_library(wcrypto src/lib/wcrypto.cpp)
add_library(xor_enc src/lib/xor_enc.cpp)

set_target_properties(common_lib PROPERTIES CXX_EXTENSIONS OFF)

add_subdirectory(src/set1)
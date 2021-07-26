cmake_minimum_required(VERSION 3.16)
project(Cryptopals VERSION 1.0
        DESCRIPTION "Cryptopals Exercises in CXX"
        LANGUAGES CXX)
		
add_executable(set1 src/main.cpp src/cryptopals.cpp src/set1/set1.cpp)
target_compile_features(set1 PUBLIC cxx_std_17)
set_target_properties(set1 PROPERTIES CXX_EXTENSIONS OFF)
target_include_directories(set1 PUBLIC src/set1)
target_include_directories(set1 PUBLIC include)
target_link_libraries(set1 crypto)

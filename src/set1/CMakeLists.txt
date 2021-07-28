add_executable(set1 set1.cpp)
target_link_libraries(set1 PUBLIC common_lib wcrypto xor_enc crypto)
target_include_directories(set1 PRIVATE .)
target_include_directories(set1 PUBLIC ${PROJECT_SOURCE_DIR}/include)

target_compile_features(set1 PUBLIC cxx_std_17)
set_target_properties(set1 PROPERTIES CXX_EXTENSIONS OFF)





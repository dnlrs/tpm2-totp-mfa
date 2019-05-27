cmake_minimum_required(VERSION 3.0.0)
project(tpm_policies VERSION 0.1.0)

#include(CTest)
#enable_testing()


add_library(ltpm    
    src/utils.cpp
    src/hash_key.cpp
    src/policy.cpp
    src/primary_key.cpp
    src/nv_index.cpp
    src/totp.cpp
    src/tpm.cpp
    src/sym_key.cpp)

target_link_libraries(ltpm -L/usr/local/lib)
target_link_libraries(ltpm -ltss2-esys)
target_link_libraries(ltpm -ltss2-mu)
target_link_libraries(ltpm -ltss2-tcti-tabrmd)
target_link_libraries(ltpm -lcrypto)
target_link_libraries(ltpm -lqrencode)

add_executable(tpm_policies src/main.cpp)
target_link_libraries(tpm_policies ltpm)

#set(CPACK_PROJECT_NAME ${PROJECT_NAME})
#set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
#include(CPack)

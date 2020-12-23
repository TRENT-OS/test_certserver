#
# Test CertServer component
#
# Copyright (C) 2020, Hensoldt Cyber GmbH
#

cmake_minimum_required(VERSION 3.7.2)

os_set_config_file(system_config.h)


#-------------------------------------------------------------------------------
project(system_config C)
add_library(${PROJECT_NAME} INTERFACE)
target_include_directories(${PROJECT_NAME} INTERFACE ${CMAKE_CURRENT_LIST_DIR})


#-------------------------------------------------------------------------------
project(test_certserver C)

CertServer_DeclareCAmkESComponent(
    CertServer
)
EntropySource_DeclareCAmkESComponent(
    EntropySource
)

DeclareCAmkESComponent(
    test_CertServer1
    SOURCES
        components/Tests/src/test_CertServer.c
    C_FLAGS
        -Wall
        -Werror
        -DCLIENT_ID=101
    LIBS
        os_core_api
        lib_macros
        CertServer_client
)
DeclareCAmkESComponent(
    test_CertServer2
    SOURCES
        components/Tests/src/test_CertServer.c
    C_FLAGS
        -Wall
        -Werror
        -DCLIENT_ID=102
    LIBS
        os_core_api
        lib_macros
        CertServer_client
 )
 DeclareCAmkESComponent(
    test_CertServer3
    SOURCES
        components/Tests/src/test_CertServer.c
    C_FLAGS
        -Wall
        -Werror
        -DCLIENT_ID=103
    LIBS
        os_core_api
        lib_macros
        CertServer_client
)

DeclareAndCreateCamkESSystem(main.camkes)
GenerateSimulateScript()

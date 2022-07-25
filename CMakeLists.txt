#
# Test CertServer component
#
# Copyright (C) 2020-2022, HENSOLDT Cyber GmbH
#

cmake_minimum_required(VERSION 3.7.2)

#-------------------------------------------------------------------------------
# use the SDK
find_package("os-sdk" REQUIRED)
os_sdk_set_defaults()
os_sdk_setup(CONFIG_FILE "system_config.h" CONFIG_PROJECT "system_config")


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

os_sdk_create_CAmkES_system("main.camkes")

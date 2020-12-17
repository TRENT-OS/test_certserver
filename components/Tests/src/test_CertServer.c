/* Copyright (C) 2020, Hensoldt Cyber GmbH */

#include "CertServer.h"

#include "LibMacros/Test.h"
#include "SharedCerts.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include <camkes.h>

static const if_CertServer_t certServer =
    IF_CERTSERVER_ASSIGN(
        cert_rpc,
        cert_port);

// Test Functions --------------------------------------------------------------

static void
test_CertServer_initChain(void)
{
    TEST_START();

    TEST_SUCCESS(CertServer_initChain(&certServer));

    TEST_FINISH();
}

static void
test_CertServer_freeChain(void)
{
    TEST_START();

    TEST_SUCCESS(CertServer_freeChain(&certServer));

    TEST_FINISH();
}

static void
test_CertServer_addCertToChain(void)
{
    uint8_t cert[] = TEST_SERVER_CERT;
    size_t certLen = sizeof(cert);
    OS_CertParserCert_Encoding_t enc = OS_CertParserCert_Encoding_PEM;

    TEST_START();

    TEST_SUCCESS(CertServer_addCertToChain(&certServer, enc, cert, certLen));

    TEST_FINISH();
}

static void
test_CertServer_verifyChain(void)
{
    OS_CertParser_VerifyFlags_t flags;

    TEST_START();

    TEST_SUCCESS(CertServer_verifyChain(&certServer, &flags));

    TEST_FINISH();
}

// Public Functions ------------------------------------------------------------

int run()
{
    test_CertServer_initChain();
    test_CertServer_addCertToChain();
    test_CertServer_verifyChain();
    test_CertServer_freeChain();

    Debug_LOG_INFO("All tests successfully completed.");

    return 0;
}

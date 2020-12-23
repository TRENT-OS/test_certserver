/* Copyright (C) 2020, Hensoldt Cyber GmbH */

#include "CertServer.h"

#include "lib_macros/Test.h"
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
test_CertServer_initChain_pos(
    uint32_t cid)
{
    TEST_START("i", cid);

    TEST_SUCCESS(CertServer_initChain(&certServer));
    TEST_SUCCESS(CertServer_freeChain(&certServer));

    TEST_FINISH();
}

static void
test_CertServer_initChain_neg(
    uint32_t cid)
{
    TEST_START("i", cid);

    // Empty context
    TEST_INVAL_PARAM(CertServer_initChain(NULL));

    // Try to init twice
    TEST_SUCCESS(CertServer_initChain(&certServer));
    TEST_INVAL_STATE(CertServer_initChain(&certServer));
    TEST_SUCCESS(CertServer_freeChain(&certServer));

    TEST_FINISH();
}

static void
test_CertServer_addCertToChain_pos(
    uint32_t cid)
{
    const uint8_t cert[] = TEST_SERVER_CERT_DER;
    const uint8_t cert0[] = TEST_ROOT_CA_CERT;
    const uint8_t cert1[] = TEST_IMED_CA_CERT;

    TEST_START("i", cid);

    // Add the CA chain to the CertServer; this makes not much sense if we are
    // looking to do an actual verification (the same chain is configured as
    // trusted chain), but allows to add at least two certs here..
    TEST_SUCCESS(CertServer_initChain(&certServer));
    TEST_SUCCESS(CertServer_addCertToChain(
                     &certServer,
                     OS_CertParserCert_Encoding_PEM,
                     cert0,
                     sizeof(cert0)));
    TEST_SUCCESS(CertServer_addCertToChain(
                     &certServer,
                     OS_CertParserCert_Encoding_PEM,
                     cert1,
                     sizeof(cert1)));
    TEST_SUCCESS(CertServer_freeChain(&certServer));

    // Add DER encoded cert
    TEST_SUCCESS(CertServer_initChain(&certServer));
    TEST_SUCCESS(CertServer_addCertToChain(
                     &certServer,
                     OS_CertParserCert_Encoding_DER,
                     cert,
                     sizeof(cert)));
    TEST_SUCCESS(CertServer_freeChain(&certServer));

    TEST_FINISH();
}

static void
test_CertServer_addCertToChain_neg(
    uint32_t cid)
{
    const uint8_t cert[] = TEST_SERVER_CERT;

    TEST_START("i", cid);

    TEST_SUCCESS(CertServer_initChain(&certServer));

    // Missing context
    TEST_INVAL_PARAM(CertServer_addCertToChain(
                         NULL,
                         OS_CertParserCert_Encoding_PEM,
                         cert,
                         sizeof(cert)));
    // Incorrect encoding
    TEST_INVAL_PARAM(CertServer_addCertToChain(
                         &certServer,
                         666,
                         cert,
                         sizeof(cert)));
    // Empty buffer
    TEST_INVAL_PARAM(CertServer_addCertToChain(
                         &certServer,
                         OS_CertParserCert_Encoding_PEM,
                         NULL,
                         sizeof(cert)));
    // Invalid len (zero)
    TEST_INVAL_PARAM(CertServer_addCertToChain(
                         &certServer,
                         OS_CertParserCert_Encoding_PEM,
                         cert,
                         0));
    // Invalid len (bigger than dataport)
    TEST_INVAL_PARAM(CertServer_addCertToChain(
                         &certServer,
                         OS_CertParserCert_Encoding_PEM,
                         cert,
                         OS_Dataport_getSize(certServer.dataport) + 1));

    // Add cert twice; since the second one is not signed by the first, this
    // should fail with the error actually coming from the certparser lib..
    TEST_SUCCESS(CertServer_addCertToChain(
                     &certServer,
                     OS_CertParserCert_Encoding_PEM,
                     cert,
                     sizeof(cert)));
    TEST_ABORTED(CertServer_addCertToChain(
                     &certServer,
                     OS_CertParserCert_Encoding_PEM,
                     cert,
                     sizeof(cert)));

    TEST_SUCCESS(CertServer_freeChain(&certServer));

    TEST_FINISH();
}

static void
test_CertServer_verifyChain_pos(
    uint32_t cid)
{
    const uint8_t cert[] = TEST_SERVER_CERT;
    OS_CertParser_VerifyFlags_t flags;

    TEST_START("i", cid);

    TEST_SUCCESS(CertServer_initChain(&certServer));
    TEST_SUCCESS(CertServer_addCertToChain(
                     &certServer,
                     OS_CertParserCert_Encoding_PEM,
                     cert,
                     sizeof(cert)));
    TEST_SUCCESS(CertServer_verifyChain(&certServer, &flags));
    TEST_TRUE(flags == 0);
    TEST_SUCCESS(CertServer_freeChain(&certServer));

    TEST_FINISH();
}

static void
test_CertServer_verifyChain_neg(
    uint32_t cid)
{
    const uint8_t cert[] = TEST_SERVER_CERT_SELF_SIGNED;
    OS_CertParser_VerifyFlags_t flags;

    TEST_START("i", cid);

    TEST_SUCCESS(CertServer_initChain(&certServer));
    TEST_SUCCESS(CertServer_addCertToChain(
                     &certServer,
                     OS_CertParserCert_Encoding_PEM,
                     cert,
                     sizeof(cert)));
    // Empty context
    TEST_INVAL_PARAM(CertServer_verifyChain(NULL, &flags));
    // Empty flag
    TEST_INVAL_PARAM(CertServer_verifyChain(&certServer, NULL));
    // The cert we use is self-signed, so cannot be matched against the configured
    // ca chain
    TEST_GENERIC(CertServer_verifyChain(&certServer, &flags));
    TEST_TRUE(flags == OS_CertParser_VerifyFlags_INVALID_SIG);

    TEST_SUCCESS(CertServer_freeChain(&certServer));

    TEST_FINISH();
}

static void
test_CertServer_freeChain_pos(
    uint32_t cid)
{
    TEST_START("i", cid);

    TEST_SUCCESS(CertServer_initChain(&certServer));
    TEST_SUCCESS(CertServer_freeChain(&certServer));

    TEST_FINISH();
}

static void
test_CertServer_freeChain_neg(
    uint32_t cid)
{
    TEST_START("i", cid);

    // There is no chain yet
    TEST_INVAL_STATE(CertServer_freeChain(&certServer));
    // Try empty context
    TEST_SUCCESS(CertServer_initChain(&certServer));
    TEST_INVAL_PARAM(CertServer_freeChain(NULL));

    TEST_SUCCESS(CertServer_freeChain(&certServer));

    TEST_FINISH();
}

// Public Functions ------------------------------------------------------------

int run()
{
    Debug_LOG_INFO("[CID=%i] Tests starting...", CLIENT_ID);

    test_CertServer_initChain_pos(CLIENT_ID);
    test_CertServer_initChain_neg(CLIENT_ID);

    test_CertServer_addCertToChain_pos(CLIENT_ID);
    test_CertServer_addCertToChain_neg(CLIENT_ID);

    test_CertServer_verifyChain_pos(CLIENT_ID);
    test_CertServer_verifyChain_neg(CLIENT_ID);

    test_CertServer_freeChain_pos(CLIENT_ID);
    test_CertServer_freeChain_neg(CLIENT_ID);

    Debug_LOG_INFO("[CID=%i] All tests successfully completed...", CLIENT_ID);

    return 0;
}

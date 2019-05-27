#include "hash_key.h"
#include "policy.h"
#include "utils.h"

#include "tss2/tss2_mu.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

bool create_keyedhash(    
    ESYS_CONTEXT   *ctx, 
    ESYS_TR         parent_handle, 
    TPM2B_PRIVATE **kh_private,
    TPM2B_PUBLIC  **kh_public,
    ESYS_TR        *kh_handle)
{   
    // command parameters
    TPM2B_SENSITIVE_CREATE in_sensitive = {};
    TPM2B_PUBLIC           in_public    = {};
    TPM2B_DATA             outside_info = {};
    TPML_PCR_SELECTION     creation_pcr = {};


    // response parameters
    TPM2B_PRIVATE       *out_private     = nullptr;
    TPM2B_PUBLIC        *out_public      = nullptr;
    TPM2B_CREATION_DATA *creation_data   = nullptr;
    TPM2B_DIGEST        *creation_hash   = nullptr;
    TPMT_TK_CREATION    *creation_ticket = nullptr;

    // init command parameters
    in_public.publicArea.type             = TPM2_ALG_KEYEDHASH;
    in_public.publicArea.nameAlg          = TPM2_ALG_SHA256;
    in_public.publicArea.objectAttributes = ( 
                                            TPMA_OBJECT_SIGN_ENCRYPT | 
                                            TPMA_OBJECT_SENSITIVEDATAORIGIN |
                                            TPMA_OBJECT_USERWITHAUTH );
    TPMT_KEYEDHASH_SCHEME scheme = {};
    scheme.scheme                = TPM2_ALG_HMAC;
    scheme.details.hmac.hashAlg  = TPM2_ALG_SHA1;
    in_public.publicArea.parameters.keyedHashDetail.scheme = scheme;


    ESYS_TR policy_session = ESYS_TR_NONE;
    TSS2_RC rc             = TSS2_RC_SUCCESS;
    TPM2B_DIGEST *policy_digest = nullptr;
    try {

        if (!create_duplication_policy(ctx, &policy_session)) {
            return false;
        }

        rc = Esys_PolicyGetDigest(
                        ctx, policy_session, 
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, 
                        &policy_digest);
        check_rc(rc, "Getting policy digest failed");

        rc = Esys_FlushContext(ctx, policy_session);
        check_rc(rc, "flushing policy session failed");
        policy_session = ESYS_TR_NONE;

        in_public.publicArea.authPolicy = *policy_digest;

        rc = Esys_Create(
                        ctx, parent_handle,
                        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                        &in_sensitive, &in_public, 
                        &outside_info, &creation_pcr, 
                        kh_private, kh_public, 
                        &creation_data, &creation_hash, &creation_ticket);
        check_rc(rc, "Creating keyedhash object failed");

        *kh_handle = ESYS_TR_NONE;
        rc = Esys_Load(
                        ctx, parent_handle,
                        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                        *kh_private, *kh_public, kh_handle);
        check_rc(rc, "Loading keyedhash object failed");

    } catch (tpm_exception& te) {
        printf("%s\n", te.what());

        if (policy_session != ESYS_TR_NONE) {
            Esys_FlushContext(ctx, policy_session);
        }

        return false;
    }

    return true;
}

bool show_key(
    ESYS_CONTEXT *ctx,
    const ESYS_TR kh_handle)
{
    // command parameters
    TPM2B_DATA          encryption_key_in = {};
    TPMT_SYM_DEF_OBJECT symmetric_alg     = {};

    // response parameters
    TPM2B_DATA             *encryption_key_out = nullptr;
    TPM2B_PRIVATE          *duplicate          = nullptr;
    TPM2B_ENCRYPTED_SECRET *out_sym_seed       = nullptr;

    // init command parameters
    symmetric_alg.algorithm = TPM2_ALG_NULL;

    ESYS_TR session_handle = ESYS_TR_NONE;
    TSS2_RC rc             = TSS2_RC_SUCCESS;
    try {
        
        if (!create_duplication_policy(ctx, &session_handle)) {
        return false;
        }

        rc = Esys_Duplicate(
                        ctx, 
                        kh_handle,      /* object handle */ 
                        ESYS_TR_NONE,   /* new parent handle */
                        session_handle, ESYS_TR_NONE, ESYS_TR_NONE, /* session handles */ 
                        &encryption_key_in, &symmetric_alg,
                        &encryption_key_out, &duplicate, &out_sym_seed);
        check_rc(rc, "Duplicating keyedhash object failed");

        rc = Esys_TR_Close(ctx, &session_handle);
        check_rc(rc, "Closing session failed");

    } catch (tpm_exception& te) {
        printf("%s\n", te.what());

        if (session_handle != ESYS_TR_NONE) {
            Esys_FlushContext(ctx, session_handle);
        }

        return false;
    }

    /*
        Print hash key.
        NOTE: when parsing a TPM2B_PRIVATE, remember that 
        TPM-generated data is in big endian format. 
    */
    uint8_t *phk = (uint8_t*) duplicate;
    phk += 76; // jump to hash key
    
    printf("Hash key:\n\n");
    qrencode_wrap(phk, 20);
    printf("\n\n");
    
    for (int i = 0; i < 20; i++)
        printf("%02x", phk[i]);
    printf("\n");

    return true;
}

bool create_duplication_policy(
    ESYS_CONTEXT *ctx,
    ESYS_TR      *session_handle)
{   
    *session_handle = ESYS_TR_NONE;

    TPM2B_NONCE  nonce_caller = {};
    TPMT_SYM_DEF symmetric    = {};

    nonce_caller.size   = 16; // should be at least 16 octets
    symmetric.algorithm = TPM2_ALG_NULL;
    TSS2_RC rc = TPM2_RC_SUCCESS;

    try {

        rc = Esys_StartAuthSession(
                        ctx, /* esys context */
                        ESYS_TR_NONE, /* tpmKey */ 
                        ESYS_TR_NONE, /* bound object */ 
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, /* session handles */
                        &nonce_caller,
                        TPM2_SE_POLICY, /* session type */
                        &symmetric, /* algo and size for param encryption*/ 
                        TPM2_ALG_SHA256,
                        session_handle);
        check_rc(rc, "Starting trial session failed");

        rc = Esys_PolicyPassword(
                        ctx, *session_handle,
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE);
        check_rc(rc, "Adding password policy failed");
    
        rc = Esys_PolicyCommandCode(
                        ctx, *session_handle,
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                        TPM2_CC_Duplicate);
        check_rc(rc, "Adding command policy failed");

    } catch (tpm_exception& te) {
        printf("%s\n", te.what());

        if (*session_handle != ESYS_TR_NONE) {
            Esys_FlushContext(ctx, *session_handle);
        }

        return false;
    }

    // response parameters
    
    if (rc != TPM2_RC_SUCCESS) {
        printf(" (error: %d)\n", rc);
        return false;
    }

    return true;
}
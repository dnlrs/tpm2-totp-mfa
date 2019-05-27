#include "policy.h"
#include "utils.h"

#include <cstdio>
#include <cstring>

bool create_policy(
    ESYS_CONTEXT *ctx,
    ESYS_TR       nv_handle,
    const char   *nv_psw,
    int           nv_psw_size,
    TPM2B_DIGEST *sk_policy)
{   
    TPM2B_NONCE  nonce_caller   = {};
    TPMT_SYM_DEF symmetric      = {};

    nonce_caller.size   = 16; // must be at least 16 octets
    symmetric.algorithm = TPM2_ALG_NULL;

    TSS2_RC       rc             = TSS2_RC_SUCCESS;
    ESYS_TR       session_handle = ESYS_TR_NONE;
    TPM2B_DIGEST *policy_digest  = nullptr;
    try {
        rc = Esys_StartAuthSession(
                        ctx,            /* esys context */
                        ESYS_TR_NONE,   /* tpmKey */ 
                        ESYS_TR_NONE,   /* bound object */ 
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, /* session handles */
                        &nonce_caller,
                        TPM2_SE_TRIAL,  /* session type */
                        &symmetric,     /* algo and size for param encryption*/ 
                        TPM2_ALG_SHA256,
                        &session_handle);
        check_rc(rc, "Starting trial session failed");

        /*
            In order to satisfy the policy the caller must
            prove that it knows the authValue of the object 
            with this policy.
        */
        rc = Esys_PolicyPassword(
                    ctx, session_handle, 
                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE);
        check_rc(rc, "Adding policyPassword failed");

        /* 
            In order to satisfy the policy the caller must
            prove that it knows the authValue of another
            object (of a NV index in this case).
            Note: during policy evaluation the caller must
            prove knowledge of the authValue associated with 
            the other object. 
        */
        TPM2B_NONCE  nonce_tpm  = {};
        TPM2B_DIGEST cp_hash_a  = {};
        TPM2B_NONCE  policy_ref = {};
        INT32        expiration = 0;

        TPM2B_TIMEOUT *timeout       = nullptr;
        TPMT_TK_AUTH  *policy_ticket = nullptr;
        
        TPM2B_AUTH auth_value = {};
        auth_value.size = nv_psw_size;
        memcpy(&auth_value.buffer[0], nv_psw, auth_value.size);

        rc = Esys_TR_SetAuth(ctx, nv_handle, &auth_value);
        check_rc(rc, "Setting psw for psw session failed");

        rc = Esys_PolicySecret(
                        ctx,            /* esys context */
                        nv_handle,      /* entity providing authZ */
                        session_handle, 
                        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, /* session handles */
                        &nonce_tpm,     /* policy non ce for the session */
                        &cp_hash_a,     /* digest of cp to which this authZ is limited */
                        &policy_ref,    /* reference to a policy relating to authZ */
                        expiration,     /* time when the authZ will expire */
                        &timeout, 
                        &policy_ticket);
        check_rc(rc, "Adding policy secret failed");

        /* Wipe out the authValue from memory. */
        rc = Esys_TR_SetAuth(ctx, nv_handle, nullptr);
        check_rc(rc, "Clearing password from memory failed");

        /* Get the policy digest and close the session. */
        rc = Esys_PolicyGetDigest(
                            ctx, session_handle, 
                            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, 
                            &policy_digest);
        check_rc(rc, "Getting policy digest failed");

        rc = Esys_FlushContext(ctx, session_handle);
        check_rc(rc, "Closing session failed");

    } catch (tpm_exception &te) {
        printf("%s\n", te.what());

        Esys_TR_SetAuth(ctx, nv_handle, nullptr);
        if (session_handle != ESYS_TR_NONE) {
            Esys_FlushContext(ctx, session_handle);
        }

        return false;
    }

    // save the policy digest
    sk_policy->size = policy_digest->size;
    memcpy(&sk_policy->buffer[0], &policy_digest->buffer[0], sk_policy->size);
    
    return true;
}

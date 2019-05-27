#include "policy.h"


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

    ESYS_TR      session_handle = ESYS_TR_NONE;

    nonce_caller.size   = 16; // must be at least 16 octets
    symmetric.algorithm = TPM2_ALG_NULL;

    TSS2_RC rval = Esys_StartAuthSession(
                        ctx,            /* esys context */
                        ESYS_TR_NONE,   /* tpmKey */ 
                        ESYS_TR_NONE,   /* bound object */ 
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, /* session handles */
                        &nonce_caller,
                        TPM2_SE_TRIAL,  /* session type */
                        &symmetric,     /* algo and size for param encryption*/ 
                        TPM2_ALG_SHA256,
                        &session_handle);
    if (rval != TPM2_RC_SUCCESS) {
        printf("create_policy: starting trial session failed (error: %d)\n", rval);
        return false;
    }

    /*
        In order to satisfy the policy the caller must
        prove that it knows the authValue of the object 
        with this policy.
    */
    rval = Esys_PolicyPassword(
                ctx, session_handle, 
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE);
    if (rval != TPM2_RC_SUCCESS) {
        printf("create_policy: adding policyPassword failed (error: %d)\n", rval);
        return false;
    }

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

    rval = Esys_TR_SetAuth(ctx, nv_handle, &auth_value);
    if (rval != TPM2_RC_SUCCESS) {
        printf("create_policy: setting psw for psw session failed (error: %d)\n", rval);
        return false;
    }

    rval = Esys_PolicySecret(
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
    if (rval != TPM2_RC_SUCCESS) {
        printf("create_policy: adding policy secret failed (error: %d)\n", rval);
        return false;
    }

    /* Wipe out the authValue from memory. */
    rval = Esys_TR_SetAuth(ctx, nv_handle, nullptr);
    if (rval != TPM2_RC_SUCCESS) {
        printf("create_policy: crearing paswword from memory failed (error: %d)\n", rval);
        return false;
    }

    /* Get and save the policy digest and close the session. */
    TPM2B_DIGEST *policy_digest = nullptr;

    rval = Esys_PolicyGetDigest(
                        ctx, session_handle, 
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, 
                        &policy_digest);
    if (rval != TPM2_RC_SUCCESS) {
        printf("create_policy: getting policy digest failed (error: %d)\n", rval);
        return false;
    }

    sk_policy->size = policy_digest->size;
    memcpy(&sk_policy->buffer[0], &policy_digest->buffer[0], sk_policy->size);

    rval = Esys_FlushContext(ctx, session_handle);
    if (rval != TPM2_RC_SUCCESS) {
        printf("create_policy: closing session failed (error: %d)\n", rval);
        return false;
    }

    return true;
}

#include "nv_index.h"

#include "tpm_exception.h"
#include "totp.h"
#include "utils.h"

#include <cstdio>
#include <cstring>

bool create_nv_space(
    ESYS_CONTEXT *ctx,
    ESYS_TR      *nv_handle,
    ESYS_TR      *kh_handle)
{   
    ESYS_TR policy_session = ESYS_TR_NONE;
    if (!nv_create_admin_policy(ctx, &policy_session)) {
        return false;
    }

    TSS2_RC rc = TPM2_RC_SUCCESS;
    TPM2B_DIGEST *policy_digest = nullptr;
    try {

        rc = Esys_PolicyGetDigest(
                        ctx, policy_session, 
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, 
                        &policy_digest);
        check_rc(rc, "Getting policy digest failed");

        rc = Esys_FlushContext(ctx, policy_session);
        check_rc(rc, "Flushing session context failed");
        policy_session = ESYS_TR_NONE;

        // command parameters
        TPM2B_AUTH      auth_value  = {};
        TPM2B_NV_PUBLIC public_info = {};

        time_t initial_time = 0;
        uint64_t first_otp  = 0;
        if (!calculate_topt(ctx, kh_handle, &initial_time, &first_otp, true))
            return false;

        auth_value.size = sizeof(first_otp);
        memcpy(&auth_value.buffer[0], (void*) &first_otp, auth_value.size);

        public_info.nvPublic.nvIndex    = 0x018094AB; // random handle from owner space
        public_info.nvPublic.nameAlg    = TPM2_ALG_SHA256;
        public_info.nvPublic.attributes = ( 
                        TPMA_NV_OWNERWRITE | TPMA_NV_AUTHWRITE |
                        TPMA_NV_AUTHREAD | TPMA_NV_WRITE_STCLEAR |
                        TPMA_NV_READ_STCLEAR | TPMA_NV_OWNERREAD);
        public_info.nvPublic.authPolicy = *policy_digest;
        public_info.nvPublic.dataSize   = 8;

        rc = Esys_NV_DefineSpace(
                        ctx,              /* esys context */ 
                        ESYS_TR_RH_OWNER, /* hierarchy */
                        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, /* session handles */ 
                        &auth_value,      /* authZ value */
                        &public_info,     /* public parameters of NV area */
                        nv_handle);             /* nv handle */
        check_rc(rc, "Defining NV space failed");

        free(policy_digest);

    } catch (tpm_exception& te) {
        printf("%s\n", te.what());
        
        if (policy_session != ESYS_TR_NONE) {
            Esys_FlushContext(ctx, policy_session);
        }

        free(policy_digest);
        return false;
    }

    return true;
}

bool delete_nv_space(
    ESYS_CONTEXT *ctx,
    ESYS_TR      *nv_handle)
{
    TSS2_RC rc = Esys_NV_UndefineSpace(
                        ctx, ESYS_TR_RH_OWNER, *nv_handle, 
                        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE);
    
    if (rc != TPM2_RC_SUCCESS) {
        printf("Undefining NV space failed (error: 0x%08x)", rc);
        return false;
    }

    return true;
}

bool nv_update_authValue(
    ESYS_CONTEXT *ctx,
    ESYS_TR      *nv_handle,
    ESYS_TR      *kh_handle,
    time_t       *last_updated)
{
    time_t   time_value = 0;
    uint64_t old_otp = 0;
    uint64_t new_otp = 0;

    TPM2B_AUTH old_auth = {};
    TPM2B_AUTH new_auth = {};

    /*
        Calculate current NV index authValue and the new one.
    */
    if (!calculate_topt(ctx, kh_handle, last_updated, &old_otp, true)) {
        return false;
    }
    old_auth.size = sizeof(old_otp);
    memcpy(&old_auth.buffer[0], (void*) &old_otp, old_auth.size);

    if (!calculate_topt(ctx, kh_handle, &time_value, &new_otp, false)) {
        return false;
    }
    new_auth.size = sizeof(new_otp);
    memcpy(&new_auth.buffer[0], (void*) &new_otp, new_auth.size);

    /*
        Change NV authValue with new calculated OTP.
    */
    ESYS_TR policy_session = ESYS_TR_NONE;
    TSS2_RC rc             = TSS2_RC_SUCCESS;
    try {

        if (!nv_create_admin_policy(ctx, &policy_session)) {
            return false;
        }
    
        rc = Esys_TR_SetAuth(ctx, *nv_handle, &old_auth);
        check_rc(rc, "Setting old authValue failed");

        rc = Esys_NV_ChangeAuth(
                        ctx, *nv_handle, 
                        policy_session, ESYS_TR_NONE, ESYS_TR_NONE, 
                        &new_auth);
        check_rc(rc, "Changing authValue failed")

        *last_updated = time_value;

        rc = Esys_TR_SetAuth(ctx, *nv_handle, nullptr);
        check_rc(rc, "Clearing auth from memory failed")

        rc = Esys_TR_Close(ctx, &policy_session);
        check_rc(rc, "Closing policy session failed")

    } catch (tpm_exception& te) {
        printf("%s\n", te.what());

        Esys_TR_SetAuth(ctx, *nv_handle, nullptr);
        if (policy_session != ESYS_TR_NONE) {
            Esys_FlushContext(ctx, policy_session);
        }

        return false;
    }

    return true;
}

bool nv_create_admin_policy(
    ESYS_CONTEXT *ctx,
    ESYS_TR      *policy_session)
{
    *policy_session = ESYS_TR_NONE;

    TPM2B_NONCE  nonce_caller = {};
    TPMT_SYM_DEF symmetric    = {};

    nonce_caller.size   = 16; // minimum required
    symmetric.algorithm = TPM2_ALG_NULL;

    TSS2_RC rc = TSS2_RC_SUCCESS;

    try {
        rc = Esys_StartAuthSession(
                        ctx, ESYS_TR_NONE, ESYS_TR_NONE, 
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                        &nonce_caller, TPM2_SE_POLICY, &symmetric,
                        TPM2_ALG_SHA256, policy_session);
        check_rc(rc, "Starting auth session failed");

        rc = Esys_PolicyPassword(
                        ctx, *policy_session,
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE);
        check_rc(rc, "Adding policyPassword failed");

        rc = Esys_PolicyCommandCode(
                        ctx, *policy_session,
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                        TPM2_CC_NV_ChangeAuth);
        check_rc(rc, "Adding policyCommand failed");
    } 
    catch(tpm_exception& te) {
        printf("%s", te.what());

        if (*policy_session != ESYS_TR_NONE) {
            rc = Esys_FlushContext(ctx, *policy_session);
            if (rc != TPM2_RC_SUCCESS)
                printf("Flushing context failed (error 0x%08x)", rc);
            *policy_session = ESYS_TR_NONE;
        }

        return false;
    }

    return true;
}
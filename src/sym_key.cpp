#include "sym_key.h"


#include <cstdio>
#include <cstring>
#include <string>

TPM2B_MAX_BUFFER enc_message = {};

bool create_sym_key(
    ESYS_CONTEXT   *ctx,
    ESYS_TR         parent_handle, 
    TPM2B_DIGEST   *sk_policy,
    TPM2B_PRIVATE **sk_private, 
    TPM2B_PUBLIC  **sk_public,
    ESYS_TR        *sk_handle)
{
    // command parameters
    TPM2B_SENSITIVE_CREATE in_sensitive = {};
    TPM2B_PUBLIC           in_public    = {};
    TPM2B_DATA             outside_info = {};
    TPML_PCR_SELECTION     creation_pcr = {};


    // response parameters
    TPM2B_PRIVATE  *out_private = nullptr;
    TPM2B_PUBLIC   *out_public  = nullptr;
    TPM2B_CREATION_DATA *creation_data   = nullptr;
    TPM2B_DIGEST        *creation_hash   = nullptr;
    TPMT_TK_CREATION    *creation_ticket = nullptr;

    // set authValue
    TPM2B_AUTH userAuth = {};
    userAuth.size = sizeof(sk_password);
    memcpy(&userAuth.buffer[0], sk_password, userAuth.size);

    in_sensitive.size = sizeof(TPMS_SENSITIVE_CREATE);
    in_sensitive.sensitive.userAuth = userAuth;

    in_public.publicArea.type    = TPM2_ALG_SYMCIPHER;
    in_public.publicArea.nameAlg = TPM2_ALG_SHA256;
    in_public.publicArea.objectAttributes = (
                                   TPMA_OBJECT_DECRYPT |
                                   TPMA_OBJECT_SIGN_ENCRYPT |
                                   TPMA_OBJECT_FIXEDPARENT |
                                   TPMA_OBJECT_FIXEDTPM |
                                   TPMA_OBJECT_SENSITIVEDATAORIGIN);
    // set authPolicy
    in_public.publicArea.authPolicy = *sk_policy;
    in_public.publicArea.parameters.symDetail.sym.algorithm   = TPM2_ALG_AES;
    in_public.publicArea.parameters.symDetail.sym.keyBits.aes = 128;
    in_public.publicArea.parameters.symDetail.sym.mode.aes    = TPM2_ALG_CBC;

    TSS2_RC rval = Esys_Create(ctx, parent_handle, 
                               ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                               &in_sensitive, &in_public, 
                               &outside_info, &creation_pcr,
                               &out_private, &out_public, 
                               &creation_data, &creation_hash, 
                               &creation_ticket);
    if (rval != TPM2_RC_SUCCESS) {
        printf("create_sym_key: creating symmetric key failed  (error %d)\n", rval);
        return false;
    }

    ESYS_TR object_handle = 0;
    rval = Esys_Load(ctx, parent_handle, 
                     ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, 
                     out_private, out_public, &object_handle);
    if (rval != TPM2_RC_SUCCESS) {
        printf("create_sym_key: loading symmetric key failed (error %d)\n", rval);
        return false;
    }

    *sk_public  = out_public;
    *sk_private = out_private;
    *sk_handle  = object_handle;
    return true;
}


bool encryptdecrypt_message(
    ESYS_CONTEXT *ctx,
    ESYS_TR       nv_handle,
    const char   *nv_psw,
    int           nv_psw_size,
    ESYS_TR       sk_handle,
    bool          decrypt)
{
    TPM2B_NONCE  nonce_caller   = {};
    TPMT_SYM_DEF symmetric      = {};
    
    ESYS_TR      session_handle = ESYS_TR_NONE;

    nonce_caller.size   = 16;
    symmetric.algorithm = TPM2_ALG_NULL;

    TSS2_RC rval = Esys_StartAuthSession(
                        ctx, ESYS_TR_NONE, ESYS_TR_NONE, 
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, 
                        &nonce_caller, TPM2_SE_POLICY, 
                        &symmetric, TPM2_ALG_SHA256, &session_handle);
    if (rval != TPM2_RC_SUCCESS) {
        printf("en/de-crypt_message: start authsession failed.\n");
        return false;
    }

    rval = Esys_PolicyPassword(
                        ctx, session_handle, 
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE);
    if (rval != TPM2_RC_SUCCESS) {
        printf("en/de-crypt_message: policy password failed.\n");
        return false;
    }

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
        printf("en/de-crypt_message: setting NV authValue failed.\n");
        return false;
    }

    rval = Esys_PolicySecret(ctx, nv_handle, session_handle,
                             ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                             &nonce_tpm, &cp_hash_a, &policy_ref, expiration,
                             &timeout, &policy_ticket);
    if (rval != TPM2_RC_SUCCESS) {
        printf("en/de-crypt_message: policySecret failed.\n");
        return false;
    }

    auth_value.size = sizeof(sk_password);
    memcpy(&auth_value.buffer[0], sk_password, auth_value.size);

    rval = Esys_TR_SetAuth(ctx, sk_handle, &auth_value);
    if (rval != TPM2_RC_SUCCESS) {
        printf("en/de-crypt_message: setting sym key authValue failed.\n");
        return false;
    }

    TPM2B_IV         iv_in   = {};
    TPM2B_MAX_BUFFER in_data = {};
    TPMI_YES_NO      is_decrypt = (decrypt ? TPM2_YES : TPM2_NO);

    TPM2B_IV         *iv_out   = nullptr;
    TPM2B_MAX_BUFFER *out_data = nullptr;

    iv_in.size = TPM2_MAX_SYM_BLOCK_SIZE;

    in_data = enc_message;

    if (decrypt == false) {
        in_data.size = 16; 
        memcpy(&in_data.buffer[0], message, sizeof(message));
    }

    rval = Esys_EncryptDecrypt(ctx, sk_handle, 
                               session_handle, ESYS_TR_NONE, ESYS_TR_NONE, 
                               is_decrypt, TPM2_ALG_NULL, 
                               &iv_in, &in_data, 
                               &out_data, &iv_out);
    if (rval != TPM2_RC_SUCCESS) {
        if ((rval & TPM2_RC_POLICY_FAIL) == TPM2_RC_POLICY_FAIL)
            printf("en/de-crypt_message: authorization failed.\n");
        else {
            printf("en/de-crypt_message: encryptdecrypt failed.\n");
        }
        return false;
    }

    rval = Esys_TR_SetAuth(ctx, nv_handle, nullptr);
    if (rval != TPM2_RC_SUCCESS) {
        printf("en/de-crypt_message: clearing nv password from memory failed.\n");
        return false;
    }
    
    rval = Esys_TR_SetAuth(ctx, sk_handle, nullptr);
    if (rval != TPM2_RC_SUCCESS) {
        printf("en/de-crypt_message: clearing sym key password from memory failed.\n");
        return false;
    }

    if (decrypt) {
        std::string msg((char*) &out_data->buffer[0], out_data->size);
        printf("Authorization OK, message: %s\n", msg.c_str());       
    } else {
        enc_message = *out_data;
        printf("encrypted message: ");
        for (int i = 0; i < out_data->size; i++)
            printf("%02x", out_data->buffer[i]);
        printf("\n");       
    }

    rval = Esys_TR_Close(ctx, &session_handle);
    if (rval != TPM2_RC_SUCCESS) {
        printf("en/de-crypt_message: flushcontext failed.\n");
        return false;
    }

    return true;
}
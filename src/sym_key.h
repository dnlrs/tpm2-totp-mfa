#ifndef SYM_KEY_H_INCLUDED
#define SYM_KEY_H_INCLUDED

#include "tss2/tss2_esys.h"

constexpr char sk_password[16] = "symkey-password";
constexpr char message[] = "OTP Correct!";
extern TPM2B_MAX_BUFFER enc_message;

bool create_sym_key(
    ESYS_CONTEXT   *ctx,
    ESYS_TR         parent_handle, 
    TPM2B_DIGEST   *sk_policy,
    TPM2B_PRIVATE **sk_private, 
    TPM2B_PUBLIC  **sk_public,
    ESYS_TR        *sk_handle);

bool encryptdecrypt_message(
    ESYS_CONTEXT *ctx,
    ESYS_TR       nv_handle,
    const char   *nv_psw,
    int           nv_psw_size,
    ESYS_TR       sk_handle,
    bool          decrypt = true);

#endif // SYM_KEY_H_INCLUDED
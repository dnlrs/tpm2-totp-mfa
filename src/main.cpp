#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <ctime>

#include "tss2/tss2_esys.h"

#include "tpm.h"
#include "hash_key.h"
#include "nv_index.h"
#include "policy.h"
#include "primary_key.h"
#include "sym_key.h"
#include "totp.h"

/*
    Steps:
      1. Initialize tpm connection
      2. Create primary key
      3. Create keyedhash key (and show it once for sync with app)
      4. Create NV Ram with initial dummy password
      5. Create symkey policy (password + NVRam password)
      6. Create symkey with policy
      7. encrypt secret message with symkey
      8. loop: when user asks, change nv password and try to decrypt data
*/
int main(int argc, char **argv)
{
    // initialize tpm connection
    tpm tpm_handle;

    // primary key
    ESYS_TR       pk_handle  = ESYS_TR_NONE;
    TPMS_CONTEXT *pk_context = nullptr;

    // hash key
    ESYS_TR        kh_handle  = ESYS_TR_NONE;
    TPM2B_PRIVATE *kh_private = nullptr;
    TPM2B_PUBLIC  *kh_public  = nullptr;

    // NV index
    ESYS_TR nv_handle = ESYS_TR_NONE;

    // symmetric key
    ESYS_TR        sk_handle  = ESYS_TR_NONE;
    TPM2B_DIGEST   sk_policy  = {};
    TPM2B_PRIVATE *sk_private = nullptr;
    TPM2B_PUBLIC  *sk_public  = nullptr;

    // topt related
    time_t   last_time = 0;
    uint64_t first_otp = 0;

    printf("Creating primary key...\n");
    bool rval = create_primary(
                    tpm_handle.get_context(), 
                    &pk_handle, &pk_context);
    if (!rval)
        goto finish;
    
    printf("Creating keyedhash object (hmac key)...\n");
    rval = create_keyedhash(
                tpm_handle.get_context(), pk_handle, 
                &kh_private, &kh_public, &kh_handle);
    if (!rval)
        goto finish;

    rval = show_key(tpm_handle.get_context(), kh_handle);
    if (!rval)
        goto finish;

    printf("Creating NV space...\n");
    rval = create_nv_space(
                tpm_handle.get_context(), 
                &nv_handle, &kh_handle);
    if (!rval)
        goto finish;


    rval = calculate_topt(
                tpm_handle.get_context(), 
                &kh_handle, &last_time, 
                &first_otp, true);
    if (!rval)
        goto finish;

    printf("Creating symmetric key policy...\n");
    rval = create_policy(
                tpm_handle.get_context(), 
                nv_handle, 
                (char*)&first_otp, sizeof(first_otp),
                &sk_policy);
     if (!rval)
        goto finish;

    printf("Creating symmetric key...\n");
    rval = create_sym_key(
                tpm_handle.get_context(), 
                pk_handle, &sk_policy, 
                &sk_private, &sk_public, &sk_handle);
    if (!rval)
        goto finish;

    printf("Encrypting secret message...\n");
    rval = encryptdecrypt_message(
                tpm_handle.get_context(), nv_handle, 
                (char*)&first_otp, sizeof(first_otp),
                sk_handle, false);
    if (!rval)
        goto finish;

    printf("Decrypting secret message...\n");
    rval = encryptdecrypt_message(
                tpm_handle.get_context(), nv_handle, 
                (char*)&first_otp, sizeof(first_otp),
                sk_handle, true);
    if (!rval)
        goto finish;

    while (true) {
        uint64_t user_otp = 0;
        printf("Insert OTP (0 to stop): ");
        scanf("%" SCNu64, &user_otp);
        if (user_otp == 0)
            break;

        time_t   now      = 0;
        uint64_t real_otp = 0;
        rval = calculate_topt(
                    tpm_handle.get_context(), &kh_handle, 
                    &now, &real_otp, false);

        printf("user OTP: %" PRIu64 "\n", user_otp);
        printf("real OTP: %" PRIu64 "\n", real_otp);

        rval = nv_update_authValue(
                    tpm_handle.get_context(), 
                    &nv_handle, &kh_handle, 
                    &last_time);
        if (!rval)
            goto finish;
        
        rval = encryptdecrypt_message(
                    tpm_handle.get_context(),
                    nv_handle, (char*) 
                    &user_otp, (int) sizeof(user_otp), 
                    sk_handle, true);
        if (!rval) {
            printf("Authorization failed.\n");
        }
    }


finish:
    if (pk_handle != ESYS_TR_NONE) {
        printf("Flushing primary key...\n");
        rval = Esys_FlushContext(tpm_handle.get_context(), pk_handle);
        if (rval != TPM2_RC_SUCCESS) {
            printf("Failed to flush primary key.\n");
        }
    }

    if (kh_handle != ESYS_TR_NONE) {
        printf("Flushing keyedhash object...\n");
        rval = Esys_FlushContext(tpm_handle.get_context(), kh_handle);
        if (rval != TPM2_RC_SUCCESS) {
            printf("Failed to flush hash key.\n");
        }
    }

    if (nv_handle != ESYS_TR_NONE) {
        printf("Deleting NV space...\n");
        rval = delete_nv_space(tpm_handle.get_context(), &nv_handle);
    }

    if (sk_handle != ESYS_TR_NONE) {
        printf("Flushing symmetric key...\n");
        rval = Esys_FlushContext(tpm_handle.get_context(), sk_handle);
        if (rval != TPM2_RC_SUCCESS) {
            printf("Failed to symmetric key.\n");
        }
    }

    return 0;
}
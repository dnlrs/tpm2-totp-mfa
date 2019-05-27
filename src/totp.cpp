#include "totp.h"


bool  calculate_topt(
    ESYS_CONTEXT *ctx,
    ESYS_TR      *kh_handle,
    time_t       *time_value,
    uint64_t     *otp,
    bool          use_time_value)
{
    TPM2B_MAX_BUFFER  buffer  = {0, {0}};
    TPM2B_DIGEST     *out_hmac = nullptr;

    /* Construct the RFC 6238 input */
    time_t now = ( use_time_value ? *time_value : time(NULL));
    time_t tmp = now / TIMESTEPSIZE;
    tmp = htobe64(tmp);
    buffer.size = sizeof(tmp);
    memcpy(&buffer.buffer[0], (void*) &tmp, buffer.size);

    TSS2_RC rval = Esys_HMAC(
                        ctx, *kh_handle, 
                        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                        &buffer, TPM2_ALG_SHA1, &out_hmac);
    if (rval != TPM2_RC_SUCCESS) {
        printf("HMAC calculation failed (error: %d)\n", rval);
        return false;
    }

    /* Perform the RFC 6238 -> RFC 4226 HOTP truncing */
    int offset = out_hmac->buffer[out_hmac->size - 1] & 0x0f;

    *otp = ((uint32_t)out_hmac->buffer[offset]   & 0x7f) << 24
         | ((uint32_t)out_hmac->buffer[offset+1] & 0xff) << 16
         | ((uint32_t)out_hmac->buffer[offset+2] & 0xff) <<  8
         | ((uint32_t)out_hmac->buffer[offset+3] & 0xff);
    *otp %= (1000000);

    if (!use_time_value)
        *time_value = now;
    
    return true;
}
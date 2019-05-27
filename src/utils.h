#ifndef UTILS_H_INCLUDED
#define UTILS_H_INCLUDED

#include "tpm_exception.h"

#include "tss2/tss2_esys.h"

/* If (rc != TPM2_RC_SUCCESS) throws tpm_exception */
#define check_rc(r, s) \
            if ((r) != TPM2_RC_SUCCESS) { \
                throw tpm_exception((s), (r)); \
            }

#define URL_PREFIX "otpauth://totp/TPM2-TOTP?secret="

static char *
base32enc(const uint8_t *in, size_t in_size);

bool 
qrencode_wrap(uint8_t* secret, int secret_size);

char *
qrencode(const char *url);

void print2b_digest(TPM2B_DIGEST *data);

#endif
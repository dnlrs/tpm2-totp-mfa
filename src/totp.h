#ifndef TOTP_H_INCLUDED
#define TOTP_H_INCLUDED

#include <cstdio>
#include <cstring>
#include <ctime>

#include "endian.h"

#include "tss2/tss2_esys.h"

/* RFC 6238 TOTP defines */
#define TIMESTEPSIZE 30
#define SECRETLEN    20

bool calculate_topt(
    ESYS_CONTEXT *ctx,
    ESYS_TR      *kh_handle,
    time_t       *time_value,
    uint64_t     *otp,
    bool          use_time_value = false);

#endif // TOTP_H_INCLUDED
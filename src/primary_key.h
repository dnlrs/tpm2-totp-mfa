#ifndef PRIMARY_KEY_H_INCLUDED
#define PRIMARY_KEY_H_INCLUDED

#include "tss2/tss2_esys.h"

bool create_primary(
    ESYS_CONTEXT  *ctx, 
    ESYS_TR       *pk_handle, 
    TPMS_CONTEXT **pk_context);

#endif // PRIMARY_KEY_H_INCLUDED
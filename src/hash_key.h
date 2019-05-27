#ifndef HASH_KEY_H_INCLUDED
#define HASH_KEY_H_INCLUDED

#include "tss2/tss2_esys.h"

bool create_keyedhash(    
    ESYS_CONTEXT   *ctx, 
    ESYS_TR         parent_handle, 
    TPM2B_PRIVATE **kh_private,
    TPM2B_PUBLIC  **kh_public,
    ESYS_TR        *kh_handle);

bool show_key(
    ESYS_CONTEXT  *ctx,
    const ESYS_TR  kh_handle);


bool create_duplication_policy(
    ESYS_CONTEXT *ctx,
    ESYS_TR      *dup_policy);

#endif // HASH_KEY_H_INCLUDED
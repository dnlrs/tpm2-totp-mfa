#ifndef NV_INDEX_H_INCLUDED
#define NV_INDEX_H_INCLUDED

#include <ctime>

#include "tss2/tss2_esys.h"

bool create_nv_space(
    ESYS_CONTEXT *ctx,
    ESYS_TR      *nv_handle,
    ESYS_TR      *kh_handle);

bool delete_nv_space(
    ESYS_CONTEXT *ctx,
    ESYS_TR      *nv_handle);

bool nv_update_authValue(
    ESYS_CONTEXT *ctx,
    ESYS_TR      *nv_handle,
    ESYS_TR      *kh_handle,
    time_t       *last_updated);

bool nv_create_admin_policy(
    ESYS_CONTEXT *ctx,
    ESYS_TR      *policy_session);

#endif // NV_INDEX_H_INCLUDED
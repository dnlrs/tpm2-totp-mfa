#ifndef POLICY_H_INCLUDED
#define POLICY_H_INCLUDED

#include "tss2/tss2_esys.h"


/* 
    Creates a policy composed by 2 factors:

    - knowledge of the object's password (authValue)
    - knowledge of the secret of a NV index

    Steps:
    1. start policy session (trial)
    2. add policy password
    3. add policy secret (nv index related)
      a. set passowrd into esys context
      b. actually add policy secret
      c. clear password from memory
    4. get policy digest
    5. save policy digest
    6. close session
*/
bool create_policy(
    ESYS_CONTEXT *ctx,
    ESYS_TR       nv_handle,
    const char   *nv_psw,
    int           nv_psw_size,
    TPM2B_DIGEST *sk_policy);


#endif // POLICY_H_INCLUDED
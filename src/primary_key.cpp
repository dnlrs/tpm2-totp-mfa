#include "primary_key.h"
#include "utils.h"

#include <cstdio>
#include <cstring>

bool create_primary(
    ESYS_CONTEXT  *ctx, 
    ESYS_TR       *pk_handle, 
    TPMS_CONTEXT **pk_context)
{
    // command parameters
    TPM2B_SENSITIVE_CREATE in_sensitive = {};
    TPM2B_PUBLIC           in_public    = {};
    TPM2B_DATA             outside_info = {};
    TPML_PCR_SELECTION     creation_pcr = {};
    
    // response parameters
    TPM2B_PUBLIC        *out_public      = nullptr;
    TPM2B_CREATION_DATA *creation_data   = nullptr;
    TPM2B_DIGEST        *creation_hash   = nullptr;
    TPMT_TK_CREATION    *creation_ticket = nullptr;

    // init command parameters
    in_public.publicArea.type             = TPM2_ALG_ECC;
    in_public.publicArea.nameAlg          = TPM2_ALG_SHA256;
    in_public.publicArea.objectAttributes = ( 
                        TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_RESTRICTED |
                        TPMA_OBJECT_DECRYPT | TPMA_OBJECT_NODA |
                        TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                        TPMA_OBJECT_SENSITIVEDATAORIGIN);
    in_public.publicArea.parameters.eccDetail.symmetric.algorithm   = TPM2_ALG_AES;
    in_public.publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128; 
    in_public.publicArea.parameters.eccDetail.symmetric.mode.aes    = TPM2_ALG_CBC;
    in_public.publicArea.parameters.eccDetail.scheme.scheme         = TPM2_ALG_NULL;
    in_public.publicArea.parameters.eccDetail.curveID               = TPM2_ECC_NIST_P256;
    in_public.publicArea.parameters.eccDetail.kdf.scheme            = TPM2_ALG_NULL;

    in_public.size = sizeof(TPMT_PUBLIC);

    TSS2_RC rc = TSS2_RC_SUCCESS;
    *pk_handle = ESYS_TR_NONE;
    try {
        rc = Esys_CreatePrimary(
                        ctx, ESYS_TR_RH_NULL, 
                        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                        &in_sensitive, &in_public,
                        &outside_info, &creation_pcr,
                        pk_handle, &out_public, 
                        &creation_data, &creation_hash, 
                        &creation_ticket);
        check_rc(rc, "Create primary failed");

        rc = Esys_ContextSave(ctx, *pk_handle, pk_context);
        check_rc(rc, "Saving primary context failed");

    } catch (tpm_exception &te) {
        printf("%s\n", te.what());
        
        if (*pk_handle != ESYS_TR_NONE) {
            Esys_FlushContext(ctx, *pk_handle);
            *pk_handle = ESYS_TR_NONE;
        }

        return false;
    }
    
    return true;    
}

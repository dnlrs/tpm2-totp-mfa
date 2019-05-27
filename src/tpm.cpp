#include "tpm.h"
#include "tpm_exception.h"

#include <cstring>
#include <inttypes.h>
#include <cstdlib>

#include "tss2/tss2_common.h"       // return/error codes, ABI version
#include "tss2/tss2_tpm2_types.h"   // ABI constants, types definition, constants
#include "tss2/tss2-tcti-tabrmd.h"


tpm::tpm()
{
    init_tcti_tabrmd_context();
    init_esys_context();
}

tpm::~tpm()
{
    finalize_esys_context();
    finalize_tcti_tabrmd_context();
}

void tpm::init_tcti_tabrmd_context()
{
    TSS2_RC rc;
    size_t context_size;

    /* This is the default cconfiguration (same as passing NULL) */
    // const char *conf = "host=localhost,port=2321";

    /*
     * Init TCTI context for use with simulator (through tabrmd):
     * - get minimum required size for mssim context
     * - allocate context structure
     * - initialize tcti context
     */
    rc = Tss2_Tcti_Tabrmd_Init(nullptr, &context_size, NULL);
    if (rc != TSS2_RC_SUCCESS)
        throw tpm_exception("Failed to get allocation size for mssim TCTI", rc);

    tcti_context = (TSS2_TCTI_CONTEXT *) calloc(1, context_size);
    if (!tcti_context)
        throw tpm_exception("Memory allocation for TCTI context failed", rc);
    
    rc = Tss2_Tcti_Tabrmd_Init(tcti_context, &context_size, NULL);
    if (rc != TSS2_RC_SUCCESS)
        throw tpm_exception("Failed to initialize mssim TCTI context", rc);
}

void tpm::finalize_tcti_tabrmd_context()
{
    Tss2_Tcti_Finalize(tcti_context); // free(tcti_context);
}

void tpm::init_esys_context()
{
    TSS2_RC rc;
    // size_t context_size;
    TSS2_ABI_VERSION abi_version = TSS2_ABI_VERSION_CURRENT;

    rc = Esys_Initialize(&esys_context, tcti_context, &abi_version);
    if (rc != TSS2_RC_SUCCESS)
        throw tpm_exception("Failed to initialize ESYS context", rc);
}

void tpm::finalize_esys_context()
{
    Esys_Finalize(&esys_context);
}
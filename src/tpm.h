#ifndef TPM_H_INCLUDED
#define TPM_H_INCLUDED

#include <cassert>
#include <cinttypes>

#include "tss2/tss2_tcti_mssim.h"
#include "tss2/tss2_esys.h"


class tpm {

public:
    tpm();
    ~tpm();

    ESYS_CONTEXT *get_context() { return esys_context; }

private:

    void init_tcti_tabrmd_context();
    void finalize_tcti_tabrmd_context();

    void init_esys_context();
    void finalize_esys_context();

private:
    // context
    TSS2_TCTI_CONTEXT *tcti_context = nullptr;
    ESYS_CONTEXT      *esys_context = nullptr;

};

#endif // !TPM_H_INCLUDED
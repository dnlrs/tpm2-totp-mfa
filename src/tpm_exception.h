#ifndef TPM_EXCEPTION_H_INCLUDED
#define TPM_EXCEPTION_H_INCLUDED

#include "tss2/tss2_esys.h"

#include <exception>
#include <string>

class tpm_exception : public std::exception {
public:
    
    tpm_exception(std::string msg, TSS2_RC code) 
    {
        char err_hex[21] = {};
        sprintf(err_hex, " (error: 0x%08x)", code);
        err_hex[20] - '\0';

        errmsg  = std::string(msg + err_hex);
        errcode = code;
    }

    const char *what() const throw() {
        return errmsg.c_str();
    }

private:
    std::string errmsg;
    TSS2_RC     errcode;
};

#endif // !TPM_EXCEPTION_H_INCLUDED
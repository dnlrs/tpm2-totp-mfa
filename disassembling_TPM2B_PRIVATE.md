
# TPM2B_PRIVATE

005e005c00080020000000000000000000000000000000000000000000000000000000000000000000209367b8ff3d0056f727655c8a8d8094383b2724d64141da4eee9c7503bbd8e9080014d9f3f6e3760b1fcb94c32e2638434dd377be0837
012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789

unpacks into:

TPM2B_PRIVATE {
    .size = 005e
    .buffer = TPM2B_SENSITIVE {
        .size = 005c
        .sensitiveArea = TPMT_SENSITIVE {
            .sensitiveType  = 0008 // tpm_alg_keyedhash
            .authValue      = TPM2B_AUTH = TPM2B_DIGEST {
                .size   = 0020
                .buffer = 0000000000000000000000000000000000000000000000000000000000000000
                }
            .seedValue = TPM2B_DIGEST {
                .size   = 0020
                .buffer = 9367b8ff3d0056f727655c8a8d8094383b2724d64141da4eee9c7503bbd8e908
                }
            .sensitive = TPMU_SENSITIVE_COMPOSITE = TPM2B_SENSITIVE_DATA {
                .size   = 0014
                .buffer = d9f3f6e3760b1fcb94c32e2638434dd377be0837
                }
            }
        }
    }
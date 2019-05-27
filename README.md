# TPM2.0 based TOPT authentication

*NOTE*: **this is not secure software**! It's a proof of concept and its main
purpose it to test tpm2.0 capabilities.

*NOTE2*: in order to test tpm2.0 duplication capabilities the HMAC key necessary
for OTP calculation is first generated in the tpm and then duplicated in
clear to allow importing it in OTP applications. However when duplicating the
resulting data blob is not automatically unmarshalled by the ESYS-api and it requires to manually extract the key (see [disassembling TPM2B_PRIVATE](disassembling_TPM2B_PRIVATE.md)). That is why this software **works only on the
MS tpm2.0 simulator**.  
In real applications the HMAC key would be first generated randomly and then
imported in the tpm.

This software uses policies to implement 2-factor authentication (a
*hardcoded* password and an OTP) in order to allow the user to decrypt a
secret message using a tpm-protected symmetric key.

## Build

```sh
cmake --build ./build --config Debug --target all -- -j$(nproc)
```

## Run

```sh
./build/tpm_policies
```

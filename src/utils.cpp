#include "utils.h"

#include "tss2/tss2_esys.h"

#include "qrencode.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

void 
print2b_digest(TPM2B_DIGEST *data)
{   
    int size = data->size;
    printf("size  : %04x", size);
    
    if (size > sizeof(TPMU_HA)) {
        printf(" ! INVALID SIZE");
        size = sizeof(TPMU_HA);
    }

    printf("\n");
    printf("buffer: ");
    for (int i = 0; i < size; i++)
        printf("%02x", data->buffer[i]);
    printf("\n");
}

static char *
base32enc(const uint8_t *in, size_t in_size) {
	static unsigned char base32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    size_t i = 0, j = 0;
    size_t out_size = ((in_size + 4) / 5) * 8;
    unsigned char *r = (unsigned char *) malloc(out_size + 1);

    while (1) {
        r[i++]  = in[j] >> 3 & 0x1F;
        r[i++]  = in[j] << 2 & 0x1F;
        if (++j >= in_size) break; else i--;
        r[i++] |= in[j] >> 6 & 0x1F;
        r[i++]  = in[j] >> 1 & 0x1F;
        r[i++]  = in[j] << 4 & 0x1F;
        if (++j >= in_size) break; else i--;
        r[i++] |= in[j] >> 4 & 0x1F;
        r[i++]  = in[j] << 1 & 0x1F;
        if (++j >= in_size) break; else i--;
        r[i++] |= in[j] >> 7 & 0x1F;
        r[i++]  = in[j] >> 2 & 0x1F;
        r[i++]  = in[j] << 3 & 0x1F;
        if (++j >= in_size) break; else i--;
        r[i++] |= in[j] >> 5 & 0x1F;
        r[i++]  = in[j] & 0x1F;
        if (++j >= in_size) break;
    }
    for (j = 0; j < i; j++) {
        r[j] = base32[r[j]];
    }
    while (i < out_size) {
        r[i++] = '=';
    }
    r[i] = 0;
	return (char *)r;
}


char *
qrencode(const char *url)
{
    QRcode *qrcode = QRcode_encodeString(url, 0/*=version*/, QR_ECLEVEL_L,
                                         QR_MODE_8, 1/*=case*/);
    if (!qrcode) { printf("QRcode failed.\n"); return NULL; }

    char *qrpic = (char *)malloc(/* Margins top / bot*/ 2 * (
                            (qrcode->width+2) * 2 - 2 +
                            strlen("\033[47m%*s\033[0m\n") ) +
                         /* lines */ qrcode->width * (
                            strlen("\033[47m  ") * (qrcode->width + 1) +
                            strlen("\033[47m  \033[0m\n")
                         ) + 1 /* \0 */);
    size_t idx = 0;
    idx += sprintf(&qrpic[idx], "\033[47m%*s\033[0m\n", 2*(qrcode->width+2), "");
    for (int y = 0; y < qrcode->width; y++) {
        idx += sprintf(&qrpic[idx], "\033[47m  ");
        for (int x = 0; x < qrcode->width; x++) {
            if (qrcode->data[y*qrcode->width + x] & 0x01) {
                idx += sprintf(&qrpic[idx], "\033[40m  ");
            } else {
                idx += sprintf(&qrpic[idx], "\033[47m  ");
            }
        }
        idx += sprintf(&qrpic[idx], "\033[47m  \033[0m\n");
    }
    idx += sprintf(&qrpic[idx], "\033[47m%*s\033[0m\n", 2*(qrcode->width+2), "");
    (void)(idx);
    free(qrcode);
    return qrpic;
}


bool 
qrencode_wrap(uint8_t* secret, int secret_size)
{
    char *base32key = base32enc(secret, secret_size);
    char *url = (char*) calloc(1, strlen(base32key) + strlen(URL_PREFIX) + 1);
    
    sprintf(url, URL_PREFIX "%s", base32key);
    free(base32key);


    char *qrpic = qrencode(url);
    if (!qrpic) {
        free(url);
        return false;
    }

    printf("%s\n", qrpic);
    printf("%s\n", url);
    free(qrpic);
    free(url);

    return true;
}
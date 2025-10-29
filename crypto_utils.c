#include "crypto_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>

// Convierte un uint64_t a un DES_cblock (8 bytes big-endian).
// Nota: ignoramos bits de paridad de DES; varias llaves distintas
// pueden producir la misma llave efectiva de DES. Eso se documenta en el reporte.
static void key_from_u64(uint64_t k, DES_cblock *out) {
    for (int i = 0; i < 8; ++i) {
        (*out)[7 - i] = (unsigned char)((k >> (i * 8)) & 0xFF);
    }
}

// Padding PKCS#7.
static unsigned char *pkcs7_pad(const unsigned char *in, size_t len, size_t block, size_t *out_len) {
    size_t pad = block - (len % block);
    if (pad == 0) pad = block;
    *out_len = len + pad;

    unsigned char *out = (unsigned char *)malloc(*out_len);
    if (!out) return NULL;

    memcpy(out, in, len);
    memset(out + len, (unsigned char)pad, pad);
    return out;
}

// Remueve PKCS#7. Devuelve NULL si padding inválido.
static unsigned char *pkcs7_unpad(unsigned char *buf, size_t *len) {
    if (*len == 0) return NULL;
    unsigned char pad = buf[*len - 1];
    if (pad == 0 || pad > 8) return NULL; // DES bloque = 8 bytes

    for (size_t i = 0; i < pad; ++i) {
        if (buf[*len - 1 - i] != pad) return NULL;
    }

    *len -= pad;
    return buf;
}

bool des_encrypt_ecb(const unsigned char *plain, size_t plen,
                     uint64_t key, unsigned char **out, size_t *out_len)
{
    *out = NULL;
    *out_len = 0;

    size_t padded_len = 0;
    unsigned char *padded = pkcs7_pad(plain, plen, 8, &padded_len);
    if (!padded) return false;

    DES_cblock kblock;
    key_from_u64(key, &kblock);

    DES_key_schedule sched;
    // DES_set_key_unchecked está deprecada en OpenSSL 3, pero funciona.
    DES_set_key_unchecked(&kblock, &sched);

    unsigned char *cipher = (unsigned char *)malloc(padded_len);
    if (!cipher) {
        free(padded);
        return false;
    }

    for (size_t i = 0; i < padded_len; i += 8) {
        DES_ecb_encrypt(
            (const_DES_cblock *)(padded + i),
            (DES_cblock *)(cipher + i),
            &sched,
            DES_ENCRYPT
        );
    }

    free(padded);
    *out = cipher;
    *out_len = padded_len;
    return true;
}

bool des_decrypt_ecb(const unsigned char *cipher, size_t clen,
                     uint64_t key, unsigned char **out, size_t *out_len)
{
    *out = NULL;
    *out_len = 0;

    if (clen == 0 || (clen % 8) != 0) return false;

    DES_cblock kblock;
    key_from_u64(key, &kblock);

    DES_key_schedule sched;
    DES_set_key_unchecked(&kblock, &sched);

    unsigned char *plain = (unsigned char *)malloc(clen);
    if (!plain) return false;

    for (size_t i = 0; i < clen; i += 8) {
        DES_ecb_encrypt(
            (const_DES_cblock *)(cipher + i),
            (DES_cblock *)(plain + i),
            &sched,
            DES_DECRYPT
        );
    }

    size_t plen = clen;
    if (!pkcs7_unpad(plain, &plen)) {
        free(plain);
        return false;
    }

    *out = plain;
    *out_len = plen;
    return true;
}

bool buffer_contains_substring(const unsigned char *buf, size_t len, const char *needle)
{
    size_t nlen = strlen(needle);
    if (nlen == 0 || len < nlen) return false;

    // Búsqueda ingenua O(n*m) es suficiente aquí.
    for (size_t i = 0; i + nlen <= len; ++i) {
        if (memcmp(buf + i, needle, nlen) == 0) {
            return true;
        }
    }
    return false;
}

bool load_file(const char *path, unsigned char **buf, size_t *len)
{
    *buf = NULL;
    *len = 0;

    FILE *f = fopen(path, "rb");
    if (!f) return false;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);

    if (sz <= 0) {
        fclose(f);
        return false;
    }

    unsigned char *tmp = (unsigned char *)malloc((size_t)sz);
    if (!tmp) {
        fclose(f);
        return false;
    }

    size_t r = fread(tmp, 1, (size_t)sz, f);
    fclose(f);

    if (r != (size_t)sz) {
        free(tmp);
        return false;
    }

    *buf = tmp;
    *len = (size_t)sz;
    return true;
}

bool save_file(const char *path, const unsigned char *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;

    size_t w = fwrite(buf, 1, len, f);
    fclose(f);

    return (w == len);
}
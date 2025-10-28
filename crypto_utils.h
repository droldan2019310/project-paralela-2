#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

// Carga archivo completo en memoria (binario). Devuelve buffer y tamaño.
bool load_file(const char *path, unsigned char **buf, size_t *len);
// Guarda buffer en archivo (binario).
bool save_file(const char *path, const unsigned char *buf, size_t len);

// Cifrado/Descifrado DES-ECB con padding PKCS#7 usando OpenSSL (libcrypto).
// La llave es un entero de 64 bits; se empaqueta en 8 bytes (paridad ignorada).
bool des_encrypt_ecb(const unsigned char *plain, size_t plen,
                     uint64_t key, unsigned char **out, size_t *out_len);

bool des_decrypt_ecb(const unsigned char *cipher, size_t clen,
                     uint64_t key, unsigned char **out, size_t *out_len);

// Busca substring (ASCII/UTF-8) dentro de un buffer arbitrario (que puede contener NULes por padding).
bool buffer_contains_substring(const unsigned char *buf, size_t len, const char *needle);

#endif // CRYPTO_UTILS_H
#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

// Carga archivo completo en memoria (binario). Devuelve buffer y tamaño.
// Devuelve true en éxito. El caller debe liberar *buf con free().
bool load_file(const char *path, unsigned char **buf, size_t *len);

// Guarda buffer como archivo binario. Devuelve true si escribió todo.
bool save_file(const char *path, const unsigned char *buf, size_t len);

// Cifrado DES-ECB con padding PKCS#7.
// key es un entero de 64 bits; lo empaquetamos en 8 bytes tipo DES_cblock.
// out se aloca dinámicamente, caller debe hacer free().
// Regresa true si ok.
bool des_encrypt_ecb(const unsigned char *plain, size_t plen,
                     uint64_t key, unsigned char **out, size_t *out_len);

// Descifrado DES-ECB con padding PKCS#7.
// out se aloca dinámicamente, caller debe hacer free().
// Regresa true si ok (padding válido, etc.).
bool des_decrypt_ecb(const unsigned char *cipher, size_t clen,
                     uint64_t key, unsigned char **out, size_t *out_len);

// Busca una subcadena ASCII/UTF-8 "needle" dentro del buffer binario buf.
// Permite detectar una "frase clave" dentro del plaintext descifrado.
bool buffer_contains_substring(const unsigned char *buf, size_t len, const char *needle);

#endif // CRYPTO_UTILS_H
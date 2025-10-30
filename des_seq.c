#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "crypto_utils.h"

static void usage(const char *prog) {
    fprintf(stderr,
        "Uso: %s <encrypt|decrypt|bruteforce> "
        "-i <in> [-o <out>] [-k <key>] [-kw <phrase>] [-s <start>] [-e <end>]\n",
        prog
    );
}

static bool parse_u64(const char *s, uint64_t *out) {
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (!s || *s == '\0' || (end && *end != '\0')) return false;
    *out = (uint64_t)v;
    return true;
}

// timestamp helper
static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

// Preview "humano": imprimimos solo caracteres ASCII imprimibles
// y cortamos cuando empieza padding raro. Máx first_n chars.
static void print_preview(const unsigned char *buf, size_t len, size_t first_n) {
    size_t n = (len < first_n ? len : first_n);
    printf("[preview plaintext]: \"");
    for (size_t i = 0; i < n; i++) {
        unsigned char c = buf[i];
        if (c >= 32 && c <= 126) {
            putchar(c);
        } else {
            // paramos para no mostrar padding PKCS#7 como puntos raros
            break;
        }
    }
    printf("\"");
    if (len > first_n) {
        printf("...");
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    const char *mode = argv[1];
    const char *in   = NULL;
    const char *out  = NULL;
    const char *kw   = NULL;

    uint64_t key   = 0;
    uint64_t start = 0;
    uint64_t end   = 0;

    bool have_key   = false;
    bool have_range = false;

    for (int i = 2; i < argc; ++i) {
        if (!strcmp(argv[i], "-i") && i+1 < argc) {
            in = argv[++i];
        } else if (!strcmp(argv[i], "-o") && i+1 < argc) {
            out = argv[++i];
        } else if (!strcmp(argv[i], "-k") && i+1 < argc) {
            have_key = parse_u64(argv[++i], &key);
        } else if (!strcmp(argv[i], "-kw") && i+1 < argc) {
            kw = argv[++i];
        } else if (!strcmp(argv[i], "-s") && i+1 < argc) {
            have_range = parse_u64(argv[++i], &start) || have_range;
        } else if (!strcmp(argv[i], "-e") && i+1 < argc) {
            uint64_t t;
            if (parse_u64(argv[++i], &t)) {
                end = t;
                have_range = true;
            }
        }
    }

    if (!in) {
        fprintf(stderr, "Falta -i\n");
        return 1;
    }

    // ------------------------------------------------------------------
    // encrypt
    // ------------------------------------------------------------------
    if (!strcmp(mode, "encrypt")) {
        if (!have_key) {
            fprintf(stderr, "Falta -k para encrypt\n");
            return 1;
        }

        unsigned char *plain = NULL;
        size_t plen = 0;
        if (!load_file(in, &plain, &plen)) {
            fprintf(stderr, "No pude leer %s\n", in);
            return 1;
        }

        unsigned char *cipher = NULL;
        size_t clen = 0;
        if (!des_encrypt_ecb(plain, plen, key, &cipher, &clen)) {
            fprintf(stderr, "Error cifrando\n");
            free(plain);
            return 1;
        }
        free(plain);

        if (!out) out = "cipher.bin";
        if (!save_file(out, cipher, clen)) {
            fprintf(stderr, "No pude guardar %s\n", out);
            free(cipher);
            return 1;
        }

        printf("[encrypt] Escribí %zu bytes en %s (key original=%llu)\n",
               clen, out, (unsigned long long)key);

        free(cipher);
        return 0;
    }

    // ------------------------------------------------------------------
    // decrypt
    // ------------------------------------------------------------------
    if (!strcmp(mode, "decrypt")) {
        if (!have_key) {
            fprintf(stderr, "Falta -k para decrypt\n");
            return 1;
        }

        unsigned char *cipher = NULL;
        size_t clen = 0;
        if (!load_file(in, &cipher, &clen)) {
            fprintf(stderr, "No pude leer %s\n", in);
            return 1;
        }

        unsigned char *plain = NULL;
        size_t plen = 0;
        if (!des_decrypt_ecb(cipher, clen, key, &plain, &plen)) {
            fprintf(stderr, "Error descifrando (key=%llu)\n",
                    (unsigned long long)key);
            free(cipher);
            return 2;
        }
        free(cipher);

        if (!out) out = "plain.txt";
        if (!save_file(out, plain, plen)) {
            fprintf(stderr, "No pude guardar %s\n", out);
            free(plain);
            return 1;
        }

        printf("[decrypt] Escribí %zu bytes en %s usando key=%llu\n",
               plen, out, (unsigned long long)key);
        print_preview(plain, plen, 80);
        return 0;
    }

    // ------------------------------------------------------------------
    // bruteforce
    // ------------------------------------------------------------------
    if (!strcmp(mode, "bruteforce")) {
        if (!kw) {
            fprintf(stderr, "Falta -kw <frase_clave> para bruteforce\n");
            return 1;
        }
        if (!have_range) {
            fprintf(stderr, "Falta rango -s/-e para bruteforce\n");
            return 1;
        }

        unsigned char *cipher = NULL;
        size_t clen = 0;
        if (!load_file(in, &cipher, &clen)) {
            fprintf(stderr, "No pude leer %s\n", in);
            return 1;
        }

        double t0 = now_sec();

        uint64_t found_key = 0;
        bool found = false;
        unsigned char *found_plain = NULL;
        size_t found_plen = 0;

        for (uint64_t k = start; k <= end; ++k) {
            unsigned char *plain = NULL;
            size_t plen = 0;

            if (des_decrypt_ecb(cipher, clen, k, &plain, &plen)) {
                if (buffer_contains_substring(plain, plen, kw)) {
                    found = true;
                    found_key = k;
                    found_plain = plain; // guardamos para preview
                    found_plen  = plen;
                    break;
                }
                free(plain);
            }

            if (k == UINT64_MAX) break; // safety overflow
        }

        double t1 = now_sec();
        double elapsed = t1 - t0;

        // calcular llaves probadas y throughput
        unsigned long long tested_keys =
            found ? (unsigned long long)(found_key - start + 1ULL)
                  : (unsigned long long)(end - start + 1ULL);

        double keys_per_sec = tested_keys / (elapsed > 0 ? elapsed : 1e-9);

        free(cipher);

        if (found) {
            printf("[bruteforce] ¡Llave encontrada!: %llu\n",
                   (unsigned long long)found_key);
            print_preview(found_plain, found_plen, 80);

            printf("[bruteforce] Nota: esta llave descifra el mensaje.\n");
            printf("[bruteforce] Puede no coincidir exactamente con la llave 'original' ");
            printf("por bits de paridad DES, pero es criptográficamente equivalente.\n");

            printf("[bruteforce] Llaves probadas ~ %llu\n", tested_keys);
            printf("[bruteforce] Velocidad aprox: %.2f llaves/seg\n", keys_per_sec);
            printf("[bruteforce] Tiempo total (secuencial): %.6f s\n", elapsed);

            free(found_plain);
            return 0;
        } else {
            printf("[bruteforce] Llave no encontrada en [%llu, %llu]\n",
                   (unsigned long long)start,
                   (unsigned long long)end);

            printf("[bruteforce] Llaves probadas ~ %llu\n", tested_keys);
            printf("[bruteforce] Velocidad aprox: %.2f llaves/seg\n", keys_per_sec);
            printf("[bruteforce] Tiempo total (secuencial): %.6f s\n", elapsed);

            return 3;
        }
    }

    usage(argv[0]);
    return 1;
}
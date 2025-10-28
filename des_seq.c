#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "crypto_utils.h"

static void usage(const char *prog) {
    fprintf(stderr,
    "Uso: %s <encrypt|decrypt|bruteforce> -i <in> [-o <out>] [-k <key>] [-kw <phrase>] [-s <start>] [-e <end>]\n",
    prog);
}

static bool parse_u64(const char *s, uint64_t *out) {
    char *end=NULL; unsigned long long v = strtoull(s, &end, 10);
    if (!s || *s=='\0' || (end && *end!='\0')) return false;
    *out = (uint64_t)v; return true;
}

int main(int argc, char **argv)
{
    if (argc < 3) { usage(argv[0]); return 1; }
    const char *mode = argv[1];
    const char *in = NULL, *out = NULL, *kw = NULL;
    uint64_t key = 0, start = 0, end = 0;
    bool have_key=false, have_range=false;

    for (int i=2; i<argc; ++i) {
        if (!strcmp(argv[i], "-i") && i+1<argc) in = argv[++i];
        else if (!strcmp(argv[i], "-o") && i+1<argc) out = argv[++i];
        else if (!strcmp(argv[i], "-k") && i+1<argc) { have_key = parse_u64(argv[++i], &key); }
        else if (!strcmp(argv[i], "-kw") && i+1<argc) kw = argv[++i];
        else if (!strcmp(argv[i], "-s") && i+1<argc) { have_range = parse_u64(argv[++i], &start) || have_range; }
        else if (!strcmp(argv[i], "-e") && i+1<argc) { uint64_t t; if(parse_u64(argv[++i], &t)){ end=t; have_range=true; } }
    }

    if (!in) { fprintf(stderr, "Falta -i\n"); return 1; }

    if (!strcmp(mode, "encrypt")) {
        if (!have_key) { fprintf(stderr, "Falta -k para encrypt\n"); return 1; }
        unsigned char *plain=NULL; size_t plen=0;
        if(!load_file(in, &plain, &plen)){ fprintf(stderr,"No pude leer %s\n", in); return 1; }
        unsigned char *cipher=NULL; size_t clen=0;
        if(!des_encrypt_ecb(plain, plen, key, &cipher, &clen)){
            fprintf(stderr, "Error cifrando\n"); free(plain); return 1; }
        free(plain);
        if (!out) out = "cipher.bin";
        if(!save_file(out, cipher, clen)){ fprintf(stderr, "No pude guardar %s\n", out); free(cipher); return 1; }
        printf("[encrypt] Escribí %zu bytes en %s\n", clen, out);
        free(cipher); return 0;
    }
    else if (!strcmp(mode, "decrypt")) {
        if (!have_key) { fprintf(stderr, "Falta -k para decrypt\n"); return 1; }
        unsigned char *cipher=NULL; size_t clen=0;
        if(!load_file(in, &cipher, &clen)){ fprintf(stderr,"No pude leer %s\n", in); return 1; }
        unsigned char *plain=NULL; size_t plen=0;
        if(!des_decrypt_ecb(cipher, clen, key, &plain, &plen)){
            fprintf(stderr, "Error descifrando (key=%llu)\n", (unsigned long long)key); free(cipher); return 2; }
        free(cipher);
        if (!out) out = "plain.txt";
        if(!save_file(out, plain, plen)){ fprintf(stderr, "No pude guardar %s\n", out); free(plain); return 1; }
        printf("[decrypt] Escribí %zu bytes en %s\n", plen, out);
        free(plain); return 0;
    }
    else if (!strcmp(mode, "bruteforce")) {
        if (!kw) { fprintf(stderr, "Falta -kw <frase_clave> para bruteforce\n"); return 1; }
        if (!have_range) { fprintf(stderr, "Falta rango -s/-e para bruteforce\n"); return 1; }
        unsigned char *cipher=NULL; size_t clen=0;
        if(!load_file(in, &cipher, &clen)){ fprintf(stderr,"No pude leer %s\n", in); return 1; }

        uint64_t found_key = 0; bool found = false;
        for (uint64_t k = start; k <= end; ++k) {
            unsigned char *plain=NULL; size_t plen=0;
            if (des_decrypt_ecb(cipher, clen, k, &plain, &plen)) {
                if (buffer_contains_substring(plain, plen, kw)) { found=true; found_key=k; free(plain); break; }
                free(plain);
            }
            if (k == UINT64_MAX) break; // evitar overflow
        }
        free(cipher);
        if (found) {
            printf("[bruteforce] ¡Llave encontrada!: %llu\n", (unsigned long long)found_key);
            return 0;
        } else {
            printf("[bruteforce] Llave no encontrada en el rango [%llu, %llu]\n",
                   (unsigned long long)start, (unsigned long long)end);
            return 3;
        }
    }

    usage(argv[0]);
    return 1;
}
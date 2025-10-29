#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <limits.h> // LONG_MAX
#include "crypto_utils.h"

static void usage(const char *p){
    if (!p) p = "des_mpi";
    fprintf(stderr,
        "Uso: %s -i <cipher.bin> -kw <frase> -s <start> -e <end>\n",
        p
    );
}

static bool parse_u64(const char *s, uint64_t *out){
    char *e = NULL;
    unsigned long long v = strtoull(s, &e, 10);
    if (!s || *s=='\0' || (e && *e!='\0')) return false;
    *out = (uint64_t)v;
    return true;
}

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

// Preview tipo humano, misma lógica que en des_seq.c
static void print_preview(const unsigned char *buf, size_t len, size_t first_n) {
    size_t n = (len < first_n ? len : first_n);
    printf("[preview plaintext]: \"");
    for (size_t i = 0; i < n; i++) {
        unsigned char c = buf[i];
        if (c >= 32 && c <= 126) {
            putchar(c);
        } else {
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
    MPI_Init(&argc, &argv);

    int rank = 0;
    int size = 1;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    const char* in = NULL;
    const char* kw = NULL;
    uint64_t s = 0, e = 0;
    int have_range = 0;

    // Parse args
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-i") && i+1 < argc) {
            in = argv[++i];
        } else if (!strcmp(argv[i], "-kw") && i+1 < argc) {
            kw = argv[++i];
        } else if (!strcmp(argv[i], "-s") && i+1 < argc) {
            parse_u64(argv[++i], &s);
            have_range = 1;
        } else if (!strcmp(argv[i], "-e") && i+1 < argc) {
            parse_u64(argv[++i], &e);
            have_range = 1;
        }
    }

    if (!in || !kw || !have_range) {
        if (rank == 0) usage(argv[0]);
        MPI_Finalize();
        return 1;
    }

    // Rank 0 lee el ciphertext
    unsigned char *cipher = NULL;
    size_t clen = 0;
    if (rank == 0) {
        if (!load_file(in, &cipher, &clen)) {
            fprintf(stderr, "[rank0] No pude leer %s\n", in);
            clen = 0;
        }
    }

    // Broadcast tamaño
    unsigned long long clen64 = (rank == 0) ? (unsigned long long)clen : 0ULL;
    MPI_Bcast(&clen64, 1, MPI_UNSIGNED_LONG_LONG, 0, MPI_COMM_WORLD);

    if (clen64 == 0ULL) {
        if (rank == 0)
            fprintf(stderr, "Cipher vacío; abortando.\n");
        if (cipher) free(cipher);
        MPI_Finalize();
        return 1;
    }
    size_t gclen = (size_t)clen64;

    // Broadcast bytes del cipher
    if (rank != 0) {
        cipher = (unsigned char*)malloc(gclen);
        if (!cipher) {
            fprintf(stderr, "[rank %d] malloc fallo\n", rank);
            MPI_Abort(MPI_COMM_WORLD, 2);
        }
    }
    MPI_Bcast(cipher, (int)gclen, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

    // Broadcast palabra clave
    int kwlen = (int)strlen(kw);
    MPI_Bcast(&kwlen, 1, MPI_INT, 0, MPI_COMM_WORLD);

    char *gkw = (char*)malloc((size_t)kwlen + 1);
    if (!gkw) {
        fprintf(stderr, "[rank %d] malloc fallo kw\n", rank);
        free(cipher);
        MPI_Abort(MPI_COMM_WORLD, 3);
    }
    if (rank == 0) {
        memcpy(gkw, kw, (size_t)kwlen);
    }
    MPI_Bcast(gkw, kwlen, MPI_CHAR, 0, MPI_COMM_WORLD);
    gkw[kwlen] = '\0';

    // Dividir [s, e] en bloques casi equitativos
    __uint128_t total = (__uint128_t)e - (__uint128_t)s + 1;
    uint64_t chunk = (uint64_t)(total / size);
    uint64_t rem   = (uint64_t)(total % size);

    uint64_t my_s = s
                  + (uint64_t)rank * chunk
                  + (uint64_t)(rank < (int)rem ? rank : (int)rem);
    uint64_t my_e = my_s + chunk - 1;
    if ((uint64_t)rank < rem) my_e++;
    if (my_e < my_s) my_e = my_s;

    uint64_t my_work = (my_e >= my_s) ? (my_e - my_s + 1ULL) : 0ULL;

    if (rank == 0) {
        printf("[MPI] size=%d, rango global=[%llu,%llu]\n",
               size,
               (unsigned long long)s,
               (unsigned long long)e);
    }
    printf("[rank %d] subrango=[%llu,%llu] trabajo_total_llaves=%llu\n",
           rank,
           (unsigned long long)my_s,
           (unsigned long long)my_e,
           (unsigned long long)my_work);

    // Sincronizar antes de cronometrar
    MPI_Barrier(MPI_COMM_WORLD);
    double t0 = now_sec();

    // Búsqueda local
    uint64_t found_key = 0;
    int found = 0;

    for (uint64_t k = my_s; k <= my_e; ++k) {
        unsigned char *plain = NULL;
        size_t plen = 0;

        if (des_decrypt_ecb(cipher, gclen, k, &plain, &plen)) {
            if (buffer_contains_substring(plain, plen, gkw)) {
                found = 1;
                found_key = k;
                free(plain);
                break;
            }
            free(plain);
        }

        if (k == UINT64_MAX) break; // safety overflow
    }

    double t1 = now_sec();
    double local_elapsed = t1 - t0;

    // Reducción global para obtener la menor llave válida
    struct {
        long val;
        int  rank;
    } local_min, global_min;

    long sentinel = LONG_MAX; // "no encontré nada"
    local_min.val  = found ? (long)found_key : sentinel;
    local_min.rank = rank;

    MPI_Allreduce(&local_min,
                  &global_min,
                  1,
                  MPI_LONG_INT,
                  MPI_MINLOC,
                  MPI_COMM_WORLD);

    // Tiempo total paralelo = máximo de los tiempos locales
    double global_time_max = 0.0;
    MPI_Allreduce(&local_elapsed,
                  &global_time_max,
                  1,
                  MPI_DOUBLE,
                  MPI_MAX,
                  MPI_COMM_WORLD);

    // ¿Alguien encontró?
    int someone_found = (global_min.val != sentinel);

    // Vamos a imprimir métricas globales sólo en rank 0
    if (rank == 0) {
        if (someone_found) {
            printf("[MPI] ¡Llave encontrada!: %ld (rank %d)\n",
                   global_min.val,
                   global_min.rank);

            // Intentar descifrar con la llave ganadora para mostrar preview
            unsigned char *plain_ok = NULL;
            size_t plen_ok = 0;
            if (des_decrypt_ecb(cipher, gclen,
                                (uint64_t)global_min.val,
                                &plain_ok,
                                &plen_ok)) {

                printf("[MPI] Esta llave descifra el mensaje.\n");
                print_preview(plain_ok, plen_ok, 80);

                printf("[MPI] Nota: esta llave puede no ser numéricamente igual ");
                printf("a la llave original usada para cifrar,\n");
                printf("      debido a bits de paridad en DES. ");
                printf("Pero es criptográficamente equivalente (descifra bien).\n");

                free(plain_ok);
            } else {
                printf("[MPI] (Advertencia: no pude descifrar con la llave ganadora, ");
                printf("esto no debería pasar normalmente)\n");
            }
        } else {
            printf("[MPI] Ninguna llave encontrada en el rango global.\n");
        }

        // Métricas de rendimiento paralelo:
        // Tiempo total paralelo:
        printf("[MPI] Tiempo total paralelo (max entre ranks): %.6f s\n", global_time_max);

        // Throughput paralelo aprox:
        unsigned long long total_keyspace =
            (unsigned long long)(e - s + 1ULL);

        double keys_per_sec_parallel =
            total_keyspace / (global_time_max > 0 ? global_time_max : 1e-9);

        printf("[MPI] Llaves totales en el rango: %llu\n", total_keyspace);
        printf("[MPI] Velocidad paralela aprox: %.2f llaves/seg (global)\n",
               keys_per_sec_parallel);

        printf("[MPI] => Usa este tiempo como T_par(%d). Compara con T_seq del modo secuencial para sacar speedup.\n", size);
        printf("[MPI] Resultado: podemos recuperar el texto cifrado sin conocer la llave original.\n");
    }

    free(cipher);
    free(gkw);

    MPI_Finalize();
    return someone_found ? 0 : 3;
}
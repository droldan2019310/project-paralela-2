// des_mpi.c — versión MPI (Open MPI) para bruteforce DES con palabra clave
#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "crypto_utils.h"

#define TAG_FOUND  42
#define TAG_STOP   43

static void usage(const char *p){
    if (p==NULL) p="des_mpi";
    fprintf(stderr, "Uso: %s -i <cipher.bin> -kw <frase> -s <start> -e <end>\n", p);
}

static bool parse_u64(const char *s, uint64_t *out){
    char *e=NULL;
    unsigned long long v = strtoull(s, &e, 10);
    if (!s || *s=='\0' || (e && *e!='\0')) return false;
    *out = (uint64_t)v;
    return true;
}

int main(int argc, char **argv)
{
    MPI_Init(&argc, &argv);
    int rank, size;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    const char* in=NULL;
    const char* kw=NULL;
    uint64_t s=0, e=0;
    int have_range=0;

    for (int i=1;i<argc;i++){
        if (!strcmp(argv[i], "-i")  && i+1<argc) in=argv[++i];
        else if (!strcmp(argv[i], "-kw") && i+1<argc) kw=argv[++i];
        else if (!strcmp(argv[i], "-s")  && i+1<argc) { parse_u64(argv[++i], &s); have_range=1; }
        else if (!strcmp(argv[i], "-e")  && i+1<argc) { parse_u64(argv[++i], &e); have_range=1; }
    }
    if (!in || !kw || !have_range) { if(rank==0) usage(argv[0]); MPI_Finalize(); return 1; }

    // Rank 0 carga el archivo cifrado
    unsigned char *cipher = NULL;
    size_t clen = 0;
    if (rank==0){
        if(!load_file(in, &cipher, &clen)){
            fprintf(stderr, "[rank0] No pude leer %s\n", in);
            clen = 0; // señalar fallo
        }
    }

    // Difundir tamaño usando tipo estable (ULL) y luego castear a size_t
    unsigned long long gclen64 = (rank==0) ? (unsigned long long)clen : 0ULL;
    MPI_Bcast(&gclen64, 1, MPI_UNSIGNED_LONG_LONG, 0, MPI_COMM_WORLD);
    if (gclen64 == 0ULL){
        if (rank==0) fprintf(stderr, "Cipher vacio; abortando.\n");
        if (cipher) free(cipher);
        MPI_Finalize();
        return 1;
    }
    size_t gclen = (size_t)gclen64;

    // Asegurar buffer y difundir bytes
    if (rank!=0) cipher = (unsigned char*)malloc(gclen);
    MPI_Bcast(cipher, (int)gclen, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

    // Broadcast de la palabra clave (longitud + bytes + terminador)
    int kwlen = (int)strlen(kw);
    MPI_Bcast(&kwlen, 1, MPI_INT, 0, MPI_COMM_WORLD);
    char *gkw = (char*)malloc((size_t)kwlen + 1);
    if (rank==0) memcpy(gkw, kw, (size_t)kwlen);
    MPI_Bcast(gkw, kwlen, MPI_CHAR, 0, MPI_COMM_WORLD);
    gkw[kwlen] = '\0';

    // División del rango [s, e] en bloques casi equitativos
    __uint128_t total = (__uint128_t)e - (__uint128_t)s + 1; // evitar overflow
    uint64_t chunk = (uint64_t)(total / size);
    uint64_t rem   = (uint64_t)(total % size);

    uint64_t my_s = s + (uint64_t)rank * chunk
                  + (uint64_t)(rank < (int)rem ? rank : (int)rem);
    uint64_t my_e = my_s + chunk - 1;
    if ((uint64_t)rank < rem) my_e++;
    if (my_e < my_s) my_e = my_s;

    if (rank==0) {
        printf("[MPI] size=%d, rango global=[%llu,%llu]\n",
               size, (unsigned long long)s, (unsigned long long)e);
    }
    printf("[rank %d] subrango=[%llu,%llu]\n",
           rank, (unsigned long long)my_s, (unsigned long long)my_e);

    // Bucle de búsqueda con parada cooperativa
    MPI_Status st;
    int flag = 0;
    uint64_t found_key = 0;
    int found = 0;

    for (uint64_t k = my_s; k <= my_e; ++k) {
        // ¿Llegó señal de STOP? (consume el mensaje si existe)
        MPI_Iprobe(MPI_ANY_SOURCE, TAG_STOP, MPI_COMM_WORLD, &flag, &st);
        if (flag){
            unsigned long long tmp;
            MPI_Recv(&tmp, 1, MPI_UNSIGNED_LONG_LONG, st.MPI_SOURCE, TAG_STOP, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
            break;
        }

        unsigned char *plain=NULL; size_t plen=0;
        if (des_decrypt_ecb(cipher, gclen, k, &plain, &plen)) {
            if (buffer_contains_substring(plain, plen, gkw)) {
                found = 1; found_key = k; free(plain);
                // Notificar a todos: llave encontrada
                for (int dst=0; dst<size; ++dst)
                    if (dst!=rank)
                        MPI_Send(&found_key, 1, MPI_UNSIGNED_LONG_LONG, dst, TAG_STOP, MPI_COMM_WORLD);
                break;
            }
            free(plain);
        }
        if (k == UINT64_MAX) break; // safety contra overflow
    }

    // Reducción tipo MINLOC estándar: (long,int) con MPI_LONG_INT
    // Sentinel: ~0UL como "no encontrado"
    struct { long val; int rank; } local_min =
        { (long)(found ? (long)found_key : (long)~0UL), rank },
      global_min;

    MPI_Allreduce(&local_min, &global_min, 1, MPI_LONG_INT, MPI_MINLOC, MPI_COMM_WORLD);

    int someone_found = (global_min.val != (long)~0UL);
    if (rank==0){
        if (someone_found)
            printf("[MPI] ¡Llave encontrada!: %ld (rank %d)\n", global_min.val, global_min.rank);
        else
            printf("[MPI] Ninguna llave encontrada en el rango global.\n");
    }

    free(cipher);
    free(gkw);
    MPI_Finalize();
    return someone_found ? 0 : 3;
}

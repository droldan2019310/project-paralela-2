# Proyecto 2 – DES Bruteforce (Secuencial y MPI)


## Requisitos
- C / C++ (C estándar).
- Open MPI (mpicc/mpirun instalados).
- OpenSSL (libcrypto) para DES: `brew install openssl@3` en macOS.


## Compilación
# Usa pkg-config si está disponible; el Makefile intenta resolver rutas comunes.
make clean && make all


## Archivos de entrada/salida
- Texto plano: archivo `.txt` (UTF-8).
- Cifrado: archivo binario `.bin` producido por `encrypt`.


## Ejemplos de uso


### 1) Cifrar un texto de archivo con una llave dada (secuencial)
# Llave (entero unsigned) p.ej. 42
./des_seq encrypt -i texto.txt -o cipher.bin -k 42


### 2) Verificar descifrado con llave conocida (secuencial)
./des_seq decrypt -i cipher.bin -o plano_recuperado.txt -k 42


### 3) Búsqueda por fuerza bruta (secuencial)
# Busca en el rango [start, end] e imprime la primera llave encontrada
./des_seq bruteforce -i cipher.bin -kw "es una prueba de" -s 0 -e 1000000


### 4) Búsqueda por fuerza bruta (MPI)
# Divide equitativamente el rango [s,e] entre np procesos; cualquier proceso que encuentre la llave
# notifica a los demás para detener la búsqueda (stop cooperativo).
mpirun -np 4 ./des_mpi -i cipher.bin -kw "es una prueba de" -s 0 -e 1000000


## Parámetros
- `-i <path>`: archivo de entrada. En `encrypt`, es el texto plano. En `decrypt` y `bruteforce`, es el binario cifrado.
- `-o <path>`: archivo de salida (opcional en `bruteforce`).
- `-k <uint64>`: llave (entero no negativo). Para DES se usan 8 bytes; aquí extendemos el entero a 64 bits.
- `-kw "frase"`: palabra/frase clave a buscar dentro del texto descifrado.
- `-s <uint64>` `-e <uint64>`: rango de búsqueda (inclusive).


## Notas de portabilidad
- macOS: OpenSSL es *keg-only*.
- Exporta PKG_CONFIG_PATH: `export PKG_CONFIG_PATH=$(brew --prefix openssl@3)/lib/pkgconfig`.
- O ajusta `OPENSSL_INC` y `OPENSSL_LIB` en el Makefile.
- Linux: usualmente `pkg-config` resuelve `-lcrypto` sin cambios.


## Metodología de medición
- Ejecutar con `-np 4` y el texto: `Esta es una prueba de proyecto 2`.
- Palabra clave: `es una prueba de`.
- Probar llaves: `123456`, `(2^56)/4` y `(2^56)/4 + 1` (adaptando rangos para ensayo). Registre tiempos.
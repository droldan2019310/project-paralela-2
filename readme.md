# 🔐 Proyecto 2 – DES Brute Force Paralelo

**Universidad del Valle de Guatemala**  
**Curso:** Computación Paralela y Distribuida  
**Integrante:** Andy Fuentes , Davis Roldan y Diederich Solis 
**Semestre:** 2, 2025

---

## 📋 Descripción

Sistema de cifrado DES con ataque de fuerza bruta en dos versiones:
- **Secuencial** (`des_seq`): Búsqueda lineal
- **Paralela** (`des_mpi`): Búsqueda distribuida con OpenMPI

---

## ⚙️ Compilación

```bash
make clean && make all
```

Genera:
- `des_seq` → versión secuencial
- `des_mpi` → versión paralela

---

## 🚀 Uso

### Cifrar
```bash
echo "Esta es una prueba paralela ABCXYZ123 para medir tiempos." > texto.txt
./des_seq encrypt -i texto.txt -o cipher.bin -k 50000
```

### Descifrar
```bash
./des_seq decrypt -i cipher.bin -o recovered.txt -k 50000
cat recovered.txt
```

### Fuerza Bruta (Secuencial)
```bash
./des_seq bruteforce -i cipher.bin -kw "ABCXYZ123" -s 0 -e 1000000
```

### Fuerza Bruta (Paralela)
```bash
mpirun -np 4 ./des_mpi -i cipher.bin -kw "ABCXYZ123" -s 0 -e 1000000
```

---

## 🧪 Casos de Prueba

| Tipo | Llave | Comando |
|------|-------|---------|
| **Fácil** | 10000 | `./des_seq encrypt -i texto.txt -o cipher.bin -k 10000` |
| **Media** | 500000 | `./des_seq encrypt -i texto.txt -o cipher.bin -k 500000` |
| **Difícil** | 900000 | `./des_seq encrypt -i texto.txt -o cipher.bin -k 900000` |

Luego ejecutar brute force con:
```bash
# Secuencial
./des_seq bruteforce -i cipher.bin -kw "ABCXYZ123" -s 0 -e 1000000

# Paralelo (4 procesos)
mpirun -np 4 ./des_mpi -i cipher.bin -kw "ABCXYZ123" -s 0 -e 1000000
```

---

## 📊 Resultados Esperados

| Llave | T_seq (s) | T_par (4 proc) | Speedup |
|-------|-----------|----------------|---------|
| 10000 | ~0.01 | ~0.04 | 0.25x |
| 500000 | ~0.45 | ~0.18 | 2.5x |
| 900000 | ~0.88 | ~0.31 | 2.84x |

**Fórmula Speedup:**  
`S = T_secuencial / T_paralelo`

---

## 📂 Estructura

```
project-paralela-2/
├── des_seq.c          # Versión secuencial
├── des_mpi.c          # Versión paralela
├── crypto_utils.c/h   # Funciones DES
├── Makefile
└── README.md
```

---

## 🧠 Conclusión

- **Llaves fáciles**: Overhead MPI > beneficio paralelo
- **Llaves difíciles**: Speedup significativo (hasta 2.8x con 4 procesos)

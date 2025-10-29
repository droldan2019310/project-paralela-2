CC      := gcc
MPICC   := mpicc
CFLAGS  := -O2 -Wall -Wextra -std=c11 -Wno-deprecated-declarations
LDFLAGS :=

# Intentar con pkg-config primero
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS   := $(shell pkg-config --libs openssl 2>/dev/null)

# Si pkg-config no devuelve nada, usar rutas típicas de Homebrew (ajusta si hace falta).
ifeq ($(strip $(OPENSSL_LIBS)),)
    OPENSSL_INC ?= /opt/homebrew/Cellar/openssl@3/3.6.0/include
    OPENSSL_LIB ?= /opt/homebrew/Cellar/openssl@3/3.6.0/lib
    CFLAGS  += -I$(OPENSSL_INC)
    # En tu mac viste que linkeó bien con -lssl -lcrypto
    LDFLAGS += -L$(OPENSSL_LIB) -lssl -lcrypto
else
    CFLAGS  += $(OPENSSL_CFLAGS)
    LDFLAGS += $(OPENSSL_LIBS)
endif

SRC_COMMON = crypto_utils.c
HDR_COMMON = crypto_utils.h

all: des_seq des_mpi

des_seq: des_seq.c $(SRC_COMMON) $(HDR_COMMON)
	$(CC) $(CFLAGS) -o $@ des_seq.c $(SRC_COMMON) $(LDFLAGS)

des_mpi: des_mpi.c $(SRC_COMMON) $(HDR_COMMON)
	$(MPICC) $(CFLAGS) -o $@ des_mpi.c $(SRC_COMMON) $(LDFLAGS)

clean:
	rm -f des_seq des_mpi *.o *.bin *.txt *.out
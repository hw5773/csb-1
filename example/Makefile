CC      = gcc
LD      = ld
AR      = ar
NM      = nm
OBJCOPY = objcopy
OBJDUMP = objdump
READELF = readelf

GCC=gcc
EXEC=ex_debug
SRC=ex_debug.c
OBJ=ex_debug.o

BINS=${EXEC}
OBJS=${OBJ}

all: ex_debug


ex_debug: ${OBJ}
	${CC} -o ${EXEC} ${OBJ}

ex_debug.o: ${SRC}
	${CC} -c $<

clean:
	rm ${BINS} ${OBJS}

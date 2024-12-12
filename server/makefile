CC ?= $(CROSS_COMPILE)gcc
CFLAGS ?= -Wall -DUSE_AESD_CHAR_DEVICE -g -O0
LDFLAGS ?= -lpthread -lrt
SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)

TARGET ?= aesdsocket

all: $(TARGET)

default : $(TARGET)

$(TARGET) : $(OBJ)
	$(CC) $(OBJ) -o $(TARGET) $(LDFLAGS) 

*.o: *.c
	$(CC) $(CFLAGS) -c $< -o $@	

clean:
	rm -f $(OBJ) $(TARGET)


PHONY: all clean
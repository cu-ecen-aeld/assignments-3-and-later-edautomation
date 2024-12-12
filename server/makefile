CC ?= $(CROSS_COMPILE)gcc
CHAR_DRIVER ?= USE_AESD_CHAR_DEVICE
CFLAGS ?= -Wall -D$(CHAR_DRIVER) -g -O0
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
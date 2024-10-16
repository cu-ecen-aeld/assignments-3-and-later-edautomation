

CC = $(CROSS_COMPILE)gcc
CFLAGS = -Wall
LDFLAGS = -pthread
SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)

TARGET = aesdsocket

all: $(TARGET)

default : $(TARGET)

$(TARGET) : $(OBJ)
	$(CC) $(LDFLAGS) $(OBJ) -o $(TARGET)

*.o: *.c
	$(CC) $(CFLAGS) -c $< -o $@	

clean:
	rm -f $(OBJ) $(TARGET)


PHONY: all clean
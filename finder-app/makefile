
CC = gcc
CFLAGS = -Wall
LDFLAGS = 
SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)

TARGET = writer

all: $(TARGET)

$(TARGET) : $(OBJ)
	$(CC) $(LDFLAGS) $(OBJ) -o $(TARGET)

*.o: *.c
	$(CC) $(CFLAGS) -c $< -o $@	

clean:
	rm -f $(OBJ) $(TARGET)


PHONY: all clean
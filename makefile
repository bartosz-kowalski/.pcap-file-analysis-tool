CC = gcc
CFLAGS = -O2 -Iinclude -g -Wall -Wextra 

TARGET = build/program

SRC = src/main.c src/header_parser.c 
OBJ = $(SRC:src/%.c=build/%.o)

all: $(TARGET)

$(TARGET): $(OBJ)
	 $(CC) $(CFLAGS) $^ -o $@

build/%.o: src/%.c 
	@mkdir -p build
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f build/*.o $(TARGET)

.PHONY: all clean
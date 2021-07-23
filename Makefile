CC = arm-linux-gnueabi-gcc
HEADERS = 
AFLAGS = -static -march=armv7-a
NAME = linux-sniffer
FILES = $(NAME).c
TARGET = $(NAME)

.PHONY: default all clean

all: $(TARGET)

$(TARGET): $(FILES) $(HEADERS)
	$(CC) $(AFLAGS) $(FILES) -o $(TARGET)


clean:
	rm -f *.o

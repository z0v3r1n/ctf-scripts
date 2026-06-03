CC := g++

TARGET = ./build/chall
SRC = main.cpp

CFLAGS = -O2 -Wl,-z,relro,-z,now

$(TARGET): $(SRC)
	$(CC) $(SRC) -o $(TARGET) $(CFLAGS) 
clean:
	rm -f $(TARGET)
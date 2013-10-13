# Modify CC for cross compilation
CC=gcc

all:
	$(CC) wifi_analyzer.c -o wifi_analyzer -fno-stack-protector
install:
	sudo cp wifi_analyzer /sbin
clean:
	rm wifi_analyzer

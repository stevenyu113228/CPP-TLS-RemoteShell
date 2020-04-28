all: server client
CC = g++

server: server.cpp
	$(CC) -o Server server.cpp  -lssl -lcrypto 

client: client.cpp
	$(CC)  -o Client client.cpp  -lssl -lcrypto 


.PHONY: clean,run

clean:
	rm Server Client

test:
	./Server
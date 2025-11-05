all: server client
server:
	g++ server/server.cpp -o server/server -lpthread
client:
	g++ client/client.cpp -o client/client
clean:
	rm -f server/server client/client


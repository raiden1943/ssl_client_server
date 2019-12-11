all : clean ssl_client_server

ssl_client_server: ssl.o
	g++ -g -o ssl_client ssl_client.o -pthread -lssl -lcrypto
	g++ -g -o ssl_server ssl_server.o -pthread -lssl -lcrypto

ssl.o:
	g++ -g -c -o ssl_client.o ssl_client.cpp
	g++ -g -c -o ssl_server.o ssl_server.cpp

clean:
	rm -f ssl_client
	rm -f ssl_server
	rm -f *.o

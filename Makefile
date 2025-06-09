all: peer

peer: peer.cpp
	 g++ -std=c++17 peer.cpp -o peer -lssl -lcrypto -lpthread

clean:
	rm -f peer

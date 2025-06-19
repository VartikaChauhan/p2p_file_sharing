CXX = g++
CXXFLAGS = -Wall -std=c++17
LDFLAGS = -lssl -lcrypto -pthread

TARGET = peer
SRC = peer.cpp peer_discovery.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)


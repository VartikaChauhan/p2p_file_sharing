CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++17 -O2
LDFLAGS = -lssl -lcrypto -lpthread

SRCS = peer.cpp crypto_utils.cpp peer_discovery.cpp
OBJS = $(SRCS:.cpp=.o)
TARGET = peer

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f *.o $(TARGET)


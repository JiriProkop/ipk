SNIFFER = sniffer
SERVER_CLIENT = ipkcpc
CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++20


.PHONY: clean all

all: $(SNIFFER)

$(SERVER_CLIENT):

$(SNIFFER):

clean:
	rm -f $(SNIFFER) $(SERVER_CLIENT)


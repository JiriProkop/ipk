SNIFFER = ipk-sniffer
SERVER_CLIENT = ipkcpc
CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++20


.PHONY: clean all

all: $(SNIFFER)

$(SERVER_CLIENT):

LDLIBS = -lpcap

$(SNIFFER):

clean:
	rm -f $(SNIFFER) $(SERVER_CLIENT)


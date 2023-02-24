EXEC = proj1
CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++20


.PHONY: clean all

all: $(EXEC)

$(EXEC):

clean:
	rm -f $(EXEC)


# Makefile for P2P File Sharing System

CXX = g++
CXXFLAGS = -std=c++17 -pthread -Wall -Wextra
LDFLAGS = -lssl -lcrypto

# Directories
TRACKER_DIR = '.'
CLIENT_DIR = '.'

# Targets
all: tracker client

tracker:
	$(CXX) $(CXXFLAGS) $(TRACKER_DIR)/tracker.cpp -o tracker $(LDFLAGS)

client:
	$(CXX) $(CXXFLAGS) $(CLIENT_DIR)/client.cpp -o client $(LDFLAGS)

clean:
	rm -f tracker client

.PHONY: all clean tracker client
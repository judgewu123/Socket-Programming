CC = gcc
CXX = g++
VERSION = -std=c++11


CLIENT = client.cpp
SERVER = server.cpp
CLI = client
SER = server

all: server client
  
server: $(SERVER)
	$(CXX) $(SERVER) -o $(SER) $(VERSION)
client: $(CLIENT)
	$(CXX) $(CLIENT) -o $(CLI) $(VERSION)


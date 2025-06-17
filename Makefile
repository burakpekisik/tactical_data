# Directories
SRC_DIR = src
INCLUDE_DIR = include
BIN_DIR = bin
BUILD_DIR = build
DATA_DIR = data

# Compiler settings
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -I$(INCLUDE_DIR)
LIBS = -lcjson

# Source files
SERVER_SOURCES = $(SRC_DIR)/server/server.c
JSON_SERVER_SOURCES = $(SRC_DIR)/server/json_server.c $(SRC_DIR)/common/json_utils.c
ENCRYPTED_SERVER_SOURCES = $(SRC_DIR)/server/encrypted_server.c $(SRC_DIR)/common/json_utils.c $(SRC_DIR)/common/crypto_utils.c $(SRC_DIR)/crypto/aes.c

CLIENT_SOURCES = $(SRC_DIR)/client/client.c
JSON_CLIENT_SOURCES = $(SRC_DIR)/client/json_client.c $(SRC_DIR)/common/json_utils.c
ENCRYPTED_CLIENT_SOURCES = $(SRC_DIR)/client/encrypted_client.c $(SRC_DIR)/common/json_utils.c $(SRC_DIR)/common/crypto_utils.c $(SRC_DIR)/crypto/aes.c

PARSER_SOURCES = $(SRC_DIR)/common/json_parser.c

# Targets
all: directories encrypted-server encrypted-client

directories:
	mkdir -p $(BIN_DIR) $(BUILD_DIR)

encrypted-server:
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/encrypted_server $(ENCRYPTED_SERVER_SOURCES) $(LIBS)

encrypted-client:
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/encrypted_client $(ENCRYPTED_CLIENT_SOURCES) $(LIBS)

# Run targets
run-encrypted-server:
	./$(BUILD_DIR)/encrypted_server

run-encrypted-client:
	./$(BUILD_DIR)/encrypted_client

clean:
	rm -rf $(BIN_DIR)/* $(BUILD_DIR)/*

.PHONY: all directories clean run-server run-client run-json-server run-json-client run-encrypted-server run-encrypted-client run-json-parser
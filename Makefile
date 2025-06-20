# Directories
SRC_DIR = src
INCLUDE_DIR = include
BIN_DIR = bin
BUILD_DIR = build
DATA_DIR = data

# Compiler settings
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -I$(INCLUDE_DIR)
LIBS = -lcjson -lsqlite3 -lcrypto -lssl -lpthread

# Source files
SERVER_SOURCES = $(SRC_DIR)/server/server.c
JSON_SERVER_SOURCES = $(SRC_DIR)/server/json_server.c $(SRC_DIR)/common/json_utils.c
ENCRYPTED_SERVER_SOURCES = $(SRC_DIR)/server/encrypted_server.c $(SRC_DIR)/client/fallback_manager.c $(SRC_DIR)/client/protocol_manager.c $(SRC_DIR)/common/json_utils.c $(SRC_DIR)/common/crypto_utils.c $(SRC_DIR)/thread/thread_monitor.c $(SRC_DIR)/connection/connection_manager.c $(SRC_DIR)/connection/tcp_connection.c $(SRC_DIR)/connection/udp_connection.c $(SRC_DIR)/connection/p2p_connection.c $(SRC_DIR)/control/control_interface.c $(SRC_DIR)/crypto/aes.c $(SRC_DIR)/dynamic_key/ecdh.c $(SRC_DIR)/database/create.c $(SRC_DIR)/database/insert.c $(SRC_DIR)/database/select.c $(SRC_DIR)/database/update.c $(SRC_DIR)/database/delete.c $(SRC_DIR)/database/db_test_utils.c

CLIENT_SOURCES = $(SRC_DIR)/client/client.c
JSON_CLIENT_SOURCES = $(SRC_DIR)/client/json_client.c $(SRC_DIR)/common/json_utils.c
ENCRYPTED_CLIENT_SOURCES = $(SRC_DIR)/client/encrypted_client.c $(SRC_DIR)/client/fallback_manager.c $(SRC_DIR)/client/protocol_manager.c $(SRC_DIR)/common/json_utils.c $(SRC_DIR)/common/crypto_utils.c $(SRC_DIR)/crypto/aes.c $(SRC_DIR)/dynamic_key/ecdh.c

PARSER_SOURCES = $(SRC_DIR)/common/json_parser.c

# Database tools
DATABASE_SOURCES = $(SRC_DIR)/database/create.c $(SRC_DIR)/database/insert.c $(SRC_DIR)/database/select.c $(SRC_DIR)/database/update.c $(SRC_DIR)/database/delete.c $(SRC_DIR)/database/open.c

# Targets
all: directories encrypted-server encrypted-client db-tools ecdh-test

directories:
	mkdir -p $(BIN_DIR) $(BUILD_DIR) $(SRC_DIR)/test

encrypted-server:
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/encrypted_server $(ENCRYPTED_SERVER_SOURCES) $(LIBS)

encrypted-client:
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/encrypted_client $(ENCRYPTED_CLIENT_SOURCES) $(LIBS)

# Database tools
db-test-standalone:
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/db_test_standalone $(SRC_DIR)/database/tests/test_data_standalone.c $(SRC_DIR)/database/create.c $(SRC_DIR)/database/insert.c $(SRC_DIR)/common/json_utils.c $(LIBS)

db-test-operations:
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/db_test_operations $(SRC_DIR)/database/tests/test_operations.c $(SRC_DIR)/database/create.c $(SRC_DIR)/database/insert.c $(SRC_DIR)/database/select.c $(SRC_DIR)/database/update.c $(SRC_DIR)/database/delete.c $(SRC_DIR)/common/json_utils.c $(LIBS)

db-tools: db-test-standalone db-test-operations

# ECDH test tool
ecdh-test:
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/ecdh_test $(SRC_DIR)/test/ecdh_test.c $(SRC_DIR)/common/crypto_utils.c $(SRC_DIR)/crypto/aes.c $(SRC_DIR)/dynamic_key/ecdh.c $(LIBS)

# Run targets
run-encrypted-server:
	./$(BUILD_DIR)/encrypted_server

run-encrypted-client:
	./$(BUILD_DIR)/encrypted_client

# Database run targets
run-db-test-standalone:
	./$(BUILD_DIR)/db_test_standalone

run-db-test-operations:
	./$(BUILD_DIR)/db_test_operations

# Run ECDH test
run-ecdh-test:
	./$(BUILD_DIR)/ecdh_test

clean:
	rm -rf $(BIN_DIR)/* $(BUILD_DIR)/* *.db

.PHONY: all directories clean run-server run-client run-json-server run-json-client run-encrypted-server run-encrypted-client run-json-parser db-tools db-test-standalone db-test-operations run-db-test-standalone run-db-test-operations ecdh-test run-ecdh-test
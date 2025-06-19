#!/bin/bash

# Docker Test Script for Tactical Data Server
echo "=== Docker Test Script ==="
echo "Testing TCP, UDP, and P2P connections"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test TCP connection
echo -e "\n${YELLOW} Testing TCP connection (port 8080)...${NC}"
if nc -z localhost 8080; then
    echo -e "${GREEN}✓ TCP Server is running${NC}"
else
    echo -e "${RED}✗ TCP Server is not responding${NC}"
fi

# Test UDP connection
echo -e "\n${YELLOW} Testing UDP connection (port 8081)...${NC}"
if nc -u -z localhost 8081; then
    echo -e "${GREEN}✓ UDP Server is running${NC}"
else
    echo -e "${RED}✗ UDP Server is not responding${NC}"
fi

# Test P2P connection (future)
echo -e "\n${YELLOW} Testing P2P connection (port 8082)...${NC}"
if nc -z localhost 8082; then
    echo -e "${GREEN}✓ P2P Node is running${NC}"
else
    echo -e "${YELLOW}⚠ P2P Node is not implemented yet${NC}"
fi

# Check container status
echo -e "\n${YELLOW} Container Status:${NC}"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# Check server logs
echo -e "\n${YELLOW} Recent Server Logs:${NC}"
docker logs tactical-data-server --tail 10

echo -e "\n${GREEN}=== Test Complete ===${NC}"

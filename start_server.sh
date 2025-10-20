#!/bin/bash

# WebSSH Server Startup Script
# Author: steven
# Description: Build and start the WebSSH server

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print banner
echo -e "${BLUE}"
echo "==========================================="
echo "  WebSSH Server - Startup Script"
echo "==========================================="
echo -e "${NC}"

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo -e "${RED}Error: Rust/Cargo is not installed${NC}"
    echo "Please install Rust from https://rustup.rs/"
    exit 1
fi

echo -e "${GREEN}✓ Rust/Cargo found${NC}"

# Check Rust version
RUST_VERSION=$(rustc --version | awk '{print $2}')
echo -e "${BLUE}Rust version: ${RUST_VERSION}${NC}"

# Build the project
echo ""
echo -e "${YELLOW}Building project in release mode...${NC}"
if cargo build --release 2>&1 | tail -n 10; then
    echo -e "${GREEN}✓ Build successful${NC}"
else
    echo -e "${RED}✗ Build failed${NC}"
    exit 1
fi

# Create data directory if it doesn't exist
if [ ! -d "data" ]; then
    echo -e "${YELLOW}Creating data directory...${NC}"
    mkdir -p data
    echo -e "${GREEN}✓ Data directory created${NC}"
fi

# Start the server
echo ""
echo -e "${GREEN}Starting WebSSH server...${NC}"
echo -e "${BLUE}Server will be available at: http://127.0.0.1:18022${NC}"
echo -e "${YELLOW}Default credentials: admin / admin${NC}"
echo -e "${RED}IMPORTANT: Change the default password after first login!${NC}"
echo ""

# Run the server
./target/release/webssh


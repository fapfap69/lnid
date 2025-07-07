#!/bin/bash

# Script per testare memory leak in LNID
# Usage: ./test-memory.sh

echo "=== LNID Memory Leak Test ==="

# Controlla se valgrind è installato
if ! command -v valgrind &> /dev/null; then
    echo "Valgrind non trovato. Installalo con:"
    echo "  Ubuntu/Debian: sudo apt install valgrind"
    echo "  macOS: brew install valgrind"
    exit 1
fi

# Directory di lavoro
cd src/build || { echo "Directory build non trovata"; exit 1; }

echo "1. Test server daemon (modalità normale)..."
timeout 10s valgrind --leak-check=full --show-leak-kinds=all \
    --suppressions=/usr/share/valgrind/default.supp \
    ./lnidd -p 17000 -v &
SERVER_PID=$!

sleep 2

echo "2. Test client normale..."
valgrind --leak-check=full --show-leak-kinds=all \
    ./lnid-cli -i 127.0.0.1 -p 17000 -v

echo "3. Test client cifrato..."
valgrind --leak-check=full --show-leak-kinds=all \
    ./lnid-cli -i 127.0.0.1 -p 17000 -c -v

echo "4. Test scan..."
valgrind --leak-check=full --show-leak-kinds=all \
    ./lnid-scan -s 127.0.0 -p 17000 -t 50 -o 100 -v

# Termina il server
kill $SERVER_PID 2>/dev/null

echo "5. Test server cifrato..."
timeout 10s valgrind --leak-check=full --show-leak-kinds=all \
    ./lnidd -p 17001 -c -v &
SERVER_PID=$!

sleep 3

echo "6. Test client con server cifrato..."
valgrind --leak-check=full --show-leak-kinds=all \
    ./lnid-cli -i 127.0.0.1 -p 17001 -c -v

# Cleanup
kill $SERVER_PID 2>/dev/null
wait

echo "=== Test completato ==="
echo "Controlla l'output per eventuali memory leak"
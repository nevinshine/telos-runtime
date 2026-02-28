#!/bin/bash

# Compile the torture suite
echo "[*] Compiling benchmark suite..."
gcc -O3 -pthread benchmark_torture.c -o bench_torture

echo -e "\n========================================="
echo -e "       PHASE 1: NATIVE BASELINE          "
echo -e "========================================="
./bench_torture

echo -e "\n========================================="
echo -e "       PHASE 2: TELOS GUARDED            "
echo -e "========================================="

sudo python3 run_guarded.py

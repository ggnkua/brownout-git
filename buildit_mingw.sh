#!/bin/sh
g++ -O3 -std=gnu++11 brownout.cpp -Isimpleopt -I. -o brownout.exe -Wl,-Bstatic -static

m68k-ossom-elf-gcc -m68000 -mshort -c simple.c -o simple.o
m68k-ossom-elf-ld --emit-relocs simple.o -o simple.elf
../brownout.exe -i simple.elf -o simple.prg -s -d

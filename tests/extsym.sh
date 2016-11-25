m68k-ossom-elf-gcc -m68000 -mshort -c extsym.c -o extsym.o
m68k-ossom-elf-ld --emit-relocs extsym.o -o extsym.elf
../brownout.exe -i extsym.elf -o extsym1.prg -s -d
../brownout.exe -i extsym.elf -o extsym2.prg -x -d

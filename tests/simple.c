/*
 * A very simple program to test a few things.
 *
 * This was written in order to test the following:
 * - Compiling/linking (m68k-ossom-elf toolchain)
 * - ELF to PRG conversion (using brownout)
 * - GST Symbol table creation (brownout -s flag)
 * - Oddly sized segments (notice that tab2 is of odd length
 *
 * To build this, execute simple.sh (or copy the commands
 * in your command prompt if you don't have bash).
 * The resulting program should be able to be loaded
 * into a ST debugger or disassembler with a fully working
 * symbol table.
 *
 */

int tab[5] = {3, 6, 9, 12, 15};
char tab2[7] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70};
typedef struct
{
    int a;
    char b;
    short c[5];
} somethingsomething;

somethingsomething something;

int main()
{
    int a, b, c, d, e;
    a = 10;
    b = 30;
    if (a > b)
    {
        d = a - b;
        b = a * b;
        e = a / e;
    }
    else
        b = d = e = a + b;
    return 1;
}


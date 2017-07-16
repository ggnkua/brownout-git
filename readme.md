brownout - A humble .elf to ST .prg binary converter

Written by George Nakos and Douglas Litte.

Uses the *elfio* library by Serge Lamikhov-Center to do the
heavy lifting that is ELF parsing. See elfio.hpp for its
license.

Command line parsing uses *simpleopt* by Brodie Thiesfield.
See SimpleOpt.h for its license.

Everything else is released under the WTFPL. Probably.


Usage: brownout -i <input_elf_file_name> -o <output_tos_file_name> [-p PRGFLAGS] [-s] [-d] [-x]

            -s will create a symbol table.

            -d will turn on verbose debugging.

            -x will create an extended symbol table.

            -f will turn on C++ symbol demangling (i.e. you don't get ugly symbol names).

            -v will turn on verbose mode (less spammy than debugging)

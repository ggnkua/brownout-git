/*

brownout - A humble .elf to ST .prg binary converter

Written by George Nakos and Douglas Litte.

Uses the elfio library by Serge Lamikhov-Center to do the
heavy lifting that is ELF parsing. Also used elfdump.cpp
from the examples folder as the basis for this source.
See elfio.hpp for its license.

Command line parsing uses simpleopt by Brodie Thiesfield.
See SimpleOpt.h for its license.

Everything apart from elfio library is released under
the WTFPL. Probably.

*/

#ifdef _MSC_VER
#define _SCL_SECURE_NO_WARNINGS
#define ELFIO_NO_INTTYPES

//#include <stdio.h>

// Yes yes dear, fopen is insecure, blah blah. We know.
// Don't bug us about it.
#define _CRT_SECURE_NO_WARNINGS

// Let's make sure struct members are aligned to 2 bytes.
// I wouldn't have put this here if I didn't get bit by this nonsense.
#pragma pack(2)
#endif

#include <assert.h>
#include <iostream>
#include <elfio/elfio_dump.hpp>
#include <elfio/elfio.hpp>
#include <SimpleOpt.h>
#include <map>

// Little endian to big endian conversion depending on platform
#if defined(__linux__)
    #include <endian.h>
    #define BYTESWAP32 htobe32
    #define BYTESWAP16 htobe16
#endif
#ifdef _MSC_VER
    #include <stdlib.h>
    #define BYTESWAP16 _byteswap_ushort
    #define BYTESWAP32 _byteswap_ulong
#endif

// M68k defines lifted from bintools 2.27.
// Added here instead of elftypes.hpp so the
// elfio lib won't need any modifying should
// we ever need to update to a newer version.

#define R_68K_NONE           0
#define R_68K_32             1
#define R_68K_16             2
#define R_68K_8              3
#define R_68K_PC32           4
#define R_68K_PC16           5
#define R_68K_PC8            6
#define R_68K_GOT32          7
#define R_68K_GOT16          8
#define R_68K_GOT8           9
#define R_68K_GOT32O        10
#define R_68K_GOT16O        11
#define R_68K_GOT8O         12
#define R_68K_PLT32         13
#define R_68K_PLT16         14
#define R_68K_PLT8          15
#define R_68K_PLT32O        16
#define R_68K_PLT16O        17
#define R_68K_PLT8O         18
#define R_68K_COPY          19
#define R_68K_GLOB_DAT      20
#define R_68K_JMP_SLOT      21
#define R_68K_RELATIVE      22
#define R_68K_GNU_VTINHERIT 23
#define R_68K_GNU_VTENTRY   24
#define R_68K_TLS_GD32      25
#define R_68K_TLS_GD16      26
#define R_68K_TLS_GD8       27
#define R_68K_TLS_LDM32     28
#define R_68K_TLS_LDM16     29
#define R_68K_TLS_LDM8      30
#define R_68K_TLS_LDO32     31
#define R_68K_TLS_LDO16     32
#define R_68K_TLS_LDO8      33
#define R_68K_TLS_IE32      34
#define R_68K_TLS_IE16      35
#define R_68K_TLS_IE8       36
#define R_68K_TLS_LE32      37
#define R_68K_TLS_LE16      38
#define R_68K_TLS_LE8       39
#define R_68K_TLS_DTPMOD32  40
#define R_68K_TLS_DTPREL32  41
#define R_68K_TLS_TPREL32   42

#if defined(_MSC_VER)
# include <windows.h>
# include <tchar.h>
#else
# define TCHAR		char
# define _T(x)		x
# define _tprintf	printf
# define _tmain		main
#endif

enum
{
    OPT_INFILE,
    OPT_OUTFILE,
    OPT_PRGFLAGS,
    OPT_SYMTABLE,
    OPT_ELF_HEADER,
    OPT_ELF_SECTION_HEADERS,
    OPT_ELF_SEGMENT_HEADERS,
    OPT_ELF_SYMBOL_TABLES,
    OPT_ELF_NOTES,
    OPT_ELF_DYNAMIC_TAGS,
    OPT_ELF_SECTION_DATAS,
    OPT_ELF_SEGMENT_DATAS,
    OPT_HELP,
    OPT_DEBUG
};

CSimpleOpt::SOption g_rgOptions[] =
{
    { OPT_INFILE,               _T("-i"),     SO_REQ_SEP },
    { OPT_OUTFILE,              _T("-o"),     SO_REQ_SEP },
    { OPT_PRGFLAGS,             _T("-p"),     SO_REQ_SEP },
    { OPT_SYMTABLE,             _T("-s"),     SO_NONE    },
    { OPT_DEBUG,                _T("-d"),     SO_NONE    },
    { OPT_HELP,                 _T("-h"),     SO_NONE    },
    SO_END_OF_OPTIONS                       // END
};

typedef struct
{
    uint16_t    PRG_magic;  // This WORD contains the magic value (0x601A).
    uint32_t    PRG_tsize;  // This LONG contains the size of the TEXT segment in bytes.
    uint32_t    PRG_dsize;  // This LONG contains the size of the DATA segment in bytes.
    uint32_t    PRG_bsize;  // This LONG contains the size of the BSS segment in bytes.
    uint32_t    PRG_ssize;  // This LONG contains the size of the symbol table in bytes.
    uint32_t    PRG_res1;   // This LONG is unused and is currently reserved.
    uint32_t    PRGFLAGS;   // This LONG contains flags which define certain process characteristics (as defined below).
    uint16_t    ABSFLAG;    // This WORD flag should be non-zero to indicate that the program has no fixups or 0 to indicate it does.Since some versions of TOS handle files with this value being non-zero incorrectly, it is better to represent a program having no fixups with 0 here and placing a 0 longword as the fixup offset.
} PRG_HEADER;


using namespace ELFIO;

void printhelp()
{
    printf( "Usage: brownout -i <input_elf_file_name> -o <output_tos_file_name> [-p PRGFLAGS] [-s] [-d]\n"
            "-s will create a symbol table\n"
            "-d will turn on verbose debugging.\n");
}

int _tmain(int argc, TCHAR * argv[])
{

    PRG_HEADER toshead = {0, 0, 0, 0, 0, 0, 0, 0};  // Set up TOS header

    //if ( argc != 3 && argc != 4)
    //{
    //    printf( "Usage: brownout <input_elf_file_name> <output_tos_file_name> [PRGFLAGS]\n" );
    //    return 1;
    //}

    // declare our options parser, pass in the arguments from main
    // as well as our array of valid options.
    CSimpleOpt args(argc, argv, g_rgOptions);
    char infile[1024];
    char outfile[1024];
    bool DEBUG = false;
    bool SYMTABLE = false;

    bool gotinput = false, gotoutput = false;

    // while there are arguments left to process
    while (args.Next())
    {
        if (args.LastError() == SO_SUCCESS)
        {
            if (args.OptionId() == OPT_HELP)
            {
                printhelp();
                return 0;
            }
            //_tprintf(_T("Option, ID: %d, Text: '%s', Argument: '%s'\n"),
            //    args.OptionId(), args.OptionText(),
            //    args.OptionArg() ? args.OptionArg() : _T(""));
            else if (args.OptionId() == OPT_INFILE)
            {
                std::string s_arg = (std::string)args.OptionArg();
                strcpy(infile, s_arg.c_str());
                gotinput = true;
            }
            else if (args.OptionId() == OPT_OUTFILE)
            {
                std::string s_arg = (std::string)args.OptionArg();
                strcpy(outfile, s_arg.c_str());
                gotoutput = true;
            }
            else if (args.OptionId() == OPT_PRGFLAGS)
            {
                std::string s_arg = (std::string)args.OptionArg();
                toshead.PRGFLAGS = atoi(s_arg.c_str());
            }
            else if (args.OptionId() == OPT_DEBUG)
            {
                DEBUG = true;
            }
            else if (args.OptionId() == OPT_SYMTABLE)
            {
                SYMTABLE = true;
            }
        }
        else
        {
            _tprintf(_T("Invalid argument: %s\n"), args.OptionText());
            return 1;
        }
    }

    if ((gotinput & gotoutput) == false)
    {
        printhelp();
        return 1;
    }

    elfio reader;

    if ( !reader.load( infile ) )
    {
        printf( "File %s is not found or it is not an ELF file\n", infile );
        return 1;
    }

    if (DEBUG)
    {
        dump::header         ( std::cout, reader );
        dump::section_headers( std::cout, reader );
        dump::segment_headers( std::cout, reader );
        dump::symbol_tables  ( std::cout, reader );
        dump::notes          ( std::cout, reader );
        dump::dynamic_tags   ( std::cout, reader );
        dump::section_datas  ( std::cout, reader );
        dump::segment_datas  ( std::cout, reader );
    }

    //

    Elf_Half sec_num = reader.sections.size();

    typedef struct
    {
        int         type;       // Type of section (see enum below)
        uint32_t    offset;     // Offset of section inside the TOS PRG
        uint32_t    size;       // Size of section
        const char  *data;      // Points to the start of the actual section data
    } ST_SECTION;

    enum
    {
        SECT_TEXT,
        SECT_DATA,
        SECT_BSS
    };

    typedef struct
    {
        uint32_t offset_fixup;                      // Offset inside the section
        int section;                                // Which section we're on
    } TOS_RELOC;

    toshead.PRG_magic = 0x601a;                     // MandatoryA

    //if (argc == 4)
    //    toshead.PRGFLAGS = atoi(argv[3]);           // Set PRGFLAGS

    TOS_RELOC tos_relocs[100 * 1024];                // Enough? Who knows!
    int no_relocs = 0;

    uint32_t file_offset = 28;                      // first text section after the tos header
    ST_SECTION prg_sect[32];                        // Enough? Who knows!
    int section_map[32];                            // This keeps track of which elf section is mapped in which prg_sect index (i.e. a reverse look-up)
    int no_sect = 0;

	for (int i = 0; i < 32; i++)
		section_map[i] = -1;

    section *psec;

    // TODO: refactor the following 3 loops into 1 by
    // making prg_sect [32][3] and iterating once again
    // to determine offsets into file?

    // Group text segments and determine their position inside the output file
    for ( int i = 0; i < sec_num; i++ )
    {
        psec = reader.sections[i];
        if (psec->get_type() == SHT_PROGBITS &&
                psec->get_name() == ".text")
        {
            prg_sect[no_sect].type = SECT_TEXT;
            prg_sect[no_sect].offset = file_offset;                     // Mark start offset of section inside .prg
            prg_sect[no_sect].size = (uint32_t)psec->get_size();        // Mark section's size
            prg_sect[no_sect].data = (const char *)psec->get_data();    // Mark section's start of data

            file_offset += (uint32_t)psec->get_size();                  // Update prg offset
            toshead.PRG_tsize += (uint32_t)psec->get_size();            // Update prg text size
            section_map[i] = no_sect;                                   // Mark where in prg_sect this section will lie
            no_sect++;
        }
    }

    // Group data segments and determine their position inside the output file
    for ( int i = 0; i < sec_num; i++ )
    {
        psec = reader.sections[i];
        if (psec->get_type() == SHT_PROGBITS &&
                psec->get_name() == ".data")
        {
            prg_sect[no_sect].type = SECT_DATA;
            prg_sect[no_sect].offset = file_offset;                     // Mark start offset of section inside .prg
            prg_sect[no_sect].size = (uint32_t)psec->get_size();        // Mark section's size
            prg_sect[no_sect].data = (const char *)psec->get_data();    // Mark section's start of data
            file_offset += (uint32_t)psec->get_size();                  // Update prg offset
            toshead.PRG_dsize += (uint32_t)psec->get_size();            // Update prg data size
            section_map[i] = no_sect;                                   // Mark where in prg_sect this section will lie
            no_sect++;
        }
    }

    // Group BSS segments and determine their position inside the output file
    for ( int i = 0; i < sec_num; i++ )
    {
        psec = reader.sections[i];
        if (psec->get_type() == SHT_NOBITS)
        {
            prg_sect[no_sect].type = SECT_BSS;
            prg_sect[no_sect].offset = file_offset;                     // Mark start offset of section inside .prg
            prg_sect[no_sect].size = (uint32_t)psec->get_size();        // Mark section's size
            toshead.PRG_bsize += (uint32_t)psec->get_size();            // Update prg bss size
            no_sect++;
        }
    }

    // Perform any relocations that may be needed
    //section *psec_reloc;
    for ( int i = 0; i < sec_num; i++ )
    {
        psec = reader.sections[i];
        std::string sectname = psec->get_name();                        // Debug
        int test1 = sectname.find(".text");                             // Check if this is a text relocation segment
        int test2 = sectname.find(".data");                             // Check if this is a data relocation segment
        if (psec->get_type() == SHT_RELA && (test1 > 0 || test2 > 0))
        {
            Elf64_Addr   offset;
            Elf64_Addr   symbolValue;
            std::string  symbolName;
            Elf_Word     type;
            Elf_Sxword   addend;
            Elf_Sxword   calcValue;
            relocation_section_accessor relocs(reader, psec);

            //int sec_size=(int)psec->get_size()/sizeof(Elf32_Rela);    //Number of entries in the table
            int sec_size = (int)relocs.get_entries_num();               //Number of entries in the table
            for (Elf_Xword j = 0; j < sec_size; j++)
            {
                relocs.get_entry(j, offset, symbolValue, symbolName, type, addend, calcValue);
                switch(type)
                {
                case R_68K_32:
                {
                    if (0)
                    {
                        std::cout << "Relocatable symbol " << j << " at section " << i
                                  << " [" << psec->get_name() << "] at offset " << offset << " addend " << addend<< std::endl;
                    }
                    // TODO: Ok, we need to mark which section this relocation
                    // is refering to. For now we're going to blindly assume that it
                    // refers to the previous one as they usually go in pairs
                    // (.text / .rela.text). If this is bad then well, this is what
                    // to change!
					assert(i >= 0);
					assert(section_map[i - 1] >= 0);
                    tos_relocs[no_relocs].section = section_map[i - 1];
                    tos_relocs[no_relocs].offset_fixup = (uint32_t)offset;
                    no_relocs++;
                    break;
                }
                case R_68K_16:
                {
                    std::cout << "Section" << i <<
                              ": 16-bit relocations not allowed (apparently)"
                              << std::endl;
                    break;
                }
                case R_68K_PC16:
                {
                    //PC relative section, no relocation needed
                    break;
                }
                default:
                {
                    //std::cout << "What the hell kind of type that? "
                    //    << (int)type << "? Really?" << std::endl;
                    break;
                }
                }
            }
        }
    }

    // TODO: look into making a proper GST symbol table

    /*
    SYMBOL TABLE
    ------------
    The  symbol  table  defines the symbols referenced by a command file.  Each
    entry in the symbol table is associated with an index  that  indicates  its
    entry  number.    Entries are numbered sequentially starting with zero.  As
    shown in Figure 3-3, each symbol table entry is  composed  of  seven  words
    that describe the symbol's name, type, and value.


                             +--------+--------+
                           0 |                 |
                             +      Symbol     +
                             |                 |
                             +                 +
                             |       Name      |
                             +                 +
                           6 |                 |
                             +--------+--------+
                           8 |       Type      |
                             +--------+--------+
                           A |                 |
                             +      Value      +
                           C |                 |
                             +--------+--------+

                      Figure 3-3.  Symbol Table Entry


    Table 3-1 describes the fields of a symbol table entry.



                   Table 3-1.  Symbol Table Entry Fields

    Field     Definition


    Name      Symbol   name,   null-padded   right  if  less  than  eight
             characters.

    Type      Symbol type as indicated by the following values:

             0100H:  bss-based relocatable
             0200H:  text-based relocatable
             0400H:  data-based relocatable
             0800H:  external reference
             1000H:  equated register
             2000H:  global
             4000H:  equated
             8000H:  defined


    Value     Symbol value where the value can be  an  address,  register
             number, value of an _expression_, and so forth. Note that the
             linkers interpret the value when  the  symbol  is  external
             (0800H) as the size of a common region.
    */

    typedef struct
    {
        char name[8];
        uint16_t type;
        uint32_t value;
    } GST_SYMBOL;

    GST_SYMBOL symtab[100*1024];    // Enough? Who knows!
    int no_sym=0;

    if (SYMTABLE)
    {
        for ( int i = 0; i < sec_num; i++ )
        {
            psec = reader.sections[i];
            if (psec->get_type() == SHT_SYMTAB /* || psec->get_type() == SHT_DYNSYM */)
            {
                symbol_section_accessor symbols( reader, psec );

                Elf_Xword     sym_no = symbols.get_symbols_num();

                if ( sym_no > 0 ) {
                    
                    for ( Elf_Half i = 0; i < sym_no; ++i ) {
                        std::string   name;
                        Elf64_Addr    value   = 0;
                        Elf_Xword     size    = 0;
                        unsigned char bind    = 0;
                        unsigned char type    = 0;
                        Elf_Half      section = 0;
                        unsigned char other   = 0;
                        symbols.get_symbol( i, name, value, size, bind, type, section, other );
                        name[7]=0;  //TODO: check everything!
                        strcpy(symtab[no_sym].name,name.c_str());
                        symtab[no_sym].value=value;
                        switch (type)
                        {
                        case STB_LOCAL:
                        case STB_WEAK:
                            {
                                //Bounds checking to see which segment it belongs
                                symtab[no_sym].type=0x100; //TEXT
                                symtab[no_sym].type=0x200; //DATA
                                symtab[no_sym].type=0x300; //BSS
                            }
                        case STB_GLOBAL:
                            {
                                symtab[no_sym].type=0x2000;
                            }
                        case STB_LOOS:
                        case STB_HIOS:
                        case STB_LOPROC:
                        case STB_HIPROC:
                            {
                                // Do nothing?
                            }
                        }
                        no_sym++;

                    }

                }


                //prg_sect[no_sect].type=SECT_BSS;
                //prg_sect[no_sect].offset=file_offset;
                //prg_sect[no_sect].reloc_needed=false;
                //bss_size+=psec->get_size();
                //no_sect++;
            }
        }
        toshead.PRG_ssize=no_sym*14;
        //Byte swap table and dump it
        for (int i=0;i<no_sym;i++)
        {
            symtab[i].type=BYTESWAP16(symtab[i].type);
            symtab[i].value=BYTESWAP32(symtab[i].value);
        }
    }


    // Print some basic info
    std::cout << "Text size: " << /*hex << */ toshead.PRG_tsize << std::endl <<
              "Data size:" << toshead.PRG_dsize << std::endl <<
              "BSS size:" << toshead.PRG_bsize << std::endl;

    // Open output file and write things
    FILE *tosfile = fopen(outfile, "wb");


    // Byte swap prg header if needed
    // TODO: take care of portability stuff.... eventually
    PRG_HEADER writehead;
    writehead.PRG_magic = BYTESWAP16(toshead.PRG_magic);
    writehead.PRG_tsize = BYTESWAP32(toshead.PRG_tsize);
    writehead.PRG_dsize = BYTESWAP32(toshead.PRG_dsize);
    writehead.PRG_bsize = BYTESWAP32(toshead.PRG_bsize);
    writehead.PRG_ssize = BYTESWAP32(toshead.PRG_ssize);
    writehead.PRG_res1 = BYTESWAP32(toshead.PRG_res1);
    writehead.PRGFLAGS = BYTESWAP32(toshead.PRGFLAGS);
    writehead.ABSFLAG = BYTESWAP16(toshead.ABSFLAG);

    // Write header
    fwrite(&writehead, sizeof(writehead), 1, tosfile);

    // Write text and data sections
    for (int i = 0; i < no_sect; i++)
    {
        if (prg_sect[i].type == SECT_TEXT || prg_sect[i].type == SECT_DATA)
        {
            fwrite(prg_sect[i].data, prg_sect[i].size, 1, tosfile);
            file_offset += prg_sect[i].size;

        }
        // TODO: Add padding after sections?
        // TODO2: For 030 executables pad sections to 4 bytes?
        // TODO3: For 030 executables, insert a nop at the start of the first
        //        text segment so the start of the code is aligned to 4 bytes?
        //        (TOS 4 aligns mallocs to 4 bytes but the header is 28 bytes)
    }

    // TODO: write symbol table
    if (toshead.PRG_ssize != 0)
    {
        fwrite(symtab,toshead.PRG_ssize,1,tosfile);
        file_offset+=toshead.PRG_ssize;
    }

	// shove all reloc indices in a map, using the address as the sort key
	// (equivalent to a tree-insert-sort)
	typedef std::map<uint32_t, int> relocmap_t;
	relocmap_t relocmap;
	for (int r = 0; r < no_relocs; r++)
	{
		// compute reloc address
		//uint32_t addr = tos_relocs[r].offset_fixup + prg_sect[tos_relocs[r].section].offset - 28;
		uint32_t addr = tos_relocs[r].offset_fixup;

		// make sure only one reloc for each address!
		assert(relocmap.find(addr) == relocmap.end());

		// index of this reloc address
		relocmap[addr] = r;
	}

    // Write relocation table
	if (no_relocs > 0)
    {
		// sorted map of reloc indices
		relocmap_t::iterator it = relocmap.begin();

		// get first address-sorted reloc index
		int ri = it->second; it++;

		uint32_t current_reloc;
		uint32_t next_reloc;
		uint32_t diff;
		uint8_t temp;
		uint32_t temp_byteswap;
		// Handle first relocation separately as
		// the offset needs to be a longword.
				

		current_reloc = tos_relocs[ri].offset_fixup;
		temp_byteswap = BYTESWAP32(current_reloc);
		fwrite(&temp_byteswap, 4, 1, tosfile);
		for (int i = 1; i < no_relocs; i++)
		{
			// get next address-sorted reloc index
			int ri = it->second; it++;

			next_reloc = tos_relocs[ri].offset_fixup;
			diff = next_reloc - current_reloc;
			while (diff > 254)
			{
				temp = 1;
				fwrite(&temp, 1, 1, tosfile);
				diff -= 254;
			}
			temp = diff;
			fwrite(&temp, 1, 1, tosfile);
			current_reloc = next_reloc;
		}

		// Finally, write a 0 to terminate the symbol table
        temp = 0;
        fwrite(&temp, 1, 1, tosfile);
    }
    else
    {
        // Write a null longword to express list termination
        // (as suggested by the Atari Compendium chapter 2)
        fwrite(&no_relocs, 4, 1, tosfile);
    }

    // Done writing stuff
    fclose(tosfile);

    return 0;
}



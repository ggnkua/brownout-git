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
// Yes yes dear, fopen is insecure, blah blah. We know.
// Don't bug us about it.
#define _CRT_SECURE_NO_WARNINGS
// Let's make sure struct members are aligned to 2 bytes.
// I wouldn't have put this here unless I got bit by this nonsense.
#pragma pack(2)
#endif

#include <assert.h>
#include <iostream>
#include <elfio/elfio_dump.hpp>
#include <elfio/elfio.hpp>
#include <stdio.h>
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
			
uint32_t relo_data[1];

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
		uint32_t offset_fixup;					// Offset inside the section
		uint32_t elfsymaddr;
        int elfsection;								// Which section we're on
		int tossection;

    } TOS_RELOC;

    toshead.PRG_magic = 0x601a;                     // MandatoryA

	typedef std::map<uint32_t, std::pair<uint32_t, int> > elfsectionboundsmap_t;
	elfsectionboundsmap_t elfsectionboundsmap;

    //if (argc == 4)
    //    toshead.PRGFLAGS = atoi(argv[3]);           // Set PRGFLAGS

    TOS_RELOC tos_relocs[16 * 1024];                // Enough? Who knows!
    int no_relocs = 0;

    uint32_t file_offset = 28;                      // first text section after the tos header
    ST_SECTION prg_sect[256];                        // Enough? Who knows!
    int section_map[256];                            // This keeps track of which elf section is mapped in which prg_sect index (i.e. a reverse look-up)
    int no_sect = 0;
	bool claimed_sections[256];



	for (int i = 0; i < 256; i++)
	{
		section_map[i] = -1;
		claimed_sections[i] = false;
	}

    section *psec;

    // TODO: refactor the following 3 loops into 1 by
    // making prg_sect [32][3] and iterating once again
    // to determine offsets into file?

    for ( int i = 0; i < sec_num; i++ )
    {
		if (claimed_sections[i]) continue;
        psec = reader.sections[i];
		if ((psec->get_type() == SHT_PROGBITS) && (psec->get_name() == ".boot"))
        {
			claimed_sections[i] = true;
            prg_sect[no_sect].type = SECT_TEXT;
            prg_sect[no_sect].offset = file_offset;                     // Mark start offset of section inside .prg
            prg_sect[no_sect].size = (uint32_t)psec->get_size();        // Mark section's size
            prg_sect[no_sect].data = (const char *)psec->get_data();    // Mark section's start of data

			// record section bounds (and index) in a map of <startaddr/index> pairs using endaddr as the sort key,
			// for identity queries using reloc addresses. this way we can identify & bounds-check the owning 
			// section and identify it from a single query address.
			elfsectionboundsmap[psec->get_address() + psec->get_size()] = std::pair<uint32_t, int>(psec->get_address(), i);		

            file_offset += (uint32_t)psec->get_size();                  // Update prg offset
            toshead.PRG_tsize += (uint32_t)psec->get_size();            // Update prg text size
            section_map[i] = no_sect;                                   // Mark where in prg_sect this section will lie
			std::cout << "record [" << psec->get_name() << "] esi:" << i << " tsi:" << no_sect << " fbeg:" << (prg_sect[no_sect].offset) << " fend:" << file_offset << std::endl;
            no_sect++;
        }
    }

    // Group text segments and determine their position inside the output file
    for ( int i = 0; i < sec_num; i++ )
    {
		if (claimed_sections[i]) continue;
        psec = reader.sections[i];
		if 
		(
			(psec->get_flags() & SHF_EXECINSTR) ||			
			//((psec->get_type() == SHT_PROGBITS) && (psec->get_name() == ".text")) ||
			//((psec->get_type() == SHT_PROGBITS) && (psec->get_name() == ".init")) ||
			//((psec->get_type() == SHT_PROGBITS) && (psec->get_name() == ".fini")) ||
			(
				(psec->get_type() == SHT_INIT_ARRAY) ||
				(psec->get_type() == SHT_PREINIT_ARRAY) ||
				(psec->get_type() == SHT_FINI_ARRAY)
			)
		)
        {
			claimed_sections[i] = true;
			prg_sect[no_sect].type = SECT_TEXT;
            prg_sect[no_sect].offset = file_offset;                     // Mark start offset of section inside .prg
            prg_sect[no_sect].size = (uint32_t)psec->get_size();        // Mark section's size
            prg_sect[no_sect].data = (const char *)psec->get_data();    // Mark section's start of data

			// record section bounds (and index) in a map of <startaddr/index> pairs using endaddr as the sort key,
			// for identity queries using reloc addresses. this way we can identify & bounds-check the owning 
			// section and identify it from a single query address.
			elfsectionboundsmap[psec->get_address() + psec->get_size()] = std::pair<uint32_t, int>(psec->get_address(), i);		

            file_offset += (uint32_t)psec->get_size();                  // Update prg offset
            toshead.PRG_tsize += (uint32_t)psec->get_size();            // Update prg text size
            section_map[i] = no_sect;                                   // Mark where in prg_sect this section will lie
			std::cout << "record [" << psec->get_name() << "] esi:" << i << " tsi:" << no_sect << " fbeg:" << (prg_sect[no_sect].offset) << " fend:" << file_offset << std::endl;
            no_sect++;
        }
    }

    // Group data segments and determine their position inside the output file
    for ( int i = 0; i < sec_num; i++ )
    {
		if (claimed_sections[i]) continue;
        psec = reader.sections[i];
        if (psec->get_type() == SHT_PROGBITS && (psec->get_flags() & SHF_ALLOC)
                /*psec->get_name() == ".data"*/)
        {
			claimed_sections[i] = true;
			prg_sect[no_sect].type = SECT_DATA;
            prg_sect[no_sect].offset = file_offset;                     // Mark start offset of section inside .prg
            prg_sect[no_sect].size = (uint32_t)psec->get_size();        // Mark section's size
            prg_sect[no_sect].data = (const char *)psec->get_data();    // Mark section's start of data

			// record section bounds (and index) in a map of <startaddr/index> pairs using endaddr as the sort key,
			// for identity queries using reloc addresses. this way we can identify & bounds-check the owning 
			// section and identify it from a single query address.
			elfsectionboundsmap[psec->get_address() + psec->get_size()] = std::pair<uint32_t, int>(psec->get_address(), i);		
	
			file_offset += (uint32_t)psec->get_size();                  // Update prg offset
            toshead.PRG_dsize += (uint32_t)psec->get_size();            // Update prg data size
            section_map[i] = no_sect;                                   // Mark where in prg_sect this section will lie
			std::cout << "record [" << psec->get_name() << "] esi:" << i << " tsi:" << no_sect << " fbeg:" << (prg_sect[no_sect].offset) << " fend:" << file_offset << std::endl;
            no_sect++;
        }
    }

    // Group BSS segments and determine their position inside the output file
    for ( int i = 0; i < sec_num; i++ )
    {
		if (claimed_sections[i]) continue;
        psec = reader.sections[i];
        if (psec->get_type() == SHT_NOBITS)
        {
			claimed_sections[i] = true;
			prg_sect[no_sect].type = SECT_BSS;
            prg_sect[no_sect].offset = file_offset;                     // Mark start offset of section inside .prg
            prg_sect[no_sect].size = (uint32_t)psec->get_size();        // Mark section's size

			// record section bounds (and index) in a map of <startaddr/index> pairs using endaddr as the sort key,
			// for identity queries using reloc addresses. this way we can identify & bounds-check the owning 
			// section and identify it from a single query address.
			elfsectionboundsmap[psec->get_address() + psec->get_size()] = std::pair<uint32_t, int>(psec->get_address(), i);			
			
			file_offset += (uint32_t)psec->get_size();                  // Update prg offset

			toshead.PRG_bsize += (uint32_t)psec->get_size();            // Update prg bss size
			section_map[i] = no_sect;                                   // Mark where in prg_sect this section will lie
			std::cout << "record [" << psec->get_name() << "] esi:" << i << " tsi:" << no_sect << " fbeg:" << (prg_sect[no_sect].offset) << " fend:" << file_offset << std::endl;
            no_sect++;
        }
    }

    // Perform any relocations that may be needed
    //section *psec_reloc;
    for ( int i = 0; i < sec_num; i++ )
    {
        psec = reader.sections[i];
        std::string sectname = psec->get_name();                        // Debug
  //      int test1 = sectname.find(".text");                             // Check if this is a text relocation segment
  //      int test2 = sectname.find(".data");                             // Check if this is a data relocation segment
        if (psec->get_type() == SHT_RELA /*&& (test1 > 0 || test2 > 0)*/)
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
                    if (DEBUG)
                    {
                        std::cout << "Reloc " << j 
								  << " in section " << i << " [" << psec->get_name() << "]"
								  << " offset:" << offset 
								  << " symval:" << symbolValue 
								  << " sym:" << symbolName
								  << " type:" << type 
								  << " addend:" << addend
								  << " calc:" << calcValue 
								  << std::endl;
                    }
                    // TODO: Ok, we need to mark which section this relocation
                    // is refering to. For now we're going to blindly assume that it
                    // refers to the previous one as they usually go in pairs
                    // (.text / .rela.text). If this is bad then well, this is what
                    // to change!
					assert(i > 0);
					assert(section_map[i - 1] >= 0);
                    tos_relocs[no_relocs].elfsection = i - 1;
                    tos_relocs[no_relocs].tossection = section_map[i - 1];
                    tos_relocs[no_relocs].offset_fixup = (uint32_t)offset;
					tos_relocs[no_relocs].elfsymaddr = calcValue;// symbolValue;
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
                    std::cout << "Section" << i <<
                              ": 16-bit relocations not allowed (apparently)"
                              << std::endl;
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

    if (SYMTABLE)
    {
        for ( int i = 0; i < sec_num; i++ )
        {
            psec = reader.sections[i];
            if (psec->get_type() == SHT_SYMTAB)
            {
                //prg_sect[no_sect].type=SECT_BSS;
                //prg_sect[no_sect].offset=file_offset;
                //prg_sect[no_sect].reloc_needed=false;
                //bss_size+=psec->get_size();
                //no_sect++;
            }
        }
    }

    // Print some basic info
    std::cout << "Text size: " << /*hex << */ toshead.PRG_tsize << std::endl <<
              "Data size:" << toshead.PRG_dsize << std::endl <<
              "BSS size:" << toshead.PRG_bsize << std::endl;

    // Open output file and write things
    FILE *tosfile = fopen(outfile, "w+b");


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
    }

	// shove all reloc indices in a map, using the address as the sort key
	// (equivalent to a tree-insert-sort)
	typedef std::map<uint32_t, int> relocmap_t;
	relocmap_t relocmap;
	for (int r = 0; r < no_relocs; r++)
	{
		// compute reloc address
		section *psec = reader.sections[tos_relocs[r].elfsection];
		uint32_t esa = psec->get_address();
		uint32_t tsa = prg_sect[tos_relocs[r].tossection].offset;

		uint32_t tosreloc_file = tos_relocs[r].offset_fixup - esa + tsa;
		uint32_t tosreloc_mem = tosreloc_file - 28;

		// make sure only one reloc for each address!
		assert(relocmap.find(tosreloc_mem) == relocmap.end());

		// index of this reloc address
		relocmap[tosreloc_mem] = r;
	}

	if (no_relocs > 0)
	{
		fflush(tosfile);
		long sv = ftell(tosfile);

		// sorted map of reloc indices
		relocmap_t::iterator it = relocmap.begin();

		while (it != relocmap.end())
		{
			int r = it->second; it++;

			section *psec = reader.sections[tos_relocs[r].elfsection];
			uint32_t esa = psec->get_address();
			uint32_t tsa = prg_sect[tos_relocs[r].tossection].offset;

			uint32_t tosreloc_file = tos_relocs[r].offset_fixup - esa + tsa;
			uint32_t tosreloc_mem = tosreloc_file - 28;

			printf("esa:%x, tsa:%x, osf:%x, tosreloc:%x\n", esa, tsa, tos_relocs[r].offset_fixup, tosreloc_mem);

			// adjust the original reloc value to cope with section output rearrangement (ELF->TOS)
			// since the automatic part of the relocation is a shared base address only. we're upsetting 
			// relocs on an individual (or at least per-section) basis so they need more fine-grained repair.
			if (1)
			{
				// extract the original reloc data
				fseek(tosfile, (long)tosreloc_file, 0);
				fread(relo_data, 1, 4, tosfile);
				uint32_t reference = BYTESWAP32(relo_data[0]);

				reference = tos_relocs[r].elfsymaddr;

				// find ELF section this reference belongs to (section with lower bound <= query address)
				elfsectionboundsmap_t::iterator reference_bound = elfsectionboundsmap.upper_bound(reference);
				// make sure it refers to a section we actually kept
				assert(reference_bound != elfsectionboundsmap.end());
				// make sure the reference is actually inside the nearest section (i.e. not < section startaddr) pair<[startaddr],index>
				assert(reference >= reference_bound->second.first);
				// get ELF section index pair<endaddr,[index]>
				int reference_elfidx = reference_bound->second.second;
				assert(section_map[reference_elfidx] >= 0);
				// base address of original elf section bounding the reference
				uint32_t reference_esa = reader.sections[reference_elfidx]->get_address();
				// base address of new tos section bounding the reference
				uint32_t reference_tsa = prg_sect[section_map[reference_elfidx]].offset - 28;

/*
// we don't need this unless we have to relocate XX.l(PC) relative between two sections \o/
				uint32_t relocsite = tos_relocs[r].offset_fixup;
				// find ELF section this reference belongs to (sectirefeon with lower bound <= query address)
				elfsectionboundsmap_t::iterator relocsite_bound = elfsectionboundsmap.upper_bound(relocsite);
				// make sure it refers to a section we actually kept
				assert(relocsite_bound != elfsectionboundsmap.end());
				// make sure the reference is actually inside the nearest section (i.e. not < section startaddr) pair<[startaddr],index>
				assert(relocsite >= relocsite_bound->second.first);
				// get ELF section index pair<endaddr,[index]>
				int relocsite_elfidx = relocsite_bound->second.second;
				assert(section_map[relocsite_elfidx] >= 0);
				// base address of original elf section bounding the reference
				uint32_t relocsite_esa = reader.sections[relocsite_elfidx]->get_address();
				// base address of new tos section bounding the reference
				uint32_t relocsite_tsa = prg_sect[section_map[relocsite_elfidx]].offset - 28;
*/


				printf("reloc references: ea:%x esec:%s ess:%x ese:%x\n", 
					reference, 
					reader.sections[reference_elfidx]->get_name().c_str(), 
					reference_bound->second.first, 
					reference_bound->first
				);

				// adjust the relocation to compensate for section rearrangement
				reference = reference - reference_esa + reference_tsa;
				
				//if (relocsite_elfidx == reference_elfidx)
				//{
				//	// if the relocation refers to same section, apply relocsite adjustment to reference
				//	reference = reference - relocsite_esa + relocsite_tsa;
				//}
				//else
				//{
				//	// if the relocation crosses section bounaries, apply adjustment to reference
				//	reference = reference - reference_esa + reference_tsa;
				//}

				// store the updated reloc data
				relo_data[0] = BYTESWAP32(reference);
				fseek(tosfile, (long)tosreloc_file, 0);
				fwrite(relo_data, 1, 4, tosfile);
			}
		}
		fseek(tosfile, sv, 0);
	}
	
    // Write relocation table
	if (no_relocs > 0)
    {
		// sorted map of reloc indices
		relocmap_t::iterator it = relocmap.begin();


		uint32_t current_reloc;
		uint32_t next_reloc;
		uint32_t diff;
		uint8_t temp;
		uint32_t temp_byteswap;
		// Handle first relocation separately as
		// the offset needs to be a longword.
				
		// get first address-sorted reloc index
		current_reloc = it->first;
		int ri = it->second; it++;

//		current_reloc = tos_relocs[ri].offset_fixup;
		temp_byteswap = BYTESWAP32(current_reloc);
		fwrite(&temp_byteswap, 4, 1, tosfile);
		for (int i = 1; i < no_relocs; i++)
		{
			// get next address-sorted reloc index
			next_reloc = it->first;
			int ri = it->second; it++;

//			next_reloc = tos_relocs[ri].offset_fixup;
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



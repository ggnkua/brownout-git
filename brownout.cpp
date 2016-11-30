/*

brownout - A humble .elf to ST .prg binary converter

Written by George Nakos and Douglas Litte.

Uses the elfio library by Serge Lamikhov-Center to do the
heavy lifting that is ELF parsing. Also used elfdump.cpp
from the examples folder as the basis for this source.
See elfio.hpp for its license.

Command line parsing uses simpleopt by Brodie Thiesfield.
See SimpleOpt.h for its license.

Everything else is released under the WTFPL. Probably.

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

// better at catching things early inside VS debugger
//#define assert(_x_) { if (!(_x_)) { __asm int 3 }; }

void demangle(std::string &name, std::string &demangled);

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
    OPT_DEBUG,
    OPT_DEMANGLE,
    OPT_EXTEND
};

CSimpleOpt::SOption g_rgOptions[] =
{
    { OPT_INFILE,               _T("-i"),     SO_REQ_SEP },
    { OPT_OUTFILE,              _T("-o"),     SO_REQ_SEP },
    { OPT_PRGFLAGS,             _T("-p"),     SO_REQ_SEP },
    { OPT_SYMTABLE,             _T("-s"),     SO_NONE    },
    { OPT_DEBUG,                _T("-d"),     SO_NONE    },
    { OPT_EXTEND,               _T("-x"),     SO_NONE    },
    { OPT_DEMANGLE,             _T("-f"),     SO_NONE    },
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
            "-s will create a symbol table.\n"
            "-d will turn on verbose debugging.\n"
            "-f will turn off C++ symbol demangling (i.e. you get ugly symbol names).\n");
}

    typedef struct
    {
		uint32_t offset_fixup;					// Offset inside the section
		uint32_t elfsymaddr;
        int elfsection;								// Which section we're on
		int tossection;

    } TOS_RELOC;

TOS_RELOC tos_relocs[100 * 1024];                // Enough? Who knows!

typedef struct
{
    char name[8];
    uint16_t type;
    uint32_t value;
} GST_SYMBOL;

GST_SYMBOL symtab[100 * 1024];  // Enough? Who knows!

typedef struct
{
    int         type;       // Type of section (see enum below)
    uint32_t    offset;     // Offset of section inside the TOS PRG
    uint32_t    size;       // Original size of section
    uint32_t    padded_size;    // Size of section with even padding
    const char  *data;      // Points to the start of the actual section data
    uint32_t    sect_start; // address of section start inside the elf
    uint32_t    sect_end;   // address of section end inside the elf
} ST_SECTION;

enum
{
    SECT_TEXT,
    SECT_DATA,
    SECT_BSS
};

enum
{
    SYM_NONE,
    SYM_DRI,
    SYM_EXTEND
};
			
uint32_t relo_data[1];

int _tmain(int argc, TCHAR * argv[])
{

    PRG_HEADER toshead = {0x601a, 0, 0, 0, 0, 0, 0, 0};  // Set up TOS header

    // declare our options parser, pass in the arguments from main
    // as well as our array of valid options.
    CSimpleOpt args(argc, argv, g_rgOptions);
    char infile[1024];
    char outfile[1024];
    bool DEBUG = false;
    int SYMTABLE = SYM_NONE;
    bool DEMANGLE = true;

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
                SYMTABLE = SYM_DRI;
            }
            else if (args.OptionId() == OPT_EXTEND)
            {
                SYMTABLE = SYM_EXTEND;
            }
            else if (args.OptionId() == OPT_DEMANGLE)
            {
                DEMANGLE = false;
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

    // From here on starts the browness - helmets on!

    Elf_Half sec_num = reader.sections.size();

	typedef std::map<uint32_t, std::pair<uint32_t, int> > elfsectionboundsmap_t;
	elfsectionboundsmap_t elfsectionboundsmap;

    int no_relocs = 0;

    uint32_t file_offset = 28;                       // Mostly used to calculate the offset of the BSS section inside the .prg
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

	std::cout << "performing section layout..." << std::endl;

	// inject link section in front of everything, which links to real entrypoint
	// since ELF has its entrypoint in the header

	char injected_link_section[] =
	{
		0x60,0x00,
		0x00,0x00
	};

	{
            prg_sect[no_sect].type = SECT_TEXT;
            prg_sect[no_sect].offset = file_offset;
            prg_sect[no_sect].size = 4;
            prg_sect[no_sect].padded_size = 4;
            prg_sect[no_sect].data = (const char *)injected_link_section;
			prg_sect[no_sect].sect_start = 0;
			prg_sect[no_sect].sect_end = 0;
			
            file_offset += 4;
            toshead.PRG_tsize += 4;
			std::cout << "record [.tos_entrypoint] tsi:" << no_sect << " fbeg:" << (prg_sect[no_sect].offset) << " fend:" << file_offset << std::endl;
            no_sect++;
	}

    for ( int i = 0; i < sec_num; i++ )
    {
		if (claimed_sections[i]) continue;
        psec = reader.sections[i];
		if ((psec->get_type() == SHT_PROGBITS) && 
			(psec->get_name() == ".boot") &&
			(psec->get_size() > 0))
        {
			claimed_sections[i] = true;
            prg_sect[no_sect].type = SECT_TEXT;
            prg_sect[no_sect].offset = file_offset;                     // Mark start offset of section inside .prg
            prg_sect[no_sect].size = (uint32_t)psec->get_size();        // Mark section's size
            prg_sect[no_sect].padded_size = (prg_sect[no_sect].size + 1) & 0xfffffffe; // Pad section size so it will be even if needed
            prg_sect[no_sect].data = (const char *)psec->get_data();    // Mark section's start of data
            prg_sect[no_sect].sect_start = (uint32_t)psec->get_address();   // Mark elf section's start (for symbol outputting)
            prg_sect[no_sect].sect_end = (uint32_t)psec->get_address() + (uint32_t)psec->get_size(); // Mark elf section's end (for symbol outputting)

			// record section bounds (and index) in a map of <startaddr/index> pairs using endaddr as the sort key,
			// for identity queries using reloc addresses. this way we can identify & bounds-check the owning 
			// section and identify it from a single query address.
			elfsectionboundsmap[psec->get_address() + psec->get_size()] = std::pair<uint32_t, int>(psec->get_address(), i);		

            file_offset += prg_sect[no_sect].padded_size;               // Update prg BSS offset
            toshead.PRG_tsize += prg_sect[no_sect].padded_size;         // Update prg text size
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
			(
			(psec->get_flags() & SHF_EXECINSTR) ||			
			(
				(psec->get_type() == SHT_INIT_ARRAY) ||
				(psec->get_type() == SHT_PREINIT_ARRAY) ||
				(psec->get_type() == SHT_FINI_ARRAY)
			)
		)
			&& (psec->get_size() > 0)
			&& (psec->get_name().find(".debug_") == std::string::npos)
		)
        {
			claimed_sections[i] = true;
            prg_sect[no_sect].type = SECT_TEXT;
            prg_sect[no_sect].offset = file_offset;                     // Mark start offset of section inside .prg
            prg_sect[no_sect].size = (uint32_t)psec->get_size();        // Mark section's size
            prg_sect[no_sect].padded_size = (prg_sect[no_sect].size + 1) & 0xfffffffe; // Pad section size so it will be even if needed
            prg_sect[no_sect].data = (const char *)psec->get_data();    // Mark section's start of data
            prg_sect[no_sect].sect_start = (uint32_t)psec->get_address();   // Mark elf section's start (for symbol outputting)
            prg_sect[no_sect].sect_end = (uint32_t)psec->get_address() + (uint32_t)psec->get_size(); // Mark elf section's end (for symbol outputting)

			// record section bounds (and index) in a map of <startaddr/index> pairs using endaddr as the sort key,
			// for identity queries using reloc addresses. this way we can identify & bounds-check the owning 
			// section and identify it from a single query address.
			elfsectionboundsmap[psec->get_address() + psec->get_size()] = std::pair<uint32_t, int>(psec->get_address(), i);		

            file_offset += prg_sect[no_sect].padded_size;               // Update prg BSS offset
            toshead.PRG_tsize += prg_sect[no_sect].padded_size;         // Update prg text size
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
        if ((psec->get_type() == SHT_PROGBITS) && 
			(psec->get_flags() & SHF_ALLOC) &&
			(psec->get_size() > 0) &&
			(psec->get_name().find(".debug_") == std::string::npos)
		)
        {
			claimed_sections[i] = true;
            prg_sect[no_sect].type = SECT_DATA;
            prg_sect[no_sect].offset = file_offset;                     // Mark start offset of section inside .prg
            prg_sect[no_sect].size = (uint32_t)psec->get_size();        // Mark section's size
            prg_sect[no_sect].padded_size = (prg_sect[no_sect].size + 1) & 0xfffffffe; // Pad section size so it will be even if needed
            prg_sect[no_sect].data = (const char *)psec->get_data();    // Mark section's start of data

			// record section bounds (and index) in a map of <startaddr/index> pairs using endaddr as the sort key,
			// for identity queries using reloc addresses. this way we can identify & bounds-check the owning 
			// section and identify it from a single query address.
			elfsectionboundsmap[psec->get_address() + psec->get_size()] = std::pair<uint32_t, int>(psec->get_address(), i);		
	
            prg_sect[no_sect].sect_start = (uint32_t)psec->get_address();   // Mark elf section's start (for symbol outputting)
            prg_sect[no_sect].sect_end = (uint32_t)psec->get_address() + (uint32_t)psec->get_size(); // Mark elf section's end (for symbol outputting)
            file_offset += prg_sect[no_sect].padded_size;               // Update prg BSS offset
            toshead.PRG_dsize += prg_sect[no_sect].padded_size;         // Update prg data size
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
        if ((psec->get_type() == SHT_NOBITS) &&
			(psec->get_size() > 0) &&
			(psec->get_name().find(".debug_") == std::string::npos)
		)
        {
			claimed_sections[i] = true;
            prg_sect[no_sect].type = SECT_BSS;
            prg_sect[no_sect].offset = file_offset;                     // Mark start offset of section inside .prg
            prg_sect[no_sect].size = (uint32_t)psec->get_size();        // Mark section's size

			// record section bounds (and index) in a map of <startaddr/index> pairs using endaddr as the sort key,
			// for identity queries using reloc addresses. this way we can identify & bounds-check the owning 
			// section and identify it from a single query address.
			elfsectionboundsmap[psec->get_address() + psec->get_size()] = std::pair<uint32_t, int>(psec->get_address(), i);			
			
            prg_sect[no_sect].padded_size = (prg_sect[no_sect].size + 1) & 0xfffffffe; // Pad section size so it will be even if needed
            prg_sect[no_sect].sect_start = (uint32_t)psec->get_address();   // Mark elf section's start (for symbol outputting)
            prg_sect[no_sect].sect_end = (uint32_t)psec->get_address() + (uint32_t)psec->get_size(); // Mark elf section's end (for symbol outputting)
			file_offset += (uint32_t)psec->get_size();                  // Update prg offset
            toshead.PRG_bsize += prg_sect[no_sect].padded_size;            // Update prg bss size
			section_map[i] = no_sect;                                   // Mark where in prg_sect this section will lie
			std::cout << "record [" << psec->get_name() << "] esi:" << i << " tsi:" << no_sect << " fbeg:" << (prg_sect[no_sect].offset) << " fend:" << file_offset << std::endl;
            no_sect++;
        }
    }

    // Print some basic info
    std::cout << 
		"TEXT size: " << toshead.PRG_tsize << std::endl <<
		"DATA size:" << toshead.PRG_dsize << std::endl <<
              "BSS size:" << toshead.PRG_bsize << std::endl;

	std::cout << "processing relocation entries..." << std::endl;

	uint32_t entrypoint_reference = reader.get_entry();

	{

		if (1)
		{
			std::cout << "hunting entrypoint symbol..." << std::endl;

			for (int si = 0; si < sec_num; si++)
			{
				psec = reader.sections[si];
				if (psec->get_type() == SHT_SYMTAB)
				{
					symbol_section_accessor symbols( reader, psec );

					Elf_Xword sym_no = symbols.get_symbols_num();

					if (sym_no > 0)
					{
						int remaining = 1;
						for (Elf_Half i = 0; (i < sym_no) && (remaining > 0); ++i)
						{
							std::string   name;
							Elf64_Addr    value   = 0;
							Elf_Xword     size    = 0;
							unsigned char bind    = 0;
							unsigned char type    = 0;
							Elf_Half      section = 0;
							unsigned char other   = 0;
							symbols.get_symbol( i, name, value, size, bind, type, section, other );

							// Check binding type
							switch (bind)
							{
								case STB_LOCAL:
								case STB_WEAK:
								case STB_GLOBAL:
								{
									// Section 65521 is (probably) the section for absolute labels
									//if (section == 65521)
									//{
									//}
									//else
									{
										if ((name.compare("_start") == 0) ||
											(name.compare("__start") == 0))
										{
											entrypoint_reference = value;
											remaining--;
											break;
										}
									}
									break;
								}
								default:
								{
									// Do nothing?
									break;
								}
							}
						}
					}
				}
			}
		}

		// find ELF section this reference belongs to (section with lower bound <= query address)
		elfsectionboundsmap_t::iterator reference_bound = elfsectionboundsmap.upper_bound(entrypoint_reference);
		// make sure it refers to a section we actually kept
		assert(reference_bound != elfsectionboundsmap.end());
		// make sure the reference is actually inside the nearest section (i.e. not < section startaddr) pair<[startaddr],index>
		assert(entrypoint_reference >= reference_bound->second.first);
		// get ELF section index pair<endaddr,[index]>
		int reference_elfidx = reference_bound->second.second;
		assert(section_map[reference_elfidx] >= 0);
		// base address of original elf section bounding the reference
		uint32_t reference_esa = reader.sections[reference_elfidx]->get_address();
		// base address of new tos section bounding the reference
		uint32_t reference_tsa = prg_sect[section_map[reference_elfidx]].offset - 28;

		entrypoint_reference = entrypoint_reference - reference_esa + reference_tsa;

		uint32_t branch_offset = entrypoint_reference - 2;

		injected_link_section[2] = (branch_offset >> 8) & 0xFF;
		injected_link_section[3] = (branch_offset >> 0) & 0xFF;
	}


    // Perform any relocations that may be needed
    //section *psec_reloc;
    for ( int i = 0; i < sec_num; i++ )
    {
        psec = reader.sections[i];
        std::string sectname = psec->get_name();                        // Debug
        if (
		(psec->get_type() == SHT_RELA) &&
		(psec->get_name().find(".debug_") == std::string::npos)
	)
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
                // So, before we forget what variable does what,
                // let's add an example to illustrate them.
                // Assume there's this code here:
                // 2c98:	47f9 0005 6c56 	lea 56c56 <_s_entity_links+0x4>,a3
                // Obviously the address _s_entity_links+0x4 needs to be
                // relocated. For this we need:
                // a) The offset into the section that contains the longword
                //    to be patched. This is provided by "offset".
                // b) The address of _s_entity_links. This is provided by "symbolValue".
                // c) The value to patch into the offset. This is provided by "calcValue.
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
                    assert(i >= 0);
					if (section_map[i - 1] >= 0)
					{
						assert((offset & 1) == 0);
                    assert(section_map[i - 1] >= 0);

                    if ((offset&1)==1)
                    {
                        // Now here's an odd one. We are asked to relocate
                        // a symbol that lies at an odd address. "That's absurd,
                        // it shouldn't happen" you say? Well guess what, we got
                        // bit by this exact issue while linking some libraries
                        // that had some weird exception handling code.
                        std::cout << "Fatal error: ELF file contains relocation that points "
                                << "to symbol \"" << symbolName << "\" from an odd address"
                                << " (" << offset << ")!" << std::endl
                                << "brownout cannot produce a valid TOS executable under"
                                << " these circumstances. Please correct the issue."
                                << std::endl;
                                exit(0);

                    }

                    tos_relocs[no_relocs].elfsection = i - 1;
                    tos_relocs[no_relocs].tossection = section_map[i - 1];
                    tos_relocs[no_relocs].offset_fixup = (uint32_t)offset;
					tos_relocs[no_relocs].elfsymaddr = calcValue;// symbolValue;
                    no_relocs++;
					}
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
                    std::cout << "Section" << i <<
                              ": 16-bit relocations not allowed (apparently)"
                              << std::endl;                    break;
                }
                default:
                {
                    break;
                }
                }
            }
        }
    }

	
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

    int no_sym = 0;

    if (SYMTABLE)
    {
		std::cout << "generating symbol table..." << std::endl;

        for ( int i = 0; i < sec_num; i++ )
        {
            psec = reader.sections[i];
            if (psec->get_type() == SHT_SYMTAB /* || psec->get_type() == SHT_DYNSYM */)
            {
                symbol_section_accessor symbols( reader, psec );

                Elf_Xword     sym_no = symbols.get_symbols_num();

                if ( sym_no > 0 )
                {

					for (Elf_Half i = 0; i < sym_no; ++i)
					{
						char gst_name[25] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
							0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
							0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
							0x0 };
						std::string   name;
						Elf64_Addr    value = 0;
						Elf_Xword     size = 0;
						unsigned char bind = 0;
						unsigned char type = 0;
						Elf_Half      section = 0;
						unsigned char other = 0;
						symbols.get_symbol(i, name, value, size, bind, type, section, other);

						if (DEMANGLE)
						{
							bool wasmangled = false;
							// only try to demangle valid symbols
							if (name.length() > 0)
							{
								if (name.find("_Z") < 2)
								{

									std::string nameout;
									std::string namein(name);
									demangle(namein, nameout);

									bool demangled =
										(nameout.length() > 0) &&
										((namein.length() != nameout.length()) ||
										(namein.compare(nameout) != 0));

									// if demangle failed, output symbol will be the input symbol
									// so check for underscore and retry with underscore trimmed ($%^$%^ underscores!!!)
									while (
										(namein[0] == '_') &&
										!demangled
										)
									{
										namein = namein.substr(1, namein.length() - 1);
										demangle(namein, nameout);

										demangled =
											(nameout.length() > 0) &&
											((namein.length() != nameout.length()) ||
											(namein.compare(nameout) != 0));
									}

									if (demangled)
									{
										if (DEBUG)
										{
											std::cout << "demangled: " << nameout << " [" << name << "] with value " << value << std::endl;
										}

										name = nameout;
										wasmangled = true;
									}
								}

								if (DEBUG)
								{
									if (!wasmangled)
										std::cout << "symbol: " << name << " with value " << value << std::endl;
								}
							}
						}

						{
							// filter illegal/annoying stuff out of symbols
							std::string name_filtered;
							for (std::string::iterator it = name.begin(); it != name.end(); it++)
							{
								char c = *it;
								if ((c >= 32) && (c < 127))
								{
									switch (c)
									{
									case ' ': c = 0; break;
									//case '!': c = 0; break;
									case '"': c = 0; break;
									//case '#': c = 0; break;
									//case '$': c = 0; break;
									//case '%': c = 0; break;
									//case '\'': c = 0; break;
									case '`': c = 0; break;
									//case '/': c = 0; break;
									//case '\\': c = 0; break;
									//case ';': c = 0; break;
									//case '?': c = 0; break;
									//case '@': c = 0; break;
									default:
										break;
									}
									if (c)
										name_filtered.push_back(c);
								}
							}
							name = name_filtered;
						}

						strcpy(gst_name, name.substr(0, 24).c_str());
                        // Skip null names
                        if (gst_name[0] == NULL)
                            continue;

                        // Check binding type
                        switch (bind)
                        {
                        case STB_LOCAL:
                        case STB_WEAK:
                        case STB_GLOBAL:
                        {
                            // Section 65521 is (probably) the section for absolute labels
                            if (section == 65521 && value != 0)
                            {
                                if (SYMTABLE == SYM_DRI || (SYMTABLE==SYM_EXTEND && strlen(gst_name)<=8))
                                {
                                    memcpy(symtab[no_sym].name, gst_name, 8);
                                    symtab[no_sym].type = 0x2000;           // GLOBAL
                                    symtab[no_sym].value = (uint32_t)value;
                                }
                                else
                                {
                                    memcpy(symtab[no_sym].name, gst_name, 8);
                                    symtab[no_sym].type = 0x2048;           // GLOBAL + continued on next symbol
                                    symtab[no_sym].value = (uint32_t)value;
                                    no_sym++;
                                    memcpy(&symtab[no_sym], &gst_name[8], 14);  // Extended mode - copy 1 more symbol's worth of chars in the next symbol
                                    no_sym++;                                
                                }
                            }
                            else if (section == 65521 && value == 0)
                            {
                                break;
                            }
                            else
                            {
                                // Bounds checking to see which segment it belongs
                                for (int j = 0; j < no_sect; j++)
                                {
                                    if (value >= prg_sect[j].sect_start && value <= prg_sect[j].sect_end)
                                    {
                                        switch (prg_sect[j].type)
                                        {
                                        case SECT_TEXT:
                                            if (SYMTABLE == SYM_DRI || (SYMTABLE==SYM_EXTEND && strlen(gst_name)<=8))
                                            {
                                                symtab[no_sym].type = 0x8200; //TEXT + defined
                                                symtab[no_sym].value = (uint32_t)value - prg_sect[j].sect_start + prg_sect[j].offset - 28;
                                                memcpy(symtab[no_sym].name, gst_name, 8);
                                                no_sym++;
                                                break;
                                            }
                                            else
                                            {
                                                symtab[no_sym].value = (uint32_t)value - prg_sect[j].sect_start + prg_sect[j].offset - 28;
                                                memcpy(symtab[no_sym].name, gst_name, 8);
                                                symtab[no_sym].type = 0x8248; //TEXT + defined + continued on next symbol
                                                no_sym++;
                                                memcpy(&symtab[no_sym], &gst_name[8], 14);  // Extended mode - copy 1 more symbol's worth of chars in the next symbol
                                                no_sym++;
                                                break;
                                            }
                                        case SECT_DATA:
                                            if (SYMTABLE == SYM_DRI || (SYMTABLE==SYM_EXTEND && strlen(gst_name)<=8))
                                            {
                                                symtab[no_sym].value = (uint32_t)value - prg_sect[j].sect_start + prg_sect[j].offset - 28;
                                                memcpy(symtab[no_sym].name, gst_name, 8);
                                                symtab[no_sym].type = 0x8400; //DATA + defined
                                                no_sym++;
                                                break;
                                                }
                                            else
                                            {
                                                symtab[no_sym].value = (uint32_t)value - prg_sect[j].sect_start + prg_sect[j].offset - 28;
                                                memcpy(symtab[no_sym].name, gst_name, 8);
                                                symtab[no_sym].type = 0x8248; //DATA + defined + continued on next symbol
                                                no_sym++;
                                                memcpy(&symtab[no_sym], &gst_name[8], 14);  // Extended mode - copy 1 more symbol's worth of chars in the next symbol
                                                no_sym++;
                                                break;
                                            }
                                        case SECT_BSS:
                                            if (SYMTABLE == SYM_DRI || (SYMTABLE==SYM_EXTEND && strlen(gst_name)<=8))
                                            {
                                                symtab[no_sym].value = (uint32_t)value - prg_sect[j].sect_start + prg_sect[j].offset - 28;
                                                memcpy(symtab[no_sym].name, gst_name, 8);
                                                symtab[no_sym].type = 0x8100; //BSS + defined
                                                no_sym++;
                                                break;
                                            }
                                            else
                                            {
                                                symtab[no_sym].value = (uint32_t)value - prg_sect[j].sect_start + prg_sect[j].offset - 28;
                                                memcpy(symtab[no_sym].name, gst_name, 8);
                                                symtab[no_sym].type = 0x8248; //BSS + defined + continued on next symbol
                                                no_sym++;
                                                memcpy(&symtab[no_sym], &gst_name[8], 14);  // Extended mode - copy 1 more symbol's worth of chars in the next symbol
                                                no_sym++;
                                                break;
                                            }
                                        default:
                                            // Probably do nothing?
                                            break;
                                        }
                                        continue;
                                    }
                                }
                            }

                            break;
                        }
                        //case STB_GLOBAL:
                        //{
                        //    // Section 65521 is (probably) the section for absolute labels
                        //    if (section == 65521 && value != 0)
                        //    {
                        //        strcpy(symtab[no_sym].name, gst_name);
                        //        symtab[no_sym].type = 0x2000;
                        //        symtab[no_sym].value = (uint32_t)value;
                        //    }
                        //    else
                        //    {
                        //        for (int j = 0; j < no_sect; j++)
                        //        {
                        //            if (value >= prg_sect[j].sect_start && value <= prg_sect[j].sect_end)
                        //            {
                        //                strcpy(symtab[no_sym].name, gst_name);
                        //                symtab[no_sym].type = 0x2000;
                        //                symtab[no_sym].value = (uint32_t)value - prg_sect[j].sect_start + prg_sect[j].offset;
                        //                no_sym++;
                        //                break;
                        //            }
                        //        }
                        //    }
                        //    break;
                        //}
                        case STB_LOOS:
                        case STB_HIOS:
                        case STB_LOPROC:
                        case STB_HIPROC:
                        {
                            // Do nothing?
                            break;
                        }
                        }

                    }

                }

            }
        }
        toshead.PRG_ssize = no_sym * sizeof(GST_SYMBOL);
        //Byte swap table
		bool extension_follows = false;
		bool extension = false;
        for (int i = 0; i < no_sym; i++)
        {
			extension_follows = (symtab[i].type == 0x8248);

			if (!extension)
			{
				// don't swap string-extension part of extended symbol format
				symtab[i].type = BYTESWAP16(symtab[i].type);
				symtab[i].value = BYTESWAP32(symtab[i].value);
			}

			extension = extension_follows;
        }
    }

	std::cout << "emitting program data..." << std::endl;

    // Open output file and write things
    FILE *tosfile = fopen(outfile, "w+b");

    // Byte swap prg header if needed
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
            if ((prg_sect[i].size & 1) == 1)
            {
                // Odd size, add padding
                char pad = 0;
                fwrite(&pad, 1, 1, tosfile);
            }
        }
        // TODO2: For 030 executables pad sections to 4 bytes?
    }

    // write symbol table
    if (toshead.PRG_ssize != 0)
    {
		std::cout << "emitting symbol table..." << std::endl;

        fwrite(symtab, toshead.PRG_ssize, 1, tosfile);
    }


	// shove all reloc indices in a map, using the address as the sort key
	// (equivalent to a tree-insert-sort)
	if (no_relocs > 0)
		std::cout << "sorting " << no_relocs << " relocations..." << std::endl;

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
		std::cout << "correcting relocations after section layout..." << std::endl;

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

			if (DEBUG)
			{
				printf("esa:%x, tsa:%x, osf:%x, tosreloc:%x\n", esa, tsa, tos_relocs[r].offset_fixup, tosreloc_mem);
			}

			// adjust the original reloc value to cope with section output rearrangement (ELF->TOS)
			// since the automatic part of the relocation is a shared base address only. we're upsetting 
			// relocs on an individual (or at least per-section) basis so they need more fine-grained repair.
			if (1)
			{
				// extract the original reloc data
				//fseek(tosfile, (long)tosreloc_file, 0);
				//fread(relo_data, 1, 4, tosfile);
				//uint32_t freference = BYTESWAP32(relo_data[0]);

				uint32_t reference = tos_relocs[r].elfsymaddr;

				{

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

				if (DEBUG)
				{
					printf("reloc references: ea:%x esec:%s ess:%x ese:%x\n",
						reference,
						reader.sections[reference_elfidx]->get_name().c_str(),
						reference_bound->second.first,
						reference_bound->first
						);
				}

				// adjust the relocation to compensate for section rearrangement
				reference = reference - reference_esa + reference_tsa;
				}

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
		std::cout << "emitting relocation table..." << std::endl;

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

		temp_byteswap = BYTESWAP32(current_reloc);
		fwrite(&temp_byteswap, 4, 1, tosfile);
		for (int i = 1; i < no_relocs; i++)
		{
			// get next address-sorted reloc index
			next_reloc = it->first;
			int ri = it->second; it++;

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
		std::cout << "no relocation table required." << std::endl;

        // Write a null longword to express list termination
        // (as suggested by the Atari Compendium chapter 2)
        fwrite(&no_relocs, 4, 1, tosfile);
    }

    // Done writing stuff
    fclose(tosfile);

	std::cout << "done!" << std::endl;

    return 0;
}

// Execute program and grab console output
// Thanks to waqas and jotik for the snippet
// (from http://stackoverflow.com/a/478960)
// Hopefully they don't have too large unix beards.
//
#include <cstdio>
#include <iostream>
#include <memory>
//#include <stdexcept>
//#include <string>
#if defined(_MSC_VER)
#define POPEN _popen
#define PCLOSE _pclose
#else
#define POPEN popen
#define PCLOSE pclose
#endif
std::string exec(const char* cmd) {
    char buffer[128];
    std::string result = "";
    std::shared_ptr<FILE> pipe(POPEN(cmd, "r"), PCLOSE);
    if (!pipe) throw std::runtime_error("popen() failed!");
    while (!feof(pipe.get())) {
        if (fgets(buffer, 128, pipe.get()) != NULL)
            result += buffer;
    }
    return result;
}

//#include <string>
//#include <iostream>
//#include <windows.h> 
//#include <stdio.h>
//#pragma warning( disable : 4800 ) // stupid warning about bool
#define BUFSIZE 4096
HANDLE g_hChildStd_OUT_Rd = NULL;
HANDLE g_hChildStd_OUT_Wr = NULL;
HANDLE g_hChildStd_ERR_Rd = NULL;
HANDLE g_hChildStd_ERR_Wr = NULL;

PROCESS_INFORMATION CreateChildProcess(std::string &name); 
void ReadFromPipe(PROCESS_INFORMATION, std::string &demangled); 

void demangle(std::string &name, std::string &demangled)
{
    if (0)
    {
        SECURITY_ATTRIBUTES sa; 
        // Set the bInheritHandle flag so pipe handles are inherited. 
        sa.nLength = sizeof(SECURITY_ATTRIBUTES); 
        sa.bInheritHandle = TRUE; 
        sa.lpSecurityDescriptor = NULL; 
        // Create a pipe for the child process's STDERR. 
        if ( ! CreatePipe(&g_hChildStd_ERR_Rd, &g_hChildStd_ERR_Wr, &sa, 0) ) {
            exit(1); 
        }
        // Ensure the read handle to the pipe for STDERR is not inherited.
        if ( ! SetHandleInformation(g_hChildStd_ERR_Rd, HANDLE_FLAG_INHERIT, 0) ){
            exit(1);
        }
        // Create a pipe for the child process's STDOUT. 
        if ( ! CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &sa, 0) ) {
            exit(1);
        }
        // Ensure the read handle to the pipe for STDOUT is not inherited
        if ( ! SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0) ){
            exit(1); 
        }
        // Create the child process. 
        PROCESS_INFORMATION piProcInfo = CreateChildProcess(name);

        // Read from pipe that is the standard output for child process. 
        ReadFromPipe(piProcInfo, demangled);
    }

    demangled=exec(((std::string)"m68k-ataribrown-elf-c++filt " + name).c_str());

	// trim control characters from response
	if (demangled.length() > 0)
		while ((demangled.back() == '\n') || (demangled.back() == '\r') || (demangled.back() == ' '))
			demangled.pop_back();

    // The remaining open handles are cleaned up when this process terminates. 
    // To avoid resource leaks in a larger application, 
    //   close handles explicitly.
} 

// Create a child process that uses the previously created pipes
//  for STDERR and STDOUT.
PROCESS_INFORMATION CreateChildProcess(std::string &name)
{
	// remove superfluous underscore
	//int trim = 0;
	//if (name[0] == '_')
	//	trim = 1;
	//std::string trimmed_name = name.substr(trim, name.length() - trim);

	std::string cmd = "m68k-ataribrown-elf-c++filt -p " + name;// trimmed_name;

    // Set the text I want to run
    PROCESS_INFORMATION piProcInfo; 
    STARTUPINFO siStartInfo;
    bool bSuccess = FALSE; 

    // Set up members of the PROCESS_INFORMATION structure. 
    ZeroMemory( &piProcInfo, sizeof(PROCESS_INFORMATION) );

    // Set up members of the STARTUPINFO structure. 
    // This structure specifies the STDERR and STDOUT handles for redirection.
    ZeroMemory( &siStartInfo, sizeof(STARTUPINFO) );
    siStartInfo.cb = sizeof(STARTUPINFO); 
    siStartInfo.hStdError = g_hChildStd_ERR_Wr;
    siStartInfo.hStdOutput = g_hChildStd_OUT_Wr;
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

    // Create the child process. 
    bSuccess = CreateProcess(
		NULL, 
        (char*)cmd.c_str(),     // command line 
        NULL,          // process security attributes 
        NULL,          // primary thread security attributes 
        TRUE,          // handles are inherited 
        0,             // creation flags 
        NULL,          // use parent's environment 
        NULL,          // use parent's current directory 
        &siStartInfo,  // STARTUPINFO pointer 
        &piProcInfo);  // receives PROCESS_INFORMATION
    CloseHandle(g_hChildStd_ERR_Wr);
    CloseHandle(g_hChildStd_OUT_Wr);
    // If an error occurs, exit the application. 
    if ( ! bSuccess ) {
        exit(1);
    }
    return piProcInfo;
}

// Read output from the child process's pipe for STDOUT
// and write to the parent process's pipe for STDOUT. 
// Stop when there is no more data. 
void ReadFromPipe(PROCESS_INFORMATION piProcInfo, std::string &demangled) 
{
    DWORD dwRead; 
    CHAR chBuf[BUFSIZE];
    bool bSuccess = FALSE;
    std::string out = "", err = "";
    for (;;) { 
        bSuccess=ReadFile( g_hChildStd_OUT_Rd, chBuf, BUFSIZE, &dwRead, NULL);
        if( ! bSuccess || dwRead == 0 ) break; 

        std::string s(chBuf, dwRead);
        out += s;
    } 
    dwRead = 0;
    for (;;) { 
        bSuccess=ReadFile( g_hChildStd_ERR_Rd, chBuf, BUFSIZE, &dwRead, NULL);
        if( ! bSuccess || dwRead == 0 ) break; 

        std::string s(chBuf, dwRead);
        err += s;

    } 

	// captured stdout
	demangled = out;
}

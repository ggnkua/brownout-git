/*

brownout - A humble .elf to ST .prg binary converter

Written by George Nakos and Douglas Little.
Thanks to Troed Sångberg for the Macintosh bits.

Uses the elfio library by Serge Lamikhov-Center to do the
heavy lifting that is ELF parsing. Also used elfdump.cpp
from the examples folder as the basis for this source.
See elfio.hpp for its license.

Command line parsing uses simpleopt by Brodie Thiesfield.
See SimpleOpt.h for its license.

Everything else is released under the WTFPL. Probably.

*/

#define VERSION fawn

#define STRINGIFY2(X) #X
#define STRINGIFY(X) STRINGIFY2(X)

#ifdef _MSC_VER
#define _SCL_SECURE_NO_WARNINGS
#define ELFIO_NO_INTTYPES

// Yes yes dear, fopen is insecure, blah blah. We know.
// Don't bug us about it.
#define _CRT_SECURE_NO_WARNINGS

// Let's make sure struct members are aligned to 2 bytes.
// We wouldn't have put this here if we didn't get bit by this nonsense.
// Note: When building under gcc, turning this on globally does some
//       "creative" optimisations so it's turned on for selective structs.
//       And it's too early to start drinking...
#pragma pack(2)

// Oooh look, VS 2019 thinks it's a bad idea to use #pragma pack because
// it would lead to corruption. Like, we don't know why we want to pack structs
// because "who packs structs? We have memory and all. Are you some kind of
// weirdo?". And, wow, they had to take the extra mile and make this a
// fatal compilation error too. They really don't want people doing this!
/// Pffffft, anyway, defining this magic switch makes bad error go away.
#define WINDOWS_IGNORE_PACKING_MISMATCH
#endif

// M68k defines lifted from bintools 2.27.
// Added here instead of elftypes.hpp so the
// elfio lib won't need any modifying should
// we ever need to update to a newer version.

// note: elfio_relocation.hpp contained x86 elf reloc handling only - has been modified to use these instead

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

#include <assert.h>
#include <iostream>
#include <elfio/elfio_dump.hpp>
#include <elfio/elfio.hpp>
#include <SimpleOpt.h>
#include <map>
#include <cstdio>
#include <iostream>
#include <memory>

// default c++filt, can also be set on commandline
std::string brownfilter = "m68k-atarimegabrown-elf-c++filt";


/* some reference code for GOT/PLT relocation handling - although we will probably never want to have
   these present in the first place since they can change code generation at the referring site to something 
   unusable at runtime without the section being populated.

// copied from Atom OS

R_386_GOTOFF (== 0x9)
This relocation type computes the difference between a symbol's value and the address of the global offset table. It also instructs the link-editor to create the global offset table.

R_386_GOTPC (== 0xA)
This relocation type resembles R_386_PC32, except it uses the address of the global offset table in its calculation

    uint GOT = Heap.kmalloc(1024 * 128); // 128 KB
    ...
    private static void Relocate(Elf_Header* aHeader, Elf_Shdr* aShdr, uint GOT)
    {
        uint BaseAddress = (uint)aHeader;
        Elf32_Rel* Reloc = (Elf32_Rel*)aShdr->sh_addr;
        Elf_Shdr* TargetSection = (Elf_Shdr*)(BaseAddress + aHeader->e_shoff) + aShdr->sh_info;

        uint RelocCount = aShdr->sh_size / aShdr->sh_entsize;

        uint SymIdx, SymVal, RelocType;
        for (int i = 0; i < RelocCount; i++, Reloc++)
        {
            SymVal = 0;
            SymIdx = (Reloc->r_info >> 8);
            RelocType = Reloc->r_info & 0xFF;

            if (SymIdx != SHN_UNDEF)
            {
                if (RelocType == R_386_GOTPC)
                    SymVal = GOT;
                else
                    SymVal = GetSymValue(aHeader, TargetSection->sh_link, SymIdx);
            }

            uint* add_ref = (uint*)(TargetSection->sh_addr + Reloc->r_offset);
            switch(RelocType)
            {
                case R_386_32:
                    *add_ref = SymVal + *add_ref; // S + A
                    break;
                case R_386_GOTOFF:
                    *add_ref = SymVal + *add_ref - GOT; // S + A - GOT
                    break;
                case R_386_PLT32:   // L + A - P
                case R_386_PC32:    // S + A - P
                case R_386_GOTPC:   // GOT + A - P
                    *add_ref = SymVal + *add_ref - (uint)add_ref;
                    break;
                default:
                    throw new Exception("[ELF]: Unsupported Relocation type");
            }
        }
    }
*/

// better at catching things early inside VS debugger
#ifdef _MSC_VER
#define assert(_x_) { if (!(_x_)) { __debugbreak(); }; }
//#define assert(_x_) { if (!(_x_)) { __asm int 3 }; }
#endif

void demangle(std::string &name, std::string &demangled);

// Little endian to big endian conversion depending on platform
#if defined(__linux__) || defined(__CYGWIN__)
#include <endian.h>
#define BYTESWAP32 htobe32
#define BYTESWAP16 htobe16
#endif
#if defined(__MINGW32__)
static __inline unsigned short
__bswap_16 (unsigned short __x)
{
    return (__x >> 8) | (__x << 8);
}

static __inline unsigned int
__bswap_32 (unsigned int __x)
{
    return (__bswap_16 (__x & 0xffff) << 16) | (__bswap_16 (__x >> 16));
} 

#define BYTESWAP32 __bswap_32
#define BYTESWAP16 __bswap_16

#endif
#if defined(__APPLE__)
#include "mac_endian.h"
#define BYTESWAP32 htobe32
#define BYTESWAP16 htobe16
#endif
#ifdef _MSC_VER
#include <stdlib.h>
#define BYTESWAP16 _byteswap_ushort
#define BYTESWAP32 _byteswap_ulong
#endif


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
	OPT_EXTEND,
	OPT_DEMANGLE,
	OPT_CXXFILT,
	//
	// OPT_ELF_HEADER,
	// OPT_ELF_SECTION_HEADERS,
	// OPT_ELF_SEGMENT_HEADERS,
	// OPT_ELF_SYMBOL_TABLES,
	// OPT_ELF_NOTES,
	// OPT_ELF_DYNAMIC_TAGS,
	// OPT_ELF_SECTION_DATAS,
	// OPT_ELF_SEGMENT_DATAS,
	//
	//
    OPT_VERBOSE,
	OPT_DEBUG,
	OPT_HELP,
	//
	OPT_END__
};

CSimpleOpt::SOption g_rgOptions[] =
{
	{ OPT_INFILE, _T("-i"), SO_REQ_SEP },
	{ OPT_OUTFILE, _T("-o"), SO_REQ_SEP },
	{ OPT_PRGFLAGS, _T("-p"), SO_REQ_SEP },
	{ OPT_SYMTABLE, _T("-s"), SO_NONE },
	{ OPT_EXTEND, _T("-x"), SO_NONE },
	{ OPT_DEMANGLE, _T("-f"), SO_NONE },
    { OPT_CXXFILT, _T("-cxxf"), SO_REQ_SEP },
	//
    { OPT_VERBOSE, _T("-v"), SO_NONE },
	{ OPT_DEBUG, _T("-d"), SO_NONE },
	{ OPT_HELP, _T("-h"), SO_NONE },

	SO_END_OF_OPTIONS                       // END
};

void printhelp()
{
	printf("brownout version \"" STRINGIFY(VERSION) "\"\n"
        "Usage: brownout -i <input_elf_file_name> -o <output_tos_file_name> [-p PRGFLAGS] [-s] [-d] [-x]\n"
		"-i input ELF file.\n"
		"-o output TOS file.\n"
		"-p to specify TOS PRGFLAGS.\n"
		"-s will create a symbol table.\n"
		"-x will create an extended symbol table.\n"
		"-f will turn on C++ symbol demangling via GCC's c++filt tool (i.e. you don't get ugly symbol names).\n"
		"-cxxf to specify c++filt demangling tool for any gcc version (if different from default: [%s]).\n"
        "-v will turn on verbose mode (less spammy than debugging)\n"
		"-d will turn on verbose debugging.\n"
        "-h shows help\n",
		//
		brownfilter.c_str() // c++filt default name
	);
}


#if defined(__linux__) || defined(__CYGWIN__) || defined(__MINGW32__) || defined(__APPLE__)
#pragma pack(push,2)
#endif
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
#if defined(__linux__) || defined(__CYGWIN__) || defined(__MINGW32__) || defined(__APPLE__)
#pragma pack(pop)
#endif

using namespace ELFIO;

static const int TOS_FILE_HEADERSIZE = 28;

typedef struct
{
	uint32_t offset_fixup;					// Offset inside the section
	uint32_t elfcalcvalue;
	short elfsection;						// Which section we're on
	short tossection;
	std::string elfsymname;
	bool absolute;
	short type;

} TOS_RELOC;

#define MAX_TOS_RELOCS (256*1024)

TOS_RELOC tos_relocs[MAX_TOS_RELOCS];                // Enough? Who knows!

#if defined(__linux__) || defined(__CYGWIN__) || defined(__MINGW32__) || defined(__APPLE__)
#pragma pack(push,2)
#endif
typedef struct
{
	char name[8];
	uint16_t type;
	uint32_t value;
} GST_SYMBOL;
#if defined(__linux__) || defined(__CYGWIN__) || defined(__MINGW32__) || defined(__APPLE__)
#pragma pack(pop)
#endif

GST_SYMBOL symtab[100 * 1024];  // Enough? Who knows!

typedef struct
{
	int         type;       // Type of section (see enum below)
	std::string	name;
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
bool DEMANGLE = false;
Elf_Half sec_num;
typedef std::map<uint32_t, std::pair<uint32_t, int> > elfsectionboundsmap_t;
elfio reader;

static elfsectionboundsmap_t::iterator get_section_for_va(elfsectionboundsmap_t &smap, uint32_t _va)
{
	// find ELF section this reference belongs to
	// 1) search for first section with (VA < section_end)
	elfsectionboundsmap_t::iterator reference_bound = smap.upper_bound(_va);	

	// 2) no result could mean we're pointing at the very end of the last section, which is still valid (or beyond - which would be a fail)
    if (reference_bound == smap.end())
    {
		// check end of last section
		auto last = std::prev(reference_bound);
		if (last->first == _va)
		{
			// yup - pointing at the end of last section
			return last;
		}

		// pointing somewhere unmapped, beyond last section.
		// It might have been a section we filtered out during the gathering of sections,
		// so let's re-read all sections and try to find which section this relocation is mapped.
		// At least then the user will have more info to look into the problem
		printf("error: reference 0x%08x points at an area not mapped by existing sections\n", _va);
		for (int i = 0; i < sec_num; i++)
		{
			uint32_t sect_start, sect_end;
			ELFIO::section *psec = reader.sections[i];
			sect_start = psec->get_address();
			sect_end = sect_start + psec->get_size();
			if (sect_start <= _va && sect_end >= _va)
			{
				printf("This reference is located at section %s\n", psec->get_name().c_str());
				break;
			}
		}
		exit(-1);
    }

	// 3) if this returns a section which doesn't contain the VA (VA >= section_start)
	// then it must be a reference to the end of a section (but not the last section, handled above), 
	// so we use an end-inclusive search to make sure it refers to a section we actually kept
	//if (_va < reference_bound->second.first)
	//	reference_bound = smap.lower_bound(_va);

	// make sure the reference is actually inside the nearest section (i.e. not < section startaddr) pair<[startaddr],index>
	assert(_va >= reference_bound->second.first);

	return reference_bound;
}

int _tmain(int argc, TCHAR * argv[])
{
	PRG_HEADER toshead = { 0x601a, 0, 0, 0, 0, 0, 0, 0 };  // Set up TOS header

	// declare our options parser, pass in the arguments from main
	// as well as our array of valid options.
	CSimpleOpt args(argc, argv, g_rgOptions);
	char infile[1024];
	char outfile[1024];
	bool DEBUG = false;
	bool FPIC = false;
	int SYMTABLE = SYM_NONE;
    bool VERBOSE = false;

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
                VERBOSE = true;
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
				DEMANGLE = true;
			}
			else if (args.OptionId() == OPT_CXXFILT)
			{
				brownfilter = (std::string)args.OptionArg();
			}
            else if (args.OptionId() == OPT_VERBOSE)
            {
                VERBOSE = true;
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

	if (!reader.load(infile))
	{
		printf("File %s is not found or it is not an ELF file\n", infile);
		return 1;
	}

	if (DEBUG)
	{
		dump::header(std::cout, reader);
		dump::section_headers(std::cout, reader);
		dump::segment_headers(std::cout, reader);
		dump::symbol_tables(std::cout, reader);
		dump::notes(std::cout, reader);
		dump::dynamic_tags(std::cout, reader);
		dump::section_datas(std::cout, reader);
		dump::segment_datas(std::cout, reader);
	}

	if (reader.get_type() != ET_EXEC)
	{
		printf("error: file %s is not an ELF executable (possibly an object file)\n", infile);
		exit(1);
	}

	// From here on starts the browness - helmets on!

	sec_num = reader.sections.size();

	elfsectionboundsmap_t elfsectionboundsmap;
	elfsectionboundsmap_t elfsectionstartmap;

	int no_relocs = 0;

	uint32_t file_offset = TOS_FILE_HEADERSIZE;      // Mostly used to calculate the offset of the BSS section inside the .prg
	ST_SECTION prg_sect[256];                        // Enough? Who knows!
	int section_map[256];                            // This keeps track of which elf section is mapped in which prg_sect index (i.e. a reverse look-up)
	int no_sect = 0;
	bool claimed_sections[256];


	for (int i = 0; i < 256; i++)
	{
		section_map[i] = -1;
		claimed_sections[i] = false;
	}

	ELFIO::section *psec;

    if (VERBOSE)
    {
        std::cout << "performing section layout..." << std::endl;
    }

	// inject link section in front of everything, which links to real entrypoint
	// since ELF has its entrypoint in the header

	char injected_link_section[] =
	{
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x4e, 0x71
	};

	int linksize = 0;

	if (FPIC)
	{
		// 32k relative branch
		injected_link_section[0] = 0x60;
		injected_link_section[1] = 0x00;
		linksize = 4;
	}
	else
	{
		// abs jmp
		injected_link_section[0] = 0x4e;
		injected_link_section[1] = 0xf9;
		linksize = 8;
	}

	{
		prg_sect[no_sect].type = SECT_TEXT;
		prg_sect[no_sect].name = "TEXT";
		prg_sect[no_sect].offset = file_offset;
		prg_sect[no_sect].size = linksize;
		prg_sect[no_sect].padded_size = linksize;
		prg_sect[no_sect].data = (const char *)injected_link_section;
		prg_sect[no_sect].sect_start = 0;
		prg_sect[no_sect].sect_end = 0;

		file_offset += linksize;
		toshead.PRG_tsize += linksize;
        if (VERBOSE)
        {
			printf("record: section[.tos_entrypoint] tsi:%d fbeg:0x%x fend:0x%x\n",
				no_sect, prg_sect[no_sect].offset, file_offset);
        }
		no_sect++;
	}

	for (int i = 0; i < sec_num; i++)
	{
		if (claimed_sections[i]) continue;
		psec = reader.sections[i];
		if ((psec->get_type() == SHT_PROGBITS) &&
			(psec->get_name() == ".boot") &&
			(psec->get_size() > 0))
		{
			claimed_sections[i] = true;
			prg_sect[no_sect].type = SECT_TEXT;
			prg_sect[no_sect].name = "TEXT";
			prg_sect[no_sect].offset = file_offset;                     // Mark start offset of section inside .prg
			prg_sect[no_sect].size = (uint32_t)psec->get_size();        // Mark section's size
			prg_sect[no_sect].padded_size = (prg_sect[no_sect].size + 1) & 0xfffffffe; // Pad section size so it will be even if needed
			prg_sect[no_sect].data = (const char *)psec->get_data();    // Mark section's start of data
			prg_sect[no_sect].sect_start = (uint32_t)psec->get_address();   // Mark elf section's start (for symbol outputting)
			prg_sect[no_sect].sect_end = (uint32_t)psec->get_address() + (uint32_t)psec->get_size(); // Mark elf section's end (for symbol outputting)

			// record section bounds (and index) in a map of <startaddr/index> pairs using endaddr as the sort key,
			// for identity queries using reloc addresses. this way we can identify & bounds-check the owning
			// section and identify it from a single query address.
			if (elfsectionstartmap.find(psec->get_address()) != elfsectionstartmap.end())
			{
				printf("error: section[%s] elfaddr:0x%08x esi:%d tsi:%d fbeg:0x%x fend:0x%x collides with an existing section\n",
					psec->get_name().c_str(), uint32_t(psec->get_address()), i, no_sect, file_offset, file_offset + prg_sect[no_sect].padded_size);
				exit(1);
			}
			elfsectionstartmap[prg_sect[no_sect].sect_start] = std::pair<uint32_t, int>(prg_sect[no_sect].sect_end, i);
			elfsectionboundsmap[prg_sect[no_sect].sect_end] = std::pair<uint32_t, int>(prg_sect[no_sect].sect_start, i);

			file_offset += prg_sect[no_sect].padded_size;               // Update prg BSS offset
			toshead.PRG_tsize += prg_sect[no_sect].padded_size;         // Update prg text size
			section_map[i] = no_sect;                                   // Mark where in prg_sect this section will lie
            if (VERBOSE)
            {
				printf("record: section[%s] elfaddr:0x%08x esi:%d tsi:%d fbeg:0x%x fend:0x%x\n",
					psec->get_name().c_str(), uint32_t(psec->get_address()), i, no_sect, prg_sect[no_sect].offset, file_offset);
            }
			no_sect++;
		}
	}
	// Group text segments and determine their position inside the output file
	for (int i = 0; i < sec_num; i++)
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
			//&& (psec->get_name().find(".init") == std::string::npos)
		)
		{
			claimed_sections[i] = true;
			prg_sect[no_sect].type = SECT_TEXT;
			prg_sect[no_sect].name = "TEXT";
			prg_sect[no_sect].offset = file_offset;                     // Mark start offset of section inside .prg
			prg_sect[no_sect].size = (uint32_t)psec->get_size();        // Mark section's size
			prg_sect[no_sect].padded_size = (prg_sect[no_sect].size + 1) & 0xfffffffe; // Pad section size so it will be even if needed
			prg_sect[no_sect].data = (const char *)psec->get_data();    // Mark section's start of data
			prg_sect[no_sect].sect_start = (uint32_t)psec->get_address();   // Mark elf section's start (for symbol outputting)
			prg_sect[no_sect].sect_end = (uint32_t)psec->get_address() + (uint32_t)psec->get_size(); // Mark elf section's end (for symbol outputting)

			// record section bounds (and index) in a map of <startaddr/index> pairs using endaddr as the sort key,
			// for identity queries using reloc addresses. this way we can identify & bounds-check the owning
			// section and identify it from a single query address.
			if (elfsectionstartmap.find(psec->get_address()) != elfsectionstartmap.end())
			{
				printf("error: section[%s] elfaddr:0x%08x esi:%d tsi:%d fbeg:0x%x fend:0x%x collides with an existing section\n",
					psec->get_name().c_str(), uint32_t(psec->get_address()), i, no_sect, file_offset, file_offset + prg_sect[no_sect].padded_size);
				exit(1);
			}
			elfsectionstartmap[prg_sect[no_sect].sect_start] = std::pair<uint32_t, int>(prg_sect[no_sect].sect_end, i);
			elfsectionboundsmap[prg_sect[no_sect].sect_end] = std::pair<uint32_t, int>(prg_sect[no_sect].sect_start, i);

			file_offset += prg_sect[no_sect].padded_size;               // Update prg BSS offset
			toshead.PRG_tsize += prg_sect[no_sect].padded_size;         // Update prg text size
			section_map[i] = no_sect;                                   // Mark where in prg_sect this section will lie
            if (VERBOSE)
            {
				printf("record: section[%s] elfaddr:0x%08x esi:%d tsi:%d fbeg:0x%x fend:0x%x\n",
					psec->get_name().c_str(), uint32_t(psec->get_address()), i, no_sect, prg_sect[no_sect].offset, file_offset);
            }
			no_sect++;
		}
	}

	// Group data segments and determine their position inside the output file
	for (int i = 0; i < sec_num; i++)
	{
		if (claimed_sections[i]) continue;
		psec = reader.sections[i];
		if ((psec->get_type() == SHT_PROGBITS) &&
			(psec->get_flags() & SHF_ALLOC) &&
			(psec->get_size() > 0) &&
			(psec->get_name().find(".debug_") == std::string::npos) &&
			(psec->get_name().find(".init") == std::string::npos)
			)
		{
			claimed_sections[i] = true;
			prg_sect[no_sect].type = SECT_DATA;
			prg_sect[no_sect].name = "DATA";
			prg_sect[no_sect].offset = file_offset;                     // Mark start offset of section inside .prg
			prg_sect[no_sect].size = (uint32_t)psec->get_size();        // Mark section's size
			prg_sect[no_sect].padded_size = (prg_sect[no_sect].size + 1) & 0xfffffffe; // Pad section size so it will be even if needed
			prg_sect[no_sect].data = (const char *)psec->get_data();    // Mark section's start of data
			prg_sect[no_sect].sect_start = (uint32_t)psec->get_address();   // Mark elf section's start (for symbol outputting)
			prg_sect[no_sect].sect_end = (uint32_t)psec->get_address() + (uint32_t)psec->get_size(); // Mark elf section's end (for symbol outputting)

			//if (elfsectionboundsmap.find(psec->get_address() + psec->get_size()) != elfsectionboundsmap.end())
			//{
   //             std::cerr << "error: section [" << psec->get_name() << "] esi:" << i << " tsi:" << no_sect << " fbeg:" << (prg_sect[no_sect].offset) << " fend:" << file_offset << " collides with an existing section" << std::endl;
			//}

			// record section bounds (and index) in a map of <startaddr/index> pairs using endaddr as the sort key,
			// for identity queries using reloc addresses. this way we can identify & bounds-check the owning
			// section and identify it from a single query address.
			if (elfsectionstartmap.find(psec->get_address()) != elfsectionstartmap.end())
			{
				printf("error: section[%s] elfaddr:0x%08x esi:%d tsi:%d fbeg:0x%x fend:0x%x collides with an existing section\n",
					psec->get_name().c_str(), uint32_t(psec->get_address()), i, no_sect, file_offset, file_offset + prg_sect[no_sect].padded_size);
				exit(1);
			}
			elfsectionstartmap[prg_sect[no_sect].sect_start] = std::pair<uint32_t, int>(prg_sect[no_sect].sect_end, i);
			elfsectionboundsmap[prg_sect[no_sect].sect_end] = std::pair<uint32_t, int>(prg_sect[no_sect].sect_start, i);

			file_offset += prg_sect[no_sect].padded_size;               // Update prg BSS offset
			toshead.PRG_dsize += prg_sect[no_sect].padded_size;         // Update prg data size
			section_map[i] = no_sect;                                   // Mark where in prg_sect this section will lie
            if (VERBOSE)
            {
				printf("record: section[%s] elfaddr:0x%08x esi:%d tsi:%d fbeg:0x%x fend:0x%x\n",
					psec->get_name().c_str(), uint32_t(psec->get_address()), i, no_sect, prg_sect[no_sect].offset, file_offset);
            }
			no_sect++;
		}
	}

	// Group BSS segments and determine their position inside the output file
	for (int i = 0; i < sec_num; i++)
	{
		if (claimed_sections[i]) continue;
		psec = reader.sections[i];
		if ((psec->get_type() == SHT_NOBITS) &&
			(psec->get_size() > 0) &&
			(psec->get_name().find(".debug_") == std::string::npos) &&
			(psec->get_name().find(".init") == std::string::npos)
			)
		{
			claimed_sections[i] = true;
			prg_sect[no_sect].type = SECT_BSS;
			prg_sect[no_sect].name = "BSS";
			prg_sect[no_sect].offset = file_offset;                     // Mark start offset of section inside .prg
			prg_sect[no_sect].size = (uint32_t)psec->get_size();        // Mark section's size
			prg_sect[no_sect].padded_size = (prg_sect[no_sect].size + 1) & 0xfffffffe; // Pad section size so it will be even if needed
			prg_sect[no_sect].sect_start = (uint32_t)psec->get_address();   // Mark elf section's start (for symbol outputting)
			prg_sect[no_sect].sect_end = (uint32_t)psec->get_address() + (uint32_t)psec->get_size(); // Mark elf section's end (for symbol outputting)

			// record section bounds (and index) in a map of <startaddr/index> pairs using endaddr as the sort key,
			// for identity queries using reloc addresses. this way we can identify & bounds-check the owning
			// section and identify it from a single query address.
			if (elfsectionstartmap.find(psec->get_address()) != elfsectionstartmap.end())
			{
				printf("error: section[%s] elfaddr:0x%08x esi:%d tsi:%d fbeg:0x%x fend:0x%x collides with an existing section\n",
					psec->get_name().c_str(), uint32_t(psec->get_address()), i, no_sect, file_offset, file_offset + prg_sect[no_sect].padded_size);
				exit(1);
			}
			elfsectionstartmap[prg_sect[no_sect].sect_start] = std::pair<uint32_t, int>(prg_sect[no_sect].sect_end, i);
			elfsectionboundsmap[prg_sect[no_sect].sect_end] = std::pair<uint32_t, int>(prg_sect[no_sect].sect_start, i);

			//file_offset += (uint32_t)psec->get_size();                  // Update prg offset
			file_offset += prg_sect[no_sect].padded_size;                  // Update prg offset
			toshead.PRG_bsize += prg_sect[no_sect].padded_size;            // Update prg bss size
			section_map[i] = no_sect;                                   // Mark where in prg_sect this section will lie
            if (VERBOSE)
            {
				printf("record: section[%s] elfaddr:0x%08x esi:%d tsi:%d fbeg:0x%x fend:0x%x\n",
					psec->get_name().c_str(), uint32_t(psec->get_address()), i, no_sect, prg_sect[no_sect].offset, file_offset);
            }
			no_sect++;
		}
	}

	// Print some basic info
    if (VERBOSE)
    {
        std::cout <<
            "TEXT size: " << toshead.PRG_tsize << std::endl <<
            "DATA size:" << toshead.PRG_dsize << std::endl <<
            "BSS size:" << toshead.PRG_bsize << std::endl;
    }

    if (VERBOSE)
    {
        std::cout << "processing relocation entries..." << std::endl;
    }

	uint32_t elf_entrypoint = 1;// reader.get_entry();

	{

		if (1)
		{
            if (VERBOSE)
            {
                std::cout << "hunting entrypoint symbol..." << std::endl;
            }

			for (int si = 0; si < sec_num; si++)
			{
				psec = reader.sections[si];
				if (psec->get_type() == SHT_SYMTAB)
				{
					symbol_section_accessor symbols(reader, psec);

					Elf_Xword sym_no = symbols.get_symbols_num();

					if (sym_no > 0)
					{
						int remaining = 1;
						for (Elf_Half i = 0; (i < sym_no) && (remaining > 0); ++i)
						{
							std::string   name;
							Elf64_Addr    value = 0;
							Elf_Xword     size = 0;
							unsigned char bind = 0;
							unsigned char type = 0;
							Elf_Half      section = 0;
							unsigned char other = 0;
							symbols.get_symbol(i, name, value, size, bind, type, section, other);

//							if (name.length() > 0)
//								__asm int 3;

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
									if ((name.compare("__start") == 0) ||
										(name.compare("_start") == 0))
									{
										elf_entrypoint = value;
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

		if (elf_entrypoint == 1)
		{
			std::cerr << "error: entrypoint (_start symbol) could not be found. can't link!" << std::endl;
			exit(1);
		}

		// find ELF section this reference belongs to (section with lower bound <= query address)
		elfsectionboundsmap_t::iterator reference_bound = get_section_for_va(elfsectionboundsmap, elf_entrypoint);
		// get ELF section index pair<endaddr,[index]>
		int reference_elfidx = reference_bound->second.second;
		int reference_tosidx = section_map[reference_elfidx];
		assert(reference_tosidx >= 0);
		// base address of original elf section bounding the reference
		uint32_t reference_esa = reader.sections[reference_elfidx]->get_address();
		// base address of new tos section bounding the reference
		uint32_t reference_tsa = prg_sect[reference_tosidx].offset - TOS_FILE_HEADERSIZE;

		uint32_t tos_entrypoint = elf_entrypoint - reference_esa + reference_tsa;

//        if (VERBOSE)
        {
            printf("entrypoint located at eVA:$%06x (tVA:$%06x)\n", elf_entrypoint, tos_entrypoint);
        }

		if (FPIC)
		{
			uint32_t branch_offset = tos_entrypoint - 2;

			if (branch_offset >= 32768)
			{
				std::cerr << "error: entrypoint (_start symbol) is >= 32k into program image in -fpic mode. can't link!" << std::endl;
				exit(1);
			}

			// word branch - no relocation required
			injected_link_section[2] = (branch_offset >> 8) & 0xFF;
			injected_link_section[3] = (branch_offset >> 0) & 0xFF;
		}
		else
		{
			// abs jmp - must emit relocation for thi
			injected_link_section[2] = (tos_entrypoint >> 24) & 0xFF;
			injected_link_section[3] = (tos_entrypoint >> 16) & 0xFF;
			injected_link_section[4] = (tos_entrypoint >> 8) & 0xFF;
			injected_link_section[5] = (tos_entrypoint >> 0) & 0xFF;

			// record the relocation for processing
			tos_relocs[no_relocs].elfsection = -1;
			tos_relocs[no_relocs].tossection = 0;
			tos_relocs[no_relocs].offset_fixup = (uint32_t)2;
			tos_relocs[no_relocs].elfcalcvalue = tos_entrypoint;
			tos_relocs[no_relocs].elfsymname = "toslink";
			// we need to handle more than one type of reloc, so we query again later after filtering and sorting
			// todo: can remove some of these stored fields not required for the sorting pass
			// and defer them to the final stage. they eat a lot of memory anyway.
			tos_relocs[no_relocs].type = R_68K_32;
			// only absolute relocations make it into the TOS reloc table.
			// the pc-relative ones are just baked into the text/data after section rearrangement.
			tos_relocs[no_relocs].absolute = true;
			no_relocs++;

			if (no_relocs > MAX_TOS_RELOCS)
			{
				std::cerr << "error: tos_relocs overflow! increase MAX_TOS_RELOCS and rebuild!" << std::endl;
				exit(1);
			}

		}
	}


	// Perform any relocations that may be needed
	//section *psec_reloc;
	for (int i = 0; i < sec_num; i++)
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
				switch (type)
				{
				case R_68K_32:
				case R_68K_PC32:
				case R_68K_PC16:
				case R_68K_PC8:
				{
					if (DEBUG)
					{
						// get reloc type string for printing
						std::string typestr;
						switch (type)
						{
						case R_68K_32:		typestr = "32"; break;
						case R_68K_PC32:	typestr = "PC32"; break;
						case R_68K_PC16:	typestr = "PC16"; break;
						case R_68K_PC8:		typestr = "PC8"; break;
						default:			typestr = "???"; break;
						}

						std::cout << "ELF R_68K_" << typestr
							<< " " << j
							<< " in section " << i << " [" << psec->get_name() << "]"
							<< " offset:" << offset
							<< " symval:" << symbolValue
							<< " sym:" << symbolName
							<< " type:" << type
							<< " addend:" << addend
							<< " calc:" << calcValue
							<< std::endl;
					}

					assert(i >= 0);
					{
						if (offset & 1)
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
							exit(-1);

						}

						// find ELF section this reference belongs to (section with lower bound <= query address)
						elfsectionboundsmap_t::iterator reloc_bound = get_section_for_va(elfsectionboundsmap, offset);
						// get ELF section index pair<endaddr,[index]>
						int reloc_elfidx = reloc_bound->second.second;
						assert(section_map[reloc_elfidx] >= 0);

						// record the relocation for processing
						tos_relocs[no_relocs].elfsection = reloc_elfidx;// i - 1;
						tos_relocs[no_relocs].tossection = section_map[reloc_elfidx];// section_map[i - 1];
						tos_relocs[no_relocs].offset_fixup = (uint32_t)offset;
						tos_relocs[no_relocs].elfcalcvalue = calcValue;// symbolValue;
						tos_relocs[no_relocs].elfsymname = symbolName;
						// we need to handle more than one type of reloc, so we query again later after filtering and sorting
						// todo: can remove some of these stored fields not required for the sorting pass
						// and defer them to the final stage. they eat a lot of memory anyway.
						tos_relocs[no_relocs].type = type;
						// only absolute relocations make it into the TOS reloc table.
						// the pc-relative ones are just baked into the text/data after section rearrangement.
						tos_relocs[no_relocs].absolute = (type == R_68K_32);
						no_relocs++;

						if (no_relocs > MAX_TOS_RELOCS)
						{
							std::cerr << "error: tos_relocs overflow! increase MAX_TOS_RELOCS and rebuild!" << std::endl;
							exit(1);
						}
					}
					break;
				}

				case R_68K_NONE:
				{
					std::cerr << "warning: encountered unhandled R_68K_NONE relocation"
						<< " in section " << i << " [" << psec->get_name() << "]"
						<< " offset:" << offset
						<< " symval:" << symbolValue
						<< " sym:" << symbolName
						<< " addend:" << addend
						<< " calc:" << calcValue
						<< std::endl;

					std::cerr << "\tthis may be a GCC6 bug - cases affecting [.eh_frame] can be removed by adding -fno-exceptions"
						<< std::endl;

					break;
				}

				case R_68K_GOT32:
				case R_68K_GOT16:
				case R_68K_GOT8:
				case R_68K_GOT32O:
				case R_68K_GOT16O:
				case R_68K_GOT8O:
				case R_68K_PLT32:
				case R_68K_PLT16:
				case R_68K_PLT8:
				case R_68K_PLT32O:
				case R_68K_PLT16O:
				case R_68K_PLT8O:
				{
					std::cerr << "error: encountered unhandled relocation type [" << type << "]"
						<< " in section " << i << " [" << psec->get_name() << "]"
						<< " offset:" << offset
						<< " symval:" << symbolValue
						<< " sym:" << symbolName
						<< " addend:" << addend
						<< " calc:" << calcValue
						<< std::endl;

					std::cerr << " these relocations refer to GOT/PLT sections not supported by TOS." << std::endl;
					std::cerr << " please recompile affected Atari code with '-fno-plt -fno-pic' options" << std::endl;

					exit(1);

					break;
				}

				default:
				{
					std::cerr << "error: encountered unhandled R_68K_?? relocation type [" << type << "]"
						<< " in section " << i << " [" << psec->get_name() << "]"
						<< " offset:" << offset
						<< " symval:" << symbolValue
						<< " sym:" << symbolName
						<< " addend:" << addend
						<< " calc:" << calcValue
						<< std::endl;

					exit(1);

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
        if (VERBOSE)
        {
            std::cout << "generating symbol table..." << std::endl;
        }

		for (int i = 0; i < sec_num; i++)
		{
			psec = reader.sections[i];
			if (psec->get_type() == SHT_SYMTAB /* || psec->get_type() == SHT_DYNSYM */)
			{
				symbol_section_accessor symbols(reader, psec);

				Elf_Xword     sym_no = symbols.get_symbols_num();

				if (sym_no > 0)
				{

					for (Elf_Half i = 0; i < sym_no; ++i)
					{
						char gst_name[25] =
						{	
							0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
							0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
							0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
							0x0
						};

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
										!demangled &&
                                        DEMANGLE
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
						if (gst_name[0] == 0)
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
								if (SYMTABLE == SYM_DRI || (SYMTABLE == SYM_EXTEND && strlen(gst_name) <= 8))
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
											if (SYMTABLE == SYM_DRI || (SYMTABLE == SYM_EXTEND && strlen(gst_name) <= 8))
											{
												symtab[no_sym].type = 0x8200; //TEXT + defined
												symtab[no_sym].value = (uint32_t)value - prg_sect[j].sect_start + prg_sect[j].offset - TOS_FILE_HEADERSIZE;
												memcpy(symtab[no_sym].name, gst_name, 8);
												no_sym++;
												break;
											}
											else
											{
												symtab[no_sym].value = (uint32_t)value - prg_sect[j].sect_start + prg_sect[j].offset - TOS_FILE_HEADERSIZE;
												memcpy(symtab[no_sym].name, gst_name, 8);
												symtab[no_sym].type = 0x8248; //TEXT + defined + continued on next symbol
												no_sym++;
												memcpy(&symtab[no_sym], &gst_name[8], 14);  // Extended mode - copy 1 more symbol's worth of chars in the next symbol
												no_sym++;
												break;
											}
										case SECT_DATA:
											if (SYMTABLE == SYM_DRI || (SYMTABLE == SYM_EXTEND && strlen(gst_name) <= 8))
											{
												symtab[no_sym].value = (uint32_t)value - prg_sect[j].sect_start + prg_sect[j].offset - TOS_FILE_HEADERSIZE;
												memcpy(symtab[no_sym].name, gst_name, 8);
												symtab[no_sym].type = 0x8400; //DATA + defined
												no_sym++;
												break;
											}
											else
											{
												symtab[no_sym].value = (uint32_t)value - prg_sect[j].sect_start + prg_sect[j].offset - TOS_FILE_HEADERSIZE;
												memcpy(symtab[no_sym].name, gst_name, 8);
												symtab[no_sym].type = 0x8248; //DATA + defined + continued on next symbol
												no_sym++;
												memcpy(&symtab[no_sym], &gst_name[8], 14);  // Extended mode - copy 1 more symbol's worth of chars in the next symbol
												no_sym++;
												break;
											}
										case SECT_BSS:
											if (SYMTABLE == SYM_DRI || (SYMTABLE == SYM_EXTEND && strlen(gst_name) <= 8))
											{
												symtab[no_sym].value = (uint32_t)value - prg_sect[j].sect_start + prg_sect[j].offset - TOS_FILE_HEADERSIZE;
												memcpy(symtab[no_sym].name, gst_name, 8);
												symtab[no_sym].type = 0x8100; //BSS + defined
												no_sym++;
												break;
											}
											else
											{
												symtab[no_sym].value = (uint32_t)value - prg_sect[j].sect_start + prg_sect[j].offset - TOS_FILE_HEADERSIZE;
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

    if (VERBOSE)
    {
        std::cout << "emitting program data..." << std::endl;
    }

	// Open output file and write things
	FILE *tosfile = fopen(outfile, "w+b");
	if (tosfile==NULL)
	{
		std::cout << "Unable to open file " << outfile << " for output." << std::endl;
		exit(1);
	}

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

    // Figure out how big our output program will be
    int prgsize= toshead.PRG_tsize + toshead.PRG_dsize + toshead.PRG_ssize;
    if (no_relocs > 0)
        prgsize += 8*1024*1024;        // Let's assume that 1mb should be enough for relocations? (O_o otherwise a ton of code has to be added for analytical calculation)
    char *prgbuffer = (char *)malloc(prgsize);
    char *prgbuffer_start = prgbuffer;

	// Write header
	//fwrite(&writehead, sizeof(writehead), 1, tosfile);
    memcpy(prgbuffer, &writehead, sizeof(writehead));
    prgbuffer = prgbuffer+sizeof(writehead);

	// Write text and data sections
	for (int i = 0; i < no_sect; i++)
	{
		if (prg_sect[i].type == SECT_TEXT || prg_sect[i].type == SECT_DATA)
		{
			//fwrite(prg_sect[i].data, prg_sect[i].size, 1, tosfile);
            memcpy(prgbuffer, prg_sect[i].data, prg_sect[i].size);
            prgbuffer = prgbuffer + prg_sect[i].size;
			if ((prg_sect[i].size & 1) == 1)
			{
				// Odd size, add padding
				//char pad = 0;
				//fwrite(&pad, 1, 1, tosfile);
                *prgbuffer++ = 0;
			}
		}
		// TODO2: For 030 executables pad sections to 4 bytes?
	}

	// write symbol table
	if (toshead.PRG_ssize != 0)
	{
        if (VERBOSE)
        {
            std::cout << "emitting symbol table..." << std::endl;
        }

		//fwrite(symtab, toshead.PRG_ssize, 1, tosfile);
        memcpy(prgbuffer, symtab, toshead.PRG_ssize);
        prgbuffer = prgbuffer + toshead.PRG_ssize;
	}


	// shove all reloc indices in a map, using the address as the sort key
	// (equivalent to a tree-insert-sort)
	if (no_relocs > 0 && VERBOSE)
		std::cout << "sorting " << no_relocs << " relocations..." << std::endl;

	typedef std::map<uint32_t, int> relocmap_t;
	relocmap_t relocmap;
	for (int r = 0; r < no_relocs; r++)
	{
		// compute reloc address

		std::string &ref_name = tos_relocs[r].elfsymname;
		//std::string elf_sec_name("-missing-");

		// assume elfsection=-1 to mean zero offset, for tos-based injected relocs.
		uint32_t esa = 0;
		ELFIO::section *psec = 0;
		if (tos_relocs[r].elfsection >= 0)
		{
			psec = reader.sections[tos_relocs[r].elfsection];
			esa = psec->get_address();
			//elf_sec_name = psec->get_name();
		}
		else
		{
	        std::cout << "note: reloc [" << ref_name << "] refers to non-existent elf section" << std::endl;
		}

		uint32_t tsa = prg_sect[tos_relocs[r].tossection].offset;

		uint32_t tosreloc_file = tos_relocs[r].offset_fixup - esa + tsa;
		uint32_t tosreloc_mem = tosreloc_file - TOS_FILE_HEADERSIZE;

		// make sure only one reloc for each address!
		assert(relocmap.find(tosreloc_mem) == relocmap.end());

		// index of this reloc address
		relocmap[tosreloc_mem] = r;
	}

	if (no_relocs > 0)
	{
        if (VERBOSE)
        {
            std::cout << "correcting relocations after section layout..." << std::endl;
        }

		fflush(tosfile);
		long sv = ftell(tosfile);

		// sorted map of reloc indices
		relocmap_t::iterator it = relocmap.begin();

		while (it != relocmap.end())
		{
			int r = it->second;
			it++;

			std::string &ref_name = tos_relocs[r].elfsymname;
			std::string elf_sec_name("-missing-");

			// assume elfsection=-1 to mean zero offset, for tos-based injected relocs.
			uint32_t esa = 0;
			ELFIO::section *psec = 0;
			if (tos_relocs[r].elfsection >= 0)
			{
				psec = reader.sections[tos_relocs[r].elfsection];
				esa = psec->get_address();
				elf_sec_name = psec->get_name();
			}
			//else
			//{
	  //          std::cout << "note: reloc [" << ref_name << "] refers to non-existent elf section" << std::endl;
			//}

			std::string &tossecname = prg_sect[tos_relocs[r].tossection].name;
			uint32_t tsa = prg_sect[tos_relocs[r].tossection].offset;
			uint32_t elfoffset = tos_relocs[r].offset_fixup;
			uint32_t reference = tos_relocs[r].elfcalcvalue;

			uint32_t tosreloc_file = tos_relocs[r].offset_fixup - esa + tsa;
			uint32_t tosreloc_mem = tosreloc_file - TOS_FILE_HEADERSIZE;

			short r_type = tos_relocs[r].type;

			switch (r_type)
			{
			case R_68K_32:
				if (VERBOSE)
					printf("tosreloc:[%s] type:[R_68k_32] val:[0x%x] elfsec:[%s] tossec:[%s]\n", 
						ref_name.c_str(), reference, elf_sec_name.c_str(), tossecname.c_str());
			default:
				break;
			case R_68K_PC32:
				if (VERBOSE)
					printf("tosreloc:[%s] type:[R_68K_PC32] val:[0x%x=(0x%x+0x%x)] elfsec:[%s] tossec:[%s]\n", 
						ref_name.c_str(), (reference + elfoffset), reference, elfoffset, elf_sec_name.c_str(), tossecname.c_str());
				reference += elfoffset;
				break;
			case R_68K_PC16:
				if (VERBOSE)
					printf("tosreloc:[%s] type:[R_68K_PC16] val:[0x%x=(0x%x+0x%x)] elfsec:[%s] tossec:[%s]\n", 
						ref_name.c_str(), (reference + elfoffset), reference, elfoffset, elf_sec_name.c_str(), tossecname.c_str());
				reference += elfoffset;
				break;
			case R_68K_PC8:
				if (VERBOSE)
					printf("tosreloc:[%s] type:[R_68K_PC8] val:[0x%x=(0x%x+0x%x)] elfsec:[%s] tossec:[%s]\n", 
						ref_name.c_str(), (reference + elfoffset), reference, elfoffset, elf_sec_name.c_str(), tossecname.c_str());
				reference += elfoffset;
				break;
			}

			// find ELF section this reference belongs to (section with lower bound <= query address)
			elfsectionboundsmap_t::iterator reference_bound = get_section_for_va(elfsectionboundsmap, reference);
			// get ELF section index pair<endaddr,[index]>
			int reference_elfidx = reference_bound->second.second;
			assert(section_map[reference_elfidx] >= 0);
			// base address of original elf section bounding the reference
			uint32_t reference_esa = reader.sections[reference_elfidx]->get_address();
			// base address of new tos section bounding the reference
			uint32_t reference_tsa = prg_sect[section_map[reference_elfidx]].offset - TOS_FILE_HEADERSIZE;

			if (DEBUG || (r_type != R_68K_32))
			{
				//	printf("esa:%x, tsa:%x, osf:%x, tosreloc:%x\n", esa, tsa, tos_relocs[r].offset_fixup, tosreloc_mem);

				static const char* const typestrs[] =
				{
					"R_68K_NONE",
					"R_68K_32",
					"R_68K_16",
					"R_68K_8",
					"R_68K_PC32",
					"R_68K_PC16",
					"R_68K_PC8"
				};

				if (tos_relocs[r].elfsection < 0)
				{
					// injected relocs which did not originate from the elf
					printf("emitting injected reloc\n");
				}
				else
				if (ref_name.length() > 0)
				{
					// points at a named public symbol
					printf
						(
						"%s: eVA:$%06x eSec[%s] eSecVA:$%06x (tVA:$%06x tSecVA:$%06x) -> r_sym[%s] r_eVA:$%06x r_eSec[%s] r_eSecVA:$%06x r_eSecVAE:$%06x (r_tVA:$%06x r_tSecVA:$%06x)\n",
						typestrs[r_type],
						//
						elfoffset,												// elf RVA
						reader.sections[tos_relocs[r].elfsection]->get_name().c_str(),		// elf section name
						esa,													// elf section start VA
						//
						tosreloc_mem,											// tos RVA
						tsa,													// tos section start RVA
						//
						ref_name.c_str(),										// referred symbol name
						reference,												// referred elf VA (symbol VA)
						reader.sections[reference_elfidx]->get_name().c_str(),	// referred elf section name
						reference_bound->second.first,							// referred elf section start VA
						reference_bound->first,									// referred elf section end VA
						//
						reference - reference_esa + reference_tsa,				// referred tos VA
						reference_tsa											// referred tos section start VA
						);
				}
				else
				{
					// points at anonymous or hidden symbol
					printf
						(
						"%s: eVA:$%06x eSec[%s] eSecVA:$%06x (tVA:$%06x tSecVA:$%06x) -> r_eVA:$%06x r_eSec[%s] r_eSecVA:$%06x r_eSecVAE:$%06x (r_tVA:$%06x r_tSecVA:$%06x)\n",
						typestrs[r_type],
						//
						elfoffset,											// elf RVA
						reader.sections[tos_relocs[r].elfsection]->get_name().c_str(),		// elf section name
						esa,													// elf section start VA
						//
						tosreloc_mem,											// tos RVA
						tsa,													// tos section start RVA
						//
						reference,												// referred elf VA (symbol VA)
						reader.sections[reference_elfidx]->get_name().c_str(),	// referred elf section name
						reference_bound->second.first,							// referred elf section start VA
						reference_bound->first,									// referred elf section end VA
						//
						reference - reference_esa + reference_tsa,				// referred tos VA
						reference_tsa											// referred tos section start VA
						);
				}
			} // DEBUG

			// adjust the relative part of the reloc value to cope with section output rearrangement (ELF->TOS)
			// since the automatic part of the relocation is a shared base address only. we're upsetting
			// relocs on an individual (or at least per-section) basis so they need more fine-grained repair.

			switch (r_type)
			{
			case R_68K_32:
				// adjust the REL part to compensate for section rearrangement
				// this is an ABS relocation so adjust relative to sections only
				if (tos_relocs[r].elfsection >= 0)
				{
					reference -= reference_esa;
					reference += reference_tsa;
				}

				// write the updated 32bit value
				//relo_data[0] = BYTESWAP32(reference);
				//fseek(tosfile, (long)tosreloc_file, 0);
				//fwrite(relo_data, 1, 4, tosfile);
                *(uint32_t *)&prgbuffer_start[tosreloc_file] = BYTESWAP32(reference);
				break;

			case R_68K_PC32:
				//assert(tos_relocs[r].elfsection != reference_elfidx);

				//if (tos_relocs[r].elfsection != reference_elfidx)
				if (tos_relocs[r].elfsection >= 0)
				{
					// adjust the REL part to compensate for section rearrangement
					// this is a PC-relative relocation so subtract reloc location in TOS VA
					reference -= reference_esa;
					reference += reference_tsa;
				}

				reference -= tosreloc_mem;

				// write the updated 32bit value
				//relo_data[0] = BYTESWAP32(reference);
				//fseek(tosfile, (long)tosreloc_file, 0);
				//fwrite(relo_data, 1, 4, tosfile);
                *(uint32_t *)&prgbuffer_start[tosreloc_file] = BYTESWAP32(reference);
				break;

			case R_68K_PC16:
				//std::cerr << "error: won't process cross-section 16bit PC-relative relocation type [R_68K_PC16]" << std::endl;
				//exit(1);

				//assert(tos_relocs[r].elfsection != reference_elfidx);

				//if (tos_relocs[r].elfsection != reference_elfidx)
				if (tos_relocs[r].elfsection >= 0)
				{
					// adjust the REL part to compensate for section rearrangement
					// this is a PC-relative relocation so subtract reloc location in TOS VA
					reference -= reference_esa;
					reference += reference_tsa;
				}

				reference -= tosreloc_mem;

				if (((int)reference < -32768) || ((int)reference >= 32768))
				{
					std::cerr << "error: can't process 16bit PC-relative relocation type [R_68K_PC16] - calculated offset exceeds 16bit range!" << std::endl;
					exit(1);
				}

				// write the updated 32bit value
				//relo_data[0] = BYTESWAP32(reference);
				//fseek(tosfile, (long)tosreloc_file, 0);
				//fwrite(relo_data, 1, 4, tosfile);
                *(uint16_t *)&prgbuffer_start[tosreloc_file] = BYTESWAP16((uint16_t)reference);

				break;

			case R_68K_PC8:
				std::cerr << "error: won't process cross-section 8bit PC-relative relocation type [R_68K_PC8]" << std::endl;
				exit(1);
				break;

			default:
				std::cerr << "error: can't process unhandled relocation type [" << r_type << "]" << std::endl;
				exit(1);
				break;
			}
		} // while (it != relocmap.end())

		fseek(tosfile, sv, 0);
	}

	// Write relocation table
	if (no_relocs > 0)
	{
        if (VERBOSE)
        {
            std::cout << "emitting relocation table..." << std::endl;
        }

		// sorted map of reloc indices
		relocmap_t::iterator it = relocmap.begin();

		uint32_t current_reloc;
		uint32_t next_reloc;
		uint32_t diff;
		uint8_t temp;
		uint32_t temp_byteswap;
		int i = 0, ri = 0;
		// Handle first relocation separately as
		// the offset needs to be a longword.

		// get first address-sorted reloc index
		current_reloc = it->first;
		ri = it->second; it++; i++;

		// scan until first absolute relocation (R_68k_32). we don't put the PC-relative ones in the TOS reloctbl.
		while (!(tos_relocs[ri].absolute))
		{
			current_reloc = it->first;
			ri = it->second; it++; i++;
		}

		//temp_byteswap = BYTESWAP32(current_reloc);
		//fwrite(&temp_byteswap, 4, 1, tosfile);
        *(uint32_t *)prgbuffer= BYTESWAP32(current_reloc);
        prgbuffer = prgbuffer + 4;
		for (; i < no_relocs; i++)
		{
			// get next address-sorted reloc index
			next_reloc = it->first;
			ri = it->second; it++;

			// process only absolute relocations (R_68k_32). we don't put the PC-relative ones in the TOS reloctbl.
			if (tos_relocs[ri].absolute)
			{
				diff = next_reloc - current_reloc;
				while (diff > 254)
				{
					//temp = 1;
					//fwrite(&temp, 1, 1, tosfile);
                    *prgbuffer++ = 1;
					diff -= 254;
				}
				//temp = diff;
				//fwrite(&temp, 1, 1, tosfile);
                *prgbuffer++ = diff;
				current_reloc = next_reloc;
			}
		}

		// Finally, write a 0 to terminate the symbol table
		//temp = 0;
		//fwrite(&temp, 1, 1, tosfile);
        *prgbuffer++ = 0;
	}
	else
	{
		// todo: corner case where all relocations were PC-relative, should still have routed here. needs fixed.
        if (VERBOSE)
        {
            std::cout << "no relocation table required." << std::endl;
        }

		// Write a null longword to express list termination
		// (as suggested by the Atari Compendium chapter 2)
		//fwrite(&no_relocs, 4, 1, tosfile);
        *(uint32_t *)prgbuffer = 0;
        prgbuffer = prgbuffer + 4;

	}

    // Now, write the file in one big swoop

    fwrite(prgbuffer_start, prgbuffer - prgbuffer_start, 1, tosfile);

	// Done writing stuff
	fclose(tosfile);

    if (VERBOSE)
    {
        std::cout << "done!" << std::endl;
    }

	return 0;
}

// Execute program and grab console output
// Thanks to waqas and jotik for the snippet
// (from http://stackoverflow.com/a/478960)
// Hopefully they don't have too large unix beards.
//

#if defined(_MSC_VER)
#define POPEN _popen
#define PCLOSE _pclose
#else
#define POPEN popen
#define PCLOSE pclose
#endif
std::string exec(const char* cmd)
{
	char buffer[128];
	std::string result = "";
	std::shared_ptr<FILE> pipe(POPEN(cmd, "r"), PCLOSE);
	//if (!pipe) throw std::runtime_error("popen() failed!");
    //if (pipe==NULL)
    //{
    //    std::cout << "Note: m68k-ataribrown-elf-c++filt not found in your path - turning demangling off." << std::endl;
    //    return NULL;
    //}
    while (!feof(pipe.get()))
	{
		if (fgets(buffer, 128, pipe.get()) != NULL)
			result += buffer;
	}
	return result;
}

void demangle(std::string &name, std::string &demangled)
{

	demangled = exec((brownfilter + " " + name).c_str());

    if (demangled== "")
    {
        std::cout << "Note: " << brownfilter << " not found in your path - turning demangling off." << std::endl;
        DEMANGLE = false;
    }

	// trim control characters from response
	if (demangled.length() > 0)
		while ((demangled.back() == '\n') || (demangled.back() == '\r') || (demangled.back() == ' '))
			demangled.pop_back();

}

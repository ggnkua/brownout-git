/*
elfdump.cpp - Dump ELF file using ELFIO library.

Copyright (C) 2001-2015 by Serge Lamikhov-Center

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#ifdef _MSC_VER
  #define _SCL_SECURE_NO_WARNINGS
  #define ELFIO_NO_INTTYPES
#endif

#include <iostream>
#include <elfio/elfio_dump.hpp>
#include <elfio/elfio.hpp>

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

using namespace ELFIO;

int main( int argc, char** argv )
{
    if ( argc != 2 ) {
        printf( "Usage: ELFDump <file_name>\n" );
        return 1;
    }

    elfio reader;
    
    if ( !reader.load( argv[1] ) ) {
        printf( "File %s is not found or it is not an ELF file\n", argv[1] );
        return 1;
    }

    dump::header         ( std::cout, reader );
    dump::section_headers( std::cout, reader );
    dump::segment_headers( std::cout, reader );
    dump::symbol_tables  ( std::cout, reader );
    dump::notes          ( std::cout, reader );
    dump::dynamic_tags   ( std::cout, reader );
    dump::section_datas  ( std::cout, reader );
    dump::segment_datas  ( std::cout, reader );

	Elf_Half sec_num=reader.sections.size();

	typedef struct
	{
		int         type;
        int         section_no;
		uint32_t    offset;
	} ST_SECTION;

    enum
    {
        SECT_TEXT,
        SECT_DATA,
        SECT_BSS
    };

    uint32_t file_offset=28;        //first text section after the tos header
	int text_size=0,
        data_size=0,
        bss_size=0;
    ST_SECTION program_sections[32];
    int no_sections=0;

	section *psec;

    // TODO: refactor the following 3 loops into 1 by
    // making program_sections [32][3] and iterating once again
    // to determine offsets into file?

    // Group text segments and determine their position inside the output file
	for ( int i = 0; i < sec_num; i++ )
    {
        psec = reader.sections[i];
        if (psec->get_type()==SHT_PROGBITS &&
            psec->get_name()==".text")
        {
            program_sections[no_sections].type=SECT_TEXT;
            program_sections[no_sections].offset=file_offset;
            program_sections[no_sections].section_no=i;

            file_offset+=psec->get_size();
            no_sections++;
        }
    }

    // Group data segments and determine their position inside the output file
	for ( int i = 0; i < sec_num; i++ )
    {
        psec = reader.sections[i];
        if (psec->get_type()==SHT_PROGBITS &&
            psec->get_name()==".data")
        {
            program_sections[no_sections].type=SECT_DATA;
            program_sections[no_sections].offset=file_offset;
            program_sections[no_sections].section_no=i;
            file_offset+=psec->get_size();
            no_sections++;
        }
    }

    // Group BSS segments and determine their position inside the output file
	for ( int i = 0; i < sec_num; i++ )
    {
        psec = reader.sections[i];
        if (psec->get_type()==SHT_NOBITS)
        {
            program_sections[no_sections].type=SECT_BSS;
            program_sections[no_sections].offset=file_offset;
            program_sections[no_sections].section_no=i;
            bss_size+=psec->get_size();
            no_sections++;
        }
    }

    // Perform any relocations that may be needed
	section *psec_reloc;
	for ( int i = 0; i < sec_num; i++ )
    {
        psec = reader.sections[i];
        if (psec->get_type()==SHT_RELA)
        {
			//relocation_section_accessor(reader,psec);
			Elf64_Addr   offset;
			Elf64_Addr   symbolValue;
			std::string  symbolName;
			Elf_Word     type;
			Elf_Sxword   addend;
			Elf_Sxword   calcValue;
			relocation_section_accessor relocs(reader,psec);
			for (Elf_Xword j=0;j<psec->get_size();j++)
			{
				relocs.get_entry(j, offset, symbolValue, symbolName, type, addend, calcValue);
				switch(type)
				{
				case R_68K_32:
					{
						std::cout << "yay, relocatable symbol!"<< std::endl;
						break;
					}
				case R_68K_16:
					{
						//Everything stays nicely aligned, nothing to do here
						break;
					}
				case R_68K_PC16:
					{
						std::cout << "Section" << i <<
							": 16-bit relocations not allowed (apparently)" 
							<< std::endl;
						break;
					}
				default:
					{
						std::cout << "What the hell kind of type that? "
							<< (int)type << "? Really?" << std::endl;
						break;
					}
				}
			}
		}
    }

	// TODO: look into making a proper GST symbol table
	for ( int i = 0; i < sec_num; i++ )
    {
        psec = reader.sections[i];
        if (psec->get_type()==SHT_SYMTAB)
        {
            //program_sections[no_sections].type=SECT_BSS;
            //program_sections[no_sections].offset=file_offset;
            //program_sections[no_sections].section_no=i;
			//program_sections[no_sections].reloc_needed=false;
            //bss_size+=psec->get_size();
            //no_sections++;
        }
    }


	// Calculate text, data and bss sizes
	/*for ( int i = 0; i < sec_num; ++i )
	{
		section* psec = reader.sections[i];

		switch(psec->get_type())
		{
		case SHT_PROGBITS:
			{
				if (psec->get_name() ==".text")
					text_size+=psec->get_size();
				else if (psec->get_name()==".data")
					data_size+=psec->get_size();
				break;
			}
		case SHT_SYMTAB:
			{
				break;
			}
		case SHT_RELA:
			{
				break;
			}
		case SHT_NOBITS:
			{
				bss_size+=psec->get_size();
				break;
			}
		default:
			break;
		}
	}*/

		std::cout << "Text size: " << /*hex << */ text_size << std::endl << 
			"Data size:" << data_size << std::endl << 
			"BSS size:" << bss_size << std::endl;
			


    return 0;
}

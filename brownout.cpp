/*

brownout - A humble .elf to ST .prg binary converter

Written by George Nakos and Douglas Litte.

Uses the elfio library by Serge Lamikhov-Center to do the
heavy lifting that is ELF parsing. Also used elfdump.cpp
from the examples folder as the basis for this source.
See elfio.hpp for its license.

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

#include <iostream>
#include <elfio/elfio_dump.hpp>
#include <elfio/elfio.hpp>
#include <stdio.h>
#include <stdlib.h>

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
    if ( argc != 3 && argc!=4) {
        printf( "Usage: brownout <input_elf_file_name> <output_tos_file_name> [PRGFLAGS]\n" );
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
    //dump::dynamic_tags   ( std::cout, reader );
    //dump::section_datas  ( std::cout, reader );
    //dump::segment_datas  ( std::cout, reader );

    // 

    Elf_Half sec_num=reader.sections.size();

    typedef struct
    {
        int         type;
        int         section_no;
        uint32_t    offset;
        uint32_t    size;
        const char  *data;
    } ST_SECTION;

    enum
    {
        SECT_TEXT,
        SECT_DATA,
        SECT_BSS
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

    typedef struct
    {
        uint32_t offset_fixup;  // Offset inside the section
        int section;            // Which section we're on
    } TOS_RELOC;

    PRG_HEADER toshead={0,0,0,0,0,0,0,0};   // Set up TOS header
    toshead.PRG_magic=0x601a;               // Mandatory
    if (argc==4)
        toshead.PRGFLAGS=atoi(argv[3]);

    TOS_RELOC tos_relocs[10*1024];  // Enough? Who knows!
    int no_relocs=0;

    uint32_t file_offset=28;        // first text section after the tos header
    ST_SECTION prg_sect[32];        // Enough? Who knows!
    int section_map[32];            // This keeps track of which elf section is mapped in which prg_sect index (i.e. a reverse look-up)
    int no_sect=0;

    section *psec;

    // TODO: refactor the following 3 loops into 1 by
    // making prg_sect [32][3] and iterating once again
    // to determine offsets into file?

    // Group text segments and determine their position inside the output file
    for ( int i = 0; i < sec_num; i++ )
    {
        psec = reader.sections[i];
        if (psec->get_type()==SHT_PROGBITS &&
            psec->get_name()==".text")
        {
            prg_sect[no_sect].type=SECT_TEXT;
            prg_sect[no_sect].offset=file_offset;
            prg_sect[no_sect].section_no=i;
            prg_sect[no_sect].size=(uint32_t)psec->get_size();
            prg_sect[no_sect].data=(const char *)psec->get_data();

            file_offset+=(uint32_t)psec->get_size();
            toshead.PRG_tsize+=(uint32_t)psec->get_size();
            section_map[i]=no_sect;         // Mark where in prg_sect this section will lie
            no_sect++;
        }
    }

    // Group data segments and determine their position inside the output file
    for ( int i = 0; i < sec_num; i++ )
    {
        psec = reader.sections[i];
        if (psec->get_type()==SHT_PROGBITS &&
            psec->get_name()==".data")
        {
            prg_sect[no_sect].type=SECT_DATA;
            prg_sect[no_sect].offset=file_offset;
            prg_sect[no_sect].section_no=i;
            prg_sect[no_sect].size=(uint32_t)psec->get_size();
            prg_sect[no_sect].data=(const char *)psec->get_data();
            file_offset+=(uint32_t)psec->get_size();
            toshead.PRG_dsize+=(uint32_t)psec->get_size();
            section_map[i]=no_sect;         // Mark where in prg_sect this section will lie
            no_sect++;
        }
    }

    // Group BSS segments and determine their position inside the output file
    for ( int i = 0; i < sec_num; i++ )
    {
        psec = reader.sections[i];
        if (psec->get_type()==SHT_NOBITS)
        {
            prg_sect[no_sect].type=SECT_BSS;
            prg_sect[no_sect].offset=file_offset;
            prg_sect[no_sect].section_no=i;
            prg_sect[no_sect].size=(uint32_t)psec->get_size();
            toshead.PRG_bsize+=(uint32_t)psec->get_size();
            no_sect++;
        }
    }

    // Perform any relocations that may be needed
    //section *psec_reloc;
    for ( int i = 0; i < sec_num; i++ )
    {
        psec = reader.sections[i];
        std::string sectname=psec->get_name();  // Debug
        int test1=sectname.find(".text");   // Check if this is a text relocation segment
        int test2=sectname.find(".data");   // Check if this is a data relocation segment
        if (psec->get_type()==SHT_RELA && (test1>0 || test2>0))
        {
            Elf64_Addr   offset;
            Elf64_Addr   symbolValue;
            std::string  symbolName;
            Elf_Word     type;
            Elf_Sxword   addend;
            Elf_Sxword   calcValue;
            relocation_section_accessor relocs(reader,psec);
            // r_offset, r_info&$ff, r_info>>8, r_addend
            // [(2, 1, 22, 0), (66, 1, 3, 0)]
            //int sec_size=(int)psec->get_size()/sizeof(Elf32_Rela);  //Number of entries in the table
            int sec_size=(int)relocs.get_entries_num();  //Number of entries in the table
            for (Elf_Xword j=0;j<sec_size;j++)
            {
                relocs.get_entry(j, offset, symbolValue, symbolName, type, addend, calcValue);
                //Elf_Word symbol;
                switch(type)
                {
                case R_68K_32:
                    {
                        std::cout << "Relocatable symbol " << j << " at section "<< i 
                            << " at offset " << offset << std::endl;
                        // TODO: Ok, we need to mark which section this relocation
                        // is refering to. For now we're going to blindly assume that it
                        // refers to the previous one as they usually go in pairs
                        // (.text / .rela.text). If this is bad then well, this is what
                        // to change!
                        tos_relocs[no_relocs].section=section_map[i-1];
                        tos_relocs[no_relocs].offset_fixup=(uint32_t)offset;
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
    for ( int i = 0; i < sec_num; i++ )
    {
        psec = reader.sections[i];
        if (psec->get_type()==SHT_SYMTAB)
        {
            //prg_sect[no_sect].type=SECT_BSS;
            //prg_sect[no_sect].offset=file_offset;
            //prg_sect[no_sect].section_no=i;
            //prg_sect[no_sect].reloc_needed=false;
            //bss_size+=psec->get_size();
            //no_sect++;
        }
    }

    // Print some basic info
    std::cout << "Text size: " << /*hex << */ toshead.PRG_tsize << std::endl << 
    "Data size:" << toshead.PRG_dsize << std::endl << 
    "BSS size:" << toshead.PRG_bsize << std::endl;

    // Open output file and write things
    FILE *tosfile=fopen(argv[2],"wb");

 
    // Byte swap prg header if needed
    // TODO: take care of portability stuff.... eventually
    PRG_HEADER writehead;
    writehead.PRG_magic=_byteswap_ushort(toshead.PRG_magic);
    writehead.PRG_tsize=_byteswap_ulong(toshead.PRG_tsize);
    writehead.PRG_dsize=_byteswap_ulong(toshead.PRG_dsize);
    writehead.PRG_bsize=_byteswap_ulong(toshead.PRG_bsize);
    writehead.PRG_ssize=_byteswap_ulong(toshead.PRG_ssize);
    writehead.PRG_res1=_byteswap_ulong(toshead.PRG_res1);
    writehead.PRGFLAGS=_byteswap_ulong(toshead.PRGFLAGS);
    writehead.ABSFLAG=_byteswap_ushort(toshead.ABSFLAG);

    // Write header
    fwrite(&writehead,sizeof(writehead),1,tosfile);

    // Write text and data sections
    for (int i=0;i<no_sect;i++)
    {
        if (prg_sect[i].type==SECT_TEXT || prg_sect[i].type==SECT_DATA)
        {
            fwrite(prg_sect[i].data,prg_sect[i].size,1,tosfile);
            file_offset+=prg_sect[i].size;

        }
        // TODO: Add padding after sections?
        // TODO2: For 030 executables pad sections to 4 bytes?
        // TODO3: For 030 executables, insert a nop at the start of the first
        //        text segment so the start of the code is aligned to 4 bytes?
        //        (TOS 4 aligns mallocs to 4 bytes but the header is 28 bytes)
    }

    // TODO: write symbol table
    if (toshead.PRG_ssize!=0)
    {
    }

    // Write relocation table
    if (no_relocs>0)
    {
        uint32_t current_reloc;
        uint32_t next_reloc;
        uint32_t diff;
        uint8_t temp;
        uint32_t temp_byteswap;
        // Handle first relocation separately as 
        // the offset needs to be a longword.
        current_reloc=tos_relocs[0].offset_fixup+prg_sect[tos_relocs[0].section].offset-28;
        temp_byteswap=_byteswap_ulong(current_reloc);
        fwrite(&temp_byteswap,4,1,tosfile);
        for (int i=1;i<no_relocs;i++)
        {
            next_reloc=tos_relocs[i].offset_fixup+prg_sect[tos_relocs[i].section].offset-28;
            diff=next_reloc-current_reloc;
            while (diff>254)
            {
                temp=1;
                fwrite(&temp,1,1,tosfile);
                diff-=254;
            }
            temp=diff;
            fwrite(&temp,1,1,tosfile);
            current_reloc=next_reloc;
        }
        // Finally, write a 0 to terminate the symbol table
        temp=0;
        fwrite(&temp,1,1,tosfile);
    }
    else
    {
        // Write a null longword to express list termination
        // (as suggested by the Atari Compendium chapter 2)
        fwrite(&no_relocs,4,1,tosfile);
    }

    // Done writing stuff
    fclose(tosfile);

    return 0;
}

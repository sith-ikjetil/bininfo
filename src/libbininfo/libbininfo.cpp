/*
* File: libbininfo.cpp
* Date: 2026-08-21
* Author: Kjetil Kristoffer Solberg <post@ikjetil.no>
* Description: Binary file inspection library.
**/
//
// #include
//
#include <elf.h>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include "../include/bininfo.h"

//
// using
//
using json = nlohmann::json;

//
// nammespace
//
namespace fs = std::filesystem;

//
// Function prototypes
//
static std::string machine_name(uint16_t machine);
static std::string machine_name(uint16_t machine);
static std::string hex_value(uint64_t value);
static std::string section_flags(uint64_t flags);
static std::string section_type_name(uint32_t type);
static json analyze_elf64(const std::string& filename);

//
// extern
//
extern "C" {
    //
    // (i): Gives bininfo library version.
    //
    const char *bininfo_version(void)
    {
        return "1.0";
    }

    //
    // (i): Gives analyze as json.
    //
    const char *bininfo_analyze_json(const char *filename)
    {        
        if (!filename) {
            json result = {
                {"success", false},
                {"error", {
                    {"code", "INVALID_ARGUMENT"},
                    {"message", "filename is null"}
                }}
            };

            std::string text = result.dump(2);

            char *buffer =
                static_cast<char*>(std::malloc(text.size() + 1));

            if (!buffer)
                return nullptr;

            std::memcpy(buffer, text.c_str(), text.size() + 1);

            return buffer;
        }

        json result;

        try {
            fs::path path(filename);

            if (!fs::is_regular_file(path)) {
                result = {
                    {"success", false},
                    {"error", {
                        {"code", "FILE_NOT_FOUND"},
                        {"message", "File does not exist or is not a regular file"}
                    }}
                };
            }
            else {
                std::ifstream file(filename, std::ios::binary);

                unsigned char ident[EI_NIDENT] {};

                file.read(
                    reinterpret_cast<char*>(ident),
                    sizeof(ident)
                );

                if (!file) {
                    result = {
                        {"success", false},
                        {"error", {
                            {"code", "READ_FAILED"},
                            {"message", "Unable to read file header"}
                        }}
                    };
                }
                else if (
                    ident[EI_MAG0] != ELFMAG0 ||
                    ident[EI_MAG1] != ELFMAG1 ||
                    ident[EI_MAG2] != ELFMAG2 ||
                    ident[EI_MAG3] != ELFMAG3)
                {
                    result = {
                        {"success", false},
                        {"error", {
                            {"code", "UNKNOWN_FORMAT"},
                            {"message", "File is not an ELF binary"}
                        }}
                    };
                }
                else if (ident[EI_CLASS] == ELFCLASS64) {
                    result = analyze_elf64(filename);
                }
                else if (ident[EI_CLASS] == ELFCLASS32) {
                    result = {
                        {"success", false},
                        {"error", {
                            {"code", "UNSUPPORTED"},
                            {"message", "ELF32 is not supported yet"}
                        }}
                    };
                }
                else {
                    result = {
                        {"success", false},
                        {"error", {
                            {"code", "INVALID_ELF"},
                            {"message", "Unknown ELF class"}
                        }}
                    };
                }
            }
        }
        catch (const std::exception& e) {
            result = {
                {"success", false},
                {"error", {
                    {"code", "EXCEPTION"},
                    {"message", e.what()}
                }}
            };
        }

        std::string text = result.dump(2);

        char *buffer =
            static_cast<char*>(std::malloc(text.size() + 1));

        if (!buffer)
            return nullptr;

        std::memcpy(
            buffer,
            text.c_str(),
            text.size() + 1
        );

        return buffer;
    }

    //
    // (i): Free's output (json/xml).
    //
    void bininfo_free(void *ptr) 
    {
        std::free(ptr);
    }
}

//
// Function: machine_name
//
// (i): Return machine name.
//
static std::string machine_name(uint16_t machine)
{
    switch (machine) {
        case EM_X86_64:  return "x86-64";
        case EM_386:     return "x86";
        case EM_AARCH64: return "AArch64";
        case EM_ARM:     return "ARM";
        case EM_RISCV:   return "RISC-V";
        default:         return "unknown";
    }
}

//
// Function: elf_type_name
//
// (i): Return elf type name as string.
//
static std::string elf_type_name(uint16_t type)
{
    switch (type) {
        case ET_NONE: return "none";
        case ET_REL:  return "relocatable";
        case ET_EXEC: return "executable";
        case ET_DYN:  return "shared-object";
        case ET_CORE: return "core";
        default:      return "unknown";
    }
}

//
// Function: hex_value
//
// (i): Output uint64_t as hex string.
//
static std::string hex_value(uint64_t value)
{
    std::ostringstream ss;
    ss << "0x"
       << std::hex
       << std::setw(16)
       << std::setfill('0')
       << value;

    return ss.str();
}

//
// Function: section_type_name
//
// (i): Output type of section as string.
//
static std::string section_type_name(uint32_t type)
{
    switch (type) {
        case SHT_NULL:     return "NULL";
        case SHT_PROGBITS: return "PROGBITS";
        case SHT_SYMTAB:   return "SYMTAB";
        case SHT_STRTAB:   return "STRTAB";
        case SHT_RELA:     return "RELA";
        case SHT_HASH:     return "HASH";
        case SHT_DYNAMIC:  return "DYNAMIC";
        case SHT_NOTE:     return "NOTE";
        case SHT_NOBITS:   return "NOBITS";
        case SHT_REL:      return "REL";
        case SHT_SHLIB:    return "SHLIB";
        case SHT_DYNSYM:   return "DYNSYM";
        case SHT_INIT_ARRAY: return "INIT_ARRAY";
        case SHT_FINI_ARRAY: return "FINI_ARRAY";
        case SHT_PREINIT_ARRAY: return "PREINIT_ARRAY";
        case SHT_GROUP:    return "GROUP";
        case SHT_SYMTAB_SHNDX: return "SYMTAB_SHNDX";

#ifdef SHT_GNU_HASH
        case SHT_GNU_HASH: return "GNU_HASH";
#endif

#ifdef SHT_GNU_verdef
        case SHT_GNU_verdef: return "GNU_VERDEF";
#endif

#ifdef SHT_GNU_verneed
        case SHT_GNU_verneed: return "GNU_VERNEED";
#endif

#ifdef SHT_GNU_versym
        case SHT_GNU_versym: return "GNU_VERSYM";
#endif

        default:
            return "UNKNOWN";
    }
}

//
// Function: section_flags
//
// (i): Output section flags as string.
//
static std::string section_flags(uint64_t flags)
{
    std::string result;

    if (flags & SHF_WRITE)
        result += "W";

    if (flags & SHF_ALLOC)
        result += "A";

    if (flags & SHF_EXECINSTR)
        result += "X";

    if (flags & SHF_MERGE)
        result += "M";

    if (flags & SHF_STRINGS)
        result += "S";

    if (flags & SHF_INFO_LINK)
        result += "I";

    if (flags & SHF_LINK_ORDER)
        result += "L";

    if (flags & SHF_OS_NONCONFORMING)
        result += "O";

    if (flags & SHF_GROUP)
        result += "G";

    if (flags & SHF_TLS)
        result += "T";

    return result;
}

//
// Functioon: analyze_elf64
//
// (i): Analyze ELF64
//
static json analyze_elf64(const std::string& filename)
{
    std::ifstream file(filename, std::ios::binary);

    if (!file) {
        return {
            {"success", false},
            {"error", {
                {"code", "OPEN_FAILED"},
                {"message", "Unable to open file"}
            }}
        };
    }

    uint64_t file_size = 0;

    try {
        file_size = fs::file_size(filename);
    }
    catch (const std::exception& e) {
        return {
            {"success", false},
            {"error", {
                {"code", "FILE_SIZE_FAILED"},
                {"message", e.what()}
            }}
        };
    }

    if (file_size < sizeof(Elf64_Ehdr)) {
        return {
            {"success", false},
            {"error", {
                {"code", "INVALID_ELF"},
                {"message", "File is smaller than an ELF64 header"}
            }}
        };
    }

    Elf64_Ehdr ehdr {};

    file.read(
        reinterpret_cast<char*>(&ehdr),
        sizeof(ehdr)
    );

    if (!file) {
        return {
            {"success", false},
            {"error", {
                {"code", "READ_FAILED"},
                {"message", "Unable to read ELF64 header"}
            }}
        };
    }

    /*
     * Verify ELF magic.
     */
    if (ehdr.e_ident[EI_MAG0] != ELFMAG0 ||
        ehdr.e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr.e_ident[EI_MAG2] != ELFMAG2 ||
        ehdr.e_ident[EI_MAG3] != ELFMAG3)
    {
        return {
            {"success", false},
            {"error", {
                {"code", "INVALID_ELF"},
                {"message", "Invalid ELF magic"}
            }}
        };
    }

    if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        return {
            {"success", false},
            {"error", {
                {"code", "INVALID_ELF_CLASS"},
                {"message", "File is not ELF64"}
            }}
        };
    }

    /*
     * For now this parser assumes little-endian ELF64.
     */
    if (ehdr.e_ident[EI_DATA] != ELFDATA2LSB) {
        return {
            {"success", false},
            {"error", {
                {"code", "UNSUPPORTED_ENDIANNESS"},
                {"message", "Big-endian ELF64 is not supported yet"}
            }}
        };
    }

    /*
     * Validate section-header entry size.
     */
    if (ehdr.e_shnum != 0 &&
        ehdr.e_shentsize != sizeof(Elf64_Shdr))
    {
        return {
            {"success", false},
            {"error", {
                {"code", "INVALID_SECTION_HEADER"},
                {"message", "Unexpected ELF section header size"}
            }}
        };
    }

    /*
     * Validate section-header table bounds.
     */
    const uint64_t section_table_size =
        static_cast<uint64_t>(ehdr.e_shnum) *
        sizeof(Elf64_Shdr);

    if (ehdr.e_shnum != 0) {
        if (ehdr.e_shoff > file_size ||
            section_table_size > file_size - ehdr.e_shoff)
        {
            return {
                {"success", false},
                {"error", {
                    {"code", "INVALID_SECTION_TABLE"},
                    {"message", "Section header table is outside the file"}
                }}
            };
        }
    }

    /*
     * Construct the main result.
     */
    json result;

    result["success"] = true;
    result["schemaVersion"] = 1;

    result["file"] = {
        {"path", filename},
        {"size", file_size}
    };

    result["binary"] = {
        {"format", "ELF"},
        {"class", "ELF64"},
        {"architecture", machine_name(ehdr.e_machine)},
        {"type", elf_type_name(ehdr.e_type)},
        {"entryPoint", hex_value(ehdr.e_entry)}
    };

    switch (ehdr.e_ident[EI_DATA]) {
        case ELFDATA2LSB:
            result["binary"]["endianness"] = "little";
            break;

        case ELFDATA2MSB:
            result["binary"]["endianness"] = "big";
            break;

        default:
            result["binary"]["endianness"] = "unknown";
            break;
    }

    /*
     * ELF-header-specific information.
     */
    result["elf"] = {
        {"version", ehdr.e_version},

        {"programHeaderOffset", ehdr.e_phoff},
        {"programHeaderEntrySize", ehdr.e_phentsize},
        {"programHeaderCount", ehdr.e_phnum},

        {"sectionHeaderOffset", ehdr.e_shoff},
        {"sectionHeaderEntrySize", ehdr.e_shentsize},
        {"sectionHeaderCount", ehdr.e_shnum},

        {"sectionNameTableIndex", ehdr.e_shstrndx},

        {"flags", ehdr.e_flags},
        {"headerSize", ehdr.e_ehsize}
    };

    /*
     * Arrays that may be empty.
     */
    result["sections"] = json::array();
    result["imports"] = json::array();
    result["exports"] = json::array();
    result["dependencies"] = json::array();

    /*
     * Some ELF files can legally have no section table.
     */
    if (ehdr.e_shnum == 0) {
        result["importCount"] = 0;
        result["exportCount"] = 0;
        result["dependencyCount"] = 0;
        return result;
    }

    /*
     * Read all section headers.
     */
    std::vector<Elf64_Shdr> sections(ehdr.e_shnum);

    file.clear();

    file.seekg(
        static_cast<std::streamoff>(ehdr.e_shoff),
        std::ios::beg
    );

    if (!file) {
        return {
            {"success", false},
            {"error", {
                {"code", "SEEK_FAILED"},
                {"message", "Unable to seek to ELF section table"}
            }}
        };
    }

    file.read(
        reinterpret_cast<char*>(sections.data()),
        static_cast<std::streamsize>(
            sections.size() * sizeof(Elf64_Shdr)
        )
    );

    if (!file) {
        return {
            {"success", false},
            {"error", {
                {"code", "READ_FAILED"},
                {"message", "Unable to read ELF section headers"}
            }}
        };
    }

    /*
     * Section-name string table.
     */
    std::vector<char> section_names;
    uint64_t section_name_table_size = 0;

    if (ehdr.e_shstrndx != SHN_UNDEF) {

        if (ehdr.e_shstrndx >= sections.size()) {
            return {
                {"success", false},
                {"error", {
                    {"code", "INVALID_STRING_TABLE"},
                    {"message", "Invalid section-name string table index"}
                }}
            };
        }

        const Elf64_Shdr& shstr =
            sections[ehdr.e_shstrndx];

        if (shstr.sh_type != SHT_STRTAB) {
            return {
                {"success", false},
                {"error", {
                    {"code", "INVALID_STRING_TABLE"},
                    {"message", "Section-name table is not a string table"}
                }}
            };
        }

        if (shstr.sh_offset > file_size ||
            shstr.sh_size > file_size - shstr.sh_offset)
        {
            return {
                {"success", false},
                {"error", {
                    {"code", "INVALID_STRING_TABLE"},
                    {"message", "Section-name string table is outside the file"}
                }}
            };
        }

        section_name_table_size = shstr.sh_size;

        section_names.assign(
            static_cast<size_t>(shstr.sh_size) + 1,
            '\0'
        );

        file.clear();

        file.seekg(
            static_cast<std::streamoff>(shstr.sh_offset),
            std::ios::beg
        );

        if (!file) {
            return {
                {"success", false},
                {"error", {
                    {"code", "SEEK_FAILED"},
                    {"message", "Unable to seek to section-name string table"}
                }}
            };
        }

        file.read(
            section_names.data(),
            static_cast<std::streamsize>(shstr.sh_size)
        );

        if (!file) {
            return {
                {"success", false},
                {"error", {
                    {"code", "READ_FAILED"},
                    {"message", "Unable to read section-name string table"}
                }}
            };
        }
    }

    /*
     * Retrieve a section name safely.
     */
    auto get_section_name =
        [&](const Elf64_Shdr& sh) -> std::string
    {
        if (section_names.empty())
            return "";

        if (sh.sh_name >= section_name_table_size)
            return "<invalid>";

        const char* start =
            section_names.data() + sh.sh_name;

        const size_t remaining =
            static_cast<size_t>(
                section_name_table_size - sh.sh_name
            );

        const void* end =
            std::memchr(start, '\0', remaining);

        if (!end)
            return "<invalid>";

        return std::string(
            start,
            static_cast<const char*>(end) - start
        );
    };

    /*
     * Parse each section.
     */
    for (size_t i = 0; i < sections.size(); ++i) {

        const Elf64_Shdr& sh = sections[i];

        const std::string name =
            get_section_name(sh);

        bool section_bounds_valid = true;

        if (sh.sh_type != SHT_NOBITS && sh.sh_size != 0) {
            if (sh.sh_offset > file_size ||
                sh.sh_size > file_size - sh.sh_offset)
            {
                section_bounds_valid = false;
            }
        }

        json section = {
            {"index", i},
            {"name", name},

            {"type", section_type_name(sh.sh_type)},
            {"typeValue", sh.sh_type},

            {"flags", section_flags(sh.sh_flags)},
            {"flagsValue", sh.sh_flags},

            {"address", hex_value(sh.sh_addr)},
            {"offset", sh.sh_offset},
            {"size", sh.sh_size},

            {"alignment", sh.sh_addralign},
            {"entrySize", sh.sh_entsize},

            {"link", sh.sh_link},
            {"info", sh.sh_info},

            {"storedInFile", sh.sh_type != SHT_NOBITS},
            {"boundsValid", section_bounds_valid}
        };

        result["sections"].push_back(section);
    }

    /*
     * ------------------------------------------------------------
     * Parse shared-library dependencies.
     * ------------------------------------------------------------
     *
     * SHT_DYNAMIC contains Elf64_Dyn entries.
     *
     * DT_NEEDED entries contain offsets into the dynamic string
     * table. sh_link identifies that string table, normally .dynstr.
     */
    for (size_t section_index = 0;
         section_index < sections.size();
         ++section_index)
    {
        const Elf64_Shdr& dynamic_section =
            sections[section_index];

        if (dynamic_section.sh_type != SHT_DYNAMIC)
            continue;

        /*
         * sh_link identifies the associated dynamic string table.
         */
        if (dynamic_section.sh_link >= sections.size())
            continue;

        const Elf64_Shdr& dynamic_strtab =
            sections[dynamic_section.sh_link];

        if (dynamic_strtab.sh_type != SHT_STRTAB)
            continue;

        /*
         * Validate .dynamic bounds.
         */
        if (dynamic_section.sh_offset > file_size ||
            dynamic_section.sh_size >
                file_size - dynamic_section.sh_offset)
        {
            continue;
        }

        /*
         * Validate .dynstr bounds.
         */
        if (dynamic_strtab.sh_offset > file_size ||
            dynamic_strtab.sh_size >
                file_size - dynamic_strtab.sh_offset)
        {
            continue;
        }

        uint64_t dynamic_entry_size =
            dynamic_section.sh_entsize;

        if (dynamic_entry_size == 0)
            dynamic_entry_size = sizeof(Elf64_Dyn);

        if (dynamic_entry_size < sizeof(Elf64_Dyn))
            continue;

        const uint64_t dynamic_entry_count =
            dynamic_section.sh_size /
            dynamic_entry_size;

        /*
         * Read the dynamic string table.
         */
        std::vector<char> dynamic_strings(
            static_cast<size_t>(dynamic_strtab.sh_size) + 1,
            '\0'
        );

        file.clear();

        file.seekg(
            static_cast<std::streamoff>(
                dynamic_strtab.sh_offset
            ),
            std::ios::beg
        );

        if (!file)
            continue;

        file.read(
            dynamic_strings.data(),
            static_cast<std::streamsize>(
                dynamic_strtab.sh_size
            )
        );

        if (!file)
            continue;

        /*
         * Parse each Elf64_Dyn entry.
         */
        for (uint64_t dynamic_index = 0;
             dynamic_index < dynamic_entry_count;
             ++dynamic_index)
        {
            const uint64_t dynamic_offset =
                dynamic_section.sh_offset +
                dynamic_index * dynamic_entry_size;

            if (dynamic_offset > file_size ||
                sizeof(Elf64_Dyn) >
                    file_size - dynamic_offset)
            {
                break;
            }

            Elf64_Dyn dyn {};

            file.clear();

            file.seekg(
                static_cast<std::streamoff>(
                    dynamic_offset
                ),
                std::ios::beg
            );

            if (!file)
                break;

            file.read(
                reinterpret_cast<char*>(&dyn),
                sizeof(dyn)
            );

            if (!file)
                break;

            /*
             * DT_NULL terminates the dynamic array.
             */
            if (dyn.d_tag == DT_NULL)
                break;

            /*
             * DT_NEEDED identifies a required shared library.
             */
            if (dyn.d_tag != DT_NEEDED)
                continue;

            const uint64_t name_offset =
                dyn.d_un.d_val;

            if (name_offset >= dynamic_strtab.sh_size)
                continue;

            const char* start =
                dynamic_strings.data() + name_offset;

            const size_t remaining =
                static_cast<size_t>(
                    dynamic_strtab.sh_size -
                    name_offset
                );

            const void* end =
                std::memchr(
                    start,
                    '\0',
                    remaining
                );

            if (!end)
                continue;

            std::string dependency_name(
                start,
                static_cast<const char*>(end) - start
            );

            if (dependency_name.empty())
                continue;

            result["dependencies"].push_back(
                dependency_name
            );
        }
    }

    /*
     * ELF symbol helper functions.
     */
    auto symbol_binding_name =
        [](unsigned char info) -> const char*
    {
        switch (ELF64_ST_BIND(info)) {

            case STB_LOCAL:
                return "LOCAL";

            case STB_GLOBAL:
                return "GLOBAL";

            case STB_WEAK:
                return "WEAK";

#ifdef STB_GNU_UNIQUE
            case STB_GNU_UNIQUE:
                return "GNU_UNIQUE";
#endif

            default:
                return "UNKNOWN";
        }
    };

    auto symbol_type_name =
        [](unsigned char info) -> const char*
    {
        switch (ELF64_ST_TYPE(info)) {

            case STT_NOTYPE:
                return "NOTYPE";

            case STT_OBJECT:
                return "OBJECT";

            case STT_FUNC:
                return "FUNC";

            case STT_SECTION:
                return "SECTION";

            case STT_FILE:
                return "FILE";

            case STT_COMMON:
                return "COMMON";

            case STT_TLS:
                return "TLS";

#ifdef STT_GNU_IFUNC
            case STT_GNU_IFUNC:
                return "GNU_IFUNC";
#endif

            default:
                return "UNKNOWN";
        }
    };

    auto symbol_visibility_name =
        [](unsigned char other) -> const char*
    {
        switch (ELF64_ST_VISIBILITY(other)) {

            case STV_DEFAULT:
                return "DEFAULT";

            case STV_INTERNAL:
                return "INTERNAL";

            case STV_HIDDEN:
                return "HIDDEN";

            case STV_PROTECTED:
                return "PROTECTED";

            default:
                return "UNKNOWN";
        }
    };

    /*
     * Parse dynamic symbol tables.
     */
    for (size_t section_index = 0;
         section_index < sections.size();
         ++section_index)
    {
        const Elf64_Shdr& symtab =
            sections[section_index];

        if (symtab.sh_type != SHT_DYNSYM)
            continue;

        if (symtab.sh_link >= sections.size())
            continue;

        const Elf64_Shdr& strtab =
            sections[symtab.sh_link];

        if (strtab.sh_type != SHT_STRTAB)
            continue;

        if (symtab.sh_offset > file_size ||
            symtab.sh_size > file_size - symtab.sh_offset)
        {
            continue;
        }

        if (strtab.sh_offset > file_size ||
            strtab.sh_size > file_size - strtab.sh_offset)
        {
            continue;
        }

        uint64_t symbol_entry_size =
            symtab.sh_entsize;

        if (symbol_entry_size == 0)
            symbol_entry_size = sizeof(Elf64_Sym);

        if (symbol_entry_size < sizeof(Elf64_Sym))
            continue;

        const uint64_t symbol_count =
            symtab.sh_size / symbol_entry_size;

        std::vector<char> symbol_names(
            static_cast<size_t>(strtab.sh_size) + 1,
            '\0'
        );

        file.clear();

        file.seekg(
            static_cast<std::streamoff>(strtab.sh_offset),
            std::ios::beg
        );

        if (!file)
            continue;

        file.read(
            symbol_names.data(),
            static_cast<std::streamsize>(strtab.sh_size)
        );

        if (!file)
            continue;

        for (uint64_t symbol_index = 0;
             symbol_index < symbol_count;
             ++symbol_index)
        {
            const uint64_t symbol_offset =
                symtab.sh_offset +
                symbol_index * symbol_entry_size;

            if (symbol_offset > file_size ||
                sizeof(Elf64_Sym) >
                    file_size - symbol_offset)
            {
                break;
            }

            Elf64_Sym symbol {};

            file.clear();

            file.seekg(
                static_cast<std::streamoff>(
                    symbol_offset
                ),
                std::ios::beg
            );

            if (!file)
                break;

            file.read(
                reinterpret_cast<char*>(&symbol),
                sizeof(symbol)
            );

            if (!file)
                break;

            if (symbol.st_name == 0)
                continue;

            if (symbol.st_name >= strtab.sh_size)
                continue;

            const char* start =
                symbol_names.data() + symbol.st_name;

            const size_t remaining =
                static_cast<size_t>(
                    strtab.sh_size -
                    symbol.st_name
                );

            const void* end =
                std::memchr(
                    start,
                    '\0',
                    remaining
                );

            if (!end)
                continue;

            std::string symbol_name(
                start,
                static_cast<const char*>(end) - start
            );

            if (symbol_name.empty())
                continue;

            const unsigned binding =
                ELF64_ST_BIND(symbol.st_info);

            const unsigned type =
                ELF64_ST_TYPE(symbol.st_info);

            const unsigned visibility =
                ELF64_ST_VISIBILITY(symbol.st_other);

            /*
             * Only callable functions.
             */
            bool is_function =
                type == STT_FUNC;

#ifdef STT_GNU_IFUNC
            if (type == STT_GNU_IFUNC)
                is_function = true;
#endif

            if (!is_function)
                continue;

            json symbol_json = {
                {"name", symbol_name},

                {"binding",
                    symbol_binding_name(symbol.st_info)},

                {"type",
                    symbol_type_name(symbol.st_info)},

                {"visibility",
                    symbol_visibility_name(symbol.st_other)},

                {"value",
                    hex_value(symbol.st_value)},

                {"size",
                    symbol.st_size},

                {"sectionIndex",
                    symbol.st_shndx},

                {"symbolIndex",
                    symbol_index},

                {"symbolTable",
                    get_section_name(symtab)}
            };

            /*
             * IMPORT
             */
            if (symbol.st_shndx == SHN_UNDEF) {

                if (binding == STB_GLOBAL ||
                    binding == STB_WEAK)
                {
                    result["imports"].push_back(
                        std::move(symbol_json)
                    );
                }

                continue;
            }

            /*
             * EXPORT
             *
             * Only strong GLOBAL functions.
             */
            if (binding != STB_GLOBAL)
                continue;

            if (visibility != STV_DEFAULT &&
                visibility != STV_PROTECTED)
            {
                continue;
            }

            result["exports"].push_back(
                std::move(symbol_json)
            );
        }
    }

    /*
     * Final counts.
     */
    result["importCount"] =
        result["imports"].size();

    result["exportCount"] =
        result["exports"].size();

    result["dependencyCount"] =
        result["dependencies"].size();

    return result;
}
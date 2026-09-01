/*
* File: bininfo.cpp
* Date: 2026-08-21
* Author: Kjetil Kristoffer Solberg <post@ikjetil.no>
* Description: A utility that outputs data about ELF32/ELF64 as JSON. 
*/
//
// #include
//
#include <elf.h>
#include <stddef.h>
#include <iostream>
#include <string>
#include <print>
#include <filesystem>
#include <nlohmann/json.hpp>
#include "../include/bininfo.h"

//
// using
//
using json = nlohmann::json;
using std::cerr;
using std::cout;
using std::println;
using std::endl;
using std::string;

//
// namespace
//
namespace fs = std::filesystem;

//
// namespace BinInfo
//
namespace BinInfo {
    //
    // Function prototypes.
    //
    void PrintUsageScreen();
    bool IsArgSet(string token, int argc, char** argv);
    string GetArgFilename(int argc, char** argv);
    void print_as_text(const char* result);

    //
    // Function: BinInfo::main
    //
    // (i): Main entry point.
    //
    int main(int argc, char** argv) {
        string filename = GetArgFilename(argc, argv);

        if (filename.empty()) {
            PrintUsageScreen();
            return 1;
        }

        const char *result = bininfo_analyze_json(filename.c_str(), IsArgSet("--include-exports",argc, argv), IsArgSet("--include-imports",argc,argv), IsArgSet("--include-sections",argc,argv));

        if (!result) {
            println(stderr, "Unable to analyze file");
            return 1;
        }

        if (IsArgSet("--format=json",argc,argv)) {            
            println("{}", result);
        }
        else {
            print_as_text(result);
        }

        bininfo_free(reinterpret_cast<void*>(const_cast<char*>(result)));

        return 0;
    }    

    //
    // Function: PrintUsageScreen
    //
    // (i): Outputs usage information.
    //
    void PrintUsageScreen() {
        println("Usage: bininfo [options] <filename>");
        println("Version: 1.3");
        println("Outputs information from binary ELF64 files as JSON to stdout");
        println();
        println("Options:");
        println("  --include-exports     Include exports in output.");
        println("  --include-imports     Include imports in output.");
        println("  --include-sections    Include sections in output.");
        println("  --format=text         Display a concise text summary (default).");
        println("  --format=json         Display a complete analysis as JSON.");
        println();
        println("Examples:");
        println("  bininfo /usr/bin/ls                       Outputs default info.");        
        println("  bininfo /usr/bin/ls --include-exports     Outputs info including exports.");
        println("  bininfo /usr/bin/ls --include-imports     Outputs info including imports.");
        println("  bininfo /usr/bin/ls --include-sections    Outputs info including sections.");
        println("  bininfo /usr/bin/ls | ccat --syntax=json  Outputs info and colorize output.");
        println();
        println("Created by Kjetil Kristoffer Solberg <post@ikjetil.no>.");
        println("Written in C++.");
        println();
    }

    //
    // Function: IsArgSet
    //
    // (i): Returnes true if token is set. False otherwise.
    //
    bool IsArgSet(string token, int argc, char** argv) {
        for (int i = 1; i < argc; i++) {
            if (token == argv[i]) {
                return true;
            }
        }
        return false;
    }

    //
    // Function: GetArgFilename
    //
    // (i): Returnes the first valid filename argument or empty string.
    //
    string GetArgFilename(int argc, char** argv) {
        for (int i = 1; i < argc; i++) {
            if (fs::exists(argv[i])) {
                return argv[i];
            }
        }
        return "";
    }

    //
    // Function: print_as_text
    //
    // (i): Prints default output as text output.
    //
    void print_as_text(const char* result)
    {
        try
        {
            json j = json::parse(result);

            if (!j.value("success", false))
            {
                std::println("Analysis failed.");
                return;
            }

            // File
            if (j.contains("file"))
            {
                const auto& file = j["file"];

                std::println("File");
                std::println("  Path:              {}",
                            file.value("path", "unknown"));

                std::println("  Size:              {} bytes",
                            file.value("size", 0ULL));

                std::println("");
            }

            // Binary
            if (j.contains("binary"))
            {
                const auto& binary = j["binary"];

                std::println("Binary");
                std::println("  Format:            {}",
                            binary.value("format", "unknown"));

                std::println("  Class:             {}",
                            binary.value("class", "unknown"));

                std::println("  Architecture:      {}",
                            binary.value("architecture", "unknown"));

                std::println("  Type:              {}",
                            binary.value("type", "unknown"));

                std::println("  Endianness:        {}",
                            binary.value("endianness", "unknown"));

                std::println("  Entry point:       {}",
                            binary.value("entryPoint", "unknown"));

                std::println("");
            }

            // Dependencies
            if (j.contains("dependencies") &&
                j["dependencies"].is_array())
            {
                std::println("Dependencies ({})",
                            j["dependencies"].size());

                for (const auto& dependency : j["dependencies"])
                {
                    if (dependency.is_string())
                        std::println("  {}", dependency.get<std::string>());
                }

                std::println("");
            }

            // ELF-specific information
            if (j.contains("elf"))
            {
                const auto& elf = j["elf"];

                std::println("ELF");
                std::println("  Version:           {}",
                            elf.value("version", 0));

                std::println("  Header size:       {} bytes",
                            elf.value("headerSize", 0));

                std::println("  Program headers:   {}",
                            elf.value("programHeaderCount", 0));

                std::println("  Section headers:   {}",
                            elf.value("sectionHeaderCount", 0));

                std::println("  Program hdr offset:{}",
                            elf.value("programHeaderOffset", 0ULL));

                std::println("  Section hdr offset:{}",
                            elf.value("sectionHeaderOffset", 0ULL));

                std::println("  Flags:             {}",
                            elf.value("flags", 0));
            }
        }
        catch (const json::parse_error& e)
        {
            std::println(stderr, "Invalid JSON: {}", e.what());
        }
    }
}// namespace BinInfo

//
// Function: main
//
// (i): Main entry point redirection
//
int main(int argc, char** argv) {
    return BinInfo::main(argc,argv);
}
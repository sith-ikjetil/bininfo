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
#include "../include/bininfo.h"

//
// using
//
using std::cerr;
using std::cout;
using std::println;
using std::endl;
using std::string;

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
            cerr << "Unable to analyze file\n";
            return 1;
        }

        cout << result << '\n';

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
        println("Version: 1.2");
        println("Outputs information from binary ELF64 files as JSON to stdout");
        println();
        println("Options:");
        println("  --include-exports     include exports in output.");
        println("  --include-imports     include imports in output.");
        println("  --include-sections    include sections in output.");
        println();
        println("Examples:");
        println("  bininfo /usr/bin/ls                       Outputs default info");
        println("  bininfo /usr/bin/ls --include-exports     Outputs info including exports");
        println("  bininfo /usr/bin/ls --include-imports     Outputs info including imports");
        println("  bininfo /usr/bin/ls --include-sections    Outputs info including sections");
        println("  bininfo /usr/bin/ls | ccat --syntax=json  Outputs info and colorize output");
        println();
        println("Created by Kjetil Kristoffer Solberg <post@ikjetil.no>");
        println("Written in C++");
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
            if (std::filesystem::exists(argv[i])) {
                return argv[i];
            }
        }
        return "";
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
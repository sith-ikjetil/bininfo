/*
* File: bininfo.cpp
* Author: Kjetil Kristoffer Solberg <post@ikjetil.no>
* Description: A utility that outputs data about ELF32/ELF64 as JSON.
* Date: 2026-08-21
**/
//
// #include
//
#include <elf.h>
#include <stddef.h>
#include <iostream>
#include <string>
#include "../include/bininfo.h"

//
//
//
using std::cerr;
using std::cout;
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

    //
    // Function: BinInfo::main
    //
    // (i): Main entry point.
    //
    int main(int argc, char** argv) {
        if (argc < 2) {
            PrintUsageScreen();
            return 1;
        }

        const char *result = bininfo_analyze_json(argv[1], IsArgSet("--include-exports",argc, argv), IsArgSet("--include-imports",argc,argv), IsArgSet("--include-sections",argc,argv));

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
        cout << "Usage: bininfo <filename>" << endl;
        cout << "Version: 1.1" << endl;
        cout << "Outputs information from binary ELF64 files as JSON to stdout" << endl;
        cout << endl;
        cout << "  --include-exports     include exports in output." << endl;
        cout << "  --include-imports     include imports in output." << endl;
        cout << "  --include-sections    include sections in output." << endl;
        cout << endl;
        cout << "Examples:" << endl;
        cout << "  bininfo /usr/bin/ls                       Outputs default info" << endl;
        cout << "  bininfo /usr/bin/ls --include-exports     Outputs info including exports" << endl;
        cout << "  bininfo /usr/bin/ls --include-imports     Outputs info including imports" << endl;
        cout << "  bininfo /usr/bin/ls --include-sections    Outputs info including sections" << endl;
        cout << "  bininfo /usr/bin/ls | ccat --syntax=json  Outputs info and colorize output" << endl;
        cout << endl;
        cout << "Created by Kjetil Kristoffer Solberg <post@ikjetil.no>" << endl;
        cout << "Written in C++" << endl;        
        cout << endl;
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
}

//
// Function: main
//
// (i): Main entry point redirection
//
int main(int argc, char** argv) {
    return BinInfo::main(argc,argv);
}
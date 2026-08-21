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

    //
    // Function: BinInfo::main
    //
    // (i): Main entry point.
    //
    int main(int argc, char** argv) {
        if (argc != 2) {
            PrintUsageScreen();
            return 1;
        }

        const char *result = bininfo_analyze_json(argv[1]);

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
        cout << "Version: 1.0" << endl;
        cout << "Outputs information from binary ELF64 files as JSON" << endl;
        cout << endl;
        cout << "Created by Kjetil Kristoffer Solberg <post@ikjetil.no>" << endl;
        cout << "Written in C++" << endl;        
        cout << endl;
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
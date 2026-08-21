#!/bin/bash
#: Title       : build-debug.sh
#: Date        : 2026-08-21
#: Author      : Kjetil Kristoffer Solberg <post@ikjetil.no>
#: Version     : 1.0
#: Description : Builds libbininfo.so.
echo "Building libbininfo..."
echo "> using debug build <"
g++ -ggdb -std=c++23 -fPIC -shared libbininfo.cpp -o libbininfo.so
if [[ $? -eq 0 ]]
then
    echo "> libbininfo build ok <"
    cp libbininfo.so ../bininfo
else
    echo "> libbininfo build error <"
fi
echo "> build process complete <"

echo ""
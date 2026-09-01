#!/bin/bash
#: Title       : build-debug.sh
#: Date        : 2026-08-21
#: Author      : Kjetil Kristoffer Solberg <post@ikjetil.no>
#: Version     : 1.0
#: Description : Builds bininfo shell utility.
echo "Building bininfo..."
echo "> using debug build <"
g++ -g -O0 bininfo.cpp -std=c++23 -Wl,-rpath,'$ORIGIN' -L. -lbininfo -o bininfo
if [[ $? -eq 0 ]]
then
    echo "> bininfo build ok <"
else
    echo "> bininfo build error <"
fi
echo "> build process complete <"

echo ""
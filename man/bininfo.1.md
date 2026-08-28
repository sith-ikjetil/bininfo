% bininfo(1) bininfo 1.1
% Written by Kjetil Kristoffer Solberg
% August 2026

# NAME
bininfo - outputs information from binary ELF64 files as JSON

# SYNOPSIS
**bininfo** [*FILE*]  

# DESCRIPTION
Outputs information from binary ELF64 files to stdout as JSON

# EXAMPLES
**bininfo** /usr/bin/ls  
Outputs default info  

**bininfo** /usr/bin/ls -\-include-exports  
Outputs info including exports  

**bininfo** /usr/bin/ls -\-include-imports  
Outputs info including imports  

**bininfo** /usr/bin/ls -\-include-sections  
Outputs info including sections  

**bininfo** /usr/bin/ls | ccat -\-syntax=json  
Outputs info and colorize output  

# BUGS
All software have bugs :)

# COPYRIGHT
License GPL-3.0-or-later. This is free software: you are free to change and redistribute it. There is NO WARRENTY, to the extent permitted by law.

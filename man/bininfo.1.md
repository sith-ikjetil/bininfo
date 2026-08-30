% bininfo(1) bininfo 1.2
% Written by Kjetil Kristoffer Solberg
% August 2026

# NAME
bininfo - outputs information from binary ELF64 files as JSON

# SYNOPSIS
**bininfo** [*OPTIONS*] [*FILE*]  

# DESCRIPTION
Outputs information from binary ELF64 files to stdout as JSON

# OPTIONS
**-\-include-exports**     include exports in output  
**-\-include-imports**     include imports in output  
**-\-include-sections**    include sections in output  

# EXAMPLES
**bininfo** /usr/bin/ls  
Outputs default info  

**bininfo** -\-include-exports /usr/bin/ls  
Outputs info including exports  

**bininfo** -\-include-imports /usr/bin/ls  
Outputs info including imports  

**bininfo** -\-include-sections /usr/bin/ls  
Outputs info including sections  

**bininfo** /usr/bin/ls | ccat -\-syntax=json  
Outputs info and colorize output  

# BUGS
All software have bugs :)

# COPYRIGHT
License GPL-3.0-or-later. This is free software: you are free to change and redistribute it. There is NO WARRENTY, to the extent permitted by law.

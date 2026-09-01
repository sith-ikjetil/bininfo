% bininfo(1) bininfo 1.3
% Written by Kjetil Kristoffer Solberg
% September 2026

# NAME
bininfo - outputs information from binary ELF64 files as JSON.

# SYNOPSIS
**bininfo** [*OPTIONS*] [*FILE*]  

# DESCRIPTION
Outputs information from binary ELF64 files to stdout as JSON.

# OPTIONS
**-\-include-exports**     Include exports in output.  
**-\-include-imports**     Include imports in output.  
**-\-include-sections**    Include sections in output.  
**-\-format=text**         Display a concise text summary (default).  
**-\-format=json**         Display a complete analysis as JSON.  
**-\-color=auto**          Color when stdout is a terminal.  
**-\-color=always**        Always emit ANSI colors.  
**-\-color=never**         Never emit ANSI colors.  

# EXAMPLES
**bininfo** /usr/bin/ls  
Outputs default info.  

**bininfo** -\-include-exports /usr/bin/ls  
Outputs info including exports.  

**bininfo** -\-include-imports /usr/bin/ls  
Outputs info including imports.  

**bininfo** -\-include-sections /usr/bin/ls  
Outputs info including sections.  

**bininfo** /usr/bin/ls | ccat -\-syntax=json  
Outputs info and colorize output.  

# BUGS
All software have bugs :)

# COPYRIGHT
License GPL-3.0-or-later. This is free software: you are free to change and redistribute it. There is NO WARRENTY, to the extent permitted by law.

# p4backup
A small backup script for perforce instances which does not require p4api nor p4dctl.

Supports checkpointing, verifying checkpoints, and archiving the whole depot.

usage: p4backup.py [-h] [-v] [-c] [-b]

optional arguments:

  -h, --help        show this help message and exit  
  -v, --verify      Runs p4 verify  
  -c, --checkpoint  Runs p4 checkpoint  
  -b, --backup      Runs full backup

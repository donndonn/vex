#!/usr/bin/env python

import re
import os
import subprocess
import sys

p = re.compile("\S+:\s*(\S+\s+\S+\s+\S+\s+\S+)\s+(.*)")

def write_bb(out, line, bb):
    out.write("\n")
    r = p.search(line)
    if r == None:
        raise Exception("Failed to parse line '%s'\n" % line)

    insn = " ".join(r.group(2).split())
    out.write("%s\n" % insn)
    out.write(". %d 0x12345678 8\n" % bb)
    out.write(". %s" % r.group(1))
    out.write(" 12 e0 0d e0\n") # append cxbe to actually end the basic block

def convert_file(filename):
    print "Converting file", filename
    basename = os.path.splitext(filename)[0]

    command = "gcc -m64 -Wall -c %s -o %s.o" % (filename, basename)
    if subprocess.call(command, shell=True) != 0:
        raise Exception("Failed to compile %s" % filename)

    command = "/usr/bin/dis -n -q %s.o" % basename
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)

    orig_file="%s.orig" % basename
    out = open(orig_file, "wt")
    out.write("A basic block is represented by three consecutive lines.\n")
    out.write("Every basic block ends with 'cxbe' instruction.\n\n")

    bb = 1
    for line in iter(proc.stdout.readline, ''):
        write_bb(out, line.rstrip(), bb)
        bb = bb + 1

    command = "rm %s.o" % basename
    subprocess.call(command, shell=True)

def main(argv):
    for arg in sys.argv[1:]:
        convert_file(arg)

main(sys.argv)

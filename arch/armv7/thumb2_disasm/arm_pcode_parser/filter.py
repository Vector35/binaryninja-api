#!/usr/bin/python

# the docs will use a strange angled single quote, and when copy pasted
# it shows up at by sequence \xe2\x80\x98 or \xe2\x80\x99 and a similar
# case for double quotes

# this remedies that problem on a given file


import os
import sys

print "filtering %s" % sys.argv[1]
fp = open(sys.argv[1],'rb')
buf = fp.read()
fp.close()

len0 = len(buf)
print "file size before: %d\n" % len0
buf = buf.replace("\xe2\x80\x98", "'")
buf = buf.replace("\xe2\x80\x99", "'")
buf = buf.replace("\xe2\x80\x9C", '"')
buf = buf.replace("\xe2\x80\x9D", '"')
len1 = len(buf)
print "file size after: %d\n" % len1
print "(%d stupid quotes replaced)" % ((len0-len1)/3)

fp = open(sys.argv[1],'wb')
fp.write(buf)
fp.close()


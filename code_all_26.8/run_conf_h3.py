#!/usr/bin/python

import sys
import os

command="rdisc6 h3-eth0 -r 1  1> /dev/null  2> /dev/null"
#print command
os.system(command)

command="/sbin/route -A inet6 add default gw 2003::1 1> /dev/null 2>/dev/null"
#print command
os.system(command)


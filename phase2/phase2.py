#!/usr/bin/python
#-------------------------------------------------------------------------------
# Name:        phase2
# Purpose:
#
# Author:      chuchiu
#
# Created:     16/04/2016
# Copyright:   (c) chuchiu 2016
# Licence:     <your licence>
#-------------------------------------------------------------------------------
import json
import sys

def main():
    if(len(sys.argv) != 2):
        print("Error: Please indicate your type of payload!\n");
        sys.exit();

    if(sys.argv[1] == 'oracle'):
        readPath = 'oracle_payload.txt';
    if(sys.argv[1] == 'postgresql'):
        readPath = 'postgresql_payload.txt';
    if(sys.argv[1] == 'mysql'):
        readPath = 'mysql_payload.txt';
    if(sys.argv[1] == 'sqlserver'):
        readPath = 'sqlserver_payload.txt';

    writePath = '../results/phase2.json';

    IN = open(readPath,'r');
    OUT = open(writePath,'w');

    OUT.write('[\n\"');
    n = 0;
    for line in IN:
        if(n != 0):
            OUT.write('",\n\"');
        line2 = line.rstrip()
        OUT.write(line2);
        n = n+1;
    OUT.write('"\n]');

    OUT.close();
    IN.close();

    #with open('.\phase2.json','w') as outfile:
    #    json.dump(data,outfile)

if __name__ == '__main__':
    main()


#!/usr/bin/python3
import pdb
import argparse, sys, timeit, time, os, subprocess;

total_dirs = 0;
total_levels = 0;

levels = 2;
number = 10;

def create(l):
    global total_levels;
    global total_dirs;

    if (l == levels):
        return;
    
    total_levels += 1;


    for i in range(number):
        wd = os.getcwd();
        s = "lvl" + str(l) + "num" + str(i);
        os.mkdir(s);
        total_dirs += 1;
        
        # go up by one level and create the directory
        os.chdir(s);
        create(l + 1);
        os.chdir(wd);

def delete(l, n):
    global total_levels;
    global total_dirs;

    if (l == levels):
        return;

    wd = os.getcwd();

    for i in range(number):
        s = "lvl" + str(l) + "num" + str(i);
        os.chdir(s)
        delete(l + 1, i)
        os.chdir(wd)

    # delete all the empty folders
    for i in range(number):
        s = "lvl" + str(l) + "num" + str(i);
        os.rmdir(s);

parser = argparse.ArgumentParser(description = 'Create directory structure');
parser.add_argument('depth', type=int, help='Number of levels');
parser.add_argument('count', type=int, help='Number of directories per level');
args = parser.parse_args();

levels = args.depth;
number = args.count;

if (levels > 5 or (levels > 3 and number > 12)):
    print("depth > 5 or (depth > 3 and count > 12)");
    sys.exit(-1);

testdir = "test."+str(os.getpid());
rootdir = os.getcwd();

print("Testdir = {}, Depth = {}, Per level = {}".format(testdir, levels, number));

os.mkdir(testdir);
os.chdir(rootdir + '/' + testdir);

# create
t1 = time.monotonic()
create(0)
t1 = time.monotonic() - t1

print('--------------------------')

# delete
t2 = time.monotonic()
#pdb.set_trace()
delete(0, 0)
t2 = time.monotonic() - t2

os.chdir(rootdir);
os.rmdir(testdir);

print("dirs={} \t create = {}s \t delete = {}s".format(total_dirs, t1, t2));

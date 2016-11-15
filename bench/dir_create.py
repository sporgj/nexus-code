#!/usr/bin/python3
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

def run():
    create(0);

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

t1 = timeit.timeit(run, number=1);

print("Total dirs = {}".format(total_dirs));
print("Total time = {}s".format(t1));

cmd = ['rm', '-rf', rootdir + '/' + testdir];
subprocess.call(cmd);

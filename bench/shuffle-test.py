'''
Script will create two directories: testdir/a and testdir/b.
The goal is for b/ to be metadata directory to a/: Files will be created in both
a/ and b/.

In addition, b/ will contain an additional file which will serve as the parent dirnode.
On every file added/deleted, data will be written to the file. The amount of data written
will be equal to that the parent dirnode will have saved

'''

import uuid, time, os, sys, timeit, subprocess, random, argparse;
from pathlib import Path;

parser = argparse.ArgumentParser(description='Microbenchmark replicating the\
                                behaviour of ucafs under the bonnie test')
parser.add_argument('file_count', type=int, help='number of files')
parser.add_argument("--shuffle", dest="randomize", action="store_true",
                    help="Randomize the create/delete")
parser.add_argument("-r", "--rounds", dest="rounds", default=1, type=int, help="Number of rounds")
parser.add_argument("--omit-dnode", dest="omit", action="store_false",
                    help="Whether to simulate the 'saving' of the parent dirnode")
args = parser.parse_args()

# parse the arguments
gbl_filecount = args.file_count
gbl_randomize = (args.randomize != None)
gbl_rounds = args.rounds
gbl_dnode = args.omit

# these were derived from the packet trace
start_size = 179
entry_size = 37

(dira, dirb) = ('a', 'b')

def create_files(testdir, files, dnode_file):
    '''
    Create the files a/ and b/

    @param files_a is the list of files for a
    @param files_b is the list of files by b
    @return a pair (time_a, time_b)
    '''
    create_time = 0
    time_a = 0
    time_b = 0
    time_dnode = 0

    # the dnode length will be the base
    dnode_len = start_size

    for i in range(len(files)):
        # 1 - Update the dnode file
        if not dnode_file == None:
            # create the string
            buf = 'a' * dnode_len
            t1 = time.monotonic()
            with open(dnode_file, 'w+') as fd:
               fd.write(buf)

            time_dnode += time.monotonic() - t1
            dnode_len += entry_size;

        # 2 - Create the metadata file
        t1 = time.monotonic()
        fd = open('/'.join([testdir, dirb, files[i]]), 'w+')
        fd.close()
        time_b += time.monotonic() - t1

        # 3 - Now create the "real" file
        t1 = time.monotonic()
        fd = open('/'.join([testdir, dira, files[i]]), 'w+')
        fd.close()
        time_a += time.monotonic() - t1

    return (time_a, time_b, time_dnode)

def remove_files(testdir, files, dnode_file):
    '''
    delete the files a/ and b/

    @return tuple (time_a, time_b, time_dnode)
    '''
    create_time = 0
    time_a = 0
    time_b = 0
    time_dnode = 0

    # dnode len will be the start + entry_size * (filecount - 1)
    dnode_len = start_size + entry_size * (gbl_filecount - 1)

    for i in range(len(files)):
        # 1 - Update the dnode file
        if dnode_file:
            # create the string
            buf = 'a' * dnode_len
            t1 = time.monotonic()
            with open(dnode_file, 'w') as fd:
               fd.write(buf)

            time_dnode += time.monotonic() - t1
            dnode_len -= entry_size;

        # 2 - Remove the metadata file
        t1 = time.monotonic()
        os.remove('/'.join([testdir, dirb, files[i]]))
        time_b += time.monotonic() - t1

        # 3 - Now create the "real" file
        t1 = time.monotonic()
        os.remove('/'.join([testdir, dira, files[i]]))
        time_a += time.monotonic() - t1;

    return (time_a, time_b, time_dnode)

def run():
    print ('create_a', 'create_b', 'create_dnode', 'del_a', 'del_b', 'del_dnode')
    # create the test directory and subdirs
    testdir = 'test.' + str(os.getpid())
    subdirs = [os.sep.join([testdir, sd]) for sd in [dira, dirb]]
    for d in subdirs:
        os.makedirs(d)

    # create the array of values
    filenames = ['file-'+str(i) for i in range(gbl_filecount)];

    dnode_fname = os.sep.join([testdir, dirb, 'dnode']) if gbl_dnode else None

    (ca, cb, cd) = create_files(testdir, filenames, dnode_fname)

    # randomize the entries and then remove them
    if gbl_randomize:
        random.shuffle(filenames)

    (ra, rb, rd) = remove_files(testdir, filenames, dnode_fname)

    print('{:.6f}s {:.6f}s {:.6f}s {:.6f}s {:.6f}s {:.6f}s'.format(ca, cb, cd, ra, rb, rd))
    subprocess.call(['rm', '-rf', testdir])

if __name__ == '__main__':
    run();

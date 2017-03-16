import os, argparse, sys, time, random;
from pathlib import Path;

parser = argparse.ArgumentParser(description="Create files in a flat directory in seq/rand order")
parser.add_argument("file_count", type=int, help="Number of files")
parser.add_argument("--shuffle", dest="randomize", action="store_true",
                    help="Randomize the create/delete")
parser.add_argument("-r", "--rounds", dest="rounds", default=1, type=int, help="Number of rounds")
args = parser.parse_args()

# parse the arguments
gbl_filecount = args.file_count
gbl_randomize = (args.randomize != None)
gbl_rounds = args.rounds

def create_files(filelist):
    create_time = 0

    for fpath in filelist:
        t1 = time.monotonic()
        Path(fpath).touch()
        create_time += time.monotonic() - t1

    return create_time

def remove_files(filelist):
    remove_time = 0

    for fpath in filelist:
        t1 = time.monotonic()
        os.remove(fpath)
        remove_time += time.monotonic() - t1

    return remove_time

def run():
    # Create the home directory
    testdir = 'test.' + str(os.getpid())
    os.mkdir(testdir)

    for i in range(gbl_rounds):
        # generate the list of all files
        gbl_filelist = [testdir+'/file-'+str(i) for i in range(gbl_filecount)]

        # create the files
        create = create_files(gbl_filelist)

        if gbl_randomize:
            random.shuffle(gbl_filelist)

        # remove the files
        remove = remove_files(gbl_filelist)

        del(gbl_filelist)

        print("count={} \t create={:.6f}s \t delete={:.6f}s"\
                .format(gbl_filecount, create, remove))

    os.rmdir(testdir)

if __name__ == '__main__':
    run()

#!/usr/bin/python3
import logging, os, subprocess

logging.basicConfig(level=logging.INFO)

logger = logging.getLogger(__name__)

tarc_cmd = 'tar -cf {:} {:}'

def units(un):
    c = un[-1]
    if c == 'k':
        m = 1024
    elif c == 'm':
        m = 1024 * 1024
    else:
        m = 1
    return int(un[:-1]) * m

SMALL_FILE_SIZE = units('10k')
MEDIUM_FILE_SIZE = units('10m')
LARGE_FILE_SIZE = units('100m')

SMALL_DIR_SIZE = 32
MEDIUM_DIR_SIZE = 256
LARGE_DIR_SIZE = 1024

WORKLOAD_DIR = 'ucafs-workloads'
FORMAT = '{:06d}'

large_file_small_dir = (LARGE_FILE_SIZE, SMALL_DIR_SIZE, 'large_file_small_dir',)
medium_file_medium_dir = (MEDIUM_FILE_SIZE, MEDIUM_DIR_SIZE, 'medium_file_medium_dir')
small_file_large_dir = (SMALL_FILE_SIZE, LARGE_DIR_SIZE, 'small_file_large_dir')

# generates the data sizes
datasets = [large_file_small_dir, medium_file_medium_dir, small_file_large_dir]

def create_dataset(dset):
    '''
    Creates the dataset containing all the files
    '''
    (file_size, dir_size, dir_name) = dset
    total_size = file_size * dir_size

    # the path to the containing folder
    path = '{:}/{:}'.format(WORKLOAD_DIR, dir_name)
    logger.info('Creating {}/'.format(path))
    os.makedirs(path)

    # now start creating the files
    logger.info('file_sizes={}, #files={} ---> TOTAL={}'.format(file_size, dir_size,
            total_size))

    for i in range(dir_size):
        fpath = '{:}/{:07d}'.format(path, i)
        with open(fpath, 'wb') as fout:
            fout.write(os.urandom(file_size))

    tarprog = tarc_cmd.format(dir_name, dir_name + '.tar.gz')
    subprocess.check_output(tarprog, shell=True)

    logger.info('Finished')



for dataset in datasets:
    create_dataset(dataset)

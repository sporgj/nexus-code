#!/usr/bin/python3.5
import subprocess, time
#workloads = ['media', 'src', 'www']
workloads = ['www']

tar_files = [wrk + '-workload.tar' for wrk in workloads]
gz_files = [wrk + '-workload.tar.gz' for wrk in workloads]

cp_cmd = 'cp {:} .'
gunzip_cmd = 'gunzip {:}'
grep1_cmd = 'grep -q -a \'javascript\' {:}'
tarx_cmd = 'tar -xf {:}'
du_cmd = 'du -cs {:}'
grep2_cmd = 'grep -q -R \'javascript\' {:}'
tarc_cmd = 'tar -czf {:} {:}'
rm_cmd = 'rm -rf {:} {:} {:}'

flush_cmd = 'sudo fs flushall && echo 3 | sudo tee /proc/sys/vm/drop_caches'

GREP = [2, 5]

def gen(workload):
    folder = workload
    gz_file = workload+'-workload.tar.gz'
    tar_file = workload+'-workload.tar'
    cv_file = workload+'-compress.tar.xz'
    
    # create cp
    cp = cp_cmd.format('/home/briand/ucafs/bench/ucafs-workloads/'+gz_file)

    # gunzip
    gunzip = gunzip_cmd.format(gz_file)

    # grepping the larger tar file
    grep1 = grep1_cmd.format(tar_file)

    # extract tar
    tar1 = tarx_cmd.format(tar_file)

    # du_cmd
    du = du_cmd.format(folder)

    # grepping recursively
    grep2 = grep2_cmd.format(folder)

    # creating the tar file
    tar2 = tarc_cmd.format(cv_file, folder)

    # the removal
    rm = rm_cmd.format(cv_file, tar_file, folder)

    return (cp, gunzip, grep1, tar1, du, grep2, tar2, rm,)

def run_test(workload):
    commands = gen(workload)
    fmt = ', '.join(['{:.3f}' for c in commands])
    vals = []
    i = 0

    # run each command
    for cmd in commands:
        # clear the cache
        subprocess.check_output(flush_cmd, shell=True)
        cmd_array = cmd.split(' ')

        t1 = time.monotonic()
        rv = subprocess.run(cmd_array)
        if rv.returncode != 0 and not (i in GREP):
            print('FAIL: ' + (' '.join(cmd_array)))
            return;
        t1 = time.monotonic() - t1
        i += 1

        vals.append(t1)

    print(fmt.format(*vals))

v = 'cp, gunzip, grep1, tar1, du, grep2, tar2, rm_cmd'
print(v)
for load in workloads:
    print('#', load)
    for i in range(5):
        run_test(load)

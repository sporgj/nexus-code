#!/usr/bin/python3.5
import subprocess, time, os
#workloads = ['large_file_small_dir', 'medium_file_medium_dir', 'small_file_large_dir']
workloads = ['medium_file_medium_dir', 'small_file_large_dir']
#workloads = ['small_file_large_dir']

tar_files = [wrk + '-workload.tar' for wrk in workloads]
gz_files = [wrk + '-workload.tar.gz' for wrk in workloads]

tarx_cmd = 'tar -xf {:}'
du_cmd = 'du -cs {:}'
grep2_cmd = 'grep -q -R \'javascript\' {:}'
tarc_cmd = 'tar -cf {:} {:}'
cp_cmd = 'cp -r {0}/{1} {0}/{1}-txt'
mv_cmd = 'mv {0}/{1} {0}/{1}-txt'
rm_cmd = 'rm -rf {:} {:}'

flush_cmd = 'sudo fs flushall && echo 3 | sudo tee /proc/sys/vm/drop_caches'

GREP = [2]

# create the file to run the test
timestr = time.strftime("%Y%m%d-%H%M%S")
fd = open('/home/briand/results/microbm-'+timestr+'.txt', 'w')

def gen(workload):
    folder = workload
    gz_file = workload+'.tar.gz'
    cv_file = workload+'-compress.tar.gz'
    gz_path = '/home/briand/ucafs/bench/ucafs-workloads/'+gz_file 

    # extract tar
    tar1 = tarx_cmd.format(gz_path)

    # du_cmd
    du = du_cmd.format(folder)

    # grepping recursively
    grep2 = grep2_cmd.format(folder)

    # creating the tar file
    tar2 = tarc_cmd.format(cv_file, folder)

    # copy one item
    cp = cp_cmd.format(folder, '0000001')

    mv = mv_cmd.format(folder, '0000002')

    # the removal
    rm = rm_cmd.format(cv_file, folder)

    return (tar1, du, grep2, tar2, cp, mv, rm,)

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
    
    data = fmt.format(*vals)
    fd.writelines([data, '\n'])
    fd.flush()

    print(data)

v = 'tar_x, du, grep, tar_c, cp, mv, rm'
print(v)
fd.writelines([os.getcwd(), '\n', v, '\n'])
fd.flush()

for load in workloads:
    print('#', load)
    fd.writelines(['#', load, '\n'])
    fd.flush()

    for i in range(25):
        run_test(load)

fd.close()

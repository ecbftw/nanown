
import multiprocessing

def setCPUAffinity():
    from ctypes import cdll,c_int,byref
    cpus = multiprocessing.cpu_count()
    
    libc = cdll.LoadLibrary("libc.so.6")
    #libc.sched_setaffinity(os.getpid(), 1, ctypes.byref(ctypes.c_int(0x01)))
    return libc.sched_setaffinity(0, 4, byref(c_int(0x00000001<<(cpus-1))))


def setTCPTimestamps(enabled=True):
    fh = open('/proc/sys/net/ipv4/tcp_timestamps', 'r+b')
    ret_val = False
    if fh.read(1) == b'1':
        ret_val = True

    fh.seek(0)
    if enabled:
        fh.write(b'1')
    else:
        fh.write(b'0')
    fh.close()
    
    return ret_val


previous_governors = None
def setPowersave(enabled):
    global previous_governors
    cpus = multiprocessing.cpu_count()
    if enabled:
        if previous_governors == None:
            previous_governors = [b"powersave"]*cpus
        new_governors = previous_governors
    else:
        new_governors = [b"performance"]*cpus

    previous_governors = []
    for c in range(cpus):
        fh = open('/sys/devices/system/cpu/cpu%d/cpufreq/scaling_governor' % c, 'r+b')
        previous_governors.append(fh.read())
        fh.seek(0)
        fh.write(new_governors[c])
        fh.close()
        

def setLowLatency(enabled):
    fh = open('/proc/sys/net/ipv4/tcp_low_latency', 'r+b')
    ret_val = False
    if fh.read(1) == b'1':
        ret_val = True

    fh.seek(0)
    if enabled:
        fh.write(b'1')
    else:
        fh.write(b'0')
    fh.close()
    
    return ret_val


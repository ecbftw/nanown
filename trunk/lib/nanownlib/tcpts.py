
import sys
import socket
import queue
import statistics
import threading
import json
from .stats import OLSRegression


def trickleHTTPRequest(ip,port,hostname):
    my_port = None
    try:
        sock = socket.create_connection((ip, port))
        my_port = sock.getsockname()[1]
        
        #print('.')
        sock.sendall(b'GET / HTTP/1.1\r\n')
        time.sleep(0.5)
        rest = b'''Host: '''+hostname.encode('utf-8')+b'''\r\nUser-Agent: Secret Agent Man\r\nX-Extra: extra read all about it!\r\nConnection: close\r\n'''
        for r in rest:
            sock.sendall(bytearray([r]))
            time.sleep(0.05)

        time.sleep(0.5)
        sock.sendall('\r\n')

        r = None
        while r != b'':
            r = sock.recv(16)

        sock.close()
    except Exception as e:
        pass

    return my_port


def runTimestampProbes(host_ip, port, hostname, num_trials, concurrency=4):
    #XXX: can we use WorkerThreads for this parallel stuff?
    myq = queue.Queue()
    def threadWrapper(*args):
        try:
            myq.put(trickleHTTPRequest(*args))
        except Exception as e:
            sys.stderr.write("ERROR from trickleHTTPRequest: %s\n" % repr(e))
            myq.put(None)

    threads = []
    ports = []
    for i in range(num_trials):
        if len(threads) >= concurrency:
            ports.append(myq.get())
        t = threading.Thread(target=threadWrapper, args=(host_ip, port, hostname))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    while myq.qsize() > 0:
        ports.append(myq.get())

    return ports


def computeTimestampPrecision(sniffer_fp, ports):
    rcvd = []
    for line in sniffer_fp:
        p = json.loads(line)
        if p['sent']==0:
            rcvd.append((p['observed'],p['tsval'],int(p['local_port'])))

    slopes = []
    for port in ports:
        trcvd = [tr for tr in rcvd if tr[2]==port and tr[1]!=0]

        if len(trcvd) < 2:
            sys.stderr.write("WARN: Inadequate data points.\n")
            continue
        
        if trcvd[0][1] > trcvd[-1][1]:
            sys.stderr.write("WARN: TSval wrap.\n")
            continue

        x = [tr[1] for tr in trcvd]
        y = [tr[0] for tr in trcvd]

        slope,intercept = OLSRegression(x, y)
        slopes.append(slope)

    if len(slopes) == 0:
        return None,None,None

    m = statistics.mean(slopes)
    if len(slopes) == 1:
        return (m, None, slopes)
    else:
        return (m, statistics.stdev(slopes), slopes)

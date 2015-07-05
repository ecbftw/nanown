#!/usr/bin/env python3
#-*- mode: Python;-*-

import sys
import time
import random
import argparse
import socket
import datetime
import http.client
import threading
import queue
import subprocess
import multiprocessing
import csv
import json
import gzip
import statistics
import numpy
import netifaces
try:
    import requests
except:
    sys.stderr.write('ERROR: Could not import requests module.  Ensure it is installed.\n')
    sys.stderr.write('       Under Debian, the package name is "python3-requests"\n.')
    sys.exit(1)

from .stats import *


def getLocalIP(remote_host, remote_port):
    connection = socket.create_connection((remote_host, remote_port))
    ret_val = connection.getsockname()[0]
    connection.close()

    return ret_val


def getIfaceForIP(ip):
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, None)
        if addrs:
            for a in addrs:
                if a.get('addr', None) == ip:
                    return iface


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

    
def OLSRegression(x,y):
    #print(x,y)
    x = numpy.array(x)
    y = numpy.array(y)
    #A = numpy.vstack([x, numpy.ones(len(x))]).T
    #m, c = numpy.linalg.lstsq(A, y)[0] # broken
    #c,m = numpy.polynomial.polynomial.polyfit(x, y, 1) # less accurate
    c,m = numpy.polynomial.Polynomial.fit(x,y,1).convert().coef

    #print(m,c)

    #import matplotlib.pyplot as plt
    #plt.clf()
    #plt.scatter(x, y)
    #plt.plot(x, m*x + c, 'r', label='Fitted line')
    #plt.show()
    
    return (m,c)


def startSniffer(target_ip, target_port, output_file):
    my_ip = getLocalIP(target_ip, target_port)
    my_iface = getIfaceForIP(my_ip)
    return subprocess.Popen(['chrt', '-r', '99', './bin/csamp', my_iface, my_ip,
                             target_ip, "%d" % target_port, output_file, '0'])

def stopSniffer(sniffer):
    sniffer.terminate()
    sniffer.wait(2)
    if sniffer.poll() == None:
        sniffer.kill()
        sniffer.wait(1)

        
def setCPUAffinity():
    import ctypes
    from ctypes import cdll,c_int,byref
    cpus = multiprocessing.cpu_count()
    
    libc = cdll.LoadLibrary("libc.so.6")
    #libc.sched_setaffinity(os.getpid(), 1, ctypes.byref(ctypes.c_int(0x01)))
    return libc.sched_setaffinity(0, 4, byref(c_int(0x00000001<<(cpus-1))))


# Monkey patching that instruments the HTTPResponse to collect connection source port info
class MonitoredHTTPResponse(http.client.HTTPResponse):
    local_address = None

    def __init__(self, sock, *args, **kwargs):
        self.local_address = sock.getsockname()
        super(MonitoredHTTPResponse, self).__init__(sock,*args,**kwargs)
            
requests.packages.urllib3.connection.HTTPConnection.response_class = MonitoredHTTPResponse


def removeDuplicatePackets(packets):
    #return packets
    suspect = None
    seen = {}
    # XXX: Need to review this deduplication algorithm and make sure it is correct
    for p in packets:
        key = (p['sent'],p['tcpseq'],p['tcpack'],p['payload_len'])
        #if (key not in seen)\
        #   or p['sent']==1 and (seen[key]['observed'] < p['observed'])\
        #   or p['sent']==0 and (seen[key]['observed'] > p['observed']):
        if (key not in seen) or (seen[key]['observed'] > p['observed']):
            seen[key] = p
    
    if len(seen) < len(packets):
        suspect = 'd'
        #sys.stderr.write("INFO: removed %d duplicate packets.\n" % (len(packets) - len(seen)))

    return suspect,seen.values()


def analyzePackets(packets, timestamp_precision, trim_sent=0, trim_rcvd=0):
    suspect,packets = removeDuplicatePackets(packets)

    #sort_key = lambda d: (d['tcpseq'],d['tcpack'])
    sort_key = lambda d: (d['observed'],d['tcpseq'])
    sent = sorted((p for p in packets if p['sent']==1 and p['payload_len']>0), key=sort_key)
    rcvd = sorted((p for p in packets if p['sent']==0 and p['payload_len']>0), key=sort_key)

    if len(sent) <= trim_sent:
        last_sent = sent[-1]
    else:
        last_sent = sent[trim_sent]

    if len(rcvd) <= trim_rcvd:
        last_rcvd = rcvd[0]
    else:
        last_rcvd = rcvd[len(rcvd)-1-trim_rcvd]
    
    packet_rtt = last_rcvd['observed'] - last_sent['observed']
    if packet_rtt < 0:
        sys.stderr.write("WARN: Negative packet_rtt. last_rcvd=%s,last_sent=%s\n" % (last_rcvd, last_sent))

    last_sent_ack = None
    try:
        last_sent_ack = min(((p['observed'],p) for p in packets
                             if p['sent']==0 and p['payload_len']+last_sent['tcpseq']==p['tcpack']))[1]
    except Exception as e:
        sys.stderr.write("WARN: Could not find last_sent_ack.\n")

    tsval_rtt = None
    if None not in (timestamp_precision, last_sent_ack):
        tsval_rtt = int(round((last_rcvd['tsval'] - last_sent_ack['tsval'])*timestamp_precision))

    return {'packet_rtt':packet_rtt,
            'tsval_rtt':tsval_rtt,
            'suspect':suspect,
            'sent_trimmed':trim_sent,
            'rcvd_trimmed':trim_rcvd},len(sent),len(rcvd)


# trimean and mad for each dist of differences
def evaluateTrim(db, unusual_case, strim, rtrim):
    cursor = db.conn.cursor()
    query="""
      SELECT packet_rtt-(SELECT avg(packet_rtt) FROM probes,trim_analysis 
                         WHERE sent_trimmed=:strim AND rcvd_trimmed=:rtrim AND trim_analysis.probe_id=probes.id AND probes.test_case!=:unusual_case AND sample=u.sample AND probes.type in ('train','test'))
      FROM (SELECT probes.sample,packet_rtt FROM probes,trim_analysis WHERE sent_trimmed=:strim AND rcvd_trimmed=:rtrim AND trim_analysis.probe_id=probes.id AND probes.test_case=:unusual_case AND probes.type in ('train','test')) u
    """

    params = {"strim":strim,"rtrim":rtrim,"unusual_case":unusual_case}
    cursor.execute(query, params)
    differences = [row[0] for row in cursor]
    
    return trimean(differences),mad(differences)



def analyzeProbes(db):
    db.conn.execute("CREATE INDEX IF NOT EXISTS packets_probe ON packets (probe_id)")
    pcursor = db.conn.cursor()
    kcursor = db.conn.cursor()

    pcursor.execute("SELECT tcpts_mean FROM meta")
    try:
        timestamp_precision = pcursor.fetchone()[0]
    except:
        timestamp_precision = None
    
    pcursor.execute("DELETE FROM trim_analysis")
    db.conn.commit()
    
    count = 0
    sent_tally = []
    rcvd_tally = []
    for pid, in pcursor.execute("SELECT id FROM probes"):
        kcursor.execute("SELECT * FROM packets WHERE probe_id=?", (pid,))
        try:
            analysis,s,r = analyzePackets(kcursor.fetchall(), timestamp_precision)
            analysis['probe_id'] = pid
            sent_tally.append(s)
            rcvd_tally.append(r)
        except Exception as e:
            print(e)
            sys.stderr.write("WARN: couldn't find enough packets for probe_id=%s\n" % pid)
        
        #print(pid,analysis)
        db.addTrimAnalyses([analysis])
        count += 1
    db.conn.commit()
    num_sent = statistics.mode(sent_tally)
    num_rcvd = statistics.mode(rcvd_tally)
    sent_tally = None
    rcvd_tally = None
    print("num_sent: %d, num_rcvd: %d" % (num_sent,num_rcvd))
    
    for strim in range(0,num_sent):
        for rtrim in range(0,num_rcvd):
            if strim == 0 and rtrim == 0:
                continue # no point in doing 0,0 again
            for pid, in pcursor.execute("SELECT id FROM probes"):
                kcursor.execute("SELECT * FROM packets WHERE probe_id=?", (pid,))
                try:
                    analysis,s,r = analyzePackets(kcursor.fetchall(), timestamp_precision, strim, rtrim)
                    analysis['probe_id'] = pid
                except Exception as e:
                    print(e)
                    sys.stderr.write("WARN: couldn't find enough packets for probe_id=%s\n" % pid)
                    
                db.addTrimAnalyses([analysis])
            db.conn.commit()

    # Populate analysis table so findUnusualTestCase can give us a starting point
    pcursor.execute("DELETE FROM analysis")
    db.conn.commit()
    pcursor.execute("INSERT INTO analysis SELECT id,probe_id,suspect,packet_rtt,tsval_rtt FROM trim_analysis WHERE sent_trimmed=0 AND rcvd_trimmed=0")
    
    unusual_case,delta = findUnusualTestCase(db)
    evaluations = {}
    for strim in range(0,num_sent):
        for rtrim in range(0,num_rcvd):
            evaluations[(strim,rtrim)] = evaluateTrim(db, unusual_case, strim, rtrim)

    import pprint
    pprint.pprint(evaluations)

    delta_margin = 0.1
    best_strim = 0
    best_rtrim = 0
    good_delta,good_mad = evaluations[(0,0)]
    
    for strim in range(1,num_sent):
        delta,mad = evaluations[(strim,0)]
        if abs(good_delta - delta) < abs(delta_margin*good_delta) and mad < good_mad:
            best_strim = strim
        else:
            break

    good_delta,good_mad = evaluations[(best_strim,0)]
    for rtrim in range(1,num_rcvd):
        delta,mad = evaluations[(best_strim,rtrim)]
        if (abs(delta) > abs(good_delta) or abs(good_delta - delta) < abs(delta_margin*good_delta)) and mad < good_mad:
            best_rtrim = rtrim
        else:
            break

    print("selected trim parameters:",(best_strim,best_rtrim))
    
    if best_strim != 0 or best_rtrim !=0:
        pcursor.execute("DELETE FROM analysis")
        db.conn.commit()
        pcursor.execute("INSERT INTO analysis SELECT id,probe_id,suspect,packet_rtt,tsval_rtt FROM trim_analysis WHERE sent_trimmed=? AND rcvd_trimmed=?",
                        (best_strim,best_rtrim))
    
    return count


        
def parseJSONLines(fp):
    for line in fp:
        yield json.loads(line)


def associatePackets(sniffer_fp, db):
    sniffer_fp.seek(0)

    # now combine sampler data with packet data
    buffered = []

    cursor = db.conn.cursor()
    cursor.execute("SELECT count(*) count,min(time_of_day) start,max(time_of_day+userspace_rtt) end from probes")
    ptimes = cursor.fetchone()
    window_size = 100*int((ptimes['end']-ptimes['start'])/ptimes['count'])
    print("associate window_size:", window_size)

    db.addPackets(parseJSONLines(sniffer_fp), window_size)

    cursor.execute("SELECT count(*) count FROM packets WHERE probe_id is NULL")
    unmatched = cursor.fetchone()['count']
    if unmatched > 0:
        sys.stderr.write("WARNING: %d observed packets didn't find a home...\n" % unmatched)
 
    return None


def enumStoredTestCases(db):
    cursor = db.conn.cursor()
    cursor.execute("SELECT test_case FROM probes GROUP BY test_case")
    return [tc[0] for tc in cursor]


def findUnusualTestCase(db):
    test_cases = enumStoredTestCases(db)

    cursor = db.conn.cursor()
    cursor.execute("SELECT packet_rtt FROM probes,analysis WHERE probes.id=analysis.probe_id AND probes.type in ('train','test')")
    global_tm = trimean([row['packet_rtt'] for row in cursor])

    tm_abs = []
    tm_map = {}
    # XXX: if more speed needed, percentile extension to sqlite might be handy...
    for tc in test_cases:
        cursor.execute("SELECT packet_rtt FROM probes,analysis WHERE probes.id=analysis.probe_id AND probes.type in ('train','test') AND probes.test_case=?", (tc,))
        tm_map[tc] = trimean([row['packet_rtt'] for row in cursor])
        tm_abs.append((abs(tm_map[tc]-global_tm), tc))

    magnitude,tc = max(tm_abs)
    cursor.execute("SELECT packet_rtt FROM probes,analysis WHERE probes.id=analysis.probe_id AND probes.type in ('train','test') AND probes.test_case<>?", (tc,))
    remaining_tm = trimean([row['packet_rtt'] for row in cursor])

    return (tc, tm_map[tc]-remaining_tm)


def reportProgress(db, sample_types, start_time):
    cursor = db.conn.cursor()
    output = ''
    total_completed = 0
    total_requested = 0
    for st in sample_types:
        cursor.execute("SELECT count(id) c FROM (SELECT id FROM probes WHERE type=? AND time_of_day>? GROUP BY sample)", (st[0],int(start_time*1000000000)))
        count = cursor.fetchone()[0]
        output += " | %s remaining: %d" % (st[0], st[1]-count)
        total_completed += count
        total_requested += st[1]

    rate = total_completed / (time.time() - start_time)
    total_time = total_requested / rate        
    eta = datetime.datetime.fromtimestamp(start_time+total_time)
    print("STATUS:",output[3:],"| est. total_time: %s | est. ETA: %s" % (str(datetime.timedelta(seconds=total_time)), str(eta)))

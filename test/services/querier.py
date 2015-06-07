#!/usr/bin/env python3
#
# Copyright (C) 2015 Blindspot Security LLC
# by Timothy D. Morgan
# twits: @ecbftw

import sys
import time
import hashlib
import socketserver
import http.server
import sqlite3

mem = sqlite3.connect(':memory:')
disk = sqlite3.connect('/var/tmp/x.db')
memc = mem.cursor()
diskc = disk.cursor()

q='''CREATE TABLE user
     (username text, pwdhash text, other text, data real, stuff real)'''
memc.execute(q)
diskc.execute(q)
q="INSERT INTO user VALUES ('jack','010203040506070809000A0B0C0D0E0F','hello',42,3.1415926535)"
memc.execute(q)
diskc.execute(q)
mem.commit()
disk.commit()



class HashHandler(http.server.BaseHTTPRequestHandler):
    """
    """

    def do_GET(self):
        resolution = time.clock_getres(time.CLOCK_MONOTONIC)

        conn = None
        if 't=' in self.path:
            t = self.path.split('t=', 1)[1]
            if t == '1':
                conn = memc
            elif t == '2':
                conn = diskc

        received = int(time.monotonic()/resolution)
        if conn != None:
            x = conn.execute("SELECT * FROM user WHERE username='jack'")
        now = int(time.monotonic()/resolution)
        
        self.send_response(200)
        self.send_header('Content-Type','text/plain; charset=UTF-8')
        self.end_headers()

        content = "waited: %d\n" % (now - received)
        self.wfile.write(content.encode('utf-8'))
        self.wfile.flush()


if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 3240
    server = socketserver.TCPServer((HOST, PORT), HashHandler)
    server.serve_forever()

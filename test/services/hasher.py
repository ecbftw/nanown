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


class HashHandler(http.server.BaseHTTPRequestHandler):
    """
    """

    def do_GET(self):
        resolution = time.clock_getres(time.CLOCK_MONOTONIC)

        do_hash = False
        if 't=' in self.path and self.path.split('t=', 1)[1] == '1':
            do_hash = True

        received = int(time.monotonic()/resolution)
        if do_hash:
            x = hashlib.md5(b'01234567').digest()
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

#-*- mode: Python;-*-

import sys
import os
import uuid
import threading
import sqlite3

def _newid():
    return uuid.uuid4().hex


class db(threading.local):
    conn = None
    cursor = None
    def __init__(self, path):
        exists = os.path.exists(path)
        self.conn = sqlite3.connect(path)
        self.conn.execute("PRAGMA foreign_keys = ON;")
        self.conn.row_factory = sqlite3.Row
        
        if not exists:
            self.conn.execute(
                """CREATE TABLE meta (id BLOB PRIMARY KEY,
                                      tcpts_mean REAL,
                                      tcpts_stddev REAL,
                                      tcpts_slopes TEXT)
                """)

            self.conn.execute(
                """CREATE TABLE probes (id BLOB PRIMARY KEY,
                                        sample INTEGER,
                                        test_case TEXT,
                                        type TEXT,
                                        tc_order INTEGER,
                                        time_of_day INTEGER,
                                        local_port INTEGER,
                                        reported INTEGER,
                                        userspace_rtt INTEGER,
                                        UNIQUE (sample, test_case))
                """)

            self.conn.execute(
                """CREATE TABLE packets (id BLOB PRIMARY KEY,
                                         probe_id REFERENCES probes(id) ON DELETE CASCADE,
                                         sent INTEGER,
                                         observed INTEGER,
                                         tsval INTEGER,
                                         payload_len INTEGER,
                                         tcpseq INTEGER,
                                         tcpack INTEGER)
                """)

            self.conn.execute(
                """CREATE TABLE analysis (id BLOB PRIMARY KEY,
                                          probe_id UNIQUE REFERENCES probes(id) ON DELETE CASCADE,
                                          suspect TEXT,
                                          packet_rtt INTEGER,
                                          tsval_rtt INTEGER)
                """)

            self.conn.execute(
                """CREATE TABLE trim_analysis (id BLOB PRIMARY KEY,
                                               probe_id REFERENCES probes(id) ON DELETE CASCADE,
                                               suspect TEXT,
                                               packet_rtt INTEGER,
                                               tsval_rtt INTEGER,
                                               sent_trimmed INTEGER,
                                               rcvd_trimmed INTEGER)
                """)

            self.conn.execute(
                """CREATE TABLE classifier_results (id BLOB PRIMARY KEY,
                                                    algorithm TEXT,
                                                    params TEXT,
                                                    sample_size INTEGER,
                                                    num_trials INTEGER,
                                                    trial_type TEXT,
                                                    false_positives REAL,
                                                    false_negatives REAL)
                """)

    def __del__(self):
        if self.conn:
            self.conn.commit()
            self.conn.close()

    def _insert(self, table, row):
        rid = _newid()
        keys = row.keys()
        columns = ','.join(keys)
        placeholders = ':'+', :'.join(keys)
        query = "INSERT INTO %s (id,%s) VALUES ('%s',%s)" % (table, columns, rid, placeholders)
        #print(row)
        self.conn.execute(query, row)
        return rid

    def addMeta(self, meta):
        ret_val = self._insert('meta', meta)
        self.conn.commit()
        return ret_val
    
    def addProbes(self, p):
        return [self._insert('probes', row) for row in p]

    def addPackets(self, pkts, window_size):
        query = ("INSERT INTO packets (id,probe_id,sent,observed,tsval,payload_len,tcpseq,tcpack)"
                 " VALUES(randomblob(16),"
                 "(SELECT id FROM probes WHERE local_port=:local_port AND :observed>time_of_day"
                 " AND :observed<time_of_day+userspace_rtt+%d" 
                 " ORDER BY time_of_day ASC LIMIT 1),"
                 ":sent,:observed,:tsval,:payload_len,:tcpseq,:tcpack)") % window_size
        self.conn.execute("PRAGMA foreign_keys = OFF;")
        self.conn.execute("CREATE INDEX IF NOT EXISTS probes_port ON probes (local_port)")
        cursor = self.conn.cursor()
        #print(query, list(pkts)[0:3])
        cursor.executemany(query, pkts)
        self.conn.commit()
        self.conn.execute("PRAGMA foreign_keys = ON;")

    def addAnalyses(self, analyses):
        return [self._insert('analysis', row) for row in analyses]

    def addTrimAnalyses(self, analyses):
        return [self._insert('trim_analysis', row) for row in analyses]

    def addClassifierResults(self, results):
        ret_val = self._insert('classifier_results', results)
        self.conn.commit()
        return ret_val

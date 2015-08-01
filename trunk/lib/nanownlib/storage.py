#-*- mode: Python;-*-

import sys
import os
import uuid
import random
import threading
import sqlite3
try:
    import numpy
except:
    sys.stderr.write('ERROR: Could not import numpy module.  Ensure it is installed.\n')
    sys.stderr.write('       Under Debian, the package name is "python3-numpy"\n.')
    sys.exit(1)

# Don't trust numpy's seeding
numpy.random.seed(random.SystemRandom().randint(0,2**32-1))

def _newid():
    return uuid.uuid4().hex


class db(threading.local):
    conn = None
    cursor = None
    _population_sizes = None
    _population_cache = None
    _offset_cache = None
    _cur_offsets = None
    
    def __init__(self, path):
        exists = os.path.exists(path)
        self.conn = sqlite3.connect(path)
        self.conn.execute("PRAGMA foreign_keys = ON;")
        self.conn.row_factory = sqlite3.Row
        self._population_sizes = {}
        self._population_cache = {}
        self._offset_cache = {}
        self._cur_offsets = {}
        
        if not exists:
            self.conn.execute(
                """CREATE TABLE meta (id BLOB PRIMARY KEY,
                                      tcpts_mean REAL,
                                      tcpts_stddev REAL,
                                      tcpts_slopes TEXT,
                                      unusual_case TEXT,
                                      greater INTEGER)
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
                                                    classifier TEXT,
                                                    trial_type TEXT,
                                                    num_observations INTEGER,
                                                    num_trials INTEGER,
                                                    params TEXT,
                                                    false_positives REAL,
                                                    false_negatives REAL)
                """)

    def __del__(self):
        if self.conn:
            self.conn.commit()
            self.conn.close()

    
    def populationSize(self, probe_type):
        if probe_type in self._population_sizes:
            return self._population_sizes[probe_type]

        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT max(c) FROM (SELECT count(sample) c FROM probes WHERE type=? GROUP BY test_case)", (probe_type,))
            self._population_sizes[probe_type] = cursor.fetchone()[0]
            return self._population_sizes[probe_type]
        except Exception as e:
            print(e)
            return 0


    def subseries(self, probe_type, unusual_case, size=None, offset=None):
        cache_key = (probe_type,unusual_case)
        if cache_key not in self._population_cache:
            query="""
            SELECT packet_rtt AS unusual_packet,
                   (SELECT avg(packet_rtt) FROM probes,analysis
                    WHERE analysis.probe_id=probes.id AND probes.test_case!=:unusual_case AND probes.type=:probe_type AND sample=u.sample) AS other_packet,

                   tsval_rtt AS unusual_tsval,
                   (SELECT avg(tsval_rtt) FROM probes,analysis
                    WHERE analysis.probe_id=probes.id AND probes.test_case!=:unusual_case AND probes.type=:probe_type AND sample=u.sample) AS other_tsval,

                   reported AS unusual_reported,
                   (SELECT avg(reported) FROM probes,analysis
                    WHERE analysis.probe_id=probes.id AND probes.test_case!=:unusual_case AND probes.type=:probe_type AND sample=u.sample) AS other_reported

            FROM   (SELECT probes.sample,packet_rtt,tsval_rtt,reported FROM probes,analysis 
                    WHERE analysis.probe_id=probes.id AND probes.test_case =:unusual_case AND probes.type=:probe_type) u
            """
    
            params = {"probe_type":probe_type, "unusual_case":unusual_case}
            cursor = self.conn.cursor()
            cursor.execute(query, params)
            p = [dict(row) for row in cursor.fetchall()]
            self._population_cache[cache_key] = p
            self._offset_cache[cache_key] = tuple(numpy.random.random_integers(0,len(p)-1, len(p)/5))
            self._cur_offsets[cache_key] = 0

        population = self._population_cache[cache_key]

        if size == None or size > len(population):
            size = len(population)
        if offset == None or offset >= len(population) or offset < 0:
            offset = self._offset_cache[cache_key][self._cur_offsets[cache_key]]
            self._cur_offsets[cache_key] = (offset + 1) % len(self._offset_cache[cache_key])
        
        try:
            offset = int(offset)
            size = int(size)
        except Exception as e:
            print(e, offset, size)
            return None
        
        ret_val = population[offset:offset+size]
        if len(ret_val) < size:
            ret_val += population[0:size-len(ret_val)]
        
        return ret_val
    
    
    def resetOffsets(self):
        for k in self._cur_offsets.keys():
            self._cur_offsets[k] = 0

            
    def clearCache(self):
        self._population_cache = {}
        self._offset_cache = {}
        self._cur_offsets = {}

        
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
                 " VALUES(hex(randomblob(16)),"
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

    def addClassifierResult(self, results):
        ret_val = self._insert('classifier_results', results)
        self.conn.commit()
        return ret_val

    def fetchClassifierResult(self, classifier, trial_type, num_observations, params=None):
        query = """
          SELECT * FROM classifier_results
            WHERE classifier=:classifier 
                  AND trial_type=:trial_type 
                  AND num_observations=:num_observations"""
        if params != None:
            query += """
                  AND params=:params"""
        query += """
            ORDER BY false_positives+false_negatives
            LIMIT 1
        """

        qparams = {'classifier':classifier, 'trial_type':trial_type,
                   'num_observations':num_observations,'params':params}
        cursor = self.conn.cursor()
        cursor.execute(query, qparams)
        ret_val = cursor.fetchone()
        if ret_val != None:
            ret_val = dict(ret_val)
        return ret_val
    
    def deleteClassifierResults(self, classifier, trial_type, num_observations=None):
        params = {"classifier":classifier,"trial_type":trial_type,"num_observations":num_observations}
        query = """
          DELETE FROM classifier_results
          WHERE classifier=:classifier AND trial_type=:trial_type
        """
        if num_observations != None:
            query += " AND num_observations=:num_observations"
        
        self.conn.execute(query, params)
        self.conn.commit()
    
    def setUnusualCase(self, unusual_case, greater):
        query = """SELECT * FROM meta LIMIT 1"""
        cursor = self.conn.cursor()
        cursor.execute(query)
        row = cursor.fetchone()
        if row == None:
            params = {"id":_newid()}
        else:
            params = dict(row)

        params["unusual_case"]=unusual_case
        params["greater"]=greater
        
        keys = params.keys()
        columns = ','.join(keys)
        placeholders = ':'+', :'.join(keys)
        
        query = """INSERT OR REPLACE INTO meta (%s) VALUES (%s)""" % (columns, placeholders)
        cursor.execute(query, params)
        
        
    def getUnusualCase(self):
        query = """SELECT unusual_case,greater FROM meta LIMIT 1"""
        cursor = self.conn.cursor()
        cursor.execute(query)
        row = cursor.fetchone()
        if row == None or row[0] == None or row[1] == None:
            return None
        else:
            return tuple(row)

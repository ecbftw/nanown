#

import threading
import queue


class WorkerThreads(object):
    workq = None
    resultq = None
    target = None
    
    def __init__(self, num_workers, target):
        self.workq = queue.Queue()
        self.resultq = queue.Queue()
        self.target = target
        
        self.workers = []
        for i in range(num_workers):
            t = threading.Thread(target=self._worker)
            t.daemon = True
            t.start()
            self.workers.append(t)

    def _worker(self):
        while True:
            item = self.workq.get()
            if item == None:
                self.workq.task_done()
                break

            job_id,args = item
            try:
                self.resultq.put((job_id, self.target(*args)))
            except Exception as e:
                sys.stderr.write("ERROR: Job '%s' failed with '%s'.  Dropping...\n",
                                 (str(job_id),str(e)))
            self.workq.task_done()

    def addJob(self, job_id, args):
        self.workq.put((job_id, args))
            
    def wait(self):
        self.workq.join()

    def __del__(self):
        self.stop()
    
    def stop(self):
        for i in range(0,len(self.workers)):
            self.workq.put(None)
        for w in self.workers:
            w.join()

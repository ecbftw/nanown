
import time
import statistics
import functools
import pprint
import json

from .stats import *
from .parallel import WorkerThreads

def trainBoxTest(db, unusual_case, greater, num_observations):
    db.resetOffsets()
    
    def trainAux(low,high,num_trials):
        estimator = functools.partial(multiBoxTest, {'low':low, 'high':high}, greater)
        estimates = bootstrap3(estimator, db, 'train', unusual_case, num_observations, num_trials)
        null_estimates = bootstrap3(estimator, db, 'train_null', unusual_case, num_observations, num_trials)

        bad_estimates = len([e for e in estimates if e != 1])
        bad_null_estimates = len([e for e in null_estimates if e != 0])
        
        false_negatives = 100.0*bad_estimates/num_trials
        false_positives = 100.0*bad_null_estimates/num_trials
        return false_positives,false_negatives

    #start = time.time()
    wt = WorkerThreads(2, trainAux)
    
    num_trials = 200
    width = 1.0
    performance = []
    for low in range(0,50):
        wt.addJob(low, (low,low+width,num_trials))
    wt.wait()
    while not wt.resultq.empty():
        job_id,errors = wt.resultq.get()
        fp,fn = errors
        performance.append(((fp+fn)/2.0, job_id, fn, fp))
    performance.sort()
    #pprint.pprint(performance)
    #print(time.time()-start)
    
    num_trials = 200
    lows = [p[1] for p in performance[0:5]]
    widths = [w/10.0 for w in range(5,65,5)]
    performance = []
    for width in widths:
        false_positives = []
        false_negatives = []
        for low in lows:
            wt.addJob(low,(low,low+width,num_trials))
        wt.wait()
        while not wt.resultq.empty():
            job_id,errors = wt.resultq.get()
            fp,fn = errors
            false_negatives.append(fn)
            false_positives.append(fp)

        #print(width, false_negatives)
        #print(width, false_positives)
        #performance.append(((statistics.mean(false_positives)+statistics.mean(false_negatives))/2.0,
        #                    width, statistics.mean(false_negatives), statistics.mean(false_positives)))
        performance.append((abs(statistics.mean(false_positives)-statistics.mean(false_negatives)),
                            width, statistics.mean(false_negatives), statistics.mean(false_positives)))
    performance.sort()
    #pprint.pprint(performance)
    good_width = performance[0][1]
    #print("good_width:",good_width)


    num_trials = 500
    performance = []
    for low in lows:
        wt.addJob(low, (low,low+good_width,num_trials))
    wt.wait()
    while not wt.resultq.empty():
        job_id,errors = wt.resultq.get()
        fp,fn = errors
        performance.append(((fp+fn)/2.0, job_id, fn, fp))
    performance.sort()
    #pprint.pprint(performance)
    best_low = performance[0][1]
    #print("best_low:", best_low)

    
    num_trials = 500
    widths = [good_width+(x/100.0) for x in range(-70,75,5) if good_width+(x/100.0) > 0.0]
    performance = []
    for width in widths:
        wt.addJob(width, (best_low,best_low+width,num_trials))
    wt.wait()
    while not wt.resultq.empty():
        job_id,errors = wt.resultq.get()
        fp,fn = errors
        #performance.append(((fp+fn)/2.0, job_id, fn, fp))
        performance.append((abs(fp-fn), job_id, fn, fp))
    performance.sort()
    #pprint.pprint(performance)
    best_width=performance[0][1]
    #print("best_width:",best_width)
    #print("final_performance:", performance[0][0])

    wt.stop()
    params = json.dumps({"low":best_low,"high":best_low+best_width}, sort_keys=True)
    return {'trial_type':"train",
            'num_observations':num_observations,
            'num_trials':num_trials,
            'params':params,
            'false_positives':performance[0][3],
            'false_negatives':performance[0][2]}


def trainSummary(summaryFunc, db, unusual_case, greater, num_observations):
    db.resetOffsets()
    stest = functools.partial(summaryTest, summaryFunc)
    
    def trainAux(distance, threshold, num_trials):
        estimator = functools.partial(stest, {'distance':distance,'threshold':threshold}, greater)
        estimates = bootstrap3(estimator, db, 'train', unusual_case, num_observations, num_trials)
        null_estimates = bootstrap3(estimator, db, 'train_null', unusual_case, num_observations, num_trials)

        bad_estimates = len([e for e in estimates if e != 1])
        bad_null_estimates = len([e for e in null_estimates if e != 0])
        
        false_negatives = 100.0*bad_estimates/num_trials
        false_positives = 100.0*bad_null_estimates/num_trials
        return false_positives,false_negatives

    #determine expected delta based on differences
    mean_diffs = [s['unusual_packet']-s['other_packet'] for s in db.subseries('train', unusual_case)]
    threshold = summaryFunc(mean_diffs)/2.0
    #print("init_threshold:", threshold)
    
    wt = WorkerThreads(2, trainAux)
    
    num_trials = 500
    performance = []
    for distance in range(1,50):
        wt.addJob(distance, (distance,threshold,num_trials))
    wt.wait()
    while not wt.resultq.empty():
        job_id,errors = wt.resultq.get()
        fp,fn = errors
        performance.append(((fp+fn)/2.0, job_id, fn, fp))
    
    performance.sort()
    #pprint.pprint(performance)
    good_distance = performance[0][1]
    #print("good_distance:",good_distance)

    
    num_trials = 500
    performance = []
    for t in range(80,122,2):
        wt.addJob(threshold*(t/100.0), (good_distance,threshold*(t/100.0),num_trials))
    wt.wait()
    while not wt.resultq.empty():
        job_id,errors = wt.resultq.get()
        fp,fn = errors
        #performance.append(((fp+fn)/2.0, job_id, fn, fp))
        performance.append((abs(fp-fn), job_id, fn, fp))
    performance.sort()
    #pprint.pprint(performance)
    good_threshold = performance[0][1]
    #print("good_threshold:", good_threshold)

    
    num_trials = 500
    performance = []
    for d in [good_distance+s for s in range(-4,5)
              if good_distance+s > -1 and good_distance+s < 51]:
        wt.addJob(d, (d,good_threshold,num_trials))
    wt.wait()
    while not wt.resultq.empty():
        job_id,errors = wt.resultq.get()
        fp,fn = errors
        performance.append(((fp+fn)/2.0, job_id, fn, fp))
    performance.sort()
    #pprint.pprint(performance)
    best_distance = performance[0][1]
    #print("best_distance:",best_distance)

    
    num_trials = 500
    performance = []
    for t in range(90,111):
        wt.addJob(good_threshold*(t/100.0), (best_distance,good_threshold*(t/100.0),num_trials))
    wt.wait()
    while not wt.resultq.empty():
        job_id,errors = wt.resultq.get()
        fp,fn = errors
        #performance.append(((fp+fn)/2.0, job_id, fn, fp))
        performance.append((abs(fp-fn), job_id, fn, fp))
    performance.sort()
    #pprint.pprint(performance)
    best_threshold = performance[0][1]
    #print("best_threshold:", best_threshold)

    wt.stop()
    params = json.dumps({'distance':best_distance,'threshold':best_threshold}, sort_keys=True)
    return {'trial_type':"train",
            'num_observations':num_observations,
            'num_trials':num_trials,
            'params':params,
            'false_positives':performance[0][3],
            'false_negatives':performance[0][2]}


def trainKalman(db, unusual_case, greater, num_observations):
    db.resetOffsets()

    def trainAux(params, num_trials):
        estimator = functools.partial(kalmanTest, params, greater)
        estimates = bootstrap3(estimator, db, 'train', unusual_case, num_observations, num_trials)
        null_estimates = bootstrap3(estimator, db, 'train_null', unusual_case, num_observations, num_trials)
        
        bad_estimates = len([e for e in estimates if e != 1])
        bad_null_estimates = len([e for e in null_estimates if e != 0])
        
        false_negatives = 100.0*bad_estimates/num_trials
        false_positives = 100.0*bad_null_estimates/num_trials
        return false_positives,false_negatives
    
    mean_diffs = [s['unusual_packet']-s['other_packet'] for s in db.subseries('train', unusual_case)]
    good_threshold = kfilter({},mean_diffs)['est'][-1]/2.0

    wt = WorkerThreads(2, trainAux)
    num_trials = 200
    performance = []
    for t in range(90,111):
        params = {'threshold':good_threshold*(t/100.0)}
        wt.addJob(good_threshold*(t/100.0), (params,num_trials))
    wt.wait()
    while not wt.resultq.empty():
        job_id,errors = wt.resultq.get()
        fp,fn = errors
        #performance.append(((fp+fn)/2.0, job_id, fn, fp))
        performance.append((abs(fp-fn), job_id, fn, fp))
    performance.sort()
    #pprint.pprint(performance)
    best_threshold = performance[0][1]
    #print("best_threshold:", best_threshold)
    params = {'threshold':best_threshold}

    wt.stop()
    
    return {'trial_type':"train",
            'num_observations':num_observations,
            'num_trials':num_trials,
            'params':json.dumps(params, sort_keys=True),
            'false_positives':performance[0][3],
            'false_negatives':performance[0][2]}

    
def trainTsval(db, unusual_case, greater, num_observations):
    db.resetOffsets()

    def trainAux(params, num_trials):
        estimator = functools.partial(tsvalwmeanTest, params, greater)
        estimates = bootstrap3(estimator, db, 'train', unusual_case, num_observations, num_trials)
        null_estimates = bootstrap3(estimator, db, 'train_null', unusual_case, num_observations, num_trials)
        
        bad_estimates = len([e for e in estimates if e != 1])
        bad_null_estimates = len([e for e in null_estimates if e != 0])
        
        false_negatives = 100.0*bad_estimates/num_trials
        false_positives = 100.0*bad_null_estimates/num_trials
        return false_positives,false_negatives
    
    train = db.subseries('train', unusual_case)
    null = db.subseries('train_null', unusual_case)
    good_threshold = (tsvalwmean(train)+tsvalwmean(null))/2.0

    wt = WorkerThreads(2, trainAux)
    num_trials = 200
    performance = []
    for t in range(90,111):
        params = {'threshold':good_threshold*(t/100.0)}
        wt.addJob(good_threshold*(t/100.0), (params,num_trials))
    wt.wait()
    while not wt.resultq.empty():
        job_id,errors = wt.resultq.get()
        fp,fn = errors
        #performance.append(((fp+fn)/2.0, job_id, fn, fp))
        performance.append((abs(fp-fn), job_id, fn, fp))
    performance.sort()
    #pprint.pprint(performance)
    best_threshold = performance[0][1]
    #print("best_threshold:", best_threshold)
    params = {'threshold':best_threshold}

    wt.stop()
    
    return {'trial_type':"train",
            'num_observations':num_observations,
            'num_trials':num_trials,
            'params':json.dumps(params, sort_keys=True),
            'false_positives':performance[0][3],
            'false_negatives':performance[0][2]}


classifiers = {'boxtest':{'train':trainBoxTest, 'test':multiBoxTest, 'train_results':[]},
               'midsummary':{'train':functools.partial(trainSummary, midsummary), 'test':midsummaryTest, 'train_results':[]},
               'ubersummary':{'train':functools.partial(trainSummary, ubersummary), 'test':ubersummaryTest, 'train_results':[]},
               'quadsummary':{'train':functools.partial(trainSummary, quadsummary), 'test':quadsummaryTest, 'train_results':[]},
               'tsvalwmean':{'train':trainTsval, 'test':tsvalwmeanTest, 'train_results':[]},
               #'kalman':{'train':trainKalman, 'test':kalmanTest, 'train_results':[]},
               #'_trimean':{'train':None, 'test':trimeanTest, 'train_results':[]},
              }

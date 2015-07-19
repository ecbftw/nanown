
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


from pykalman import KalmanFilter
_pykalman4d_params = None
_pykalman4d_params = {'observation_covariance': [[11960180434.411114, 4760272534.795976, 8797551081.431936, 6908794128.927051], [4760272534.795962, 12383598172.428213, 5470747537.2599745, 11252625555.297853], [8797551081.431955, 5470747537.2601185, 1466222848395.7058, 72565713883.12643], [6908794128.927095, 11252625555.297981, 72565713883.12654, 1519760903943.507]], 'transition_offsets': [592.5708159274, 583.3804671015271, 414.4187239098291, 562.166786712371], 'observation_offsets': [165.2279084503762, 157.76807691937614, 168.4235495099334, 225.33433430227353], 'initial_state_covariance': [[33599047.5, -18251285.25, 3242535690.59375, -8560730487.84375], [-18251285.25, 9914252.3125, -1761372688.59375, 4650260880.1875], [3242535690.59375, -1761372688.59375, 312926663745.03125, -826168494791.7188], [-8560730487.84375, 4650260880.1875, -826168494791.7188, 2181195982530.4688]], 'initial_state_mean': [12939012.5625, 12934563.71875, 13134751.608, 13138990.9985], 'transition_covariance': [[2515479496.145993, -401423541.70620924, 1409951418.1627903, 255932902.74454522], [-401423541.706214, 2744353887.676857, 1162316.2019491254, 1857251491.3987627], [1409951418.1628358, 1162316.2020361447, 543279068599.8229, -39399311190.5746], [255932902.74459982, 1857251491.398838, -39399311190.574585, 537826124257.5266]], 'observation_matrices': [[1.4255288693095167, -0.4254638445329988, 0.0003406844036817347, -0.0005475021956726778], [-0.46467270827589857, 1.4654311778340343, -0.0003321330280128265, -0.0002853945703691352], [-0.2644570970067974, -0.33955835481495455, 1.7494161615202275, -0.15394117603733548], [-0.3419097544041847, -0.23992883666045373, -0.15587790880447727, 1.7292393175137022]], 'transition_matrices': [[0.52163952865412, 0.47872618354122665, -0.0004322286766109684, 0.00017293351811531466], [0.5167436693545113, 0.48319044922845933, 7.765428142114672e-05, -0.00021518950285326355], [0.2091705950622469, 0.41051399729482796, 0.19341113299389256, 0.19562916616052917], [0.368592004009912, 0.22263632461118732, 0.20756792378812872, 0.20977025833570906]]}
_pykalman4d_good_threshold = 2009.25853272
_pykalman4d_params = None

_pykalman4d_params = {'observation_covariance': [[32932883342.63772, 18054300398.442295, 27538911550.824535, 17152378956.778696], [18054300398.446983, 436546443436.5115, 37327644533.69647, 424485386677.31274], [27538911550.838238, 37327644533.706024, 3276324705772.982, 456017515263.88715], [17152378956.788027, 424485386677.317, 456017515263.88245, 3767844180658.1724]], 'observation_matrices': [[1.025773112769464, -0.028755990114063934, 0.0003540921897382532, 0.0025748564713126143], [-0.8595457826320256, 1.8607522167556567, -0.003520779053701517, 0.002309145982167138], [-0.5806427858959466, 0.22466075141448982, 1.6247192012813798, -0.27363797512617793], [-0.5853369461874607, 0.262177909212312, -0.28415108658843735, 1.6020343138710018]], 'initial_state_mean': [0.0, 0.0, 0.0, 0.0], 'observation_offsets': [549.4498515668686, 484.2106453284049, 648.556719142234, 380.10978090584763], 'transition_covariance': [[4147844406.7768326, -1308763245.5992138, 2920744388.523955, 860096280.797968], [-1308763245.5998695, 171190325905.83395, 3557618712.218984, 165332873663.83142], [2920744388.532502, 3557618712.2283373, 1054894349089.0673, -117551209299.73402], [860096280.805706, 165332873663.83963, -117551209299.73474, 1223605046475.7324]], 'transition_offsets': [1156.9264087977374, 1150.752680207601, 1312.2595286459816, 1267.4069537452415], 'initial_state_covariance': [[667999273207241.0, 669330484615232.1, 713726904326576.2, 731731206363217.4], [669330484615390.9, 670664348906228.8, 715149243295271.9, 733189424910272.2], [713726904326843.4, 715149243295370.6, 762584802695960.9, 781821582244358.5], [731731206363417.0, 733189424910299.0, 781821582244278.6, 801543624134758.0]], 'transition_matrices': [[0.9680677036616316, 0.03260717171917804, 0.0005279411071512641, -0.0012363486571871363], [0.9555219601128613, 0.03851351491891819, 0.00411268796118236, 0.0017357967358293536], [0.622254432930994, -0.2583795512595657, 0.31745705251401546, 0.32357126976364725], [0.6644076824932768, -0.33545285094373867, 0.3295778964272671, 0.34682391469482354]]}
_pykalman4d_good_threshold = -253.849393803
def trainPyKalman4D(db, unusual_case, greater, num_observations):
    global _pykalman4d_params
    global _pykalman4d_good_threshold
    db.resetOffsets()

    if _pykalman4d_params == None:
        train = db.subseries('train',unusual_case, offset=0)
        null = db.subseries('train_null',unusual_case, offset=0)
        train_array = numpy.asarray([(s['unusual_packet'],s['other_packet'],s['unusual_tsval'],s['other_tsval'])
                                     for s in train])
        null_array = numpy.asarray([(s['unusual_packet'],s['other_packet'],s['unusual_tsval'],s['other_tsval'])
                                    for s in null])
        kf = KalmanFilter(n_dim_obs=4, n_dim_state=4)
        #initial_state_mean=[quadsummary([s['unusual_packet'] for s in train]),
        #                                      quadsummary([s['other_packet'] for s in train]),
        #                                      numpy.mean([s['unusual_tsval'] for s in train]),
        #                                      numpy.mean([s['other_tsval'] for s in train])])

        kf = kf.em(train_array+null_array[0:50000], n_iter=10,
                   em_vars=('transition_matrices',
                            'observation_matrices',
                            'transition_offsets',
                            'observation_offsets',
                            'transition_covariance',
                            'observation_covariance',
                            'initial_state_covariance'))
        _pykalman4d_params = {'transition_matrices': kf.transition_matrices.tolist(),
                              'observation_matrices': kf.observation_matrices.tolist(),
                              'transition_offsets': kf.transition_offsets.tolist(),
                              'observation_offsets': kf.observation_offsets.tolist(),
                              'transition_covariance': kf.transition_covariance.tolist(),
                              'observation_covariance': kf.observation_covariance.tolist(),
                              'initial_state_mean': kf.initial_state_mean.tolist(),
                              'initial_state_covariance': kf.initial_state_covariance.tolist()}
        print(_pykalman4d_params)
    
        kf = KalmanFilter(n_dim_obs=4, n_dim_state=4, **_pykalman4d_params)
        smoothed,covariance = kf.smooth(train_array)
        null_smoothed,covariance = kf.smooth(null_array)

        kp = _pykalman4d_params.copy()
        #kp['initial_state_mean']=[quadsummary([s['unusual_packet'] for s in train]),
        #                          quadsummary([s['other_packet'] for s in train]),
        #                          numpy.mean([s['unusual_tsval'] for s in train]),
        #                          numpy.mean([s['other_tsval'] for s in train])]
        #kf = KalmanFilter(n_dim_obs=4, n_dim_state=4, **kp)
        #null_smoothed,covariance = kf.smooth(null_array)
        
        _pykalman4d_good_threshold = (numpy.mean([m[0]-m[1] for m in smoothed])+numpy.mean([m[0]-m[1] for m in null_smoothed]))/2.0
        print(_pykalman4d_good_threshold)

    
    def trainAux(params, num_trials):
        estimator = functools.partial(pyKalman4DTest, params, greater)
        estimates = bootstrap3(estimator, db, 'train', unusual_case, num_observations, num_trials)
        null_estimates = bootstrap3(estimator, db, 'train_null', unusual_case, num_observations, num_trials)
        
        bad_estimates = len([e for e in estimates if e != 1])
        bad_null_estimates = len([e for e in null_estimates if e != 0])
        
        false_negatives = 100.0*bad_estimates/num_trials
        false_positives = 100.0*bad_null_estimates/num_trials
        return false_positives,false_negatives

    params = {'threshold':_pykalman4d_good_threshold, 'kparams':_pykalman4d_params}

    wt = WorkerThreads(2, trainAux)
    num_trials = 50
    performance = []
    for t in range(-80,100,20):
        thresh = _pykalman4d_good_threshold + abs(_pykalman4d_good_threshold)*(t/100.0)
        params['threshold'] = thresh
        wt.addJob(thresh, (params.copy(),num_trials))
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
    params['threshold']=best_threshold

    wt.stop()
    
    return {'trial_type':"train",
            'num_observations':num_observations,
            'num_trials':num_trials,
            'params':json.dumps(params, sort_keys=True),
            'false_positives':performance[0][3],
            'false_negatives':performance[0][2]}



classifiers = {'boxtest':{'train':trainBoxTest, 'test':multiBoxTest, 'train_results':[]},
               'midsummary':{'train':functools.partial(trainSummary, midsummary), 'test':midsummaryTest, 'train_results':[]},
               #'ubersummary':{'train':functools.partial(trainSummary, ubersummary), 'test':ubersummaryTest, 'train_results':[]},
               'quadsummary':{'train':functools.partial(trainSummary, quadsummary), 'test':quadsummaryTest, 'train_results':[]},
               'septasummary':{'train':functools.partial(trainSummary, septasummary), 'test':septasummaryTest, 'train_results':[]},
               #'pykalman4d':{'train':trainPyKalman4D, 'test':pyKalman4DTest, 'train_results':[]},
               #'tsvalwmean':{'train':trainTsval, 'test':tsvalwmeanTest, 'train_results':[]},
               #'kalman':{'train':trainKalman, 'test':kalmanTest, 'train_results':[]},
               #'_trimean':{'train':None, 'test':trimeanTest, 'train_results':[]},
              }

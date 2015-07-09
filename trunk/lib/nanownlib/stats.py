
import sys
import os
import math
import statistics
import gzip
import random
import scipy
import scipy.stats
import numpy

# Don't trust numpy's seeding
numpy.random.seed(random.SystemRandom().randint(0,2**32-1))


def mad(arr):
    """ Median Absolute Deviation: a "Robust" version of standard deviation.
        Indices variabililty of the sample.
        https://en.wikipedia.org/wiki/Median_absolute_deviation 
    """
    arr = numpy.ma.array(arr).compressed() # should be faster to not use masked arrays.
    med = numpy.median(arr)
    return numpy.median(numpy.abs(arr - med))


def cov(x,y):
    mx = statistics.mean(x)
    my = statistics.mean(y)
    products = []
    for i in range(0,len(x)):
        products.append((x[i] - mx)*(y[i] - my))

    return statistics.mean(products)


def difference(ls):
    return ls[0]-ls[1]

def product(ls):
    return ls[0]*ls[1]

def hypotenuse(ls):
    return math.hypot(ls[0],ls[1])
    
def trustValues(derived, trustFunc):
    ret_val = []
    for k,v in derived.items():
        ret_val.append((trustFunc((v['long'],v['short'])), k))

    ret_val.sort()
    return ret_val


def prunedWeights(derived, trust, alpha):
    weights = {}

    threshold = len(trust)*(1.0-alpha)
    for i in range(0,len(trust)):
        if i < threshold:
            weights[trust[i][1]] = 1.0
        else:
            weights[trust[i][1]] = 0.0

    return weights


def linearWeights(derived, trust, alpha):
    x1 = trust[0][0]
    y1 = 1.0 + (alpha*10)
    x2 = trust[(len(trust)-1)//3][0]
    y2 = 1.0
    m = (y1-y2)/(x1-x2)
    b = y1 - m*x1

    weights = {}
    for t,k in trust:
        weights[k] = m*t+b
        if weights[k] < 0.0:
            weights[k] = 0.0

    return weights


def invertedWeights(derived,trust,alpha):
    # (x+1-first_sample)^(-alpha)
    #scale = trust[0][0]

    #weights = {}
    #for t,k in trust:
    #    weights[k] = (t+1-scale)**(-1.0*alpha)
    #    if weights[k] < 0.0:
    #        weights[k] = 0.0

    weights = {}
    for i in range(len(trust)):
        w = 10.0/(i+2.0)-0.2
        if w < 0.0:
            w = 0.0
        weights[trust[i][1]] = w
        
    
    return weights



def arctanWeights(derived,trust,alpha):
    shift = trust[int((len(trust)-1)*(1.0-alpha))][0]
    minimum = trust[0][0]
    
    weights = {}
    for i in range(len(trust)):
        w = math.pi/2.0 - math.atan(2*(trust[i][0] - shift)/(shift-minimum))
        if w < 0.0:
            w = 0.0
        weights[trust[i][1]] = w

    return weights


def arctanWeights2(derived,trust,alpha):
    shift = trust[int((len(trust)-1)*(1.0-alpha))][0]
    minimum = trust[0][0]
    stretch = trust[int((len(trust)-1)*0.5)][0] - minimum # near median
    
    weights = {}
    for i in range(len(trust)):
        w = math.pi/2.0 - math.atan(3*(trust[i][0] - shift)/(shift-minimum))
        if w < 0.0:
            w = 0.0
        weights[trust[i][1]] = w

    return weights


def midhinge(values, distance=25):
    return (numpy.percentile(values, 50-distance) + numpy.percentile(values, 50+distance))/2.0

def trimean(values, distance=25):
    return (midhinge(values, distance) + statistics.median(values))/2

def weightedMean(derived, weights):
    normalizer = sum(weights.values())/len(weights)
    return statistics.mean([w*(derived[k]['long']-derived[k]['short'])/normalizer for k,w in weights.items()])

def weightedMeanTsval(derived, weights):
    normalizer = sum(weights.values())/len(weights)
    return statistics.mean([w*(derived[k]['long_tsval']-derived[k]['short_tsval'])/normalizer for k,w in weights.items()])


def estimateMean(trustFunc, weightFunc, alpha, derived):
    trust = trustValues(derived, trustFunc)
    weights = weightFunc(derived, trust, alpha)
    return weightedMean(derived, weights)


def estimateMeanTsval(trustFunc, weightFunc, alpha, derived):
    trust = trustValues(derived, trustFunc)
    weights = weightFunc(derived, trust, alpha)
    return weightedMeanTsval(derived, weights)


#def estimateMedian(trustFunc, weightFunc, alpha, derived):
#    trust = trustValues(derived, trustFunc)
#    weights = weightFunc(derived, trust, alpha)

#    return statistics.median([(derived[k]['long']-derived[k]['short']) for k,w in weights.items() if w > 0.0])

def estimateMedian(derived):
    return statistics.median([(d['long']-d['short']) for d in derived.values()])


def estimateMidhinge(derived):
    return midhinge([(d['long']-d['short']) for d in derived.values()])


def estimateTrimean(derived):
    return trimean([(d['long']-d['short']) for d in derived.values()])


def tTest(expected_mean, derived):
    diffs = [(d['long']-d['short']) for d in derived.values()]
    null_tval, null_pval = scipy.stats.ttest_1samp(diffs, 0.0)
    tval, pval = scipy.stats.ttest_1samp(diffs, expected_mean)

    if pval < null_pval:
        return 1
    else:
        return 0

    
def diffMedian(derived):
    l = [tc['long']-tc['short'] for s,tc in derived.items()]
    return statistics.median(l)


def subsample_ids(db, probe_type, subsample_size=None):
    cursor = db.conn.cursor()
    cursor.execute("SELECT max(c) FROM (SELECT count(sample) c FROM probes WHERE type=? GROUP BY test_case)", (probe_type,))
    population_size = cursor.fetchone()[0]
    #print("population_size:", population_size)
    if subsample_size == None or subsample_size > population_size:
        subsample_size = population_size
    
    start = numpy.random.random_integers(0,population_size-1)
    cursor.execute("SELECT sample FROM probes WHERE type=? GROUP BY sample ORDER BY sample LIMIT ? OFFSET ?", (probe_type,subsample_size,start))
    for row in cursor:
        subsample_size -= 1
        yield row['sample']

    if subsample_size > 0:
        cursor.execute("SELECT sample FROM probes WHERE type=? GROUP BY sample ORDER BY sample LIMIT ?", (probe_type,subsample_size))
        for row in cursor:
            yield row['sample']
    

def subsample(db, probe_type, subsample_size=None):
    cursor = db.conn.cursor()
    cursor.execute("SELECT count(test_case) FROM (SELECT test_case FROM probes GROUP BY test_case)")
    num_test_cases = cursor.fetchone()[0]
    
    for sid in subsample_ids(db, probe_type, subsample_size):
        cursor.execute("SELECT test_case,tc_order,time_of_day,reported,userspace_rtt,suspect,packet_rtt,tsval_rtt FROM probes p,analysis a WHERE p.sample=? and a.probe_id=p.id", (sid,))
        probes = cursor.fetchall()
        if len(probes) != num_test_cases:
            sys.stderr.write("WARN: sample %d had %d probes, but %d expected!  Discarding...\n" % (sid, len(probes), num_test_cases))
            continue
        yield (sid,[dict(r) for r in probes])


def subseries(db, probe_type, unusual_case, size=None, offset=None, field='packet_rtt'):
    population_size = db.populationSize(probe_type)

    if size == None or size > population_size:
        size = population_size
    if offset == None or offset >= population_size or offset < 0:
        offset = numpy.random.random_integers(0,population_size-1)

    query="""
      SELECT %(field)s AS unusual_case,
             (SELECT avg(%(field)s) FROM probes,analysis
              WHERE analysis.probe_id=probes.id AND probes.test_case!=:unusual_case AND probes.type=:probe_type AND sample=u.sample) AS other_cases
      FROM   (SELECT probes.sample,%(field)s FROM probes,analysis 
              WHERE analysis.probe_id=probes.id AND probes.test_case =:unusual_case AND probes.type=:probe_type) u
      LIMIT :size OFFSET :offset
    """ % {"field":field}
    
    params = {"probe_type":probe_type, "unusual_case":unusual_case, "offset":offset, "size":size}
    cursor = db.conn.cursor()
    cursor.execute(query, params)
    ret_val = [dict(row) for row in cursor.fetchall()]
    #for row in cursor:
    #    size -= 1
    #    yield dict(row)

    size -= len(ret_val)
    if size > 0:
        params['offset'] = 0
        params['size'] = size
        cursor.execute(query, params)
        ret_val += [dict(row) for row in cursor.fetchall()]
        #for row in cursor:
        #    yield dict(row)
    
    return ret_val


# if test_cases=None, include all of them.  Otherwise, include only the specified test cases.
def samples2Distributions(samples, field, test_cases=None):
    ret_val = {}
    
    for sid,probes in samples:
        for p in probes:
            if p['test_case'] in ret_val:
                ret_val[p['test_case']].append(p[field])
            elif test_cases == None or p['test_case'] in test_cases:
                ret_val[p['test_case']] = [p[field]]
                
                
    return ret_val


def samples2MeanDiffs(samples, field, unusual_case):
    ret_val = {}
    
    for sid,probes in samples:
        unusual_value = None
        for p in probes:
            if p['test_case'] == unusual_case:
                unusual_value = p[field]
                break
        yield statistics.mean([unusual_value-p[field] for p in probes if p['test_case'] != unusual_case])


def bootstrap(estimator, db, probe_type, test_cases, subsample_size, num_trials):
    ret_val = []
    for t in range(num_trials):
        ret_val.append(estimator(test_cases, subsample(db, probe_type, subsample_size)))

    return ret_val


def bootstrap2(estimator, db, probe_type, subsample_size, num_trials):
    ret_val = []
    for t in range(num_trials):
        ret_val.append(estimator(subsample(db, probe_type, subsample_size)))

    return ret_val


def bootstrap3(estimator, db, probe_type, unusual_case, subseries_size, num_trials):
    ret_val = []
    for t in range(num_trials):
        ret_val.append(estimator(subseries(db, probe_type, unusual_case, subseries_size)))

    return ret_val


# Returns the test case name that clearly has higher RTT; otherwise, returns None
def boxTest(params, test_cases, samples):
    if len(test_cases) != 2:
        # XXX: somehow generalize the box test to handle more than 2 cases
        raise Exception()
    dists = samples2Distributions(samples,'packet_rtt', test_cases) #XXX: field from params

    tmp1,tmp2 = dists.items()
    test_case1,dist1 = tmp1
    test_case2,dist2 = tmp2
    
    d1_high = numpy.percentile(dist1, params['high'])
    d2_low = numpy.percentile(dist2, params['low'])
    if d1_high < d2_low:
        return test_case2

    d1_low = numpy.percentile(dist1, params['low'])
    d2_high = numpy.percentile(dist2, params['high'])

    if d2_high < d1_low:
        return test_case1
    
    return None


# Returns 1 if unusual_case is unusual in the expected direction
#         0 if it isn't unusual
#        -1 if it is unusual in the wrong direction
def multiBoxTest(params, unusual_case, greater, samples):
    #XXX: packet_rtt field from params
    dists = samples2Distributions(samples, 'packet_rtt')
    
    uc = dists[unusual_case]
    rest = []
    for tc,d in dists.items():
        if tc != unusual_case:
            rest.extend(d)

    uc_high = numpy.percentile(uc, params['high'])
    rest_low = numpy.percentile(rest, params['low'])
    if uc_high < rest_low:
        if greater:
            return -1
        else:
            return 1

    uc_low = numpy.percentile(uc, params['low'])
    rest_high = numpy.percentile(rest, params['high'])
    if rest_high < uc_low:
        if greater:
            return 1
        else:
            return -1
        
    return 0


# Returns 1 if unusual_case is unusual in the expected direction
#         0 otherwise
def midhingeTest(params, greater, samples):
    diffs = [s['unusual_case']-s['other_cases'] for s in samples]

    mh = midhinge(diffs, params['distance'])
    if greater:
        if mh > params['threshold']:
            return 1
        else:
            return 0
    else:
        if mh < params['threshold']:
            return 1
        else:
            return 0


def rmse(expected, measurements):
    s = sum([(expected-m)**2 for m in measurements])/len(measurements)
    return math.sqrt(s)

def nrmse(expected, measurements):
    return rmse(expected, measurements)/(max(measurements)-min(measurements))

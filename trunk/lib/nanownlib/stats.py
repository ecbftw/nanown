
import sys
import os
import functools
import math
import statistics
import gzip
import random
try:
    import numpy
except:
    sys.stderr.write('ERROR: Could not import numpy module.  Ensure it is installed.\n')
    sys.stderr.write('       Under Debian, the package name is "python3-numpy"\n.')
    sys.exit(1)

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


def midsummary(values, distance=25):
    #return (numpy.percentile(values, 50-distance) + numpy.percentile(values, 50+distance))/2.0
    l,h = numpy.percentile(values, (50-distance,50+distance))
    return (l+h)/2.0

def trimean(values, distance=25):
    return (midsummary(values, distance) + statistics.median(values))/2

def ubersummary(values, distance=25):
    left2 = 50-distance
    left3 = 50-(distance/2.0)
    left1 = left2/2.0
    right2 = 50+distance
    right3 = 50+(distance/2.0)
    right1 = (right2+100)/2.0
    l1,l2,l3,r3,r2,r1 = numpy.percentile(values, (left1,left2,left3,right3,right2,right1))
    #print(l1,l2,l3,m,r3,r2,r1)
    return (l1+l2*4+l3+r3+r2*4+r1)/12.0
    #return statistics.mean((l1,l2,l3,m,r3,r2,r1))

    
def quadsummary(values, distance=25):
    left1 = 50-distance
    left2 = (left1+50)/2.0
    right1 = 50+distance
    right2 = (right1+50)/2.0
    l1,l2,r2,r1 = numpy.percentile(values, (left1,left2,right2,right1))
    #print(left1,left2,left3,50,right3,right2,right1)
    #print(l1,l2,l3,m,r3,r2,r1)
    return (l1+l2+r2+r1)/4.0
    #return statistics.mean((l1,l2,l3,m,r3,r2,r1))

    
def septasummary(values, distance=25):
    left2 = 50-distance
    left3 = 50-(distance/2.0)
    left1 = left2/2.0
    right2 = 50+distance
    right3 = 50+(distance/2.0)
    right1 = (right2+100)/2.0
    l1,l2,l3,m,r3,r2,r1 = numpy.percentile(values, (left1,left2,left3,50,right3,right2,right1))
    return (l1+l2+l3+m+r3+r2+r1)/7.0


def tsvalwmean(subseries):
    weights = [(s['unusual_packet']+s['other_packet'])**2 for s in subseries]
    normalizer = sum(weights)/len(weights)
    return numpy.mean([weights[i]*(subseries[i]['unusual_tsval']-subseries[i]['other_tsval'])/normalizer
                       for i in range(len(weights))])

#def tsvalwmean(subseries):
#    return numpy.mean([(s['unusual_tsval']-s['other_tsval']) for s in subseries])


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


def bootstrap3(estimator, db, probe_type, unusual_case, subseries_size, num_trials):
    ret_val = []
    for t in range(num_trials):
        ret_val.append(estimator(db.subseries(probe_type, unusual_case, subseries_size)))

    return ret_val


# Returns 1 if unusual_case is unusual in the expected direction
#         0 if it isn't unusual
#        -1 if it is unusual in the wrong direction
def multiBoxTest(params, greater, samples):
    uc = [s['unusual_packet'] for s in samples]
    rest = [s['other_packet'] for s in samples]
    
    uc_high,uc_low = numpy.percentile(uc, (params['high'],params['low']))
    rest_high,rest_low = numpy.percentile(rest, (params['high'],params['low']))
    if uc_high < rest_low:
        if greater:
            return -1
        else:
            return 1

    if rest_high < uc_low:
        if greater:
            return 1
        else:
            return -1
        
    return 0


# Returns 1 if unusual_case is unusual in the expected direction
#         0 otherwise
def summaryTest(f, params, greater, samples):
    diffs = [s['unusual_packet']-s['other_packet'] for s in samples]

    mh = f(diffs, params['distance'])
    #print("estimate:", mh)
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


midsummaryTest = functools.partial(summaryTest, midsummary)
trimeanTest = functools.partial(summaryTest, trimean)
ubersummaryTest = functools.partial(summaryTest, ubersummary)
quadsummaryTest = functools.partial(summaryTest, quadsummary)
septasummaryTest = functools.partial(summaryTest, septasummary)

def rmse(expected, measurements):
    s = sum([(expected-m)**2 for m in measurements])/len(measurements)
    return math.sqrt(s)

def nrmse(expected, measurements):
    return rmse(expected, measurements)/(max(measurements)-min(measurements))


class KalmanFilter1D:
    def __init__(self, x0, P, R, Q):
        self.x = x0
        self.P = P
        self.R = R
        self.Q = Q

    def update(self, z):
        self.x = (self.P * z + self.x * self.R) / (self.P + self.R)
        self.P = 1. / (1./self.P + 1./self.R)

    def predict(self, u=0.0):
        self.x += u
        self.P += self.Q


def kfilter(params, observations):
    x = numpy.array(observations)    
    movement = 0
    est = []
    var = []
    kf = KalmanFilter1D(x0 = quadsummary(x), # initial state
                        #P  = 10000,         # initial variance
                        P  = 10,            # initial variance
                        R  = numpy.std(x),   # msensor noise
                        Q  = 0)              # movement noise
    for round in range(1):
        for d in x:
            kf.predict(movement)
            kf.update(d)
            est.append(kf.x)
            var.append(kf.P)

    return({'est':est, 'var':var})


def kalmanTest(params, greater, samples):
    diffs = [s['unusual_packet']-s['other_packet'] for s in samples]

    m = kfilter(params, diffs)['est'][-1]
    if greater:
        if m > params['threshold']:
            return 1
        else:
            return 0
    else:
        if m < params['threshold']:
            return 1
        else:
            return 0


def tsvalwmeanTest(params, greater, samples):
    m = tsvalwmean(samples)
    if greater:
        if m > params['threshold']:
            return 1
        else:
            return 0
    else:
        if m < params['threshold']:
            return 1
        else:
            return 0


from pykalman import KalmanFilter
def pyKalman4DTest(params, greater, samples):
    kp = params['kparams']
    #kp['initial_state_mean']=[quadsummary([s['unusual_packet'] for s in samples]),
    #                          quadsummary([s['other_packet'] for s in samples]),
    #                          numpy.mean([s['unusual_tsval'] for s in samples]),
    #                          numpy.mean([s['other_tsval'] for s in samples])]
    kf = KalmanFilter(n_dim_obs=4, n_dim_state=4, **kp)
    smooth,covariance = kf.smooth([(s['unusual_packet'],s['other_packet'],s['unusual_tsval'],s['other_tsval'])
                                   for s in samples])
    m = numpy.mean(smooth)
    if greater:
        if m > params['threshold']:
            return 1
        else:
            return 0
    else:
        if m < params['threshold']:
            return 1
        else:
            return 0
    

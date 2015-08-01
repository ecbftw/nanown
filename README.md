# Nanown

A tool for identifying, evaluating, and exploiting timing
vulnerabilities remotely.  This is part of the output from a research
effort [discussed at BlackHat 2015](https://www.blackhat.com/us-15/briefings.html#web-timing-attacks-made-practical).
This project is still highly experimental and not particularly easy to
use at this point.


# Prerequisites

Linux and Python 3.4+ are required.  Yes, really, your Python needs to
be that new.  You will also need to install the following modules for
this version of Python:
```
requests
numpy
netifaces 
matplotlib
```
On Debian unstable, you can get these by running:
```
apt-get install python3-requests python3-numpy python3-netifaces python3-matplotlib
```
Otherwise, resort to `pip3`.

In addition, you'll need to have a C compiler and the development
package for libpcap installed.  Under Debian this is probably sufficient:
```
apt-get install libpcap-dev gcc
```


# Installation

Hah! Funny.

Currently there's no installation script...

To attempt to use this code, clone the repository and build the
`nanown-listen` tool with:
```
cd nanown/trunk/src && ./compile.sh
```

That will drop the `nanown-listen` binary under nanown/trunk/bin.  You
must then put this directory in your `$PATH` in order to perform any
data collection.

To run any of the other scripts, change to the nanown/trunk directory
and run them directly from there.  E.g.:
```
bin/train ...args...
bin/graph ...args...
```


# Usage

Our goal for a usage workflow is this:

1. Based on example HTTP requests, and test cases supplied by the user,
   a script generator creates a new script.  This new script serves
   as the sample collection script, customized for your web
   application.

2. After collecting samples using the script from step 1, you run a
   mostly automated script to train and test various classifiers on your
   samples.  This will then tell you how many samples you need to
   reliably detect the timing difference.

3. Given the output from step 3 and inputs to step 1, a second script
   generator creates an attack script for you as a starting point.  You
   customize this and run your attacks.

Sounds great, yeah?  Well steps 1 and 3 aren't quite implemented yet. =\

If you are really dying to use this code right now, just make a copy of
the `trunk/bin/sampler` script and hack on it until it sends HTTP requests
that your targeted web application expects.  Be sure to define the test
cases appropriately.  Then run it to collect at least
50,000 samples for each the train, test and train_null data sets
(150,000 samples total).  NOTE: Your sampler script must be run as `root`
so it can tweak local networking settings and sniff packets.

Next you can move on to step 2, where you simply run the train script
against the database created by your sampler script:
```
bin/train mysamples.db
```
This will run for a while.  If you cancel out and re-run it, it will
pick up where it left off.  Pay special attention to the final results
it prints out.  This will tell you how many samples are needed to
distinguish between the test cases.  Do a little math on your own to
decide how feasible your overall attack will be.

Finally, we come to step 3.  If you choose to carry out an attack, you
will need to implement your own attack script that collects batches of
samples, distinguishes between them using the best classifier available
(from step 2) and then repeats as needed.  Consider starting with the
sample script at `test/blackhat-demo/jregistrate-attack`.

Any questions?  See the source, watch our BlackHat presentation, read
our research paper, or [post an issue](https://github.com/ecbftw/nanown/issues) on GitHub.

#!/usr/bin/python

"""
A decision tree based system for calculating matches ratios.
Part of the Pigaios Project.

Copyright (c) 2018, Joxean Koret
"""

import os
import sys
import time
import sklearn
import numpy as np

try:
  import matplotlib.pyplot as plt
except:
  pass

from sklearn import tree
from sklearn.externals import joblib

SK_VERSION = int(sklearn.__version__.split(".")[1])

#-------------------------------------------------------------------------------
def log(msg):
  print("[%s] %s" % (time.asctime(), msg))

#-------------------------------------------------------------------------------
class CPigaiosDecisionTree:
  def __init__(self):
    self.X = []
    self.y = []
    self.clf = None
    self.criterion = "mse"

    self.dt_type = tree.DecisionTreeRegressor

  def load_data(self, dataset="dataset.csv"):
    if len(self.X) > 0:
      return self.X, self.y

    lines = open(dataset, "rb").readlines()
    x_values = []
    y_values = []
    for i, line in enumerate(lines):
      if i == 0:
        continue

      line = line.strip("\n").strip("\r")
      fields = line.split(",")
      is_match = fields[2]
      x_values.append( map(float, fields[3:]) )
      y_values.append( [float(is_match)] )

    return np.array(x_values), np.array(y_values)

  def predict(self):
    X = self.X
    y = self.y

    ones = 0
    ones_bad = 0
    zeros = 0
    zeros_bad = 0
    total_matches = 0
    for i in range(0, len(X)):
      tmp = X[i]
      ret = self.clf.predict(tmp.reshape(1, -1))
      ret = round(ret)
      if ret == y[i]:
        total_matches += 1

      if y[i] != 1:
        if ret != 0:
          zeros_bad += 1
        else:
          zeros += 1
        continue

      if ret == y[i]:
        ones += 1
      else:
        ones_bad += 1

    line = "Correctly predicted %d out of %d (true positives %d -> %f%%, false positives %d -> %f%%)"
    log(line % (ones, ones + ones_bad, ones_bad, (ones * 100. / (ones + ones_bad)), zeros_bad, ((zeros_bad * 100. / (zeros + zeros_bad)))))
    log("Total right matches %d -> %f%%" % (total_matches, (total_matches * 100. / len(X))))

  def load_model(self):
    dirname = os.path.dirname(os.path.realpath(__file__))
    filename = os.path.join(dirname, "clf.pkl")
    return joblib.load(filename)

  def train(self):
    log("Loading data...")
    self.X, self.y = self.load_data()
    log("Fitting data with %s(%s)..." % (self.dt_type.__name__, repr(self.criterion)))
    self.clf = self.dt_type(criterion=self.criterion)
    self.clf.fit(self.X, self.y)
    log("Predicting...")
    self.predict()
    log("Saving model...")
    joblib.dump(self.clf, "clf.pkl")

  def test(self):
    log("Loading model and data...")
    self.clf = joblib.load("clf.pkl")
    self.X, self.y = self.load_data()
    log("Predicting...")
    self.predict()
  
  def graphviz(self):
    if self.clf is None:
      log("Loading model...")
      self.clf = joblib.load("clf.pkl")

    dot_data = tree.export_graphviz(self.clf, out_file="pigaios.dot", filled=True, rounded=True, special_characters=True)
    os.system("dot -Tx11 pigaios.dot")
  
  def plot(self):
    log("Loading data...")
    self.X, self.y = self.load_data()

    log("Fiting data in a classifier and a regressor")
    clf1 = tree.DecisionTreeClassifier()
    clf2 = tree.DecisionTreeRegressor()
    clf1.fit(self.X, self.y)
    clf2.fit(self.X, self.y)

    y_1 = clf1.predict(self.X)
    y_2 = clf2.predict(self.X)

    # Plot the results
    plt.figure(1)

    plt.subplot(311)
    plt.plot(self.y)

    plt.subplot(312)
    plt.plot(y_1)

    plt.subplot(313)
    plt.plot(y_2)
    plt.show()

#-------------------------------------------------------------------------------
def usage():
  print "Usage: %s [options]" % sys.argv[0]
  print
  print "--train                  Train the decision tree."
  print "--verify                 Test the trained decision tree."
  print "--classifier             Use a decision tree classifier."
  print "--regressor              Use a decision tree regressor."
  print "--graphviz               Show the generated decision tree."
  print "--criterion-mse          Set the regressor criterion to MSE."
  print "--criterion-fmse         Set the regressor criterion to Friedman's MSE."
  if SK_VERSION >= 18:
    print "--criterion-mae          Set the regressor criterion to MAE."
  print "--criterion-gini         Set the classifier criterion to Gini."
  print "--criterion-entropy      Set the classifier criterion to entropy."
  print "--plot                   Plot the accuracy differences between a classifier and a regressor"
  print

#-------------------------------------------------------------------------------
def main(args):
  pdt = CPigaiosDecisionTree()
  for arg in args:
    if arg in ["-t", "--train"]:
      pdt.train()
    elif arg in ["-v", "--verify"]:
      pdt.test()
    elif arg in ["-c", "--classifier"]:
      log("Using a decision tree classifier")
      pdt.dt_type = tree.DecisionTreeClassifier
    elif arg in ["-r", "--regressor"]:
      log("Using a decision tree regressor")
      pdt.dt_type = tree.DecisionTreeRegressor
    elif arg in ["-g", "--graphviz"]:
      pdt.graphviz()
    elif arg in ["-mse", "--criterion-mse"]:
      pdt.criterion = "mse"
    elif arg in ["-fmse", "--criterion-fmse"]:
      pdt.criterion = "friedman_mse"
    elif arg in ["-mae", "--criterion-mae"]:
      if SK_VERSION < 18:
        raise Exception("Unsupported in version 1.%d" % SK_VERSION)
      pdt.criterion = "mae"
    elif arg in ["-gini", "--criterion-gini"]:
      pdt.criterion = "gini"
    elif arg in ["-entropy", "--criterion-entropy"]:
      pdt.criterion = "entropy"
    elif arg in ["--plot"]:
      pdt.plot()
    else:
      usage()

if __name__ == "__main__":
  if len(sys.argv) == 1:
    usage()
  else:
    main(sys.argv[1:])

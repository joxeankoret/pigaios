#!/usr/bin/env python2.7

"""
A machine learning based system for calculating matches ratios. Part of the
Pigaios Project.

Copyright (c) 2018, Joxean Koret

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

from __future__ import print_function

#-------------------------------------------------------------------------------
# Dear SciKit and NumPy developers: fuck you.
#
def warn(*args, **kwargs):
  pass
import warnings
warnings.warn = warn
warnings.filterwarnings("ignore")
#
# End of code to disable the annonyance of importing numpy and/or SciKit
#-------------------------------------------------------------------------------

import os
import sys
import csv
import time
import math
import random
import sklearn
import threading
import numpy as np
np.warnings.filterwarnings('ignore')

from sklearn import tree
from sklearn import ensemble
from sklearn import neighbors
from sklearn import naive_bayes
from sklearn import linear_model
from sklearn import neural_network
from sklearn.externals import joblib
from sklearn.model_selection import cross_val_score
from sklearn.utils.validation import check_is_fitted

#-------------------------------------------------------------------------------
SK_MAJOR = int(sklearn.__version__.split(".")[0])
SK_MINOR = int(sklearn.__version__.split(".")[1])

#-------------------------------------------------------------------------------
# All the known working classifiers are listed here. All the classifiers but one
# increase the number of true positives. The Bayesian Ridge doesn't increase the
# number of true positives but reduces the false positives ratio a 0.0048%. Not
# very interesting, but I'll leave it here.
#
ML_CLASSIFIERS = [
  (tree.DecisionTreeClassifier, "Decision Tree Classifier", []),
  ]

#-------------------------------------------------------------------------------
def log(msg):
  print("[%s] %s" % (time.asctime(), msg))

#-------------------------------------------------------------------------------
# The original VotingClassifier class uses np.bincount() with an array and
# annoyingly it will fail with a message like "cannot cast float64 to int64".
#
class CPigaiosVotingClassifier(ensemble.VotingClassifier):
  def predict(self, X):
    """ Predict class labels for X.

    Parameters
    ----------
    X : {array-like, sparse matrix}, shape = [n_samples, n_features]
      Training vectors, where n_samples is the number of samples and
      n_features is the number of features.

    Returns
    ----------
    maj : array-like, shape = [n_samples]
      Predicted class labels.
    """

    check_is_fitted(self, 'estimators_')
    if self.voting == 'soft':
      maj = np.argmax(self.predict_proba(X), axis=1)

    else:  # 'hard' voting
      predictions = self._predict(X)
      maj = np.apply_along_axis(
        lambda x: np.argmax(
          np.bincount(list(x), weights=self._weights_not_none, )),
        axis=1, arr=predictions)

    maj = self.le_.inverse_transform(maj)
    return maj

#-------------------------------------------------------------------------------
class CPigaiosMultiClassifier(object):
  def __init__(self, random_state=None):
    self.clfs = {}
    for classifier, name, args in ML_CLASSIFIERS:
      has_seed = 'random_state' in dir(classifier.__init__.im_class())
      if has_seed:
        self.clfs[name] = classifier(random_state=random_state)
        for arg_name, arg_value in args:
          setattr(self.clfs[name], arg_name, arg_value)
      else:
        self.clfs[name] = classifier()
        for arg_name, arg_value in args:
          setattr(self.clfs[name], arg_name, arg_value)

  def fit(self, X, y):
    threads = []
    for clf in self.clfs.values():
      print("Fitting", clf)
      t = threading.Thread(target=clf.fit, args=(X, y))
      t.start()
      threads.append(t)

    for t in threads:
      t.join()

  def predict(self, input_val):
    ret = []
    for clf in self.clfs.values():
      tmp = clf.predict(input_val).item()
      tmp = round(float(tmp), 2)
      ret.append(min(tmp, 1.0))

    min_val = 0.0
    max_val = max(ret)
    if round(max_val) == 1.0:
      if sum(ret) >= 2.0:
        min_val = max_val

    val = sum(ret) / len(ret)
    if val < min_val:
      val = min_val

    return val

  def predict_proba(self, input_val):
    ret = []
    for clf in self.clfs.values():
      ret.append(clf.predict_proba(input_val)[0][1])
    return sum(ret) / len(ret)

#-------------------------------------------------------------------------------
class CPigaiosClassifier:
  def __init__(self):
    self.X = []
    self.y = []
    self.clf = None
    self.criterion = "gini"
    self.dt_type = tree.DecisionTreeClassifier

  def load_data(self, dataset="dataset.csv"):
    if len(self.X) > 0:
      return self.X, self.y

    x_values = []
    y_values = []
    with open(dataset, "r") as f:
      reader = csv.reader(f)
      next(reader, None)
      for row in reader:
        is_match = row[2]
        x_values.append(map(float, row[3:]))
        y_values.append([float(is_match)])

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

    line = "Correctly predicted %d out of %d (false negatives %d -> %f%%, false positives %d -> %f%%)"
    log(line % (ones, ones + ones_bad, ones_bad, \
       (ones_bad * 100. / (ones + ones_bad)), zeros_bad, \
       ((zeros_bad * 100. / (zeros + zeros_bad)))))
    log("Total right matches %d -> %f%%" % (total_matches, (total_matches * 100. / len(X))))

  def load_model(self):
    dirname = os.path.dirname(os.path.realpath(__file__))
    filename = os.path.join(dirname, "clf.pkl")
    return joblib.load(filename)

  def train(self):
    log("Loading data...")
    self.X, self.y = self.load_data()
    log("Fitting data with %s(%s)..." % (self.dt_type.__name__, repr(self.criterion)))
    if self.criterion is not None:
      self.clf = self.dt_type(self.criterion)
    else:
      self.clf = self.dt_type()

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

  def vote(self):
    log("Loading data...")
    self.X, self.y = self.load_data()
    estimators = []
    names = []
    for classifier, name, arg in ML_CLASSIFIERS:
      clf = classifier(arg)
      log("Creating model %s..." % (classifier.__name__))
      estimators.append([classifier.__name__, clf])
      names.append(name)

    log("Fitting data with VotingClassifier('hard')")
    self.clf = CPigaiosVotingClassifier(estimators=estimators, voting='hard', n_jobs=-1)
    self.clf.fit(self.X, self.y)

    log("Predicting...")
    self.predict()
    log("Saving model...")
    joblib.dump(self.clf, "clf.pkl")

    for clf, label in zip(estimators, names):
      try:
        scores = cross_val_score(clf, self.X, self.y, cv=5, scoring='accuracy')
        print("Accuracy: %0.2f (+/- %0.2f) [%s]" % (scores.mean(), scores.std(), label))
      except:
        print("Error with", clf, ":", sys.exc_info()[1])

  def graphviz(self):
    if self.clf is None:
      log("Loading model...")
      self.clf = joblib.load("clf.pkl")

    dot_data = tree.export_graphviz(self.clf, out_file="pigaios.dot", \
                                    filled=True, rounded=True, \
                                    special_characters=True)
    os.system("dot -Tx11 pigaios.dot")

#-------------------------------------------------------------------------------
def usage():
  print("Usage: %s [options]" % sys.argv[0])
  print()
  print("--multi-classifier       Use the default multi-classifier.")
  print("--train                  Train the classifier.")
  print("--verify                 Test the trained classifier.")
  print("--dt-classifier          Use a decision tree classifier.")
  print("--dt-regressor           Use a decision tree regressor.")
  print("--logistic-regression    Use a logistic regression classifier.")
  print("--sgd-classifier         Use a linear classifier with SGD training.")
  print("--gaussian-naive-bayes   Use a Gaussian Naive Bayes classifier.")
  print("--multinomial-bayes      Use a Gaussian Multinomial Naive Bayes classifier.")
  print("--random-forest          Use a Random Forest classifier.")
  print("--graphviz               Show the generated decision tree.")
  print("--criterion-mse          Set the regressor criterion to MSE.")
  print("--criterion-fmse         Set the regressor criterion to Friedman's MSE.")
  if (SK_MAJOR == 0 and SK_MINOR >= 18) or SK_MAJOR >= 1:
    print("--criterion-mae          Set the regressor criterion to MAE.")
  print("--criterion-gini         Set the classifier criterion to Gini.")
  print("--criterion-entropy      Set the classifier criterion to entropy.")
  print()

#-------------------------------------------------------------------------------
def main(args):
  random.seed(1)
  pdt = CPigaiosClassifier()
  for arg in args:
    if arg in ["-t", "--train"]:
      pdt.train()
    elif arg in ["-v", "--verify"]:
      pdt.test()
    elif arg in ["-dt", "--dt-classifier"]:
      log("Using a decision tree classifier")
      pdt.dt_type = tree.DecisionTreeClassifier
      pdt.criterion = "gini"
    elif arg in ["-dr", "--dt-regressor"]:
      log("Using a decision tree regressor")
      pdt.dt_type = tree.DecisionTreeRegressor
      pdt.criterion = "mse"
    elif arg in ["-b", "--linear-bayesian"]:
      log("Using a Bayesian Ridge linear model")
      pdt.dt_type = linear_model.BayesianRidge
      pdt.criterion = None
    elif arg in ["-lr", "--logistic-regression"]:
      log("Using a Logistic Regression linear model")
      pdt.dt_type = linear_model.LogisticRegression
      pdt.criterion = None
    elif arg in ["-sc", "--sgd-classifier"]:
      log("Using an SGD Classifier model")
      pdt.dt_type = linear_model.SGDClassifier
      pdt.criterion = None
    elif arg in ["-gauss", "--gaussian-naive-bayes"]:
      log("Using a Gaussian Naive Bayes model")
      pdt.dt_type = naive_bayes.GaussianNB
      pdt.criterion = None
    elif arg in ["-m", "--multinomial-bayes"]:
      log("Using a Gaussian Multinomial Naive Bayes model")
      pdt.dt_type = naive_bayes.MultinomialNB
      pdt.criterion = None
    elif arg in ["-bnb", "--bernoulli-bayes"]:
      log("Using a Bernoulli Naive Bayes model")
      pdt.dt_type = naive_bayes.BernoulliNB
      pdt.criterion = None
    elif arg in ["-gbc", "--gradient-boost-classifier"]:
      log("Using a Gradient Boosting Classifier")
      pdt.dt_type = ensemble.GradientBoostingClassifier
      pdt.criterion = None
    elif arg in ["-gbr", "--gradient-boost-regressor"]:
      log("Using a Gradient Boosting Regressor")
      pdt.dt_type = ensemble.GradientBoostingRegressor
      pdt.criterion = None
    elif arg in ["-vt", "--voting-classifier"]:
      log("Using a Voting Classifier")
      pdt.vote()
    elif arg in ["-multi", "--multi-classifier"]:
      log("Using the Pigaios Multi Classifier")
      pdt.dt_type = CPigaiosMultiClassifier
      pdt.criterion = None
    elif arg in ["-mlpc", "--mlp-classifier"]:
      log("Using the MLPClassifier")
      pdt.dt_type = neural_network.MLPClassifier
      pdt.criterion = 15
    elif arg in ["-rf", "--random-forest"]:
      log("Using the RandomForestClassifier")
      pdt.dt_type = ensemble.RandomForestClassifier
      pdt.criterion = 10
    elif arg in ["-g", "--graphviz"]:
      pdt.graphviz()
    elif arg in ["-mse", "--criterion-mse"]:
      pdt.criterion = "mse"
    elif arg in ["-fmse", "--criterion-fmse"]:
      pdt.criterion = "friedman_mse"
    elif arg in ["-mae", "--criterion-mae"]:
      pdt.criterion = "mae"
    elif arg in ["-gini", "--criterion-gini"]:
      pdt.criterion = "gini"
    elif arg in ["-entropy", "--criterion-entropy"]:
      pdt.criterion = "entropy"
    else:
      usage()

if __name__ == "__main__":
  if len(sys.argv) == 1:
    usage()
  else:
    main(sys.argv[1:])

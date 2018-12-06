# Dataset

The following is a dataset created with the good matches discovered between ZLib 1.2.11 & 1.2.5, Curl, Lua, Busybox, GMP, the whole coreutils and SQLite.
It contains all the positives found between the source code and the binaries as well as a random selection of 1,000,000 negative results, created with the following easy SQLite3 command line tool script:

```
$ sqlite3 dataset.db
sqlite> .headers on
sqlite> .mode csv
sqlite> .output dataset.csv
sqlite> select * from matches where accurate = 1;
sqlite> .headers off
sqlite> select * from matches where accurate = 0 order by random() limit 1000000;
sqlite> .quit
```

## Results

The current classifier is based on the results of multiple other classifiers, namely: 

 * Decision Tree Classifier.
 * RandomForestClassifier.
 * Bernoulli Naive Bayes.
 * Gradient Boosting Classifier.

Using this multi-classifier to train an adapted dataset the following initial results were observed and reproduced:

```
$ ml/pigaios_ml.py -multi -v
[Fri Sep 21 11:26:14 2018] Using the Pigaios Multi Classifier
[Fri Sep 21 11:26:14 2018] Loading model and data...
[Fri Sep 21 11:26:14 2018] Predicting...
[Fri Sep 21 11:26:16 2018] Correctly predicted 3840 out of 4392 (true positives 552 -> 87.431694%, false positives 441 -> 4.410000%)
[Fri Sep 21 11:26:16 2018] Total right matches 13399 -> 93.100334%
```

Later on, after refining the dataset and adding more fields, the following results were observed:

```
$ ../ml/pigaios_ml.py -multi -t
[Thu Dec  6 20:50:08 2018] Using the Pigaios Multi Classifier
[Thu Dec  6 20:50:08 2018] Loading data...
[Thu Dec  6 20:50:16 2018] Fitting data with CPigaiosMultiClassifier(None)...
Fitting DecisionTreeClassifier(class_weight=None, criterion='gini', max_depth=None,
            max_features=None, max_leaf_nodes=None,
            min_impurity_decrease=0.0, min_impurity_split=None,
            min_samples_leaf=1, min_samples_split=2,
            min_weight_fraction_leaf=0.0, presort=False, random_state=None,
            splitter='best')
Fitting BernoulliNB(alpha=1.0, binarize=0.0, class_prior=None, fit_prior=True)
Fitting GradientBoostingClassifier(criterion='friedman_mse', init=None,
              learning_rate=0.1, loss='deviance', max_depth=3,
              max_features=None, max_leaf_nodes=None,
              min_impurity_decrease=0.0, min_impurity_split=None,
              min_samples_leaf=1, min_samples_split=2,
              min_weight_fraction_leaf=0.0, n_estimators=100,
              presort='auto', random_state=None, subsample=1.0, verbose=0,
              warm_start=False)
Fitting RandomForestClassifier(bootstrap=True, class_weight=None, criterion='gini',
            max_depth=None, max_features='auto', max_leaf_nodes=None,
            min_impurity_decrease=0.0, min_impurity_split=None,
            min_samples_leaf=1, min_samples_split=2,
            min_weight_fraction_leaf=0.0, n_estimators=10, n_jobs=1,
            oob_score=False, random_state=None, verbose=0,
            warm_start=False)
[Thu Dec  6 20:54:26 2018] Predicting...
[Thu Dec  6 21:05:14 2018] Correctly predicted 13813 out of 19075 (false negatives 5262 -> 27.585845%, false positives 832 -> 0.083200%)
[Thu Dec  6 21:05:14 2018] Total right matches 1012981 -> 99.402007%
[Thu Dec  6 21:05:14 2018] Saving model...
```

So, in summary, our model predicts >98% matches from the dataset correctly with ~0.5% of false positives, which is more than acceptable.

## How to generate datasets

If you want to generate your own datasets, export your binary or binaries as well as the source codes and, then, use the script ```ml/pigaios_create_dataset.py``` to create a CSV file.

## How to train datasets

If you want to train the model with your own datasets or using a different classifier, use the script ```ml/pigaios_ml.py```.

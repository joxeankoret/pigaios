# Dataset

The following is a dataset created with the good matches discovered between ZLib 1.2.11 & 1.2.5, Curl, Lua, Busybox and SQLite.
It contains all the positives found between the source code and the binaries as well as a random selection of 100,000 negative results, created with the following easy SQLite3 command line tool script:

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

 * Decision Tree Regressor.
 * Bernoulli Naive Bayes.
 * Gradient Boosting Regressor.

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
$ ml/pigaios_ml.py -multi -v
[Tue Sep 25 11:54:06 2018] Using the Pigaios Multi Classifier
[Tue Sep 25 11:54:06 2018] Loading model and data...
[Tue Sep 25 11:54:07 2018] Predicting...
[Tue Sep 25 11:54:22 2018] Correctly predicted 5140 out of 6989 (true positives 1849 -> 73.544141%, false positives 161 -> 0.161000%)
[Tue Sep 25 11:54:22 2018] Total right matches 104979 -> 98.121302%
```

So, in summary, our model predicts >98% matches from the dataset correctly with ~0.1% of false positives, which is more than acceptable.

## How to generate datasets

If you want to generate your own datasets, export your binary or binaries as well as the source codes and, then, use the script ```ml/pigaios_create_dataset.py``` to create a CSV file.

## How to train datasets

If you want to train the model with your own datasets or using a different classifier, use the script ```ml/pigaios_ml.py```.

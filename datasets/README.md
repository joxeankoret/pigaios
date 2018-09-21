# Dataset

The following is a dataset created with the good matches discovered between ZLib, Capstone (x86 only), Curl, Lua and SQLite.
It contains the positives found between the source code and the binaries as well as a selection of 10,000 negative results.

## Results

The current classifier is based on the results of multiple other classifiers, namely: 

 * Decision Tree Regressor.
 * Bernoulli Naive Bayes.
 * Gradient Boosting Regressor.

Using this multi-classifier to train an adapted dataset the following results were observed and reproduced:

```
[Fri Sep 21 11:26:14 2018] Using the Pigaios Multi Classifier
[Fri Sep 21 11:26:14 2018] Loading model and data...
[Fri Sep 21 11:26:14 2018] Predicting...
[Fri Sep 21 11:26:16 2018] Correctly predicted 3840 out of 4392 (true positives 552 -> 87.431694%, false positives 441 -> 4.410000%)
[Fri Sep 21 11:26:16 2018] Total right matches 13399 -> 93.100334%
```

So, in summary, our model predicts >93% matches from the dataset correctly with ~4.5% of false positives, which isn't that big.

## How to generate datasets

If you want to generate your own datasets, export your binary or binaries as well as the source codes and, then, use the script ```ml/pigaios_create_dataset.py``` to create a CSV file.

## How to train datasets

If you want to train the model with your own datasets or using a different classifier, use the script ```ml/pigaios_ml.py```.

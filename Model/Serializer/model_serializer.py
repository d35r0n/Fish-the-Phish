# Importing required libraries
import numpy as np
import pandas as pd
import pickle

from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split

# Reading the Dataset
data = pd.read_csv('../Dataset/phishing.csv')

# Preprocessing the Dataset
data = data.drop(['Index'], axis=1)

# Splitting the Dataset into with & without phishing classification column
X = data.drop(['class'], axis=1)
y = data['class']

# Train-Test Splitting the Dataset
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size = 0.2, random_state = 42)
X_train.shape, y_train.shape, X_test.shape, y_test.shape

# Instantiating the model
gbc = GradientBoostingClassifier(max_depth=4,learning_rate=0.7)

# Fitting the model
gbc.fit(X_train,y_train)

# Serializing the model
pickle.dump(gbc, open("./serialized/model.pickle","wb"))
# ----------------------------------------------------------------------------- 
# Program Description
# ----------------------------------------------------------------------------- 
# This file is responsible for the loading up of model, extraction of Features
# from the given URL and then processing the URL Data using the Machine
# Learning model to give us both if the website is safe to use and what is the
# safety score of the URL (i.e. how safe the website it) in a float value
# ----------------------------------------------------------------------------- 

# Importing the Required Libraries
from feature_extractor import *
import numpy as np
import pickle


# Loading the Serialized Model
model = pickle.load(open("./model.pickle","rb"))


# Function to check if the URL provided is Phishing or not
def is_url_phishy(url):
    '''This function checks the given URL with our Machine Learning Model.
    It returns an array consisting of two values: Is the url safe to visit,
    How safe is the URL to be visited (between 0 and 1)'''
    # Getting the Features from the URL and converting them to numpy array
    data = np.array(extract_features(url)).reshape(1,30)
    # Running the model to get the Category (1 -> Not Phishing; 0 -> Phishing)
    is_safe = "Safe" if (model.predict(data)[0] == 1) else "Not Safe"
    # Running the model to get the percentage of how much the URL is NOT phishy
    safety_score = model.predict_proba(data)[0,1]
    # Returning the values in an array
    return [is_safe, "{:.2f}%".format(safety_score*100)]

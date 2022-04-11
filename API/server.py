from base64 import urlsafe_b64decode as usb64d
from flask_restful import Api, Resource
from flask import Flask
from url_check import *

app = Flask(__name__)
api = Api(app)

class Fisher(Resource):


    def process_url(self, url):
        '''Converts the Base64 encoded URL to Plain Text'''
        return usb64d(url.encode()).decode()


    def get(self, url):
        '''Uses the model to check the provided URL for Phishing'''
        # Processing the URL and getting the Safety Report
        safe, score = is_url_phishy(self.process_url(url))
        # Storing results in required format
        report = {
            "url"  : self.process_url(url),
            "safe" : safe,
            "score": score
        }
        # Returning the Results
        return report


api.add_resource(Fisher, "/fisher/<string:url>")


if __name__=="__main__":
    app.run(debug=True)

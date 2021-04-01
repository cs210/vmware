from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from flask_restplus import Api, Resource, fields
from werkzeug.utils import secure_filename
import os

import sys
sys.path.append('../../')
import features
import feature_utils

feature_extractors = feature_utils.DEFAULT_FEATURE_EXTRACTORS

# Flask app configuration
flask_app = Flask(__name__)
cors = CORS(flask_app, resources={r"*": {"origins": "*"}})

app = Api(app = flask_app, 
      version = "1.0", 
      title = "VirusTotal++", 
      description = "Perform endpoint telemetry on an uploaded PE file.")

# Where should uploaded files go?
UPLOAD_FOLDER = 'uploads/'
flask_app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# TODO: When runtime telementry is completed, add a namespace for it as well as
# corresponding endpoints
static_telemetry_namespace = app.namespace('static_telemetry', description='APIs to expose static endpoint telemetry statistics.')

# TODO: Enable model when additional parameters (aside from uploaded file) are required
model = app.model('Expected POST request parameters', 
          {'example_string': fields.String(required = True, 
            description="Example", 
            help="Example"),
          'example_integer': fields.Integer(required = True, 
            description="Example", 
            help="Example")
          })

@static_telemetry_namespace.route("/")
class MainClass(Resource):

  def options(self):
    response = make_response()
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add('Access-Control-Allow-Headers', "*")
    response.headers.add('Access-Control-Allow-Methods', "*")
    return response

  # @app.expect(model)
  def post(self):
    try:
      file = request.files['file']
      filename = secure_filename(file.filename)
      file.save(UPLOAD_FOLDER + filename)
      # data = [val for val in formData.values()]

      # Run analysis (TODO: this needs to be written better)
      features = feature_utils.extract_features(UPLOAD_FOLDER + filename, feature_extractors)
      features = str(features)

      response = jsonify({
        "statusCode": 200,
        "fileName": filename,
        "output": features
      })
      response.headers.add('Access-Control-Allow-Origin', '*')
      return response

    except Exception as error:
      print("ERROR", error, os.getcwd())
      return jsonify({
        "statusCode": 500,
        "status": "Could not make prediction",
        "error": str(error)
      })
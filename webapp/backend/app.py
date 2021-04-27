from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from flask_restplus import Api, Resource, fields
from werkzeug.utils import secure_filename
import os

import sys
import numpy as np
import pandas as pd
import hashlib

import database

sys.path.append('../../')
import features
import feature_utils


feature_extractors = {**feature_utils.NUMERIC_FEATURE_EXTRACTORS, **feature_utils.ALPHABETICAL_FEATURE_EXTRACTORS}

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

meta_database = database.MetaDatabase()

# TODO: This is a hardcoded number. It needs to be fixed, but can't be repeatedly
# re-initialized as we can only have one database. So how do we handle the addition
# of new features? 
feature_database = database.FeatureDatabase(num_dimensions=6744)

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
      # data = [val for val in formData.values()]
      file = request.files['file']
      filename = secure_filename(file.filename)
      file.save(UPLOAD_FOLDER + filename)

      file_md5 = hashlib.md5(open(UPLOAD_FOLDER + filename, 'rb').read()).hexdigest()

      # TODO: Need a step here to search for a file's existence in the database
      # and return the database values if present, perhaps by hash first.

      # Run analysis
      features, sparse_vector = feature_utils.extract_features(UPLOAD_FOLDER + filename, feature_extractors, feature_list_dir_prefix='../..')
      features = str(features)
      
      # Store the sparse feature vector in a reasonable way
      # TODO: This needs to be consistent for every future extension. How do we manage this?
      #  without this functionality, it's difficult for people to add new extractors as our
      #  datbase has a fixed-length feature vector size. For now, we're going to fix
      #  the feature fector size, but this is a real issue.

      # Step 1: add the file's meta information to the meta database
      primary_key = meta_database.add(file_md5)

      # Step 2: associate the primary key with the file's feature list in the feature database
      feature_database.add(primary_key, sparse_vector)

      # Step 3: sanity checks! (perhaps remove in production)
      assert feature_database.search_primary_key(primary_key) is not None
      assert feature_database.search_similarity(sparse_vector, k=1)[1][0] == [primary_key]

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
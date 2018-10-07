from flask import Flask

APP = Flask(__name__)
APP.config["JSONIFY_PRETTYPRINT_REGULAR"] = True

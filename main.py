from flask import Flask, Response, render_template, jsonify
import json
import os
from pymongo import MongoClient
from utils.knockpy_runner import run_knockpy_and_enhance_streaming

app = Flask(__name__)
MXTOOLBOX_API_KEY = 
DNSDUMPSTER_API_KEY = 

client = MongoClient("mongodb://localhost:27017/")
db = client["subdomain_db"]
collection = db["iitm_subdomains"]

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/results")
def results():
    return jsonify(list(collection.find({}, {"_id": 0})))

@app.route("/rescan/stream")
def rescan_stream():
    def generate():
        domain = "snu.edu.in"
        for message in run_knockpy_and_enhance_streaming(
            domain,
            collection,
            MXTOOLBOX_API_KEY,
            DNSDUMPSTER_API_KEY
        ):
            yield f"data: {message}\n\n"
    return Response(generate(), mimetype="text/event-stream")

if __name__ == "__main__":
    app.run(debug=True)

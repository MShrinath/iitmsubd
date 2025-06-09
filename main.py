from flask import Flask, Response, render_template, jsonify
from scanner.knock_runner import run_knockpy_and_enhance_streaming
from pymongo import MongoClient
from bson import ObjectId
import os
app = Flask(__name__)
client = MongoClient(os.getenv("MONGO_URI"))
print(os.getenv("MONGO_URI"));
db = client["iitm_scan"]
collection = db["subdomains"]

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/results")
def results():
    data = list(collection.find({}, {"_id": 0}))
    return jsonify(data)

@app.route("/rescan/stream")
def rescan_stream():
    def generate():
        domain = "iitm.ac.in"
        for message in run_knockpy_and_enhance_streaming(domain, collection):
            yield f"data: {message}\n\n"
    return Response(generate(), mimetype="text/event-stream")

if __name__ == "__main__":
    app.run(debug=True)

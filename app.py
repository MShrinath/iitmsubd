from flask import Flask, Response, render_template, jsonify
import json
import os
from utils.knockpy_runner import run_knockpy_and_enhance_streaming
from utils.nmap_runner import run_nmap_raw

app = Flask(__name__)
DATA_FILE = "data/iitm.ac.in_data.json"

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/results")
def results():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            data = json.load(f)
        return jsonify(data)
    else:
        return jsonify([])

@app.route("/rescan/stream")
def rescan_stream():
    def generate():
        domain = "iitm.ac.in"
        for message in run_knockpy_and_enhance_streaming(domain, DATA_FILE):
            yield f"data: {message}\n\n"
    return Response(generate(), mimetype="text/event-stream")

@app.route('/nmap/<ip>')
def nmap_scan(ip):
    output = run_nmap_raw(ip, DATA_FILE)
    return output

if __name__ == "__main__":
    app.run(debug=True)

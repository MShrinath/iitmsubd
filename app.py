from flask import Flask, Response, render_template, jsonify
import json
import os
from utils import config 
from utils.knockpy_runner import runner_knockpy
from utils.subfinder_runner import runner_subfinder
from utils.nmap_runner import show_nmap , rerun_nmap_raw

app = Flask(__name__)

DOMAIN = config.DOMAIN
KNOCKPY_DATA_FILE = config.KNOCKPY_DATA_FILE
SUBFINDER_DATA_FILE = config.SUBFINDER_DATA_FILE

# TOOL_MAP = {
#     "knockpy": {
#         "data_file": KNOCKPY_DATA_FILE
#     },
#     "subfinder": {
#         "data_file": SUBFINDER_DATA_FILE
#     }
# }

@app.route("/")
def index():
    return render_template("index.html", domain=DOMAIN)

@app.route("/knockpy")
def index_knockpy():
    return render_template("knockpy.html", domain=DOMAIN)

@app.route("/subfinder")
def index_subfinder():
    return render_template("subfinder.html", domain=DOMAIN)

@app.route("/results/knockpy")
def results_knockpy():
    if os.path.exists(KNOCKPY_DATA_FILE):
        with open(KNOCKPY_DATA_FILE, "r") as f:
            data = json.load(f)
        return jsonify(data)
    else:
        return jsonify([])

@app.route("/rescan/knockpy")
def rescan_knockpy():
    def generate():
        for message in runner_knockpy(DOMAIN, KNOCKPY_DATA_FILE):
            yield f"data: {message}\n\n"
    return Response(generate(), mimetype="text/event-stream")

# @app.route("/results/subfinder")
# def results_subfinder():
#     if os.path.exists(SUBFINDER_DATA_FILE):
#         with open(SUBFINDER_DATA_FILE, "r") as f:
#             data = json.load(f)
#         return jsonify(data)
#     else:
#         return jsonify([])

# @app.route("/rescan/subfinder")
# def rescan_subfinder():
#     def generate():
#         for message in runner_subfinder(DOMAIN, SUBFINDER_DATA_FILE):
#             yield f"data: {message}\n\n"
#     return Response(generate(), mimetype="text/event-stream")

@app.route('/nmap/<ip>')
def nmap_scan(ip):
    output = show_nmap(ip, KNOCKPY_DATA_FILE)
    return output

@app.route('/renmap/<ip>')
def renmap_scan(ip):
    output = rerun_nmap_raw(ip, KNOCKPY_DATA_FILE)
    return output

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

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

TOOL_RUNNERS = {
    "knockpy": runner_knockpy,
    "subfinder": runner_subfinder
}

TOOL_FILES = {
    "knockpy": KNOCKPY_DATA_FILE,
    "subfinder": SUBFINDER_DATA_FILE
}


@app.route("/")
def index():
    return render_template("index.html", domain=DOMAIN)

@app.route("/knockpy")
def index_knockpy():
    return render_template("knockpy.html", domain=DOMAIN)

@app.route("/subfinder")
def index_subfinder():
    return render_template("subfinder.html", domain=DOMAIN)

@app.route("/results/<tool>")
def results(tool):
    if tool not in TOOL_FILES:
        return jsonify({"error": "Invalid tool"}), 404

    path = TOOL_FILES[tool]
    if not os.path.exists(path):
        return jsonify([])

    with open(path) as f:
        return jsonify(json.load(f))

@app.route("/rescan/<tool>")
def rescan(tool):
    if tool not in TOOL_RUNNERS:
        return "Invalid tool", 404

    runner = TOOL_RUNNERS[tool]
    datafile = TOOL_FILES[tool]

    def generate():
        for msg in runner(DOMAIN, datafile):
            yield f"data: {msg}\n\n"

    return Response(generate(), mimetype="text/event-stream")


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

# IITM Subdomain Enumeration Tool

This developer-only tool enumerates subdomains for a given domain _iitm.ac.in_, collects details (like HTTP/HTTPS status, certificate information) and generates an interactive summary report.

## Features

- **Subdomain Enumeration:** Uses the [knock-subdomains](https://pypi.org/project/knock-subdomains/) package as part of the process.
- **Enhanced Results:** The tool loads and enhances subdomain data with certificate details.
- **Real-time Scan Streaming:** Uses Server-Sent Events (SSE) to stream scan progress.
- **Interactive Report:** The web UI (built with Flask and Chart.js) displays a dashboard with domain status, certificate charts, and filtering/searching capabilities.
- **Developer-Only:** This tool is intended for internal development and testing.

## Project Structure

- **app.py:** Main Flask application which serves the web pages and API endpoints.
- **Dockerfile:** Containerize the tool for consistent development environment.
- **requirements.txt:** Lists required Python packages (Flask, knock-subdomains, etc.).
- **templates/index.html:** Front-end page for the report.
- **static/script.js:** Contains logic for fetching, filtering, and rendering the report.
- **data/iitm.ac.in_knockpy_results_with_certs.json:** Data file storing subdomain scan results.
- **utils/knockpy_runner.py:** Module that runs the subdomain enumeration and enhances the output.

## Installation

Ensure you have Docker installed on your system. Then build and run the container using the following commands:

```sh
docker build -t iitm-subd .
docker run -p 5000:5000 iitm-subd
```
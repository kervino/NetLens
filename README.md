
# NetLens

A Python-based defensive network traffic analyzer
for offline PCAP files.

## Features

- Source and destination IP analysis
- TCP/UDP protocol statistics
- Source and destination port extraction
- Text and JSON reports
- Potential TCP SYN port-scan detection
- Fixed 60-second detection windows
- Automated tests

## Requirements

- Python 3.11+
- Scapy

## Installation

Create a virtual environment:

python -m venv .venv

Install dependencies using the virtual
environment's Python:

.venv\Scripts\python.exe -m pip install -r requirements.txt

## Usage (Windows CMD)

.venv\Scripts\python.exe src\analyze.py tests\fixtures\netlens-office-synthetic.pcap

## Testing

.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py" -v

## Limitations

- Offline analysis only
- Detection uses a configurable-in-code
  threshold of 5 unique TCP destination ports
  within fixed 60-second windows
- Alerts indicate possible suspicious activity,
  not confirmed attacks
